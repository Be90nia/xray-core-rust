//! naive 入站（naiveproxy 服务端语义）。
//!
//! TLS（rustls，ALPN h2）→ hyper h2 server：
//! 1. 非 CONNECT 请求 → 404 fallback（naiveproxy probe-resistance 伪装面）
//! 2. CONNECT + `Proxy-Authorization: Basic` 认证失败 → 407 + `Proxy-Authenticate`
//! 3. CONNECT 认证通过 → 200 空响应（请求带 `padding` 头则响应也带，双向首 8 帧 kVariant1
//!    帧化，复用 [`crate::padding`]）→ 隧道流经 `hyper::upgrade::on` 的 `Upgraded`
//!    交付，双向桥接到目标： 生产经 [`DispatchHandler`] 分发，`None` 时 mock 直连（测试场景）。
//!
//! 与 Go 的关系：Go Xray 无 naive proxy——语义基线为 naiveproxy 官方服务端
//! （Caddy forwardproxy）/ sing-box naive inbound。UDP over h2 不支持
//! （naiveproxy 本身无 UDP）。

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use bytes::Bytes;
use http::{Method, StatusCode, header::PROXY_AUTHORIZATION};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_rustls::TlsAcceptor;
use xray_app_dispatcher::default::DispatchHandler;
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_features::inbound::{InboundError, InboundHandler};
use xray_transport::link::Link;

use crate::{PaddingReader, PaddingWriter, padding::random_padding_header};

/// 统一响应 body：CONNECT 200 / 404 / 407 均为空 body。
///
/// hyper server 对 h2 CONNECT 强制 success 响应 body 为空（非零 content-length
/// 直接 RST）；隧道双向流经 [`hyper::upgrade::on`] 的 `Upgraded` 交付。
type RespBody = http_body_util::Empty<Bytes>;

/// naive 入站认证配置（sing-box naive inbound 惯例：单 users 条目）。
#[derive(Debug, Clone)]
pub struct NaiveInboundConfig {
    /// Basic auth 用户名。
    pub username: String,
    /// Basic auth 密码。
    pub password: String,
}

impl NaiveInboundConfig {
    /// settings JSON → 认证配置：`{"users":[{"name":"user","pass":"pass"}]}`。
    ///
    /// users 缺失/为空 → 硬错（naive 无匿名模式，对齐 Caddy forwardproxy）。
    pub fn from_settings_json(data: &[u8]) -> std::io::Result<Self> {
        let v: serde_json::Value = serde_json::from_slice(data)
            .map_err(|e| std::io::Error::other(format!("naive inbound settings JSON: {e}")))?;
        let user =
            v.get("users").and_then(|u| u.as_array()).and_then(|a| a.first()).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "naive inbound requires users[0] {name, pass}",
                )
            })?;
        let username = user.get("name").and_then(|x| x.as_str()).unwrap_or_default();
        let password = user.get("pass").and_then(|x| x.as_str()).unwrap_or_default();
        Ok(Self { username: username.to_string(), password: password.to_string() })
    }
}

// ============================================================
// h2 下行通道：mpsc ↔ hyper response body 桥
// ============================================================

// ============================================================
// 入站 Handler
// ============================================================

struct InboundSlot {
    _accept_task: JoinHandle<()>,
}

/// naive 入站 Handler，实现 [`InboundHandler`]。
///
/// `start` 时 bind TcpListener 并 spawn accept 循环（TLS + h2 服务）；
/// drop 时 abort accept 任务关闭端口（xray-core 接线层以保活模式持有）。
pub struct NaiveInboundHandler {
    tag: String,
    bind_addr: SocketAddr,
    tls: TlsAcceptor,
    auth: Arc<NaiveInboundConfig>,
    /// 生产路径 dispatcher；None = mock 直连（测试场景）。
    dispatch: Option<Arc<dyn DispatchHandler>>,
    started: AtomicBool,
    local_port: AtomicU16,
    slot: Mutex<Option<InboundSlot>>,
}

impl NaiveInboundHandler {
    /// 构造入站 Handler（TLS 配置应含 ALPN h2，见
    /// `xray_tls::server_config::build_server_config` 默认值）。
    pub fn new(
        tag: impl Into<String>,
        bind_addr: SocketAddr,
        tls_config: Arc<tokio_rustls::rustls::ServerConfig>,
        auth: NaiveInboundConfig,
    ) -> Self {
        Self {
            tag: tag.into(),
            bind_addr,
            tls: TlsAcceptor::from(tls_config),
            auth: Arc::new(auth),
            dispatch: None,
            started: AtomicBool::new(false),
            local_port: AtomicU16::new(0),
            slot: Mutex::new(None),
        }
    }

    /// 注入 dispatcher（生产路径：CONNECT 经 router 分发而非直连）。
    #[must_use]
    pub fn with_dispatch(mut self, dispatch: Arc<dyn DispatchHandler>) -> Self {
        self.dispatch = Some(dispatch);
        self
    }

    fn lock_slot(&self) -> std::sync::MutexGuard<'_, Option<InboundSlot>> {
        self.slot.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Drop for NaiveInboundHandler {
    fn drop(&mut self) {
        if let Some(slot) = self.lock_slot().take() {
            slot._accept_task.abort();
        }
    }
}

#[async_trait::async_trait]
impl InboundHandler for NaiveInboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self) -> Result<(), InboundError> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Err(InboundError::AlreadyStarted(self.tag.clone()));
        }
        let listener = TcpListener::bind(self.bind_addr).await.map_err(|e| {
            InboundError::ListenError(format!("naive bind {}: {e}", self.bind_addr))
        })?;
        let port = listener
            .local_addr()
            .map_err(|e| InboundError::ListenError(format!("naive local_addr: {e}")))?
            .port();
        self.local_port.store(port, Ordering::SeqCst);
        let acceptor = self.tls.clone();
        let auth = Arc::clone(&self.auth);
        let dispatch = self.dispatch.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((tcp, _peer)) => {
                        let acceptor = acceptor.clone();
                        let auth = Arc::clone(&auth);
                        let dispatch = dispatch.clone();
                        tokio::spawn(async move {
                            let tls = match acceptor.accept(tcp).await {
                                Ok(t) => t,
                                Err(e) => {
                                    tracing::debug!(target: "naive", error = %e, "tls accept failed");
                                    return;
                                },
                            };
                            let service = service_fn(move |req| {
                                handle_request(req, dispatch.clone(), Arc::clone(&auth))
                            });
                            if let Err(e) =
                                hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                                    .serve_connection(TokioIo::new(tls), service)
                                    .await
                            {
                                tracing::debug!(target: "naive", error = %e, "h2 connection ended");
                            }
                        });
                    },
                    Err(e) => {
                        tracing::debug!(target: "naive", error = %e, "accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    },
                }
            }
        });
        *self.lock_slot() = Some(InboundSlot { _accept_task: accept_task });
        tracing::info!(tag = %self.tag, addr = %self.bind_addr, "naive inbound listening");
        Ok(())
    }

    async fn close(&self) -> Result<(), InboundError> {
        if let Some(slot) = self.lock_slot().take() {
            slot._accept_task.abort();
        }
        self.local_port.store(0, Ordering::SeqCst);
        self.started.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn port(&self) -> u16 {
        self.local_port.load(Ordering::SeqCst)
    }
}

// ============================================================
// h2 请求处理：fallback 404 / auth 407 / CONNECT 200 + relay
// ============================================================

async fn handle_request(
    mut req: http::Request<Incoming>,
    dispatch: Option<Arc<dyn DispatchHandler>>,
    auth: Arc<NaiveInboundConfig>,
) -> Result<http::Response<RespBody>, Infallible> {
    // fallback：非 CONNECT 一律 404 空响应（naiveproxy probe-resistance——
    // 主动探测看到的是普通 404 站点，不暴露代理身份）
    if req.method() != Method::CONNECT {
        tracing::debug!(target: "naive", method = %req.method(), "fallback 404");
        return Ok(response_status(StatusCode::NOT_FOUND));
    }

    // 认证：Proxy-Authorization: Basic base64(user:pass)，失败 407
    // （Caddy forwardproxy / sing-box naive 语义）
    if let Err(reason) = check_proxy_auth(req.headers(), &auth) {
        tracing::debug!(target: "naive", reason, "auth rejected");
        let mut resp = response_status(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        resp.headers_mut().insert(
            http::header::PROXY_AUTHENTICATE,
            http::HeaderValue::from_static("Basic realm=\"naive\""),
        );
        return Ok(resp);
    }

    // CONNECT authority-form：目标必有端口，缺失按畸形请求拒绝
    let Some(authority) = req.uri().authority() else {
        tracing::debug!(target: "naive", "CONNECT without authority");
        return Ok(response_status(StatusCode::BAD_REQUEST));
    };
    let Some(port) = authority.port_u16() else {
        tracing::debug!(target: "naive", authority = %authority, "CONNECT without port");
        return Ok(response_status(StatusCode::BAD_REQUEST));
    };
    let host = authority.host().to_string();
    // drop(authority)（no-op）已移除：authority 为引用，drop 无效果

    // 请求带 padding 头 → 服务端支持确认，响应也带，双向首 8 帧帧化
    let padded = req.headers().contains_key("padding");

    // hyper server 对 h2 CONNECT 同样走 upgrade：request body 被抽空（读即
    // EOF），真实双向流在 200 空响应后经 `on(req)` 的 Upgraded 交付。
    let upgrade = hyper::upgrade::on(&mut req);
    let dest = Destination::new(
        host.parse::<Address>().unwrap_or_else(|_| Address::Domain(host.clone())),
        Port::new(port),
        Network::TCP,
    );
    match dispatch {
        Some(dispatch) => {
            tokio::spawn(async move {
                let upgraded = match upgrade.await {
                    Ok(u) => u,
                    Err(e) => {
                        tracing::debug!(target: "naive", error = %e, "tunnel upgrade failed");
                        return;
                    },
                };
                let (rd, wr) = tokio::io::split(TokioIo::new(upgraded));
                let link = Link::new(
                    xray_buf::io::new_reader(PaddingReader::new(rd, padded)),
                    xray_buf::io::new_writer(PaddingWriter::new(wr, padded)),
                );
                let _ = dispatch.dispatch(&dest, link).await;
            });
        },
        None => {
            tokio::spawn(relay_mock_direct(host.clone(), port, upgrade, padded));
        },
    }

    let mut builder = http::Response::builder().status(StatusCode::OK);
    if padded {
        builder = builder.header("padding", random_padding_header());
    }
    let resp = builder.body(RespBody::new()).expect("static response parts are valid");
    tracing::debug!(target: "naive", host, port, padded, "naive tunnel established");
    Ok(resp)
}

/// `Proxy-Authorization: Basic` 校验（恒定时间比较，防时序探测）。
fn check_proxy_auth(
    headers: &http::HeaderMap,
    expected: &NaiveInboundConfig,
) -> Result<(), &'static str> {
    let value = headers
        .get(PROXY_AUTHORIZATION)
        .ok_or("missing proxy-authorization")?
        .to_str()
        .map_err(|_| "non-ascii proxy-authorization")?;
    let credentials = value.strip_prefix("Basic ").ok_or("not basic scheme")?;
    let decoded = B64.decode(credentials).map_err(|_| "bad base64")?;
    let decoded = std::str::from_utf8(&decoded).map_err(|_| "bad utf-8 credentials")?;
    let (user, pass) = decoded.split_once(':').ok_or("no colon in credentials")?;
    if ct_eq_str(user, &expected.username) && ct_eq_str(pass, &expected.password) {
        Ok(())
    } else {
        Err("credentials mismatch")
    }
}

/// 长度不等直接 false 的恒定时间字符串比较（同 Go `subtle.ConstantTimeCompare` 语义）。
fn ct_eq_str(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn response_status(status: StatusCode) -> http::Response<RespBody> {
    http::Response::builder()
        .status(status)
        .body(RespBody::new())
        .expect("static response parts are valid")
}

/// mock 直连 relay（dispatch=None 的测试路径）。
async fn relay_mock_direct(
    host: String,
    port: u16,
    upgrade: hyper::upgrade::OnUpgrade,
    padded: bool,
) {
    let target = match tokio::net::TcpStream::connect((host.as_str(), port)).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!(target: "naive", %host, port, error = %e, "mock upstream dial failed");
            return;
        },
    };
    let upgraded = match upgrade.await {
        Ok(u) => u,
        Err(e) => {
            tracing::debug!(target: "naive", error = %e, "mock tunnel upgrade failed");
            return;
        },
    };
    let (rd, wr) = tokio::io::split(TokioIo::new(upgraded));
    let mut tunnel =
        crate::dial::NaiveConn::new(PaddingReader::new(rd, padded), PaddingWriter::new(wr, padded));
    let mut target = target;
    let _ = tokio::io::copy_bidirectional(&mut tunnel, &mut target).await;
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_tls::{fingerprint::get_fingerprint, server_config::build_server_config};

    use super::*;
    use crate::{dial::dial_naive, uri::NaiveConfig};

    /// 自签证书 TLS：`(server config, 证书 pin hex, 证书 DER)`。
    fn test_tls() -> (Arc<rustls::ServerConfig>, String, Vec<u8>) {
        let (cert_pem, key_pem) =
            xray_tls::certificate::generate_self_signed_cert(&["localhost"]).unwrap();
        let entry = serde_json::json!({ "certificate": cert_pem, "key": key_pem });
        let (certs, _) = xray_tls::certificate::entry_certs_and_key(&entry).unwrap();
        let pin = xray_tls::pin::generate_cert_hash_hex(certs[0].as_ref());
        let ss =
            serde_json::json!({ "certificates": [{ "certificate": cert_pem, "key": key_pem }] });
        let config = build_server_config("tls", Some(&ss)).unwrap().expect("tls config");
        (config, pin, certs[0].as_ref().to_vec())
    }

    fn test_auth() -> NaiveInboundConfig {
        NaiveInboundConfig { username: "user".into(), password: "pass".into() }
    }

    fn client_config(port: u16, pin: &str, password: &str) -> NaiveConfig {
        NaiveConfig {
            host: "127.0.0.1".into(),
            port,
            sni: "localhost".into(),
            username: "user".into(),
            password: password.into(),
            fingerprint: get_fingerprint("chrome").expect("chrome fingerprint"),
            pinned_peer_cert_sha256: Some(pin.into()),
        }
    }

    /// 起一个 naive 入站并返回监听地址（handler drop = abort accept task，
    /// 但任务 detach 自持 listener——测试进程存活期间端口保持服务）。
    ///
    /// ponytail: 测试收尾靠进程退出回收端口，不做显式 close。
    async fn start_test_inbound(
        dispatch: Option<Arc<dyn DispatchHandler>>,
    ) -> (SocketAddr, String, Vec<u8>) {
        let (config, pin, cert_der) = test_tls();
        let handler = NaiveInboundHandler::new(
            "naive-test",
            "127.0.0.1:0".parse().unwrap(),
            config,
            test_auth(),
        );
        let handler = match dispatch {
            Some(d) => handler.with_dispatch(d),
            None => handler,
        };
        handler.start().await.expect("naive inbound start");
        let addr = SocketAddr::from(([127, 0, 0, 1], handler.port()));
        std::mem::forget(handler);
        (addr, pin, cert_der)
    }

    /// 回显 fake dispatcher：读尽 link 上行全部写回 link.writer。
    ///
    /// 同时验证 Link 组装方向正确（reader=客户端上行，writer=服务端下行）。
    #[derive(Debug)]
    struct EchoDispatch;
    impl DispatchHandler for EchoDispatch {
        fn tag(&self) -> &str {
            "echo-fake"
        }

        fn dispatch(
            &self,
            _dest: &Destination,
            mut link: Link,
        ) -> xray_app_dispatcher::default::PinFuture<()> {
            Box::pin(async move {
                loop {
                    let mb = match link.reader.read_multi_buffer().await {
                        Ok(mb) => mb,
                        Err(e) => {
                            tracing::debug!(target: "naive", error = %e, "echo dispatch read ended");
                            break;
                        },
                    };
                    if mb.is_empty() {
                        break;
                    }
                    if let Err(e) = link.writer.write_multi_buffer(mb).await {
                        tracing::debug!(target: "naive", error = %e, "echo dispatch write ended");
                        break;
                    }
                }
                link.writer.shutdown();
            })
        }
    }

    #[tokio::test]
    async fn settings_json_parses_users() {
        let cfg =
            NaiveInboundConfig::from_settings_json(br#"{"users":[{"name":"user","pass":"pass"}]}"#)
                .unwrap();
        assert_eq!(cfg.username, "user");
        assert_eq!(cfg.password, "pass");
        assert!(NaiveInboundConfig::from_settings_json(b"{}").is_err());
        assert!(NaiveInboundConfig::from_settings_json(br#"{"users":[]}"#).is_err());
    }

    /// 认证失败 → 407，客户端 dial 报错且隧道不建立。
    #[tokio::test]
    async fn auth_failure_rejected() {
        let (addr, pin, _cert_der) = start_test_inbound(None).await;
        let config = client_config(addr.port(), &pin, "wrong");
        let err = match dial_naive(&config, "127.0.0.1", 1).await {
            Err(e) => e,
            Ok(_) => panic!("wrong credentials must be rejected"),
        };
        assert!(err.contains("407"), "expected 407 rejection, got: {err}");
    }

    /// h2 CONNECT 建链 + 数据双向回传（dispatch 生产路径，>8 帧混合 padding/直通）。
    #[tokio::test]
    async fn connect_establishes_and_relays_bidirectional() {
        let (addr, pin, _cert_der) = start_test_inbound(Some(Arc::new(EchoDispatch))).await;
        let config = client_config(addr.port(), &pin, "pass");
        let conn = dial_naive(&config, "echo.test", 443).await.expect("tunnel");
        let (mut rd, mut wr) = tokio::io::split(conn);

        // 12 块写：首 8 帧走 padding 帧化，后 4 块直通（覆盖两种路径）
        let chunks: Vec<Vec<u8>> =
            (0..12usize).map(|i| vec![b'a' + i as u8; 700 + i * 13]).collect();
        let expected: Vec<u8> = chunks.concat();
        let writer_task = tokio::spawn(async move {
            for c in &chunks {
                wr.write_all(c).await.unwrap();
            }
            wr.flush().await.unwrap();
            wr.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        rd.read_to_end(&mut got).await.unwrap();
        writer_task.await.unwrap();
        assert_eq!(
            got.len(),
            expected.len(),
            "length mismatch: got {} want {}",
            got.len(),
            expected.len()
        );
        assert_eq!(got, expected, "echo must be byte-for-byte");
    }

    /// 非 CONNECT 请求 → 404 fallback（raw h2 client 验证伪装面）。
    #[tokio::test]
    async fn fallback_404_for_non_connect() {
        let (addr, _pin, cert_der) = start_test_inbound(None).await;

        // client：服务端自签证书入 root store（anytls inbound_dispatch 同款）
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.into()).unwrap();
        let mut config =
            rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let config = Arc::new(config);

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(config)
            .connect("localhost".try_into().unwrap(), tcp)
            .await
            .unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = http::Request::builder()
            .method(Method::GET)
            .uri("https://localhost/")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let resp = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
            .await
            .expect("404 within timeout")
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
