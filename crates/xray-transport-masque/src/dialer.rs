//! MASQUE 客户端拨号（Go `transport/internet/masque/dialer.go dialHTTP2` 直译）。
//!
//! 层序（规划 §5 B2.6，Go `dialHTTP2:182-191` 同款）：TCP → **finalmask（TCP 后、
//! TLS 前）** → TLS（指纹走 btls / 否则 rustls，同 splithttp/grpc 调用序）→
//! ALPN=h2 硬校验 → [`crate::h2::connect_h2`] → [`crate::connect::establish`]。
//!
//! 硬约束（extra 条款 `MASQUE-TLS-REQUIRED` / `MASQUE-H2-ONLY`）：`security=tls`
//! 必选；用户 ALPN 必须显式含 `h2` 且不含 `h3`——Go `hub.go:47-50` 对 ALPN 缺省
//! 的解释是走 h3，本仓 h3 押后（规划 §7 R11/R9），缺省即 fail-visible 硬错。
//!
//! `dial` 由聚合口 `xray_core::register::register_all_transports()` 包装成
//! [`xray_transport::dialer::TransportDialFn`] 注册（**本批不接聚合口**，规划 §5 B1.4）。

use std::time::Duration;

use xray_common::net::destination::Destination;
use xray_transport::{
    connection::{Connection, TcpConnection},
    dialer::StreamSettings,
    finalmask::{shared_tcpmask_manager_from_json, wrap_conn_client_into_connection},
    sockopt::{SocketOptions, dial_client_tcp},
};

use crate::{
    config::Config,
    connect::{ConnectIpSession, establish},
    error::{MasqueError, Result},
    h2::connect_h2,
};

/// TCP 拨号外层超时（对齐 grpc/system_dialer DEFAULT_DIAL_TIMEOUT 16s）。
const TCP_DIAL_TIMEOUT: Duration = Duration::from_secs(16);

/// 客户端拨号：建立 CONNECT-IP 隧道并完成地址协商（Go `Dial` h2 分支）。
///
/// `sockopt` 本批未消费（显式收窗等运维面随 B4 接线批对齐 splithttp 同款）。
pub async fn dial(
    dest: &Destination,
    sockopt: &SocketOptions,
    settings: &StreamSettings,
    config: &Config,
) -> Result<ConnectIpSession> {
    let _ = sockopt;

    // MASQUE-TLS-REQUIRED：无 TLS 即硬错（Go dialHTTP2 前置 tlsConfig nil 检查）。
    if settings.security != "tls" {
        return Err(MasqueError::Protocol(format!(
            "masque: security must be \"tls\", got {:?}",
            settings.security
        )));
    }
    let security_json = settings.security_json.as_ref();

    // MASQUE-H2-ONLY：用户 ALPN 必须显式含 h2 且不含 h3（规划 §7 R9/R11）。
    let alpn = security_json.and_then(|v| v.get("alpn")).and_then(|v| v.as_array());
    let alpn_ok = alpn.is_some_and(|a| {
        a.iter().any(|x| x.as_str() == Some("h2")) && !a.iter().any(|x| x.as_str() == Some("h3"))
    });
    if !alpn_ok {
        return Err(MasqueError::Protocol(
            "masque: tlsSettings.alpn must explicitly include \"h2\" \
             (h3 is unsupported; Go treats a missing h2 as h3)"
                .into(),
        ));
    }

    let sni_owned = security_json
        .and_then(|v| v.get("serverName"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| dest.address().to_string());
    let base_tls = xray_tls::client_config::build_client_config("tls", security_json, &sni_owned)?
        .ok_or_else(|| MasqueError::Protocol("masque: TLS client config missing".into()))?;

    // 指纹解析（Go dialHTTP2:206 `tls.GetFingerprint`）。
    let fp_name = security_json
        .and_then(|v| v.as_object())
        .and_then(|m| m.get("fingerprint"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let fingerprint = if fp_name.is_empty() {
        None
    } else {
        Some(xray_tls::fingerprint::get_fingerprint(fp_name).map_err(|e| {
            MasqueError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("masque: invalid fingerprint: {e}"),
            ))
        })?)
    };

    // WARP 变体（Go dialer.go `useWarp`）：客户端证书恒挂；pin 由 WARP 自己的
    // SPKI 验证器执行（除非用户的 pcs/vcn/allowInsecure 已接管）。btls（指纹）路径
    // 拿不到 peer 证书 ⇒ 该组合 fail-visible 拒绝，不静默丢 pin。
    let warp = config.warp.as_ref();
    if warp.is_some() && fingerprint.is_some() {
        return Err(MasqueError::Protocol(
            "masque: \"warp\" can't be combined with \"fingerprint\": \
             the WARP endpoint key pin is verified by the rustls backend"
                .into(),
        ));
    }
    let tls_cfg = match warp {
        Some(w) => w.client_config(&base_tls, crate::warp::pin_required(security_json))?,
        None => base_tls,
    };

    // finalmask 配置解析前移到网络拨号之前（R12 fail-visible：配置含 finalmask 而
    // 不合法 → 装配期即报，不烧一次 TCP 拨号才发现；空 manager = 恒等）。
    let tcpmask = shared_tcpmask_manager_from_json(settings.finalmask_json.as_ref())?;

    // TCP（16s 上限；域名前置/CDN 后端下 IP 直连极快，DNS hang 不得拖死拨号）。
    let addr = format!("{}:{}", dest.address(), dest.port().value());
    let tcp =
        tokio::time::timeout(TCP_DIAL_TIMEOUT, dial_client_tcp(&addr)).await.map_err(|_| {
            MasqueError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "masque dial timeout",
            ))
        })??;
    tcp.set_nodelay(true).ok();

    // finalmask 包装（TCP 后、TLS 前——首字节 = mask 头而非 TLS record）。
    let conn: Box<dyn Connection> =
        wrap_conn_client_into_connection(&tcpmask, Box::new(TcpConnection::new(tcp)))?;

    // TLS（指纹走 btls 真实浏览器 ClientHello，否则 rustls——Go UClient/Client 同判）。
    // ALPN 硬校验在 Box 之前做：ConnInterface 实现挂在具体包装类型上
    // （Go dialHTTP2:226-230：协商非 h2 即断链）。
    let (negotiated, tls_stream): (String, Box<dyn Connection>) = match fingerprint {
        Some(fp) => {
            let c = xray_tls::utls::u_client(conn, &sni_owned, tls_cfg, fp, None, security_json)
                .await?;
            let n = xray_tls::ConnInterface::negotiated_protocol(&c).await;
            (n, Box::new(c))
        },
        None => {
            let c = xray_tls::utls::client(conn, &sni_owned, tls_cfg).await?;
            let n = xray_tls::ConnInterface::negotiated_protocol(&c).await;
            (n, Box::new(c))
        },
    };
    // Go dialHTTP2:191：WARP 下服务端可以协商空 ALPN（Cloudflare 不回 ALPN）。
    if negotiated != "h2" && !(warp.is_some() && negotiated.is_empty()) {
        return Err(MasqueError::Protocol(format!(
            "masque: the server negotiated \"{negotiated}\" instead of h2"
        )));
    }

    let authority = resolve_authority(config, &sni_owned, dest.port().value());
    let authority =
        if warp.is_some() { crate::warp::cloudflare_authority(&authority) } else { authority };
    let session = connect_h2(tls_stream, config, &authority).await?;
    establish(session, warp).await
}

/// 请求 `:authority`（Go `dialer.go authority`）：config.host 优先；否则 SNI
/// （剥括号）+ 非 443 端口带端口，IPv6 字面量补括号。
fn resolve_authority(config: &Config, server_name: &str, port: u16) -> String {
    if !config.host.is_empty() {
        return config.host.clone();
    }
    let host = server_name.trim_start_matches('[').trim_end_matches(']');
    if host.contains(':') {
        if port == 443 {
            return format!("[{host}]");
        }
        return format!("[{host}]:{port}");
    }
    if port == 443 { host.to_string() } else { format!("{host}:{port}") }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, sync::Arc, time::Duration};

    use bytes::Bytes;
    use http::{Request, Response};
    use http_body_util::Full;
    use hyper::{body::Incoming, ext::Protocol, service::service_fn};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use xray_common::net::{address::Address, destination::Destination, port::Port};
    use xray_transport::sockopt::SocketOptions;

    use super::*;
    use crate::connect::test_support::{echo_loop, test_config, udp_v4_packet};

    /// rcgen 自签证书（SAN localhost）→ (PEM 证书, PEM 私钥, DER)。
    fn make_cert() -> (String, String, Vec<u8>) {
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let key_pair = rcgen::KeyPair::generate().expect("keypair");
        let cert = params.self_signed(&key_pair).expect("self signed");
        (cert.pem(), key_pair.serialize_pem(), cert.der().to_vec())
    }

    /// 真 TCP + TLS(rustls, pin) + h2 + 胶囊全链路 e2e：finalmask(None)=恒等接线 +
    /// ALPN 硬校验 + establish 地址协商 + IP 包往返。
    #[tokio::test]
    async fn dial_tls_loopback_e2e() {
        let (cert_pem, key_pem, cert_der) = make_cert();
        let server_json = serde_json::json!({
            "certificates": [{ "certificate": cert_pem, "key": key_pem }],
            "alpn": ["h2"],
        });
        let server_cfg = xray_tls::server_config::build_server_config("tls", Some(&server_json))
            .expect("server config builds")
            .expect("server config present");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        #[allow(
            clippy::disallowed_methods,
            reason = "测试基建 server accept 循环（spawn 三分类②），随用随弃"
        )]
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { break };
                let sc = Arc::clone(&server_cfg);
                #[allow(
                    clippy::disallowed_methods,
                    reason = "测试基建 per-conn server 任务（spawn 三分类②）"
                )]
                tokio::spawn(async move {
                    let tls = xray_tls::utls::server(
                        xray_transport::connection::TcpConnection::new(tcp),
                        sc,
                    )
                    .await
                    .expect("server tls accept");
                    let mut builder =
                        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                    let _ = builder
                        .http2()
                        .enable_connect_protocol()
                        .serve_connection_with_upgrades(
                            TokioIo::new(tls),
                            service_fn(|req: Request<Incoming>| async move {
                                let proto = req
                                    .extensions()
                                    .get::<Protocol>()
                                    .map_or_else(String::new, |p| p.as_str().to_string());
                                assert_eq!(proto, "connect-ip");
                                let upgrade = hyper::upgrade::on(req);
                                #[allow(
                                    clippy::disallowed_methods,
                                    reason = "测试基建 upgrade 回声任务（spawn 三分类②）"
                                )]
                                tokio::spawn(async move {
                                    if let Ok(io) = upgrade.await {
                                        echo_loop(
                                            io,
                                            crate::connect::test_support::ServerBehavior::Echo,
                                        )
                                        .await;
                                    }
                                });
                                Ok::<_, std::convert::Infallible>(
                                    Response::builder()
                                        .status(200)
                                        .body(Full::new(Bytes::new()))
                                        .expect("static response"),
                                )
                            }),
                        )
                        .await;
                });
            }
        });

        let pin = xray_tls::pin::generate_cert_hash_hex(&cert_der);
        let settings = StreamSettings {
            protocol: "masque".into(),
            security: "tls".into(),
            security_json: Some(serde_json::json!({
                "serverName": "localhost",
                "alpn": ["h2"],
                "pinnedPeerCertSha256": pin,
            })),
            ..StreamSettings::tcp()
        };
        let dest =
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(addr.port()));
        let mut session = dial(&dest, &SocketOptions::default(), &settings, &test_config())
            .await
            .expect("dial over real TLS");

        // establish：本端地址已协商（每族一个，非 0.0.0.0）。
        assert!(
            session.local_addrs().iter().any(|a| matches!(a, IpAddr::V4(v) if !v.is_unspecified())),
            "establish must surface a real v4 local addr, got {:?}",
            session.local_addrs()
        );

        // IP 包往返一例。
        let local4 = session
            .local_addrs()
            .iter()
            .find_map(|a| if let IpAddr::V4(v) = a { Some(v) } else { None })
            .expect("v4 local addr");
        let packet = udp_v4_packet(*local4, *local4, 64, b"e2e");
        let r = session.send_packet(&packet).await.expect("send");
        assert!(r.is_none(), "normal packet must not yield ICMP");
        let got = tokio::time::timeout(Duration::from_secs(5), session.recv_packet())
            .await
            .expect("recv within 5s")
            .expect("packet");
        assert_eq!(&got[20 + 8..], b"e2e");
        session.close();
    }

    /// MASQUE-TLS-REQUIRED：security ≠ tls 即硬错（不网络拨号）。
    #[tokio::test]
    async fn dial_rejects_non_tls_security() {
        let dest = Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(1));
        let settings = StreamSettings {
            protocol: "masque".into(),
            security: "none".into(),
            ..StreamSettings::tcp()
        };
        let err = dial(&dest, &SocketOptions::default(), &settings, &test_config())
            .await
            .expect_err("non-tls must fail");
        assert!(err.to_string().contains("security must be"), "{err}");
    }

    /// MASQUE-H2-ONLY：ALPN 缺省 / 缺 h2 / 含 h3 均硬错（规划 §7 R9/R11）。
    #[tokio::test]
    async fn dial_rejects_alpn_violations() {
        let dest = Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(1));
        for (alpn_json, why) in [
            (serde_json::json!({"serverName": "localhost"}), "missing alpn"),
            (serde_json::json!({"serverName": "localhost", "alpn": ["http/1.1"]}), "no h2"),
            (serde_json::json!({"serverName": "localhost", "alpn": ["h2", "h3"]}), "h3 present"),
        ] {
            let settings = StreamSettings {
                protocol: "masque".into(),
                security: "tls".into(),
                security_json: Some(alpn_json),
                ..StreamSettings::tcp()
            };
            let err = dial(&dest, &SocketOptions::default(), &settings, &test_config())
                .await
                .err()
                .unwrap_or_else(|| panic!("{why} must fail"));
            assert!(err.to_string().contains("alpn"), "{why}: expected alpn error, got {err}");
        }
    }

    /// finalmask 配置非法 → fail-visible（R12：不静默）。
    #[tokio::test]
    async fn dial_fail_visible_on_bad_finalmask() {
        let dest = Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(1));
        let settings = StreamSettings {
            protocol: "masque".into(),
            security: "tls".into(),
            security_json: Some(serde_json::json!({
                "serverName": "localhost",
                "alpn": ["h2"],
            })),
            finalmask_json: Some(serde_json::json!({"tcp": [{"type": "noise"}]})),
            ..StreamSettings::tcp()
        };
        let err = dial(&dest, &SocketOptions::default(), &settings, &test_config())
            .await
            .expect_err("unknown tcp mask type must fail loudly");
        assert!(
            err.to_string().contains("unsupported tcp mask type"),
            "expected finalmask error, got {err}"
        );
    }

    /// WARP 形态 h2 环回服务端的句柄：要求客户端证书、断言 Cloudflare 头、以 bare
    /// DATAGRAM 回声。
    ///
    /// `frames` 记录 `(胶囊类型字节, 首载荷字节)`：首帧类型必须 0（DATAGRAM，无
    /// ADDRESS_REQUEST），首载荷字节必须 0x45（裸 IPv4，无 contextID 前缀）。
    struct WarpServer {
        port: u16,
        /// 服务端证书 SPKI（= 客户端 `warp.publicKey` 的 pin 目标）。
        server_spki: Vec<u8>,
        /// 服务端收到的客户端证书 SPKI。
        client_spki: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        /// 服务端收到的帧记录。
        frames: Arc<std::sync::Mutex<Vec<(u8, u8)>>>,
    }

    /// 起一个 WARP 形态的 h2 环回服务端（客户端证书校验 + bare DATAGRAM 回声）。
    async fn spawn_warp_server() -> WarpServer {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::rustls::{
            self, DistinguishedName,
            pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime},
            server::danger::{ClientCertVerified, ClientCertVerifier},
        };

        /// 记录客户端证书 SPKI 并恒通过（Go `tls.RequireAnyClientCert` 同款）。
        #[derive(Debug)]
        struct RecordingClientVerifier {
            provider: Arc<rustls::crypto::CryptoProvider>,
            seen: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        }
        impl ClientCertVerifier for RecordingClientVerifier {
            fn root_hint_subjects(&self) -> &[DistinguishedName] {
                &[]
            }

            fn verify_client_cert(
                &self,
                end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _now: UnixTime,
            ) -> std::result::Result<ClientCertVerified, rustls::Error> {
                let spki = crate::warp::subject_public_key_info(end_entity.as_ref())
                    .ok_or_else(|| rustls::Error::General("client cert without SPKI".into()))?;
                self.seen.lock().expect("lock").push(spki.to_vec());
                Ok(ClientCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                rustls::crypto::verify_tls12_signature(
                    message,
                    cert,
                    dss,
                    &self.provider.signature_verification_algorithms,
                )
            }

            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                rustls::crypto::verify_tls13_signature(
                    message,
                    cert,
                    dss,
                    &self.provider.signature_verification_algorithms,
                )
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                self.provider.signature_verification_algorithms.supported_schemes()
            }
        }

        let server_key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("server key");
        let server_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let server_cert = server_params.self_signed(&server_key).expect("self signed");
        let server_spki = server_key.public_key_der();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let seen: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::default();
        let mut server_cfg = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_client_cert_verifier(Arc::new(RecordingClientVerifier {
                provider,
                seen: Arc::clone(&seen),
            }))
            .with_single_cert(
                vec![CertificateDer::from(server_cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .expect("server config");
        server_cfg.alpn_protocols = vec![b"h2".to_vec()];
        // 服务端公钥（WARP pin 的对端）= 客户端 `warp.publicKey` 配置值。
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        let frames: Arc<std::sync::Mutex<Vec<(u8, u8)>>> = Arc::default();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let frames_srv = Arc::clone(&frames);
        #[allow(
            clippy::disallowed_methods,
            reason = "测试基建 server accept 循环（spawn 三分类②），随用随弃"
        )]
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { break };
                let acceptor = acceptor.clone();
                let frames = Arc::clone(&frames_srv);
                #[allow(
                    clippy::disallowed_methods,
                    reason = "测试基建 per-conn server 任务（spawn 三分类②）"
                )]
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else { return };
                    let mut builder =
                        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                    let _ = builder
                        .http2()
                        .enable_connect_protocol()
                        .serve_connection_with_upgrades(
                            TokioIo::new(tls),
                            service_fn(move |req: Request<Incoming>| {
                                let frames = Arc::clone(&frames);
                                async move {
                                    // WARP 形态断言（Go warp_test.go:302-306 同项）。
                                    assert_eq!(req.method(), http::Method::CONNECT);
                                    assert_eq!(
                                        req.uri().authority().map(http::uri::Authority::as_str),
                                        Some("cloudflareaccess.com:443")
                                    );
                                    // 普通 CONNECT 不带 `:path`/`:scheme`（RFC 9113 §8.5）——
                                    // Go 的 http2 客户端同判（TestDialWarpHTTP2 不查 path）。
                                    assert!(
                                        req.uri().path().is_empty(),
                                        "plain CONNECT must not carry :path, got {:?}",
                                        req.uri().path()
                                    );
                                    assert_eq!(
                                        req.headers()
                                            .get("cf-connect-proto")
                                            .and_then(|v| v.to_str().ok()),
                                        Some("cf-connect-ip")
                                    );
                                    assert_eq!(
                                        req.headers()
                                            .get("pq-enabled")
                                            .and_then(|v| v.to_str().ok()),
                                        Some("false")
                                    );
                                    assert!(
                                        req.headers().get("capsule-protocol").is_none(),
                                        "WARP 形态不得带 Capsule-Protocol"
                                    );
                                    assert!(
                                        req.extensions().get::<Protocol>().is_none(),
                                        "WARP 形态不得带 :protocol"
                                    );
                                    let upgrade = hyper::upgrade::on(req);
                                    #[allow(
                                        clippy::disallowed_methods,
                                        reason = "测试基建 upgrade 回声任务（spawn 三分类②）"
                                    )]
                                    tokio::spawn(async move {
                                        let Ok(io) = upgrade.await else { return };
                                        let mut io = TokioIo::new(io);
                                        let mut hdr = [0u8; 2];
                                        loop {
                                            if io.read_exact(&mut hdr).await.is_err() {
                                                return;
                                            }
                                            let mut payload = vec![0u8; usize::from(hdr[1])];
                                            if io.read_exact(&mut payload).await.is_err() {
                                                return;
                                            }
                                            frames.lock().expect("lock").push((hdr[0], payload[0]));
                                            if io.write_all(&hdr).await.is_err()
                                                || io.write_all(&payload).await.is_err()
                                                || io.flush().await.is_err()
                                            {
                                                return;
                                            }
                                        }
                                    });
                                    Ok::<_, std::convert::Infallible>(
                                        Response::builder()
                                            .status(200)
                                            .body(Full::new(Bytes::new()))
                                            .expect("static response"),
                                    )
                                }
                            }),
                        )
                        .await;
                });
            }
        });
        WarpServer { port, server_spki, client_spki: seen, frames }
    }

    /// WARP 变体全链路：`masqueSettings.warp` 解析 → 客户端证书 + 端点公钥 pin +
    /// Cloudflare 头 + 静态地址（无 ADDRESS_REQUEST）+ bare DATAGRAM 收发。
    #[tokio::test]
    async fn dial_warp_loopback_e2e() {
        use base64::Engine as _;
        let server = spawn_warp_server().await;
        let client_key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("client key");

        let masque_cfg = Config::from_json(Some(&serde_json::json!({
            "warp": {
                "privateKey": base64::engine::general_purpose::STANDARD
                    .encode(client_key.serialize_der()),
                "publicKey": base64::engine::general_purpose::STANDARD
                    .encode(&server.server_spki),
                "address": ["172.16.0.2", "fd01::1"],
            }
        })))
        .expect("warp settings must parse");
        assert!(masque_cfg.warp.is_some());
        assert_eq!(masque_cfg.host, crate::warp::WARP_HOST);
        assert_eq!(masque_cfg.path, crate::warp::WARP_PATH);

        let settings = StreamSettings {
            protocol: "masque".into(),
            security: "tls".into(),
            security_json: Some(serde_json::json!({
                "serverName": "localhost",
                "alpn": ["h2"],
            })),
            ..StreamSettings::tcp()
        };
        let dest =
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(server.port));
        let mut session = dial(&dest, &SocketOptions::default(), &settings, &masque_cfg)
            .await
            .expect("warp dial over real TLS");

        // 静态地址（Go establish 的 WARP 分支；无 ADDRESS_REQUEST）。
        let local: Vec<IpAddr> = session.local_addrs().to_vec();
        assert_eq!(
            local,
            vec![
                "172.16.0.2".parse::<IpAddr>().expect("v4"),
                "fd01::1".parse::<IpAddr>().expect("v6"),
            ]
        );

        // 客户端证书确实是 WARP 私钥那张（服务端 SPKI 记录核对）。
        let seen = server.client_spki.lock().expect("lock").clone();
        assert_eq!(seen.len(), 1, "server must receive exactly one client cert");
        assert_eq!(seen[0], client_key.public_key_der());

        // bare DATAGRAM 往返。
        let local4 = std::net::Ipv4Addr::new(172, 16, 0, 2);
        let packet = udp_v4_packet(local4, local4, 64, b"warp");
        assert!(session.send_packet(&packet).await.expect("send").is_none());
        let got = tokio::time::timeout(Duration::from_secs(5), session.recv_packet())
            .await
            .expect("recv within 5s")
            .expect("packet");
        assert_eq!(&got[20 + 8..], b"warp");

        // 帧记录：首帧 = DATAGRAM(0) + 裸 IPv4(0x45)；无 ADDRESS_REQUEST。
        let frames = server.frames.lock().expect("lock").clone();
        assert_eq!(frames, vec![(0u8, 0x45u8)], "no ADDRESS_REQUEST, bare IPv4 payload");
        session.close();
    }

    /// 端点公钥不匹配 ⇒ 握手期 Err（Go `TestDialWarpRejectedKey`）。
    #[tokio::test]
    async fn dial_warp_rejects_mismatched_public_key() {
        use base64::Engine as _;
        let server = spawn_warp_server().await;
        let client_key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("client key");
        let other_key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("other key");
        let masque_cfg = Config::from_json(Some(&serde_json::json!({
            "warp": {
                "privateKey": base64::engine::general_purpose::STANDARD
                    .encode(client_key.serialize_der()),
                "publicKey": base64::engine::general_purpose::STANDARD
                    .encode(other_key.public_key_der()),
                "address": ["172.16.0.2"],
            }
        })))
        .expect("warp settings must parse");
        let settings = StreamSettings {
            protocol: "masque".into(),
            security: "tls".into(),
            security_json: Some(serde_json::json!({
                "serverName": "localhost",
                "alpn": ["h2"],
            })),
            ..StreamSettings::tcp()
        };
        let dest =
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(server.port));
        let err = dial(&dest, &SocketOptions::default(), &settings, &masque_cfg)
            .await
            .expect_err("mismatched warp publicKey must be rejected");
        assert!(
            err.to_string().contains("doesn't match \"publicKey\""),
            "expected WARP pin error, got {err}"
        );
    }
}
