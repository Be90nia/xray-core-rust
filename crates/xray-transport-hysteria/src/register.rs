//! Hysteria transport dialer + listener 注册。
//!
//! dialer: 完整拨号流程——解析配置 → TLS → QuinnHysteriaTransport → HysteriaClient → HysteriaConn。
//! listener: TLS ServerConfig → QuinnListenerFactory → accept loop → HysteriaConn。

use std::{future::Future, io, net::SocketAddr, pin::Pin, sync::Arc};

use xray_proto::xray::transport::internet::QuicParams;
use xray_transport::{
    connection::Connection,
    dialer::{StreamSettings, TransportDialFn, register_transport_dialer},
    listener_registry::{
        ConnHandler, TransportListenFn, TransportListener, register_transport_listener,
    },
    sockopt::SocketOptions,
};

use crate::{
    PROTOCOL_NAME,
    conn::{HysteriaConn, InterStreamConn, QuicConn, QuicStream},
    dialer::{DialDestination, HysteriaClient},
    hub::{HysteriaListenerFactory, HysteriaQuicListener, MasqType},
    hysteria_transport::QuinnHysteriaTransport,
    proto_config::Config,
    quinn_adapter::{QuinnListenerFactory, QuinnQuicStream},
};

/// 注册 Hysteria transport dialer。
///
/// 完整拨号流程：
/// 1. 解析 `hysteriaSettings` JSON → hysteria `Config`
/// 2. 从 `security`/`security_json` 构建 TLS `ClientConfig`
/// 3. 创建 `QuinnHysteriaTransport`（quinn + h3 auth）
/// 4. 创建 `HysteriaClient` → `client.tcp()` → `HysteriaConn`
///
/// 幂等：重复注册的 `AlreadyExists` 被忽略。
pub fn register_dialer() -> io::Result<()> {
    let dialer: TransportDialFn = Arc::new(move |dest, _sockopt, settings| {
        let dest = dest.clone();
        let settings = settings.clone();
        Box::pin(async move { dial_hysteria(&dest, &settings).await })
    });
    let _ = register_transport_dialer(PROTOCOL_NAME, dialer);
    Ok(())
}

/// 注册 Hysteria transport listener。
///
/// 监听流程：
/// 1. 从 `streamSettings.security` 构建 TLS `ServerConfig`
/// 2. 创建 `QuinnListenerFactory` → `factory.listen()` 得到 `HysteriaQuicListener`
/// 3. spawn accept 循环：每条 QUIC conn → `accept_bi` 取 client-initiated bi-stream →
///    `QuinnQuicStream` → `InterStreamConn`（server 模式）→ `HysteriaConn` → handler
///
/// 幂等：重复注册的 `AlreadyExists` 被忽略。
pub fn register_listener() -> io::Result<()> {
    let listen_fn: TransportListenFn = Arc::new(move |addr, settings, _sockopt, handler| {
        Box::pin(async move { listen_hysteria(addr, settings, handler).await })
    });
    let _ = register_transport_listener(PROTOCOL_NAME, listen_fn);
    Ok(())
}

/// 监听 + spawn accept 循环。
///
/// 同 gRPC 模式：返回的 `TransportListener` 仅记录 `local_addr`，
/// 实际 QUIC endpoint 由 spawned accept task 持有；task 退出（accept 失败）时 endpoint drop
/// 即关闭。
async fn listen_hysteria(
    addr: SocketAddr,
    settings: StreamSettings,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    // 1. TLS server config（hysteria 强制 TLS）
    let tls_cfg = xray_tls::server_config::build_server_config(
        &settings.security,
        settings.security_json.as_ref(),
    )?
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "hysteria listener requires TLS (streamSettings.security must be \"tls\" or \"reality\")",
        )
    })?;

    // UDP 混淆 salamander/gecko（Go hysteria/hub.go:301-306：`UdpmaskManager.
    // WrapPacketConnServer` 包装 pktConn 后再交给 quic.Transport.Listen；
    // Rust 经 quinn AsyncUdpSocket 注入，finalmask_json.udp[].salamander 配置，
    // settings.packetSize 切 Gecko 分片模式）。
    let factory = QuinnListenerFactory::new(tls_cfg).with_obfs(
        crate::salamander_socket::parse_udp_obfs(settings.finalmask_json.as_ref())?,
    );
    let config = Arc::new(parse_hysteria_config(settings.transport_json.as_ref())?);
    let quic_params = Arc::new(
        crate::quic_params::parse_quic_params(settings.finalmask_json.as_ref())?
            .unwrap_or_else(crate::quic_params::default_hysteria_quic_params),
    );
    // masq 从 proto Config 解析（masquerade JSON 已由 parse_hysteria_config 展开；
    // 对应 Go hub.go:210-254 listen 时 switch masqType）
    let masq = MasqType::from_config(&config)
        .map_err(|e| io::Error::other(format!("hysteria masq config: {e}")))?;
    // ponytail: 此链（transport registry）无 validator 注入点，静态 auth 由
    // factory.listen 内部用 config.auth 兜底（Go hub.go:63-64 config.Auth 对比）
    let on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync> = Arc::new(|_| {});
    let listener = factory
        .listen(addr, config, quic_params, masq, None, on_new_conn, None)
        .await
        .map_err(|e| io::Error::other(format!("hysteria listen bind failed: {e}")))?;

    let local = listener.local_addr();

    // 3. spawn accept loop。listener 句柄持 endpoint（Arc clone）+ abort 句柄：
    // close() 先 abort 本循环，再触发 HysteriaQuicListener::close()（ep.close 强杀
    // QUIC 栈——factory.listen 内层的 accept 循环因此 accept None 退出，endpoint
    // 全部 clone 归零，driver 停、UDP socket 关、端口释放。修复前 close() 仅日志，
    // endpoint 永不释放成幽灵 inbound，对齐 Go hub.go Close=listener+tr.Close）。
    let quic_listener = listener.clone();

    let accept_task = tokio::spawn(async move {
        loop {
            let conn = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            let h = handler.clone();
            tokio::spawn(async move {
                accept_hysteria_conn(conn, h).await;
            });
        }
    });

    Ok(Box::new(HysteriaTransportListener {
        local,
        listener: quic_listener,
        abort: accept_task.abort_handle(),
    }))
}

/// 单条 QUIC conn 内的 accept_bi 循环：把 client-initiated bi-stream 桥到 handler。
///
/// server 端不主动 open_bi——等客户端开 stream 后 accept_bi 取回。
async fn accept_hysteria_conn(conn: Arc<dyn QuicConn>, handler: ConnHandler) {
    let quinn_conn = match conn.as_quinn_connection() {
        Some(c) => c.clone(),
        None => return,
    };
    let local = conn.local_addr();
    let remote = conn.remote_addr();

    loop {
        let (send, recv) = match quinn_conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => break,
        };
        let stream: Arc<dyn QuicStream> = Arc::new(QuinnQuicStream::new(send, recv, local, remote));
        let frame_type = match crate::conn::read_varint_stream(&*stream).await {
            Ok(value) => value,
            Err(_) => {
                let _ = stream.cancel_read(0x101);
                continue;
            },
        };
        if frame_type != crate::config::FrameTypeTCPRequest {
            let _ = stream.cancel_read(0x101);
            continue;
        }
        let inter = Arc::new(InterStreamConn::new(stream, local, remote, false));
        handler(Box::new(HysteriaConn::new(inter)));
    }
}

/// Hysteria transport listener 句柄。
///
/// 持 QUIC endpoint（`HysteriaQuicListener` Arc clone）+ accept task abort 句柄；
/// `close()` 二者皆触发，确定性释放端口。
struct HysteriaTransportListener {
    local: SocketAddr,
    listener: Arc<dyn HysteriaQuicListener>,
    abort: tokio::task::AbortHandle,
}

impl TransportListener for HysteriaTransportListener {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn close(&self) -> io::Result<()> {
        tracing::info!("hysteria listener close addr={}", self.local);
        self.abort.abort();
        // trait close 是 async（内部 ep.close 同步生效）；TransportListener::close
        // 是同步 fn，spawn 之。调用方均在 runtime 上下文（生产 instance close / 测试）。
        let l = self.listener.clone();
        tokio::spawn(async move {
            let _ = l.close().await;
        });
        Ok(())
    }
}

/// 实际拨号：解析配置 → TLS → QuinnHysteriaTransport → HysteriaClient → HysteriaConn。
async fn dial_hysteria(
    dest: &xray_common::net::destination::Destination,
    settings: &StreamSettings,
) -> io::Result<Box<dyn Connection>> {
    // 1. 解析 hysteriaSettings JSON
    let config = parse_hysteria_config(settings.transport_json.as_ref())?;

    // 2. TLS 配置
    let default_sni = dest.address().to_string();
    let tls_config = xray_tls::client_config::build_client_config(
        &settings.security,
        settings.security_json.as_ref(),
        &default_sni,
    )?;

    let tls_client_config = match tls_config {
        Some(c) => rustls::ClientConfig::clone(&c),
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria requires TLS (streamSettings.security must be \"tls\" or \"reality\")",
            ));
        },
    };

    // 3. 构造 dest（hysteria 用 UDP，需从 TCP dest 转换）
    let dest_addr = resolve_dest_to_socket_addr(dest)?;
    let dial_dest = DialDestination { udp_addr: dest_addr, host: default_sni.clone() };
    // 4. 创建 transport + client
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().map_err(|e: std::net::AddrParseError| {
        io::Error::other(format!("invalid bind addr: {e}"))
    })?;
    // UDP 混淆 salamander/gecko（Go hysteria/dialer.go:170-175：`UdpmaskManager.
    // WrapPacketConnClient` 包装 pktConn 后再交给 quic.Transport.DialEarly）。
    let transport = QuinnHysteriaTransport::new(tls_client_config, bind_addr)?.with_obfs(
        crate::salamander_socket::parse_udp_obfs(settings.finalmask_json.as_ref())?,
    );
    let quic_params = Arc::new(
        crate::quic_params::parse_quic_params(settings.finalmask_json.as_ref())?
            .unwrap_or_else(crate::quic_params::default_hysteria_quic_params),
    );
    let client = HysteriaClient::new(dial_dest, Arc::new(config), quic_params, Arc::new(transport));
    let target_addr = match dest.address() {
        xray_common::net::address::Address::Domain(host) => {
            xray_common::net::address::Address::new_domain(host)
        },
        xray_common::net::address::Address::IPv4(ip) => {
            xray_common::net::address::Address::IPv4(*ip)
        },
        xray_common::net::address::Address::IPv6(ip) => {
            xray_common::net::address::Address::IPv6(*ip)
        },
    };
    let conn = client
        .tcp(&target_addr, dest.port())
        .await
        .map_err(|e| io::Error::other(format!("hysteria dial failed: {e}")))?;

    Ok(Box::new(HysteriaConn::new(conn)))
}

/// 从 `hysteriaSettings` JSON 解析为 prost [`Config`]。
///
/// 接受的 JSON 字段：
/// - `auth`：鉴权 token
/// - `masqType`：伪装类型（proto3 JSON camelCase 兼容）
/// - `masquerade`：伪装配置嵌套对象（Go 用户配置形态，infra/conf transport_internet.go:498-510
///   `Masquerade` struct → :542-549 展开为 proto 扁平字段）
/// - `udpIdleTimeout`：UDP 空闲超时（秒）
/// - `version`：协议版本
///
/// `None` 返回默认配置。
fn parse_hysteria_config(json: Option<&serde_json::Value>) -> io::Result<Config> {
    let Some(v) = json else {
        return Ok(crate::proto_config::default_config());
    };
    let Some(obj) = v.as_object() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hysteriaSettings must be a JSON object",
        ));
    };

    let auth = obj.get("auth").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let masq_type = obj.get("masqType").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let udp_idle_timeout = obj.get("udpIdleTimeout").and_then(|x| x.as_i64()).unwrap_or(60);
    let version = obj.get("version").and_then(|x| x.as_i64()).unwrap_or(0) as i32;

    let mut config = Config { auth, masq_type, udp_idle_timeout, version, ..Config::default() };
    if let Some(m) = obj.get("masquerade") {
        crate::proto_config::apply_masquerade_json(&mut config, m)?;
    }
    Ok(config)
}

/// 把 `Destination` 解析为 `SocketAddr`（hysteria 强制 UDP，需 IP:port）。
///
/// 域名地址返回 `InvalidInput` 错误（QUIC 要求 IP 地址）。
fn resolve_dest_to_socket_addr(
    dest: &xray_common::net::destination::Destination,
) -> io::Result<SocketAddr> {
    use xray_common::net::address::Address;
    let ip = match dest.address() {
        Address::IPv4(ip) => std::net::IpAddr::V4(*ip),
        Address::IPv6(ip) => std::net::IpAddr::V6(*ip),
        Address::Domain(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria requires IP address destination (domain not supported yet, needs DNS resolution)",
            ));
        },
    };
    Ok(SocketAddr::new(ip, dest.port().value()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_dialer_is_idempotent() {
        register_dialer().expect("first register ok");
        register_dialer().expect("second register ok (idempotent)");
    }

    #[test]
    fn parse_hysteria_config_none_returns_default() {
        let cfg = parse_hysteria_config(None).unwrap();
        assert_eq!(cfg.auth, "");
        assert_eq!(cfg.udp_idle_timeout, 60);
    }

    #[test]
    fn parse_hysteria_config_basic_fields() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"auth":"my-token","udpIdleTimeout":120,"version":2}"#)
                .unwrap();
        let cfg = parse_hysteria_config(Some(&v)).unwrap();
        assert_eq!(cfg.auth, "my-token");
        assert_eq!(cfg.udp_idle_timeout, 120);
        assert_eq!(cfg.version, 2);
    }

    #[test]
    fn parse_hysteria_config_non_object_returns_err() {
        let v: serde_json::Value = serde_json::from_str(r#""not-an-object""#).unwrap();
        let r = parse_hysteria_config(Some(&v));
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    /// masquerade 嵌套对象 → proto 扁平字段（Go infra/conf transport_internet.go:498-510
    /// + 542-549 展开）。四类形态各验一遍 + `MasqType::from_config` 回读等价。
    #[test]
    fn parse_hysteria_config_masquerade_object() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"auth":"t","masquerade":{"type":"file","dir":"/var/www"}}"#)
                .unwrap();
        let cfg = parse_hysteria_config(Some(&v)).unwrap();
        assert_eq!(cfg.masq_type, "file");
        assert_eq!(cfg.masq_file, "/var/www");
        assert_eq!(MasqType::from_config(&cfg).unwrap(), MasqType::File("/var/www".into()));

        let v: serde_json::Value = serde_json::from_str(
            r#"{"masquerade":{"type":"proxy","url":"https://e.com","rewriteHost":true,"insecure":true}}"#,
        )
        .unwrap();
        let cfg = parse_hysteria_config(Some(&v)).unwrap();
        assert!(cfg.masq_url_rewrite_host);
        assert!(cfg.masq_url_insecure);
        assert!(matches!(
            MasqType::from_config(&cfg).unwrap(),
            MasqType::Proxy { url, rewrite_host: true, insecure: true } if url == "https://e.com"
        ));

        let v: serde_json::Value = serde_json::from_str(
            r#"{"masquerade":{"type":"string","content":"hi","headers":{"X-A":"1"},"statusCode":418}}"#,
        )
        .unwrap();
        let cfg = parse_hysteria_config(Some(&v)).unwrap();
        assert_eq!(cfg.masq_string, "hi");
        assert_eq!(cfg.masq_string_headers.get("X-A").unwrap(), "1");
        assert_eq!(cfg.masq_string_status_code, 418);
        assert!(matches!(
            MasqType::from_config(&cfg).unwrap(),
            MasqType::String { body, status_code: 418, .. } if body == "hi"
        ));
    }

    /// 无 masquerade 键 → 字段保持默认（零行为变化）。
    #[test]
    fn parse_hysteria_config_no_masquerade_untouched() {
        let v: serde_json::Value = serde_json::from_str(r#"{"auth":"t"}"#).unwrap();
        let cfg = parse_hysteria_config(Some(&v)).unwrap();
        assert_eq!(cfg.masq_type, "");
        assert_eq!(MasqType::from_config(&cfg).unwrap(), MasqType::NotFound);
    }
    /// close() abort accept task → endpoint drop，新 QUIC 握手失败
    /// （票 4kjs 回归锚：修复前 close() 仅日志，endpoint 永远存活，connect 一直成功）。
    #[tokio::test]
    async fn close_rejects_new_connections() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        let settings = StreamSettings {
            protocol: "hysteria".into(),
            security: "tls".into(),
            ..Default::default()
        };
        let handler: ConnHandler = Arc::new(|_| {});
        let listener = listen_hysteria("127.0.0.1:0".parse().unwrap(), settings, handler)
            .await
            .expect("listen_hysteria");
        let addr = listener.local_addr().unwrap();

        listener.close().unwrap();

        // quinn 客户端（h3 ALPN + allowInsecure + 1s idle）连接必须失败。
        let client_tls = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({"allowInsecure": true, "alpn": ["h3"]})),
            "127.0.0.1",
        )
        .unwrap()
        .expect("client tls config");
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(1_000))));
        let mut quic_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        ));
        quic_cfg.transport_config(Arc::new(transport));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quic_cfg);

        let result = endpoint.connect(addr, "127.0.0.1").unwrap().await;
        assert!(result.is_err(), "post-close connect must fail");
        endpoint.close(0u32.into(), b"test done");
    }
}
