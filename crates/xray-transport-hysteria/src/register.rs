//! Hysteria transport dialer + listener 注册。
//!
//! dialer: 完整拨号流程——解析配置 → TLS → QuinnHysteriaTransport → HysteriaClient → HysteriaConn。
//! listener: TLS ServerConfig → QuinnListenerFactory → accept loop → HysteriaConn。

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use xray_transport::connection::Connection;
use xray_transport::dialer::{StreamSettings, TransportDialFn, register_transport_dialer};
use xray_transport::listener_registry::{
    ConnHandler, TransportListener, TransportListenFn, register_transport_listener,
};
use xray_transport::sockopt::SocketOptions;

use crate::conn::{HysteriaConn, InterStreamConn, QuicConn, QuicStream};
use crate::dialer::{DialDestination, HysteriaClient};
use crate::hysteria_transport::QuinnHysteriaTransport;
use crate::proto_config::Config;
use crate::PROTOCOL_NAME;
use crate::hub::{HysteriaListenerFactory, HysteriaQuicListener, MasqType};
use crate::quinn_adapter::{QuinnListenerFactory, QuinnQuicStream};
use xray_proto::xray::transport::internet::QuicParams;

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
/// 3. spawn accept 循环：每条 QUIC conn → `accept_bi` 取 client-initiated bi-stream
///    → `QuinnQuicStream` → `InterStreamConn`（server 模式）→ `HysteriaConn` → handler
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
/// 实际 QUIC endpoint 由 spawned accept task 持有；task 退出（accept 失败）时 endpoint drop 即关闭。
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

    // 2. QuinnListenerFactory → listen
    let factory = QuinnListenerFactory::new(tls_cfg);
    let config = Arc::new(parse_hysteria_config(settings.transport_json.as_ref())?);
    let quic_params = Arc::new(QuicParams::default());
    // ponytail: factory 当前忽略 masq/validator/on_new_conn；后续接 HTTP/3 auth/masquerade 时再注入
    let on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync> = Arc::new(|_| {});
    let listener = factory
        .listen(
            addr,
            config,
            quic_params,
            MasqType::NotFound,
            None,
            on_new_conn,
        )
        .await
        .map_err(|e| io::Error::other(format!("hysteria listen bind failed: {e}")))?;

    let local = listener.local_addr();

    // 3. spawn accept loop
    tokio::spawn(async move {
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

    Ok(Box::new(HysteriaTransportListener { local }))
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
        let stream: Arc<dyn QuicStream> =
            Arc::new(QuinnQuicStream::new(send, recv, local, remote));
        let inter = Arc::new(InterStreamConn::new(stream, local, remote, false));
        handler(Box::new(HysteriaConn::new(inter)));
    }
}

/// Hysteria transport listener 句柄。
///
/// 仅记录 `local_addr`；QUIC endpoint 由 spawned accept task 持有，
/// `close()` 不做实际关闭（task 退出时 endpoint drop 即关闭）。
struct HysteriaTransportListener {
    local: SocketAddr,
}

impl TransportListener for HysteriaTransportListener {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn close(&self) -> io::Result<()> {
        tracing::info!("hysteria listener close addr={}", self.local);
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
        }
    };

    // 3. 构造 dest（hysteria 用 UDP，需从 TCP dest 转换）
    let dest_addr = resolve_dest_to_socket_addr(dest)?;
    let dial_dest = DialDestination {
        udp_addr: dest_addr,
        host: default_sni.clone(),
    };

    // 4. 创建 transport + client
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().map_err(|e: std::net::AddrParseError| {
        io::Error::other(format!("invalid bind addr: {e}"))
    })?;
    let transport = QuinnHysteriaTransport::new(tls_client_config, bind_addr)?;

    let quic_params = Arc::new(xray_proto::xray::transport::internet::QuicParams::default());
    let client = HysteriaClient::new(
        dial_dest,
        Arc::new(config),
        quic_params,
        Arc::new(transport),
    );

    // 5. 建立连接 → HysteriaConn（已实现 AsyncRead + AsyncWrite + Connection）
    let conn = client.tcp().await.map_err(|e| {
        io::Error::other(format!("hysteria dial failed: {e}"))
    })?;

    Ok(Box::new(HysteriaConn::new(conn)))
}

/// 从 `hysteriaSettings` JSON 解析为 prost [`Config`]。
///
/// 接受的 JSON 字段（对齐 proto3 JSON camelCase）：
/// - `auth`：鉴权 token
/// - `masqType`：伪装类型
/// - `udpIdleTimeout`：UDP 空闲超时（秒）
/// - `version`：协议版本
///
/// `None` 返回默认配置。
fn parse_hysteria_config(json: Option<&serde_json::Value>) -> io::Result<Config> {
    let Some(v) = json else { return Ok(crate::proto_config::default_config()); };
    let Some(obj) = v.as_object() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hysteriaSettings must be a JSON object",
        ));
    };

    let auth = obj
        .get("auth")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let masq_type = obj
        .get("masqType")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let udp_idle_timeout = obj
        .get("udpIdleTimeout")
        .and_then(|x| x.as_i64())
        .unwrap_or(60);
    let version = obj
        .get("version")
        .and_then(|x| x.as_i64())
        .unwrap_or(0) as i32;

    Ok(Config {
        auth,
        masq_type,
        udp_idle_timeout,
        version,
        ..Config::default()
    })
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
        }
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
        let v: serde_json::Value = serde_json::from_str(
            r#"{"auth":"my-token","udpIdleTimeout":120,"version":2}"#,
        )
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
}
