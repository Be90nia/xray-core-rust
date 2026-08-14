//! TCP transport dialer 注册。
//!
//! 对应 Go `transport/internet/tcp/dialer.go`：`init()` 注册
//! `RegisterTransportDialer("tcp", Dial)`。建立裸 TCP 连接后按
//! `streamSettings.security` 包装 TLS / REALITY（对齐 Go `Dial` line 36-102）。

use std::io;
use std::sync::Arc;

use xray_common::net::destination::Destination;
use xray_tls::client_config::build_client_config;
use xray_transport::connection::Connection;
use xray_transport::dialer::{StreamSettings, TransportDialFn, register_transport_dialer};
use xray_transport::sockopt::SocketOptions;

/// 注册 TCP transport dialer（`"tcp"` / `"raw"`）。
///
/// 幂等：重复注册忽略 `AlreadyExists`（对齐其他 transport 的容错）。
/// 必须在 `register_all_transports` 中调用，否则 `dial_with_settings("tcp", ...)`
/// 走 fallback 裸系统拨号（不包装 security）。
pub fn register_dialer() -> io::Result<()> {
    // TransportDialFn 返回 'static future：clone dest/sockopt/settings 进 async move block。
    let dialer: TransportDialFn = Arc::new(move |dest, sockopt, settings| {
        let dest = dest.clone();
        let sockopt = sockopt.clone();
        let settings = settings.clone();
        Box::pin(async move { dial_tcp(&dest, &sockopt, &settings).await })
    });
    // ponytail: 重复注册忽略——主代理与测试可能并发触发注册。
    let _ = register_transport_dialer("tcp", dialer.clone());
    let _ = register_transport_dialer("raw", dialer);
    Ok(())
}

/// 实际拨号：`dial_system` 建裸 TCP → 按 `security` 包装 TLS。
///
/// 对应 Go `tcp/dialer.go::Dial`：`internet.DialSystem` 后 `tls.ConfigFromStreamSettings` 包装。
async fn dial_tcp(
    dest: &Destination,
    sockopt: &SocketOptions,
    settings: &StreamSettings,
) -> io::Result<Box<dyn Connection>> {
    let conn = xray_transport::system_dialer::dial_system(dest, sockopt).await?;
    wrap_security(conn, settings, dest).await
}

/// 按 `settings.security` 包装 TLS / REALITY。`security="none"`（或空）原样返回。
///
/// `security="reality"` 当前 fallback 到标准 TLS 握手并打 warn——完整 REALITY
/// uTLS 握手见 P0 issue #2iu（依赖 RealityConfig 解析 + `u_client`）。
async fn wrap_security(
    conn: Box<dyn Connection>,
    settings: &StreamSettings,
    dest: &Destination,
) -> io::Result<Box<dyn Connection>> {
    // security=none（或空）原样返回。
    if !settings.is_tls() {
        return Ok(conn);
    }
    // security=reality：委托 xray_reality 做 REALITY TLS 握手（session_id/auth_key/cert HMAC）。
    if settings.security == "reality" {
        return xray_reality::register::handshake_over(conn, settings).await;
    }
    // security=tls：标准 rustls 包装。
    let default_sni = dest.address().to_string();
    let sni = resolve_sni(settings, &default_sni);
    let config = build_client_config(&settings.security, settings.security_json.as_ref(), &default_sni)?;
    match config {
        Some(cfg) => {
            let tls_conn = xray_tls::utls::client(conn, &sni, cfg).await?;
            Ok(Box::new(tls_conn))
        }
        None => Ok(conn),
    }
}

/// 解析 SNI：优先 `security_json.serverName`，fallback 目标地址（对齐 Go `WithDestination`）。
fn resolve_sni(settings: &StreamSettings, default_sni: &str) -> String {
    settings
        .security_json
        .as_ref()
        .and_then(|v| v.as_object())
        .and_then(|m| m.get("serverName"))
        .and_then(|v| v.as_str())
        .unwrap_or(default_sni)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_sni_uses_settings_servername() {
        let mut s = StreamSettings::tcp();
        s.security = "tls".to_string();
        s.security_json = Some(serde_json::json!({"serverName": "example.com"}));
        assert_eq!(resolve_sni(&s, "1.2.3.4"), "example.com");
    }

    #[test]
    fn resolve_sni_falls_back_to_dest() {
        let s = StreamSettings::tcp();
        assert_eq!(resolve_sni(&s, "1.2.3.4"), "1.2.3.4");
    }
}
