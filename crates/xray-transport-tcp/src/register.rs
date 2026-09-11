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

/// 实际拨号：`dial_system` 建裸 TCP → 按 `security` 包装 TLS → 按 `header` 包装伪装。
///
/// 对应 Go `tcp/dialer.go::Dial`：`internet.DialSystem` 后 `tls` 包装（line 36-102），
/// 再 `HeaderSettings` → `ConnectionAuthenticator.Client(conn)`（line 104-115）。
async fn dial_tcp(
    dest: &Destination,
    sockopt: &SocketOptions,
    settings: &StreamSettings,
) -> io::Result<Box<dyn Connection>> {
    let conn = xray_transport::system_dialer::dial_system(dest, sockopt).await?;
    let conn = wrap_security(conn, settings, dest).await?;
    // Tcpmask 装配（Go tcp/dialer.go:28 WrapConnClient）：finalmask_json.tcp[] 每条 mask
    // 链式 WrapConnClient；无 mask / 空数组 → 跳过（向后兼容）。
    let mgr = xray_transport::finalmask::build_tcpmask_manager_from_json(
        settings.finalmask_json.as_ref(),
    )?;
    let conn: Box<dyn Connection> = if !mgr.tcpmasks.is_empty() {
        xray_transport::finalmask::wrap_conn_client_into_connection(&mgr, conn)?
    } else {
        conn
    };
    // header 伪装装配（Go tcp/dialer.go:105-115，TLS 之后）：
    // `tcpSettings.header.type = "http"` → client 包装；`"none"`/缺失 → 不包装。
    if let Some(auth) =
        xray_transport::headers::conn::auth_from_json(settings.transport_json.as_ref())?
    {
        return Ok(xray_transport::headers::conn::wrap_client(conn, &auth));
    }
    Ok(conn)
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
    // security=tls：有 fingerprint 或 ECH 用 u_client（btls 真实指纹），否则标准 rustls。
    let default_sni = dest.address().to_string();
    let sni = resolve_sni(settings, &default_sni);
    let config = build_client_config(&settings.security, settings.security_json.as_ref(), &default_sni)?;
    match config {
        Some(cfg) => {
            // 解析 fingerprint 字段（对齐 Go tls.ConfigFromStreamSettings → GetFingerprint）。
            let fp_name = settings
                .security_json
                .as_ref()
                .and_then(|v| v.as_object())
                .and_then(|m| m.get("fingerprint"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // ECH config list（对齐 Go ApplyECH client 分支；ECH 仅 btls 后端支持）。
            let json = settings.security_json.clone().unwrap_or(serde_json::Value::Null);
            let ech_list = xray_tls::ech::parse_ech_config_list(&json);
            let ech = (!ech_list.is_empty()).then_some(ech_list.as_str());
            if !fp_name.is_empty() {
                let fp = xray_tls::fingerprint::get_fingerprint(fp_name)
                    .map_err(|e| io::Error::other(format!("invalid fingerprint: {e}")))?;
                let tls_conn =
                    xray_tls::utls::u_client(conn, &sni, cfg, fp, ech, settings.security_json.as_ref()).await?;
                Ok(Box::new(tls_conn))
            } else if ech.is_some() {
                // Go 端 ECH 不依赖 fingerprint（stdlib 原生）；Rust 端 ECH 仅 btls 可用，
                // 未指定 fingerprint 时用默认 Chrome 指纹走 btls，保 ECH 生效。
                tracing::warn!(
                    target: "xray_transport_tcp",
                    "ECH enabled without fingerprint; using default Chrome fingerprint via btls"
                );
                let tls_conn = xray_tls::utls::u_client(
                    conn,
                    &sni,
                    cfg,
                    xray_tls::fingerprint::Fingerprint::Chrome,
                    ech,
                    settings.security_json.as_ref(),
                )
                .await?;
                Ok(Box::new(tls_conn))
            } else {
                let tls_conn = xray_tls::utls::client(conn, &sni, cfg).await?;
                Ok(Box::new(tls_conn))
            }
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
