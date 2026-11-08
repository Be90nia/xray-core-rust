//! TCP transport dialer 注册。
//!
//! 对应 Go `transport/internet/tcp/dialer.go`：`init()` 注册
//! `RegisterTransportDialer("tcp", Dial)`。建立裸 TCP 连接后按
//! `streamSettings.security` 包装 TLS / REALITY（对齐 Go `Dial` line 36-102）。
//!
//! **红线触碰记录（2026-11-08）**：本文件属 CLAUDE.md §4 红线表条目，本次改动依据
//! 用户「修吧」授权 + bd k2tq1 裁定：注册失败由 `let _ =` 静默丢弃改为
//! `ignore_already_exists(...)?` 上抛（fail-visible——静默失败会让
//! `dial_with_settings` 落裸 TCP fallback 且跳过安全层）。改动仅 `register_dialer`
//! 的两处注册调用，拨号路径未动；状态口径见 CLAUDE.md §4 同条。

use std::{io, sync::Arc};

use xray_common::net::destination::Destination;
use xray_tls::client_config::build_client_config;
use xray_transport::{
    connection::Connection,
    dialer::{StreamSettings, TransportDialFn, register_transport_dialer},
    ignore_already_exists,
    sockopt::SocketOptions,
};

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
    // 幂等放行 `AlreadyExists`（并发/多入口重复注册），其余失败上抛——禁 `let _ =`
    // （bd k2tq1：注册静默失败 ⇒ `dial_with_settings` 走裸 TCP fallback，安全层被跳过）。
    ignore_already_exists(register_transport_dialer("tcp", dialer.clone()))?;
    ignore_already_exists(register_transport_dialer("raw", dialer))?;
    Ok(())
}

/// 实际拨号：`dial_system` 建裸 TCP → 按 finalmask 包装 → 按 `security` 包装 TLS
/// → 按 `header` 包装伪装。
///
/// 对应 Go `tcp/dialer.go::Dial`：mask 取代 `internet.DialSystem`（line 26-32，
/// 即 mask 在安全层**之内**），再 `tls` 包装（line 36-102），
/// 再 `HeaderSettings` → `ConnectionAuthenticator.Client(conn)`（line 104-115）。
async fn dial_tcp(
    dest: &Destination,
    sockopt: &SocketOptions,
    settings: &StreamSettings,
) -> io::Result<Box<dyn Connection>> {
    let conn = xray_transport::system_dialer::dial_system(dest, sockopt).await?;
    // Tcpmask 装配（Go tcp/dialer.go:26-32：`FinalMask.DialTCP` **取代**
    // `DialSystem`）⇒ mask 包住裸 socket，TLS/REALITY 跑在 mask **之上**，握手
    // 字节也过 mask。服务端同侧：hub.rs `WrapConnServer` 在 accept 即解包、TLS 在其上
    // （Go hub.go `FinalMask.Listen` 取代 `ListenSystem`）。次序反了（mask 在安全层
    // 外 = 吃明文、服务端吃密文）⇒ 首帧即不匹配，tcp+finalmask+tls 组合不可用（bd 1jt9v）。
    let mgr = xray_transport::finalmask::build_tcpmask_manager_from_json(
        settings.finalmask_json.as_ref(),
    )?;
    let conn: Box<dyn Connection> = if !mgr.tcpmasks.is_empty() {
        xray_transport::finalmask::wrap_conn_client_into_connection(&mgr, conn)?
    } else {
        conn
    };
    // 记录对齐读钳制（bd VISIONMAC）：TLS/REALITY 层 deframer 贪婪 recv 会在
    // vision DIRECT 切换窗口把「DIRECT 帧 + 对端 raw 字节」一并拉进 TLS 层
    // （半条记录滞留 opaque 缓冲 → 切 raw 后字节永久不可达 → 下游停滞）。
    // framer 让安全层每次 recv 恰好消费一条完整记录，DIRECT 帧后的 socket
    // 游标精确停在记录边界，raw 克隆天然续读完整裸流（等价 Go readFromUntil
    // + UnwrapRawConn 反射回收组合，无需 unsafe）。位置：mask 之上、安全层之下
    // ——它钳制的是 mask 解包后的 TLS 记录流。
    let conn: Box<dyn Connection> = if settings.is_tls() {
        Box::new(xray_transport::record_framer::RecordFramer::new(conn))
    } else {
        conn
    };
    let conn = wrap_security(conn, settings, dest).await?;
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
    // 未知/已移除 security 硬错（Go transport_internet.go:129-132），此前 xtls 等
    // 非法值经 is_tls()==false 静默裸连。
    settings.validate_security()?;
    // security=none（或空）原样返回。
    if !settings.is_tls() {
        return Ok(conn);
    }
    // security=reality：委托 xray_reality 做 REALITY TLS 握手（session_id/auth_key/cert HMAC）。
    if settings.security == "reality" {
        return xray_reality::register::handshake_over(conn, settings).await;
    }
    // security=tls：恒走 `u_client`（btls 真实指纹）。Go `GetFingerprint("")` =
    // `HelloChrome_Auto`——未配 fingerprint 也发 Chrome uTLS hello；此前 Rust 缺省落
    // rustls 原生 hello（252B、无 GREASE），DPI 可一眼判定（bd qscjv）。
    let default_sni = dest.address().to_string();
    let sni = resolve_sni(settings, &default_sni);
    let config =
        build_client_config(&settings.security, settings.security_json.as_ref(), &default_sni)?;
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
            // 空串 → `Fingerprint::Chrome`（Go `GetFingerprint("")`）；清单外硬错。
            let fp = xray_tls::fingerprint::get_fingerprint(fp_name)
                .map_err(|e| io::Error::other(format!("invalid fingerprint: {e}")))?;
            // ALPN 显式按配置重写（Go 也按 `tlsSettings.alpn` 发；缺省 ["h2","http/1.1"]），
            // 否则 btls 会用模板 ALPN 忽略用户配置。
            let alpn = cfg.alpn_protocols.clone();
            let tls_conn = xray_tls::utls::u_client_with_alpn(
                conn,
                &sni,
                cfg,
                fp,
                ech,
                settings.security_json.as_ref(),
                Some(&alpn),
            )
            .await?;
            Ok(Box::new(tls_conn))
        },
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
