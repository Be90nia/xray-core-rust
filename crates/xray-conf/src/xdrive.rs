//! xdrive transport 专项校验——Go `infra/conf/xray.go:273-319 validateXDrive` 同款 lint。
//!
//! Go 在 inbound/outbound Build 之后逐条目调用（入站 `:216`、出站 `:399`），仅当
//! `streamSettings` 协议名为 xdrive 时生效；Rust 侧挂在 [`crate::init::ValidationStage`]
//! （配置装载期，先于 xray-core 协议解析），非 xdrive 网络恒 `Ok(())`。
//!
//! 规则（与 Go 逐条对齐，文案逐字）：
//! - 出站：① `flow` 拒 ② `encryption` 无 ENC 拒 ③ 非 reverse 时强制 mux 开启 （enabled 且
//!   concurrency/xudpConcurrency 非负且 `xudpProxyUDP443 != "skip"`） ④ `testpre` 拒；reverse 自开
//!   mux 是 ③ 的例外（Go `:292`：`account.Reverse != nil` 即算，`"reverse": {}` 亦然）。
//! - 入站：⑤ `decryption` 无 ENC 拒、任一 user `flow` 拒、多端口拒。
//! - 其他协议：`the xdrive transport can only be used by VLESS`。
//!
//! ENC 判定复用 `xray_proxy_vless::encryption` 解析器（禁另写一份）。语义差异登记：
//! Go 只对 `== "none"` 判否，空串/畸形 ENC 由 VLESS Build 兜底硬错；Rust 在 lint 期用
//! 解析器判 `None`，同一批配置（none/空/畸形）统一以 xdrive 文案更早拒掉——净行为
//! 等价（配置都无法启动），报错更点名。
//!
//! 出站 user 取址对齐 Go Build：vnext 形式取 `vnext[0].users[0]`（Go 只取第一个）；
//! 扁平形式（顶层 address，Go vless.go:263-271）读 settings 顶层字段。

use skeleton::lint::LintError;
use xray_proxy_vless::encryption::{parse_client_encryption, parse_server_decryption};

use crate::{common::PortList, config::MuxConfig};

/// 校验单个 inbound/outbound 条目的 xdrive 专项约束（非 xdrive 网络恒 `Ok(())`）。
pub fn validate_xdrive(
    kind: &str,
    tag: &str,
    protocol: &str,
    settings: Option<&serde_json::Value>,
    stream_settings: Option<&serde_json::Value>,
    mux: Option<&MuxConfig>,
    ports: Option<&PortList>,
) -> Result<(), LintError> {
    // Go `:275-277`：ss == nil 或协议名非 xdrive → 直接放行。method 优先于 network
    // （Go transport_internet.go:85-88 同款取法）。
    let net = stream_settings
        .and_then(|ss| ss.get("method").or_else(|| ss.get("network")))
        .and_then(|v| v.as_str());
    let Some(net) = net else { return Ok(()) };
    if !net.eq_ignore_ascii_case("xdrive") {
        return Ok(());
    }
    if !protocol.eq_ignore_ascii_case("vless") {
        return Err(lint_err(kind, tag, "the xdrive transport can only be used by VLESS"));
    }
    // streamSettings.port（fronting 端口，Go StreamConfig.Port uint16）：非整数/越界
    // 硬错（Go 是 JSON unmarshal 硬错；B0 放开 address/port 硬拒后的配套门）。
    if let Some(p) = stream_settings.and_then(|ss| ss.get("port")).filter(|v| !v.is_null()) {
        if p.as_u64().and_then(|v| u16::try_from(v).ok()).is_none() {
            return Err(lint_err(
                kind,
                tag,
                "streamSettings.port must be an integer in 0..=65535 (xdrive fronting)",
            ));
        }
    }
    match kind {
        "outbound" => validate_outbound(kind, tag, settings, mux),
        "inbound" => validate_inbound(kind, tag, settings, ports),
        _ => Ok(()),
    }
}

/// 出站四条规则（Go `:279-299`）。
fn validate_outbound(
    kind: &str,
    tag: &str,
    settings: Option<&serde_json::Value>,
    mux: Option<&MuxConfig>,
) -> Result<(), LintError> {
    // Go `:280-283`：出站恒有唯一 user（Build 保证）；Rust settings 缺失/畸形由
    // xray-core parse_vless_config 兜底硬错，lint 跳过。
    let Some(user) = vless_outbound_user(settings) else { return Ok(()) };
    // ① flow 拒（Go `:286-288`）。
    let flow = user.get("flow").and_then(|v| v.as_str()).unwrap_or("");
    if !flow.is_empty() {
        return Err(lint_err(kind, tag, "the xdrive transport doesn't support VLESS \"flow\""));
    }
    // ② encryption 无 ENC 拒（Go `:289-292`；空串/畸形一并拒，见模块文档语义差异注）。
    let encryption = user.get("encryption").and_then(|v| v.as_str()).unwrap_or("");
    if parse_client_encryption(encryption).is_none() {
        return Err(lint_err(
            kind,
            tag,
            "the xdrive transport needs VLESS \"encryption\", run \"xray vlessenc\" to get one",
        ));
    }
    // ③ reverse 自开 mux（Go `:292` 例外分支），否则强制 mux 开启。
    // Go 判据是 `account.Reverse == nil`（`*Reverse` 指针）：JSON 里 `"reverse"` 键存在
    // 且非 `null` 即视为已配置——`"reverse": {}`（空对象、无 tag）同样免 mux；只有
    // 缺键 / `null` 才回到强制 mux（bd hjtlk D7：本仓旧判据按 tag 非空，误拒 Go 合法配置）。
    let reverse_set = user.get("reverse").is_some_and(|r| !r.is_null());
    if !reverse_set {
        let mux_ok = mux.is_some_and(|m| {
            m.enabled
                && m.concurrency >= 0
                && m.xudp_concurrency >= 0
                && m.xudp_proxy_udp_443 != "skip"
        });
        if !mux_ok {
            return Err(lint_err(
                kind,
                tag,
                "the xdrive transport needs \"mux\" enabled, with no negative \"concurrency\" or \
                 \"xudpConcurrency\" and no \"xudpProxyUDP443\":\"skip\"",
            ));
        }
    }
    // ④ testpre 拒（Go `:297-299`）。
    let testpre = user.get("testpre").and_then(|v| v.as_i64()).unwrap_or(0);
    if testpre != 0 {
        return Err(lint_err(kind, tag, "the xdrive transport doesn't support VLESS \"testpre\""));
    }
    Ok(())
}

/// 入站规则（Go `:301-316`）：decryption 强制 + 任一 user flow 拒 + 单端口。
fn validate_inbound(
    kind: &str,
    tag: &str,
    settings: Option<&serde_json::Value>,
    ports: Option<&PortList>,
) -> Result<(), LintError> {
    // ⑤ decryption 无 ENC 拒（Go `:301-303`）。
    let decryption =
        settings.and_then(|s| s.get("decryption")).and_then(|v| v.as_str()).unwrap_or("");
    if parse_server_decryption(decryption).is_none() {
        return Err(lint_err(
            kind,
            tag,
            "the xdrive transport needs VLESS \"decryption\", run \"xray vlessenc\" to get one",
        ));
    }
    // ⑤b 任一 user flow 拒（Go `:304-312` 逐 user）。
    if let Some(clients) = settings.and_then(|s| s.get("clients")).and_then(|c| c.as_array()) {
        for client in clients {
            let flow = client.get("flow").and_then(|v| v.as_str()).unwrap_or("");
            if !flow.is_empty() {
                return Err(lint_err(
                    kind,
                    tag,
                    "the xdrive transport doesn't support VLESS \"flow\"",
                ));
            }
        }
    }
    // ⑤c 多端口拒（Go `:314-316`：pl != nil && len(Ports()) != 1；nil → 跳过）。
    if let Some(ports) = ports {
        let total: usize =
            ports.0.iter().map(|r| usize::from(r.end.saturating_sub(r.start)) + 1).sum();
        if total != 1 {
            return Err(lint_err(kind, tag, "the xdrive transport can only listen on one port"));
        }
    }
    Ok(())
}

/// 出站 VLESS user 取址：vnext 形式 `vnext[0].users[0]`（Go Build 只取第一个，vless.go:275+）；
/// 扁平形式（顶层 address，Go vless.go:263-271）→ settings 顶层即 user 字段。
/// 两者都取不到 → `None`（畸形配置由 parse_vless_config 硬错，lint 跳过）。
fn vless_outbound_user(settings: Option<&serde_json::Value>) -> Option<&serde_json::Value> {
    let settings = settings?;
    if let Some(user) = settings
        .get("vnext")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|rec| rec.get("users"))
        .and_then(|u| u.as_array())
        .and_then(|u| u.first())
    {
        return Some(user);
    }
    settings.get("address").and_then(|a| a.as_str()).is_some().then_some(settings)
}

fn lint_err(kind: &str, tag: &str, msg: &str) -> LintError {
    LintError::new(format!("{kind} '{tag}': {msg}"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{
        common::{PortList, PortRange},
        config::{Config, InboundDetourConfig, OutboundDetourConfig},
        init::register_builtin_stages,
        lint::{clear_stages, post_process, tests::TEST_LOCK},
    };

    const CLIENT_ENC: &str =
        "mlkem768x25519plus.native.0rtt.GS1D3kYFox-0dmcTK1u-2LaiSB-iM_Kve8N4bT--DhE";
    const SERVER_ENC: &str =
        "mlkem768x25519plus.native.1800s.GS1D3kYFox-0dmcTK1u-2LaiSB-iM_Kve8N4bT--DhE";
    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn xdrive_ss() -> serde_json::Value {
        json!({"network": "xdrive", "xdriveSettings": {"service": "local"}})
    }

    fn vnext_user(user: serde_json::Value) -> serde_json::Value {
        json!({"vnext": [{"address": "s.example.com", "port": 443, "users": [user]}]})
    }

    fn mux_ok() -> MuxConfig {
        MuxConfig { enabled: true, concurrency: 128, ..Default::default() }
    }

    // ===== 出站六规则矩阵（正/反） =====

    #[test]
    fn outbound_missing_mux_rejected() {
        let err = validate_xdrive(
            "outbound",
            "ob",
            "vless",
            Some(&vnext_user(json!({"id": UUID, "encryption": CLIENT_ENC}))),
            Some(&xdrive_ss()),
            None,
            None,
        )
        .expect_err("mux 未启用必须拒");
        let msg = err.to_string();
        assert!(msg.contains("needs \"mux\" enabled"), "got: {msg}");
        assert!(msg.contains("ob"), "tag missing: {msg}");
    }

    #[test]
    fn outbound_mux_enabled_passes_and_negative_variants_rejected() {
        let user = vnext_user(json!({"id": UUID, "encryption": CLIENT_ENC}));
        let ss = xdrive_ss();
        // 正例：enabled + concurrency 128（不触碰缺省 8——本仓 mux 缺省语义零改动）。
        assert!(
            validate_xdrive(
                "outbound",
                "ob",
                "vless",
                Some(&user),
                Some(&ss),
                Some(&mux_ok()),
                None
            )
            .is_ok()
        );
        // 反例三支：disabled / 负 concurrency / 负 xudpConcurrency / skip。
        for bad in [
            MuxConfig::default(),
            MuxConfig { enabled: true, concurrency: -1, ..Default::default() },
            MuxConfig { enabled: true, xudp_concurrency: -1, ..Default::default() },
            MuxConfig { enabled: true, xudp_proxy_udp_443: "skip".into(), ..Default::default() },
        ] {
            let err = validate_xdrive(
                "outbound",
                "ob",
                "vless",
                Some(&user),
                Some(&ss),
                Some(&bad),
                None,
            )
            .expect_err("bad mux config must reject");
            assert!(err.to_string().contains("needs \"mux\" enabled"), "got: {err}");
        }
    }

    #[test]
    fn outbound_encryption_none_rejected() {
        let err = validate_xdrive(
            "outbound",
            "ob",
            "vless",
            Some(&vnext_user(json!({"id": UUID, "encryption": "none"}))),
            Some(&xdrive_ss()),
            Some(&mux_ok()),
            None,
        )
        .expect_err("encryption none 必须拒");
        let msg = err.to_string();
        assert!(msg.contains("needs VLESS \"encryption\""), "got: {msg}");
    }

    #[test]
    fn outbound_flow_and_testpre_rejected() {
        let ss = xdrive_ss();
        let err = validate_xdrive(
            "outbound",
            "ob",
            "vless",
            Some(&vnext_user(json!({"id": UUID, "encryption": CLIENT_ENC,
                                     "flow": "xtls-rprx-vision"}))),
            Some(&ss),
            Some(&mux_ok()),
            None,
        )
        .expect_err("flow 必须拒");
        assert!(err.to_string().contains("doesn't support VLESS \"flow\""), "got: {err}");

        let err = validate_xdrive(
            "outbound",
            "ob",
            "vless",
            Some(&vnext_user(json!({"id": UUID, "encryption": CLIENT_ENC, "testpre": 1}))),
            Some(&ss),
            Some(&mux_ok()),
            None,
        )
        .expect_err("testpre 必须拒");
        assert!(err.to_string().contains("doesn't support VLESS \"testpre\""), "got: {err}");
    }

    #[test]
    fn outbound_reverse_bypasses_mux() {
        // Go `:292`：`account.Reverse != nil` 即「已配 reverse，自开 mux」——mux 未启用 → 通过。
        let user = vnext_user(json!({"id": UUID, "encryption": CLIENT_ENC,
                                      "reverse": {"tag": "portal-tag"}}));
        assert!(
            validate_xdrive("outbound", "ob", "vless", Some(&user), Some(&xdrive_ss()), None, None)
                .is_ok()
        );
        // bd hjtlk D7：Go 判据是 `*Reverse` 指针 nil——`"reverse": {}`（空对象、无 tag）
        // 非 nil ⇒ 免 mux。旧判据按 tag 非空，会把这条 Go 合法配置误拒。
        let empty_obj = vnext_user(json!({"id": UUID, "encryption": CLIENT_ENC, "reverse": {}}));
        assert!(
            validate_xdrive(
                "outbound",
                "ob",
                "vless",
                Some(&empty_obj),
                Some(&xdrive_ss()),
                None,
                None
            )
            .is_ok(),
            "\"reverse\": {{}} 非 nil，必须免 mux"
        );
        // `"reverse": null` = Go 的 nil ⇒ 回到强制 mux。
        let null_reverse =
            vnext_user(json!({"id": UUID, "encryption": CLIENT_ENC, "reverse": null}));
        let err = validate_xdrive(
            "outbound",
            "ob",
            "vless",
            Some(&null_reverse),
            Some(&xdrive_ss()),
            None,
            None,
        )
        .expect_err("null reverse 等于未配置，mux 仍强制");
        assert!(err.to_string().contains("needs \"mux\" enabled"), "got: {err}");
    }

    #[test]
    fn outbound_flat_form_supported() {
        // 扁平形式（Go vless.go:263-271 顶层 address）→ user 字段在 settings 顶层。
        let settings = json!({"address": "s.example.com", "port": 443, "id": UUID,
                               "encryption": CLIENT_ENC});
        assert!(
            validate_xdrive(
                "outbound",
                "ob",
                "vless",
                Some(&settings),
                Some(&xdrive_ss()),
                Some(&mux_ok()),
                None
            )
            .is_ok()
        );
        // 扁平 + encryption 缺失 → 拒（Go 语义：缺省 "" 非合法 ENC）。
        let bare = json!({"address": "s.example.com", "port": 443, "id": UUID});
        let err = validate_xdrive(
            "outbound",
            "ob",
            "vless",
            Some(&bare),
            Some(&xdrive_ss()),
            Some(&mux_ok()),
            None,
        )
        .expect_err("扁平形式缺 encryption 必须拒");
        assert!(err.to_string().contains("needs VLESS \"encryption\""), "got: {err}");
    }

    // ===== 网络门 / 协议门 / fronting 键 =====

    #[test]
    fn non_xdrive_network_and_non_vless_protocol() {
        // 非 xdrive 网络：一切放行（Go `:275-277`）。
        assert!(
            validate_xdrive(
                "outbound",
                "ob",
                "vless",
                Some(&vnext_user(json!({"id": UUID}))),
                Some(&json!({"network": "tcp"})),
                None,
                None
            )
            .is_ok()
        );
        // xdrive + 非 VLESS 协议 → 拒（Go default 分支）。
        let err = validate_xdrive(
            "outbound",
            "ob",
            "trojan",
            Some(&json!({"servers": []})),
            Some(&xdrive_ss()),
            None,
            None,
        )
        .expect_err("非 VLESS 必须拒");
        assert!(err.to_string().contains("can only be used by VLESS"), "got: {err}");
    }

    #[test]
    fn fronting_port_out_of_range_rejected() {
        let err = validate_xdrive(
            "outbound",
            "ob",
            "vless",
            Some(&vnext_user(json!({"id": UUID, "encryption": CLIENT_ENC}))),
            Some(&json!({"network": "xdrive", "port": 70000})),
            Some(&mux_ok()),
            None,
        )
        .expect_err("port 越界必须拒");
        assert!(err.to_string().contains("0..=65535"), "got: {err}");
        // 合法 port 放行（无 address 仅 port 的组合由 from_json 侧判 Destination 缺失）。
        assert!(
            validate_xdrive(
                "outbound",
                "ob",
                "vless",
                Some(&vnext_user(json!({"id": UUID, "encryption": CLIENT_ENC}))),
                Some(&json!({"network": "xdrive", "port": 8443})),
                Some(&mux_ok()),
                None,
            )
            .is_ok()
        );
    }

    // ===== 入站矩阵 =====

    #[test]
    fn inbound_decryption_and_flow() {
        // decryption none → 拒。
        let err = validate_xdrive(
            "inbound",
            "in",
            "vless",
            Some(&json!({"clients": [{"id": UUID}], "decryption": "none"})),
            Some(&xdrive_ss()),
            None,
            None,
        )
        .expect_err("decryption none 必须拒");
        assert!(err.to_string().contains("needs VLESS \"decryption\""), "got: {err}");
        // 任一 client flow → 拒。
        let err = validate_xdrive(
            "inbound",
            "in",
            "vless",
            Some(&json!({"clients": [{"id": UUID, "flow": ""}, {"id": UUID,
                                       "flow": "xtls-rprx-vision"}],
                          "decryption": SERVER_ENC})),
            Some(&xdrive_ss()),
            None,
            None,
        )
        .expect_err("client flow 必须拒");
        assert!(err.to_string().contains("doesn't support VLESS \"flow\""), "got: {err}");
    }

    #[test]
    fn inbound_single_port_only() {
        let settings = json!({"clients": [{"id": UUID}], "decryption": SERVER_ENC});
        let ss = xdrive_ss();
        let one = || PortList(vec![PortRange { start: 443, end: 443 }]);
        let two = || {
            PortList(vec![PortRange { start: 443, end: 443 }, PortRange { start: 8443, end: 8443 }])
        };
        // 正例：单端口 / 无 port（Go pl == nil 跳过）。
        assert!(
            validate_xdrive(
                "inbound",
                "in",
                "vless",
                Some(&settings),
                Some(&ss),
                None,
                Some(&one())
            )
            .is_ok()
        );
        assert!(
            validate_xdrive("inbound", "in", "vless", Some(&settings), Some(&ss), None, None)
                .is_ok()
        );
        // 反例：两端口。
        let err = validate_xdrive(
            "inbound",
            "in",
            "vless",
            Some(&settings),
            Some(&ss),
            None,
            Some(&two()),
        )
        .expect_err("多端口必须拒");
        assert!(err.to_string().contains("can only listen on one port"), "got: {err}");
    }

    // ===== 验收锚（bd hjtlk B0 #5）：端到端过整条 lint =====

    #[test]
    #[allow(clippy::err_expect)] // 存量清零批次：测试断言期 expect（Config 无 Debug，禁 expect_err）
    fn xdrive_full_config_passes_and_missing_mux_fails() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        let mk = |with_mux: bool| Config {
            inbound_configs: vec![InboundDetourConfig {
                protocol: "vless".into(),
                tag: "xd-in".into(),
                port: Some(PortList(vec![PortRange { start: 443, end: 443 }])),
                settings: Some(json!({"clients": [{"id": UUID}], "decryption": SERVER_ENC})),
                stream_settings: Some(xdrive_ss()),
                ..Default::default()
            }],
            outbound_configs: vec![OutboundDetourConfig {
                protocol: "vless".into(),
                tag: "xd-out".into(),
                settings: Some(vnext_user(json!({"id": UUID, "encryption": CLIENT_ENC}))),
                stream_settings: Some(xdrive_ss()),
                mux: with_mux.then(mux_ok),
                ..Default::default()
            }],
            ..Default::default()
        };
        // 完整配置（xdriveSettings + network=xdrive + mux + encryption/decryption）→ 过。
        post_process(&mut mk(true)).expect("完整 xdrive 配置必须过 lint");
        // 缺 mux → Err（validateXDrive 同款）。
        let err = post_process(&mut mk(false)).err().expect("缺 mux 必须拒");
        assert!(err.to_string().contains("needs \"mux\" enabled"), "got: {err}");
    }
}
