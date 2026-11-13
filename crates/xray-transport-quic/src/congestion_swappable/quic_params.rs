//! `QuicParamsConfig` → quinn CC 翻译（全仓唯一实现，G7 上浮自 splithttp/xdrive）。
//!
//! 两个 Go dialer 对 `quicParams` 的消费语义不同（这是行为契约，不是重复）：
//!
//! | | splithttp H3（[`CcSemantics::SplitHttpH3`]） | xdrive h3（[`CcSemantics::XdriveH3`]） |
//! |---|---|---|
//! | Go 锚点 | `splithttp/dialer.go:161-164` + `:239-246` | `client.go:259-268` |
//! | `quicParams == None` | 兜底 BBR standard（PR #5711：H3 默认 BBR） | 保持底层缺省 CUBIC |
//! | `""`（空串） | BBR | 保持底层缺省 CUBIC |
//! | `"reno"` | 不应用（保留 quinn 默认 CUBIC） | 同左 |
//! | `"bbr"` | BBR（profile 可选，未知 profile 硬错） | 同左 |
//! | `"force-brutal"` | Brutal(up, disableLossComp)；up==0 硬错 | 硬错（brutal 是 Hysteria 的东西） |
//! | `"brutal"`/未知值 | 硬错 `unknown congestion control: …` | 硬错 `unsupported congestion control over h3: …` |
//! | 带宽字段 | 无条件解析 + ≥65536 校验（Go conf :229-243） | 不读 |
//!
//! Rust 侧 memory_settings 对 quicParams 宽容解析，conf 层校验语义（互斥/区间/
//! 未知值硬错）在本函数一并兜住——两侧错误消息文本是既有测试的行为契约，禁改。

use xray_transport::memory_settings::QuicParamsConfig;

use super::{
    CongestionError, HysteriaCCSlot, apply_bbr, apply_brutal, bbr::Profile, parse_bandwidth_bps,
};

/// quicParams → CC 的翻译语义（两个 Go dialer 的行为差异集中于此枚举）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CcSemantics {
    /// splithttp H3 语义（Go `dialer.go`）：None 兜底 BBR；brutal 通道 + 带宽校验。
    SplitHttpH3,
    /// xdrive h3 语义（Go `client.go`）：None/空串/reno 保持底层缺省；仅 bbr 可装。
    XdriveH3,
}

/// 按 [`CcSemantics`] 把 `quicParams` 翻译并应用到 CC 槽位（全仓唯一翻译实现）。
///
/// 错误文本由本函数精确控制（[`CongestionError::InvalidParams`] 文本直通），
/// 调用方（splithttp `h3_client` / xdrive `h3`）只做错误类型映射——文本是两侧
/// 既有测试断言的 grep 契约，逐字节不变。
pub fn apply_quic_params_cc(
    slot: &HysteriaCCSlot,
    quic_params: Option<&QuicParamsConfig>,
    semantics: CcSemantics,
) -> super::Result<()> {
    let Some(qp) = quic_params else {
        // splithttp：quicParams 为 nil 时兜底 BbrProfile=standard，congestion 空串
        // 走 UseBBR 分支——H3 无配置也默认 BBR（PR #5711）。xdrive：缺省保持底层 CUBIC。
        if matches!(semantics, CcSemantics::SplitHttpH3) {
            apply_bbr(slot, Profile::Standard);
        }
        return Ok(());
    };
    // splithttp（Go conf :229-243）：Brutal 带宽无条件解析（Up 与 Down 都验），
    // 失败硬错；>0 且 <65536 → 硬错。xdrive 语义不读带宽字段。
    let brutal_up_bps = match semantics {
        CcSemantics::SplitHttpH3 => {
            let up = parse_bandwidth_bps(&qp.brutal_up)
                .map_err(|e| CongestionError::InvalidParams(format!("quicParams brutalUp: {e}")))?;
            let down = parse_bandwidth_bps(&qp.brutal_down).map_err(|e| {
                CongestionError::InvalidParams(format!("quicParams brutalDown: {e}"))
            })?;
            if up > 0 && up < 65_536 {
                return Err(CongestionError::InvalidParams(
                    "BrutalUp must be at least 65536 bytes per second".into(),
                ));
            }
            if down > 0 && down < 65_536 {
                return Err(CongestionError::InvalidParams(
                    "BrutalDown must be at least 65536 bytes per second".into(),
                ));
            }
            up
        },
        CcSemantics::XdriveH3 => 0,
    };
    match (semantics, qp.congestion.to_ascii_lowercase().as_str()) {
        // 两语义同臂：reno 不应用（Go 空 case 体，保留 quinn 默认 CUBIC）。
        (_, "reno") => {},
        // splithttp `""`/`"bbr"` 与 xdrive `"bbr"`：装 BBR（fallback 通道，非 hysteria
        // active）；未知 profile 硬错（Go conf "unknown bbr profile"）。
        (CcSemantics::SplitHttpH3, "" | "bbr") | (CcSemantics::XdriveH3, "bbr") => {
            let profile = Profile::parse(&qp.bbr_profile)
                .map_err(|e| CongestionError::InvalidParams(format!("quicParams: {e}")))?;
            apply_bbr(slot, profile);
        },
        // xdrive 空串：不应用（Go client.go 空 case 体）。
        (CcSemantics::XdriveH3, "") => {},
        // 仅 splithttp：Brutal 固定带宽通道。
        (CcSemantics::SplitHttpH3, "force-brutal") => {
            if brutal_up_bps == 0 {
                return Err(CongestionError::InvalidParams("force-brutal requires up".into()));
            }
            apply_brutal(slot, brutal_up_bps, qp.brutal_disable_loss_compensation);
        },
        (CcSemantics::SplitHttpH3, other) => {
            return Err(CongestionError::InvalidParams(format!(
                "unknown congestion control: {other}, valid values: reno, bbr, brutal, force-brutal"
            )));
        },
        (CcSemantics::XdriveH3, other) => {
            return Err(CongestionError::InvalidParams(format!(
                "unsupported congestion control over h3: {other}"
            )));
        },
    }
    Ok(())
}
