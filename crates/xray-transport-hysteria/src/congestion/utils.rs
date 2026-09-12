//! Congestion 入口工具函数（对应 Go `congestion/utils.go`）。
//!
//! 提供 `normalize_type` / `normalize_bbr_profile` 字符串规范化，
//! 以及 `CongestionSetter` trait —— hysteria 的 QUIC conn 操作抽象。
//!
//! Go 端 `UseBBR` / `UseBrutal` 直接调用 `conn.SetCongestionControl`，
//! Rust 端抽象为 trait，让上层（quinn adapter）注入。

use std::sync::Arc;

use super::{
    bbr::{BbrSender, Profile},
    brutal::BrutalSender,
    types::CongestionControl,
};

pub const TYPE_BBR: &str = "bbr";
pub const TYPE_RENO: &str = "reno";

/// 规范化 congestion 类型字符串（对应 Go `NormalizeType`）。
///
/// 空串 / "bbr" → `"bbr"`；"reno" → `"reno"`；其他 → Err。
pub fn normalize_type(s: &str) -> crate::Result<String> {
    match s.to_ascii_lowercase().as_str() {
        "" | "bbr" => Ok(TYPE_BBR.into()),
        "reno" => Ok(TYPE_RENO.into()),
        other => Err(crate::HysteriaError::UnsupportedCongestionType(other.into())),
    }
}

/// 规范化 BBR profile（对应 Go `NormalizeBBRProfile`）。
///
/// 通过 [`Profile::parse`] 解析，返回 `&'static str`。
pub fn normalize_bbr_profile(s: &str) -> crate::Result<&'static str> {
    Profile::parse(s).map(|p| p.as_str())
}

/// CongestionSetter —— QUIC conn 注入 CongestionControl 的抽象
/// （对应 Go `conn.SetCongestionControl`）。
///
/// 上层（quinn adapter）实现此 trait，将 hysteria 的 [`CongestionControl`]
/// 应用到具体的 QUIC conn（quinn_proto::congestion::Controller）。
pub trait CongestionSetter: Send + Sync {
    /// 替换 conn 的 congestion control 算法为指定实现。
    fn set_congestion_control(&self, cc: Box<dyn CongestionControl>);
}

/// 创建 BBR 发送器并应用到 setter（对应 Go `UseBBR`）。
///
/// `initial_packet_size` 由 `GetInitialPacketSize(remote_addr)` 决定；
/// Rust 端简化为由调用方传入（默认 [`crate::congestion::types::INITIAL_PACKET_SIZE`]）。
pub fn use_bbr<S: CongestionSetter + ?Sized>(
    setter: &S,
    clock: Arc<dyn super::bbr::Clock>,
    initial_packet_size: i64,
    profile: Profile,
) {
    let sender = Box::new(BbrSender::new(clock, initial_packet_size, profile));
    setter.set_congestion_control(sender);
}

/// 创建 BrutalSender 并应用到 setter（对应 Go `UseBrutal(conn, tx, disableLossCompensation)`）。
pub fn use_brutal<S: CongestionSetter + ?Sized>(
    setter: &S,
    tx_bps: u64,
    disable_loss_compensation: bool,
) {
    let sender = Box::new(BrutalSender::new(tx_bps, disable_loss_compensation));
    setter.set_congestion_control(sender);
}

/// 根据字符串类型应用 congestion（对应 Go `UseConfigured`）。
///
/// - `"reno"` → 不修改
/// - 其他（`""`、`"bbr"`） → 应用 BBR
pub fn use_configured<S: CongestionSetter + ?Sized>(
    setter: &S,
    congestion_type: &str,
    bbr_profile: &str,
    clock: Arc<dyn super::bbr::Clock>,
    initial_packet_size: i64,
) -> crate::Result<()> {
    if congestion_type.eq_ignore_ascii_case(TYPE_RENO) {
        return Ok(());
    }
    let profile = Profile::parse(bbr_profile)?;
    use_bbr(setter, clock, initial_packet_size, profile);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// 测试用 setter：记录最后一次 set 的 cc 指针。
    struct TestSetter {
        last_set: Mutex<Option<Box<dyn CongestionControl>>>,
    }

    impl TestSetter {
        fn new() -> Self {
            Self { last_set: Mutex::new(None) }
        }

        fn was_set(&self) -> bool {
            self.last_set.lock().unwrap().is_some()
        }
    }

    impl CongestionSetter for TestSetter {
        fn set_congestion_control(&self, cc: Box<dyn CongestionControl>) {
            *self.last_set.lock().unwrap() = Some(cc);
        }
    }

    #[test]
    fn normalize_type_valid() {
        assert_eq!(normalize_type("").unwrap(), "bbr");
        assert_eq!(normalize_type("bbr").unwrap(), "bbr");
        assert_eq!(normalize_type("BBR").unwrap(), "bbr");
        assert_eq!(normalize_type("reno").unwrap(), "reno");
        assert_eq!(normalize_type("RENO").unwrap(), "reno");
    }

    #[test]
    fn normalize_type_invalid_errors() {
        assert!(normalize_type("cubic").is_err());
        assert!(normalize_type("bbr2").is_err());
        assert!(normalize_type("foo").is_err());
    }

    #[test]
    fn normalize_bbr_profile_valid() {
        assert_eq!(normalize_bbr_profile("").unwrap(), "standard");
        assert_eq!(normalize_bbr_profile("standard").unwrap(), "standard");
        assert_eq!(normalize_bbr_profile("Conservative").unwrap(), "conservative");
        assert_eq!(normalize_bbr_profile("AGGRESSIVE").unwrap(), "aggressive");
    }

    #[test]
    fn normalize_bbr_profile_invalid() {
        assert!(normalize_bbr_profile("weird").is_err());
    }

    #[test]
    fn use_bbr_applies_cc_to_setter() {
        let setter = TestSetter::new();
        let clock: Arc<dyn super::super::bbr::Clock> =
            Arc::new(crate::congestion::bbr::DefaultClock::new());
        use_bbr(&setter, clock, crate::congestion::types::INITIAL_PACKET_SIZE, Profile::Standard);
        assert!(setter.was_set());
    }

    #[test]
    fn use_brutal_applies_cc_to_setter() {
        let setter = TestSetter::new();
        use_brutal(&setter, 1_000_000, false);
        assert!(setter.was_set());
    }

    #[test]
    fn use_configured_reno_no_op() {
        let setter = TestSetter::new();
        let clock: Arc<dyn super::super::bbr::Clock> =
            Arc::new(crate::congestion::bbr::DefaultClock::new());
        use_configured(&setter, "reno", "standard", clock, 1200).unwrap();
        assert!(!setter.was_set()); // reno → no op
    }

    #[test]
    fn use_configured_default_applies_bbr() {
        let setter = TestSetter::new();
        let clock: Arc<dyn super::super::bbr::Clock> =
            Arc::new(crate::congestion::bbr::DefaultClock::new());
        use_configured(&setter, "", "standard", clock, 1200).unwrap();
        assert!(setter.was_set());
    }

    #[test]
    fn use_configured_invalid_profile_errors() {
        let setter = TestSetter::new();
        let clock: Arc<dyn super::super::bbr::Clock> =
            Arc::new(crate::congestion::bbr::DefaultClock::new());
        assert!(use_configured(&setter, "bbr", "weird", clock, 1200).is_err());
    }
}
