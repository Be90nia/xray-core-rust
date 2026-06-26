//! BBR 子模块根（对应 Go `congestion/bbr/`）。
//!
//! 模块构成：
//! - [`bandwidth`]：`Bandwidth` 类型 + 单位转换
//! - [`clock`]：`Clock` trait + `DefaultClock`
//! - [`windowed_filter`]：`WindowedFilter` 三槽滑窗（Nichols 算法）
//! - [`ringbuffer`]：`RingBuffer` 环形队列
//! - [`packet_queue`]：`PacketNumberIndexedQueue` 按包序号索引的队列
//! - [`bandwidth_sampler`]：`BandwidthSampler` 带宽采样器
//! - [`bbr_sender`]：`BbrSender` BBR 主算法

pub mod bandwidth;
pub mod bandwidth_sampler;
pub mod bbr_sender;
pub mod clock;
pub mod packet_queue;
pub mod ringbuffer;
pub mod windowed_filter;

pub use bbr_sender::BbrSender;
pub use bandwidth::Bandwidth;
pub use clock::{Clock, DefaultClock};

/// BBR Profile（对应 Go `type Profile string`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Profile {
    /// 保守：低 gain，更快退出 startup。
    Conservative,
    /// 标准（默认）。
    Standard,
    /// 激进：高 gain，更长 startup。
    Aggressive,
}

impl Profile {
    /// 解析字符串到 Profile（对应 Go `ParseProfile`）。
    ///
    /// 空串 / "standard" → Standard；"conservative" → Conservative；
    /// "aggressive" → Aggressive；其他 → Err。
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "" | "standard" => Ok(Self::Standard),
            "conservative" => Ok(Self::Conservative),
            "aggressive" => Ok(Self::Aggressive),
            other => Err(crate::HysteriaError::UnsupportedBbrProfile(other.into())),
        }
    }

    /// 字符串形式（对应 Go `string(profile)`）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::Standard => "standard",
            Self::Aggressive => "aggressive",
        }
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 默认 Profile（对应 Go `bbr.ProfileStandard`）。
pub const PROFILE_STANDARD: Profile = Profile::Standard;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_parse_round_trip() {
        for (input, expected) in [
            ("", Profile::Standard),
            ("standard", Profile::Standard),
            ("STANDARD", Profile::Standard),
            ("Standard", Profile::Standard),
            ("conservative", Profile::Conservative),
            ("Conservative", Profile::Conservative),
            ("aggressive", Profile::Aggressive),
            ("AGGRESSIVE", Profile::Aggressive),
        ] {
            assert_eq!(Profile::parse(input).unwrap(), expected, "input={input}");
        }
    }

    #[test]
    fn profile_parse_invalid_errors() {
        assert!(Profile::parse("weird").is_err());
        assert!(Profile::parse("unknown").is_err());
        assert!(Profile::parse("vivid").is_err());
    }

    #[test]
    fn profile_as_str_and_display() {
        assert_eq!(Profile::Conservative.as_str(), "conservative");
        assert_eq!(Profile::Standard.as_str(), "standard");
        assert_eq!(Profile::Aggressive.as_str(), "aggressive");
        assert_eq!(Profile::Standard.to_string(), "standard");
    }

    #[test]
    fn profile_standard_constant() {
        assert_eq!(PROFILE_STANDARD, Profile::Standard);
    }
}
