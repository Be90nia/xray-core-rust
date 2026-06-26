//! 路由配置辅助。
//!
//! 翻译自 `app/router/config.go` 中与 `Config.DomainStrategy` 相关的枚举。
//!
//! proto 中 `Config_DomainStrategy` 是嵌套枚举（prost 生成 `Config::DomainStrategy`），
//! 为类型安全，这里提供独立 Rust enum + 转换。

use xray_proto::xray::app::router::config::DomainStrategy as ProtoDomainStrategy;

/// 域名解析策略。对应 Go `router.Config_DomainStrategy`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum DomainStrategy {
    /// `AsIs = 0`：不解析，按规则原样匹配。
    AsIs = 0,
    /// `IpIfNonMatch = 2`：仅当当前规则不匹配时才解析。
    IpIfNonMatch = 2,
    /// `IpOnDemand = 3`：只要有域名就解析。
    IpOnDemand = 3,
}

impl DomainStrategy {
    /// 从 proto i32 值转换（无效值回退到 `AsIs`）。
    #[must_use]
    pub fn from_proto_i32(v: i32) -> Self {
        match v {
            2 => Self::IpIfNonMatch,
            3 => Self::IpOnDemand,
            _ => Self::AsIs,
        }
    }

    /// 从 proto 枚举转换。
    #[must_use]
    pub fn from_proto(p: ProtoDomainStrategy) -> Self {
        Self::from_proto_i32(p.into())
    }

    /// 转回 proto 枚举。
    #[must_use]
    pub fn to_proto(self) -> ProtoDomainStrategy {
        match self {
            Self::AsIs => ProtoDomainStrategy::AsIs,
            Self::IpIfNonMatch => ProtoDomainStrategy::IpIfNonMatch,
            Self::IpOnDemand => ProtoDomainStrategy::IpOnDemand,
        }
    }

    /// 是否需要根据域名解析 IP（IpIfNonMatch 与 IpOnDemand 都算）。
    #[must_use]
    pub fn needs_ip_resolution(self) -> bool {
        matches!(self, Self::IpIfNonMatch | Self::IpOnDemand)
    }
}

impl From<ProtoDomainStrategy> for DomainStrategy {
    fn from(p: ProtoDomainStrategy) -> Self {
        Self::from_proto(p)
    }
}

impl Default for DomainStrategy {
    fn default() -> Self {
        Self::AsIs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_proto_i32_known() {
        assert_eq!(DomainStrategy::from_proto_i32(0), DomainStrategy::AsIs);
        assert_eq!(DomainStrategy::from_proto_i32(2), DomainStrategy::IpIfNonMatch);
        assert_eq!(DomainStrategy::from_proto_i32(3), DomainStrategy::IpOnDemand);
    }

    #[test]
    fn test_from_proto_i32_invalid_falls_back_to_asis() {
        assert_eq!(DomainStrategy::from_proto_i32(1), DomainStrategy::AsIs);
        assert_eq!(DomainStrategy::from_proto_i32(99), DomainStrategy::AsIs);
        assert_eq!(DomainStrategy::from_proto_i32(-1), DomainStrategy::AsIs);
    }

    #[test]
    fn test_round_trip_to_proto() {
        for s in [DomainStrategy::AsIs, DomainStrategy::IpIfNonMatch, DomainStrategy::IpOnDemand] {
            assert_eq!(DomainStrategy::from_proto(s.to_proto()), s);
        }
    }

    #[test]
    fn test_needs_ip_resolution() {
        assert!(!DomainStrategy::AsIs.needs_ip_resolution());
        assert!(DomainStrategy::IpIfNonMatch.needs_ip_resolution());
        assert!(DomainStrategy::IpOnDemand.needs_ip_resolution());
    }
}
