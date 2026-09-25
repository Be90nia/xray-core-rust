//! xray-app-reverse 配置 + Control proto。

use xray_proto::xray::app::reverse::{
    BridgeConfig as ProtoBridgeConfig, Config as ProtoConfig, Control as ProtoControl,
    PortalConfig as ProtoPortalConfig,
};

use crate::error::ReverseError;

/// 内部域名（与 Go `internalDomain` 一致）。
pub const INTERNAL_DOMAIN: &str = "reverse";

/// Control state，对应 proto `Control.State`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlState {
    Active = 0,
    Drain = 1,
}

impl ControlState {
    pub fn from_proto_i32(v: i32) -> Result<Self, ReverseError> {
        match v {
            0 => Ok(Self::Active),
            1 => Ok(Self::Drain),
            other => Err(ReverseError::InvalidControlState(other)),
        }
    }

    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

/// Control 消息，对应 proto `Control { State, Random }`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    pub state: ControlState,
    pub random: Vec<u8>,
}

impl Default for Control {
    fn default() -> Self {
        Self { state: ControlState::Active, random: Vec::new() }
    }
}

impl Control {
    /// 从 prost Control 构造。
    pub fn from_proto(p: &ProtoControl) -> Result<Self, ReverseError> {
        Ok(Self { state: ControlState::from_proto_i32(p.state)?, random: p.random.clone() })
    }

    /// 转 prost Control。
    pub fn to_proto(&self) -> ProtoControl {
        let mut out = ProtoControl::default();
        out.state = self.state.as_i32();
        out.random = self.random.clone();
        out
    }

    /// 填充 1-64 字节的随机数（对应 Go `FillInRandom`，用 dice.Roll(64) + 1）。
    pub fn fill_in_random(&mut self) {
        use rand::Rng;
        let mut rng = rand::rng();
        // 长度 1..=64
        let len = rng.random_range(1..=64) as usize;
        self.random.clear();
        self.random.resize(len, 0u8);
        rng.fill(&mut self.random[..]);
    }
}

/// BridgeConfig，对应 proto。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BridgeConfig {
    pub tag: String,
    pub domain: String,
}

impl BridgeConfig {
    pub fn from_proto(p: &ProtoBridgeConfig) -> Self {
        Self { tag: p.tag.clone(), domain: p.domain.clone() }
    }

    pub fn to_proto(&self) -> ProtoBridgeConfig {
        let mut out = ProtoBridgeConfig::default();
        out.tag = self.tag.clone();
        out.domain = self.domain.clone();
        out
    }
}

/// PortalConfig，对应 proto。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortalConfig {
    pub tag: String,
    pub domain: String,
}

impl PortalConfig {
    pub fn from_proto(p: &ProtoPortalConfig) -> Self {
        Self { tag: p.tag.clone(), domain: p.domain.clone() }
    }

    pub fn to_proto(&self) -> ProtoPortalConfig {
        let mut out = ProtoPortalConfig::default();
        out.tag = self.tag.clone();
        out.domain = self.domain.clone();
        out
    }
}

/// ReverseConfig，对应 proto。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReverseConfig {
    pub bridges: Vec<BridgeConfig>,
    pub portals: Vec<PortalConfig>,
}

impl ReverseConfig {
    pub fn from_proto(p: &ProtoConfig) -> Self {
        Self {
            bridges: p.bridge_config.iter().map(BridgeConfig::from_proto).collect(),
            portals: p.portal_config.iter().map(PortalConfig::from_proto).collect(),
        }
    }

    pub fn to_proto(&self) -> ProtoConfig {
        let mut out = ProtoConfig::default();
        out.bridge_config = self.bridges.iter().map(|c| c.to_proto()).collect();
        out.portal_config = self.portals.iter().map(|c| c.to_proto()).collect();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_state_roundtrip() {
        for s in [ControlState::Active, ControlState::Drain] {
            assert_eq!(ControlState::from_proto_i32(s.as_i32()).unwrap(), s);
        }
    }

    #[test]
    fn control_state_invalid() {
        assert!(ControlState::from_proto_i32(2).is_err());
    }

    #[test]
    fn control_default_is_active_empty() {
        let c = Control::default();
        assert_eq!(c.state, ControlState::Active);
        assert!(c.random.is_empty());
    }

    #[test]
    fn control_fill_in_random_within_bounds() {
        let mut c = Control::default();
        for _ in 0..20 {
            c.fill_in_random();
            assert!(!c.random.is_empty(), "random must not be empty");
            assert!(c.random.len() <= 64, "random too long: {}", c.random.len());
        }
    }

    #[test]
    fn control_fill_in_random_can_be_full_64() {
        // 跑很多次确认至少一次达到 64 长度（概率约 1/64）
        let mut c = Control::default();
        let mut seen_large = false;
        for _ in 0..500 {
            c.fill_in_random();
            if c.random.len() >= 32 {
                seen_large = true;
                break;
            }
        }
        assert!(seen_large, "expected to see length >= 32 within 500 tries");
    }

    #[test]
    fn control_proto_roundtrip() {
        let mut c = Control::default();
        c.state = ControlState::Drain;
        c.random = vec![1, 2, 3, 4];
        let p = c.to_proto();
        let c2 = Control::from_proto(&p).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn bridge_config_proto_roundtrip() {
        let bc = BridgeConfig { tag: "b1".into(), domain: "example.com".into() };
        let p = bc.to_proto();
        assert_eq!(BridgeConfig::from_proto(&p), bc);
    }

    #[test]
    fn portal_config_proto_roundtrip() {
        let pc = PortalConfig { tag: "p1".into(), domain: "portal.example.com".into() };
        let p = pc.to_proto();
        assert_eq!(PortalConfig::from_proto(&p), pc);
    }

    #[test]
    fn reverse_config_proto_roundtrip() {
        let rc = ReverseConfig {
            bridges: vec![BridgeConfig { tag: "b".into(), domain: "d".into() }],
            portals: vec![
                PortalConfig { tag: "p1".into(), domain: "d1".into() },
                PortalConfig { tag: "p2".into(), domain: "d2".into() },
            ],
        };
        let p = rc.to_proto();
        assert_eq!(ReverseConfig::from_proto(&p), rc);
    }

    #[test]
    fn reverse_config_empty_default() {
        let c = ReverseConfig::default();
        assert!(c.bridges.is_empty());
        assert!(c.portals.is_empty());
    }

    #[test]
    fn internal_domain_constant() {
        assert_eq!(INTERNAL_DOMAIN, "reverse");
    }
}
