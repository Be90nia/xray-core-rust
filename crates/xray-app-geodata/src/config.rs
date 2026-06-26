//! xray-app-geodata 配置。

use xray_proto::xray::app::geodata::{Asset as ProtoAsset, Config as ProtoConfig};

/// Geodata 资产：URL + 本地文件名。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeodataAsset {
    pub url: String,
    pub file: String,
}

impl GeodataAsset {
    pub fn from_proto(p: &ProtoAsset) -> Self {
        Self {
            url: p.url.clone(),
            file: p.file.clone(),
        }
    }

    pub fn to_proto(&self) -> ProtoAsset {
        let mut out = ProtoAsset::default();
        out.url = self.url.clone();
        out.file = self.file.clone();
        out
    }
}

/// Geodata 配置：cron 调度 + outbound + 资产列表。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeodataConfig {
    pub cron: String,
    pub outbound: String,
    pub assets: Vec<GeodataAsset>,
}

impl GeodataConfig {
    pub fn from_proto(p: &ProtoConfig) -> Self {
        Self {
            cron: p.cron.clone(),
            outbound: p.outbound.clone(),
            assets: p.assets.iter().map(GeodataAsset::from_proto).collect(),
        }
    }

    pub fn to_proto(&self) -> ProtoConfig {
        let mut out = ProtoConfig::default();
        out.cron = self.cron.clone();
        out.outbound = self.outbound.clone();
        out.assets = self.assets.iter().map(|a| a.to_proto()).collect();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_default_empty() {
        let a = GeodataAsset::default();
        assert!(a.url.is_empty());
        assert!(a.file.is_empty());
    }

    #[test]
    fn asset_from_proto() {
        let mut p = ProtoAsset::default();
        p.url = "https://example.com/ip.dat".into();
        p.file = "geoip.dat".into();
        let a = GeodataAsset::from_proto(&p);
        assert_eq!(a.url, "https://example.com/ip.dat");
        assert_eq!(a.file, "geoip.dat");
    }

    #[test]
    fn asset_to_proto_roundtrip() {
        let a = GeodataAsset {
            url: "u".into(),
            file: "f".into(),
        };
        let p = a.to_proto();
        assert_eq!(GeodataAsset::from_proto(&p), a);
    }

    #[test]
    fn config_default_empty() {
        let c = GeodataConfig::default();
        assert!(c.cron.is_empty());
        assert!(c.outbound.is_empty());
        assert!(c.assets.is_empty());
    }

    #[test]
    fn config_from_proto() {
        let mut p = ProtoConfig::default();
        p.cron = "0 0 * * *".into();
        p.outbound = "direct".into();
        let mut a = ProtoAsset::default();
        a.url = "u1".into();
        a.file = "f1".into();
        p.assets.push(a);
        let c = GeodataConfig::from_proto(&p);
        assert_eq!(c.cron, "0 0 * * *");
        assert_eq!(c.outbound, "direct");
        assert_eq!(c.assets.len(), 1);
        assert_eq!(c.assets[0].url, "u1");
    }

    #[test]
    fn config_to_proto_roundtrip() {
        let c = GeodataConfig {
            cron: "*/5 * * * *".into(),
            outbound: "block".into(),
            assets: vec![
                GeodataAsset {
                    url: "u".into(),
                    file: "f".into(),
                },
                GeodataAsset {
                    url: "u2".into(),
                    file: "f2".into(),
                },
            ],
        };
        let p = c.to_proto();
        assert_eq!(GeodataConfig::from_proto(&p), c);
    }

    #[test]
    fn config_empty_proto_yields_empty() {
        let p = ProtoConfig::default();
        let c = GeodataConfig::from_proto(&p);
        assert_eq!(c, GeodataConfig::default());
    }

    #[test]
    fn config_eq_semantics() {
        let c1 = GeodataConfig {
            cron: "x".into(),
            outbound: "y".into(),
            assets: vec![],
        };
        let c2 = c1.clone();
        assert_eq!(c1, c2);
    }
}
