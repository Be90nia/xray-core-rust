//! xray-app-metrics 配置。
//!
//! 对应 Go `app/metrics/config.proto` 中的 `Config` message。

use xray_proto::xray::app::metrics::Config as ProtoConfig;

/// metrics handler 配置。
///
/// `tag`：处理 metrics HTTP 请求的 outbound handler 标签（Dialer 注册到 OutboundManager 的 key）。
/// `listen`：可选 TCP 监听地址（如 `127.0.0.1:9090`），为空时仅通过 outbound 路由暴露。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetricsConfig {
    pub tag: String,
    pub listen: String,
}

impl MetricsConfig {
    /// 从 prost 生成的 proto message 构造。
    pub fn from_proto(p: &ProtoConfig) -> Self {
        Self { tag: p.tag.clone(), listen: p.listen.clone() }
    }

    /// 转换为 prost message。
    pub fn to_proto(&self) -> ProtoConfig {
        ProtoConfig { tag: self.tag.clone(), listen: self.listen.clone() }
    }

    /// 配置校验：tag 与 listen 至少一项非空。
    ///
    /// 对应 Go `app/metrics/config.go::Config` 无显式校验，但 `metrics.New` 依赖
    /// `listen` 或 `outbound tag` 暴露端口——两者皆空即 metrics 永远不可达，视为
    /// 配置错误。
    pub fn validate(&self) -> Result<(), String> {
        if self.tag.is_empty() && self.listen.is_empty() {
            return Err("metrics: tag and listen are both empty".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        let c = MetricsConfig::default();
        assert!(c.tag.is_empty());
        assert!(c.listen.is_empty());
    }

    #[test]
    fn from_proto_copies_fields() {
        let p = ProtoConfig { tag: "metrics_out".into(), listen: "127.0.0.1:9090".into() };
        let c = MetricsConfig::from_proto(&p);
        assert_eq!(c.tag, "metrics_out");
        assert_eq!(c.listen, "127.0.0.1:9090");
    }

    #[test]
    fn to_proto_roundtrip() {
        let c = MetricsConfig { tag: "t".into(), listen: "127.0.0.1:1".into() };
        let p = c.to_proto();
        assert_eq!(p.tag, "t");
        assert_eq!(p.listen, "127.0.0.1:1");
        assert_eq!(MetricsConfig::from_proto(&p), c);
    }

    #[test]
    fn eq_on_clone() {
        let c = MetricsConfig { tag: "x".into(), listen: "y".into() };
        assert_eq!(c, c.clone());
    }

    #[test]
    fn from_proto_empty_message() {
        let p = ProtoConfig::default();
        let c = MetricsConfig::from_proto(&p);
        assert_eq!(c, MetricsConfig::default());
    }

    #[test]
    fn to_proto_default_yields_empty() {
        let c = MetricsConfig::default();
        let p = c.to_proto();
        assert!(p.tag.is_empty());
        assert!(p.listen.is_empty());
    }

    #[test]
    fn validate_both_empty_errors() {
        let c = MetricsConfig::default();
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_only_tag_ok() {
        let c = MetricsConfig { tag: "m".into(), listen: String::new() };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn validate_only_listen_ok() {
        let c = MetricsConfig { tag: String::new(), listen: "127.0.0.1:9090".into() };
        assert!(c.validate().is_ok());
    }
}
