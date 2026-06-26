//! Proto Config wrapper + 默认配置（对应 Go `config.pb.go` + `init()` 注册默认）。
//!
//! Go 源：`transport/internet/hysteria/config.pb.go`（prost 自动生成）+
//! `config.go` 中的 `init()` 注册默认配置（`UdpIdleTimeout: 60`）。

use xray_proto::xray::transport::internet::hysteria::Config as ProtoConfig;

/// 协议配置类型别名（与 KCP 一致，直接复用 prost 生成的 `Config`）。
pub type Config = ProtoConfig;

/// 默认配置（对应 Go `init()` 中 `&Config{ UdpIdleTimeout: 60 }`）。
#[must_use]
pub fn default_config() -> Config {
    Config {
        udp_idle_timeout: 60,
        ..Config::default()
    }
}

/// `Config` 字段访问器扩展（对应 Go 直接字段访问）。
///
/// Rust 端 prost 生成的字段是 `snake_case`（如 `udp_idle_timeout`），可直接访问；
/// 这里集中暴露常用字段，便于上层调用。
pub trait ConfigExt {
    /// UDP 空闲超时（秒，对应 Go `config.UdpIdleTimeout`）。
    fn udp_idle_timeout_secs(&self) -> i64;

    /// 鉴权 token（对应 Go `config.Auth`）。
    fn auth(&self) -> &str;

    /// Masquerade 类型（对应 Go `config.MasqType`）。
    fn masq_type(&self) -> &str;
}

impl ConfigExt for Config {
    fn udp_idle_timeout_secs(&self) -> i64 {
        self.udp_idle_timeout
    }

    fn auth(&self) -> &str {
        &self.auth
    }

    fn masq_type(&self) -> &str {
        &self.masq_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_udp_idle_timeout_60() {
        let c = default_config();
        assert_eq!(c.udp_idle_timeout, 60);
    }

    #[test]
    fn default_config_other_fields_default() {
        let c = default_config();
        assert_eq!(c.auth, "");
        assert_eq!(c.masq_type, "");
        assert_eq!(c.version, 0);
    }

    #[test]
    fn config_ext_accessors() {
        let c = Config {
            udp_idle_timeout: 120,
            auth: "secret-token".into(),
            masq_type: "404".into(),
            ..Config::default()
        };
        assert_eq!(c.udp_idle_timeout_secs(), 120);
        assert_eq!(c.auth(), "secret-token");
        assert_eq!(c.masq_type(), "404");
    }
}
