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

/// 把用户 JSON `masquerade` 嵌套对象展开到 proto Config 扁平字段。
///
/// 对应 Go `HysteriaConfig.Build()`（infra/conf/transport_internet.go:542-549）：
/// `Masquerade{Type,Dir,Url,RewriteHost,Insecure,Content,Headers,StatusCode}`
/// （json tag :499-509）→ `MasqType/MasqFile/MasqUrl/MasqUrlRewriteHost/
/// MasqUrlInsecure/MasqString/MasqStringHeaders/MasqStringStatusCode`。
///
/// # Errors
/// `masquerade` 非对象或 `headers` 非对象时 `InvalidInput`。
pub fn apply_masquerade_json(
    config: &mut Config,
    masquerade: &serde_json::Value,
) -> std::io::Result<()> {
    let Some(m) = masquerade.as_object() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "masquerade must be a JSON object",
        ));
    };
    let get_str = |k: &str| m.get(k).and_then(|x| x.as_str()).unwrap_or("");
    config.masq_type = get_str("type").to_string();
    config.masq_file = get_str("dir").to_string();
    config.masq_url = get_str("url").to_string();
    config.masq_url_rewrite_host = m
        .get("rewriteHost")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    config.masq_url_insecure =
        m.get("insecure").and_then(|x| x.as_bool()).unwrap_or(false);
    config.masq_string = get_str("content").to_string();
    if let Some(h) = m.get("headers") {
        let Some(hm) = h.as_object() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "masquerade.headers must be a JSON object",
            ));
        };
        config.masq_string_headers = hm
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
            .collect();
    }
    config.masq_string_status_code = m
        .get("statusCode")
        .and_then(|x| x.as_i64())
        .unwrap_or(0) as i32;
    Ok(())
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
