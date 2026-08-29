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
    use std::collections::HashMap;

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

    // ===== bd v5g：transport Config 11 字段双向覆盖 =====

    /// 全 11 字段填充的 Config（canonical 形态：masq_type 小写、status_code 非 0）。
    fn full_config() -> Config {
        Config {
            version: 2,
            auth: "server-auth".into(),
            udp_idle_timeout: 60,
            masq_type: "string".into(),
            masq_file: "/var/www".into(),
            masq_url: "https://masq.example.com".into(),
            masq_url_rewrite_host: true,
            masq_url_insecure: false,
            masq_string: "hello".into(),
            masq_string_headers: HashMap::from([
                ("X-Custom".into(), "value".into()),
                ("X-Other".into(), "v2".into()),
            ]),
            masq_string_status_code: 201,
        }
    }

    #[test]
    fn masq_from_config_to_config_roundtrip_variants() {
        use crate::hub::MasqType;
        // 4 种变体 × 自洽 source（variant 消费的 masq 字段填值，其余默认），
        // from_config → to_config → 全 11 字段恒等
        let direct = Config {
            version: 2,
            auth: "server-auth".into(),
            udp_idle_timeout: 60,
            ..Config::default()
        };
        let cases: Vec<(Config, MasqType)> = vec![
            (
                Config { masq_type: String::new(), ..direct.clone() },
                MasqType::NotFound,
            ),
            (
                Config {
                    masq_type: "file".into(),
                    masq_file: "/var/www".into(),
                    ..direct.clone()
                },
                MasqType::File("/var/www".into()),
            ),
            (
                Config {
                    masq_type: "proxy".into(),
                    masq_url: "https://masq.example.com".into(),
                    masq_url_rewrite_host: true,
                    masq_url_insecure: true,
                    ..direct.clone()
                },
                MasqType::Proxy {
                    url: "https://masq.example.com".into(),
                    rewrite_host: true,
                    insecure: true,
                },
            ),
            (
                Config {
                    masq_type: "string".into(),
                    masq_string: "hello".into(),
                    masq_string_headers: HashMap::from([("X-Custom".into(), "value".into())]),
                    masq_string_status_code: 201,
                    ..direct.clone()
                },
                MasqType::String {
                    body: "hello".into(),
                    headers: HashMap::from([("X-Custom".into(), "value".into())]),
                    status_code: 201,
                },
            ),
        ];
        for (src, m) in cases {
            assert_eq!(MasqType::from_config(&src).unwrap(), m);
            let mut out = Config::default();
            m.to_config(&mut out);
            // masq 8 字段逐项恒等（version/auth/udp_idle_timeout 由上层直写，
            // to_config 不触碰——见 transport_config_direct_fields_documented_consumers）
            assert_eq!(out.masq_type, src.masq_type);
            assert_eq!(out.masq_file, src.masq_file);
            assert_eq!(out.masq_url, src.masq_url);
            assert_eq!(out.masq_url_rewrite_host, src.masq_url_rewrite_host);
            assert_eq!(out.masq_url_insecure, src.masq_url_insecure);
            assert_eq!(out.masq_string, src.masq_string);
            assert_eq!(out.masq_string_headers, src.masq_string_headers);
            assert_eq!(out.masq_string_status_code, src.masq_string_status_code);
        }
    }


    #[test]
    fn transport_config_direct_fields_documented_consumers() {
        // version/auth/udp_idle_timeout 非 masq 字段：运行时直接读 prost 字段
        //（Go hub.go:63 config.Auth、hub.go:95 config.UdpIdleTimeout、
        // dialer.go:202 config.Auth；version 仅 JSON 层校验 ==2，
        // infra/conf/transport_internet.go:526-527）。
        let c = full_config();
        assert_eq!(c.version, 2);
        assert_eq!(c.auth, "server-auth");
        assert_eq!(c.udp_idle_timeout, 60);
    }

    #[test]
    fn masq_json_to_proto_roundtrip() {
        // JSON（apply_masquerade_json，Go infra/conf/transport_internet.go:542-549
        // 展开方向）→ proto Config → MasqType → to_config 往返
        let mut c = Config::default();
        apply_masquerade_json(
            &mut c,
            &serde_json::json!({
                "type": "string",
                "content": "page body",
                "headers": {"X-A": "1"},
                "statusCode": 200
            }),
        )
        .unwrap();
        let m = crate::hub::MasqType::from_config(&c).unwrap();
        let mut out = Config::default();
        m.to_config(&mut out);
        assert_eq!(out, c);
    }
}
