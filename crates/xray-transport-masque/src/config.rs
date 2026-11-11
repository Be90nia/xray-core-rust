//! `masqueSettings` 配置解析（Go `infra/conf/transport_method.go:806-901
//! MasqueConfig.Build` + `transport/internet/masque/config.go:12 DefaultPath`）。
//!
//! B1 范围（规划 §5 B1.3）：host / path（缺省 + URI 模板展开）/ headers（token 校验 +
//! 保留键拒绝）/ user+pass（→ `Authorization: Basic`，Go :874-880）；
//! `warp` 出现即 Err（非目标 1，L5 装配门）；proto 侧 [`Config::from_proto`] 同判。

use std::collections::HashMap;

use crate::error::{MasqueError, Result};

/// 缺省路径（Go `transport/internet/masque/config.go:12`；字面 `*` 原样发）。
pub const DEFAULT_PATH: &str = "/.well-known/masque/ip/*/*/";

/// MASQUE transport 配置（masqueSettings 解析产物）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `host[:port]`（authority 形态；空 = 走拨号目标的 host）。
    pub host: String,
    /// CONNECT-IP 请求路径（已展开 URI 模板；缺省 [`DEFAULT_PATH`]）。
    pub path: String,
    /// 附加请求头（已含 user/pass 推导出的 `Authorization`）。
    pub headers: HashMap<String, String>,
}

impl Config {
    /// 解析 `masqueSettings` JSON（`None` → 缺省配置，与 Go `loadJSON(nil)` 等价）。
    ///
    /// 校验顺序对齐 Go `Build()`：warp → path → host → headers → user/pass。
    pub fn from_json(v: Option<&serde_json::Value>) -> Result<Config> {
        let Some(v) = v else {
            return Ok(Config {
                host: String::new(),
                path: DEFAULT_PATH.to_string(),
                headers: HashMap::new(),
            });
        };
        let obj = v.as_object().ok_or_else(|| {
            MasqueError::Protocol("masqueSettings: settings must be a JSON object".into())
        })?;

        // 非目标 1（规划 §1.2）：WARP 变体（ECDSA 临时证书 + draft datagram setting）
        // 不移植，配置出现即 fail-visible 拒绝。
        if obj.get("warp").is_some_and(|w| !w.is_null()) {
            return Err(MasqueError::Protocol("masqueSettings: \"warp\" is not supported".into()));
        }

        let path = normalize_path(obj.get("path").and_then(|p| p.as_str()).unwrap_or(""))?;

        let host = obj.get("host").and_then(|h| h.as_str()).unwrap_or("").to_string();
        validate_host(&host)?;

        let user = obj.get("user").and_then(|u| u.as_str()).unwrap_or("");
        let pass = obj.get("pass").and_then(|p| p.as_str()).unwrap_or("");

        let mut headers = HashMap::new();
        if let Some(h) = obj.get("headers") {
            let Some(map) = h.as_object() else {
                return Err(MasqueError::Protocol(
                    "masqueSettings: \"headers\" must be an object".into(),
                ));
            };
            for (k, val) in map {
                let Some(val) = val.as_str() else {
                    return Err(MasqueError::Protocol(format!(
                        "masqueSettings: invalid header in \"headers\": \"{k}\""
                    )));
                };
                if !is_token(k) || !is_field_value(val) {
                    return Err(MasqueError::Protocol(format!(
                        "masqueSettings: invalid header in \"headers\": \"{k}\""
                    )));
                }
                match k.to_ascii_lowercase().as_str() {
                    "host" | "capsule-protocol" => {
                        return Err(MasqueError::Protocol(format!(
                            "masqueSettings: \"headers\" can't contain \"{k}\""
                        )));
                    },
                    "authorization" if !user.is_empty() || !pass.is_empty() => {
                        return Err(MasqueError::Protocol(
                            "masqueSettings: \"headers\" can't contain \"authorization\" when \"user\" or \"pass\" is set"
                                .into(),
                        ));
                    },
                    _ => {},
                }
                headers.insert(k.clone(), val.to_string());
            }
        }

        if user.contains(':') {
            return Err(MasqueError::Protocol(format!("masqueSettings: invalid \"user\": {user}")));
        }
        if !user.is_empty() || !pass.is_empty() {
            use base64::Engine as _;
            let cred = format!("{user}:{pass}");
            headers.insert(
                "Authorization".to_string(),
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(cred.as_bytes())
                ),
            );
        }

        Ok(Config { host, path, headers })
    }

    /// 从 proto `Config` 构造（Go 侧 Build 产物已带终值；`warp` 出现即 Err）。
    pub fn from_proto(cfg: &xray_proto::transport::internet::masque::Config) -> Result<Config> {
        if cfg.warp.is_some() {
            return Err(MasqueError::Protocol(
                "masque: proto config \"warp\" is not supported".into(),
            ));
        }
        Ok(Config {
            host: cfg.host.clone(),
            path: if cfg.path.is_empty() { DEFAULT_PATH.to_string() } else { cfg.path.clone() },
            headers: cfg.headers.clone(),
        })
    }
}

/// path 缺省 + URI 模板展开 + 校验（Go `transport_method.go:844-849`）。
///
/// 模板替换按 Go `strings.NewReplacer` 六个模式逐字面替换（六个模式互不为子串，
/// 顺序替换与同步替换等价）；替换后仍含 `{`/`}` 即硬错。
fn normalize_path(path: &str) -> Result<String> {
    let path = if path.is_empty() { DEFAULT_PATH } else { path };
    let path = path
        .replace("{target}", "*")
        .replace("{ipproto}", "*")
        .replace("{?target,ipproto}", "?target=*&ipproto=*")
        .replace("{?ipproto,target}", "?ipproto=*&target=*")
        .replace("{&target,ipproto}", "&target=*&ipproto=*")
        .replace("{&ipproto,target}", "&ipproto=*&target=*");
    if !path.starts_with('/') || path.contains('{') || path.contains('}') {
        return Err(MasqueError::Protocol(format!(
            "masqueSettings: invalid \"path\": {path}, only the variables {{target}} and {{ipproto}} are supported"
        )));
    }
    Ok(path)
}

/// host 校验：`host[:port]` authority 形态（Go `transport_method.go:850-852` 用
/// `url.Parse("https://"+host)` 且要求 `u.Host == host`；本仓无 url crate，手工校验
/// 同形态——IPv6 字面量 `[..]` 或 reg-name，端口段纯数字，拒绝 userinfo/path/空白）。
fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() {
        return Ok(());
    }
    let invalid = || MasqueError::Protocol(format!("masqueSettings: invalid \"host\": {host}"));
    let (name, port, bracketed) = match host.strip_prefix('[') {
        Some(rest) => {
            let Some(end) = rest.find(']') else { return Err(invalid()) };
            (&rest[..end], &rest[end + 1..], true)
        },
        None => match host.rfind(':') {
            Some(i) => (&host[..i], &host[i..], false),
            None => (host, "", false),
        },
    };
    let port_ok =
        port.is_empty() || (port.len() > 1 && port[1..].bytes().all(|b| b.is_ascii_digit()));
    let mut name_ok = !name.is_empty() && !name.contains(['/', '?', '#', '@', ' ', '\t', '[', ']']);
    // 非 bracket 形态多冒号 = 裸 IPv6（Go url.Parse 拒绝）；bracket 字面量的冒号合法。
    if !bracketed {
        name_ok &= !name.contains(':');
    }
    if port_ok && name_ok { Ok(()) } else { Err(invalid()) }
}

/// RFC 7230 token 字符集（Go `httpguts.ValidHeaderFieldName`）。
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            matches!(
                b,
                b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^'
                    | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z'
            )
        })
}

/// 头字段值字符集：SP/HTAB/VISIBLE/obs-text，禁 CTL 与 DEL
/// （Go `httpguts.ValidHeaderFieldValue`）。
fn is_field_value(value: &str) -> bool {
    value.bytes().all(|b| b == b'\t' || b == b' ' || (0x21..=0x7E).contains(&b) || b >= 0x80)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn none_yields_default_path() {
        let cfg = Config::from_json(None).expect("None should be default config");
        assert_eq!(cfg.path, DEFAULT_PATH);
        assert_eq!(cfg.host, "");
        assert!(cfg.headers.is_empty());
    }

    #[test]
    fn host_and_headers_roundtrip() {
        // Go masque_test.go:85-98 同形态输入。
        let cfg = Config::from_json(Some(&json!({
            "host": "example.com:8443",
            "path": "/.well-known/masque/ip/{target}/{ipproto}/",
            "headers": { "Authorization": "Basic dTpw" }
        })))
        .expect("valid settings should parse");
        assert_eq!(cfg.host, "example.com:8443");
        // {target}/{ipproto} 模板 → 字面 *
        assert_eq!(cfg.path, "/.well-known/masque/ip/*/*/");
        assert_eq!(cfg.headers.get("Authorization").map(String::as_str), Some("Basic dTpw"));
    }

    #[test]
    fn uri_template_query_form_expands() {
        // Go masque_test.go:99-103：{?target,ipproto} → ?target=*&ipproto=*
        let cfg = Config::from_json(Some(&json!({ "path": "/masque/ip{?target,ipproto}" })))
            .expect("template path should parse");
        assert_eq!(cfg.path, "/masque/ip?target=*&ipproto=*");
    }

    #[test]
    fn user_pass_derives_basic_authorization() {
        // Go masque_test.go:104-110：user=u pass=p:q → Authorization: Basic dTpwOnE=
        let cfg = Config::from_json(Some(&json!({
            "user": "u", "pass": "p:q", "headers": { "X-Token": "a" }
        })))
        .expect("user/pass settings should parse");
        assert_eq!(cfg.headers.get("Authorization").map(String::as_str), Some("Basic dTpwOnE="));
        assert_eq!(cfg.headers.get("X-Token").map(String::as_str), Some("a"));
    }

    #[test]
    fn warp_is_rejected() {
        let err = Config::from_json(Some(&json!({ "warp": { "privateKey": "k" } })))
            .expect_err("warp must be rejected");
        assert!(err.to_string().contains("warp"), "got {err}");
    }

    #[test]
    fn user_with_colon_is_invalid() {
        let err = Config::from_json(Some(&json!({ "user": "a:b", "pass": "p" })))
            .expect_err("user with colon must be invalid");
        assert!(err.to_string().contains("invalid \"user\""), "got {err}");
    }

    #[test]
    fn forbidden_header_keys_rejected() {
        for key in ["Host", "Capsule-Protocol"] {
            let err = Config::from_json(Some(&json!({ "headers": { key: "x" } })))
                .expect_err("reserved header must be rejected");
            assert!(err.to_string().contains("can't contain"), "got {err}");
        }
    }

    #[test]
    fn authorization_conflicts_with_user_pass() {
        let err = Config::from_json(Some(&json!({
            "user": "u", "pass": "p", "headers": { "Authorization": "Basic eHg=" }
        })))
        .expect_err("authorization header + user/pass must conflict");
        assert!(err.to_string().contains("authorization"), "got {err}");
    }

    #[test]
    fn invalid_path_rejected() {
        // Go 检查 = 必须以 / 开头 + 替换后不得含 {}（transport_method.go:848-849）；
        // 含空格等其余字符 Go 不拒——按 Go 语义放行（下面第二个断言）。
        for path in ["no-leading-slash", "/has{unknown}brace", "{?target,ipproto}"] {
            let err = Config::from_json(Some(&json!({ "path": path })))
                .expect_err("invalid path must be rejected");
            assert!(err.to_string().contains("invalid \"path\""), "path={path} got {err}");
        }
        let spaced = Config::from_json(Some(&json!({ "path": "/path with space" })))
            .expect("Go-side check only rejects non-/ prefix and braces");
        assert_eq!(spaced.path, "/path with space");
    }

    #[test]
    fn host_validation() {
        assert!(Config::from_json(Some(&json!({ "host": "example.com:8443" }))).is_ok());
        assert!(Config::from_json(Some(&json!({ "host": "[2001:db8::1]:443" }))).is_ok());
        assert!(
            Config::from_json(Some(&json!({ "host": "2001:db8::1" })))
                .expect_err("bare ipv6 without brackets is not an authority")
                .to_string()
                .contains("invalid \"host\"")
        );
        assert!(
            Config::from_json(Some(&json!({ "host": "user:pass@example.com" })))
                .expect_err("userinfo must be rejected")
                .to_string()
                .contains("invalid \"host\"")
        );
        assert!(
            Config::from_json(Some(&json!({ "host": "example.com/path" })))
                .expect_err("path suffix must be rejected")
                .to_string()
                .contains("invalid \"host\"")
        );
    }

    #[test]
    fn proto_warp_is_rejected_and_fields_copied() {
        let proto = xray_proto::transport::internet::masque::Config {
            host: "example.com:8443".into(),
            path: String::new(), // Go Build 产物恒非空；此处验证缺省兜底
            headers: [("X-Token".to_string(), "a".to_string())].into_iter().collect(),
            warp: None,
            xmux: None,
        };
        let cfg = Config::from_proto(&proto).expect("proto config without warp should pass");
        assert_eq!(cfg.host, "example.com:8443");
        assert_eq!(cfg.path, DEFAULT_PATH);
        assert_eq!(cfg.headers.get("X-Token").map(String::as_str), Some("a"));

        let proto_warp = xray_proto::transport::internet::masque::Config {
            warp: Some(xray_proto::transport::internet::masque::Warp::default()),
            ..proto
        };
        assert!(Config::from_proto(&proto_warp).is_err(), "proto warp must be rejected");
    }

    #[test]
    fn non_object_settings_rejected() {
        assert!(Config::from_json(Some(&json!("masque"))).is_err());
        assert!(Config::from_json(Some(&json!(42))).is_err());
    }
}
