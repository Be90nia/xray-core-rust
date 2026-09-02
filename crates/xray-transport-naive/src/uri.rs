//! `naive+https://` 分享链接解析 + xray outbound settings JSON 解析。

use serde_json::Value;
use xray_tls::fingerprint::{get_fingerprint, Fingerprint};

/// naive 出站配置。
#[derive(Debug, Clone)]
pub struct NaiveConfig {
    /// naive 服务器主机（域名或 IP）。
    pub host: String,
    /// naive 服务器端口。
    pub port: u16,
    /// TLS SNI（缺省 = host）。
    pub sni: String,
    /// Basic auth 用户名。
    pub username: String,
    /// Basic auth 密码。
    pub password: String,
    /// TLS 指纹（缺省 Chrome 133）。
    pub fingerprint: Fingerprint,
}

impl NaiveConfig {
    fn new(host: String, port: u16, username: String, password: String) -> Self {
        Self {
            sni: host.clone(),
            host,
            port,
            username,
            password,
            fingerprint: Fingerprint::HelloChrome133,
        }
    }

    /// xray outbound settings JSON → [`NaiveConfig`]。
    ///
    /// JSON 格式：
    /// `{ "server": "...", "port": 443, "sni": "...", "username": "...", "password": "...", "fingerprint": "chrome" }`
    pub fn from_json(v: &Value) -> Result<Self, String> {
        let server = v.get("server").and_then(Value::as_str).ok_or("missing server")?;
        let port = v.get("port").and_then(Value::as_u64).ok_or("missing port")?;
        let port = u16::try_from(port).map_err(|_| "port out of range")?;
        let username = v.get("username").and_then(Value::as_str).ok_or("missing username")?;
        let password = v.get("password").and_then(Value::as_str).ok_or("missing password")?;
        let mut config = Self::new(
            server.to_string(),
            port,
            username.to_string(),
            password.to_string(),
        );
        if let Some(sni) = v.get("sni").and_then(Value::as_str) {
            config.sni = sni.to_string();
        }
        if let Some(fp) = v.get("fingerprint").and_then(Value::as_str) {
            config.fingerprint = get_fingerprint(fp).map_err(|e| format!("fingerprint: {e}"))?;
        }
        Ok(config)
    }
}

/// 最小 percent-decode（userinfo/sni 值；非法序列原样保留）。
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3);
            if let Some(h) = hex.and_then(|h| std::str::from_utf8(h).ok()) {
                if let Ok(b) = u8::from_str_radix(h, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 解析 `naive+https://user:pass@host:port?security=tls&type=tcp&headerType=none`。
///
/// 仅支持 TLS 传输（naive 本义）；`sni=` 可覆盖 SNI，其余查询参数忽略。
pub fn parse_naive_uri(uri: &str) -> Result<NaiveConfig, String> {
    let rest = uri
        .trim()
        .strip_prefix("naive+https://")
        .ok_or_else(|| "scheme must be naive+https://".to_string())?;
    let rest = rest.split('#').next().unwrap_or(rest);
    let (userinfo, hostport) = rest
        .split_once('@')
        .ok_or("missing userinfo (user:pass@host:port)")?;
    let (hostport, query) = hostport.split_once('?').unwrap_or((hostport, ""));
    let (username, password) = userinfo
        .split_once(':')
        .ok_or("userinfo must be user:pass")?;
    // hostport：host:port / [::1]:port / host（缺省 443）
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>().map_err(|_| format!("invalid port: {p}"))?,
        ),
        None => (hostport, 443),
    };
    let host = pct_decode(host.trim_start_matches('[').trim_end_matches(']'));
    let mut config = NaiveConfig::new(
        host,
        port,
        pct_decode(username),
        pct_decode(password),
    );
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k {
            "sni" if !v.is_empty() => config.sni = pct_decode(v),
            "security" if !v.is_empty() && !v.eq_ignore_ascii_case("tls") => {
                return Err(format!("naive only supports security=tls, got {v}"));
            }
            _ => {}
        }
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_URI: &str = "naive+https://QaQD9ODM:a0832f31-62c1-4197-ac85-2634e38ab700@sg.yzswgroup.top:39748?security=tls&type=tcp&headerType=none";

    #[test]
    fn parse_real_node_uri() {
        let c = parse_naive_uri(REAL_URI).unwrap();
        assert_eq!(c.host, "sg.yzswgroup.top");
        assert_eq!(c.port, 39748);
        assert_eq!(c.sni, "sg.yzswgroup.top");
        assert_eq!(c.username, "QaQD9ODM");
        assert_eq!(c.password, "a0832f31-62c1-4197-ac85-2634e38ab700");
    }

    #[test]
    fn parse_sni_override_and_fragment() {
        let c = parse_naive_uri(
            "naive+https://u%3Ax:p%40ss@host.example:8443?sni=cdn.example#name",
        )
        .unwrap();
        assert_eq!(c.username, "u:x");
        assert_eq!(c.password, "p@ss");
        assert_eq!(c.sni, "cdn.example");
        assert_eq!(c.host, "host.example");
    }

    #[test]
    fn reject_wrong_scheme_and_security() {
        assert!(parse_naive_uri("https://u:p@h").is_err());
        assert!(
            parse_naive_uri("naive+https://u:p@h?security=reality").is_err(),
            "非 tls security 必须拒绝"
        );
    }

    #[test]
    fn from_json_maps_settings() {
        let v: Value = serde_json::json!({
            "server": "s.example", "port": 443, "sni": "cdn.example",
            "username": "u", "password": "p", "fingerprint": "firefox"
        });
        let c = NaiveConfig::from_json(&v).unwrap();
        assert_eq!(c.host, "s.example");
        assert_eq!(c.fingerprint, Fingerprint::Firefox);
    }

    #[test]
    fn from_json_defaults() {
        let v: Value =
            serde_json::json!({"server": "s.example", "port": 443, "username": "u", "password": "p"});
        let c = NaiveConfig::from_json(&v).unwrap();
        assert_eq!(c.sni, "s.example");
        assert_eq!(c.fingerprint, Fingerprint::HelloChrome133);
    }
}
