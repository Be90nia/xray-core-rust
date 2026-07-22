//! # 域名规范解析（对应 Go `xdns/spec.go`）
//!
//! - `domain_spec`：从 "example.com:txt" 这样的字符串解析出 (Name, rrType)。
//! - `parse_resolver`：解析 "domain:rrType+udp://server" 格式。

use std::io;

use super::dns::{Name, RR_TYPE_A, RR_TYPE_AAAA, RR_TYPE_TXT};

/// 域名规范：name + 期望的 rr_type（0 表示未指定）。
///
/// 对应 Go `domainSpec`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainSpec {
    pub name: Name,
    pub rr_type: u16,
}

/// method 字符串 → RR 类型。空字符串或 "txt" → TXT；"a" → A；"aaaa" → AAAA；其余报错。
///
/// 对应 Go `rrTypeFromMethod`。
pub fn rr_type_from_method(method: &str) -> io::Result<u16> {
    match method.to_ascii_lowercase().as_str() {
        "" | "txt" => Ok(RR_TYPE_TXT),
        "a" => Ok(RR_TYPE_A),
        "aaaa" => Ok(RR_TYPE_AAAA),
        _ => Err(invalid_data("unsupported method")),
    }
}

/// 解析 "domain[:method]" 形式。default_method 在未显式指定 method 时使用（"" 表示不指定）。
///
/// 对应 Go `parseDomainSpec`。
pub fn parse_domain_spec(s: &str, default_method: &str) -> io::Result<DomainSpec> {
    let (domain_part, method, has_method) = match s.rfind(':') {
        Some(i) => (&s[..i], &s[i + 1..], true),
        None => {
            if default_method.is_empty() {
                (s, "", false)
            } else {
                (s, default_method, true)
            }
        }
    };

    if domain_part.is_empty() {
        return Err(invalid_data("empty domain"));
    }

    let name = Name::parse(domain_part)?;

    let rr_type = if has_method {
        rr_type_from_method(method)?
    } else {
        0
    };

    Ok(DomainSpec { name, rr_type })
}

/// 解析 "domain[:rrType]+udp://server" 形式，返回 (domain Name, server, rrType)。
///
/// 对应 Go `parseResolver`。默认 method = "txt"。
pub fn parse_resolver(s: &str) -> io::Result<(Name, String, u16)> {
    let Some((head, server)) = s.split_once("+udp://") else {
        return Err(invalid_data("invalid resolver scheme"));
    };
    if server.is_empty() {
        return Err(invalid_data("empty resolver server"));
    }
    let spec = parse_domain_spec(head, "txt")?;
    Ok((spec.name, server.to_string(), spec.rr_type))
}

fn invalid_data(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rr_type_from_method_table() {
        assert_eq!(rr_type_from_method("").unwrap(), RR_TYPE_TXT);
        assert_eq!(rr_type_from_method("TXT").unwrap(), RR_TYPE_TXT);
        assert_eq!(rr_type_from_method("txt").unwrap(), RR_TYPE_TXT);
        assert_eq!(rr_type_from_method("A").unwrap(), RR_TYPE_A);
        assert_eq!(rr_type_from_method("aaaa").unwrap(), RR_TYPE_AAAA);
        assert!(rr_type_from_method("mx").is_err());
    }

    #[test]
    fn parse_domain_spec_variants() {
        // 不带 method → rr_type = 0
        let s = parse_domain_spec("example.com", "").unwrap();
        assert_eq!(s.name, Name::parse("example.com").unwrap());
        assert_eq!(s.rr_type, 0);

        // 带显式 method
        let s = parse_domain_spec("example.com:txt", "").unwrap();
        assert_eq!(s.rr_type, RR_TYPE_TXT);

        let s = parse_domain_spec("example.com:a", "").unwrap();
        assert_eq!(s.rr_type, RR_TYPE_A);

        // 使用 default_method
        let s = parse_domain_spec("example.com", "txt").unwrap();
        assert_eq!(s.rr_type, RR_TYPE_TXT);

        // 空域名报错
        assert!(parse_domain_spec("", "").is_err());
        assert!(parse_domain_spec(":txt", "").is_err());
    }

    #[test]
    fn parse_resolver_valid_and_invalid() {
        // 正常格式
        let (name, server, rr) = parse_resolver("t.example.com+udp://8.8.8.8:53").unwrap();
        assert_eq!(name, Name::parse("t.example.com").unwrap());
        assert_eq!(server, "8.8.8.8:53");
        assert_eq!(rr, RR_TYPE_TXT);

        // 带 method
        let (_name, server, rr) = parse_resolver("t.example.com:a+udp://1.1.1.1:53").unwrap();
        assert_eq!(server, "1.1.1.1:53");
        assert_eq!(rr, RR_TYPE_A);

        // 缺 scheme
        assert!(parse_resolver("t.example.com").is_err());
        // 空 server
        assert!(parse_resolver("t.example.com+udp://").is_err());
        // 空域名
        assert!(parse_resolver("+udp://8.8.8.8:53").is_err());
    }
}
