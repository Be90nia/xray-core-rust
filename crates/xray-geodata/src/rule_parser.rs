//! 规则解析器
//!
//! 对应 Go 版本 `common/geodata/rule_parser.go`，将路由规则字符串
//! 解析为 protobuf 类型 `IpRule` / `DomainRule`。
//!
//! 支持的前缀格式：
//! - `geoip:XX` → 从默认 geoip.dat 加载国家 IP
//! - `geosite:XX` → 从默认 geosite.dat 加载域名
//! - `ext:file:code` / `ext-ip:file:code` → 从指定文件加载 IP
//! - `ext-domain:file:code` → 从指定文件加载域名
//! - `!` 前缀 → 反转匹配（可叠加，每多一个 `!` 反转一次）
//! - CIDR 格式 → 自定义 IP 规则
//! - `regexp:/domain:/full:/keyword:/dotless:` → 自定义域名规则

use std::net::IpAddr;
use std::path::Path;

use crate::geosite::DomainType;
use crate::loader::GeoDataLoader;
use crate::pb::{
  domain_rule::Value as DomainRuleValue, ip_rule::Value as IpRuleValue,
  Cidr, CidrRule, Domain, DomainRule, GeoIpRule, GeoSiteRule, IpRule,
};

// ── 常量 ────────────────────────────────────────────────────────

/// 默认 GeoIP 数据文件名。
pub const DEFAULT_GEOIP_DAT: &str = "geoip.dat";

/// 默认 GeoSite 数据文件名。
pub const DEFAULT_GEOSITE_DAT: &str = "geosite.dat";

// ── 错误类型 ────────────────────────────────────────────────────

/// 规则解析错误。
#[derive(Debug, thiserror::Error)]
pub enum RuleParserError {
  /// 非法 IP 规则
  #[error("非法 IP 规则: {0}")]
  IllegalIPRule(String),

  /// 非法域名规则
  #[error("非法域名规则: {0}")]
  IllegalDomainRule(String),

  /// 语法错误
  #[error("语法错误: {0}")]
  SyntaxError(String),

  /// 文件名为空
  #[error("文件名为空")]
  EmptyFile,

  /// 代码为空
  #[error("代码为空")]
  EmptyCode,

  /// 属性为空
  #[error("属性为空")]
  EmptyAttr,

  /// 无效的 CIDR 前缀长度
  #[error("无效的 CIDR 前缀: {0}")]
  InvalidCidrPrefix(String),

  /// CIDR 前缀长度超出范围
  #[error("CIDR 前缀过大: {prefix}, 最大: {max}")]
  CidrPrefixTooLarge { prefix: u32, max: u32 },

  /// 不支持的地址族
  #[error("不支持的地址族")]
  UnsupportedAddressFamily,

  /// 无效的 IP 地址
  #[error("无效的 IP 地址: {0}")]
  InvalidIPAddress(String),

  /// dotless 规则包含点号
  #[error("dotless 规则不能包含点号: {0}")]
  DotlessContainsDot(String),

  /// 文件校验失败
  #[error("文件校验失败: {0}")]
  FileCheckFailed(String),

  /// IO 错误
  #[error("IO 错误: {0}")]
  Io(#[from] std::io::Error),
}

// ── 公共函数 ────────────────────────────────────────────────────

/// 解析 IP 规则列表。
///
/// 遍历 `rules`，对每条规则调用 [`cut_reverse_prefix`] 去除 `!` 前缀，
/// 然后按前缀分派到对应的解析函数。
///
/// - `geoip:XX` → 转为 `ext:geoip.dat:XX`
/// - `ext:` / `ext-ip:` → [`parse_geo_ip_rule`]
/// - 其他 → [`parse_custom_ip_rule`]（CIDR 格式）
pub fn parse_ip_rules(
  rules: &[String],
  datadir: &Path,
) -> Result<Vec<IpRule>, RuleParserError> {
  rules
    .iter()
    .map(|rule| {
      let (rule, reverse) = cut_reverse_prefix(rule);
      if rule.starts_with("geoip:") {
        let code = &rule[6..];
        let expanded = format!("ext:{}:{}", DEFAULT_GEOIP_DAT, code);
        parse_geo_ip_rule(&expanded, reverse, datadir)
      } else if rule.starts_with("ext:") || rule.starts_with("ext-ip:") {
        parse_geo_ip_rule(rule, reverse, datadir)
      } else {
        parse_custom_ip_rule(rule, reverse)
      }
    })
    .collect()
}

/// 解析单条域名规则。
///
/// - `geosite:XX` → 转为 `ext:geosite.dat:XX`
/// - `ext:` / `ext-domain:` → [`parse_geo_site_rule`]
/// - 其他 → [`parse_custom_domain_rule`]
pub fn parse_domain_rule(
  rule: &str,
  default_type: DomainType,
  datadir: &Path,
) -> Result<DomainRule, RuleParserError> {
  let (rule, _) = cut_reverse_prefix(rule);
  if rule.starts_with("geosite:") {
    let code = &rule[8..];
    let expanded = format!("ext:{}:{}", DEFAULT_GEOSITE_DAT, code);
    parse_geo_site_rule(&expanded, datadir)
  } else if rule.starts_with("ext:") || rule.starts_with("ext-domain:") {
    parse_geo_site_rule(rule, datadir)
  } else {
    parse_custom_domain_rule(rule, default_type)
  }
}

/// 批量解析域名规则列表。
///
/// 对每条规则调用 [`parse_domain_rule`]。
pub fn parse_domain_rules(
  rules: &[String],
  default_type: DomainType,
  datadir: &Path,
) -> Result<Vec<DomainRule>, RuleParserError> {
  rules
    .iter()
    .map(|rule| parse_domain_rule(rule, default_type, datadir))
    .collect()
}

// ── 内部函数 ────────────────────────────────────────────────────

/// 去除前导 `!` 并计算反转标志。
///
/// 每遇到一个 `!` 前缀，反转一次 bool。
/// 例如 `!!geoip:cn` 返回 `("geoip:cn", false)`。
#[must_use]
pub fn cut_reverse_prefix(s: &str) -> (&str, bool) {
  let remaining = s.trim_start_matches('!');
  let bangs = s.len() - remaining.len();
  (remaining, bangs % 2 == 1)
}

/// 解析 geoip/ext/ext-ip 前缀的 IP 规则。
///
/// 格式: `ext:filename:code` 或 `ext-ip:filename:code`。
/// `code` 也支持 `!` 前缀（与 outer_reverse 做 XOR），
/// 并转换为大写。
fn parse_geo_ip_rule(
  rule: &str,
  outer_reverse: bool,
  datadir: &Path,
) -> Result<IpRule, RuleParserError> {
  let body = if rule.starts_with("ext-ip:") {
    &rule[7..]
  } else if rule.starts_with("ext:") {
    &rule[4..]
  } else {
    return Err(RuleParserError::IllegalIPRule(rule.to_string()));
  };

  let parts: Vec<&str> = body.splitn(2, ':').collect();
  if parts.len() != 2 {
    return Err(RuleParserError::SyntaxError(rule.to_string()));
  }
  let file = parts[0];
  let code_part = parts[1];

  if file.is_empty() {
    return Err(RuleParserError::EmptyFile);
  }

  let (code, inner_reverse) = cut_reverse_prefix(code_part);
  let reverse = outer_reverse ^ inner_reverse;
  let code = code.to_uppercase();

  if code.is_empty() {
    return Err(RuleParserError::EmptyCode);
  }

  check_file(datadir, file, &code)?;

  Ok(IpRule {
    value: Some(IpRuleValue::Geoip(GeoIpRule {
      file: file.to_string(),
      code,
      reverse_match: reverse,
    })),
  })
}

/// 解析自定义 IP 规则（CIDR 格式）。
fn parse_custom_ip_rule(
  rule: &str,
  reverse: bool,
) -> Result<IpRule, RuleParserError> {
  let cidr = parse_cidr(rule)?;
  Ok(IpRule {
    value: Some(IpRuleValue::Custom(CidrRule {
      cidr: Some(cidr),
      reverse_match: reverse,
    })),
  })
}

/// 解析 CIDR 字符串。
///
/// 格式: `ip/prefix`，例如 `10.0.0.0/8` 或 `::1/128`。
/// 不含 `/` 的按最大前缀长度处理（单地址）。
pub fn parse_cidr(s: &str) -> Result<Cidr, RuleParserError> {
  let (ip_str, prefix_str) = match s.rfind('/') {
    Some(pos) => (&s[..pos], &s[pos + 1..]),
    None => (s, ""),
  };

  let ip: IpAddr = ip_str
    .parse()
    .map_err(|_| RuleParserError::InvalidIPAddress(ip_str.to_string()))?;

  let max_prefix = match ip {
    IpAddr::V4(_) => 32u32,
    IpAddr::V6(_) => 128u32,
  };

  let prefix = if prefix_str.is_empty() {
    max_prefix
  } else {
    prefix_str
      .parse::<u32>()
      .map_err(|_| RuleParserError::InvalidCidrPrefix(prefix_str.to_string()))?
  };

  if prefix > max_prefix {
    return Err(RuleParserError::CidrPrefixTooLarge {
      prefix,
      max: max_prefix,
    });
  }

  let ip_bytes = match ip {
    IpAddr::V4(v4) => v4.octets().to_vec(),
    IpAddr::V6(v6) => v6.octets().to_vec(),
  };

  Ok(Cidr::new(ip_bytes, prefix))
}

/// 解析 ext/ext-domain 前缀的域名规则。
///
/// 格式: `ext:filename:code` 或 `ext-domain:filename:code@attr1@attr2`。
fn parse_geo_site_rule(
  rule: &str,
  datadir: &Path,
) -> Result<DomainRule, RuleParserError> {
  let body = if rule.starts_with("ext-domain:") {
    &rule[11..]
  } else if rule.starts_with("ext:") {
    &rule[4..]
  } else {
    return Err(RuleParserError::IllegalDomainRule(rule.to_string()));
  };

  let parts: Vec<&str> = body.splitn(2, ':').collect();
  if parts.len() != 2 {
    return Err(RuleParserError::SyntaxError(rule.to_string()));
  }
  let file = parts[0];
  let code_with_attrs = parts[1];

  if file.is_empty() {
    return Err(RuleParserError::EmptyFile);
  }

  // 检查空 attr：code 以 `@` 结尾或包含 `@@`
  if code_with_attrs.ends_with('@') {
    return Err(RuleParserError::EmptyAttr);
  }
  if code_with_attrs.contains("@@") {
    return Err(RuleParserError::EmptyAttr);
  }

  let (code, attrs) = match code_with_attrs.find('@') {
    Some(pos) => (&code_with_attrs[..pos], &code_with_attrs[pos + 1..]),
    None => (code_with_attrs, ""),
  };

  let code = code.to_uppercase();

  if code.is_empty() {
    return Err(RuleParserError::EmptyCode);
  }

  check_file(datadir, file, &code)?;

  Ok(DomainRule {
    value: Some(DomainRuleValue::Geosite(GeoSiteRule {
      file: file.to_string(),
      code,
      attrs: attrs.to_string(),
    })),
  })
}

/// 解析自定义域名规则。
///
/// 支持的前缀：
/// - `regexp:` → 正则表达式
/// - `domain:` → 域名后缀匹配
/// - `full:` → 完整域名匹配
/// - `keyword:` → 关键字子串匹配
/// - `dotless:` → 无点域名匹配（特殊规则）
/// - 其他 → 使用 `default_type`
pub fn parse_custom_domain_rule(
  rule: &str,
  default_type: DomainType,
) -> Result<DomainRule, RuleParserError> {
  if let Some(value) = rule.strip_prefix("regexp:") {
    return Ok(DomainRule {
      value: Some(DomainRuleValue::Custom(Domain::regex(value))),
    });
  }
  if let Some(value) = rule.strip_prefix("domain:") {
    return Ok(DomainRule {
      value: Some(DomainRuleValue::Custom(Domain::domain(value))),
    });
  }
  if let Some(value) = rule.strip_prefix("full:") {
    return Ok(DomainRule {
      value: Some(DomainRuleValue::Custom(Domain::full(value))),
    });
  }
  if let Some(value) = rule.strip_prefix("keyword:") {
    return Ok(DomainRule {
      value: Some(DomainRuleValue::Custom(Domain::substr(value))),
    });
  }
  if let Some(value) = rule.strip_prefix("dotless:") {
    return parse_dotless_rule(value);
  }

  Ok(DomainRule {
    value: Some(DomainRuleValue::Custom(Domain::new(
      default_type as i32,
      rule,
    ))),
  })
}

/// 解析 dotless 特殊规则。
///
/// - 空串 → 正则 `^[^.]*$`
/// - 无点子串 → 正则 `^[^.]*{substr}[^.]*$`
/// - 有点子串 → 错误 [`RuleParserError::DotlessContainsDot`]
fn parse_dotless_rule(value: &str) -> Result<DomainRule, RuleParserError> {
  if value.is_empty() {
    return Ok(DomainRule {
      value: Some(DomainRuleValue::Custom(Domain::regex("^[^.]*$"))),
    });
  }
  if value.contains('.') {
    return Err(RuleParserError::DotlessContainsDot(value.to_string()));
  }
  let pattern = format!("^[^.]*{}[^.]*$", value);
  Ok(DomainRule {
    value: Some(DomainRuleValue::Custom(Domain::regex(&pattern))),
  })
}

/// 检查 dat 文件中是否存在指定代码的条目。
///
/// 如果 `check_file` 失败，转为 [`RuleParserError::FileCheckFailed`] 错误。
fn check_file(
  datadir: &Path,
  filename: &str,
  code: &str,
) -> Result<(), RuleParserError> {
  let loader = GeoDataLoader::new(datadir.to_path_buf());
  loader
    .check_file(filename, code)
    .map_err(|e| RuleParserError::FileCheckFailed(e.to_string()))
}

// ── 单元测试 ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
  use super::*;
  use crate::geosite::DomainType;

  // ── test_cut_reverse_prefix ─────────────────────────────────

  #[test]
  fn test_cut_reverse_prefix() {
    assert_eq!(cut_reverse_prefix("geoip:cn"), ("geoip:cn", false));
    assert_eq!(cut_reverse_prefix("!geoip:cn"), ("geoip:cn", true));
    assert_eq!(cut_reverse_prefix("!!geoip:cn"), ("geoip:cn", false));
    assert_eq!(
      cut_reverse_prefix("!!!geoip:cn"),
      ("geoip:cn", true)
    );
    assert_eq!(cut_reverse_prefix(""), ("", false));
    assert_eq!(cut_reverse_prefix("!"), ("", true));
    assert_eq!(
      cut_reverse_prefix("!ext:geoip.dat:cn"),
      ("ext:geoip.dat:cn", true)
    );
  }

  // ── test_parse_cidr ─────────────────────────────────────────

  #[test]
  fn test_parse_cidr() {
    // IPv4 CIDR
    let cidr = parse_cidr("10.0.0.0/8").unwrap();
    assert_eq!(cidr.ip, vec![10, 0, 0, 0]);
    assert_eq!(cidr.prefix, 8);

    // IPv4 单地址（无前缀）
    let cidr = parse_cidr("192.168.1.1").unwrap();
    assert_eq!(cidr.ip, vec![192, 168, 1, 1]);
    assert_eq!(cidr.prefix, 32);

    // IPv4 /32
    let cidr = parse_cidr("192.168.1.1/32").unwrap();
    assert_eq!(cidr.ip, vec![192, 168, 1, 1]);
    assert_eq!(cidr.prefix, 32);

    // IPv6 CIDR
    let cidr = parse_cidr("::1/128").unwrap();
    assert_eq!(cidr.prefix, 128);
    assert_eq!(cidr.ip.len(), 16);

    // 前缀超出范围
    let result = parse_cidr("10.0.0.0/33");
    assert!(matches!(
      result,
      Err(RuleParserError::CidrPrefixTooLarge {
        prefix: 33,
        max: 32
      })
    ));

    // 无效 IP
    let result = parse_cidr("invalid/8");
    assert!(matches!(
      result,
      Err(RuleParserError::InvalidIPAddress(_))
    ));

    // 无效前缀
    let result = parse_cidr("10.0.0.0/abc");
    assert!(matches!(
      result,
      Err(RuleParserError::InvalidCidrPrefix(_))
    ));
  }

  // ── test_parse_custom_domain_rule ───────────────────────────

  #[test]
  fn test_parse_custom_domain_rule() {
    // regexp:
    let rule = parse_custom_domain_rule(
      "regexp:.*\\.example\\.com",
      DomainType::Domain,
    )
    .unwrap();
    match rule.value {
      Some(DomainRuleValue::Custom(d)) => {
        assert_eq!(d.r#type, DomainType::Regex as i32);
        assert_eq!(d.value, ".*\\.example\\.com");
      }
      _ => panic!("期望 Custom"),
    }

    // domain:
    let rule = parse_custom_domain_rule(
      "domain:example.com",
      DomainType::Domain,
    )
    .unwrap();
    match rule.value {
      Some(DomainRuleValue::Custom(d)) => {
        assert_eq!(d.r#type, DomainType::Domain as i32);
        assert_eq!(d.value, "example.com");
      }
      _ => panic!("期望 Custom"),
    }

    // full:
    let rule = parse_custom_domain_rule(
      "full:www.example.com",
      DomainType::Domain,
    )
    .unwrap();
    match rule.value {
      Some(DomainRuleValue::Custom(d)) => {
        assert_eq!(d.r#type, DomainType::Full as i32);
        assert_eq!(d.value, "www.example.com");
      }
      _ => panic!("期望 Custom"),
    }

    // keyword:
    let rule = parse_custom_domain_rule(
      "keyword:example",
      DomainType::Domain,
    )
    .unwrap();
    match rule.value {
      Some(DomainRuleValue::Custom(d)) => {
        assert_eq!(d.r#type, DomainType::Substr as i32);
        assert_eq!(d.value, "example");
      }
      _ => panic!("期望 Custom"),
    }

    // 无前缀，使用 default_type
    let rule = parse_custom_domain_rule(
      "example.com",
      DomainType::Full,
    )
    .unwrap();
    match rule.value {
      Some(DomainRuleValue::Custom(d)) => {
        assert_eq!(d.r#type, DomainType::Full as i32);
        assert_eq!(d.value, "example.com");
      }
      _ => panic!("期望 Custom"),
    }
  }

  // ── test_parse_custom_domain_rule_dotless ───────────────────

  #[test]
  fn test_parse_custom_domain_rule_dotless() {
    // dotless: 空串 → "^[^.]*$"
    let rule = parse_custom_domain_rule(
      "dotless:",
      DomainType::Domain,
    )
    .unwrap();
    match rule.value {
      Some(DomainRuleValue::Custom(d)) => {
        assert_eq!(d.r#type, DomainType::Regex as i32);
        assert_eq!(d.value, "^[^.]*$");
      }
      _ => panic!("期望 Custom"),
    }

    // dotless: 无点子串
    let rule = parse_custom_domain_rule(
      "dotless:example",
      DomainType::Domain,
    )
    .unwrap();
    match rule.value {
      Some(DomainRuleValue::Custom(d)) => {
        assert_eq!(d.r#type, DomainType::Regex as i32);
        assert_eq!(d.value, "^[^.]*example[^.]*$");
      }
      _ => panic!("期望 Custom"),
    }

    // dotless: 有点子串 → 错误
    let result = parse_custom_domain_rule(
      "dotless:example.com",
      DomainType::Domain,
    );
    assert!(matches!(
      result,
      Err(RuleParserError::DotlessContainsDot(_))
    ));
  }

  // ── test_parse_ip_rules_reverse ─────────────────────────────
  // 复刻 Go TestParseIPRuleReverse
  // 使用 CIDR 规则（不依赖 dat 文件）

  #[test]
  fn test_parse_ip_rules_reverse() {
    // 单个 ! 反转 CIDR
    let rules: Vec<String> = vec!["!10.0.0.0/8".to_string()];
    let result = parse_ip_rules(&rules, Path::new("/nonexistent"))
      .unwrap();
    assert_eq!(result.len(), 1);
    match &result[0].value {
      Some(IpRuleValue::Custom(cidr_rule)) => {
        assert!(cidr_rule.reverse_match);
        assert_eq!(cidr_rule.cidr.as_ref().unwrap().prefix, 8);
      }
      _ => panic!("期望 Custom"),
    }

    // !! 不反转 CIDR
    let rules: Vec<String> = vec!["!!10.0.0.0/8".to_string()];
    let result = parse_ip_rules(&rules, Path::new("/nonexistent"))
      .unwrap();
    assert_eq!(result.len(), 1);
    match &result[0].value {
      Some(IpRuleValue::Custom(cidr_rule)) => {
        assert!(!cidr_rule.reverse_match);
      }
      _ => panic!("期望 Custom"),
    }

    // !!! 反转 CIDR
    let rules: Vec<String> = vec!["!!!10.0.0.0/8".to_string()];
    let result = parse_ip_rules(&rules, Path::new("/nonexistent"))
      .unwrap();
    assert_eq!(result.len(), 1);
    match &result[0].value {
      Some(IpRuleValue::Custom(cidr_rule)) => {
        assert!(cidr_rule.reverse_match);
      }
      _ => panic!("期望 Custom"),
    }

    // 无 ! 前缀的 CIDR
    let rules: Vec<String> = vec!["10.0.0.0/8".to_string()];
    let result = parse_ip_rules(&rules, Path::new("/nonexistent"))
      .unwrap();
    assert_eq!(result.len(), 1);
    match &result[0].value {
      Some(IpRuleValue::Custom(cidr_rule)) => {
        assert!(!cidr_rule.reverse_match);
      }
      _ => panic!("期望 Custom"),
    }
  }

  // ── test_parse_domain_rules ─────────────────────────────────
  // 使用自定义域名规则（不依赖 dat 文件）

  #[test]
  fn test_parse_domain_rules() {
    let rules: Vec<String> = vec![
      "domain:example.com".to_string(),
      "full:www.example.com".to_string(),
      "keyword:evil".to_string(),
    ];
    let result = parse_domain_rules(
      &rules,
      DomainType::Domain,
      Path::new("/nonexistent"),
    )
    .unwrap();
    assert_eq!(result.len(), 3);

    // 第一条: domain:
    match &result[0].value {
      Some(DomainRuleValue::Custom(d)) => {
        assert_eq!(d.r#type, DomainType::Domain as i32);
        assert_eq!(d.value, "example.com");
      }
      _ => panic!("期望 Custom"),
    }

    // 第二条: full:
    match &result[1].value {
      Some(DomainRuleValue::Custom(d)) => {
        assert_eq!(d.r#type, DomainType::Full as i32);
        assert_eq!(d.value, "www.example.com");
      }
      _ => panic!("期望 Custom"),
    }

    // 第三条: keyword:
    match &result[2].value {
      Some(DomainRuleValue::Custom(d)) => {
        assert_eq!(d.r#type, DomainType::Substr as i32);
        assert_eq!(d.value, "evil");
      }
      _ => panic!("期望 Custom"),
    }
  }
}
