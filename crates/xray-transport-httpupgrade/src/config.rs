//! HTTPUpgrade 配置。
//!
//! 对应 Go `transport/internet/httpupgrade/config.go` 与 `config.proto`。
//!
//! ## 字段
//!
//! | 字段 | 用途 |
//! |------|------|
//! | `host` | HTTP `Host` header 值（缺省用 dest 地址） |
//! | `path` | URL 路径（自动补 `/` 前缀） |
//! | `header` | 自定义额外 header（key→value） |
//! | `accept_proxy_protocol` | 服务端是否接受 PROXY protocol（切片2） |
//! | `ed` | Early Data 长度（0=立即读取响应，非 0=延迟读，用于 0-RTT） |
//!
//! ## 与 Go 差异
//!
//! Go proto 是 `map<string,string>` header，Rust 用 `std::collections::HashMap`。

use std::collections::HashMap;

use crate::error::Result;

/// HTTPUpgrade 配置。对应 proto `xray.transport.internet.httpupgrade.Config`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// HTTP `Host` header 值。空时客户端用 dest 地址，服务端不校验。
    pub host: String,
    /// URL 路径。空时默认 `/`；不以 `/` 开头自动补 `/`。
    pub path: String,
    /// 额外自定义 header。客户端写入请求，服务端不解析（仅按 host/path 校验）。
    pub header: HashMap<String, String>,
    /// 服务端是否接受 PROXY protocol v1/v2。切片2 接入。
    pub accept_proxy_protocol: bool,
    /// Early Data 长度（用于 0-RTT 优化）。0 = 客户端立即读取 101 响应；
    /// 非 0 = 延迟到首字节写入后读，避免 0-RTT 与协议握手冲突。
    pub ed: u32,
}

impl Config {
    /// 用 `path` 字段构造时确保以 `/` 开头。对应 Go `GetNormalizedPath`。
    ///
    /// - 空路径返回 `/`。
    /// - 不以 `/` 开头的路径补 `/` 前缀。
    /// - 其他原样返回。
    #[must_use]
    pub fn normalized_path(&self) -> String {
        if self.path.is_empty() {
            return "/".to_string();
        }
        if self.path.starts_with('/') {
            return self.path.clone();
        }
        format!("/{}", self.path)
    }

    /// 从 prost 生成的 proto Config 构造。对应 Go 反序列化路径。
    pub fn from_proto(
        p: xray_proto::xray::transport::internet::httpupgrade::Config,
    ) -> Result<Self> {
        Ok(Self {
            host: p.host,
            path: p.path,
            header: p.header.into_iter().collect(),
            accept_proxy_protocol: p.accept_proxy_protocol,
            ed: p.ed,
        })
    }

    /// 转换为 prost Config（用于序列化）。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::transport::internet::httpupgrade::Config {
        xray_proto::xray::transport::internet::httpupgrade::Config {
            host: self.host.clone(),
            path: self.path.clone(),
            header: self.header.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            accept_proxy_protocol: self.accept_proxy_protocol,
            ed: self.ed,
        }
    }
}

/// 从 path 提取 `?ed=N` 早期数据参数。
///
/// 对应 Go `infra/conf/transport_internet.go` `HttpUpgradeConfig.Build`：
///
/// ```go
/// if u, err := url.Parse(path); err == nil {
///     if q := u.Query(); q.Get("ed") != "" {
///         Ed, _ := strconv.Atoi(q.Get("ed"))
///         ed = uint32(Ed)
///         q.Del("ed")
///         u.RawQuery = q.Encode()
///         path = u.String()
///     }
/// }
/// ```
///
/// 语义逐条对齐：
/// - **提取门**：首个 `ed` query 值为非空字符串才提取（`?ed=`、`?ed` 或首值空 → 整体不动）。
/// - **数值**：`strconv.Atoi` 语法错误 → 0（溢出时 Go 返回钳制值且错误被忽略）； `uint32(Ed)`
///   截断低 32 位，负数回绕。
/// - **删除**：提取触发时删除**全部** `ed` 参数（即使 Atoi 失败）。
/// - **重编码**：剩余参数按 Go `Values.Encode()`——键稳定排序、`QueryEscape` （空格→`+`、保留
///   `[A-Za-z0-9-_.~]`）、恒为 `k=v`；剩余为空则整个 query 连 `?` 移除。
/// - **fragment**：`#` 后内容不参与解析，结果原样回接。
/// - **解析失败**：path 部分含非法 `%` 转义时 Go `url.Parse` 报错 → 整体跳过提取。
///
/// 返回 `(清理后 path, 提取的 ed)`；未触发提取时 ed 为 `None`（path 原样返回）。
pub(crate) fn extract_ed_from_path(path: &str) -> (String, Option<u32>) {
    let (before_frag, frag) = match path.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (path, None),
    };
    let Some((base, query)) = before_frag.split_once('?') else {
        return (path.to_string(), None);
    };
    // Go `url.Parse`：path 部分非法 % 转义 → err → 整体不提取。
    if has_invalid_escape(base) {
        return (path.to_string(), None);
    }
    // Go `parseQuery`：`&` 分割、首个 `=` 分 k/v、非法转义跳过该 pair、空 kv 跳过。
    let mut pairs: Vec<(String, String)> = Vec::new();
    for kv in query.split('&') {
        if kv.is_empty() {
            continue;
        }
        let (k, v) = match kv.split_once('=') {
            Some((k, v)) => (k, v),
            None => (kv, ""),
        };
        if let (Some(k), Some(v)) = (query_unescape(k), query_unescape(v)) {
            pairs.push((k, v));
        }
    }
    // Go `Values.Get`：取首个 ed 值；非空字符串才触发提取。
    let Some(ed_value) = pairs.iter().find(|(k, _)| k == "ed").map(|(_, v)| v.clone()) else {
        return (path.to_string(), None);
    };
    if ed_value.is_empty() {
        return (path.to_string(), None);
    }
    let ed = Some(go_atoi_u32(&ed_value));
    // Go `Values.Del("ed")` + `Values.Encode()`：删全部 ed，剩余按键排序 + QueryEscape。
    pairs.retain(|(k, _)| k != "ed");
    let mut out = base.to_string();
    if !pairs.is_empty() {
        pairs.sort_by(|a, b| a.0.cmp(&b.0)); // 稳定排序：同键多值保持插入序
        let encoded: Vec<String> =
            pairs.iter().map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v))).collect();
        out.push('?');
        out.push_str(&encoded.join("&"));
    }
    if let Some(f) = frag {
        out.push('#');
        out.push_str(f);
    }
    (out, ed)
}

/// Go `strconv.Atoi` + `uint32(...)` 转换语义（错误时返回值仍被采用）。
fn go_atoi_u32(s: &str) -> u32 {
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'+') => (false, &s[1..]),
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return 0; // 语法错误 → Go Atoi 返回 0 + err（err 被忽略）
    }
    // 溢出：Go ParseInt ErrRange 返回钳制值（正 → MaxInt64，负 → MinInt64=−2^63）。
    let limit: i128 = if neg { 1 << 63 } else { i64::MAX as i128 };
    let mut v: i128 = 0;
    for b in digits.bytes() {
        v = (v * 10 + i128::from(b - b'0')).min(limit);
    }
    (if neg { -v } else { v }) as u32 // 截断低 32 位，负数回绕（同 Go uint32(int)）
}

/// Go `url.QueryUnescape`：`+`→空格、`%XX`（大小写十六进制）解码；非法转义返回 `None`。
/// 非 UTF-8 解码结果用 lossy 替换（配置 path 实际均为 ASCII，与 Go bytes 语义无差）。
fn query_unescape(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            },
            b'%' => {
                if i + 2 >= b.len() {
                    return None;
                }
                let hi = hex_val(b[i + 1])?;
                let lo = hex_val(b[i + 2])?;
                out.push(hi << 4 | lo);
                i += 3;
            },
            c => {
                out.push(c);
                i += 1;
            },
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// Go `url.QueryEscape`：`[A-Za-z0-9-_.~]` 保留，空格→`+`，其余 `%XX` 大写。
fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(c as char)
            },
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{c:02X}")),
        }
    }
    out
}

/// path 部分是否含非法 `%` 转义（Go `unescape(path, encodePath)` 报错场景）。
fn has_invalid_escape(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() || hex_val(b[i + 1]).is_none() || hex_val(b[i + 2]).is_none() {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_path_empty_returns_slash() {
        let cfg = Config::default();
        assert_eq!(cfg.normalized_path(), "/");
    }

    #[test]
    fn normalized_path_no_leading_slash_prepended() {
        let cfg = Config { path: "ws".into(), ..Default::default() };
        assert_eq!(cfg.normalized_path(), "/ws");
    }

    #[test]
    fn normalized_path_already_valid_passthrough() {
        let cfg = Config { path: "/api/ws".into(), ..Default::default() };
        assert_eq!(cfg.normalized_path(), "/api/ws");
    }

    #[test]
    fn proto_roundtrip() {
        let mut cfg = Config {
            host: "example.com".into(),
            path: "/ws".into(),
            accept_proxy_protocol: true,
            ed: 2048,
            ..Default::default()
        };
        cfg.header.insert("X-Custom".into(), "value".into());
        let proto = cfg.to_proto();
        let cfg2 = Config::from_proto(proto).unwrap();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn default_config_is_empty() {
        let cfg = Config::default();
        assert!(cfg.host.is_empty());
        assert!(cfg.path.is_empty());
        assert!(cfg.header.is_empty());
        assert!(!cfg.accept_proxy_protocol);
        assert_eq!(cfg.ed, 0);
    }

    /// Go `HttpUpgradeConfig.Build`（infra/conf/transport_internet.go:186-210）语义表。
    #[test]
    fn extract_ed_from_path_go_semantics() {
        let f = |p: &str| super::extract_ed_from_path(p);
        // 基本提取 + 删除
        assert_eq!(f("/ws?ed=2048"), ("/ws".to_string(), Some(2048)));
        // 无 query / 无 ed：原样（不重排既有参数）
        assert_eq!(f("/ws"), ("/ws".to_string(), None));
        assert_eq!(f("/ws?x=1"), ("/ws?x=1".to_string(), None));
        // 提取门：首值空（"?ed=" / "?ed" / "?ed=&ed=2048"）→ 整体不动
        assert_eq!(f("/ws?ed="), ("/ws?ed=".to_string(), None));
        assert_eq!(f("/ws?ed"), ("/ws?ed".to_string(), None));
        assert_eq!(f("/ws?ed=&ed=2048"), ("/ws?ed=&ed=2048".to_string(), None));
        // 多 ed：Get 取首个，Del 删全部
        assert_eq!(f("/ws?ed=1&ed=2"), ("/ws".to_string(), Some(1)));
        // ed=0：非空值 → 提取（ed=0，等价不启用）+ 参数删除
        assert_eq!(f("/ws?ed=0"), ("/ws".to_string(), Some(0)));
        // 非法数值：Atoi 错误 → 0，参数仍删除
        assert_eq!(f("/ws?ed=abc"), ("/ws".to_string(), Some(0)));
        // 负数：uint32 回绕
        assert_eq!(f("/ws?ed=-1"), ("/ws".to_string(), Some(4294967295)));
        // 溢出钳制（Atoi ErrRange 的值被采用）：正 → MaxInt64 → 0xFFFFFFFF；负 → MinInt64 → 0
        assert_eq!(f("/ws?ed=99999999999999999999"), ("/ws".to_string(), Some(4294967295)));
        assert_eq!(f("/ws?ed=-99999999999999999999"), ("/ws".to_string(), Some(0)));
        // 在 i64 内但超 u32：截断低 32 位
        assert_eq!(f("/ws?ed=4294967297"), ("/ws".to_string(), Some(1)));
        // "+" 在 query unescape 中变空格 → Atoi 失败；"%2B" 解码为 "+" → Atoi 成功
        assert_eq!(f("/ws?ed=+2048"), ("/ws".to_string(), Some(0)));
        assert_eq!(f("/ws?ed=%2B2048"), ("/ws".to_string(), Some(2048)));
        // 剩余参数按 Go Values.Encode()：键排序（稳定）、恒 k=v
        assert_eq!(f("/ws?y=2&ed=1024&x=1"), ("/ws?x=1&y=2".to_string(), Some(1024)));
        assert_eq!(f("/ws?b=2&ed=1&b=1"), ("/ws?b=2&b=1".to_string(), Some(1)));
        assert_eq!(f("/ws?ed=2048&flag"), ("/ws?flag=".to_string(), Some(2048)));
        // 解码后重编码：%62 → b
        assert_eq!(f("/ws?ed=2048&a=%62"), ("/ws?a=b".to_string(), Some(2048)));
        // fragment 保留且不参与解析（含 fragment 内的 "?"）
        assert_eq!(f("/ws?ed=2048#frag"), ("/ws#frag".to_string(), Some(2048)));
        assert_eq!(f("/ws?ed=2048#f?ed=1"), ("/ws#f?ed=1".to_string(), Some(2048)));
        // 空 path：提取后为空（normalized_path 兜底 "/"）
        assert_eq!(f("?ed=2048"), ("".to_string(), Some(2048)));
        // path 部分非法 % 转义：Go url.Parse 报错 → 整体跳过
        assert_eq!(f("/w%zz?ed=2048"), ("/w%zz?ed=2048".to_string(), None));
        // query 其他 pair 非法转义：跳过该 pair，ed 提取不受影响
        assert_eq!(f("/ws?%zz=1&ed=2048"), ("/ws".to_string(), Some(2048)));
    }
}
