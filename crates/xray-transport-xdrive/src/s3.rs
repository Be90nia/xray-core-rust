//! `s3` 后端——SigV4 手写签名的对象存储。对应 Go `s3.go`（@ `676eaf66`）。
//!
//! udf-promotion-candidate：SigV4 是单一后端的协议格式（网络/协议/加密三方向
//! 件），udf 不收方向件（规划 §4.2 裁定）；若出现第二个 S3 消费方，提炼为
//! `std_ext::s3sigv4` 并删本文件。
//!
//! ## 与 Go 的已声明差异
//!
//! 1. Retry-After 头不可见：B2 发送面（`service_round_trip`/ `SessionTransport::round_trip`）只回
//!    (status, body)，本批不改 client.rs （B4 领地）⇒ 重试退避的 `retryAfter` 恒 0（Go `max(jitter,
//!    retryAfter)`）。 只影响退避精度，不影响正确性；其 HTTP-date 形态随之不解析（S3 实际响应
//!    恒秒数形态）。
//! 2. 响应上限在缓冲完成后判定（Go LimitReader 读途中截断）：发送面恒全量缓冲， 超限同样
//!    fail-visible；失控端点的峰值内存差为一次段级缓冲。
//! 3. DNS 错误分类不可见（hyper 折叠）：传输错误重试判定按 [`io::ErrorKind`]；Go
//!    `dns.IsTimeout||IsTemporary` 由 `TimedOut` 覆盖。
//! 4. 全数字四段主机名在 virtual-hosted 校验按 IP 字面量拒（Go `net.ParseIP` 只拒合法
//!    IP，非法四段如 `999.1.2.3` 放行）——偏严 fail-visible。
//! 5. 「读响应失败」不保留 status（发送面合一）：Go 读响应失败时 do() 可凭 `status≥300`
//!    提前终止；Rust 侧该错误按传输错误继续重试，终态同为 lastErr 上抛，仅多尝试几轮。

use std::{
    collections::{BTreeMap, HashSet},
    io,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use http::{Method, StatusCode, Uri};
use sha2::{Digest, Sha256};
use std_ext::{
    clock::rfc3339::format_rfc3339_seconds,
    encode::{HexCase, hex_encode},
};
use tokio::sync::Semaphore;
use xray_common::dice::roll_int63n;
use xray_transport::dialer::StreamSettings;

use crate::{
    client::{
        ClientCore, ConnPool, DRIVE_INITIAL_BACKOFF_MS, DRIVE_MAX_ATTEMPTS, DRIVE_MAX_INFLIGHT,
        DRIVE_TIMEOUT, OutRequest, SessionTransport, UnitClient, build_unit_client,
        xdrive_xmux_config,
    },
    config::Config,
    storage::{Entry, Storage, not_found},
};

type HmacSha256 = Hmac<Sha256>;

/// 每步退避上限（Go `driveMaxBackoff`；client.rs 的总预算近似是 template 用的，
/// 本后端手写重试环按 Go 逐步封顶）。
const DRIVE_MAX_BACKOFF: Duration = Duration::from_secs(8);
/// 单对象响应上限（Go `params.go maxSegmentBytes`；params.rs 同值私有，本地
/// 常量避免跨模块扩公开面）。
const MAX_SEGMENT_BYTES: usize = 16 * 1024 * 1024;
/// 非 2xx 响应体上限（Go `64 << 10` = 64KiB；错误 XML 足够）。
const ERROR_BODY_LIMIT: usize = 64 << 10;
/// 对象 key 字节上限（Go `objectKey`）。
const S3_KEY_MAX_BYTES: usize = 1024;
/// `Content-Type`（Go `http.MethodPut` 分支固定值）。
const PUT_CONTENT_TYPE: &str = "application/octet-stream";

fn invalid(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, why)
}

// ── 配置（Go S3Config + ValidateS3Config）────────────────────────────────────

/// `s3` 子对象（Go `S3Config` proto；JSON 键 endpoint/region/bucket/pathStyle）。
#[derive(Debug, Default)]
struct S3Settings {
    endpoint: String,
    region: String,
    bucket: String,
    path_style: bool,
}

/// Go conf Build 的缺省：`pathStyle == nil || *pathStyle`（缺省 true）。
fn parse_s3_settings(v: &serde_json::Value) -> io::Result<S3Settings> {
    let obj = v.as_object().ok_or_else(|| invalid(r#"service "s3" needs an "s3" object"#))?;
    let field = |key: &str| -> io::Result<String> {
        match obj.get(key) {
            None | Some(serde_json::Value::Null) => Ok(String::new()),
            Some(serde_json::Value::String(s)) => Ok(s.clone()),
            Some(other) => Err(invalid(&format!("s3 {key} must be a string, got {other}"))),
        }
    };
    let path_style = match obj.get("pathStyle") {
        None | Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(other) => {
            return Err(invalid(&format!("s3 pathStyle must be a bool, got {other}")));
        },
    };
    Ok(S3Settings {
        endpoint: field("endpoint")?,
        region: field("region")?,
        bucket: field("bucket")?,
        path_style,
    })
}

/// RFC 7230 field-value 合法字符（Go `httpguts.ValidHeaderFieldValue`）：
/// tab、0x20..=0xFF 且非 DEL。`&str` 的多字节序列字节均 ≥0x80，逐字节判定等价。
fn valid_header_field_value(s: &str) -> bool {
    s.bytes().all(|b| b == b'\t' || (0x20..=0xFF).contains(&b) && b != 0x7f)
}

/// 相对对象名合法性（Go `validS3Name`）：禁控制字符/DEL/反斜杠，`/` 分段
/// 禁空段、`.`、`..`。
#[must_use]
pub fn valid_s3_name(name: &str) -> bool {
    !name.bytes().any(|b| b < 0x20 || b == 0x7f || b == b'\\')
        && name.split('/').all(|part| !part.is_empty() && part != "." && part != "..")
}

/// IPv4 点分四段全数字，或含 `:` 的 IPv6 形态（差异 4：比 Go `net.ParseIP`
/// 偏严，只影响 virtual-hosted 的拒面，不静默放行坏 endpoint）。
fn is_ip_literal(hostname: &str) -> bool {
    hostname.contains(':') || {
        let segs = hostname.split('.').collect::<Vec<_>>();
        segs.len() == 4
            && segs.iter().all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()))
    }
}

fn s3_region(region: &str) -> String {
    if region.is_empty() { "us-east-1".to_string() } else { region.to_string() }
}

/// authority 拆 hostname/port（Go `u.Hostname()`/`u.Port()`）。IPv6 走括号形态。
fn split_authority(authority: &str) -> (String, Option<String>) {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            let port = rest[close + 1..].strip_prefix(':').map(str::to_string);
            return (rest[..close].to_string(), port);
        }
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (host.to_string(), Some(port.to_string()))
        },
        _ => (authority.to_string(), None),
    }
}

/// endpoint 全量校验（Go `ValidateS3Config` 直译；消息原文对齐）。
///
/// # Errors
/// endpoint 非 http(s) 绝对 URL / 带 credentials/query/fragment、region 或
/// secrets 含非法 header 字符、bucket 含路径分隔或（virtual-hosted）非 DNS 名、
/// remoteFolder 非法、secrets 数量不符。
fn validate(s3: &S3Settings, config: &Config) -> io::Result<()> {
    let endpoint = parse_endpoint(&s3.endpoint)?;
    if !valid_header_field_value(&s3.region) || s3.region.contains(['/', ',', ' ', '\t']) {
        return Err(invalid("invalid S3 signing region"));
    }
    if !valid_s3_name(&s3.bucket) || s3.bucket.contains('/') {
        return Err(invalid("S3 needs a bucket name without path separators"));
    }
    if !s3.path_style {
        if is_ip_literal(&endpoint.hostname) {
            return Err(invalid("S3 virtual-hosted addressing requires a DNS endpoint"));
        }
        // In this mode the bucket is part of the HTTP authority, not its path.
        // Go `strings.Trim(bucket, "abcdefghijklmnopqrstuvwxyz0123456789-.") != ""`
        // ⟺ 含任一 DNS 集外字符（Trim 剥两端遇集外字符即停；全集内才剥空）。
        let dns_ok = s3.bucket.contains("..")
            || s3.bucket.starts_with('.')
            || s3.bucket.ends_with('.')
            || !s3
                .bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
        if dns_ok {
            return Err(invalid(
                "S3 virtual-hosted addressing requires a DNS-compatible bucket name",
            ));
        }
    }
    let folder = remote_folder(config);
    if !valid_s3_name(folder) {
        return Err(invalid(
            "S3 remoteFolder must be a nonempty relative prefix without empty, '.' or '..' components",
        ));
    }
    if !(2..=3).contains(&config.secrets.len())
        || config.secrets.first().is_none_or(String::is_empty)
        || config.secrets.get(1).is_none_or(String::is_empty)
    {
        return Err(invalid(
            "S3 needs AccessKeyID, SecretAccessKey and optionally SessionToken in secrets",
        ));
    }
    for secret in &config.secrets {
        if !valid_header_field_value(secret) {
            return Err(invalid("invalid S3 secret"));
        }
    }
    if config.secrets[0].contains(['/', ' ', ',', '\t']) {
        return Err(invalid("invalid S3 AccessKeyID"));
    }
    Ok(())
}

/// Go `strings.TrimSuffix(c.RemoteFolder, "/")`（单尾）。
fn remote_folder(config: &Config) -> &str {
    config.remote_folder.strip_suffix('/').unwrap_or(&config.remote_folder)
}

// ── endpoint 解析（Go url.Parse 校验 + base 构造的段重编码）─────────────────

struct Endpoint {
    scheme: String,
    authority: String,
    hostname: String,
    port: Option<String>,
    /// 段重编码后的 path（SigV4 escape；空 endpoint path 保持空）。
    escaped_path: String,
}

/// 手工解析 endpoint（Go `url.Parse` + 拒绝集）。
///
/// 拒绝：非 http/https、非 `//` 绝对形态（Go Opaque）、空 host、userinfo、
/// query、fragment。
///
/// # Errors
/// 上述任一形态。
fn parse_endpoint(endpoint: &str) -> io::Result<Endpoint> {
    let bad =
        || invalid("S3 endpoint must be an http(s) URL without credentials, query or fragment");
    let Some((scheme_raw, rest)) = endpoint.split_once("://") else { return Err(bad()) };
    let scheme = scheme_raw.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(bad());
    }
    // query/fragment 全段禁（含尾 `?` = Go ForceQuery）。
    if rest.contains(['?', '#']) {
        return Err(bad());
    }
    let (authority, path_raw) = match rest.find('/') {
        Some(slash) => (&rest[..slash], &rest[slash..]),
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(bad());
    }
    // 段重编码（Go：EscapedPath 按 `/` 分段 → PathUnescape（失败得空段）→
    // s3EscapePath → 段内 `/` 回写 `%2F`）。
    let escaped_path = path_raw
        .split('/')
        .map(|seg| {
            let decoded = percent_decode(seg);
            s3_escape_path_bytes(&decoded).replace('/', "%2F")
        })
        .collect::<Vec<_>>()
        .join("/");
    let (hostname, port) = split_authority(authority);
    if hostname.is_empty() {
        return Err(bad());
    }
    Ok(Endpoint { scheme, authority: authority.to_string(), hostname, port, escaped_path })
}

/// Go `url.PathUnescape` 的字节等价：`%XX` 解码；畸形序列返回空（Go 错误路径
/// 得空串）。输出按字节处理，≥0x80 的字节由 escape 转成 `%XX`，无 UTF-8 面问题。
fn percent_decode(segment: &str) -> Vec<u8> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3);
            match hex.and_then(|h| {
                std::str::from_utf8(h).ok().and_then(|h| u8::from_str_radix(h, 16).ok())
            }) {
                Some(byte) => {
                    out.push(byte);
                    i += 3;
                },
                None => return Vec::new(),
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

// ── SigV4（Go s3EscapePath/s3Hash/s3HMAC/sign）──────────────────────────────

/// SigV4 path 转义（Go `s3EscapePath`）：unreserved + `/` 直通，其余 `%XX` 大写。
#[must_use]
pub fn s3_escape_path(value: &str) -> String {
    s3_escape_path_bytes(value.as_bytes())
}

fn s3_escape_path_bytes(bytes: &[u8]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            },
            _ => {
                out.push('%');
                out.push(HEX_DIGITS[usize::from(b >> 4)] as char);
                out.push(HEX_DIGITS[usize::from(b & 15)] as char);
            },
        }
    }
    out
}

/// Go `s3Hash`：SHA-256 hex（小写）。
fn s3_hash(body: &[u8]) -> String {
    hex_encode(&Sha256::digest(body), HexCase::Lower)
}

/// Go `s3HMAC`。
fn s3_hmac(key: &[u8], value: &str) -> [u8; 32] {
    // HMAC 接受任意长度 key：new_from_slice 恒 Ok（crate 文档契约）。
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(value.as_bytes());
    mac.finalize().into_bytes().into()
}

/// Go `now.UTC()` 双格式：`20060102T150405Z` 与 `20060102`。走 udf RFC 3339
/// 定宽形（恒 `YYYY-MM-DDTHH:MM:SSZ`，20 字节）压掉标点即 amz 形态。
fn amz_stamps(now: SystemTime) -> (String, String) {
    let rfc = format_rfc3339_seconds(now);
    let stamp: String =
        rfc.chars().filter(|c| c.is_ascii_digit() || *c == 'T' || *c == 'Z').collect();
    let date = rfc[..10].replace('-', "");
    (stamp, date)
}

/// SigV4 签名（Go `sign`）：产出追加头（x-amz-date/x-amz-content-sha256/
/// [x-amz-security-token]/Authorization）。自由函数便于 golden 向量对拍。
///
/// canonical token 行按 Go `strings.Fields` 折叠空白；发送头保留原始 token。
#[allow(
    clippy::too_many_arguments,
    reason = "SigV4 全量入参（Go sign 方法隐式经 receiver 拿到同九项）"
)]
fn sign_request(
    method: &str,
    path: &str,
    query: &str,
    authority: &str,
    content_type: &str,
    payload_hash: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
    token: &str,
    now: SystemTime,
) -> Vec<(String, String)> {
    let (stamp, date) = amz_stamps(now);
    let mut canonical_headers =
        format!("host:{authority}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{stamp}\n");
    let mut signed = "host;x-amz-content-sha256;x-amz-date".to_string();
    if !content_type.is_empty() {
        canonical_headers = format!("content-type:{content_type}\n{canonical_headers}");
        signed = format!("content-type;{signed}");
    }
    let mut out = vec![
        ("x-amz-date".to_string(), stamp.clone()),
        ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
    ];
    if !token.is_empty() {
        out.push(("x-amz-security-token".to_string(), token.to_string()));
        let folded = token.split_whitespace().collect::<Vec<_>>().join(" ");
        canonical_headers.push_str(&format!("x-amz-security-token:{folded}\n"));
        signed.push_str(";x-amz-security-token");
    }
    // Sign the escaped path exactly as sent.
    let canonical =
        format!("{method}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}");
    let scope = format!("{date}/{region}/s3/aws4_request");
    let to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", s3_hash(canonical.as_bytes()));
    let mut key = s3_hmac(format!("AWS4{secret_key}").as_bytes(), &date);
    key = s3_hmac(&key, region);
    key = s3_hmac(&key, "s3");
    key = s3_hmac(&key, "aws4_request");
    let signature = hex_encode(&s3_hmac(&key, &to_sign), HexCase::Lower);
    out.push((
        "authorization".to_string(),
        format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}"
        ),
    ));
    out
}

// ── query 编码（Go url.Values.Encode + ReplaceAll("+", "%20")）──────────────

/// Go `url.QueryEscape` 的值形态：unreserved 直通、空格 `%20`、其余 `%XX`
/// 大写（encodeQueryComponent 模式下子分隔符也转义）。
fn percent_encode_query(s: &str) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            },
            b' ' => out.push_str("%20"),
            _ => {
                out.push('%');
                out.push(HEX_DIGITS[usize::from(b >> 4)] as char);
                out.push(HEX_DIGITS[usize::from(b & 15)] as char);
            },
        }
    }
    out
}

/// Go `Encode()`：key 字母序（BTreeMap 天然）、`k=v&…`。
fn encode_query(params: &BTreeMap<&str, String>) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{k}={}", percent_encode_query(v)))
        .collect::<Vec<_>>()
        .join("&")
}

// ── 窄 XML 提取（Go encoding/xml 的两个用例面）──────────────────────────────

/// 解 XML 实体（标准五实体 + 数字字符引用；未知/越界实体原样保留 `&`）。
fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        // 实体名限长 10（`#x10FFFF;` 最长），防跨段误吃普通 `&`。
        match tail.find(';') {
            Some(semi) if (1..=10).contains(&semi) => {
                let resolved = match &tail[1..semi] {
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    "amp" => Some('&'),
                    name => {
                        let code = name
                            .strip_prefix("#x")
                            .or_else(|| name.strip_prefix("#X"))
                            .map(|num| u32::from_str_radix(num, 16))
                            .or_else(|| name.strip_prefix('#').map(|num| num.parse::<u32>()));
                        code.and_then(|c| c.ok()).and_then(char::from_u32)
                    },
                };
                match resolved {
                    Some(c) => {
                        out.push(c);
                        rest = &tail[semi + 1..];
                    },
                    None => {
                        out.push('&');
                        rest = &tail[1..];
                    },
                }
            },
            _ => {
                out.push('&');
                rest = &tail[1..];
            },
        }
    }
    out.push_str(rest);
    out
}

/// 按 tag 收集全部 `<tag>…</tag>` 内文（S3 内层 tag 恒无属性；开 tag 边界
/// 校验防 `<Keys` 类前缀误配）。
fn xml_sections<'a>(payload: &'a str, tag: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut rest = payload;
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        match after.chars().next() {
            Some('>') | Some(' ') | Some('/') => {},
            _ => {
                rest = after;
                continue;
            },
        }
        let Some(gt) = after.find('>') else { break };
        let body_start = gt + 1;
        let Some(rel_end) = after[body_start..].find(&close) else { break };
        out.push(&after[body_start..body_start + rel_end]);
        rest = &after[body_start + rel_end + close.len()..];
    }
    out
}

/// 首个 `<tag>` 内文（解码实体；Go xml.Unmarshal 零值等价 `None`）。
fn xml_first_text(payload: &str, tag: &str) -> Option<String> {
    xml_sections(payload, tag).into_iter().next().map(decode_entities)
}

/// ListObjectsV2 单页（Go `s3ListPage`）。
struct ListPage {
    is_truncated: bool,
    next_token: String,
    keys: Vec<String>,
    common_prefixes: Vec<String>,
}

/// Go `xml.Unmarshal` 到 `s3ListPage` 的等价面：顶层 echo 的 `<Prefix>` 不收集
/// （Go 结构体无该字段），只取 `Contents.Key` 与 `CommonPrefixes.Prefix`。
fn parse_list_page(payload: &[u8]) -> io::Result<ListPage> {
    let text = std::str::from_utf8(payload)
        .map_err(|_| invalid("invalid S3 list response"))
        .map(str::to_owned)?;
    Ok(ListPage {
        is_truncated: xml_first_text(&text, "IsTruncated").as_deref() == Some("true"),
        next_token: xml_first_text(&text, "NextContinuationToken").unwrap_or_default(),
        keys: xml_sections(&text, "Contents")
            .iter()
            .filter_map(|sec| xml_first_text(sec, "Key"))
            .collect(),
        common_prefixes: xml_sections(&text, "CommonPrefixes")
            .iter()
            .filter_map(|sec| xml_first_text(sec, "Prefix"))
            .collect(),
    })
}

// ── 重试分类（Go retryS3Error/retryableStatus/s3Missing/s3ErrorCode/…）──────

/// 可重试状态码（Go `retryableStatus`）。
fn retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

/// 传输层瞬时错误（Go `retryS3Error` 的 io::ErrorKind 面，差异 3）。
fn retryable_transport_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::WouldBlock
    )
}

/// `<Error><Code>` 提取（Go `s3ErrorCode`；无/坏 XML 得空）。
fn s3_error_code(payload: &[u8]) -> String {
    let text = std::str::from_utf8(payload).unwrap_or("");
    xml_first_text(text, "Code").unwrap_or_default()
}

/// 404 且码为 NoSuchKey/NotFound（Go `s3Missing`）。
fn s3_missing(status: u16, payload: &[u8]) -> bool {
    status == 404 && matches!(s3_error_code(payload).as_str(), "NoSuchKey" | "NotFound")
}

/// Go `s3ResponseError`（strconv.Quote → `{:?}`）。
fn s3_response_error(method: &str, status: u16, payload: &[u8]) -> io::Error {
    let code = s3_error_code(payload);
    if code.is_empty() {
        io::Error::other(format!("S3 {method} answered {status}"))
    } else {
        io::Error::other(format!("S3 {method} answered {status} ({code:?})"))
    }
}

/// Go `jitter`：half + [0, half)（dice 线程本地源）。
fn jittered(backoff: Duration) -> Duration {
    let half_ms = (backoff.as_millis() / 2) as i64;
    if half_ms <= 0 {
        return backoff;
    }
    let roll = u64::try_from(roll_int63n(half_ms)).unwrap_or(0);
    Duration::from_millis(half_ms as u64 + roll)
}

// ── 存储（Go s3Shared/s3Storage）────────────────────────────────────────────

/// 会话间共享面（Go `s3Shared`）。
struct S3Shared {
    pool: Arc<ConnPool>,
    /// 已 SigV4-escape 的 base URL，恒以 `/` 结尾（Go `base url.URL` 的
    /// RawPath 轨 + String()）。
    base: String,
    /// 签名 host 头值（URL authority，含非缺省端口）。
    authority: String,
    prefix: String,
    region: String,
    access_key: String,
    secret_key: String,
    token: String,
}

/// `s3` 对象存储后端。基座实例（`Sink::Base`）用独立客户端；会话视图
/// （`Sink::Session`，[`Storage::session`]）走 XMUX 连接池。
pub struct S3Storage {
    shared: Arc<S3Shared>,
    sink: Sink,
    inflight: Arc<Semaphore>,
}

#[allow(
    clippy::large_enum_variant,
    reason = "基座独立请求客户端 vs 会话传输句柄是 Go s3Storage 双形态的固有尺寸；单存储仅两实例，不装箱"
)]
enum Sink {
    Base(UnitClient),
    Session(SessionTransport),
}

impl S3Storage {
    /// 按流设置 + 配置构造（Go `newS3Storage`）。
    ///
    /// 直接构造**不进**共享实例表（生产路径走 [`crate::storage::new_storage`]
    /// 的 `shared_storage` 去重）。
    ///
    /// # Errors
    /// 校验失败（`validate`）、xmux/安全层配置非法。
    pub fn new(settings: &StreamSettings, config: &Config) -> io::Result<Self> {
        let s3_json =
            config.s3.as_ref().ok_or_else(|| invalid(r#"service "s3" needs an "s3" object"#))?;
        let s3 = parse_s3_settings(s3_json)?;
        validate(&s3, config)?;
        let endpoint = parse_endpoint(&s3.endpoint)?;
        let region = s3_region(&s3.region);
        let mut path = endpoint.escaped_path.clone();
        if !path.ends_with('/') {
            path.push('/');
        }
        let (base, authority) = if s3.path_style {
            path.push_str(&s3_escape_path(&s3.bucket));
            path.push('/');
            (
                format!("{}://{}{}", endpoint.scheme, endpoint.authority, path),
                endpoint.authority.clone(),
            )
        } else {
            let host = match &endpoint.port {
                Some(port) => format!("{}.{}:{}", s3.bucket, endpoint.hostname, port),
                None => format!("{}.{}", s3.bucket, endpoint.hostname),
            };
            (format!("{}://{}{}", endpoint.scheme, host, path), host)
        };
        let pool = Arc::new(ConnPool::new(settings, config)?);
        let keepalive = xdrive_xmux_config(config.xmux.as_ref(), &config.service, config.h3)?
            .h_keep_alive_period;
        let core = ClientCore::from_settings(settings, keepalive, config.h3)?;
        Ok(Self {
            shared: Arc::new(S3Shared {
                pool,
                base,
                authority,
                prefix: format!("{}/", remote_folder(config)),
                region,
                access_key: config.secrets[0].clone(),
                secret_key: config.secrets[1].clone(),
                token: config.secrets.get(2).cloned().unwrap_or_default(),
            }),
            sink: Sink::Base(build_unit_client(&core)?),
            inflight: Arc::new(Semaphore::new(DRIVE_MAX_INFLIGHT)),
        })
    }

    /// 对象 key（Go `objectKey`）：prefix + 名，1024 字节上限。
    fn object_key(&self, name: &str) -> io::Result<String> {
        if !valid_s3_name(name) {
            return Err(invalid("invalid relative S3 object name"));
        }
        let key = format!("{}{}", self.shared.prefix, name);
        if key.len() > S3_KEY_MAX_BYTES {
            return Err(invalid("S3 object key exceeds 1024 bytes"));
        }
        Ok(key)
    }

    /// 目标 URL（Go `target`）：base + escaped key + `?query`。
    fn target(&self, key: &str, query: &str) -> io::Result<Uri> {
        let mut url = format!("{}{}", self.shared.base, s3_escape_path(key));
        if !query.is_empty() {
            url.push('?');
            url.push_str(query);
        }
        url.parse().map_err(|e| io::Error::other(format!("failed to build S3 request: {e}")))
    }

    /// 发送面（Go `client.Do` 两路）。
    async fn send(&self, req: OutRequest) -> io::Result<(StatusCode, bytes::Bytes)> {
        match &self.sink {
            Sink::Base(client) => client.round_trip(req, DRIVE_TIMEOUT).await,
            Sink::Session(session) => session.round_trip(req, DRIVE_TIMEOUT).await,
        }
    }

    /// 单次尝试（Go `attempt`）：签名 + 发送 + 响应上限检查。`err` 非 None 时
    /// `status` 无意义（Go 同形：失败返回 status=0；差异 5 见文件头）。
    async fn attempt(
        &self,
        method: Method,
        key: &str,
        query: &str,
        body: &[u8],
        payload_hash: &str,
    ) -> AttemptOutcome {
        let uri = match self.target(key, query) {
            Ok(uri) => uri,
            // 构建失败：不可重试分类（Go 同款直接 return）。
            Err(_) => {
                return AttemptOutcome {
                    status: 0,
                    payload: bytes::Bytes::new(),
                    err: Some(io::Error::other("failed to build S3 request")),
                };
            },
        };
        let content_type = if method == Method::PUT { PUT_CONTENT_TYPE } else { "" };
        let mut headers = sign_request(
            method.as_str(),
            uri.path(),
            uri.query().unwrap_or(""),
            &self.shared.authority,
            content_type,
            payload_hash,
            &self.shared.region,
            &self.shared.access_key,
            &self.shared.secret_key,
            &self.shared.token,
            xray_frame::compat::clock().now_system(),
        );
        if !content_type.is_empty() {
            headers.push(("content-type".to_string(), PUT_CONTENT_TYPE.to_string()));
        }
        let req =
            OutRequest { method, uri, headers, body: Some(bytes::Bytes::copy_from_slice(body)) };
        match self.send(req).await {
            Err(e) => AttemptOutcome { status: 0, payload: bytes::Bytes::new(), err: Some(e) },
            Ok((status, payload)) => {
                let limit = if (200..300).contains(&status.as_u16()) {
                    MAX_SEGMENT_BYTES
                } else {
                    ERROR_BODY_LIMIT
                };
                if payload.len() > limit {
                    AttemptOutcome {
                        status: 0,
                        payload: bytes::Bytes::new(),
                        err: Some(io::Error::other("S3 response exceeds size limit")),
                    }
                } else {
                    AttemptOutcome { status: status.as_u16(), payload, err: None }
                }
            },
        }
    }

    /// 重试环（Go `do`）：8 次、jitter 退避每步倍增封顶 8s、inflight 槽持有至
    /// 响应读毕、每次重签（`attempt` 内取当前时钟）。
    async fn do_req(
        &self,
        method: Method,
        key: &str,
        query: &str,
        body: bytes::Bytes,
    ) -> io::Result<(u16, bytes::Bytes)> {
        let payload_hash = s3_hash(&body);
        let mut backoff = Duration::from_millis(DRIVE_INITIAL_BACKOFF_MS);
        let mut last_err: Option<io::Error> = None;
        // 差异 1：Retry-After 头不可见，恒零退避。
        let mut retry_after = Duration::ZERO;
        for attempt in 0..DRIVE_MAX_ATTEMPTS {
            if attempt > 0 {
                let delay = jittered(backoff).max(retry_after).min(DRIVE_MAX_BACKOFF);
                tokio::time::sleep(delay).await;
                backoff = backoff.saturating_mul(2).min(DRIVE_MAX_BACKOFF);
            }
            let permit = self
                .inflight
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| io::Error::other(format!("inflight semaphore closed: {e}")))?;
            let outcome = self.attempt(method.clone(), key, query, &body, &payload_hash).await;
            drop(permit);
            let AttemptOutcome { status, payload, err } = outcome;
            if let Some(err) = err {
                // Go：`err != nil && (!retryS3Error(err) || status >= 300 &&
                // !retryableStatus(status))`。
                if !retryable_transport_error(&err)
                    || (u32::from(status) >= 300 && !retryable_status(status))
                {
                    return Err(err);
                }
                last_err = Some(err);
                retry_after = Duration::ZERO;
                continue;
            }
            if !retryable_status(status) {
                return Ok((status, payload));
            }
            last_err = Some(s3_response_error(method.as_str(), status, &payload));
            retry_after = Duration::ZERO;
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("S3 request failed")))
    }

    /// 单对象删除（Go `deleteObject`）。
    async fn delete_object(&self, key: &str) -> io::Result<()> {
        let (status, payload) = self.do_req(Method::DELETE, key, "", bytes::Bytes::new()).await?;
        if status != 204 && status != 200 && !s3_missing(status, &payload) {
            return Err(s3_response_error("DELETE", status, &payload));
        }
        Ok(())
    }

    /// 分页列举（Go `list`）：list-type=2、max-keys=1000、continuation-token
    /// 防环、prefix 越界即拒。`visit` 同步（先收集后行动，语义对齐 Go
    /// 「Validate all keys before deleting any objects」）。
    async fn list_pages(
        &self,
        prefix: &str,
        delimiter: &str,
        mut visit: impl FnMut(&ListPage) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut params: BTreeMap<&str, String> = BTreeMap::from([
            ("list-type", "2".to_string()),
            ("prefix", prefix.to_string()),
            ("max-keys", "1000".to_string()),
        ]);
        if !delimiter.is_empty() {
            params.insert("delimiter", delimiter.to_string());
        }
        let mut seen = HashSet::new();
        loop {
            let query = encode_query(&params);
            let (status, payload) =
                self.do_req(Method::GET, "", &query, bytes::Bytes::new()).await?;
            if status != 200 {
                return Err(s3_response_error("LIST", status, &payload));
            }
            let page = parse_list_page(&payload)?;
            for key in &page.keys {
                if !key.starts_with(prefix) {
                    return Err(invalid("S3 returned an object outside the requested prefix"));
                }
            }
            for item in &page.common_prefixes {
                if !item.starts_with(prefix) {
                    return Err(invalid("S3 returned a directory outside the requested prefix"));
                }
            }
            if page.is_truncated
                && (page.next_token.is_empty() || !seen.insert(page.next_token.clone()))
            {
                return Err(invalid("S3 list pagination did not advance"));
            }
            visit(&page)?;
            if !page.is_truncated {
                return Ok(());
            }
            params.insert("continuation-token", page.next_token.clone());
        }
    }
}

/// [`S3Storage::attempt`] 的产物（Go `attempt` 三返回值的 struct 化）。
struct AttemptOutcome {
    status: u16,
    payload: bytes::Bytes,
    err: Option<io::Error>,
}

#[async_trait]
impl Storage for S3Storage {
    async fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let key = self.object_key(name)?;
        let (status, payload) =
            self.do_req(Method::PUT, &key, "", bytes::Bytes::copy_from_slice(data)).await?;
        if status != 200 {
            return Err(s3_response_error("PUT", status, &payload));
        }
        Ok(())
    }

    async fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        let key = self.object_key(name)?;
        let (status, payload) = self.do_req(Method::GET, &key, "", bytes::Bytes::new()).await?;
        if s3_missing(status, &payload) {
            return Err(not_found());
        }
        if status != 200 {
            return Err(s3_response_error("GET", status, &payload));
        }
        Ok(payload.to_vec())
    }

    async fn delete(&self, name: &str) -> io::Result<()> {
        let key = self.object_key(name)?;
        self.delete_object(&key).await?;
        // The trailing "/" prevents deleting streams/abcd when removing streams/abc.
        let mut nested = Vec::new();
        self.list_pages(&format!("{key}/"), "", |page| {
            nested.extend(page.keys.iter().cloned());
            Ok(())
        })
        .await?;
        for key in nested {
            self.delete_object(&key).await?;
        }
        Ok(())
    }

    async fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        let mut key = self.object_key(prefix)?;
        key.push('/');
        let mut seen = HashSet::new();
        let mut entries = Vec::new();
        let list_prefix = key.clone();
        self.list_pages(&key, "/", |page| {
            for full in page.keys.iter().chain(page.common_prefixes.iter()) {
                let Some(rest) = full.as_str().strip_prefix(list_prefix.as_str()) else { continue };
                let name = rest.split('/').next().unwrap_or("");
                if !name.is_empty() && valid_s3_name(name) && seen.insert(name.to_string()) {
                    entries.push(Entry { name: name.to_string(), inline: None });
                }
            }
            Ok(())
        })
        .await?;
        Ok(entries)
    }

    async fn close(&self) -> io::Result<()> {
        if let Sink::Session(session) = &self.sink {
            session.close();
        }
        Ok(())
    }

    /// 会话视图（Go `s3Storage.session`）：共享签名面/池，独立 XMUX 会话传输
    /// 与并发闸。
    fn session(&self) -> Option<Arc<dyn Storage>> {
        Some(Arc::new(S3Storage {
            shared: Arc::clone(&self.shared),
            sink: Sink::Session(SessionTransport::new(Arc::clone(&self.shared.pool.xmux))),
            inflight: Arc::new(Semaphore::new(DRIVE_MAX_INFLIGHT)),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_keeps_unreserved_and_slash() {
        assert_eq!(s3_escape_path("a b/c+d~e_f.g-h"), "a%20b/c%2Bd~e_f.g-h");
        assert_eq!(s3_escape_path("é"), "%C3%A9");
    }

    #[test]
    fn valid_s3_name_cases() {
        assert!(valid_s3_name("streams/abc/c2s/0.seg"));
        assert!(!valid_s3_name(""));
        assert!(!valid_s3_name("a//b"));
        assert!(!valid_s3_name("a/./b"));
        assert!(!valid_s3_name("a/../b"));
        assert!(!valid_s3_name("back\\slash"));
        assert!(!valid_s3_name("\u{7f}"));
    }

    #[test]
    fn endpoint_rejects_bad_forms() {
        for bad in [
            "ftp://h",
            "h",
            "http:/x",
            "http://user:pw@h",
            "http://h?x",
            "http://h#f",
            "http://",
            "http://h/?q",
        ] {
            assert!(parse_endpoint(bad).is_err(), "{bad} must be rejected");
        }
        let ok = parse_endpoint("https://s3.example.com:9000/base/path%2Fx").unwrap();
        assert_eq!(ok.scheme, "https");
        assert_eq!(ok.authority, "s3.example.com:9000");
        assert_eq!(ok.hostname, "s3.example.com");
        assert_eq!(ok.port.as_deref(), Some("9000"));
        // 已编码段解码后重编码：`%2F` 段 → `/` → 回写 `%2F`。
        assert_eq!(ok.escaped_path, "/base/path%2Fx");
    }

    #[test]
    fn query_encode_matches_go() {
        let mut params: BTreeMap<&str, String> =
            BTreeMap::from([("list-type", "2".into()), ("prefix", "a b/c?d".into())]);
        params.insert("delimiter", "/".into());
        assert_eq!(encode_query(&params), "delimiter=%2F&list-type=2&prefix=a%20b%2Fc%3Fd");
    }

    #[test]
    fn xml_extraction_and_entities() {
        let payload = "<Error><Code>NoSuchKey</Code><Message>a &lt; b &amp; c</Message></Error>";
        assert_eq!(s3_error_code(payload.as_bytes()), "NoSuchKey");
        let page = "<ListBucketResult xmlns=\"x\"><Prefix>ignored/</Prefix><IsTruncated>true</IsTruncated>\
            <Contents><Key>p/a.txt</Key></Contents><CommonPrefixes><Prefix>p/sub/</Prefix></CommonPrefixes>\
            <Contents><Key>p/&#65;.txt</Key></Contents></ListBucketResult>";
        let parsed = parse_list_page(page.as_bytes()).unwrap();
        assert!(parsed.is_truncated);
        assert_eq!(parsed.keys, vec!["p/a.txt", "p/A.txt"]);
        assert_eq!(parsed.common_prefixes, vec!["p/sub/"]);
        assert!(!parse_list_page(b"<ListBucketResult></ListBucketResult>").unwrap().is_truncated);
    }

    #[test]
    fn stamps_from_epoch() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_440_938_160);
        assert_eq!(amz_stamps(t), ("20150830T123600Z".to_string(), "20150830".to_string()));
    }

    // ── SigV4 golden 向量（离线手推：python hashlib/hmac 独立实现，非被测代码；
    //    hex 对照链随断言注释）────────────────────────────────────────────────

    const GOLDEN_SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const GOLDEN_ACCESS: &str = "AKIDEXAMPLE";
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn auth_header(headers: &[(String, String)]) -> &str {
        &headers.iter().find(|(k, _)| k == "authorization").expect("authorization present").1
    }

    /// G1：GET / path-style。手推链（python）：
    /// canonical-hash = 6c25e1fd569a22b60dccba5a8e2090a46a451e6a714f35cf273f2a6f55995336
    /// signing-key    = 32f78051dcde24c552811d654f4a769112bb834b03975cdd6b1fd7d16248c269
    #[test]
    fn sigv4_golden_get_path_style() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_440_938_160);
        let headers = sign_request(
            "GET",
            "/examplebucket/streams/photos/2006/January/sample.txt",
            "",
            "s3.us-east-1.amazonaws.com",
            "",
            EMPTY_SHA256,
            "us-east-1",
            GOLDEN_ACCESS,
            GOLDEN_SECRET,
            "",
            now,
        );
        assert_eq!(headers[0], ("x-amz-date".to_string(), "20150830T123600Z".to_string()));
        assert_eq!(headers[1], ("x-amz-content-sha256".to_string(), EMPTY_SHA256.to_string()));
        assert_eq!(
            auth_header(&headers),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=4c1fa928c919677f55dbdf64bfcdb375f4038a650400229fb2941a34f6ae0cfa"
        );
    }

    /// G2：PUT virtual-hosted（authority 含端口）+ content-type + session token
    /// （归一化面：`SHORT-TOKEN WITH SPACES` 已是折叠形）。手推链（python）：
    /// payload-hash  = 8445e15e40d3d937b7c2ea4ef972427d136814d69783b1e659f483589a06a937
    /// canonical-hash = 81ab9dfdad9a6b55ee39e4a4dfb6765bdbba7d022358750689d9317bc1715c3e
    /// signing-key    = 4ab54699e54e3fa0fd3c796471aad9c4af558a5b8051e537d54e5a475bda2a42
    #[test]
    fn sigv4_golden_put_virtual_hosted_token() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_451_703_845);
        let body = b"xdrive s3 body";
        let headers = sign_request(
            "PUT",
            "/streams/data.bin",
            "",
            "s3.us-east-1.amazonaws.com:9000",
            PUT_CONTENT_TYPE,
            &s3_hash(body),
            "us-east-1",
            GOLDEN_ACCESS,
            GOLDEN_SECRET,
            "SHORT-TOKEN WITH SPACES",
            now,
        );
        assert_eq!(
            auth_header(&headers),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20160102/us-east-1/s3/aws4_request, \
             SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, \
             Signature=480f3af802ffe028d11d4a0c0fc396b9a95d8642aa079d4ef6687fb71bb62f91"
        );
        // 发送面 token 保留原始（canonical 才折叠）。
        assert_eq!(
            headers.iter().find(|(k, _)| k == "x-amz-security-token").map(|(_, v)| v.as_str()),
            Some("SHORT-TOKEN WITH SPACES")
        );
    }

    /// 同参不同时钟 ⇒ 签名必变（x-amz-date 秒粒度）。
    #[test]
    fn signature_changes_with_clock() {
        let common = (
            "GET",
            "/b/k",
            "",
            "host.example.com",
            "",
            EMPTY_SHA256,
            "us-east-1",
            GOLDEN_ACCESS,
            GOLDEN_SECRET,
            "",
        );
        let t1 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_440_938_160);
        let t2 = t1 + Duration::from_secs(1);
        let a = sign_request(
            common.0, common.1, common.2, common.3, common.4, common.5, common.6, common.7,
            common.8, common.9, t1,
        );
        let b = sign_request(
            common.0, common.1, common.2, common.3, common.4, common.5, common.6, common.7,
            common.8, common.9, t2,
        );
        assert_ne!(auth_header(&a), auth_header(&b));
    }

    #[test]
    fn validation_matrix() {
        let base = |s3: serde_json::Value, secrets: Vec<&str>, folder: &str| {
            let mut config = Config { service: "s3".into(), ..Config::default() };
            config.remote_folder = folder.to_string();
            config.secrets = secrets.iter().map(|s| s.to_string()).collect();
            config.s3 = Some(s3);
            config
        };
        let good = serde_json::json!({
            "endpoint": "https://s3.example.com",
            "region": "us-east-1",
            "bucket": "examplebucket",
            "pathStyle": true
        });
        assert!(
            validate(
                &parse_s3_settings(&good).unwrap(),
                &base(good.clone(), vec!["ak", "sk"], "streams")
            )
            .is_ok()
        );

        // pathStyle 缺省 true（Go conf：nil → true）。
        let no_style = serde_json::json!({
            "endpoint": "https://s3.example.com", "bucket": "b"
        });
        let parsed = parse_s3_settings(&no_style).unwrap();
        assert!(parsed.path_style);

        let vhost_ip = serde_json::json!({
            "endpoint": "https://127.0.0.1:9000", "bucket": "b", "pathStyle": false
        });
        let err = validate(
            &parse_s3_settings(&vhost_ip).unwrap(),
            &base(vhost_ip, vec!["ak", "sk"], "streams"),
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("requires a DNS endpoint"), "{err}");

        let vhost_bad_bucket = serde_json::json!({
            "endpoint": "https://s3.example.com", "bucket": "Bad_Bucket", "pathStyle": false
        });
        let err = validate(
            &parse_s3_settings(&vhost_bad_bucket).unwrap(),
            &base(vhost_bad_bucket, vec!["ak", "sk"], "streams"),
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("DNS-compatible bucket"), "{err}");

        let folder_bad = base(good.clone(), vec!["ak", "sk"], "");
        let err = validate(&parse_s3_settings(&good).unwrap(), &folder_bad).err().unwrap();
        assert!(err.to_string().contains("remoteFolder"), "{err}");

        let secrets_short = base(good.clone(), vec!["ak"], "streams");
        let err = validate(&parse_s3_settings(&good).unwrap(), &secrets_short).err().unwrap();
        assert!(err.to_string().contains("AccessKeyID, SecretAccessKey"), "{err}");

        let secrets_bad = base(good.clone(), vec!["a k", "sk"], "streams");
        let err = validate(&parse_s3_settings(&good).unwrap(), &secrets_bad).err().unwrap();
        assert!(err.to_string().contains("invalid S3 AccessKeyID"), "{err}");

        let region_bad = serde_json::json!({
            "endpoint": "https://s3.example.com", "region": "us east", "bucket": "b"
        });
        let err = validate(
            &parse_s3_settings(&region_bad).unwrap(),
            &base(region_bad, vec!["ak", "sk"], "streams"),
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("signing region"), "{err}");
    }
}
