//! gRPC 传输配置。
//!
//! 对应 Go `transport/internet/grpc/config.go` + `encoding/customSeviceName.go` 的
//! 服务名解析逻辑。
//!
//! ## 切片边界（P5-4 切片1）
//!
//! 仅实现配置层 + 服务名/stream 名解析（纯字符串处理，独立可测）。
//! 实际 gRPC 拨号（`dial.go`）与服务端（`hub.go`）依赖
//! `google.golang.org/grpc`（HTTP/2 + protobuf framing），Rust 端等价品是
//! `tonic` / `h2`，留切片2 接入。
//!
//! ## 服务名解析（Go 兼容）
//!
//! `service_name` 字段支持两种格式：
//!
//! - **传统格式**（无 `/` 前缀）：直接 [`path_escape`] 编码整串。
//!   - 例如 `"GunService"` → `"GunService"`
//!   - stream 名固定为 `"Tun"` / `"TunMulti"`
//!
//! - **自定义路径格式**（`/` 前缀）：路径分段 + 自定义 stream 名。
//!   - 例如 `"/A/B/Tun|TunMulti"` → service=`"A/B"`，tun=`"Tun"`，multi=`"TunMulti"`
//!   - 客户端 `|` 分割前段，服务端 `|` 分割后段（multi 用第二段）

use std::io;

use crate::error::Result;

/// gRPC 配置。对应 proto `xray.transport.internet.grpc.encoding.Config`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// HTTP/2 `:authority` 伪 header。空时用 dest 地址或 TLS ServerName。
    pub authority: String,
    /// gRPC 服务名。支持传统格式（`"GunService"`）或自定义路径（`"/A/B/Tun"`）。
    /// 详见模块级文档。
    pub service_name: String,
    /// 是否启用 multi-stream 模式（每连接多路 gRPC stream，提升吞吐）。
    pub multi_mode: bool,
    /// 空闲超时（秒）。对应 gRPC keepalive `Time`。
    pub idle_timeout: i32,
    /// 健康检查超时（秒）。对应 gRPC keepalive `Timeout`。
    pub health_check_timeout: i32,
    /// 是否允许无活动 stream 时发送 keepalive（gRPC `PermitWithoutStream`）。
    pub permit_without_stream: bool,
    /// HTTP/2 初始窗口大小（字节）。0 表示用默认值。
    pub initial_windows_size: i32,
    /// User-Agent。支持预设别名：`"chrome"` / `"firefox"` / `"edge"` / `"golang"`。
    /// 空串等同 `"chrome"`。
    pub user_agent: String,
}

/// 从 `grpcSettings` JSON 解析为强类型 [`Config`]。
/// 接受的 JSON 字段（camelCase 与 snake_case 双写法均接受；
/// Go infra/conf/grpc.go 用 snake_case：`idle_timeout` 等）：
/// - `serviceName` / `service_name`：gRPC 服务名（传统格式或自定义路径 `/A/B/Tun|TunMulti`）
/// - `multiMode` / `multi_mode`：是否启用 multi-stream 模式
/// - `authority`：HTTP/2 `:authority` 伪 header
/// - `idleTimeout` / `idle_timeout`：空闲超时（秒）
/// - `healthCheckTimeout` / `health_check_timeout`：健康检查超时（秒）
/// - `permitWithoutStream` / `permit_without_stream`：无活动 stream 时是否发送 keepalive
/// - `initialWindowSize` / `initial_windows_size`：HTTP/2 初始窗口大小（字节）
/// - `userAgent` / `user_agent`：User-Agent（支持预设别名 chrome/firefox/edge/golang）
///
/// `None` 或非 object 返回 [`Config::default`]。
pub(crate) fn parse_grpc_config(json: Option<&serde_json::Value>) -> io::Result<Config> {
    let Some(v) = json else {
        return Ok(Config::default());
    };
    let Some(obj) = v.as_object() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "grpcSettings must be a JSON object",
        ));
    };

    // 字段名双写法：Go infra/conf/grpc.go 用 snake_case（idle_timeout 等 5 个），
    // proto3 JSON / 客户端配置常用 camelCase。两种都接受。
    let get_str = |camel: &str, snake: &str| {
        obj.get(camel).or_else(|| obj.get(snake)).and_then(|x| x.as_str()).unwrap_or("").to_string()
    };
    let get_bool = |camel: &str, snake: &str| {
        obj.get(camel).or_else(|| obj.get(snake)).and_then(|x| x.as_bool()).unwrap_or(false)
    };
    let get_i32 = |camel: &str, snake: &str| {
        obj.get(camel).or_else(|| obj.get(snake)).and_then(|x| x.as_i64()).unwrap_or(0) as i32
    };

    Ok(Config {
        authority: get_str("authority", "authority"),
        service_name: get_str("serviceName", "service_name"),
        multi_mode: get_bool("multiMode", "multi_mode"),
        idle_timeout: get_i32("idleTimeout", "idle_timeout"),
        health_check_timeout: get_i32("healthCheckTimeout", "health_check_timeout"),
        permit_without_stream: get_bool("permitWithoutStream", "permit_without_stream"),
        initial_windows_size: get_i32("initialWindowSize", "initial_windows_size"),
        user_agent: get_str("userAgent", "user_agent"),
    })
}

impl Config {
    /// 解析 `service_name` 为 gRPC 服务名（已 [`path_escape`]）。
    ///
    /// 对应 Go `Config.getServiceName()`。逻辑：
    ///
    /// - 无 `/` 前缀：`path_escape(service_name)`
    /// - 有 `/` 前缀：取首/尾 `/` 之间的部分，按 `/` 分段逐段 escape，用 `/` 重组
    #[must_use]
    pub fn service_name(&self) -> String {
        let name = &self.service_name;
        if !name.starts_with('/') {
            return path_escape(name);
        }
        // 自定义路径：找最后一个 '/' 的位置
        let last_slash = name.rfind('/').unwrap_or(1);
        let start = 1;
        let end = last_slash.max(1);
        let raw_service = if end > start { &name[start..end] } else { "" };
        if raw_service.is_empty() {
            return String::new();
        }
        raw_service.split('/').map(path_escape).collect::<Vec<_>>().join("/")
    }

    /// 解析 `service_name` 末段为 Tun stream 名（已 [`path_escape`]）。
    ///
    /// 对应 Go `Config.getTunStreamName()`。逻辑：
    ///
    /// - 无 `/` 前缀：固定返回 `"Tun"`
    /// - 有 `/` 前缀：取末段（最后 `/` 之后），按 `|` 分割取首段，escape
    #[must_use]
    pub fn tun_stream_name(&self) -> String {
        let name = &self.service_name;
        if !name.starts_with('/') {
            return "Tun".to_string();
        }
        let ending = ending_path(name);
        let tun_part = ending.split('|').next().unwrap_or("");
        path_escape(tun_part)
    }

    /// 解析 `service_name` 末段为 TunMulti stream 名（已 [`path_escape`]）。
    ///
    /// 对应 Go `Config.getTunMultiStreamName()`。逻辑：
    ///
    /// - 无 `/` 前缀：固定返回 `"TunMulti"`
    /// - 有 `/` 前缀：取末段按 `|` 分割
    ///   - 1 段：客户端路径，escape 段[0]
    ///   - 2 段：服务端 multi 路径，escape 段[1]
    #[must_use]
    pub fn tun_multi_stream_name(&self) -> String {
        let name = &self.service_name;
        if !name.starts_with('/') {
            return "TunMulti".to_string();
        }
        let ending = ending_path(name);
        let parts: Vec<&str> = ending.split('|').collect();
        match parts.len() {
            1 => path_escape(parts[0]),
            _ => path_escape(parts.get(1).unwrap_or(&"")),
        }
    }

    /// 从 prost 生成的 proto Config 构造。
    pub fn from_proto(
        p: xray_proto::xray::transport::internet::grpc::encoding::Config,
    ) -> Result<Self> {
        Ok(Self {
            authority: p.authority,
            service_name: p.service_name,
            multi_mode: p.multi_mode,
            idle_timeout: p.idle_timeout,
            health_check_timeout: p.health_check_timeout,
            permit_without_stream: p.permit_without_stream,
            initial_windows_size: p.initial_windows_size,
            user_agent: p.user_agent,
        })
    }

    /// 转换为 prost Config（用于序列化）。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::transport::internet::grpc::encoding::Config {
        xray_proto::xray::transport::internet::grpc::encoding::Config {
            authority: self.authority.clone(),
            service_name: self.service_name.clone(),
            multi_mode: self.multi_mode,
            idle_timeout: self.idle_timeout,
            health_check_timeout: self.health_check_timeout,
            permit_without_stream: self.permit_without_stream,
            initial_windows_size: self.initial_windows_size,
            user_agent: self.user_agent.clone(),
        }
    }
}

/// 取末段路径（最后 `/` 之后的部分）。调用方保证 `name.starts_with('/')`。
fn ending_path(name: &str) -> &str {
    match name.rfind('/') {
        Some(idx) => &name[idx + 1..],
        None => name,
    }
}

/// URL path 段 percent-escape。对应 Go `url.PathEscape`（H9 对齐
/// grpc/config.go:11-37）。Go `shouldEscape(c, encodePathSegment)`：保留
/// unreserved（`A-Za-z0-9-._~`）+ segment 模式额外保留 `$ & + : ; = @`，
/// 仅转义 `/ ; , ?` 与其余所有字节。此前仅保留 RFC3986 unreserved 导致
/// `$&+:;=@` 被过度编码 → Go 服务端按注册名原样比对时 Unimplemented。
fn path_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if path_segment_unescaped(byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex_upper(byte >> 4));
            out.push(hex_upper(byte & 0x0F));
        }
    }
    out
}

/// Go `shouldEscape(_, encodePathSegment) == false` 的字节集合。
fn path_segment_unescaped(b: u8) -> bool {
    matches!(
        b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'.' | b'_' | b'~'
            // §2.2 reserved，segment 模式保留（Go url.go:148 仅 /;,? 转义）。
            // 注意 ';' 属于转义集（Go: saves / ; ,）——不在此处。
            | b'$' | b'&' | b'+' | b':' | b'=' | b'@'
    )
}

/// 4-bit 数字转大写 hex 字符。
fn hex_upper(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'A' + (n - 10)) as char,
        _ => '0',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_escape_alphanumeric_passthrough() {
        assert_eq!(path_escape("GunService"), "GunService");
        assert_eq!(path_escape("abc123"), "abc123");
    }

    #[test]
    fn path_escape_unreserved_chars_kept() {
        assert_eq!(path_escape("a-b.c_d~e"), "a-b.c_d~e");
    }

    /// H9 回归：Go PathEscape（segment 模式）保留 `$ & + : ; = @`——旧实现
    /// 按 RFC3986 unreserved 白名单把它们编码为 %XX，Go 服务端按注册名
    /// 原样比对 → Unimplemented。
    #[test]
    fn path_escape_keeps_go_segment_reserved_chars() {
        assert_eq!(path_escape("a$b&c+d:e=f=g@h"), "a$b&c+d:e=f=g@h");
        // 仅 / ; , ? 与非 ASCII 被转义（Go shouldEscape segment 分支，url.go:148）。
        assert_eq!(path_escape("a/b"), "a%2Fb");
        assert_eq!(path_escape("a;b,c?d"), "a%3Bb%2Cc%3Fd");
        // 空格仍转义（Go 尽力而为之外的字节全部 %XX）。
        assert_eq!(path_escape("a b"), "a%20b");
    }

    #[test]
    fn path_escape_special_chars_encoded() {
        assert_eq!(path_escape(" "), "%20");
        assert_eq!(path_escape("a/b"), "a%2Fb");
        assert_eq!(path_escape("a|b"), "a%7Cb");
    }

    #[test]
    fn path_escape_non_ascii_encoded() {
        assert_eq!(path_escape("中文"), "%E4%B8%AD%E6%96%87");
    }

    #[test]
    fn path_escape_empty() {
        assert_eq!(path_escape(""), "");
    }

    #[test]
    fn service_name_traditional_format() {
        let cfg = Config { service_name: "GunService".into(), ..Default::default() };
        assert_eq!(cfg.service_name(), "GunService");
    }

    #[test]
    fn service_name_traditional_with_special_chars() {
        let cfg = Config { service_name: "Gun Service".into(), ..Default::default() };
        assert_eq!(cfg.service_name(), "Gun%20Service");
    }

    #[test]
    fn service_name_custom_path_single_segment() {
        let cfg = Config { service_name: "/A/Tun".into(), ..Default::default() };
        assert_eq!(cfg.service_name(), "A");
    }

    #[test]
    fn service_name_custom_path_multi_segment() {
        let cfg = Config { service_name: "/A/B/Tun".into(), ..Default::default() };
        assert_eq!(cfg.service_name(), "A/B");
    }

    #[test]
    fn service_name_custom_path_with_escape() {
        let cfg = Config { service_name: "/A B/Tun".into(), ..Default::default() };
        assert_eq!(cfg.service_name(), "A%20B");
    }

    #[test]
    fn tun_stream_name_traditional_returns_constant() {
        let cfg = Config { service_name: "GunService".into(), ..Default::default() };
        assert_eq!(cfg.tun_stream_name(), "Tun");
    }

    #[test]
    fn tun_stream_name_custom_path() {
        let cfg = Config { service_name: "/A/B/Tun".into(), ..Default::default() };
        assert_eq!(cfg.tun_stream_name(), "Tun");
    }

    #[test]
    fn tun_stream_name_custom_with_pipe() {
        let cfg = Config { service_name: "/A/B/Tun|TunMulti".into(), ..Default::default() };
        assert_eq!(cfg.tun_stream_name(), "Tun");
    }

    #[test]
    fn tun_stream_name_custom_renamed() {
        let cfg = Config { service_name: "/A/B/MyTun".into(), ..Default::default() };
        assert_eq!(cfg.tun_stream_name(), "MyTun");
    }

    #[test]
    fn tun_multi_stream_name_traditional_returns_constant() {
        let cfg = Config { service_name: "GunService".into(), ..Default::default() };
        assert_eq!(cfg.tun_multi_stream_name(), "TunMulti");
    }

    #[test]
    fn tun_multi_stream_name_custom_with_pipe_server_side() {
        let cfg = Config { service_name: "/A/B/Tun|TunMulti".into(), ..Default::default() };
        assert_eq!(cfg.tun_multi_stream_name(), "TunMulti");
    }

    #[test]
    fn tun_multi_stream_name_custom_single_part() {
        let cfg = Config { service_name: "/A/B/MyMulti".into(), ..Default::default() };
        assert_eq!(cfg.tun_multi_stream_name(), "MyMulti");
    }

    #[test]
    fn proto_roundtrip() {
        let cfg = Config {
            authority: "example.com".into(),
            service_name: "GunService".into(),
            multi_mode: true,
            idle_timeout: 30,
            health_check_timeout: 10,
            permit_without_stream: true,
            initial_windows_size: 65535,
            user_agent: "chrome".into(),
        };
        let proto = cfg.to_proto();
        let cfg2 = Config::from_proto(proto).unwrap();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn default_config_all_empty_or_zero() {
        let cfg = Config::default();
        assert!(cfg.authority.is_empty());
        assert!(cfg.service_name.is_empty());
        assert!(!cfg.multi_mode);
        assert_eq!(cfg.idle_timeout, 0);
    }

    #[test]
    fn typical_gun_config() {
        let cfg =
            Config { service_name: "GunService".into(), multi_mode: true, ..Default::default() };
        assert_eq!(cfg.service_name(), "GunService");
        assert_eq!(cfg.tun_stream_name(), "Tun");
        assert_eq!(cfg.tun_multi_stream_name(), "TunMulti");
    }

    #[test]
    fn custom_path_config_full() {
        let cfg_server = Config { service_name: "/A/B/Tun|TunMulti".into(), ..Default::default() };
        assert_eq!(cfg_server.service_name(), "A/B");
        assert_eq!(cfg_server.tun_stream_name(), "Tun");
        assert_eq!(cfg_server.tun_multi_stream_name(), "TunMulti");
    }
}
