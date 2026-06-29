//! SplitHTTP 传输配置。
//!
//! 对应 Go `transport/internet/splithttp/config.go` + `config.proto`。
//!
//! ## 字段规模
//!
//! SplitHTTP 是 Xray 最复杂的 transport：`Config` 有 28 字段，配合 `RangeConfig`
//! 随机范围、`XmuxConfig` 多路复用调优、7 种 `Placement` 策略（session/seq/
//! uplinkData/xPadding 可放在 path/query/header/cookie/body/auto）。
//!
//! ## 切片边界（P5-3 切片1）
//!
//! 实现所有 `GetNormalized*` 纯函数方法（默认值推断 + Placement 依赖判定）
//! + prost 双向转换。复杂方法（依赖 `http.Request` / `XPadding`）留切片2：
//! `WriteResponseHeader` / `GetRequestHeaderWithPayload` / `ApplyMetaToRequest` /
//! `FillStreamRequest` / `FillPacketRequest` / `ExtractMetaFromRequest`。

use std::collections::HashMap;

use crate::error::Result;

// ===== Placement 常量（对应 Go `common.go`）=====

/// Placement 策略：参数放在 query 的特殊 header。
pub const PLACEMENT_QUERY_IN_HEADER: &str = "queryInHeader";
/// Placement 策略：参数放在 cookie。
pub const PLACEMENT_COOKIE: &str = "cookie";
/// Placement 策略：参数放在 header。
pub const PLACEMENT_HEADER: &str = "header";
/// Placement 策略：参数放在 query string。
pub const PLACEMENT_QUERY: &str = "query";
/// Placement 策略：参数放在 URL path。
pub const PLACEMENT_PATH: &str = "path";
/// Placement 策略：参数放在 body。
pub const PLACEMENT_BODY: &str = "body";
/// Placement 策略：自动选择（实现决定）。
pub const PLACEMENT_AUTO: &str = "auto";

// ===== RangeConfig =====

/// 范围配置（含随机采样）。对应 proto `RangeConfig`。
#[derive(Debug, Clone, Default, PartialEq, Eq, Copy)]
pub struct RangeConfig {
    /// 范围下界（含）。
    pub from: i32,
    /// 范围上界（含）。
    pub to: i32,
}

impl RangeConfig {
    /// 构造 `[from, to]` 范围。
    #[must_use]
    pub fn new(from: i32, to: i32) -> Self {
        Self { from, to }
    }

    /// 返回随机值（含端点）。对应 Go `RangeConfig.rand()`。
    ///
    /// 切片1 用确定性中点 `(from + to) / 2` 作为占位（避免依赖 `xray_crypto`
    /// 的 `rand_between`）。切片2 接入真随机后，此方法保持签名不变。
    #[must_use]
    pub fn rand(&self) -> i32 {
        if self.from >= self.to {
            return self.from;
        }
        // ponytail: 确定性中点 fallback。真随机等切片2 接入 xray_crypto::rand_between。
        (self.from + self.to) / 2
    }
}

// ===== XmuxConfig =====

/// xmux 多路复用配置。对应 proto `XmuxConfig`。
///
/// 所有 `RangeConfig` 字段在 proto 中是 sub-message，Rust 端用 `Option`
/// 表达 nil 语义（`None` 时用默认 `RangeConfig { 0, 0 }`）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XmuxConfig {
    /// 最大并发请求数 / 连接。
    pub max_concurrency: Option<RangeConfig>,
    /// 最大连接数。
    pub max_connections: Option<RangeConfig>,
    /// 连接最大复用次数。
    pub c_max_reuse_times: Option<RangeConfig>,
    /// HTTP/2 stream 最大请求次数。
    pub h_max_request_times: Option<RangeConfig>,
    /// HTTP/2 stream 最大复用秒数。
    pub h_max_reusable_secs: Option<RangeConfig>,
    /// HTTP/2 keepalive 周期（秒）。
    pub h_keep_alive_period: i64,
}

impl XmuxConfig {
    /// 对应 Go `GetNormalizedMaxConcurrency`。`None` 返回 `RangeConfig { 0, 0 }`。
    #[must_use]
    pub fn normalized_max_concurrency(&self) -> RangeConfig {
        self.max_concurrency.unwrap_or(RangeConfig { from: 0, to: 0 })
    }

    #[must_use]
    pub fn normalized_max_connections(&self) -> RangeConfig {
        self.max_connections.unwrap_or(RangeConfig { from: 0, to: 0 })
    }

    #[must_use]
    pub fn normalized_c_max_reuse_times(&self) -> RangeConfig {
        self.c_max_reuse_times.unwrap_or(RangeConfig { from: 0, to: 0 })
    }

    #[must_use]
    pub fn normalized_h_max_request_times(&self) -> RangeConfig {
        self.h_max_request_times.unwrap_or(RangeConfig { from: 0, to: 0 })
    }

    #[must_use]
    pub fn normalized_h_max_reusable_secs(&self) -> RangeConfig {
        self.h_max_reusable_secs.unwrap_or(RangeConfig { from: 0, to: 0 })
    }
}

// ===== Config =====

/// SplitHTTP 主配置。对应 proto `xray.transport.internet.splithttp.Config`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// HTTP `Host` header。
    pub host: String,
    /// URL 路径（可带 `?query`，由 `normalized_query` 提取）。
    pub path: String,
    /// 工作模式（`auto` / `packet-up` / `stream-up` / `stream-one`）。
    pub mode: String,
    /// 自定义 HTTP headers。
    pub headers: HashMap<String, String>,
    /// X-Padding 字节数随机范围。
    pub x_padding_bytes: Option<RangeConfig>,
    /// 是否禁用 gRPC Content-Type header。
    pub no_grpc_header: bool,
    /// 是否禁用 SSE 响应 header。
    pub no_sse_header: bool,
    /// 服务端：单个 POST body 最大字节数随机范围。
    pub sc_max_each_post_bytes: Option<RangeConfig>,
    /// 服务端：两次 POST 最小间隔毫秒随机范围。
    pub sc_min_posts_interval_ms: Option<RangeConfig>,
    /// 服务端：最大缓冲 POST 数。
    pub sc_max_buffered_posts: i64,
    /// 服务端：stream-up 模式上传服务端推送周期随机范围（秒）。
    pub sc_stream_up_server_secs: Option<RangeConfig>,
    /// xmux 多路复用配置。
    pub xmux: Option<XmuxConfig>,
    /// 下载流配置（嵌套 StreamConfig，切片1 不解析）。
    pub download_settings: Option<Vec<u8>>, // ponytail: proto StreamConfig 留切片2 强类型化
    /// 是否启用 X-Padding 混淆模式。
    pub x_padding_obfs_mode: bool,
    /// X-Padding key（混淆模式用）。
    pub x_padding_key: String,
    /// X-Padding header 名（混淆模式用）。
    pub x_padding_header: String,
    /// X-Padding placement（混淆模式用）。
    pub x_padding_placement: String,
    /// X-Padding 填充方法（`padding` / `garble`）。
    pub x_padding_method: String,
    /// 上行 HTTP method（默认 `POST`）。
    pub uplink_http_method: String,
    /// session id placement（默认 `path`）。
    pub session_placement: String,
    /// session key 名。
    pub session_key: String,
    /// seq placement（默认 `path`）。
    pub seq_placement: String,
    /// seq key 名。
    pub seq_key: String,
    /// 上行数据 placement（默认 `body`）。
    pub uplink_data_placement: String,
    /// 上行数据 key 名。
    pub uplink_data_key: String,
    /// 上行 chunk 大小随机范围。
    pub uplink_chunk_size: Option<RangeConfig>,
    /// 服务端：最大 header 字节数。
    pub server_max_header_bytes: i32,
}

impl Config {
    /// 规范化路径：补 `/` 前后缀，剥离 `?query`。对应 Go `GetNormalizedPath`。
    ///
    /// - 空或非 `/` 开头 → 补 `/`
    /// - 末尾非 `/` → 补 `/`
    /// - `?` 后部分剥离（query 由 [`Self::normalized_query`] 提取）
    #[must_use]
    pub fn normalized_path(&self) -> String {
        let mut path = self.path.split('?').next().unwrap_or("").to_string();
        if path.is_empty() || !path.starts_with('/') {
            path.insert(0, '/');
        }
        if !path.ends_with('/') {
            path.push('/');
        }
        path
    }

    /// 提取 path 中的 `?query` 部分（不含 `?`）。对应 Go `GetNormalizedQuery`。
    #[must_use]
    pub fn normalized_query(&self) -> String {
        match self.path.split_once('?') {
            Some((_, q)) => q.to_string(),
            None => String::new(),
        }
    }

    /// 上行 HTTP method。空时默认 `POST`。对应 Go `GetNormalizedUplinkHTTPMethod`。
    #[must_use]
    pub fn normalized_uplink_http_method(&self) -> &str {
        if self.uplink_http_method.is_empty() {
            "POST"
        } else {
            &self.uplink_http_method
        }
    }

    /// 单次 POST 最大字节数范围。None 或 `to=0` 返回默认 `1_000_000..=1_000_000`。
    ///
    /// 对应 Go `GetNormalizedScMaxEachPostBytes`。
    #[must_use]
    pub fn normalized_sc_max_each_post_bytes(&self) -> RangeConfig {
        match self.sc_max_each_post_bytes {
            Some(r) if r.to != 0 => r,
            _ => RangeConfig { from: 1_000_000, to: 1_000_000 },
        }
    }

    /// 两次 POST 最小间隔（毫秒）范围。None 或 `to=0` 返回默认 `30..=30`。
    #[must_use]
    pub fn normalized_sc_min_posts_interval_ms(&self) -> RangeConfig {
        match self.sc_min_posts_interval_ms {
            Some(r) if r.to != 0 => r,
            _ => RangeConfig { from: 30, to: 30 },
        }
    }

    /// 最大缓冲 POST 数。0 返回默认 30。对应 Go `GetNormalizedScMaxBufferedPosts`。
    #[must_use]
    pub fn normalized_sc_max_buffered_posts(&self) -> i64 {
        if self.sc_max_buffered_posts == 0 {
            30
        } else {
            self.sc_max_buffered_posts
        }
    }

    /// stream-up 服务端推送周期（秒）范围。None 或 `to=0` 返回默认 `20..=80`。
    #[must_use]
    pub fn normalized_sc_stream_up_server_secs(&self) -> RangeConfig {
        match self.sc_stream_up_server_secs {
            Some(r) if r.to != 0 => r,
            _ => RangeConfig { from: 20, to: 80 },
        }
    }

    /// 上行 chunk 大小范围。依赖 [`Self::normalized_uplink_data_placement`]:
    ///
    /// - `cookie` → `2_048..=3_072` (2-3 KiB)
    /// - `header` → `3_000..=4_000` (3-4 KB)
    /// - 其他 → 复用 [`Self::normalized_sc_max_each_post_bytes`]
    ///
    /// 显式配置时：`from < 64` 强制抬到 64（header 长度限制）。
    ///
    /// 对应 Go `GetNormalizedUplinkChunkSize`。
    #[must_use]
    pub fn normalized_uplink_chunk_size(&self) -> RangeConfig {
        match self.uplink_chunk_size {
            Some(r) if r.to != 0 => {
                if r.from < 64 {
                    RangeConfig {
                        from: 64,
                        to: r.to.max(64),
                    }
                } else {
                    r
                }
            }
            _ => match self.normalized_uplink_data_placement() {
                PLACEMENT_COOKIE => RangeConfig { from: 2 * 1024, to: 3 * 1024 },
                PLACEMENT_HEADER => RangeConfig { from: 3 * 1000, to: 4 * 1000 },
                _ => self.normalized_sc_max_each_post_bytes(),
            },
        }
    }

    /// 服务端最大 header 字节数。≤0 返回默认 8192。
    #[must_use]
    pub fn normalized_server_max_header_bytes(&self) -> i32 {
        if self.server_max_header_bytes <= 0 {
            8192
        } else {
            self.server_max_header_bytes
        }
    }

    /// session placement。空返回默认 `path`。
    #[must_use]
    pub fn normalized_session_placement(&self) -> &str {
        if self.session_placement.is_empty() {
            PLACEMENT_PATH
        } else {
            &self.session_placement
        }
    }

    /// seq placement。空返回默认 `path`。
    #[must_use]
    pub fn normalized_seq_placement(&self) -> &str {
        if self.seq_placement.is_empty() {
            PLACEMENT_PATH
        } else {
            &self.seq_placement
        }
    }

    /// 上行数据 placement。空返回默认 `body`。
    #[must_use]
    pub fn normalized_uplink_data_placement(&self) -> &str {
        if self.uplink_data_placement.is_empty() {
            PLACEMENT_BODY
        } else {
            &self.uplink_data_placement
        }
    }

    /// session key 名。空时根据 placement 推断默认：
    ///
    /// - `header` → `X-Session`
    /// - `cookie` / `query` → `x_session`
    /// - 其他 → 空
    #[must_use]
    pub fn normalized_session_key(&self) -> &str {
        if !self.session_key.is_empty() {
            return &self.session_key;
        }
        match self.normalized_session_placement() {
            PLACEMENT_HEADER => "X-Session",
            PLACEMENT_COOKIE | PLACEMENT_QUERY => "x_session",
            _ => "",
        }
    }

    /// seq key 名。空时根据 placement 推断默认：
    ///
    /// - `header` → `X-Seq`
    /// - `cookie` / `query` → `x_seq`
    /// - 其他 → 空
    #[must_use]
    pub fn normalized_seq_key(&self) -> &str {
        if !self.seq_key.is_empty() {
            return &self.seq_key;
        }
        match self.normalized_seq_placement() {
            PLACEMENT_HEADER => "X-Seq",
            PLACEMENT_COOKIE | PLACEMENT_QUERY => "x_seq",
            _ => "",
        }
    }

    /// xmux 配置。None 返回默认空配置。
    #[must_use]
    pub fn normalized_xmux(&self) -> XmuxConfig {
        self.xmux.clone().unwrap_or_default()
    }

    /// 拼接 path + value。末尾有 `/` 直接接，否则补 `/` 再接。
    ///
    /// 对应 Go `appendToPath`。
    #[must_use]
    pub fn append_to_path(path: &str, value: &str) -> String {
        if path.ends_with('/') {
            format!("{path}{value}")
        } else {
            format!("{path}/{value}")
        }
    }

    /// 从 prost 生成的 proto Config 构造。
    pub fn from_proto(p: xray_proto::xray::transport::internet::splithttp::Config) -> Result<Self> {
        Ok(Self {
            host: p.host,
            path: p.path,
            mode: p.mode,
            headers: p.headers.into_iter().collect(),
            x_padding_bytes: p.x_padding_bytes.map(range_from_proto),
            no_grpc_header: p.no_grpc_header,
            no_sse_header: p.no_sse_header,
            sc_max_each_post_bytes: p.sc_max_each_post_bytes.map(range_from_proto),
            sc_min_posts_interval_ms: p.sc_min_posts_interval_ms.map(range_from_proto),
            sc_max_buffered_posts: p.sc_max_buffered_posts,
            sc_stream_up_server_secs: p.sc_stream_up_server_secs.map(range_from_proto),
            xmux: p.xmux.map(xmux_from_proto),
            download_settings: None, // ponytail: 切片2 接入 StreamConfig 强类型
            x_padding_obfs_mode: p.x_padding_obfs_mode,
            x_padding_key: p.x_padding_key,
            x_padding_header: p.x_padding_header,
            x_padding_placement: p.x_padding_placement,
            x_padding_method: p.x_padding_method,
            uplink_http_method: p.uplink_http_method,
            session_placement: p.session_placement,
            session_key: p.session_key,
            seq_placement: p.seq_placement,
            seq_key: p.seq_key,
            uplink_data_placement: p.uplink_data_placement,
            uplink_data_key: p.uplink_data_key,
            uplink_chunk_size: p.uplink_chunk_size.map(range_from_proto),
            server_max_header_bytes: p.server_max_header_bytes,
        })
    }

    /// 转换为 prost Config。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::transport::internet::splithttp::Config {
        xray_proto::xray::transport::internet::splithttp::Config {
            host: self.host.clone(),
            path: self.path.clone(),
            mode: self.mode.clone(),
            headers: self.headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            x_padding_bytes: self.x_padding_bytes.map(range_to_proto),
            no_grpc_header: self.no_grpc_header,
            no_sse_header: self.no_sse_header,
            sc_max_each_post_bytes: self.sc_max_each_post_bytes.map(range_to_proto),
            sc_min_posts_interval_ms: self.sc_min_posts_interval_ms.map(range_to_proto),
            sc_max_buffered_posts: self.sc_max_buffered_posts,
            sc_stream_up_server_secs: self.sc_stream_up_server_secs.map(range_to_proto),
            xmux: self.xmux.as_ref().map(xmux_to_proto),
            download_settings: None,
            x_padding_obfs_mode: self.x_padding_obfs_mode,
            x_padding_key: self.x_padding_key.clone(),
            x_padding_header: self.x_padding_header.clone(),
            x_padding_placement: self.x_padding_placement.clone(),
            x_padding_method: self.x_padding_method.clone(),
            uplink_http_method: self.uplink_http_method.clone(),
            session_placement: self.session_placement.clone(),
            session_key: self.session_key.clone(),
            seq_placement: self.seq_placement.clone(),
            seq_key: self.seq_key.clone(),
            uplink_data_placement: self.uplink_data_placement.clone(),
            uplink_data_key: self.uplink_data_key.clone(),
            uplink_chunk_size: self.uplink_chunk_size.map(range_to_proto),
            server_max_header_bytes: self.server_max_header_bytes,
        }
    }
}

// ===== proto 转换辅助 =====

fn range_from_proto(r: xray_proto::xray::transport::internet::splithttp::RangeConfig) -> RangeConfig {
    RangeConfig { from: r.from, to: r.to }
}

fn range_to_proto(r: RangeConfig) -> xray_proto::xray::transport::internet::splithttp::RangeConfig {
    xray_proto::xray::transport::internet::splithttp::RangeConfig { from: r.from, to: r.to }
}

fn xmux_from_proto(m: xray_proto::xray::transport::internet::splithttp::XmuxConfig) -> XmuxConfig {
    XmuxConfig {
        max_concurrency: m.max_concurrency.map(range_from_proto),
        max_connections: m.max_connections.map(range_from_proto),
        c_max_reuse_times: m.c_max_reuse_times.map(range_from_proto),
        h_max_request_times: m.h_max_request_times.map(range_from_proto),
        h_max_reusable_secs: m.h_max_reusable_secs.map(range_from_proto),
        h_keep_alive_period: m.h_keep_alive_period,
    }
}

fn xmux_to_proto(m: &XmuxConfig) -> xray_proto::xray::transport::internet::splithttp::XmuxConfig {
    xray_proto::xray::transport::internet::splithttp::XmuxConfig {
        max_concurrency: m.max_concurrency.map(range_to_proto),
        max_connections: m.max_connections.map(range_to_proto),
        c_max_reuse_times: m.c_max_reuse_times.map(range_to_proto),
        h_max_request_times: m.h_max_request_times.map(range_to_proto),
        h_max_reusable_secs: m.h_max_reusable_secs.map(range_to_proto),
        h_keep_alive_period: m.h_keep_alive_period,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Placement 常量 =====

    #[test]
    fn placement_constants_match_go() {
        assert_eq!(PLACEMENT_QUERY_IN_HEADER, "queryInHeader");
        assert_eq!(PLACEMENT_COOKIE, "cookie");
        assert_eq!(PLACEMENT_HEADER, "header");
        assert_eq!(PLACEMENT_QUERY, "query");
        assert_eq!(PLACEMENT_PATH, "path");
        assert_eq!(PLACEMENT_BODY, "body");
        assert_eq!(PLACEMENT_AUTO, "auto");
    }

    // ===== RangeConfig =====

    #[test]
    fn range_rand_deterministic_midpoint() {
        let r = RangeConfig::new(0, 100);
        assert_eq!(r.rand(), 50); // 切片1 用中点
    }

    #[test]
    fn range_rand_from_ge_to_returns_from() {
        assert_eq!(RangeConfig::new(100, 100).rand(), 100);
        assert_eq!(RangeConfig::new(100, 50).rand(), 100); // from > to 也返回 from
    }

    // ===== normalized_path / query =====

    #[test]
    fn normalized_path_empty_becomes_slash() {
        let cfg = Config::default();
        assert_eq!(cfg.normalized_path(), "/");
    }

    #[test]
    fn normalized_path_no_leading_slash_prepended() {
        let cfg = Config { path: "ws".into(), ..Default::default() };
        assert_eq!(cfg.normalized_path(), "/ws/");
    }

    #[test]
    fn normalized_path_already_valid_gets_trailing_slash() {
        let cfg = Config { path: "/api".into(), ..Default::default() };
        assert_eq!(cfg.normalized_path(), "/api/");
    }

    #[test]
    fn normalized_path_strips_query() {
        let cfg = Config { path: "/ws?x=1".into(), ..Default::default() };
        assert_eq!(cfg.normalized_path(), "/ws/");
    }

    #[test]
    fn normalized_query_extracted() {
        let cfg = Config { path: "/ws?x=1&y=2".into(), ..Default::default() };
        assert_eq!(cfg.normalized_query(), "x=1&y=2");
    }

    #[test]
    fn normalized_query_empty_when_no_question_mark() {
        let cfg = Config { path: "/ws".into(), ..Default::default() };
        assert_eq!(cfg.normalized_query(), "");
    }

    // ===== normalized_uplink_http_method =====

    #[test]
    fn uplink_http_method_default_post() {
        assert_eq!(Config::default().normalized_uplink_http_method(), "POST");
    }

    #[test]
    fn uplink_http_method_custom_passthrough() {
        let cfg = Config { uplink_http_method: "PUT".into(), ..Default::default() };
        assert_eq!(cfg.normalized_uplink_http_method(), "PUT");
    }

    // ===== normalized_sc_* =====

    #[test]
    fn sc_max_each_post_bytes_default_1m() {
        let r = Config::default().normalized_sc_max_each_post_bytes();
        assert_eq!((r.from, r.to), (1_000_000, 1_000_000));
    }

    #[test]
    fn sc_max_each_post_bytes_custom_passthrough() {
        let cfg = Config {
            sc_max_each_post_bytes: Some(RangeConfig::new(500_000, 800_000)),
            ..Default::default()
        };
        let r = cfg.normalized_sc_max_each_post_bytes();
        assert_eq!((r.from, r.to), (500_000, 800_000));
    }

    #[test]
    fn sc_max_each_post_bytes_to_zero_falls_back() {
        // 与 None 一致：to=0 触发默认值
        let cfg = Config {
            sc_max_each_post_bytes: Some(RangeConfig::new(500_000, 0)),
            ..Default::default()
        };
        let r = cfg.normalized_sc_max_each_post_bytes();
        assert_eq!((r.from, r.to), (1_000_000, 1_000_000));
    }

    #[test]
    fn sc_min_posts_interval_ms_default_30() {
        let r = Config::default().normalized_sc_min_posts_interval_ms();
        assert_eq!((r.from, r.to), (30, 30));
    }

    #[test]
    fn sc_max_buffered_posts_default_30() {
        assert_eq!(Config::default().normalized_sc_max_buffered_posts(), 30);
    }

    #[test]
    fn sc_stream_up_server_secs_default_20_to_80() {
        let r = Config::default().normalized_sc_stream_up_server_secs();
        assert_eq!((r.from, r.to), (20, 80));
    }

    #[test]
    fn server_max_header_bytes_default_8192() {
        assert_eq!(Config::default().normalized_server_max_header_bytes(), 8192);
    }

    // ===== normalized_uplink_chunk_size (placement 依赖) =====

    #[test]
    fn uplink_chunk_size_default_depends_on_placement() {
        // body → 复用 scMaxEachPostBytes (默认 1M)
        let cfg = Config::default();
        let r = cfg.normalized_uplink_chunk_size();
        assert_eq!((r.from, r.to), (1_000_000, 1_000_000));

        // cookie → 2-3 KiB
        let cfg = Config { uplink_data_placement: "cookie".into(), ..Default::default() };
        let r = cfg.normalized_uplink_chunk_size();
        assert_eq!((r.from, r.to), (2 * 1024, 3 * 1024));

        // header → 3-4 KB
        let cfg = Config { uplink_data_placement: "header".into(), ..Default::default() };
        let r = cfg.normalized_uplink_chunk_size();
        assert_eq!((r.from, r.to), (3 * 1000, 4 * 1000));
    }

    #[test]
    fn uplink_chunk_size_explicit_below_64_raised_to_64() {
        let cfg = Config {
            uplink_chunk_size: Some(RangeConfig::new(10, 100)),
            ..Default::default()
        };
        let r = cfg.normalized_uplink_chunk_size();
        assert_eq!((r.from, r.to), (64, 100));
    }

    #[test]
    fn uplink_chunk_size_explicit_to_zero_falls_back_to_placement() {
        let cfg = Config {
            uplink_chunk_size: Some(RangeConfig::new(100, 0)),
            uplink_data_placement: "cookie".into(),
            ..Default::default()
        };
        let r = cfg.normalized_uplink_chunk_size();
        assert_eq!((r.from, r.to), (2 * 1024, 3 * 1024));
    }

    // ===== placement 默认值 =====

    #[test]
    fn session_placement_default_path() {
        assert_eq!(Config::default().normalized_session_placement(), "path");
    }

    #[test]
    fn seq_placement_default_path() {
        assert_eq!(Config::default().normalized_seq_placement(), "path");
    }

    #[test]
    fn uplink_data_placement_default_body() {
        assert_eq!(Config::default().normalized_uplink_data_placement(), "body");
    }

    // ===== key 默认值推断 =====

    #[test]
    fn session_key_inferred_from_placement() {
        let mut cfg = Config::default();
        // 默认 placement=path → key 为空
        assert_eq!(cfg.normalized_session_key(), "");

        // header → X-Session
        cfg.session_placement = "header".into();
        assert_eq!(cfg.normalized_session_key(), "X-Session");

        // cookie → x_session
        cfg.session_placement = "cookie".into();
        assert_eq!(cfg.normalized_session_key(), "x_session");

        // query → x_session
        cfg.session_placement = "query".into();
        assert_eq!(cfg.normalized_session_key(), "x_session");
    }

    #[test]
    fn seq_key_inferred_from_placement() {
        let mut cfg = Config::default();
        assert_eq!(cfg.normalized_seq_key(), "");

        cfg.seq_placement = "header".into();
        assert_eq!(cfg.normalized_seq_key(), "X-Seq");

        cfg.seq_placement = "cookie".into();
        assert_eq!(cfg.normalized_seq_key(), "x_seq");
    }

    #[test]
    fn explicit_session_key_overrides_inference() {
        let cfg = Config {
            session_placement: "header".into(),
            session_key: "X-Custom".into(),
            ..Default::default()
        };
        assert_eq!(cfg.normalized_session_key(), "X-Custom");
    }

    // ===== append_to_path =====

    #[test]
    fn append_to_path_with_trailing_slash() {
        assert_eq!(Config::append_to_path("/ws/", "abc"), "/ws/abc");
    }

    #[test]
    fn append_to_path_without_trailing_slash() {
        assert_eq!(Config::append_to_path("/ws", "abc"), "/ws/abc");
    }

    // ===== XmuxConfig =====

    #[test]
    fn xmux_default_all_zero_range() {
        let x = XmuxConfig::default();
        assert_eq!(x.normalized_max_concurrency(), RangeConfig { from: 0, to: 0 });
        assert_eq!(x.normalized_max_connections(), RangeConfig { from: 0, to: 0 });
        assert_eq!(x.normalized_c_max_reuse_times(), RangeConfig { from: 0, to: 0 });
        assert_eq!(x.normalized_h_max_request_times(), RangeConfig { from: 0, to: 0 });
        assert_eq!(x.normalized_h_max_reusable_secs(), RangeConfig { from: 0, to: 0 });
    }

    #[test]
    fn xmux_custom_passthrough() {
        let x = XmuxConfig {
            max_concurrency: Some(RangeConfig::new(10, 20)),
            max_connections: Some(RangeConfig::new(1, 5)),
            ..Default::default()
        };
        assert_eq!(x.normalized_max_concurrency(), RangeConfig::new(10, 20));
        assert_eq!(x.normalized_max_connections(), RangeConfig::new(1, 5));
    }

    // ===== proto roundtrip =====

    #[test]
    fn proto_roundtrip_minimal() {
        let cfg = Config {
            host: "example.com".into(),
            path: "/ws".into(),
            mode: "auto".into(),
            ..Default::default()
        };
        let proto = cfg.to_proto();
        let cfg2 = Config::from_proto(proto).unwrap();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn proto_roundtrip_full() {
        let cfg = Config {
            host: "h".into(),
            path: "/ws?x=1".into(),
            mode: "packet-up".into(),
            headers: [("X-Token".into(), "v".into())].into_iter().collect(),
            x_padding_bytes: Some(RangeConfig::new(100, 200)),
            no_grpc_header: true,
            no_sse_header: false,
            sc_max_each_post_bytes: Some(RangeConfig::new(500_000, 1_000_000)),
            sc_min_posts_interval_ms: Some(RangeConfig::new(10, 50)),
            sc_max_buffered_posts: 60,
            sc_stream_up_server_secs: Some(RangeConfig::new(15, 90)),
            xmux: Some(XmuxConfig {
                max_concurrency: Some(RangeConfig::new(0, 100)),
                h_keep_alive_period: 60,
                ..Default::default()
            }),
            x_padding_obfs_mode: true,
            x_padding_key: "k".into(),
            uplink_http_method: "PUT".into(),
            session_placement: "header".into(),
            seq_placement: "query".into(),
            uplink_data_placement: "cookie".into(),
            uplink_chunk_size: Some(RangeConfig::new(1024, 2048)),
            server_max_header_bytes: 16384,
            ..Default::default()
        };
        let proto = cfg.to_proto();
        let cfg2 = Config::from_proto(proto).unwrap();
        assert_eq!(cfg, cfg2);
    }
}
