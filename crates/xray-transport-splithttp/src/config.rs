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

use rand::Rng;
use crate::xpadding::{apply_xpadding_to_request_meta, PADDING_METHOD_REPEAT_X, XPaddingConfig, XPaddingPlacement};

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

// ===== Session ID 字符集预设（对应 Go `splithttp.PredefinedTable`）=====

/// 命名字符集 → 字面字符集。命中时 [`Config::generate_session_id`] 用字面值替换预设名。
///
/// 对应 Go `config.go:494-504` `PredefinedTable`。空字符串对应"无预设"分支。
pub const PREDEFINED_SESSION_ID_TABLE: &[(&str, &str)] = &[
    ("ALPHABET", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    ("Alphabet", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
    ("BASE36", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    ("Base62", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
    ("HEX", "0123456789ABCDEF"),
    ("alphabet", "abcdefghijklmnopqrstuvwxyz"),
    ("base36", "0123456789abcdefghijklmnopqrstuvwxyz"),
    ("hex", "0123456789abcdef"),
    ("number", "0123456789"),
];

/// 按预设名查找字符集（区分大小写），未命中返回 `None`。
#[must_use]
pub fn lookup_predefined_session_id_table(name: &str) -> Option<&'static str> {
    PREDEFINED_SESSION_ID_TABLE
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| *v)
}

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
    /// 使用 `rand` crate 的 `thread_rng().gen_range(from..=to)` 生成
    /// 密码学安全的随机值，与 Go `crypto/rand` 行为一致。
    #[must_use]
    pub fn rand(&self) -> i32 {
        if self.from >= self.to {
            return self.from;
        }
        use rand::Rng;
        rand::rng().random_range(self.from..=self.to)
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
    /// 下载流配置（嵌套 Config，用于独立配置下行连接）。
    pub download_settings: Option<Box<Config>>,
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
    /// 自定义 sessionID 字符集。命中 [`PREDEFINED_SESSION_ID_TABLE`] 预设名时
    /// 替换为预设字符集（如 `"HEX"` → `"0123456789ABCDEF"`），否则按字面字符串处理。
    /// 对应 proto `sessionIDTable=28`（Go `Config.SessionIDTable`）。
    pub session_id_table: String,
    /// sessionID 长度随机范围（from..=to）。`None` 或 `from<=0` 时
    /// [`Config::generate_session_id`] 退化为 UUID。
    /// 对应 proto `sessionIDLength=29`（Go `Config.SessionIDLength`）。
    pub session_id_length: Option<RangeConfig>,
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

    /// sessionID 字符集：命中预设名（如 `"HEX"`）则替换为字面值，否则返回原字符串。
    /// 空字符串返回空（[`Config::generate_session_id`] 会退化为 UUID）。
    /// 对应 Go `GetNormalizedSessionIDTable` 行为（proto conf 层替换，预设查表）。
    #[must_use]
    pub fn normalized_session_id_table(&self) -> &str {
        match lookup_predefined_session_id_table(&self.session_id_table) {
            Some(s) => s,
            None => &self.session_id_table,
        }
    }

    /// sessionID 长度随机范围。`None` 或 `from<=0` 返回 `{0,0}`，
    /// 让 [`Config::generate_session_id`] 的 `length > 0` 分支失败，退化到 UUID。
    /// 对应 Go `GetNormalizedSessionIDLength`（proto nil → {0,0}）。
    #[must_use]
    pub fn normalized_session_id_length(&self) -> RangeConfig {
        match self.session_id_length {
            Some(r) if r.from > 0 => r,
            _ => RangeConfig { from: 0, to: 0 },
        }
    }

    /// 生成 sessionID。对应 Go `Config.GenerateSessionID()`（config.go:506-522）。
    ///
    /// 行为：
    /// - 若 `normalized_session_id_table` 非空 **且** `normalized_session_id_length.from > 0`：
    ///   从字符集随机取 `length` 字节（length 在 `[from, to]` 范围内随机）。
    /// - 否则：返回标准 UUID 字符串（与现有 XHTTP 默认行为兼容）。
    ///
    /// 注意：stream-one 模式下 Go 端直接跳过 `GenerateSessionID`（`sessionId = ""`），
    /// 本方法不做此判定，由调用方负责（`dialer::dial` 的 stream-one 分支传 `String::new()`）。
    #[must_use]
    pub fn generate_session_id(&self) -> String {
        let table = self.normalized_session_id_table();
        let length_cfg = self.normalized_session_id_length();
        let length = length_cfg.rand();
        if !table.is_empty() && length > 0 {
            let table_bytes = table.as_bytes();
            let mut buf = vec![0u8; length as usize];
            let mut rng = rand::rng();
            for b in &mut buf {
                *b = table_bytes[rng.random_range(0..table_bytes.len())];
            }
            // SAFETY: 所有随机字节来自 ASCII 字符集（按 conf 层校验过），UTF-8 安全。
            String::from_utf8(buf).unwrap_or_default()
        } else {
            uuid::Uuid::new_v4().to_string()
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
            session_id_table: p.session_id_table,
            session_id_length: p.session_id_length.map(range_from_proto),
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
            session_id_table: self.session_id_table.clone(),
            session_id_length: self.session_id_length.map(range_to_proto),
        }
    }
}

// ===== Request 元数据（client.rs 用于构造 hyper::Request） =====

/// 构造好的 HTTP 请求元数据：method + uri + headers + cookies + body。
///
/// 由 [`Config::build_packet_request_meta`] / [`Config::build_stream_request_meta`] 输出，
/// `client.rs` 转换为 `hyper::Request<B>` 发送。与 Go 直接操作 `*http.Request` 不同，
/// Rust 端以值传递 + 值聚合，避免生命周期耦合。
#[derive(Debug, Clone)]
pub struct RequestMeta {
    /// HTTP method（`POST` / `GET` / `PUT` 等）。
    pub method: String,
    /// 完整请求 URL（`scheme://host/path[?query]`，已含 session/seq 注入）。
    pub uri: String,
    /// 请求 header 列表（name, value）。含默认 User-Agent + 自定义 + session/seq/padding。
    pub headers: Vec<(String, String)>,
    /// Cookie 列表（name, value）。调用方需合并为单个 `Cookie:` header。
    pub cookies: Vec<(String, String)>,
    /// 请求 body（packet-up / stream-up 有；GET stream-down 为 None）。
    pub body: Option<Vec<u8>>,
}

impl Config {
    /// 默认请求 header 列表：复制 `c.headers` + 浏览器伪装默认头。
    ///
    /// 对应 Go 26.7.28 `GetRequestHeader` → `utils.TryDefaultHeadersWith(header, "fetch")`：
    /// UA 未配置 → 整套 Chrome 伪装头；UA 为 chrome/firefox/safari/edge/curl/golang
    /// → 对应伪装；其他自定义值 → 原样保留。见 [`crate::browser`]。
    #[must_use]
    pub fn get_request_header(&self) -> Vec<(String, String)> {
        let mut headers: Vec<(String, String)> =
            self.headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        // 对齐 Go 26.7.28 `GetRequestHeader`：UA 缺省时生成整套 Chrome 伪装头
        // （`utils.TryDefaultHeadersWith(header, "fetch")`），过 CDN bot 检测。
        crate::browser::try_default_headers_with(&mut headers, "fetch");
        headers
    }

    /// 计算 CORS 响应 header。对应 Go `Config.WriteResponseHeader`。
    ///
    /// 在 hub 侧对**每个**响应调用，把返回的 `(name, value)` 对追加到响应 header。
    ///
    /// 逻辑：
    /// - 请求无 `Origin` header → `Access-Control-Allow-Origin: *`
    /// - 有 `Origin` → 回显该 origin（浏览器 dialer credentials 模式要求）
    /// - session/seq/xpadding/uplink_data 任一 placement 为 cookie →
    ///   `Access-Control-Allow-Credentials: true`
    /// - `OPTIONS` preflight → 追加 `Access-Control-Allow-Methods` /
    ///   `Access-Control-Allow-Headers`（从请求的对应 header 取，缺失用 `*`）
    #[must_use]
    pub fn write_response_header(
        &self,
        request_method: &str,
        request_headers: &http::HeaderMap,
    ) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let origin = header_get(request_headers, "origin");
        if origin.is_empty() {
            out.push(("Access-Control-Allow-Origin".into(), "*".into()));
        } else {
            out.push(("Access-Control-Allow-Origin".into(), origin));
        }
        if self.normalized_session_placement() == PLACEMENT_COOKIE
            || self.normalized_seq_placement() == PLACEMENT_COOKIE
            || self.x_padding_placement == PLACEMENT_COOKIE
            || self.normalized_uplink_data_placement() == PLACEMENT_COOKIE
        {
            out.push(("Access-Control-Allow-Credentials".into(), "true".into()));
        }
        if request_method == "OPTIONS" {
            let req_method = header_get(request_headers, "access-control-request-method");
            out.push((
                "Access-Control-Allow-Methods".into(),
                if req_method.is_empty() { "*".into() } else { req_method },
            ));
            let req_headers = header_get(request_headers, "access-control-request-headers");
            out.push((
                "Access-Control-Allow-Headers".into(),
                if req_headers.is_empty() { "*".into() } else { req_headers },
            ));
        }
        out
    }

    /// XPadding 字节范围。None 或 `to=0` 返回默认 `100..=1000`。
    ///
    /// 对应 Go `GetNormalizedXPaddingBytes`。
    #[must_use]
    pub fn get_normalized_x_padding_bytes(&self) -> RangeConfig {
        match self.x_padding_bytes {
            Some(r) if r.to != 0 => r,
            _ => RangeConfig { from: 100, to: 1000 },
        }
    }

    /// 构造 XPaddingConfig。采样 padding 长度 + 根据 `x_padding_obfs_mode` 选择 placement。
    ///
    /// `obfs_mode = false`（默认）：placement=queryInHeader, header=Referer, key=x_padding（与切片 A 行为对齐，但 length 由硬编码 0 改为随机）。
    /// `obfs_mode = true`：placement/key/header 来自 config 字段，空时用默认。
    #[must_use]
    pub(crate) fn build_xpadding_config(&self, base_uri: &str) -> XPaddingConfig {
        let range = self.get_normalized_x_padding_bytes();
        let length = if range.from >= range.to {
            range.from
        } else {
            rand::rng().random_range(range.from..=range.to)
        };
        if self.x_padding_obfs_mode {
            XPaddingConfig {
                length,
                placement: XPaddingPlacement {
                    placement: if self.x_padding_placement.is_empty() {
                        PLACEMENT_QUERY_IN_HEADER.to_string()
                    } else {
                        self.x_padding_placement.clone()
                    },
                    key: if self.x_padding_key.is_empty() {
                        "x_padding".to_string()
                    } else {
                        self.x_padding_key.clone()
                    },
                    header: if self.x_padding_header.is_empty() {
                        "Referer".to_string()
                    } else {
                        self.x_padding_header.clone()
                    },
                    raw_url: base_uri.to_string(),
                },
                method: if self.x_padding_method.is_empty() {
                    PADDING_METHOD_REPEAT_X.to_string()
                } else {
                    self.x_padding_method.clone()
                },
            }
        } else {
            XPaddingConfig {
                length,
                placement: XPaddingPlacement {
                    placement: PLACEMENT_QUERY_IN_HEADER.into(),
                    key: "x_padding".into(),
                    header: "Referer".into(),
                    raw_url: base_uri.into(),
                },
                method: PADDING_METHOD_REPEAT_X.into(),
            }
        }
    }

    /// 根据 placement 策略注入 `session_id` / `seq_str` 到 `uri` / `headers` / `cookies`。
    ///
    /// 返回 `(final_uri, extra_headers, extra_cookies)`。
    /// 对应 Go `ApplyMetaToRequest`（session_id / seq_str 为空表示跳过对应字段）。
    ///
    /// 默认 placement：session_id 与 seq_str 都在 URL path（`/ws/{session}/{seq}`）,
    /// 与 Go `Xray-core` 默认一致。
    pub fn apply_meta_to_uri(
        &self,
        mut uri: String,
        session_id: &str,
        seq_str: &str,
    ) -> (String, Vec<(String, String)>, Vec<(String, String)>) {
        let session_placement = self.normalized_session_placement();
        let seq_placement = self.normalized_seq_placement();
        let session_key = self.normalized_session_key();
        let seq_key = self.normalized_seq_key();
        let mut extra_headers: Vec<(String, String)> = Vec::new();
        let mut extra_cookies: Vec<(String, String)> = Vec::new();

        if !session_id.is_empty() {
            match session_placement {
                PLACEMENT_PATH => uri = Self::append_to_path(&uri, session_id),
                PLACEMENT_QUERY => uri = uri_append_query(&uri, session_key, session_id),
                PLACEMENT_HEADER => {
                    extra_headers.push((session_key.to_string(), session_id.to_string()));
                }
                PLACEMENT_COOKIE => {
                    extra_cookies.push((session_key.to_string(), session_id.to_string()));
                }
                _ => {}
            }
        }
        if !seq_str.is_empty() {
            match seq_placement {
                PLACEMENT_PATH => uri = Self::append_to_path(&uri, seq_str),
                PLACEMENT_QUERY => uri = uri_append_query(&uri, seq_key, seq_str),
                PLACEMENT_HEADER => {
                    extra_headers.push((seq_key.to_string(), seq_str.to_string()));
                }
                PLACEMENT_COOKIE => {
                    extra_cookies.push((seq_key.to_string(), seq_str.to_string()));
                }
                _ => {}
            }
        }
        (uri, extra_headers, extra_cookies)
    }

    /// 构造 packet-up mode 的 POST 请求元数据。
    ///
    /// `base_uri` 应为完整 URL（`scheme://host/path`，不含 session/seq）。
    /// 切片 A padding 简化：硬编码 `x_padding=0` 写入 Referer header
    /// （对齐 minidialer 默认行为）。切片 B 接入完整 XPadding 后由 padding 模块注入。
    ///
    /// # Errors
    /// - [`SplitHttpError::InvalidPlacement`]: session/seq/uplink_data placement 值非合法常量
    pub fn build_packet_request_meta(
        &self,
        base_uri: &str,
        session_id: &str,
        seq_str: &str,
        payload: Vec<u8>,
    ) -> Result<RequestMeta> {
        let mut headers = self.get_request_header();

        let (uri, meta_headers, meta_cookies) =
            self.apply_meta_to_uri(base_uri.to_string(), session_id, seq_str);
        headers.extend(meta_headers);

        let mut meta = RequestMeta {
            method: self.normalized_uplink_http_method().to_string(),
            uri,
            headers,
            cookies: meta_cookies,
            body: Some(payload),
        };
        let xpad = self.build_xpadding_config(base_uri);
        apply_xpadding_to_request_meta(&mut meta, &xpad);
        Ok(meta)
    }

    /// 构造 stream-up / stream-one / stream-down mode 的请求元数据。
    ///
    /// - `body = None` → GET（stream-down，下载流）
    /// - `body = Some` → method = `normalized_uplink_http_method`（stream-up/one，上传流）
    ///
    /// stream-up/one 时设 `Content-Type: application/grpc`（除非 `no_grpc_header=true`）。
    ///
    /// # Errors
    /// - [`SplitHttpError::InvalidPlacement`]: session placement 值非合法常量
    pub fn build_stream_request_meta(
        &self,
        base_uri: &str,
        session_id: &str,
        body: Option<Vec<u8>>,
    ) -> Result<RequestMeta> {
        let mut headers = self.get_request_header();

        let (uri, meta_headers, meta_cookies) =
            self.apply_meta_to_uri(base_uri.to_string(), session_id, "");
        headers.extend(meta_headers);

        let has_body = body.is_some();
        if has_body && !self.no_grpc_header {
            headers.push(("Content-Type".to_string(), "application/grpc".to_string()));
        }

        let method = if has_body {
            self.normalized_uplink_http_method().to_string()
        } else {
            "GET".to_string()
        };
        let mut meta = RequestMeta {
            method,
            uri,
            headers,
            cookies: meta_cookies,
            body,
        };
        let xpad = self.build_xpadding_config(base_uri);
        apply_xpadding_to_request_meta(&mut meta, &xpad);
        Ok(meta)
    }
}

/// URL query 追加 helper：`uri` 已含 `?` 用 `&` 连接，否则补 `?`。
pub(crate) fn uri_append_query(uri: &str, key: &str, value: &str) -> String {
    if uri.contains('?') {
        format!("{uri}&{key}={value}")
    } else {
        format!("{uri}?{key}={value}")
    }
}

/// 从 `http::HeaderMap` 按名称取值（不区分大小写），缺失返回空串。
fn header_get(headers: &http::HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
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
    fn range_rand_returns_value_in_range() {
        let r = RangeConfig::new(0, 100);
        for _ in 0..50 {
            let v = r.rand();
            assert!((0..=100).contains(&v), "rand() returned {v}, outside [0, 100]");
        }
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

    // ===== RequestMeta / fill_* =====

    #[test]
    fn get_request_header_default_masquerades_as_chrome() {
        let cfg = Config::default();
        let headers = cfg.get_request_header();
        let ua = headers
            .iter()
            .find(|(k, _)| k == "User-Agent")
            .map(|(_, v)| v.as_str())
            .expect("User-Agent must be set when headers empty");
        assert!(
            ua.contains("Chrome/") && ua.contains("Safari/537.36"),
            "default UA must masquerade as Chrome (Go 26.7.28 TryDefaultHeadersWith), got: {ua}"
        );
        assert!(
            headers.iter().any(|(k, v)| k == "Sec-Fetch-Mode" && v == "cors"),
            "fetch variant Sec-Fetch-Mode required"
        );
    }

    #[test]
    fn get_request_header_preserves_custom_user_agent() {
        let cfg = Config {
            headers: [("User-Agent".to_string(), "Chrome/123".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let headers = cfg.get_request_header();
        let ua = headers.iter().find(|(k, _)| k == "User-Agent");
        assert_eq!(ua, Some(&("User-Agent".to_string(), "Chrome/123".to_string())));
    }

    #[test]
    fn apply_meta_to_uri_default_path_path() {
        let cfg = Config::default();
        let (uri, h, c) = cfg.apply_meta_to_uri("https://h/ws".into(), "sess123", "5");
        assert_eq!(uri, "https://h/ws/sess123/5");
        assert!(h.is_empty());
        assert!(c.is_empty());
    }

    #[test]
    fn apply_meta_to_uri_query_query() {
        let cfg = Config {
            session_placement: "query".into(),
            seq_placement: "query".into(),
            ..Default::default()
        };
        let (uri, h, c) = cfg.apply_meta_to_uri("https://h/ws?x=1".into(), "sess123", "5");
        assert_eq!(uri, "https://h/ws?x=1&x_session=sess123&x_seq=5");
        assert!(h.is_empty());
        assert!(c.is_empty());
    }

    #[test]
    fn apply_meta_to_uri_header_header() {
        let cfg = Config {
            session_placement: "header".into(),
            seq_placement: "header".into(),
            ..Default::default()
        };
        let (uri, h, c) = cfg.apply_meta_to_uri("https://h/ws".into(), "sess123", "5");
        assert_eq!(uri, "https://h/ws");
        assert!(h.iter().any(|(k, v)| k == "X-Session" && v == "sess123"));
        assert!(h.iter().any(|(k, v)| k == "X-Seq" && v == "5"));
        assert!(c.is_empty());
    }

    #[test]
    fn apply_meta_to_uri_cookie_cookie() {
        let cfg = Config {
            session_placement: "cookie".into(),
            seq_placement: "cookie".into(),
            ..Default::default()
        };
        let (uri, h, c) = cfg.apply_meta_to_uri("https://h/ws".into(), "sess123", "5");
        assert_eq!(uri, "https://h/ws");
        assert!(h.is_empty());
        assert!(c.iter().any(|(k, v)| k == "x_session" && v == "sess123"));
        assert!(c.iter().any(|(k, v)| k == "x_seq" && v == "5"));
    }

    #[test]
    fn apply_meta_to_uri_skip_empty() {
        let cfg = Config::default();
        let (uri, h, c) = cfg.apply_meta_to_uri("https://h/ws".into(), "", "");
        assert_eq!(uri, "https://h/ws");
        assert!(h.is_empty());
        assert!(c.is_empty());
    }

    #[test]
    fn build_packet_request_meta_body_filled() {
        let cfg = Config {
            host: "example.com".into(),
            path: "/ws".into(),
            ..Default::default()
        };
        let meta = cfg
            .build_packet_request_meta("https://example.com/ws", "sess", "3", b"payload".to_vec())
            .unwrap();
        assert_eq!(meta.method, "POST");
        assert_eq!(meta.uri, "https://example.com/ws/sess/3");
        assert_eq!(meta.body.as_deref(), Some(&b"payload"[..]));
        // padding length 默认范围 [100, 1000]，采样后注入 Referer 的 x_padding query。
        // 由于长度随机，这里只验证 Referer 存在、url 前缀正确、x_padding 值非空。
        let referer = meta.headers.iter().find_map(|(k, v)| {
            if k == "Referer" { Some(v.clone()) } else { None }
        }).expect("Referer header must exist");
        assert!(referer.starts_with("https://example.com/ws?x_padding="), "referer={referer}");
        let pad_value = referer.strip_prefix("https://example.com/ws?x_padding=").unwrap();
        assert!(!pad_value.is_empty(), "padding value must be non-empty, got empty");
        assert!(pad_value.chars().all(|c| c == 'X'), "default repeat-x padding should be all X, got {pad_value}");
        let ua = meta
            .headers
            .iter()
            .find(|(k, _)| k == "User-Agent")
            .map(|(_, v)| v.as_str())
            .expect("User-Agent must be set");
        assert!(ua.contains("Chrome/"), "UA must masquerade as Chrome, got: {ua}");
    }

    #[test]
    fn build_stream_request_meta_get_when_no_body() {
        let cfg = Config::default();
        let meta = cfg
            .build_stream_request_meta("https://example.com/ws", "sess", None)
            .unwrap();
        assert_eq!(meta.method, "GET");
        assert!(meta.body.is_none());
        assert!(!meta.headers.iter().any(|(k, _)| k == "Content-Type"));
    }

    #[test]
    fn build_stream_request_meta_post_when_body() {
        let cfg = Config::default();
        let meta = cfg
            .build_stream_request_meta("https://example.com/ws", "sess", Some(b"hello".to_vec()))
            .unwrap();
        assert_eq!(meta.method, "POST");
        assert_eq!(meta.body.as_deref(), Some(&b"hello"[..]));
        assert!(meta
            .headers
            .iter()
            .any(|(k, v)| k == "Content-Type" && v == "application/grpc"));
    }

    #[test]
    fn build_stream_request_meta_no_grpc_header_skips_content_type() {
        let cfg = Config { no_grpc_header: true, ..Default::default() };
        let meta = cfg
            .build_stream_request_meta("https://example.com/ws", "sess", Some(b"hello".to_vec()))
            .unwrap();
        assert!(!meta.headers.iter().any(|(k, _)| k == "Content-Type"));
    }

    // ===== write_response_header (对应 Go WriteResponseHeader) =====

    fn assert_header(h: &[(String, String)], name: &str, value: &str) {
        let found = h.iter().find(|(k, _)| k == name);
        assert!(
            found.is_some(),
            "expected header {name} in {h:?}"
        );
        assert_eq!(found.unwrap().1, value, "header {name} value mismatch");
    }

    #[test]
    fn write_response_header_no_origin_returns_wildcard() {
        let cfg = Config::default();
        let headers = http::HeaderMap::new();
        let out = cfg.write_response_header("GET", &headers);
        assert_header(&out, "Access-Control-Allow-Origin", "*");
        // 无 cookie placement → 无 credentials
        assert!(!out.iter().any(|(k, _)| k == "Access-Control-Allow-Credentials"));
    }

    #[test]
    fn write_response_header_with_origin_echoes_origin() {
        let cfg = Config::default();
        let mut headers = http::HeaderMap::new();
        headers.insert("Origin", "https://evil.example".parse().unwrap());
        let out = cfg.write_response_header("GET", &headers);
        assert_header(&out, "Access-Control-Allow-Origin", "https://evil.example");
    }

    #[test]
    fn write_response_header_cookie_placement_adds_credentials() {
        let cfg = Config {
            session_placement: PLACEMENT_COOKIE.into(),
            ..Default::default()
        };
        let headers = http::HeaderMap::new();
        let out = cfg.write_response_header("GET", &headers);
        assert_header(&out, "Access-Control-Allow-Credentials", "true");
    }

    #[test]
    fn write_response_header_options_preflow_adds_methods_and_headers() {
        let cfg = Config::default();
        let mut headers = http::HeaderMap::new();
        headers.insert("Access-Control-Request-Method", "POST".parse().unwrap());
        headers.insert(
            "Access-Control-Request-Headers",
            "Content-Type".parse().unwrap(),
        );
        let out = cfg.write_response_header("OPTIONS", &headers);
        assert_header(&out, "Access-Control-Allow-Methods", "POST");
        assert_header(&out, "Access-Control-Allow-Headers", "Content-Type");
    }

    #[test]
    fn write_response_header_options_no_request_defaults_to_wildcard() {
        let cfg = Config::default();
        let headers = http::HeaderMap::new();
        let out = cfg.write_response_header("OPTIONS", &headers);
        assert_header(&out, "Access-Control-Allow-Methods", "*");
        assert_header(&out, "Access-Control-Allow-Headers", "*");
    }
    // ===== sessionIDTable / sessionIDLength / generate_session_id =====

    #[test]
    fn lookup_predefined_session_id_table_finds_all_named_alphabets() {
        // 9 个预设名必须全部命中（与 Go config.go:494-504 PredefinedTable 对齐）。
        for (name, expected) in [
            ("ALPHABET", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            ("Alphabet", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
            ("BASE36", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            ("Base62", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
            ("HEX", "0123456789ABCDEF"),
            ("alphabet", "abcdefghijklmnopqrstuvwxyz"),
            ("base36", "0123456789abcdefghijklmnopqrstuvwxyz"),
            ("hex", "0123456789abcdef"),
            ("number", "0123456789"),
        ] {
            assert_eq!(lookup_predefined_session_id_table(name), Some(expected));
        }
        assert_eq!(lookup_predefined_session_id_table(""), None);
        assert_eq!(lookup_predefined_session_id_table("nonexistent"), None);
    }

    #[test]
    fn normalized_session_id_table_resolves_predefined_passthrough_literal() {
        // 命中预设 → 返回字面值
        let cfg = Config { session_id_table: "HEX".into(), ..Default::default() };
        assert_eq!(cfg.normalized_session_id_table(), "0123456789ABCDEF");
        // 未命中 → 原样返回（用户自定义字符集）
        let cfg = Config { session_id_table: "abc123".into(), ..Default::default() };
        assert_eq!(cfg.normalized_session_id_table(), "abc123");
        // 空 → 空（fallback 到 UUID）
        assert_eq!(Config::default().normalized_session_id_table(), "");
    }

    #[test]
    fn normalized_session_id_length_defaults_to_zero_when_invalid() {
        // None / from<=0 / 缺失都退化为 {0,0}，让 generate_session_id fallback。
        assert_eq!(Config::default().normalized_session_id_length(), RangeConfig { from: 0, to: 0 });
        let cfg = Config { session_id_length: Some(RangeConfig::new(0, 8)), ..Default::default() };
        assert_eq!(cfg.normalized_session_id_length(), RangeConfig { from: 0, to: 0 });
        let cfg = Config { session_id_length: Some(RangeConfig::new(-5, 8)), ..Default::default() };
        assert_eq!(cfg.normalized_session_id_length(), RangeConfig { from: 0, to: 0 });
        // from>0 → 原样
        let cfg = Config { session_id_length: Some(RangeConfig::new(8, 16)), ..Default::default() };
        assert_eq!(cfg.normalized_session_id_length(), RangeConfig { from: 8, to: 16 });
    }

    #[test]
    fn generate_session_id_no_table_returns_uuid() {
        // 向后兼容：未配置 table/length 时返回 UUID 字符串。
        let cfg = Config::default();
        let id = cfg.generate_session_id();
        let parsed = uuid::Uuid::parse_str(&id).expect("must be valid UUID");
        assert_eq!(parsed.get_version_num(), 4);
    }

    #[test]
    fn generate_session_id_custom_table_returns_chars_in_table_with_length() {
        // 有 table + length>0：每次返回的字符串每个字节必须是 table 成员，且长度 == length_cfg.rand()。
        let cfg = Config {
            session_id_table: "ABC".into(), // 字面值字符集
            session_id_length: Some(RangeConfig::new(8, 8)), // 固定 length=8
            ..Default::default()
        };
        for _ in 0..20 {
            let id = cfg.generate_session_id();
            assert_eq!(id.len(), 8, "expected len=8, got {id:?}");
            for c in id.chars() {
                assert!(matches!(c, 'A' | 'B' | 'C'), "char {c:?} not in table");
            }
        }
    }

    #[test]
    fn generate_session_id_predefined_hex_returns_hex_chars_with_length() {
        // 预设名 "HEX" → 字面值 "0123456789ABCDEF"，length=12。
        let cfg = Config {
            session_id_table: "HEX".into(),
            session_id_length: Some(RangeConfig::new(12, 12)),
            ..Default::default()
        };
        let id = cfg.generate_session_id();
        assert_eq!(id.len(), 12);
        for c in id.chars() {
            assert!(matches!(c, '0'..='9' | 'A'..='F'), "char {c:?} not in HEX");
        }
    }

    #[test]
    fn generate_session_id_length_without_table_falls_back_to_uuid() {
        // 只有 length 没有 table → fallback UUID（Go 行为：table=="" 时走 else 分支）。
        let cfg = Config {
            session_id_length: Some(RangeConfig::new(8, 8)),
            ..Default::default()
        };
        let id = cfg.generate_session_id();
        assert!(uuid::Uuid::parse_str(&id).is_ok(), "expected UUID, got {id:?}");
    }

    #[test]
    fn proto_roundtrip_preserves_session_id_fields() {
        // from_proto → to_proto → from_proto 必须保持字段一致。
        let cfg = Config {
            session_id_table: "HEX".into(),
            session_id_length: Some(RangeConfig::new(16, 32)),
            ..Default::default()
        };
        let proto = cfg.to_proto();
        assert_eq!(proto.session_id_table, "HEX");
        assert_eq!(proto.session_id_length.as_ref().unwrap().from, 16);
        assert_eq!(proto.session_id_length.as_ref().unwrap().to, 32);
        let cfg2 = Config::from_proto(proto).expect("from_proto");
        assert_eq!(cfg2.session_id_table, "HEX");
        assert_eq!(cfg2.session_id_length, Some(RangeConfig::new(16, 32)));
        // 整 struct round-trip 不要求相等（其他字段非覆盖项不必全一致），仅断言本字段。
    }
}
