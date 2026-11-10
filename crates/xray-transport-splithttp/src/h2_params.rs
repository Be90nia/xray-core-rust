//! 服务端 HTTP/2 参数：Go `net/http.HTTP2Config` 的 Rust 映射（proto `splithttp.h2Params`）。
//!
//! 语义源 = Go `transport/internet/splithttp/hub.go:559-565`（tcp/unix 分支）：
//! `json.Unmarshal(h2Params, &http.HTTP2Config{})`，失败即**启动失败**
//! （`failed to parse HTTP2Config`），成功则整份塞进 `http.Server{HTTP2: cfg}`。
//! JSON 面形态 = `infra/conf/transport_method.go:296/:499`：conf 层是
//! `json.RawMessage`，**原样 JSON 字节**进 proto `bytes`（不是 base64）。
//!
//! 三条纪律：
//! 1. `h2Params` 缺省 / `null` ⇒ [`H2Params::parse`] 返回 `None` ⇒ 调用方**零 setter**，
//!    默认行为与接线前逐字节一致（性能红线，见 `transport::serve_http_conn` /
//!    `hub::HubListener::serve` 的 `if let Some(p) = &ctx.h2_params` 门）。
//! 2. 值域照 Go `x/net/http2.setConfigDefaults`：越界/零值 ⇒ **回退默认**（不调 setter），
//!    不是硬错。此处「默认」= 本项目既有默认（窗 16MB/32MB、45s keep-alive 等，见 bd
//!    wz2b/xzg3x/rjzw2），**不是** Go 归一化后的 1MB 窗——否则用户随手写个越界值
//!    就会把本仓调优值打回 Go 缺省。
//! 3. Go 有该字段、但 Rust 无等价旋钮 ⇒ **接受 + 启动期一次 WARN（不应用）**。 Go
//!    配置兼容铁律优先：这四类在 Go 侧是**合法配置**，硬错会把「Go 能跑的
//!    config.json」变成本仓拒启（比行为差异更糟）。硬错只留「Go 自己也拒」的面： JSON 语法错 /
//!    非对象 / 已知字段字面类型错 / `CountError` 非 null。
//!
//! 字段映射（Go `http.HTTP2Config` → Rust）：
//!
//! | Go 字段 | Rust | 判定 |
//! |---|---|---|
//! | `MaxConcurrentStreams` | `max_concurrent_streams` | 非零生效（Go 零值 ⇒ 250） |
//! | `MaxReadFrameSize` | `max_frame_size` | 16KiB..=16777215 生效（Go 同区间） |
//! | `MaxReceiveBufferPerConnection` | `initial_connection_window_size` | 65535..=i32::MAX 生效 |
//! | `MaxReceiveBufferPerStream` | `initial_stream_window_size` | 1..=i32::MAX 生效 |
//! | `SendPingTimeout` | `keep_alive_interval` | >0 生效（0 = Go 侧不探活） |
//! | `PingTimeout` | `keep_alive_timeout` | >0 生效 |
//! | `StrictMaxConcurrentRequests` | — | 接受并忽略：Go 注释「only applies to Transports」，服务端无效果 |
//! | `MaxDecoderHeaderTableSize` / `MaxEncoderHeaderTableSize` | — | 非零 ⇒ 接受 + WARN（未应用）：hyper-util `Http2Builder` 无 HPACK 表旋钮（hyper 1.10 有 `header_table_size`，`auto::Builder` 未代理） |
//! | `WriteByteTimeout` | — | 非零 ⇒ 接受 + WARN（未应用）：h2 无写超时旋钮 |
//! | `PermitProhibitedCipherSuites` | — | `true` ⇒ 接受 + WARN（未应用）：TLS 栈（rustls）不协商 RFC 7540 禁止套件 |
//! | `CountError` | — | `null` ⇒ 忽略；非 null ⇒ 硬错（Go 侧非 null 亦 unmarshal 失败） |
//!
//! 未知键忽略（Go `encoding/json` 忽略未匹配键）；键名大小写不敏感（同 Go）；
//! 字面类型错（如 `"maxConcurrentStreams": "100"`）⇒ 硬错（同 Go）。

use std::time::Duration;

use crate::error::{Result, SplitHttpError};

/// 服务端可映射的 h2 旋钮集合；`None` 字段 = 不触碰（保留既有默认）。
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct H2Params {
    /// ← `MaxConcurrentStreams`
    pub(crate) max_concurrent_streams: Option<u32>,
    /// ← `MaxReadFrameSize`
    pub(crate) max_frame_size: Option<u32>,
    /// ← `MaxReceiveBufferPerConnection`
    pub(crate) initial_connection_window: Option<u32>,
    /// ← `MaxReceiveBufferPerStream`
    pub(crate) initial_stream_window: Option<u32>,
    /// ← `SendPingTimeout`
    pub(crate) keep_alive_interval: Option<Duration>,
    /// ← `PingTimeout`
    pub(crate) keep_alive_timeout: Option<Duration>,
}

/// Go `x/net/http2` 的帧长合法区间（`minMaxFrameSize`/`maxFrameSize`）。
const MIN_MAX_FRAME_SIZE: i64 = 16_384;
const MAX_MAX_FRAME_SIZE: i64 = 16_777_215;
/// HTTP/2 流控窗上限（Go 经 `int32` 约束）。
const MAX_WINDOW: i64 = i32::MAX as i64;

impl H2Params {
    /// 解析 `h2Params` 原始 JSON 字节。
    ///
    /// # Errors
    /// - JSON 语法错 / 非对象（Go `json.Unmarshal` 同样报错 ⇒ 启动失败）
    /// - 已知字段字面类型错
    /// - 已知字段在 Rust 无等价旋钮且该值在 Go 侧会生效（见模块文档映射表）
    pub(crate) fn parse(bytes: &[u8]) -> Result<Option<Self>> {
        if bytes.is_empty() {
            return Ok(None);
        }
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|e| invalid(format!("h2Params: invalid JSON: {e}")))?;
        // `null` = Go 侧 `json.Unmarshal("null", &HTTP2Config{})` 的 no-op ⇒ 等同未配置。
        let serde_json::Value::Object(obj) = value else {
            return match value {
                serde_json::Value::Null => Ok(None),
                other => Err(invalid(format!(
                    "h2Params must be a JSON object (Go http.HTTP2Config), got {}",
                    json_kind(&other)
                ))),
            };
        };

        let mut params = Self::default();
        for (key, raw) in &obj {
            // Go encoding/json 键名大小写不敏感。
            match key.to_ascii_lowercase().as_str() {
                "maxconcurrentstreams" => {
                    let n = int(raw, key)?;
                    // Go `uint32(...)` 截断；零值 = 未配置（Go 回退默认 250）。
                    if n != 0 {
                        params.max_concurrent_streams = Some(n as u32);
                    }
                },
                "maxreadframesize" => {
                    let n = int(raw, key)?;
                    if (MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&n) {
                        params.max_frame_size = Some(n as u32);
                    }
                },
                "maxreceivebufferperconnection" => {
                    let n = int(raw, key)?;
                    if (65_535..=MAX_WINDOW).contains(&n) {
                        params.initial_connection_window = Some(n as u32);
                    }
                },
                "maxreceivebufferperstream" => {
                    let n = int(raw, key)?;
                    if (1..=MAX_WINDOW).contains(&n) {
                        params.initial_stream_window = Some(n as u32);
                    }
                },
                "sendpingtimeout" => {
                    let n = int(raw, key)?;
                    if n > 0 {
                        params.keep_alive_interval = Some(Duration::from_nanos(n as u64));
                    }
                },
                "pingtimeout" => {
                    let n = int(raw, key)?;
                    if n > 0 {
                        params.keep_alive_timeout = Some(Duration::from_nanos(n as u64));
                    }
                },
                // Go 注释：仅对 Transport 生效，服务端无效果 ⇒ 接受并忽略（与 Go 同）。
                "strictmaxconcurrentrequests" => {
                    bool_of(raw, key)?;
                },
                // 以下四项 Go 侧会真实生效，但 Rust 无等价旋钮 ⇒ 接受 + WARN（未应用）。
                "maxdecoderheadertablesize" => unsupported(int(raw, key)?, key),
                "maxencoderheadertablesize" => unsupported(int(raw, key)?, key),
                "writebytetimeout" => unsupported(int(raw, key)?, key),
                "permitprohibitedciphersuites" => {
                    if bool_of(raw, key)? {
                        crate::LOG.warn(format!(
                            "h2Params.{key}=true not applied: rustls never negotiates HTTP/2 \
                             prohibited cipher suites"
                        ));
                    }
                },
                // Go 的 `CountError` 是 func：`null` ⇒ nil（无效果）；非 null ⇒ Go 的
                // `json.Unmarshal` 同样失败 ⇒ 同 Go 硬错。
                "counterror" if !raw.is_null() => {
                    return Err(invalid(
                        "h2Params.countError is unsupported: it is a Go callback \
                         (JSON cannot carry it; Go also rejects a non-null value)",
                    ));
                },
                "counterror" => {},
                // Go encoding/json 忽略未匹配键 ⇒ 同（含 Go 后续版本新增字段）。
                _ => {},
            }
        }
        Ok(Some(params))
    }

    /// 把已映射的旋钮写进 hyper `auto::Builder` 的 h2 面。
    ///
    /// 只写 `Some` 项：`h2Params` 缺省、`null`、或全部值越界时**零 setter 调用**。
    pub(crate) fn apply(
        &self,
        http2: &mut hyper_util::server::conn::auto::Http2Builder<'_, hyper_util::rt::TokioExecutor>,
    ) {
        if let Some(v) = self.max_concurrent_streams {
            http2.max_concurrent_streams(v);
        }
        if let Some(v) = self.max_frame_size {
            http2.max_frame_size(v);
        }
        if let Some(v) = self.initial_connection_window {
            http2.initial_connection_window_size(v);
        }
        if let Some(v) = self.initial_stream_window {
            http2.initial_stream_window_size(v);
        }
        if let Some(v) = self.keep_alive_interval {
            http2.keep_alive_interval(v);
        }
        if let Some(v) = self.keep_alive_timeout {
            http2.keep_alive_timeout(v);
        }
    }
}

fn invalid(msg: impl Into<String>) -> SplitHttpError {
    SplitHttpError::InvalidConfig(msg.into())
}

/// Go 侧该字段为 int64（`time.Duration` 亦 int64 纳秒）；非整数/溢出 ⇒ 同 Go 报错。
fn int(raw: &serde_json::Value, key: &str) -> Result<i64> {
    raw.as_i64().ok_or_else(|| {
        invalid(format!("h2Params.{key} must be an integer, got {}", json_kind(raw)))
    })
}

fn bool_of(raw: &serde_json::Value, key: &str) -> Result<bool> {
    raw.as_bool()
        .ok_or_else(|| invalid(format!("h2Params.{key} must be a boolean, got {}", json_kind(raw))))
}

/// 已知字段但 Rust 无等价旋钮：**接受 + 启动期一次 WARN**（不应用）。
///
/// 不硬错的依据 = Go 配置兼容铁律：该值在 Go 侧是合法配置，拒启会把「Go 能跑的
/// config.json」变成本仓跑不起来。值在 Go 侧本就不生效（零/负）⇒ 不吵。
/// 本函数每次 listener 启动只跑一次（`parse` 在 listener 构造期调用），故 WARN 天然不重复。
fn unsupported(value: i64, key: &str) {
    if value > 0 {
        crate::LOG.warn(format!(
            "h2Params.{key}={value} not applied: hyper's server-side HTTP/2 builder exposes no \
             equivalent knob (remaining h2Params fields still apply)"
        ));
    }
}

fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_null_are_unset() {
        assert_eq!(H2Params::parse(b"").ok().flatten(), None);
        assert_eq!(H2Params::parse(b"null").ok().flatten(), None);
        // `{}` ⇒ Some(全 None)：结构上可解析，但 apply 零 setter（同未配置）。
        assert_eq!(H2Params::parse(b"{}").ok().flatten(), Some(H2Params::default()));
    }

    #[test]
    fn mapped_fields_land_on_knobs() {
        let p = H2Params::parse(
            br#"{
                "maxConcurrentStreams": 100,
                "maxReadFrameSize": 1048576,
                "maxReceiveBufferPerConnection": 4194304,
                "maxReceiveBufferPerStream": 1048576,
                "sendPingTimeout": 30000000000,
                "pingTimeout": 15000000000,
                "strictMaxConcurrentRequests": true
            }"#,
        )
        .expect("valid")
        .expect("configured");
        assert_eq!(p.max_concurrent_streams, Some(100));
        assert_eq!(p.max_frame_size, Some(1_048_576));
        assert_eq!(p.initial_connection_window, Some(4_194_304));
        assert_eq!(p.initial_stream_window, Some(1_048_576));
        assert_eq!(p.keep_alive_interval, Some(Duration::from_secs(30)));
        assert_eq!(p.keep_alive_timeout, Some(Duration::from_secs(15)));
    }

    #[test]
    fn out_of_range_falls_back_to_default() {
        // 全部越界/零 ⇒ 不调用任何 setter（保留本项目既有默认）。
        let p = H2Params::parse(
            br#"{
                "maxConcurrentStreams": 0,
                "maxReadFrameSize": 16383,
                "maxReceiveBufferPerConnection": 65534,
                "maxReceiveBufferPerStream": 0,
                "sendPingTimeout": 0,
                "pingTimeout": -5
            }"#,
        )
        .expect("valid")
        .expect("configured");
        assert_eq!(p, H2Params::default());
        // 上界外同样回退（frame size 上界 = 16777215）。
        let p = H2Params::parse(br#"{"maxReadFrameSize": 16777216}"#)
            .expect("valid")
            .expect("configured");
        assert_eq!(p.max_frame_size, None);
    }

    #[test]
    fn unknown_keys_ignored_and_case_insensitive() {
        let p = H2Params::parse(br#"{"foo": 1, "MaxConcurrentStreams": 7}"#)
            .expect("Go 忽略未知键，键名大小写不敏感")
            .expect("configured");
        assert_eq!(p.max_concurrent_streams, Some(7));
    }

    /// Go 合法但本仓无等价旋钮 ⇒ 接受（Go 配置兼容铁律）+ WARN，不拒启；字段不落地。
    #[test]
    fn unsupported_known_fields_accepted_with_warning() {
        for json in [
            br#"{"maxDecoderHeaderTableSize": 4096}"#.as_slice(),
            br#"{"maxEncoderHeaderTableSize": 4096}"#.as_slice(),
            br#"{"writeByteTimeout": 5000000000}"#.as_slice(),
            br#"{"permitProhibitedCipherSuites": true}"#.as_slice(),
        ] {
            let p = H2Params::parse(json).expect("Go 合法配置不得拒启").expect("已配置");
            assert_eq!(p, H2Params::default(), "未应用项不得落进旋钮");
        }
        // 混合：不支持的字段只被跳过，其余照常生效。
        let p = H2Params::parse(br#"{"writeByteTimeout": 5000000000, "maxConcurrentStreams": 42}"#)
            .expect("ok")
            .expect("configured");
        assert_eq!(p.max_concurrent_streams, Some(42));
        assert_eq!(p.max_frame_size, None);

        // Go 自己会拒的面仍硬错：`countError` 非 null（func 字段）。
        let err = H2Params::parse(br#"{"countError": "x"}"#).expect_err("必须硬错");
        assert!(err.to_string().contains("h2Params."), "错误必须指出字段名: {err}");
        // 零值/负值在 Go 侧不生效 ⇒ 容忍；`countError: null` 同 Go 的 nil。
        assert!(H2Params::parse(br#"{"maxDecoderHeaderTableSize": 0}"#).is_ok());
        assert!(H2Params::parse(br#"{"writeByteTimeout": -1}"#).is_ok());
        assert!(H2Params::parse(br#"{"countError": null}"#).is_ok());
        assert!(H2Params::parse(br#"{"permitProhibitedCipherSuites": false}"#).is_ok());
    }

    #[test]
    fn malformed_inputs_error_like_go() {
        for json in [
            b"{".as_slice(),                                // JSON 语法错（Go 亦启动失败）
            b"5".as_slice(),                                // 非对象
            br#"[1]"#.as_slice(),                           // 非对象
            br#"{"maxConcurrentStreams": "1"}"#.as_slice(), // 字面类型错
            br#"{"sendPingTimeout": 1.5}"#.as_slice(),      // Go int64 不收浮点
        ] {
            assert!(H2Params::parse(json).is_err(), "必须硬错: {}", String::from_utf8_lossy(json));
        }
    }

    /// 旋钮值不可读 ⇒ 在应用函数上做冒烟：合法参数可写进真实 builder（不 panic）。
    #[test]
    fn apply_writes_mapped_knobs() {
        let mut builder =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        let p = H2Params::parse(
            br#"{"maxConcurrentStreams": 100, "maxReadFrameSize": 1048576,
                 "maxReceiveBufferPerConnection": 4194304, "maxReceiveBufferPerStream": 1048576,
                 "sendPingTimeout": 30000000000, "pingTimeout": 15000000000}"#,
        )
        .expect("valid")
        .expect("configured");
        p.apply(&mut builder.http2());
        // 未配置路径（None）由调用方 `if let Some` 门保证零 setter。
        let none_builder =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        assert!(H2Params::parse(b"").expect("ok").is_none());
        drop(none_builder);
    }
}
