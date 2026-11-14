//! Blackhole 响应配置
//!
//! 对应 Go 版本 `proxy/blackhole/config.go`。
//! Go 01a034be 起用 `Response{type, custom_response_data}` 表达三种行为：
//! "无响应"/"回写 HTTP 403"/"回写自定义数据"；Rust 端是有限、封闭的枚举
//! [`ResponseConfig`]，用 `enum` 表达更地道，且免除了 `dyn` 与 async-trait 的对象安全约束。

use std::{future::Future, pin::Pin};

use base64::Engine as _;
use xray_buf::io::{self, Writer};
use xray_proto::xray::proxy::blackhole::Config;

use crate::BlackholeError;

/// 预置 HTTP 403 响应，与 Go v26.9.9 `http403response.Write(&data)` 输出**逐字节对齐**
/// （101 字节：CRLF 行末、Header 字典序、`Content-Length: 0`、头后单个空行）。
///
/// 对应 Go `proxy/blackhole/blackhole.go` `http403response`（01a034be 起）。
pub const HTTP_403_RESPONSE: &str = "HTTP/1.1 403 Forbidden\r\n\
    Cache-Control: max-age=3600, public\r\n\
    Connection: close\r\n\
    Content-Length: 0\r\n\
    \r\n";

/// Blackhole 响应配置。
///
/// 对应 Go 01a034be `Handler.response []byte` 的三种来源：
/// - [`ResponseConfig::None`]：`type = "" / "none"`，不写任何数据；
/// - [`ResponseConfig::Http403`]：`type = "http"`，写序列化的 403 报文；
/// - [`ResponseConfig::Custom`]：`type = "custom"`，原样写 `customResponseData` 字节。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ResponseConfig {
    /// 不写入任何数据。默认值。
    #[default]
    None,
    /// 写入预置 HTTP 403 Forbidden 报文。
    Http403,
    /// 原样写自定义响应数据（可为空字节串 = 等价 None）。
    Custom(Vec<u8>),
}

impl ResponseConfig {
    /// Go `len(h.response) > 0`：是否需要写响应（并做 1s settle sleep）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            ResponseConfig::None => true,
            ResponseConfig::Http403 => false,
            ResponseConfig::Custom(data) => data.is_empty(),
        }
    }

    /// 把预置响应写入 `writer`，返回写入字节数。
    ///
    /// 对应 Go `Process` 中 `if len(h.response) > 0 { mbc.Write(h.response); ... }`。
    /// 返回 `i32` 以保持与旧 Go 签名一致。
    pub fn write_to<'a>(
        &'a self,
        writer: &'a mut dyn Writer,
    ) -> Pin<Box<dyn Future<Output = io::Result<i32>> + Send + 'a>> {
        let payload: Vec<u8> = match self {
            ResponseConfig::None => return Box::pin(async { Ok(0) }),
            ResponseConfig::Http403 => HTTP_403_RESPONSE.as_bytes().to_vec(),
            ResponseConfig::Custom(data) => data.clone(),
        };
        Box::pin(async move {
            let n = i32::try_from(payload.len()).map_err(|_| {
                io::Error::WriteError(format!(
                    "blackhole response too large for i32: {} bytes",
                    payload.len()
                ))
            })?;
            // 通过单一 Buffer 写入；MultiBuffer 仅承载一个 Buffer 即可表达 "one shot write"。
            // 容量按 payload 取块：custom_response_data 无长度上限，默认 8KB 块会静默
            // 少写而本函数仍按 payload.len() 回报写入量 ⇒ 线上短报文 + 计数说谎。
            let mut buf = xray_buf::buffer::Buffer::new_pooled(payload.len());
            let written = buf.write_from(&payload);
            assert_eq!(written, payload.len(), "blackhole 响应块按 payload 长度取块");
            let mb = xray_buf::multi::MultiBuffer::from_buffer(buf);
            writer.write_multi_buffer(mb).await?;
            Ok(n)
        })
    }
}

/// 把 protobuf [`Config`] 转换为内部 [`ResponseConfig`]。
///
/// 对应 Go 01a034be `New(ctx, config)` 的 `switch config.Response.Type`：
/// - `response` 缺省 / `type` 为 `""` 或 `"none"` → [`ResponseConfig::None`]
/// - `"http"` → [`ResponseConfig::Http403`]
/// - `"custom"` → [`ResponseConfig::Custom`]（原样携带 `custom_response_data`）
/// - 其它 → [`BlackholeError::UnknownResponseType`]
///
/// 与 Go 一致：运行时**精确匹配**，不做小写化/前缀剥离（那是 conf 层的事）。
pub fn get_internal_response(config: &Config) -> Result<ResponseConfig, BlackholeError> {
    let Some(resp) = config.response.as_ref() else {
        return Ok(ResponseConfig::None);
    };
    match resp.r#type.as_str() {
        "" | "none" => Ok(ResponseConfig::None),
        "http" => Ok(ResponseConfig::Http403),
        "custom" => Ok(ResponseConfig::Custom(resp.custom_response_data.clone())),
        other => Err(BlackholeError::UnknownResponseType(other.to_string())),
    }
}

/// conf 层 `settings.response` JSON → [`ResponseConfig`]（单份实现，三个解析面共用）。
///
/// 对齐 Go `infra/conf/blackhole.go:20-41` `BlackholeConfig.Build`：
/// - `type` **先 `strings.ToLower`**（`:24`），故 `"HTTP"`/`"Custom"` 与 Go 同判；
/// - `""`/`"none"` → [`ResponseConfig::None`]；`"http"` → [`ResponseConfig::Http403`]；
/// - `"custom"` → 标准表 base64 解码 `customResponseData`，解码失败即 Err（`:31-35`）；
/// - 其余 → Err（`:36-37` `unknown blackhole response`）：拼错的 type 必须拒启， 不得静默降级成
///   none（「以为配了拦截/回包，实际什么都没有」）。
///
/// `response` 段缺省 → [`ResponseConfig::None`]（Go `v.Response == nil`）。
pub fn response_config_from_json(
    response: Option<&serde_json::Value>,
) -> Result<ResponseConfig, String> {
    let Some(resp) = response else {
        return Ok(ResponseConfig::None);
    };
    let ty = resp.get("type").and_then(|t| t.as_str()).unwrap_or_default().to_ascii_lowercase();
    // Go 只在 custom 分支解码 base64（type=none 时 customResponseData 被忽略，不校验）。
    let data = if ty == "custom" {
        let raw = resp.get("customResponseData").and_then(|d| d.as_str()).unwrap_or_default();
        base64::engine::general_purpose::STANDARD
            .decode(raw)
            .map_err(|e| format!("failed to decode custom response data: {e}"))?
    } else {
        Vec::new()
    };
    get_internal_response(&Config { response: Some(proto_response(ty, data)) })
        .map_err(|e| e.to_string())
}

/// 构造 proto `Response` 消息（上层 adapter / 测试便捷函数）。
#[must_use]
pub fn proto_response(
    ty: String,
    custom_response_data: Vec<u8>,
) -> xray_proto::xray::proxy::blackhole::Response {
    xray_proto::xray::proxy::blackhole::Response { r#type: ty, custom_response_data }
}

#[cfg(test)]
mod tests {
    use xray_buf::multi::MultiBuffer;

    use super::*;

    /// 收集 Writer 写出的所有字节，便于断言。
    struct CollectWriter {
        chunks: Vec<MultiBuffer>,
    }

    impl CollectWriter {
        fn new() -> Self {
            Self { chunks: Vec::new() }
        }

        fn collected_bytes(&self) -> Vec<u8> {
            let mut out = Vec::new();
            for mb in &self.chunks {
                for b in mb.iter() {
                    out.extend_from_slice(b.bytes());
                }
            }
            out
        }
    }

    impl Writer for CollectWriter {
        fn write_multi_buffer(
            &mut self,
            mb: MultiBuffer,
        ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
            self.chunks.push(mb);
            Box::pin(async { Ok(()) })
        }
    }

    fn cfg_with_type(ty: &str) -> Config {
        Config { response: Some(crate::response::proto_response(ty.to_string(), Vec::new())) }
    }

    /// Go `infra/conf/blackhole.go:24` `strings.ToLower`：大小写不敏感。
    #[test]
    fn conf_json_lowercases_type() {
        let resp = serde_json::json!({"type": "HTTP"});
        assert_eq!(response_config_from_json(Some(&resp)).unwrap(), ResponseConfig::Http403);
        let resp = serde_json::json!({"type": "Custom", "customResponseData": "eHlheQ=="});
        assert_eq!(
            response_config_from_json(Some(&resp)).unwrap(),
            ResponseConfig::Custom(b"xyay".to_vec())
        );
        let resp = serde_json::json!({"type": "NONE"});
        assert_eq!(response_config_from_json(Some(&resp)).unwrap(), ResponseConfig::None);
    }

    /// Go `:36-37`：未知 type 是 Build 硬错，不得静默降级 None。
    #[test]
    fn conf_json_unknown_type_is_err() {
        let resp = serde_json::json!({"type": "htp"});
        let err = response_config_from_json(Some(&resp)).expect_err("unknown type must err");
        assert!(err.contains("htp"), "错误须点名坏值: {err}");
    }

    /// Go `:38-42`：custom 的 base64 解码失败即硬错；type≠custom 时不校验数据。
    #[test]
    fn conf_json_custom_base64_strictness() {
        let bad = serde_json::json!({"type": "custom", "customResponseData": "!!!"});
        assert!(response_config_from_json(Some(&bad)).is_err(), "坏 base64 必须硬错");
        let ignored = serde_json::json!({"type": "none", "customResponseData": "!!!"});
        assert_eq!(
            response_config_from_json(Some(&ignored)).unwrap(),
            ResponseConfig::None,
            "Go 只在 custom 分支解码，其余分支忽略数据"
        );
    }

    /// `response` 段缺省 → None（Go `v.Response == nil`）。
    #[test]
    fn conf_json_missing_response_is_none() {
        assert_eq!(response_config_from_json(None).unwrap(), ResponseConfig::None);
        let resp = serde_json::json!({});
        assert_eq!(response_config_from_json(Some(&resp)).unwrap(), ResponseConfig::None);
    }

    #[tokio::test]
    async fn none_response_writes_nothing() {
        let mut w = CollectWriter::new();
        let n = ResponseConfig::None.write_to(&mut w).await.unwrap();
        assert_eq!(n, 0);
        assert!(w.chunks.is_empty());
    }

    /// `custom_response_data` 无长度上限：超过默认 8KB 块时按需取块，
    /// **不得静默少写**（qgdgh）——旧实现只发出前 8KB 却回报 payload 全长。
    #[tokio::test]
    async fn custom_response_larger_than_default_block_is_written_whole() {
        let payload: Vec<u8> = (0..9000u32).map(|i| (i & 0xFF) as u8).collect();
        let mut w = CollectWriter::new();
        let n = ResponseConfig::Custom(payload.clone()).write_to(&mut w).await.unwrap();
        assert_eq!(n as usize, payload.len(), "回报的写入量 = payload 全长");
        assert_eq!(w.collected_bytes(), payload, "线上字节必须逐字节等于 payload");
    }

    #[tokio::test]
    async fn http_response_writes_403_payload() {
        let mut w = CollectWriter::new();
        let n = ResponseConfig::Http403.write_to(&mut w).await.unwrap();
        assert_eq!(n as usize, HTTP_403_RESPONSE.len());
        let bytes = w.collected_bytes();
        assert_eq!(bytes, HTTP_403_RESPONSE.as_bytes());
        assert!(bytes.starts_with(b"HTTP/1.1 403 Forbidden"));
    }

    #[test]
    fn http_403_payload_matches_go_http_response_write() {
        // Go 01a034be：`http403response.Write(&data)`（net/http 标准序列化，101 字节）。
        // 实测 Go：CRLF 行末；Header 按字典序写出（Cache-Control 在 Connection 前）；
        // Content-Length: 0；头后单个空行结尾。
        let expected = "HTTP/1.1 403 Forbidden\r\n\
            Cache-Control: max-age=3600, public\r\n\
            Connection: close\r\n\
            Content-Length: 0\r\n\
            \r\n";
        assert_eq!(HTTP_403_RESPONSE.len(), 101);
        assert_eq!(HTTP_403_RESPONSE, expected);
    }

    #[test]
    fn response_config_default_is_none() {
        assert_eq!(ResponseConfig::default(), ResponseConfig::None);
    }

    #[test]
    fn get_internal_response_none_when_absent() {
        let cfg = cfg_with_type("");
        assert_eq!(get_internal_response(&cfg).unwrap(), ResponseConfig::None);
    }

    #[test]
    fn get_internal_response_empty_type_is_none() {
        let cfg = cfg_with_type("");
        assert_eq!(get_internal_response(&cfg).unwrap(), ResponseConfig::None);
    }

    #[test]
    fn get_internal_response_none_type() {
        let cfg = cfg_with_type("none");
        assert_eq!(get_internal_response(&cfg).unwrap(), ResponseConfig::None);
    }

    #[test]
    fn get_internal_response_http_type() {
        let cfg = cfg_with_type("http");
        assert_eq!(get_internal_response(&cfg).unwrap(), ResponseConfig::Http403);
    }

    #[test]
    fn get_internal_response_custom_type_carries_data() {
        // Go 01a034be TestBlackholeCustomResponse：custom 原样携带字节（可大于单个 buffer）。
        let payload: Vec<u8> = (0..=255u8).cycle().take(9000).collect();
        let cfg = Config {
            response: Some(crate::response::proto_response("custom".into(), payload.clone())),
        };
        assert_eq!(get_internal_response(&cfg).unwrap(), ResponseConfig::Custom(payload));
    }

    #[tokio::test]
    async fn custom_response_writes_payload_verbatim() {
        // golden 字节断言：custom → 逐字节回写。
        let payload = b"\x00\x01custom-bytes\xff".to_vec();
        let mut w = CollectWriter::new();
        let n = ResponseConfig::Custom(payload.clone()).write_to(&mut w).await.unwrap();
        assert_eq!(n as usize, payload.len());
        assert_eq!(w.collected_bytes(), payload);
    }

    #[test]
    fn empty_custom_response_is_empty() {
        // Go `len(h.response) > 0`：空 custom 不写不睡。
        assert!(ResponseConfig::Custom(Vec::new()).is_empty());
        assert!(!ResponseConfig::Custom(b"x".to_vec()).is_empty());
        assert!(ResponseConfig::None.is_empty());
        assert!(!ResponseConfig::Http403.is_empty());
    }

    #[test]
    fn get_internal_response_unknown_type_rejected() {
        let cfg = cfg_with_type("SomeUnknown");
        match get_internal_response(&cfg) {
            Err(BlackholeError::UnknownResponseType(s)) => {
                assert_eq!(s, "SomeUnknown");
            },
            other => panic!("expected UnknownResponseType, got {other:?}"),
        }
    }
}
