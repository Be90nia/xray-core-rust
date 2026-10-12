//! Blackhole 响应配置
//!
//! 对应 Go 版本 `proxy/blackhole/config.go`。
//! Go 01a034be 起用 `Response{type, custom_response_data}` 表达三种行为：
//! "无响应"/"回写 HTTP 403"/"回写自定义数据"；Rust 端是有限、封闭的枚举
//! [`ResponseConfig`]，用 `enum` 表达更地道，且免除了 `dyn` 与 async-trait 的对象安全约束。

use std::{future::Future, pin::Pin};

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
            let mut buf = xray_buf::buffer::Buffer::new();
            buf.write_from(&payload);
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

    #[tokio::test]
    async fn none_response_writes_nothing() {
        let mut w = CollectWriter::new();
        let n = ResponseConfig::None.write_to(&mut w).await.unwrap();
        assert_eq!(n, 0);
        assert!(w.chunks.is_empty());
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
