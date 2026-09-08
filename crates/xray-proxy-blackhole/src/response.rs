//! Blackhole 响应配置
//!
//! 对应 Go 版本 `proxy/blackhole/config.go`。
//!
//! Go 用接口 `ResponseConfig` 与 `NoneResponse`/`HTTPResponse` 两个实现表达
//! "无响应"/"回写 HTTP 403"两种行为；Rust 端这两个行为是有限、封闭的枚举，
//! 用 `enum` 表达更地道，且免除了 `dyn` 与 async-trait 的对象安全约束。

use std::future::Future;
use std::pin::Pin;

use xray_buf::io::{self, Writer};
use xray_proto::xray::proxy::blackhole::Config;

use crate::BlackholeError;

/// 预置 HTTP 403 响应字符串，与 Go 版本 `http403response` 字面量**逐字节对齐**。
///
// 对应 Go `proxy/blackhole/config.go:9-15`：
// ```go
// const http403response = `HTTP/1.1 403 Forbidden
// Connection: close
// Cache-Control: max-age=3600, public
// Content-Length: 0
//
//
// `
// ```
// Go 用裸字符串字面量，行末是 **LF** 而非 CRLF（Rust 之前误写 \r\n）。
pub const HTTP_403_RESPONSE: &str = "HTTP/1.1 403 Forbidden\n\
    Connection: close\n\
    Cache-Control: max-age=3600, public\n\
    Content-Length: 0\n\
    \n\
    \n";

/// Blackhole 响应配置：要么不响应，要么回写预置的 HTTP 403 报文。
///
/// 对应 Go 接口 `proxy/blackhole.ResponseConfig` 的两个实现。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponseConfig {
    /// 不写入任何数据。对应 Go `NoneResponse`。默认值。
    #[default]
    None,
    /// 写入预置 HTTP 403 Forbidden 报文。对应 Go `HTTPResponse`。
    Http403,
}

impl ResponseConfig {
    /// 把预置响应写入 `writer`，返回写入字节数。
    ///
    /// 对应 Go `ResponseConfig.WriteTo(buf.Writer) int32`。返回 `i32` 以保持与 Go 签名一致。
    pub fn write_to<'a>(
        &'a self,
        writer: &'a mut dyn Writer,
    ) -> Pin<Box<dyn Future<Output = io::Result<i32>> + Send + 'a>> {
        match self {
            ResponseConfig::None => Box::pin(async { Ok(0) }),
            ResponseConfig::Http403 => Box::pin(async move {
                let payload = HTTP_403_RESPONSE.as_bytes();
                let n = i32::try_from(payload.len()).map_err(|_| {
                    io::Error::WriteError(format!(
                        "HTTP 403 response too large for i32: {} bytes",
                        payload.len()
                    ))
                })?;
                // 通过单一 Buffer 写入；MultiBuffer 仅承载一个 Buffer 即可表达 "one shot write"。
                let mut buf = xray_buf::buffer::Buffer::new();
                buf.write_from(payload);
                let mb = xray_buf::multi::MultiBuffer::from_buffer(buf);
                writer.write_multi_buffer(mb).await?;
                Ok(n)
            }),
        }
    }
}

/// 把 protobuf [`Config`] 转换为内部 [`ResponseConfig`]。
///
/// 对应 Go `Config.GetInternalResponse`。
///
/// 解析规则：
/// - `response` 字段为空 → [`ResponseConfig::None`]
/// - `response.type` 匹配 `xray.proxy.blackhole.NoneResponse` → [`ResponseConfig::None`]
/// - `response.type` 匹配 `xray.proxy.blackhole.HTTPResponse` → [`ResponseConfig::Http403`]
/// - 其它 → [`BlackholeError::UnknownResponseType`]
///
/// `type` 同时接受裸类型名与 gRPC 标准前缀 `type.googleapis.com/`。
pub fn get_internal_response(config: &Config) -> Result<ResponseConfig, BlackholeError> {
    let Some(msg) = config.response.as_ref() else {
        return Ok(ResponseConfig::None);
    };
    let url = msg.r#type.as_str();
    let stripped = url.strip_prefix("type.googleapis.com/").unwrap_or(url);
    match stripped {
        "xray.proxy.blackhole.NoneResponse" => Ok(ResponseConfig::None),
        "xray.proxy.blackhole.HTTPResponse" => Ok(ResponseConfig::Http403),
        other => Err(BlackholeError::UnknownResponseType(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_buf::multi::MultiBuffer;
    use xray_proto::xray::common::serial::TypedMessage;

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

    fn cfg_with_response(type_url: Option<&str>) -> Config {
        Config {
            response: type_url.map(|s| TypedMessage {
                r#type: s.to_string(),
                value: Vec::new(),
            }),
        }
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
    fn http_403_payload_matches_go_constant() {
        // edwo：Go `proxy/blackhole/config.go:9-15` 字面量用裸字符串 → 行末 LF（不是 CRLF）。
        // 之前断言 CRLF 是误抄；该断言反向钉死了错误行为。
        let expected = "HTTP/1.1 403 Forbidden\n\
            Connection: close\n\
            Cache-Control: max-age=3600, public\n\
            Content-Length: 0\n\
            \n\
            \n";
        assert_eq!(HTTP_403_RESPONSE, expected);
    }

    #[test]
    fn response_config_default_is_none() {
        assert_eq!(ResponseConfig::default(), ResponseConfig::None);
    }

    #[test]
    fn get_internal_response_none_when_absent() {
        let cfg = cfg_with_response(None);
        assert_eq!(get_internal_response(&cfg).unwrap(), ResponseConfig::None);
    }

    #[test]
    fn get_internal_response_explicit_none_type() {
        let cfg = cfg_with_response(Some("xray.proxy.blackhole.NoneResponse"));
        assert_eq!(get_internal_response(&cfg).unwrap(), ResponseConfig::None);
    }

    #[test]
    fn get_internal_response_http_type() {
        let cfg = cfg_with_response(Some("xray.proxy.blackhole.HTTPResponse"));
        assert_eq!(get_internal_response(&cfg).unwrap(), ResponseConfig::Http403);
    }

    #[test]
    fn get_internal_response_http_type_with_googleapis_prefix() {
        let cfg = cfg_with_response(Some("type.googleapis.com/xray.proxy.blackhole.HTTPResponse"));
        assert_eq!(get_internal_response(&cfg).unwrap(), ResponseConfig::Http403);
    }

    #[test]
    fn get_internal_response_unknown_type_rejected() {
        let cfg = cfg_with_response(Some("xray.proxy.blackhole.SomeUnknown"));
        match get_internal_response(&cfg) {
            Err(BlackholeError::UnknownResponseType(s)) => {
                assert_eq!(s, "xray.proxy.blackhole.SomeUnknown");
            }
            other => panic!("expected UnknownResponseType, got {other:?}"),
        }
    }
}
