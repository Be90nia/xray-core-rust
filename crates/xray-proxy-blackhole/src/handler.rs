//! Blackhole 出站处理器
//!
//! 对应 Go 版本 `proxy/blackhole/blackhole.go`。
//!
//! 当前实现聚焦业务核心：构造时一次性解析 [`Config`] 为 [`ResponseConfig`]，
//! `process` 接受任意 [`Writer`](xray_buf::io::Writer) 写出响应。Go 版本中
//! `Process(ctx, link, dialer)` 涉及的 `transport.Link`/`internet.Dialer`/`session`/`signal`
//! 交互，等 Rust 端 `xray-transport` 提供等价类型后再通过 adapter 接入。

use thiserror::Error;
use xray_buf::io::{self, Writer};
use xray_proto::xray::proxy::blackhole::Config;

use crate::response::{ResponseConfig, get_internal_response};

/// Blackhole 处理器错误。
#[derive(Debug, Error)]
pub enum BlackholeError {
    /// `Config.response.type` 指向未知响应类型。
    #[error("unknown blackhole response type: {0}")]
    UnknownResponseType(String),
    /// 写入响应时发生 IO 错误。
    #[error("write response failed: {0}")]
    WriteFailed(#[from] io::Error),
}

/// Blackhole 出站处理器：静默吞掉入站数据，可选地写回一份预置响应。
///
/// 对应 Go 版本 `proxy/blackhole.Handler`。
#[derive(Debug, Default)]
pub struct Handler {
    response: ResponseConfig,
}

impl Handler {
    /// 创建新的 blackhole 处理器，按 `config` 解析预置响应。
    ///
    /// 对应 Go `New(ctx, config)`。Go 源码中 `ctx` 在该函数内未使用，Rust 实现省略。
    pub fn new(config: Config) -> Result<Self, BlackholeError> {
        let response = get_internal_response(&config)?;
        Ok(Self { response })
    }

    /// 用显式的 [`ResponseConfig`] 直接构造（便于上层 adapter / 测试）。
    pub fn with_response(response: ResponseConfig) -> Self {
        Self { response }
    }

    /// 处理一次连接：写出预置响应并返回写入字节数。
    ///
    /// 这是 Go `Handler.Process` 中可独立测试、不依赖 transport 的子步骤。
    /// 当前签名接受 `&mut dyn Writer`；一旦 `transport::Link` 落地，
    /// 在此基础上提供完整的 `process_link(link, dialer)` 即可。
    pub async fn process(&self, writer: &mut dyn Writer) -> Result<i32, BlackholeError> {
        Ok(self.response.write_to(writer).await?)
    }

    /// 暴露内部响应配置，便于测试与上层 adapter 复用。
    pub fn response(&self) -> ResponseConfig {
        self.response.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin};

    use xray_buf::multi::MultiBuffer;

    use super::*;
    use crate::response::{HTTP_403_RESPONSE, proto_response};

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
        Config { response: Some(proto_response(ty.to_string(), Vec::new())) }
    }

    #[tokio::test]
    async fn handler_none_response_writes_zero() {
        let h = Handler::new(Config { response: None }).unwrap();
        let mut w = CollectWriter::new();
        let n = h.process(&mut w).await.unwrap();
        assert_eq!(n, 0);
        assert!(w.chunks.is_empty());
    }

    #[tokio::test]
    async fn handler_http_response_writes_payload() {
        let h = Handler::new(cfg_with_type("http")).unwrap();
        let mut w = CollectWriter::new();
        let n = h.process(&mut w).await.unwrap();
        assert_eq!(n as usize, HTTP_403_RESPONSE.len());
        assert_eq!(w.collected_bytes(), HTTP_403_RESPONSE.as_bytes());
    }

    #[tokio::test]
    async fn handler_custom_response_writes_payload_verbatim() {
        // Go 01a034be TestBlackholeCustomResponse：custom 原样回写（golden 字节断言）。
        let payload: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let h = Handler::new(Config {
            response: Some(proto_response("custom".into(), payload.clone())),
        })
        .unwrap();
        let mut w = CollectWriter::new();
        let n = h.process(&mut w).await.unwrap();
        assert_eq!(n as usize, payload.len());
        assert_eq!(w.collected_bytes(), payload);
    }

    #[test]
    fn handler_rejects_unknown_response_type() {
        let result = Handler::new(cfg_with_type("bogus"));
        match result {
            Err(BlackholeError::UnknownResponseType(s)) => {
                assert_eq!(s, "bogus");
            },
            Err(other) => panic!("expected UnknownResponseType, got {other:?}"),
            Ok(_) => panic!("expected UnknownResponseType, got Ok"),
        }
    }

    #[test]
    fn handler_exposes_response_config() {
        let h = Handler::with_response(ResponseConfig::Http403);
        assert_eq!(h.response(), ResponseConfig::Http403);
    }

    #[tokio::test]
    async fn handler_explicit_none_type_also_writes_zero() {
        let h = Handler::new(cfg_with_type("none")).unwrap();
        let mut w = CollectWriter::new();
        let n = h.process(&mut w).await.unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn handler_default_is_none_response() {
        let h = Handler::default();
        assert_eq!(h.response(), ResponseConfig::None);
    }
}
