//! VMess inbound handler + Processor trait。
//!
//! 对应 Go 版本 `proxy/vmess/inbound/inbound.go`。`Process` 主入口依赖
//! `transport::Link` + `dispatcher` + `buf.BufferedReader` 全链路，留 trait stub。
//!
//! 全部 IO 走 tokio 异步 API（`AsyncRead`/`AsyncWrite`），不阻塞事件循环。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::encoding::server::{ServerSession, SessionHistory};
use crate::error::{Result, VmessError};
use crate::validator::{MemoryUser, TimedUserValidator};

/// Inbound 处理器主入口 trait（对应 Go `inbound.Handler.Process`）。
///
/// 上层 dispatcher 注入实际 IO + dispatch 实现，本 crate 不直接依赖 transport。
/// 全异步：reader/writer 为 tokio 的 `AsyncRead`/`AsyncWrite` trait 对象。
#[async_trait]
pub trait InboundProcessor: Send + Sync {
    /// 处理一个入站连接。
    ///
    /// # Errors
    ///
    /// 实现相关。当前所有内置实现返回 [`VmessError::NotImplemented`]。
    async fn process(
        &self,
        conn_reader: &mut (dyn AsyncRead + Unpin + Send),
        conn_writer: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<()>;
}

/// Noop 处理器：始终返回 `NotImplemented`。
pub struct NoopInboundProcessor;

#[async_trait]
impl InboundProcessor for NoopInboundProcessor {
    async fn process(
        &self,
        _conn_reader: &mut (dyn AsyncRead + Unpin + Send),
        _conn_writer: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<()> {
        Err(VmessError::NotImplemented("inbound process: requires transport::Link + dispatcher chain"))
    }
}

/// VMess inbound Handler（对应 Go `inbound.Handler`）。
///
/// 持有 validator + session_history + processor 注入点。
pub struct InboundHandler {
    /// 用户 validator。
    pub validator: Arc<TimedUserValidator>,
    /// 会话反重放历史。
    pub session_history: Arc<SessionHistory>,
    /// IO processor（默认 Noop，等上层注入）。
    pub processor: Arc<dyn InboundProcessor>,
}

impl InboundHandler {
    /// 创建新 handler。
    #[must_use]
    pub fn new(
        validator: Arc<TimedUserValidator>,
        session_history: Arc<SessionHistory>,
    ) -> Self {
        Self {
            validator,
            session_history,
            processor: Arc::new(NoopInboundProcessor),
        }
    }

    /// 用自定义 processor 创建。
    #[must_use]
    pub fn with_processor(
        validator: Arc<TimedUserValidator>,
        session_history: Arc<SessionHistory>,
        processor: Arc<dyn InboundProcessor>,
    ) -> Self {
        Self {
            validator,
            session_history,
            processor,
        }
    }

    /// 处理入站连接（异步）。
    ///
    /// # Errors
    ///
    /// 委托给 processor。
    pub async fn process(
        &self,
        conn_reader: &mut (dyn AsyncRead + Unpin + Send),
        conn_writer: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<()> {
        self.processor.process(conn_reader, conn_writer).await
    }

    /// 解码请求头（异步，直接调用 `ServerSession::decode_request_header_async`）。
    ///
    /// # Errors
    ///
    /// 参见 [`ServerSession::decode_request_header_async`](crate::encoding::server::ServerSession::decode_request_header_async)。
    pub async fn decode_request_header<R>(&self, reader: &mut R) -> Result<(xray_common::protocol::RequestHeader, MemoryUser)>
    where
        R: AsyncRead + Unpin,
    {
        let mut session = ServerSession::new(&self.validator, &self.session_history);
        session.decode_request_header_async(reader).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_processor_returns_not_implemented() {
        let p = NoopInboundProcessor;
        let mut r = &b""[..];
        let mut w = tokio::io::sink();
        let err = p.process(&mut r, &mut w).await.unwrap_err();
        assert!(matches!(err, VmessError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn handler_new_creates_with_noop() {
        let v = Arc::new(TimedUserValidator::new());
        let h = Arc::new(SessionHistory::new());
        let handler = InboundHandler::new(v, h);
        let mut r = &b""[..];
        let mut w = tokio::io::sink();
        let err = handler.process(&mut r, &mut w).await.unwrap_err();
        assert!(matches!(err, VmessError::NotImplemented(_)));
    }
}
