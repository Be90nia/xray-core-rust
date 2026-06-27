//! VMess inbound handler + Processor trait。
//!
//! 对应 Go 版本 `proxy/vmess/inbound/inbound.go`。`Process` 主入口依赖
//! `transport::Link` + `dispatcher` + `buf.BufferedReader` 全链路，留 trait stub。

use std::sync::Arc;

use crate::encoding::server::{ServerSession, SessionHistory};
use crate::error::{Result, VmessError};
use crate::validator::{MemoryUser, TimedUserValidator};

/// Inbound 处理器主入口 trait（对应 Go `inbound.Handler.Process`）。
///
/// 上层 dispatcher 注入实际 IO + dispatch 实现，本 crate 不直接依赖 transport。
pub trait InboundProcessor: Send + Sync {
    /// 处理一个入站连接。
    ///
    /// # Errors
    ///
    /// 实现相关。当前所有内置实现返回 [`VmessError::NotImplemented`]。
    fn process(
        &self,
        conn_reader: &mut dyn std::io::Read,
        conn_writer: &mut dyn std::io::Write,
    ) -> Result<()>;
}

/// Noop 处理器：始终返回 `NotImplemented`。
pub struct NoopInboundProcessor;

impl InboundProcessor for NoopInboundProcessor {
    fn process(
        &self,
        _conn_reader: &mut dyn std::io::Read,
        _conn_writer: &mut dyn std::io::Write,
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

    /// 处理入站连接。
    ///
    /// # Errors
    ///
    /// 委托给 processor。
    pub fn process(
        &self,
        conn_reader: &mut dyn std::io::Read,
        conn_writer: &mut dyn std::io::Write,
    ) -> Result<()> {
        self.processor.process(conn_reader, conn_writer)
    }

    /// 解码请求头（直接调用 `ServerSession::decode_request_header`）。
    ///
    /// # Errors
    ///
    /// 参见 [`ServerSession::decode_request_header`](crate::encoding::server::ServerSession::decode_request_header)。
    pub fn decode_request_header<R: std::io::Read>(
        &self,
        reader: &mut R,
    ) -> Result<(xray_common::protocol::RequestHeader, MemoryUser)> {
        let mut session = ServerSession::new(&self.validator, &self.session_history);
        session.decode_request_header(reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_processor_returns_not_implemented() {
        let p = NoopInboundProcessor;
        let mut r = &b""[..];
        let mut w: Vec<u8> = Vec::new();
        let err = p.process(&mut r, &mut w).unwrap_err();
        assert!(matches!(err, VmessError::NotImplemented(_)));
    }

    #[test]
    fn handler_new_creates_with_noop() {
        let v = Arc::new(TimedUserValidator::new());
        let h = Arc::new(SessionHistory::new());
        let handler = InboundHandler::new(v, h);
        let mut r = &b""[..];
        let mut w: Vec<u8> = Vec::new();
        let err = handler.process(&mut r, &mut w).unwrap_err();
        assert!(matches!(err, VmessError::NotImplemented(_)));
    }
}
