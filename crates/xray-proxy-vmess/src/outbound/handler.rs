//! VMess outbound handler + Processor trait。
//!
//! 对应 Go 版本 `proxy/vmess/outbound/outbound.go`。`Process` 主入口依赖
//! `transport::Link` + `retry` + `signal` + `internet::Dialer` 全链路，留 trait stub。
//!
//! 全异步：连接建立与数据传输均通过 tokio 异步 API。

use std::sync::Arc;

use async_trait::async_trait;
use xray_common::protocol::RequestHeader;

use crate::{
    account::MemoryAccount,
    encoding::client::ClientSession,
    error::{Result, VmessError},
};

/// Outbound 处理器主入口 trait（对应 Go `outbound.Handler.Process`）。
///
/// 上层 transport 注入实际 IO 实现，本 crate 不直接依赖 transport。
/// 全异步：拨号 + body 转发全走 tokio 异步路径。
#[async_trait]
pub trait OutboundProcessor: Send + Sync {
    /// 处理一个出站请求：拨号 + 编码请求头 + 转发 body。
    ///
    /// # Errors
    ///
    /// 实现相关。当前所有内置实现返回 [`VmessError::NotImplemented`]。
    async fn process(
        &self,
        session: &ClientSession,
        header: &RequestHeader,
        account: &MemoryAccount,
    ) -> Result<()>;
}

/// Noop 处理器：始终返回 `NotImplemented`。
pub struct NoopOutboundProcessor;

#[async_trait]
impl OutboundProcessor for NoopOutboundProcessor {
    async fn process(
        &self,
        _session: &ClientSession,
        _header: &RequestHeader,
        _account: &MemoryAccount,
    ) -> Result<()> {
        Err(VmessError::NotImplemented(
            "outbound process: requires transport::Link + retry + signal chain",
        ))
    }
}

/// VMess outbound Handler（对应 Go `outbound.Handler`）。
///
/// 持有当前账户（receiver） + processor 注入点。
pub struct OutboundHandler {
    /// 当前 receiver 账户（VMess outbound 必须绑定一个账户）。
    pub account: MemoryAccount,
    /// IO processor（默认 Noop）。
    pub processor: Arc<dyn OutboundProcessor>,
}

impl OutboundHandler {
    /// 创建新 handler。
    #[must_use]
    pub fn new(account: MemoryAccount) -> Self {
        Self { account, processor: Arc::new(NoopOutboundProcessor) }
    }

    /// 用自定义 processor 创建。
    #[must_use]
    pub fn with_processor(account: MemoryAccount, processor: Arc<dyn OutboundProcessor>) -> Self {
        Self { account, processor }
    }

    /// 处理出站请求（异步）。
    ///
    /// # Errors
    ///
    /// 委托给 processor。
    pub async fn process(&self, session: &ClientSession, header: &RequestHeader) -> Result<()> {
        self.processor.process(session, header, &self.account).await
    }

    /// 编码请求头（不涉及 IO，纯计算）。
    ///
    /// # Errors
    ///
    /// 参见 [`ClientSession::encode_request_header`](crate::encoding::client::ClientSession::encode_request_header)。
    pub fn encode_request_header(
        &self,
        session: &ClientSession,
        header: &RequestHeader,
    ) -> Result<Vec<u8>> {
        let cmd_key = self.account.cmd_key();
        session.encode_request_header(header, &cmd_key)
    }
}

#[cfg(test)]
mod tests {
    use xray_common::{
        net::{address::Address, destination::Destination, port::Port},
        protocol::{Command, SecurityType},
        uuid::UUID,
    };

    use super::*;

    fn sample_account() -> MemoryAccount {
        MemoryAccount::new(UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("uuid"))
    }

    #[tokio::test]
    async fn noop_processor_returns_not_implemented() {
        let p = NoopOutboundProcessor;
        let session = ClientSession::new();
        let header = RequestHeader::new(
            crate::encoding::VERSION,
            Command::Tcp,
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(80)),
            SecurityType::Aes128Gcm,
        );
        let account = sample_account();
        let err = p.process(&session, &header, &account).await.unwrap_err();
        assert!(matches!(err, VmessError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn handler_new_creates_with_noop() {
        let handler = OutboundHandler::new(sample_account());
        let session = ClientSession::new();
        let header = RequestHeader::new(
            crate::encoding::VERSION,
            Command::Tcp,
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(80)),
            SecurityType::Aes128Gcm,
        );
        let err = handler.process(&session, &header).await.unwrap_err();
        assert!(matches!(err, VmessError::NotImplemented(_)));
    }

    #[test]
    fn handler_encode_request_header_uses_account_cmd_key() {
        let handler = OutboundHandler::new(sample_account());
        let session = ClientSession::new();
        let header = RequestHeader::new(
            crate::encoding::VERSION,
            Command::Tcp,
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::new(1, 1, 1, 1)), Port::new(443)),
            SecurityType::Aes128Gcm,
        );
        let sealed = handler.encode_request_header(&session, &header).expect("encode");
        assert!(sealed.len() > 60);
    }
}
