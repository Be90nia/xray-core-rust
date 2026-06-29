//! Shadowsocks 出站客户端处理器（stub），对应 Go `proxy/shadowsocks/client.go`。
//!
//! Process 流程依赖 `transport::Link` + `internet::Dialer` + `signal::Timer` 等基础设施，
//! 当前留 trait 接口 + Noop 实现，等核心集成时填充。

use crate::config::MemoryAccount;
use crate::error::Result;
use crate::validator::RequestCommand;

/// 出站处理器接口。
pub trait OutboundProcessor: Send + Sync {
    /// 处理一个出站连接（TCP/UDP），将 link 内的数据加密发送给远端。
    ///
    /// # Errors
    /// - 透传网络 / 加密错误。
    fn process(
        &self,
        account: &MemoryAccount,
        command: RequestCommand,
        address: &xray_common::net::address::Address,
        port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>>;
}

/// No-op 处理器：直接返回明文 payload（仅用于测试）。
pub struct NoopOutboundProcessor;

impl OutboundProcessor for NoopOutboundProcessor {
    fn process(
        &self,
        _account: &MemoryAccount,
        _command: RequestCommand,
        _address: &xray_common::net::address::Address,
        _port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        Ok(payload.to_vec())
    }
}

/// SS 出站客户端配置，对应 Go `Client{server, policyManager}`。
#[derive(Clone)]
pub struct Client {
    /// 远端服务器账户。
    pub account: MemoryAccount,
    /// 处理器实现。
    pub processor: std::sync::Arc<dyn OutboundProcessor>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("account", &self.account)
            .field("processor", &"<OutboundProcessor>")
            .finish()
    }
}

impl Client {
    /// 创建客户端。
    #[must_use]
    pub fn new(account: MemoryAccount, processor: std::sync::Arc<dyn OutboundProcessor>) -> Self {
        Self { account, processor }
    }

    /// 处理一个出站连接。
    ///
    /// # Errors
    /// - 透传 processor 错误。
    pub fn process(
        &self,
        command: RequestCommand,
        address: &xray_common::net::address::Address,
        port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        self.processor
            .process(&self.account, command, address, port, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CipherType;
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

    fn make_account() -> MemoryAccount {
        let p = ProtoAccount {
            password: "password".to_string(),
            cipher_type: CipherType::Aes128Gcm.as_i32(),
            iv_check: false,
        };
        MemoryAccount::from_proto(&p).expect("account")
    }

    #[test]
    fn noop_outbound_returns_payload() {
        let account = make_account();
        let processor = std::sync::Arc::new(NoopOutboundProcessor);
        let client = Client::new(account, processor);
        let addr = xray_common::net::address::Address::Domain("x.com".to_string());
        let result = client
            .process(RequestCommand::Tcp, &addr, 443, b"hello")
            .expect("process");
        assert_eq!(result, b"hello");
    }
}
