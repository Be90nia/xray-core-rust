//! Shadowsocks 出站客户端，对应 Go `proxy/shadowsocks/client.go`。
//!
//! # 流程
//!
//! 1. TCP connect 到 SS 服务端（`server_host:server_port`）
//! 2. 写随机 IV（长度 = `cipher.iv_size()`）
//! 3. 构造 `SSStream`（nonce 从 `[0xFF;n]` 开始）
//! 4. 首帧：`write_chunk(addr+port)`（SS 地址格式）
//! 5. body：`write_chunk(payload)` × N
//!
//! 调用方通过 [`Client::dial_target`] 一次性完成 1-4，返回的 `SSStream` 直接写 body。

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use xray_common::net::address::Address;

use crate::config::MemoryAccount;
use crate::error::Result;
use crate::protocol::write_address_port_ss;
use crate::stream::SSStream;

/// SS 出站客户端配置。
#[derive(Clone)]
pub struct Client {
    /// 账户（cipher + key + password）。
    pub account: MemoryAccount,
    /// SS 服务端 host。
    pub server_host: String,
    /// SS 服务端 port。
    pub server_port: u16,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("account", &self.account)
            .field("server", &format!("{}:{}", self.server_host, self.server_port))
            .finish()
    }
}

impl Client {
    /// 创建客户端。
    #[must_use]
    pub fn new(account: MemoryAccount, server_host: String, server_port: u16) -> Self {
        Self {
            account,
            server_host,
            server_port,
        }
    }

    /// 连接到 SS 服务端：TCP connect → 写随机 IV → 构造 SSStream。
    ///
    /// 返回的 `SSStream` 可直接 `write_chunk` 发首帧（addr+port）和 body。
    ///
    /// # Errors
    /// - [`crate::error::SsError::Io`]：TCP 连接/写 IV 失败。
    /// - 透传 `SSStream::new_client` AEAD 初始化错误。
    pub async fn connect_tcp(&self) -> Result<SSStream<TcpStream>> {
        let addr = format!("{}:{}", self.server_host, self.server_port);
        let mut tcp = TcpStream::connect(&addr).await?;
        tcp.set_nodelay(true).ok();

        // 写随机 IV（长度 = cipher.iv_size()；None cipher iv_size=0，跳过）
        let iv_size = self.account.cipher.iv_size() as usize;
        let iv: Vec<u8> = (0..iv_size).map(|_| rand::random()).collect();
        if iv_size > 0 {
            tcp.write_all(&iv).await?;
            tcp.flush().await?;
        }

        SSStream::new_client(tcp, &self.account, &iv)
    }

    /// 连接 + 发首帧（addr+port），返回 `SSStream` 供上层写 body。
    ///
    /// 这是 [`Self::connect_tcp`] + `write_chunk(addr+port)` 的便捷组合。
    ///
    /// # Errors
    /// - 透传 [`Self::connect_tcp`] 错误。
    /// - 透传 `SSStream::write_chunk` AEAD seal/IO 错误。
    pub async fn dial_target(
        &self,
        target_addr: &Address,
        target_port: u16,
    ) -> Result<SSStream<TcpStream>> {
        let mut stream = self.connect_tcp().await?;
        let mut first_frame = Vec::new();
        write_address_port_ss(&mut first_frame, target_addr, target_port);
        stream.write_chunk(&first_frame).await?;
        stream.flush().await?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CipherType;
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

    fn make_account(ct: CipherType, password: &str) -> MemoryAccount {
        let p = ProtoAccount {
            password: password.to_string(),
            cipher_type: ct.as_i32(),
            iv_check: false,
        };
        MemoryAccount::from_proto(&p).expect("account")
    }

    #[test]
    fn client_struct_construction() {
        let account = make_account(CipherType::Aes128Gcm, "password");
        let client = Client::new(account, "example.com".to_string(), 8388);
        assert_eq!(client.server_host, "example.com");
        assert_eq!(client.server_port, 8388);
    }

    #[test]
    fn client_debug_format() {
        let account = make_account(CipherType::Aes256Gcm, "p");
        let client = Client::new(account, "1.2.3.4".to_string(), 443);
        let s = format!("{client:?}");
        assert!(s.contains("1.2.3.4:443"));
    }

    #[test]
    fn client_clone_is_independent() {
        let account = make_account(CipherType::Aes128Gcm, "password");
        let client = Client::new(account, "host".to_string(), 8080);
        let cloned = client.clone();
        assert_eq!(cloned.server_port, 8080);
    }
}
