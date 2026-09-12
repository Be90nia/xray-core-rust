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

use tokio::net::TcpStream;
use xray_common::net::address::Address;

use crate::{
    config::MemoryAccount, error::Result, protocol::write_address_port_ss, stream::SSStream,
};

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
        Self { account, server_host, server_port }
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
        let tcp = TcpStream::connect(&addr).await?;
        tcp.set_nodelay(true).ok();
        self.connect_tcp_on(tcp).await
    }

    /// 在**已建立**的连接上写随机 IV 并构造 SSStream（生产 transport 路径用）。
    ///
    /// # Errors
    /// - [`crate::error::SsError::Io`]：写 IV 失败。
    /// - 透传 `SSStream::new_client` AEAD 初始化错误。
    pub async fn connect_tcp_on<C>(&self, mut conn: C) -> Result<SSStream<C>>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        // 写随机 IV（长度 = cipher.iv_size()；None cipher iv_size=0，跳过）
        let iv_size = self.account.cipher.iv_size() as usize;
        let iv: Vec<u8> = (0..iv_size).map(|_| rand::random()).collect();
        if iv_size > 0 {
            use tokio::io::AsyncWriteExt;
            conn.write_all(&iv).await?;
            conn.flush().await?;
        }

        SSStream::new_client(conn, &self.account, &iv)
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
        let tcp = TcpStream::connect(format!("{}:{}", self.server_host, self.server_port)).await?;
        tcp.set_nodelay(true).ok();
        self.dial_target_on(tcp, target_addr, target_port).await
    }

    /// [`Self::dial_target`] 在**已建立**连接上的版本（生产 transport 路径用）。
    ///
    /// # Errors
    /// - 透传 [`Self::connect_tcp_on`] 错误。
    /// - 透传 `SSStream::write_chunk` AEAD seal/IO 错误。
    pub async fn dial_target_on<C>(
        &self,
        conn: C,
        target_addr: &Address,
        target_port: u16,
    ) -> Result<SSStream<C>>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut stream = self.connect_tcp_on(conn).await?;
        let mut first_frame = Vec::new();
        write_address_port_ss(&mut first_frame, target_addr, target_port);
        stream.write_chunk(&first_frame).await?;
        stream.flush().await?;
        Ok(stream)
    }

    /// [`Self::dial_target`] + 标记流为「读 Go 风格 server response」模式。
    ///
    /// 生产 outbound proxy 路径用（dispatcher / [`crate::dispatcher::SsConnection`]）：
    /// SS TCP proxy 协议 server 在 response 开头发**新**随机 IV（Go `WriteTCPResponse`
    /// 行196-202），client 必须先读 IV 并用它派生新 aead 才能解密 response chunks。
    ///
    /// IV 读取是 **lazy** 的（第一次 `read_chunk` 时执行）：server 只在拿到 target
    /// 响应数据后才写 IV，若 dial 后同步读 IV 会与「server 等 client body」互等死锁。
    ///
    /// `dial_target` 本身不标记（用于 inbound server 测试场景——Rust inbound server
    /// 不写 IV header，那个上下文读 response 无需 rekey）。
    ///
    /// # Errors
    /// - 透传 [`Self::dial_target`] 错误。
    pub async fn dial_target_for_proxy(
        &self,
        target_addr: &Address,
        target_port: u16,
    ) -> Result<SSStream<TcpStream>> {
        let tcp = TcpStream::connect(format!("{}:{}", self.server_host, self.server_port)).await?;
        tcp.set_nodelay(true).ok();
        self.dial_target_for_proxy_on(tcp, target_addr, target_port).await
    }

    /// [`Self::dial_target_for_proxy`] 在**已建立**连接上的版本（生产 transport 路径用）。
    ///
    /// # Errors
    /// - 透传 [`Self::dial_target_on`] 错误。
    pub async fn dial_target_for_proxy_on<C>(
        &self,
        conn: C,
        target_addr: &Address,
        target_port: u16,
    ) -> Result<SSStream<C>>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut stream = self.dial_target_on(conn, target_addr, target_port).await?;
        stream.mark_response_rekey(self.account.clone());
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

    use super::*;
    use crate::config::CipherType;

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
