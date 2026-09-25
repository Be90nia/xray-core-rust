//! SS-2022 出站处理器。
//!
//! 对应 Go `proxy/shadowsocks_2022/outbound.go`。
//!
//! 出站流程复用 [`Client2022`]（ss2022/client.rs），此处仅做适配层。

use std::io;

use tokio::net::TcpStream;
use xray_common::net::address::Address;

use crate::{error::Result, ss2022::client::Client2022, stream::SSStream};

/// SS-2022 出站适配器：持有 [`Client2022`]（负责 TCP 拨号 + SS-2022 加密）。
///
/// 对应 Go `proxy/shadowsocks_2022/outbound.go::Outbound`。
///
/// 提供 `process` 方法拨号到 SS-2022 服务端并返回加密流，
/// dispatcher 接入方可在外部包一层 trait 桥接。
pub struct Ss2022Outbound {
    client: Client2022,
}

impl Ss2022Outbound {
    /// 创建 SS-2022 出站适配器。
    ///
    /// # Errors
    /// - 透传 [`Client2022::new`] 错误（cipher/PSK 无效）。
    pub fn new(cipher: &str, psk_b64: &str, server_host: &str, server_port: u16) -> Result<Self> {
        let client = Client2022::new(cipher, psk_b64, server_host, server_port)?;
        Ok(Self { client })
    }

    /// 拨号到 SS-2022 服务端并写目标地址头，返回加密流供上层写 body。
    ///
    /// 底层调 [`Client2022::dial_target`]：TCP connect -> 随机 salt ->
    /// blake3 派生 subkey -> AEAD 加密 header（fixed + variable）-> SSStream。
    ///
    /// # Errors
    /// 返回 [`io::Error`]（`ErrorKind::Other`）当：
    /// - TCP 连接失败
    /// - AEAD 初始化/加密失败
    /// - 地址编码失败
    pub async fn process(&self, addr: &Address, port: u16) -> io::Result<SSStream<TcpStream>> {
        let addr_str = match addr {
            Address::IPv4(v4) => v4.to_string(),
            Address::IPv6(v6) => v6.to_string(),
            Address::Domain(d) => d.clone(),
        };
        self.client.dial_target(&addr_str, port).await.map_err(|e| io::Error::other(e.to_string()))
    }

    /// 返回内部 [`Client2022`] 引用。
    #[must_use]
    pub fn client(&self) -> &Client2022 {
        &self.client
    }
}

impl std::fmt::Debug for Ss2022Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ss2022Outbound").field("client", &self.client).finish()
    }
}

/// SS-2022 UDP 出站配置（支持 UDP-over-TCP 模式）。
///
/// 对应 Go `ClientConfig.udp_over_tcp` + `udp_over_tcp_version`。
#[derive(Debug, Clone, Default)]
pub struct UdpOverTcpConfig {
    /// 是否启用 UDP-over-TCP。
    pub enabled: bool,
    /// UoT 协议版本（0 或 1）。
    pub version: u32,
}

/// SS-2022 出站完整配置（对应 proto `ClientConfig`）。
#[derive(Debug, Clone)]
pub struct Ss2022OutboundConfig {
    /// 服务端地址。
    pub address: String,
    /// 服务端端口。
    pub port: u16,
    /// 加密方法名称。
    pub method: String,
    /// PSK（base64 编码）。
    pub key: String,
    /// UDP-over-TCP 配置。
    pub udp_over_tcp: UdpOverTcpConfig,
}

impl Ss2022OutboundConfig {
    /// 从配置创建出站适配器。
    ///
    /// # Errors
    /// - 透传 [`Ss2022Outbound::new`] 错误。
    pub fn create_outbound(&self) -> Result<Ss2022Outbound> {
        Ss2022Outbound::new(&self.method, &self.key, &self.address, self.port)
    }
}
