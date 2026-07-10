//! Trojan 入站处理器（server），对应 Go `proxy/trojan/server.go`。
//!
//! ## 切片2（当前）
//!
//! 实现 [`TrojanServer`] impl `InboundHandler` + [`trojan_server_handshake`] 端到端验证。
//! Trojan 协议无握手响应——客户端发完 header 后直接发 payload，服务端验证 hash 后
//! 直接开始转发（切片2 仅验证 header 解析 + 用户校验，不转发）。
//!
//! ## 切片3 待实现
//!
//! - fallback（不合法用户重定向到 fallback dest）
//! - dispatch to outbound handler
//! - UDP ASSOCIATE
//! - TLS 包装层

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use xray_common::net::address::Address;
use xray_features::inbound::{InboundError, InboundHandler};

use crate::protocol::{addr_type, Network, COMMAND_TCP, CRLF};
use crate::validator::{MemoryUser, Validator};

/// Trojan 入站服务器。
///
/// `listener` 用 `tokio::sync::Mutex`（可跨 await 点持锁），与 socks 切片2 模式一致。
pub struct TrojanServer {
    /// Handler 标签（用于路由匹配）。
    tag: String,
    /// 用户验证器（共享）。
    validator: Arc<Validator>,
    /// 监听器 + accept loop 任务句柄。close 时 abort 任务取消 accept().
    slot: Mutex<Option<(Arc<TcpListener>, JoinHandle<()>)>>,
}

impl TrojanServer {
    /// 创建新 Trojan 服务器。
    #[must_use]
    pub fn new(tag: impl Into<String>, validator: Arc<Validator>) -> Self {
        Self {
            tag: tag.into(),
            validator,
            slot: Mutex::new(None),
        }
    }

    /// Handler 标签。
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// 用户验证器引用（用于 `add_user`/`remove_user`）。
    #[must_use]
    pub fn validator(&self) -> &Arc<Validator> {
        &self.validator
    }
}

#[async_trait::async_trait]
impl InboundHandler for TrojanServer {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self) -> std::result::Result<(), InboundError> {
        let listener = Arc::new(
            TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| InboundError::ListenError(format!("bind failed: {e}")))?,
        );
        let bound = listener
            .local_addr()
            .map_err(|e| InboundError::ListenError(format!("local_addr: {e}")))?;
        info!(tag = %self.tag, addr = %bound, "Trojan server started");

        let tag = self.tag.clone();
        let validator = self.validator.clone();
        let listener_clone = Arc::clone(&listener);
        let handle = tokio::spawn(async move {
            loop {
                match listener_clone.accept().await {
                    Ok((mut stream, peer)) => {
                        let tag = tag.clone();
                        let validator = validator.clone();
                        tokio::spawn(async move {
                            match trojan_server_handshake(&mut stream, &validator).await {
                                Ok((network, addr, port, user)) => {
                                    info!(
                                        tag = %tag,
                                        peer = %peer,
                                        network = ?network,
                                        dest_addr = ?addr,
                                        dest_port = port,
                                        user = %user.email,
                                        "Trojan handshake succeeded"
                                    );
                                }
                                Err(e) => {
                                    warn!(tag = %tag, peer = %peer, error = %e, "Trojan handshake failed");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        warn!(tag = %tag, error = %e, "accept failed");
                        break;
                    }
                }
            }
        });

        *self.slot.lock().await = Some((listener, handle));
        Ok(())
    }

    async fn close(&self) -> std::result::Result<(), InboundError> {
        if let Some((_listener, handle)) = self.slot.lock().await.take() {
            handle.abort();
            info!(tag = %self.tag, "Trojan server closed");
        }
        Ok(())
    }

    fn port(&self) -> u16 {
        // 同步方法无法读 async Mutex; 返回 0
        0
    }
}

/// Trojan 服务端握手——读取并校验 Trojan 请求头。
///
/// 流程：
/// 1. 读 56 字节 hex key
/// 2. `Validator::get_by_key` 校验用户
/// 3. 读 2 字节 CRLF
/// 4. 读 1 字节 CMD (`Network`)
/// 5. 读 addr+port（SOCKS5 格式: ATYP + addr + 2 字节 BE port）
/// 6. 读 2 字节 CRLF
///
/// 验证成功返回 `(network, addr, port, user)`，失败返回 `TrojanError`。
/// Trojan 协议无握手响应——调用方验证通过后直接开始双向转发。
///
/// # Errors
///
/// - [`TrojanError::ReadUserHash`]: 读 hex key 失败
/// - [`TrojanError::UserNotFound`]: 用户 hash 不在 validator 中
/// - [`TrojanError::ReadCrlf`]: CRLF 不匹配
/// - [`TrojanError::ReadCommand`]: CMD 非法
/// - [`TrojanError::ReadAddressPort`]: addr/port 解析失败
pub async fn trojan_server_handshake<S>(
    stream: &mut S,
    validator: &Validator,
) -> crate::Result<(Network, Address, u16, MemoryUser)>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
{
    // 1. 读 56 字节 hex key
    let mut key_buf = [0u8; 56];
    stream
        .read_exact(&mut key_buf)
        .await
        .map_err(|e| crate::TrojanError::ReadUserHash(format!("read key: {e}")))?;

    // 2. 校验 key via Validator
    let user = validator
        .get_by_key(&key_buf)
        .ok_or_else(|| crate::TrojanError::UserNotFound)?;

    // 3. 读 CRLF
    let mut crlf = [0u8; 2];
    stream
        .read_exact(&mut crlf)
        .await
        .map_err(|e| crate::TrojanError::ReadCrlf(format!("read header crlf: {e}")))?;
    if crlf != CRLF {
        return Err(crate::TrojanError::ReadCrlf(format!(
            "expected CRLF, got {crlf:?}"
        )));
    }

    // 4. 读 1 字节 CMD
    let mut cmd_buf = [0u8; 1];
    stream
        .read_exact(&mut cmd_buf)
        .await
        .map_err(|e| crate::TrojanError::ReadCommand(format!("read cmd: {e}")))?;
    let network = Network::from_command(cmd_buf[0]);

    // 5. 读 addr+port（先读 ATYP 确定后续长度）
    let mut atyp_buf = [0u8; 1];
    stream
        .read_exact(&mut atyp_buf)
        .await
        .map_err(|e| crate::TrojanError::ReadAddressPort(format!("read atyp: {e}")))?;
    let atyp = atyp_buf[0];

    // 根据 ATYP 读取剩余 addr+port 字节
    let (addr, port) = match atyp {
        addr_type::IPV4 => {
            let mut buf = [0u8; 6]; // 4 IP + 2 port
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|e| crate::TrojanError::ReadAddressPort(format!("read ipv4+port: {e}")))?;
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&buf[0..4]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            (Address::IPv4(std::net::Ipv4Addr::from(ip)), port)
        }
        addr_type::DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream
                .read_exact(&mut len_buf)
                .await
                .map_err(|e| crate::TrojanError::ReadAddressPort(format!("read domain len: {e}")))?;
            let len = len_buf[0] as usize;
            let mut buf = vec![0u8; len + 2]; // domain + 2 port
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|e| crate::TrojanError::ReadAddressPort(format!("read domain+port: {e}")))?;
            let domain = String::from_utf8(buf[0..len].to_vec())
                .map_err(|_| crate::TrojanError::InvalidRemoteAddress)?;
            let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
            (Address::Domain(domain), port)
        }
        addr_type::IPV6 => {
            let mut buf = [0u8; 18]; // 16 IP + 2 port
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|e| crate::TrojanError::ReadAddressPort(format!("read ipv6+port: {e}")))?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[0..16]);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            (Address::IPv6(std::net::Ipv6Addr::from(ip)), port)
        }
        _ => {
            return Err(crate::TrojanError::ReadAddressPort(format!(
                "unknown atyp: {atyp:#x}"
            )));
        }
    };

    // 6. 读结尾 CRLF
    stream
        .read_exact(&mut crlf)
        .await
        .map_err(|e| crate::TrojanError::ReadCrlf(format!("read tail crlf: {e}")))?;
    if crlf != CRLF {
        return Err(crate::TrojanError::ReadCrlf(format!(
            "expected tail CRLF, got {crlf:?}"
        )));
    }

    Ok((network, addr, port, user))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{hex_sha224, MemoryAccount};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    fn make_validator_with_user(password: &str) -> Arc<Validator> {
        let validator = Arc::new(Validator::new());
        let account = MemoryAccount::new(password.to_string());
        let user = MemoryUser::new("user@example.com", 0, account);
        validator.add(user).unwrap();
        validator
    }

    #[tokio::test]
    async fn handshake_valid_user_ipv4_succeeds() {
        let validator = make_validator_with_user("password");
        let server = TrojanServer::new("test", validator.clone());
        server.start().await.unwrap();

        // 客户端构造完整 Trojan header
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key); // 56 字节 hex
        header.extend_from_slice(&CRLF);
        header.push(COMMAND_TCP);
        header.push(addr_type::IPV4);
        header.extend_from_slice(&[127, 0, 0, 1]); // 127.0.0.1
        header.extend_from_slice(&80u16.to_be_bytes());
        header.extend_from_slice(&CRLF);

        // 连接并发送 header
        // 注意：TrojanServer start 绑定到随机端口，但我们不知道具体端口
        // 直接测试 trojan_server_handshake 函数
        let mut buf = header.clone();
        buf.extend_from_slice(b"payload data");
        let mut cursor = std::io::Cursor::new(buf);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_ok());
        let (network, addr, port, user) = result.unwrap();
        assert_eq!(network, Network::Tcp);
        match addr {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [127, 0, 0, 1]),
            _ => panic!("expected IPv4"),
        }
        assert_eq!(port, 80);
        assert_eq!(user.email, "user@example.com");

        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn handshake_invalid_user_fails() {
        let validator = make_validator_with_user("password");
        let bad_key = hex_sha224("wrong-password");
        let mut header = Vec::new();
        header.extend_from_slice(&bad_key);
        header.extend_from_slice(&CRLF);
        header.push(COMMAND_TCP);
        header.push(addr_type::IPV4);
        header.extend_from_slice(&[127, 0, 0, 1]);
        header.extend_from_slice(&80u16.to_be_bytes());
        header.extend_from_slice(&CRLF);

        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handshake_valid_user_domain_succeeds() {
        let validator = make_validator_with_user("password");
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        header.extend_from_slice(&CRLF);
        header.push(COMMAND_TCP);
        header.push(addr_type::DOMAIN);
        let domain = b"example.com";
        header.push(domain.len() as u8);
        header.extend_from_slice(domain);
        header.extend_from_slice(&443u16.to_be_bytes());
        header.extend_from_slice(&CRLF);

        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_ok());
        let (_, addr, port, _) = result.unwrap();
        match addr {
            Address::Domain(d) => assert_eq!(d, "example.com"),
            _ => panic!("expected Domain"),
        }
        assert_eq!(port, 443);
    }

    #[tokio::test]
    async fn handshake_valid_user_ipv6_succeeds() {
        let validator = make_validator_with_user("password");
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        header.extend_from_slice(&CRLF);
        header.push(COMMAND_TCP);
        header.push(addr_type::IPV6);
        let v6 = std::net::Ipv6Addr::LOCALHOST;
        header.extend_from_slice(&v6.octets());
        header.extend_from_slice(&443u16.to_be_bytes());
        header.extend_from_slice(&CRLF);

        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_ok());
        let (_, addr, _, _) = result.unwrap();
        match addr {
            Address::IPv6(v6) => assert_eq!(v6, std::net::Ipv6Addr::LOCALHOST),
            _ => panic!("expected IPv6"),
        }
    }

    #[tokio::test]
    async fn handshake_truncated_key_fails() {
        let validator = make_validator_with_user("password");
        // 只提供 10 字节（不够 56）
        let short = vec![0u8; 10];
        let mut cursor = std::io::Cursor::new(short);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handshake_truncated_header_after_valid_key_fails() {
        let validator = make_validator_with_user("password");
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        // 缺少 CRLF + CMD + addr
        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handshake_invalid_crlf_after_key_fails() {
        let validator = make_validator_with_user("password");
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        header.extend_from_slice(b"XX"); // 不是 CRLF
        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handshake_unknown_atyp_fails() {
        let validator = make_validator_with_user("password");
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        header.extend_from_slice(&CRLF);
        header.push(COMMAND_TCP);
        header.push(0x05); // 未知 ATYP
        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn start_close_releases_listener_port() {
        // 回归测试 68n: close 后 accept loop abort，端口释放
        let validator = make_validator_with_user("password");
        let server = TrojanServer::new("test-close", validator);
        server.start().await.unwrap();
        let port = server
            .slot
            .lock()
            .await
            .as_ref()
            .and_then(|(l, _)| l.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(0);
        assert!(port > 0, "server should bind to a port");

        server.close().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let addr = format!("127.0.0.1:{port}");
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            TcpStream::connect(&addr),
        )
        .await;
        match result {
            Ok(Ok(_)) => panic!("listener should be closed after close()"),
            Ok(Err(_)) | Err(_) => {}
        }
    }
}