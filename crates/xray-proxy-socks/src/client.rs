//! SOCKS 客户端 outbound
//!
//! 对应 Go `proxy/socks/client.go::Client.Process`。
//!
//! ## 设计
//!
//! `SocksClient` 持有 server endpoint + auth 配置。`dial(target)` 流程：
//! 1. TCP 连接到 SOCKS server（`server_addr`）
//! 2. SOCKS5 version + method negotiation（NoAuth / Password）
//! 3. 如选 Password：RFC 1929 用户名/密码子协议
//! 4. CONNECT 请求透传 target → server 返回 success → stream 已就绪
//! 5. 返回 `TcpStream`（上层包装为 [`Connection`] 后双向 copy 即可）
//!
//! [`Connection`]: xray_transport::connection::Connection

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Result, SocksError};
use crate::protocol::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, AUTH_NO_MATCHING_METHOD, AUTH_NOT_REQUIRED, AUTH_PASSWORD,
    CMD_TCP_CONNECT, SOCKS5_VERSION, STATUS_SUCCESS, SocksAddr, write_address_port,
};

/// SOCKS 客户端配置：server 地址 + 可选认证。
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// SOCKS 服务器地址（`host:port`）。
    pub server_addr: String,
    /// 用户名（可选；存在时优先尝试 Password 认证）。
    pub username: Option<String>,
    /// 密码（可选；与 username 配对）。
    pub password: Option<String>,
}

impl ClientConfig {
    /// 创建 NoAuth 配置。
    #[must_use]
    pub fn new_noauth(server_addr: impl Into<String>) -> Self {
        Self { server_addr: server_addr.into(), username: None, password: None }
    }

    /// 创建带密码认证的配置。
    #[must_use]
    pub fn new_with_auth(
        server_addr: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            server_addr: server_addr.into(),
            username: Some(username.into()),
            password: Some(password.into()),
        }
    }
}

/// SOCKS 客户端：拨号到 SOCKS server，SOCKS5 handshake 后返回 `TcpStream`。
///
/// 对应 Go `proxy/socks/client.go::Client`。无状态（每次 dial 都新建连接），
/// `SocksClient` 仅作为配置载体。
pub struct SocksClient {
    config: ClientConfig,
}

impl SocksClient {
    #[must_use]
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// 暴露内部配置（测试用）。
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// 拨号到 `target`（经 SOCKS server 中转）。返回建立好的 `TcpStream`。
    ///
    /// 流程见模块文档。
    pub async fn dial(&self, target: &SocksAddr) -> Result<TcpStream> {
        let mut stream = TcpStream::connect(&self.config.server_addr).await.map_err(|e| {
            SocksError::HandshakeFailed(format!("connect to socks server {}: {e}", self.config.server_addr))
        })?;

        // 1. method negotiation
        // Go protocol.go:443-447：按凭据有无二选一只发 1 个 method
        //（带凭据 [05 01 02] / 无凭据 [05 01 00]；发两个 method 的
        // [05 02 00 02] 是 DPI 可辨的 Rust 指纹，票 g6kn）。
        let auth_method: u8 = if self.config.username.is_some() {
            AUTH_PASSWORD
        } else {
            AUTH_NOT_REQUIRED
        };
        stream.write_all(&[SOCKS5_VERSION, 0x01, auth_method]).await?;

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;
        if resp[0] != SOCKS5_VERSION {
            return Err(SocksError::HandshakeFailed(format!(
                "invalid SOCKS version in method response: {}",
                resp[0]
            )));
        }
        let method = resp[1];

        // 2. 处理选定的 method
        match method {
            AUTH_NOT_REQUIRED => {}
            AUTH_PASSWORD => {
                let (u, p) = match (&self.config.username, &self.config.password) {
                    (Some(u), Some(p)) => (u.as_str(), p.as_str()),
                    _ => {
                        return Err(SocksError::AuthFailed(
                            "server picked password auth but client provided no credentials".into(),
                        ));
                    }
                };
                Self::auth_password(&mut stream, u, p).await?;
            }
            AUTH_NO_MATCHING_METHOD => {
                return Err(SocksError::AuthFailed("server returned no matching method".into()));
            }
            other => {
                return Err(SocksError::HandshakeFailed(format!(
                    "server picked unknown method: {other:#x}"
                )));
            }
        }

        // 3. CONNECT 请求
        let mut req = vec![SOCKS5_VERSION, CMD_TCP_CONNECT, 0x00];
        let _ = write_address_port(&mut req, target);
        stream.write_all(&req).await?;

        // 4. 读响应头 [VER, REP, RSV, ATYP]
        let mut resp_header = [0u8; 4];
        stream.read_exact(&mut resp_header).await?;
        if resp_header[0] != SOCKS5_VERSION {
            return Err(SocksError::HandshakeFailed(format!(
                "invalid version in connect response: {}",
                resp_header[0]
            )));
        }
        if resp_header[1] != STATUS_SUCCESS {
            return Err(SocksError::HandshakeFailed(format!(
                "connect request rejected with status: {}",
                resp_header[1]
            )));
        }

        // 5. 读 BND.ADDR + BND.PORT（按 ATYP 决定长度，丢弃——上层不用）
        let atyp = resp_header[3];
        let addr_len = match atyp {
            ATYP_IPV4 => 4,
            ATYP_IPV6 => 16,
            ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                len_buf[0] as usize
            }
            other => {
                return Err(SocksError::InvalidFrame(format!(
                    "unknown ATYP in connect response: {other:#x}"
                )));
            }
        };
        let mut rest = vec![0u8; addr_len + 2];
        stream.read_exact(&mut rest).await?;

        Ok(stream)
    }

    /// RFC 1929 用户名/密码子协议。
    async fn auth_password(stream: &mut TcpStream, username: &str, password: &str) -> Result<()> {
        let ub = username.as_bytes();
        let pb = password.as_bytes();
        if ub.len() > 255 || pb.len() > 255 {
            return Err(SocksError::AuthFailed(
                "username/password exceeds 255 bytes".into(),
            ));
        }
        let mut buf = Vec::with_capacity(3 + ub.len() + pb.len());
        buf.push(0x01); // RFC 1929 版本
        buf.push(ub.len() as u8);
        buf.extend_from_slice(ub);
        buf.push(pb.len() as u8);
        buf.extend_from_slice(pb);
        stream.write_all(&buf).await?;

        let mut auth_resp = [0u8; 2];
        stream.read_exact(&mut auth_resp).await?;
        if auth_resp[0] != 0x01 {
            return Err(SocksError::AuthFailed(format!(
                "invalid auth sub-negotiation version: {}",
                auth_resp[0]
            )));
        }
        if auth_resp[1] != 0x00 {
            return Err(SocksError::AuthFailed(format!(
                "auth failed with status: {}",
                auth_resp[1]
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::server::socks5_server_handshake;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// 启动一个 mock SOCKS5 server：完成 handshake，然后把 client 的流量 echo 给 target。
    /// 用于 e2e 验证 client handshake 正确 + 数据流透传。
    fn start_echo_socks_server(
        listener: TcpListener,
        server_config: ServerConfig,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut sock, _)) => {
                        let cfg = server_config.clone();
                        tokio::spawn(async move {
                            // 1. handshake 解析 client 想连哪
                            let target = match socks5_server_handshake(&mut sock, &cfg).await {
                                Ok(t) => t,
                                Err(_) => return,
                            };
                            // 2. ponytail: mock 不真去连 target，直接 echo
                            //    （target 在握手成功后已透明——client 写啥我们 echo 回去）
                            let _ = target;
                            let mut buf = [0u8; 1024];
                            loop {
                                match sock.read(&mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        if sock.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                            let _ = sock;
                        });
                    }
                    Err(_) => break,
                }
            }
        })
    }

    #[tokio::test]
    async fn dial_noauth_handshake_succeeds_and_echoes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = start_echo_socks_server(listener, ServerConfig::default());

        let client = SocksClient::new(ClientConfig::new_noauth(server_addr.to_string()));
        let target = SocksAddr::domain("example.com", 443);
        let mut stream = client.dial(&target).await.expect("dial succeed");

        // 验证 echo 通道
        stream.write_all(b"hello socks").await.unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(&buf[..n], b"hello socks");

        server.abort();
    }

    #[tokio::test]
    async fn dial_password_handshake_succeeds() {
        // 启动带密码的 SOCKS server
        let mut accounts = std::collections::HashMap::new();
        accounts.insert("user1".to_string(), "pass1".to_string());
        let server_cfg = ServerConfig {
            auth_type: crate::config::AuthType::Password,
            accounts,
            ..Default::default()
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = start_echo_socks_server(listener, server_cfg.clone());

        let client = SocksClient::new(ClientConfig::new_with_auth(
            server_addr.to_string(),
            "user1",
            "pass1",
        ));
        let target = SocksAddr::ipv4(std::net::Ipv4Addr::new(1, 2, 3, 4), 80);
        let mut stream = client.dial(&target).await.expect("dial succeed");

        stream.write_all(b"auth ok").await.unwrap();
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"auth ok");

        server.abort();
    }

    #[tokio::test]
    async fn dial_wrong_password_rejected() {
        let mut accounts = std::collections::HashMap::new();
        accounts.insert("user1".to_string(), "correct".to_string());
        let server_cfg = ServerConfig {
            auth_type: crate::config::AuthType::Password,
            accounts,
            ..Default::default()
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = start_echo_socks_server(listener, server_cfg);

        let client = SocksClient::new(ClientConfig::new_with_auth(
            server_addr.to_string(),
            "user1",
            "wrong",
        ));
        let target = SocksAddr::ipv4(std::net::Ipv4Addr::LOCALHOST, 80);
        let r = client.dial(&target).await;
        assert!(r.is_err(), "wrong password should fail handshake");
        server.abort();
    }

    #[tokio::test]
    async fn dial_to_unreachable_server_fails() {
        // 用一个保证未监听的端口
        let client = SocksClient::new(ClientConfig::new_noauth("127.0.0.1:1"));
        let target = SocksAddr::ipv4(std::net::Ipv4Addr::LOCALHOST, 80);
        let r = client.dial(&target).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn dial_with_credentials_sends_single_method_0x02() {
        // g6kn（Go protocol.go:443-447）：带凭据只发 1 个 method，首包字节
        // 必须 [05 01 02]；此前发 [05 02 00 02]（nmethods=2）是 DPI 可辨指纹。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let acceptor = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut first = [0u8; 3];
            sock.read_exact(&mut first).await.unwrap();
            first
        });
        let client = SocksClient::new(ClientConfig::new_with_auth(
            server_addr.to_string(),
            "user1",
            "pass1",
        ));
        let target = SocksAddr::ipv4(std::net::Ipv4Addr::LOCALHOST, 80);
        // server 不回 method 响应即断开 → dial Err 可忽略，断言点在首包字节
        let _ = client.dial(&target).await;
        let first = acceptor.await.unwrap();
        assert_eq!(first, [SOCKS5_VERSION, 0x01, AUTH_PASSWORD]);
    }

    #[test]
    fn config_noauth_constructor() {
        let c = ClientConfig::new_noauth("1.2.3.4:1080");
        assert_eq!(c.server_addr, "1.2.3.4:1080");
        assert!(c.username.is_none());
        assert!(c.password.is_none());
    }

    #[test]
    fn config_with_auth_constructor() {
        let c = ClientConfig::new_with_auth("1.2.3.4:1080", "u", "p");
        assert_eq!(c.server_addr, "1.2.3.4:1080");
        assert_eq!(c.username.as_deref(), Some("u"));
        assert_eq!(c.password.as_deref(), Some("p"));
    }
}
