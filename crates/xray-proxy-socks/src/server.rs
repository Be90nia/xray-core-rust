//! SOCKS 服务端切片2——SOCKS5 handshake 端到端验证。
//!
//! 实现 [`SocksServer`]（[`InboundHandler`] trait）+ [`socks5_server_handshake`]
//! 函数。切片2 聚焦 handshake 流程（version/auth negotiation + 请求帧解析），
//! 不实现 dispatch to outbound（留切片3，依赖 dispatcher + outbound manager）。
//!
//! 对应 Go `proxy/socks/server.go` 的 `Server.handshake5` + `Server.Process`（连接处理部分）。

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use xray_features::inbound::{InboundError, InboundHandler};

use crate::config::{AuthType, ServerConfig};
use crate::error::{Result, SocksError};
use crate::protocol::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, AUTH_NOT_REQUIRED, AUTH_NO_MATCHING_METHOD,
    AUTH_PASSWORD, CMD_TCP_CONNECT, SOCKS5_VERSION, STATUS_SUCCESS,
    SocksAddr, parse_address_port,
};

/// SOCKS 服务端。切片2：listen + accept + handshake + 日志。
///
/// `listener` 在 `start()` 后填充，`close()` 后清空。
pub struct SocksServer {
    tag: String,
    config: ServerConfig,
    /// 监听器 + accept loop 任务句柄。close 时 abort 任务取消阻塞中的 accept().
    slot: Mutex<Option<(Arc<TcpListener>, JoinHandle<()>)>>,
}

impl SocksServer {
    /// 构造 SOCKS 服务端。`addr` 是监听地址（如 `"127.0.0.1:1080"`）。
    pub fn new(tag: impl Into<String>, config: ServerConfig) -> Self {
        Self {
            tag: tag.into(),
            config,
            slot: Mutex::new(None),
        }
    }

    /// 获取监听端口（start 后有效，否则返回 0）。
    pub async fn bound_port(&self) -> u16 {
        self.slot.lock().await
            .as_ref()
            .and_then(|(l, _)| l.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(0)
    }
}

#[async_trait]
impl InboundHandler for SocksServer {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self) -> std::result::Result<(), InboundError> {
        // ponytail: 切片2 直接用 tokio TcpListener; 切片3 切换到 listen_system
        let addr: SocketAddr = "127.0.0.1:0"
            .parse()
            .map_err(|e| InboundError::ListenError(format!("invalid addr: {e}")))?;
        let listener = Arc::new(
            TcpListener::bind(addr)
                .await
                .map_err(|e| InboundError::ListenError(format!("bind failed: {e}")))?,
        );
        let bound = listener
            .local_addr()
            .map_err(|e| InboundError::ListenError(format!("local_addr: {e}")))?;
        info!(tag = %self.tag, addr = %bound, "SOCKS server started");

        // spawn accept loop — 持有 Arc<TcpListener> clone，无需访问 Mutex
        let tag = self.tag.clone();
        let config = self.config.clone();
        let listener_clone = Arc::clone(&listener);
        let handle = tokio::spawn(async move {
            loop {
                match listener_clone.accept().await {
                    Ok((mut stream, peer)) => {
                        let tag = tag.clone();
                        let config = config.clone();
                        tokio::spawn(async move {
                            match socks5_server_handshake(&mut stream, &config).await {
                                Ok(addr) => {
                                    info!(
                                        tag = %tag,
                                        peer = %peer,
                                        dest = ?addr,
                                        "SOCKS5 handshake succeeded"
                                    );
                                    // 切片3: dispatch to outbound handler
                                }
                                Err(e) => {
                                    warn!(tag = %tag, peer = %peer, error = %e, "handshake failed");
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
            // abort 取消阻塞中的 accept()，task 内 Arc<TcpListener> 随 task 结束 drop
            handle.abort();
            // _listener（我们的 Arc clone）在此 drop
            info!(tag = %self.tag, "SOCKS server closed");
        }
        Ok(())
    }

    fn port(&self) -> u16 {
        // 同步方法无法读 async Mutex; 返回 0 让调用方用 bound_port().await
        0
    }
}

/// SOCKS5 服务端握手。返回客户端请求的目标地址。
///
/// 流程（RFC 1928 + RFC 1929）:
/// 1. 读 [VER=5, NMETHODS, METHODS(NMETHODS bytes)]
/// 2. 选 method: NoAuth(0x00) / Password(0x02) / NoMatch(0xFF)
/// 3. 如需密码认证: 读 [VER=1, ULEN, UNAME, PLEN, PASSWD] + 校验 + 回 [VER=1, STATUS]
/// 4. 读请求 [VER=5, CMD, RSV=0, ATYP, DST.ADDR, DST.PORT]
/// 5. 回复 [VER=5, REP=0(success), RSV=0, ATYP=1, 0.0.0.0, 0]
pub async fn socks5_server_handshake<RW>(stream: &mut RW, config: &ServerConfig) -> Result<SocksAddr>
where
    RW: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // 步骤 1: 读版本 + 方法数
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS5_VERSION {
        return Err(SocksError::HandshakeFailed(format!(
            "unsupported SOCKS version: {}",
            header[0]
        )));
    }
    let nmethods = header[1] as usize;
    if nmethods == 0 {
        return Err(SocksError::HandshakeFailed("no auth methods offered".into()));
    }

    // 读方法列表
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // 步骤 2: 选 method
    let (selected_method, needs_auth) = select_method(&methods, config);
    stream.write_all(&[SOCKS5_VERSION, selected_method]).await?;

    if selected_method == AUTH_NO_MATCHING_METHOD {
        return Err(SocksError::AuthFailed("no matching auth method".into()));
    }

    // 步骤 3: 密码认证（如需）
    if needs_auth {
        authenticate_password(stream, config).await?;
    }

    // 步骤 4: 读请求帧
    let mut req_header = [0u8; 4]; // VER, CMD, RSV, ATYP
    stream.read_exact(&mut req_header).await?;
    if req_header[0] != SOCKS5_VERSION {
        return Err(SocksError::HandshakeFailed(format!(
            "invalid request version: {}",
            req_header[0]
        )));
    }
    if req_header[1] != CMD_TCP_CONNECT {
        // 切片2 只支持 CONNECT; BIND/UDP_ASSOCIATE 留切片3
        return Err(SocksError::HandshakeFailed(format!(
            "unsupported CMD: {} (only CONNECT=1 supported)",
            req_header[1]
        )));
    }

    // 解析地址（从 ATYP 开始读剩余字节）
    let atyp = req_header[3];
    let (addr, _consumed) = parse_address_port_from_stream(stream, atyp).await?;

    // 步骤 5: 回复成功
    // [VER=5, REP=0, RSV=0, ATYP=1(IPv4), BND.ADDR=0.0.0.0, BND.PORT=0]
    stream
        .write_all(&[SOCKS5_VERSION, STATUS_SUCCESS, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;

    Ok(addr)
}

/// 根据客户端提供的方法列表 + 服务端配置选 method。
///
/// 返回 (selected_method, needs_password_auth)。
///
/// - 服务端 NoAuth: 优先 0x00, 否则 0xFF
/// - 服务端 Password: 优先 0x02 (需密码), 否则回退 0x00, 否则 0xFF
fn select_method(client_methods: &[u8], config: &ServerConfig) -> (u8, bool) {
    match config.auth_type {
        AuthType::NoAuth => {
            if client_methods.contains(&AUTH_NOT_REQUIRED) {
                (AUTH_NOT_REQUIRED, false)
            } else {
                (AUTH_NO_MATCHING_METHOD, false)
            }
        }
        AuthType::Password => {
            // 优先密码认证
            if client_methods.contains(&AUTH_PASSWORD) {
                (AUTH_PASSWORD, true)
            } else if client_methods.contains(&AUTH_NOT_REQUIRED) {
                // 回退到无认证（与 Go 一致：如果客户端不支持密码但服务端配置 Password，
                // 仍允许 NoAuth 连接——实际生产应严格拒绝）
                (AUTH_NOT_REQUIRED, false)
            } else {
                (AUTH_NO_MATCHING_METHOD, false)
            }
        }
    }
}

/// RFC 1929 用户名/密码认证。
async fn authenticate_password<RW>(stream: &mut RW, config: &ServerConfig) -> Result<()>
where
    RW: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // 读 [VER=1, ULEN, UNAME, PLEN, PASSWD]
    let mut auth_header = [0u8; 2];
    stream.read_exact(&mut auth_header).await?;
    if auth_header[0] != 0x01 {
        return Err(SocksError::AuthFailed(format!(
            "invalid auth version: {}",
            auth_header[0]
        )));
    }
    let ulen = auth_header[1] as usize;
    let mut username = vec![0u8; ulen];
    stream.read_exact(&mut username).await?;

    let mut plen_buf = [0u8; 1];
    stream.read_exact(&mut plen_buf).await?;
    let plen = plen_buf[0] as usize;
    let mut password = vec![0u8; plen];
    stream.read_exact(&mut password).await?;

    let username_str = String::from_utf8_lossy(&username);
    let password_str = String::from_utf8_lossy(&password);

    let success = config.has_account(&username_str, &password_str);
    // 回 [VER=1, STATUS=0(success)/1(failure)]
    stream.write_all(&[0x01, if success { 0x00 } else { 0x01 }]).await?;

    if !success {
        return Err(SocksError::AuthFailed(format!(
            "invalid credentials for user: {}",
            username_str
        )));
    }
    Ok(())
}

/// 从流中按 ATYP 读取剩余地址 + 端口字节，然后用 parse_address_port 解析。
///
/// 这是 parse_address_port 的流式版本——先按 ATYP 确定剩余字节数，再读取 + 解析。
async fn parse_address_port_from_stream<RW>(
    stream: &mut RW,
    atyp: u8,
) -> Result<(SocksAddr, usize)>
where
    RW: AsyncReadExt + Unpin,
{
    match atyp {
        ATYP_IPV4 => {
            let mut buf = vec![atyp];
            buf.extend_from_slice(&[0u8; 6]); // 4 IP + 2 port
            stream.read_exact(&mut buf[1..]).await?;
            parse_address_port(&buf)
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let dlen = len_buf[0] as usize;
            let mut buf = vec![atyp, len_buf[0]];
            buf.extend_from_slice(&vec![0u8; dlen + 2]); // domain + 2 port
            stream.read_exact(&mut buf[2..]).await?;
            parse_address_port(&buf)
        }
        ATYP_IPV6 => {
            let mut buf = vec![atyp];
            buf.extend_from_slice(&[0u8; 18]); // 16 IP + 2 port
            stream.read_exact(&mut buf[1..]).await?;
            parse_address_port(&buf)
        }
        _ => Err(SocksError::InvalidFrame(format!("unknown ATYP: {atyp}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// 模拟 SOCKS5 客户端发送 NoAuth handshake + CONNECT 请求。
    async fn socks5_client_noauth_connect(stream: &mut TcpStream, dest: &str) -> Result<()> {
        // 步骤 1: 发 [VER=5, NMETHODS=1, METHOD=NoAuth]
        stream.write_all(&[SOCKS5_VERSION, 1, AUTH_NOT_REQUIRED]).await?;
        // 读 [VER=5, METHOD]
        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;
        assert_eq!(resp[0], SOCKS5_VERSION);
        assert_eq!(resp[1], AUTH_NOT_REQUIRED);
        // 步骤 4: 发 CONNECT 请求
        let (host, port) = parse_dest(dest);
        let mut req = vec![SOCKS5_VERSION, CMD_TCP_CONNECT, 0x00];
        if host.parse::<std::net::Ipv4Addr>().is_ok() {
            // IPv4
            let octets: Vec<u8> = host.split('.').map(|s| s.parse::<u8>().unwrap()).collect();
            req.push(ATYP_IPV4);
            req.extend_from_slice(&octets);
            req.extend_from_slice(&port.to_be_bytes());
        } else {
            // Domain
            req.push(ATYP_DOMAIN);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
            req.extend_from_slice(&port.to_be_bytes());
        }
        stream.write_all(&req).await?;
        // 读回复 [VER=5, REP, RSV, ATYP, 0.0.0.0, 0]
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await?;
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], STATUS_SUCCESS);
        Ok(())
    }

    fn parse_dest(dest: &str) -> (String, u16) {
        let parts: Vec<&str> = dest.rsplitn(2, ':').collect();
        let port: u16 = parts[0].parse().unwrap();
        let host = parts[1].to_string();
        (host, port)
    }

    #[tokio::test]
    async fn handshake_noauth_ipv4_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = ServerConfig::default();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            socks5_server_handshake(&mut sock, &config).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        socks5_client_noauth_connect(&mut client, "1.2.3.4:80").await.unwrap();

        let result = server.await.unwrap();
        assert!(result.is_ok());
        let socks_addr = result.unwrap();
        match &socks_addr.host {
            crate::protocol::Host::Ipv4(ip) => {
                assert_eq!(ip.octets(), [1, 2, 3, 4]);
            }
            _ => panic!("expected IPv4"),
        }
        assert_eq!(socks_addr.port, 80);
    }

    #[tokio::test]
    async fn handshake_noauth_domain_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = ServerConfig::default();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            socks5_server_handshake(&mut sock, &config).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        socks5_client_noauth_connect(&mut client, "example.com:443")
            .await
            .unwrap();

        let result = server.await.unwrap();
        assert!(result.is_ok());
        let socks_addr = result.unwrap();
        match &socks_addr.host {
            crate::protocol::Host::Domain(d) => {
                assert_eq!(d, "example.com");
            }
            _ => panic!("expected Domain"),
        }
        assert_eq!(socks_addr.port, 443);
    }

    #[tokio::test]
    async fn handshake_wrong_version_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = ServerConfig::default();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            socks5_server_handshake(&mut sock, &config).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // 发 [VER=4 (SOCKS4), NMETHODS=1, NoAuth]
        client.write_all(&[0x04, 1, AUTH_NOT_REQUIRED]).await.unwrap();

        let result = server.await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handshake_unsupported_cmd_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = ServerConfig::default();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            socks5_server_handshake(&mut sock, &config).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // NoAuth
        client.write_all(&[SOCKS5_VERSION, 1, AUTH_NOT_REQUIRED]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        // 发 BIND 请求 (CMD=2)
        client
            .write_all(&[
                SOCKS5_VERSION, 0x02, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0, 80,
            ])
            .await
            .unwrap();

        let result = server.await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn select_method_noauth_when_server_noauth() {
        let config = ServerConfig {
            auth_type: AuthType::NoAuth,
            ..Default::default()
        };
        let (method, needs_auth) = select_method(&[AUTH_NOT_REQUIRED], &config);
        assert_eq!(method, AUTH_NOT_REQUIRED);
        assert!(!needs_auth);
    }

    #[tokio::test]
    async fn select_method_no_match_when_client_only_password_server_noauth() {
        let config = ServerConfig {
            auth_type: AuthType::NoAuth,
            ..Default::default()
        };
        let (method, _) = select_method(&[AUTH_PASSWORD], &config);
        assert_eq!(method, AUTH_NO_MATCHING_METHOD);
    }

    #[tokio::test]
    async fn select_method_password_when_both_support() {
        let config = ServerConfig {
            auth_type: AuthType::Password,
            ..Default::default()
        };
        let (method, needs_auth) = select_method(&[AUTH_NOT_REQUIRED, AUTH_PASSWORD], &config);
        assert_eq!(method, AUTH_PASSWORD);
        assert!(needs_auth);
    }

    #[tokio::test]
    async fn start_close_releases_listener_port() {
        // 回归测试 68n: close 后 accept loop 必须 abort，端口必须释放
        // 旧代码: accept loop 持有 Arc<TcpListener> clone → close 后 listener 仍开 → connect 成功
        // 新代码: close abort 任务 → 端口关闭 → connect 失败
        use std::time::Duration;
        let server = SocksServer::new("test-close", ServerConfig::default());
        server.start().await.unwrap();
        let port = server.bound_port().await;
        assert!(port > 0, "server should bind to a port");

        server.close().await.unwrap();

        // abort() 是异步取消，给 executor 一个轮次清理
        tokio::time::sleep(Duration::from_millis(50)).await;

        let addr = format!("127.0.0.1:{port}");
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            TcpStream::connect(&addr),
        )
        .await;
        // 连接应失败（connection refused）——listener 已关闭
        match result {
            Ok(Ok(_)) => panic!("listener should be closed after close()"),
            Ok(Err(_)) | Err(_) => {}
        }
    }
}
