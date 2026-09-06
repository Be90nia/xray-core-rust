//! SOCKS 服务端切片2——SOCKS5 handshake 端到端验证。
//!
//! 实现 [`SocksServer`]（[`InboundHandler`] trait）+ [`socks5_server_handshake`]
//! 函数。切片2 聚焦 handshake 流程（version/auth negotiation + 请求帧解析），
//! 不实现 dispatch to outbound（留切片3，依赖 dispatcher + outbound manager）。
//!
//! 对应 Go `proxy/socks/server.go` 的 `Server.handshake5` + `Server.Process`（连接处理部分）。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
    AUTH_PASSWORD, CMD_TCP_CONNECT, CMD_UDP_ASSOCIATE, SOCKS4_REQUEST_GRANTED,
    SOCKS4_REQUEST_REJECTED, SOCKS4_VERSION, SOCKS5_VERSION,
    STATUS_CMD_NOT_SUPPORT, STATUS_SUCCESS,
    Host, SocksAddr, parse_address_port,
};

/// SOCKS5 请求结果。区分 TCP CONNECT 和 UDP ASSOCIATE。
pub enum SocksRequest {
    /// TCP CONNECT 请求。包含目标地址。
    TcpConnect(SocksAddr),
    /// UDP ASSOCIATE 请求。包含 relay 地址和绑定的 UDP socket。
    UdpAssociate(SocksAddr, tokio::net::UdpSocket),
}

impl std::fmt::Debug for SocksRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocksRequest::TcpConnect(addr) => f.debug_tuple("TcpConnect").field(addr).finish(),
            SocksRequest::UdpAssociate(addr, _) => f.debug_tuple("UdpAssociate").field(addr).field(&"<UdpSocket>").finish(),
        }
    }
}


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
                            match socks_handshake(&mut stream, &config).await {
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

/// SOCKS5 服务端握手（读 VER+NMETHODS 起始）。保留为独立可用入口，
/// 兼容既有调用方与单测；内部委托 [`socks5_handshake_from_methods`]。
pub async fn socks5_server_handshake<RW>(stream: &mut RW, config: &ServerConfig) -> Result<SocksRequest>
where
    RW: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS5_VERSION {
        return Err(SocksError::HandshakeFailed(format!(
            "unsupported SOCKS version: {}",
            header[0]
        )));
    }
    socks5_handshake_from_methods(stream, header[1] as usize, config).await
}

/// SOCKS 版本路由：读首字节区分 SOCKS4/4a 与 SOCKS5，转交对应握手。
///
/// 这是 inbound 生产入口——服务端需同时兼容 SOCKS4/4a/5 客户端。
/// 对应 Go `ServerSession.handshake4` / `handshake5` 的版本分发。
pub async fn socks_handshake<RW>(stream: &mut RW, config: &ServerConfig) -> Result<SocksRequest>
where
    RW: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut ver = [0u8; 1];
    stream.read_exact(&mut ver).await?;
    match ver[0] {
        SOCKS5_VERSION => {
            let mut nm = [0u8; 1];
            stream.read_exact(&mut nm).await?;
            socks5_handshake_from_methods(stream, nm[0] as usize, config).await
        }
        SOCKS4_VERSION => socks4_handshake(stream, config).await,
        v => Err(SocksError::HandshakeFailed(format!(
            "unsupported SOCKS version: {v}"
        ))),
    }
}

/// SOCKS5 握手后半段：VER 已读，从 method 列表开始（method negotiation → auth → request）。
async fn socks5_handshake_from_methods<RW>(
    stream: &mut RW,
    nmethods: usize,
    config: &ServerConfig,
) -> Result<SocksRequest>
where
    RW: AsyncReadExt + AsyncWriteExt + Unpin,
{
    if nmethods == 0 {
        return Err(SocksError::HandshakeFailed("no auth methods offered".into()));
    }

    // 读方法列表
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // 选 method
    let (selected_method, needs_auth) = select_method(&methods, config);
    stream.write_all(&[SOCKS5_VERSION, selected_method]).await?;

    if selected_method == AUTH_NO_MATCHING_METHOD {
        return Err(SocksError::AuthFailed("no matching auth method".into()));
    }

    // 密码认证（如需）
    if needs_auth {
        authenticate_password(stream, config).await?;
    }

    // 读请求帧
    let mut req_header = [0u8; 4]; // VER, CMD, RSV, ATYP
    stream.read_exact(&mut req_header).await?;
    if req_header[0] != SOCKS5_VERSION {
        return Err(SocksError::HandshakeFailed(format!(
            "invalid request version: {}",
            req_header[0]
        )));
    }
    let cmd = req_header[1];
    if cmd != CMD_TCP_CONNECT && cmd != CMD_UDP_ASSOCIATE {
        let reply = [SOCKS5_VERSION, STATUS_CMD_NOT_SUPPORT, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
        let _ = stream.write_all(&reply).await;
        return Err(SocksError::HandshakeFailed(format!(
            "unsupported CMD: {cmd} (only CONNECT=1 and UDP_ASSOCIATE=3 supported)"
        )));
    }
    // UDP ASSOCIATE 需 udp_enabled（Go protocol.go:171-175）：未启用时回 CMD not supported 并拒绝
    if cmd == CMD_UDP_ASSOCIATE && !config.udp_enabled {
        let reply = [SOCKS5_VERSION, STATUS_CMD_NOT_SUPPORT, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
        let _ = stream.write_all(&reply).await;
        return Err(SocksError::HandshakeFailed("UDP is not enabled".into()));
    }

    // 解析地址（从 ATYP 开始读剩余字节）
    let atyp = req_header[3];
    let (addr, _consumed) = parse_address_port_from_stream(stream, atyp).await?;

    if cmd == CMD_UDP_ASSOCIATE {
        // UDP ASSOCIATE: bind UDP relay socket——配置 address 时绑定该 IP（Go protocol.go:199-205），
        // 未配置回退 127.0.0.1（既有默认行为不变）；BND.ADDR 回 relay 实际地址
        let bind_ip = config_address_ip(config);
        let relay_socket = tokio::net::UdpSocket::bind((bind_ip, 0)).await
            .map_err(SocksError::Io)?;
        let relay_addr = relay_socket.local_addr().map_err(SocksError::Io)?;

        // 回复 [VER=5, REP=0, RSV=0, ATYP, BND.ADDR, BND.PORT]
        let octets = match relay_addr {
            SocketAddr::V4(v4) => v4.ip().octets(),
            SocketAddr::V6(v6) => {
                let mut reply = vec![SOCKS5_VERSION, STATUS_SUCCESS, 0x00, ATYP_IPV6];
                reply.extend_from_slice(&v6.ip().octets());
                reply.extend_from_slice(&v6.port().to_be_bytes());
                stream.write_all(&reply).await?;
                return Ok(SocksRequest::UdpAssociate(SocksAddr::from_socket_addr(relay_addr), relay_socket));
            }
        };
        let port_bytes = relay_addr.port().to_be_bytes();
        stream.write_all(&[
            SOCKS5_VERSION, STATUS_SUCCESS, 0x00, ATYP_IPV4,
            octets[0], octets[1], octets[2], octets[3],
            port_bytes[0], port_bytes[1],
        ]).await?;

        return Ok(SocksRequest::UdpAssociate(SocksAddr::from_socket_addr(relay_addr), relay_socket));
    }

    // TCP CONNECT: 回复成功 [VER=5, REP=0, RSV=0, ATYP=1, 0.0.0.0, 0]
    stream
        .write_all(&[SOCKS5_VERSION, STATUS_SUCCESS, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;

    Ok(SocksRequest::TcpConnect(addr))
}

/// 从配置 address（IPOrDomain）提取 UDP relay 绑定 IP。
///
/// Go protocol.go:199-205：配置 address 时绑定该 IP（BND.ADDR 回同地址）；
/// 未配置 / 域名 / 字节长度非法时回退 `127.0.0.1`（既有默认行为不变）。
fn config_address_ip(config: &ServerConfig) -> IpAddr {
    use xray_proto::xray::common::net::ip_or_domain::Address as ProtoAddr;
    config
        .address
        .as_ref()
        .and_then(|a| a.address.as_ref())
        .and_then(|addr| match addr {
            ProtoAddr::Ip(bytes) => proto_bytes_to_ip(bytes),
            ProtoAddr::Domain(_) => None,
        })
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

/// prost IPOrDomain 的 IP 字节（4/16 字节）→ [`IpAddr`]；长度非法返回 `None`。
fn proto_bytes_to_ip(bytes: &[u8]) -> Option<IpAddr> {
    if let Ok([a, b, c, d]) = <[u8; 4]>::try_from(bytes) {
        return Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
    }
    <[u8; 16]>::try_from(bytes)
        .ok()
        .map(|o| IpAddr::V6(o.into()))
}

/// SOCKS4/4a 服务端握手。VER(=0x04) 已由 [`socks_handshake`] 读取，本函数从 CMD 起始。
///
/// 协议（SOCKS4）:
/// ```text
/// +----+----+----------+--------+----------+----+
/// | VN | CD | DSTPORT  | DSTIP  | USERID   |NULL|
/// | 1  | 1  |    2     |   4    | variable | 1  |
/// +----+----+----------+--------+----------+----+
/// ```
///
/// SOCKS4a：当 DSTIP = `0.0.0.x`（x≠0）时，USERID NULL 之后跟一个 null 结尾域名。
///
/// 仅支持 CONNECT（CD=1）。回复 `[VN=0, CD=90/91, DSTPORT=0, DSTIP=0]`。
/// 配置密码认证时整体拒绝（Go protocol.go:53-56）。
/// 对应 Go `ServerSession.handshake4`。
pub async fn socks4_handshake<RW>(stream: &mut RW, config: &ServerConfig) -> Result<SocksRequest>
where
    RW: AsyncReadExt + AsyncWriteExt + Unpin,
{

    // Go protocol.go:53-56：配置密码认证时 SOCKS4 整体拒绝——其 USERID 无法承载 RFC 1929 认证
    if config.auth_type == AuthType::Password {
        let _ = stream.write_all(&[0x00, SOCKS4_REQUEST_REJECTED, 0, 0, 0, 0, 0, 0]).await;
        return Err(SocksError::HandshakeFailed(
            "SOCKS4 is not allowed when auth is required".into(),
        ));
    }
    // VER(0x04) 已读；读 CMD(1) + DSTPORT(2 BE) + DSTIP(4)
    let mut buf = [0u8; 7];
    stream.read_exact(&mut buf).await?;
    let cmd = buf[0];
    let port = u16::from_be_bytes([buf[1], buf[2]]);
    let ip = Ipv4Addr::new(buf[3], buf[4], buf[5], buf[6]);

    // 读 USERID，直到 NULL
    let _userid = read_until_null(stream).await?;

    // SOCKS4a：IP = 0.0.0.x（x≠0）→ 跟一个 null 结尾域名
    let octets = ip.octets();
    let host = if octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] != 0 {
        let domain = read_until_null(stream).await?;
        Host::Domain(domain)
    } else {
        Host::Ipv4(ip)
    };

    // 仅支持 CONNECT（CD=0x01）
    if cmd != CMD_TCP_CONNECT {
        // VN=0, CD=91(rejected), port=0, ip=0
        let _ = stream.write_all(&[0x00, SOCKS4_REQUEST_REJECTED, 0, 0, 0, 0, 0, 0]).await;
        return Err(SocksError::HandshakeFailed(format!(
            "SOCKS4 unsupported CMD: {cmd} (only CONNECT=1 supported)"
        )));
    }

    // 回复 granted：VN=0, CD=90(granted), DSTPORT=0, DSTIP=0.0.0.0
    stream.write_all(&[0x00, SOCKS4_REQUEST_GRANTED, 0, 0, 0, 0, 0, 0]).await?;

    Ok(SocksRequest::TcpConnect(SocksAddr { host, port }))
}

/// 读 null 结尾的字节串，返回 UTF-8 lossy 字符串（丢弃结尾 NULL）。
async fn read_until_null<RW>(stream: &mut RW) -> Result<String>
where
    RW: AsyncReadExt + Unpin,
{
    let mut bytes = Vec::new();
    loop {
        let mut one = [0u8; 1];
        stream.read_exact(&mut one).await?;
        if one[0] == 0 {
            break;
        }
        bytes.push(one[0]);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
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
            // 严格拒绝（Go protocol.go:109-118）：配置密码认证时仅接受 0x02，不回退 0x00——回退即认证绕过
            if client_methods.contains(&AUTH_PASSWORD) {
                (AUTH_PASSWORD, true)
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
    // 回 [VER=1, STATUS=0(success)/0xFF(failure)]（Go protocol.go:130）
    stream.write_all(&[0x01, if success { 0x00 } else { 0xFF }]).await?;

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
        let socks_addr = match result.unwrap() {
            SocksRequest::TcpConnect(addr) => addr,
            other => panic!("expected TcpConnect, got {other:?}"),
        };
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
        let socks_addr = match result.unwrap() {
            SocksRequest::TcpConnect(addr) => addr,
            other => panic!("expected TcpConnect, got {other:?}"),
        };
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

    #[tokio::test]
    async fn handshake_udp_associate_returns_relay_addr() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = ServerConfig { udp_enabled: true, ..Default::default() };

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            socks5_server_handshake(&mut sock, &config).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // NoAuth negotiation
        client.write_all(&[SOCKS5_VERSION, 1, AUTH_NOT_REQUIRED]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], SOCKS5_VERSION);
        assert_eq!(resp[1], AUTH_NOT_REQUIRED);
        // Send UDP ASSOCIATE request (CMD=0x03, DST=0.0.0.0:0)
        client
            .write_all(&[
                SOCKS5_VERSION, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0,
            ])
            .await
            .unwrap();
        // Read reply: [VER=5, REP, RSV, ATYP, BND.ADDR, BND.PORT]
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], STATUS_SUCCESS, "UDP ASSOCIATE should succeed");
        // BND.ADDR should be 127.0.0.1 (the relay socket address)
        assert_eq!(reply[3], ATYP_IPV4);
        assert_eq!(&reply[4..8], &[127, 0, 0, 1]);
        // BND.PORT should be non-zero (the relay socket port)
        let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
        assert!(relay_port > 0, "relay port should be non-zero");

        // Verify server side returned UdpAssociate variant
        let result = server.await.unwrap();
        assert!(result.is_ok());
        match result.unwrap() {
            SocksRequest::UdpAssociate(relay_addr, socket) => {
                assert_eq!(relay_addr.host, crate::protocol::Host::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
                assert_eq!(relay_addr.port, relay_port);
                // Socket should be bound and usable
                assert!(socket.local_addr().is_ok());
            }
            other => panic!("expected UdpAssociate, got {other:?}"),
        }
    }

    /// 构造一个最小 SOCKS4 CONNECT 请求（无 USERID）发送到 stream。
    async fn socks4_client_connect(
        stream: &mut TcpStream,
        ip: [u8; 4],
        port: u16,
        userid: &str,
    ) {
        let mut req = vec![SOCKS4_VERSION, CMD_TCP_CONNECT];
        req.extend_from_slice(&port.to_be_bytes());
        req.extend_from_slice(&ip);
        req.extend_from_slice(userid.as_bytes());
        req.push(0x00); // NULL terminator for USERID
        stream.write_all(&req).await.unwrap();
    }

    #[tokio::test]
    async fn socks4_handshake_ipv4_connect_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = ServerConfig::default();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            socks_handshake(&mut sock, &config).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        socks4_client_connect(&mut client, [1, 2, 3, 4], 8080, "").await;

        // 读 SOCKS4 回复：[VN=0, CD, DSTPORT(2), DSTIP(4)] = 8 字节
        let mut reply = [0u8; 8];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x00, "reply VN must be 0");
        assert_eq!(reply[1], SOCKS4_REQUEST_GRANTED, "should be granted (90)");

        let result = server.await.unwrap();
        assert!(result.is_ok());
        let socks_addr = match result.unwrap() {
            SocksRequest::TcpConnect(a) => a,
            other => panic!("expected TcpConnect, got {other:?}"),
        };
        match socks_addr.host {
            Host::Ipv4(ip) => assert_eq!(ip.octets(), [1, 2, 3, 4]),
            other => panic!("expected IPv4, got {other:?}"),
        }
        assert_eq!(socks_addr.port, 8080);
    }

    #[tokio::test]
    async fn socks4a_handshake_domain_connect_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = ServerConfig::default();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            socks_handshake(&mut sock, &config).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // SOCKS4a: DSTIP = 0.0.0.1 标记域名模式
        let mut req = vec![SOCKS4_VERSION, CMD_TCP_CONNECT];
        req.extend_from_slice(&443u16.to_be_bytes());
        req.extend_from_slice(&[0, 0, 0, 1]); // 0.0.0.x (x≠0) → 4a
        req.push(0x00); // empty USERID NULL
        req.extend_from_slice(b"example.com");
        req.push(0x00); // hostname NULL terminator
        client.write_all(&req).await.unwrap();

        let mut reply = [0u8; 8];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], SOCKS4_REQUEST_GRANTED);

        let result = server.await.unwrap();
        assert!(result.is_ok());
        let socks_addr = match result.unwrap() {
            SocksRequest::TcpConnect(a) => a,
            other => panic!("expected TcpConnect, got {other:?}"),
        };
        match socks_addr.host {
            Host::Domain(d) => assert_eq!(d, "example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
        assert_eq!(socks_addr.port, 443);
    }

    #[tokio::test]
    async fn socks_handshake_routes_socks5_and_socks4() {
        // SOCKS5 走 socks5 路径（含 method negotiation），返回 TcpConnect
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let config = ServerConfig::default();
            let server = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                socks_handshake(&mut sock, &config).await
            });
            let mut client = TcpStream::connect(addr).await.unwrap();
            socks5_client_noauth_connect(&mut client, "5.6.7.8:9999").await.unwrap();
            let r = server.await.unwrap().unwrap();
            assert!(matches!(r, SocksRequest::TcpConnect(_)));
        }
        // SOCKS4 走 socks4 路径
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let config = ServerConfig::default();
            let server = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                socks_handshake(&mut sock, &config).await
            });
            let mut client = TcpStream::connect(addr).await.unwrap();
            socks4_client_connect(&mut client, [9, 9, 9, 9], 53, "user").await;
            let mut reply = [0u8; 8];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], SOCKS4_REQUEST_GRANTED);
            let r = server.await.unwrap().unwrap();
            assert!(matches!(r, SocksRequest::TcpConnect(_)));
        }
    }

    // ===== 回归：认证绕过严格拒绝（Go protocol.go:109-118, 52-56）=====

    #[tokio::test]
    async fn select_method_rejects_noauth_when_password_configured() {
        let config = ServerConfig {
            auth_type: AuthType::Password,
            ..Default::default()
        };
        let (method, needs_auth) = select_method(&[AUTH_NOT_REQUIRED], &config);
        assert_eq!(method, AUTH_NO_MATCHING_METHOD);
        assert!(!needs_auth);
    }

    #[tokio::test]
    async fn handshake_noauth_method_rejected_when_password_configured() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = ServerConfig::default();
        config.auth_type = AuthType::Password;
        config.accounts.insert("u".into(), "p".into());

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            socks5_server_handshake(&mut sock, &config).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // 客户端只声明 NoAuth（0x00）——配置密码时必须回 0xFF 拒绝
        client.write_all(&[SOCKS5_VERSION, 1, AUTH_NOT_REQUIRED]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], SOCKS5_VERSION);
        assert_eq!(resp[1], AUTH_NO_MATCHING_METHOD, "0x00 must be rejected when password auth configured");

        let result = server.await.unwrap();
        assert!(result.is_err(), "handshake must fail for NoAuth-only client");
    }

    #[tokio::test]
    async fn handshake_password_auth_still_succeeds_when_configured() {
        // 严格拒绝不得误伤合法密码认证路径
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = ServerConfig::default();
        config.auth_type = AuthType::Password;
        config.accounts.insert("u".into(), "p".into());

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            socks5_server_handshake(&mut sock, &config).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[SOCKS5_VERSION, 1, AUTH_PASSWORD]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[1], AUTH_PASSWORD);
        // RFC 1929: [VER=1, ULEN, UNAME, PLEN, PASSWD]
        client.write_all(&[0x01, 1, b'u', 1, b'p']).await.unwrap();
        let mut auth_resp = [0u8; 2];
        client.read_exact(&mut auth_resp).await.unwrap();
        assert_eq!(auth_resp, [0x01, 0x00]);
        client.write_all(&[SOCKS5_VERSION, CMD_TCP_CONNECT, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0, 80]).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], STATUS_SUCCESS);

        let result = server.await.unwrap();
        assert!(matches!(result.unwrap(), SocksRequest::TcpConnect(_)));
    }

    #[tokio::test]
    async fn socks4_rejected_when_password_configured() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = ServerConfig::default();
        config.auth_type = AuthType::Password;
        config.accounts.insert("u".into(), "p".into());

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let r = socks_handshake(&mut sock, &config).await;
            // 拒绝后服务端仍有未读请求字节，立即 drop 会发 RST 吞掉在途拒绝帧——
            // 留时间让客户端读完（Windows loopback RST 竞态，见 v49 教训）
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            r
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        socks4_client_connect(&mut client, [1, 2, 3, 4], 8080, "u").await;
        let mut reply = [0u8; 8];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], SOCKS4_REQUEST_REJECTED, "SOCKS4 must be rejected when auth required");

        let result = server.await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn udp_associate_rejected_when_udp_disabled() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = ServerConfig::default(); // udp_enabled: false（默认）

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let r = socks5_server_handshake(&mut sock, &config).await;
            // 拒绝后服务端仍有未读地址字节，立即 drop 会发 RST 吞掉在途拒绝帧——
            // 留时间让客户端读完（Windows loopback RST 竞态，见 v49 教训）
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            r
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[SOCKS5_VERSION, 1, AUTH_NOT_REQUIRED]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        client.write_all(&[SOCKS5_VERSION, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], STATUS_CMD_NOT_SUPPORT, "ASSOCIATE must get CMD_NOT_SUPPORTED when udp disabled");

        let result = server.await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn udp_associate_binds_configured_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = ServerConfig {
            udp_enabled: true,
            address: Some(xray_proto::xray::common::net::IpOrDomain {
                address: Some(xray_proto::xray::common::net::ip_or_domain::Address::Ip(vec![127, 0, 0, 9])),
            }),
            ..Default::default()
        };

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            socks5_server_handshake(&mut sock, &config).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[SOCKS5_VERSION, 1, AUTH_NOT_REQUIRED]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        client.write_all(&[SOCKS5_VERSION, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], STATUS_SUCCESS);
        // BND.ADDR = 配置的 address IP（Go protocol.go:199-205）
        assert_eq!(&reply[4..8], &[127, 0, 0, 9], "BND.ADDR must be the configured address");

        match server.await.unwrap().unwrap() {
            SocksRequest::UdpAssociate(relay_addr, socket) => {
                assert_eq!(relay_addr.host, Host::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 9)));
                assert_eq!(
                    socket.local_addr().unwrap().ip(),
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 9))
                );
            }
            other => panic!("expected UdpAssociate, got {other:?}"),
        }
    }
}
