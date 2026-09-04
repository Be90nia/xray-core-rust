//! Shadowsocks 入站服务器处理器，对应 Go `proxy/shadowsocks/server.go`。
//!
//! Process 流程依赖 `routing::Dispatcher` + `udp::Dispatcher` + `session::Inbound`
//! 等基础设施，当前留 trait 接口 + Noop 实现。
//!
//! [`read_request`] 提供单用户场景的 TCP 首帧读取 + SSStream 构造。

use crate::config::MemoryAccount;
use crate::error::Result;
use crate::protocol::{read_address_port_ss, RequestHeader};
use crate::stream::SSStream;
use crate::validator::{MemoryUser, RequestCommand, Validator};

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// 入站处理器接口。
pub trait InboundProcessor: Send + Sync {
    /// 处理 TCP 连接：解码请求头，返回 RequestHeader 给上层 dispatcher。
    ///
    /// # Errors
    /// - 透传解码错误。
    fn handle_tcp(&self, validator: &Validator, buf: &[u8]) -> Result<RequestHeader>;

    /// 处理 UDP 包：解码数据包，返回 RequestHeader + payload。
    ///
    /// # Errors
    /// - 透传解码错误。
    fn handle_udp(&self, validator: &Validator, payload: &[u8]) -> Result<(RequestHeader, Vec<u8>)>;
}

/// No-op 处理器：直接调 protocol 函数。
pub struct NoopInboundProcessor;

impl InboundProcessor for NoopInboundProcessor {
    fn handle_tcp(&self, validator: &Validator, buf: &[u8]) -> Result<RequestHeader> {
        crate::protocol::decode_tcp_request_header(validator, buf)
    }

    fn handle_udp(&self, validator: &Validator, payload: &[u8]) -> Result<(RequestHeader, Vec<u8>)> {
        crate::protocol::decode_udp_packet(validator, payload)
    }
}

/// SS 入站服务器配置，对应 Go `Server{config, validator, policyManager, cone}`。
impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("validator", &self.validator)
            .field("processor", &"<InboundProcessor>")
            .finish()
    }
}

pub struct Server {
    /// 用户验证器。
    pub validator: Validator,
    /// 处理器实现。
    pub processor: std::sync::Arc<dyn InboundProcessor>,
}

impl Server {
    /// 创建服务器。
    #[must_use]
    pub fn new(validator: Validator, processor: std::sync::Arc<dyn InboundProcessor>) -> Self {
        Self {
            validator,
            processor,
        }
    }

    /// 从用户列表创建服务器（用 NoopInboundProcessor）。
    #[must_use]
    pub fn with_users(users: Vec<MemoryUser>) -> Self {
        let validator = Validator::new();
        for user in users {
            // 这里 unwrap：构造期间失败属于配置错误
            validator.add(user).expect("add user");
        }
        Self::new(validator, std::sync::Arc::new(NoopInboundProcessor))
    }

    /// 添加用户，对应 Go `Server.AddUser`。
    ///
    /// # Errors
    /// - 透传 validator.add 错误。
    pub fn add_user(&self, user: MemoryUser) -> Result<()> {
        self.validator.add(user)
    }

    /// 通过 email 删除用户，对应 Go `Server.RemoveUser`。
    ///
    /// # Errors
    /// - 透传 validator.del 错误。
    pub fn remove_user(&self, email: &str) -> Result<()> {
        self.validator.del(email)
    }

    /// 通过 email 查找用户，对应 Go `Server.GetUser`。
    #[must_use]
    pub fn get_user(&self, email: &str) -> Option<MemoryUser> {
        self.validator.get_by_email(email)
    }

    /// 当前用户数，对应 Go `Server.GetUsersCount`。
    #[must_use]
    pub fn users_count(&self) -> u64 {
        self.validator.count()
    }

    /// 处理 TCP 连接。
    ///
    /// # Errors
    /// - 透传 processor 错误。
    pub fn handle_tcp(&self, buf: &[u8]) -> Result<RequestHeader> {
        self.processor.handle_tcp(&self.validator, buf)
    }

    /// 处理 UDP 包。
    ///
    /// # Errors
    /// - 透传 processor 错误。
    pub fn handle_udp(&self, payload: &[u8]) -> Result<(RequestHeader, Vec<u8>)> {
        self.processor.handle_udp(&self.validator, payload)
    }
}

// ============================================================================
// TCP 首帧读取（单用户场景）
// ============================================================================

/// server 端：从 TCP 连接读取首帧（addr+port）+ 构造 SSStream。
///
/// 流程：
/// 1. 读 IV（长度 = `account.cipher.iv_size()`）
/// 2. 构造 `SSStream::new_client`（nonce 从 `[0xFF;n]` 开始）
/// 3. `read_chunk` 读首帧（addr+port，SS 地址格式）
///
/// 返回的 `SSStream` 可继续 `read_chunk` 读 body。
///
/// 单用户场景（已知 account）。多用户场景需先用 validator 匹配。
///
/// # Errors
/// - [`crate::error::SsError::Io`]：TCP 读 IV/首帧失败。
/// - [`crate::error::SsError::ReadInitial`]：首帧 EOF。
/// - 透传 `SSStream` AEAD 初始化错误。
/// - 透传 `read_address_port_ss` 解析错误。
pub async fn read_request<C>(
    mut conn: C,
    account: &MemoryAccount,
    user_email: &str,
    behavior_seed: u64,
) -> Result<(RequestHeader, SSStream<C>)>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    use xray_common::drain::{BehaviorSeedLimitedDrainer, Drainer as _};

    // 反探测 drainer（bd 7me，对应 Go ReadTCPSession protocol.go:59）：
    // 失败时按 seed 派生预算排空连接，使攻击者无法从关闭时机判断认证结果。
    let drainer = BehaviorSeedLimitedDrainer::new(behavior_seed as i64, 16 + 38, 3266, 64);

    /// 失败路径统一：排空后返回原错误（4s deadline 防客户端不关连接时服务端挂起，
    /// 对齐 Go SetReadDeadline(handshake)，与 vmess inbound 同模式）。
    async fn bail(
        drainer: &BehaviorSeedLimitedDrainer,
        conn: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
        err: crate::error::SsError,
    ) -> crate::error::SsError {
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(4),
            xray_common::drain::Drainer::drain(drainer, conn),
        )
        .await;
        crate::error::SsError::Io(err.to_string())
    }

    // 读 IV
    let iv_size = account.cipher.iv_size() as usize;
    let mut iv = vec![0u8; iv_size];
    if let Err(e) = conn.read_exact(&mut iv).await {
        // ponytail: Go 此处 AcknowledgeReceive(实际读取量)；read_exact 不回报部分读量，
        // 不扣预算 = 排空量 ≥ Go（更保守的探测抵抗方向）。
        return Err(bail(&drainer, &mut conn, e.into()).await);
    }
    drainer.acknowledge_receive(iv_size);

    // 构造 SSStream（nonce 从 [0xFF;n] 开始，第一次 read_chunk → [0;n]）
    let mut stream = match SSStream::new_client(conn, account, &iv) {
        Ok(s) => s,
        Err(e) => {
            // conn 已被 new_client 消费且回收失败场景不存在（此处错误在包 conn 之前），
            // Go 对应分支同样以 FullReader 排空——但 conn 已移动，无法回收。
            // 该错误为 AEAD 构造（key/nonce 长度），不依赖网络输入，直接透传。
            return Err(e);
        }
    };

    // 读首帧（addr+port）
    let first_frame = match stream.read_chunk().await {
        Ok(Some(f)) => f,
        Ok(None) => {
            let e = crate::error::SsError::ReadInitial("EOF reading first frame".to_string());
            let mut conn = stream.into_inner();
            return Err(bail(&drainer, &mut conn, e).await);
        }
        Err(e) => {
            let mut conn = stream.into_inner();
            return Err(bail(&drainer, &mut conn, e).await);
        }
    };

    let (address, port, _) = match read_address_port_ss(&first_frame) {
        Ok(v) => v,
        Err(e) => {
            let mut conn = stream.into_inner();
            return Err(bail(&drainer, &mut conn, e).await);
        }
    };

    let header = RequestHeader {
        version: crate::VERSION,
        user: MemoryUser::new(user_email.to_string(), account.clone()),
        command: RequestCommand::Tcp,
        address,
        port,
    };
    // Go `WriteTCPResponse`（protocol.go:191-204）：响应方向必须生成新随机 IV
    // 先行写出并重派生写侧 AEAD。旧实现复用请求 IV 且不写 IV header——
    // Rust↔Rust 自洽，但 Go client 按标准先读 IV 再解密，报
    // "cipher: message authentication failed"（反向互操作实测）。
    stream
        .begin_server_response(account)
        .await
        .map_err(|e| crate::error::SsError::Io(e.to_string()))?;
 
    Ok((header, stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CipherType, MemoryAccount};
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
    fn server_with_users_initial_count() {
        let users = vec![
            MemoryUser::new(
                "u1@x.com",
                make_account(CipherType::Aes128Gcm, "p1"),
            ),
            MemoryUser::new(
                "u2@x.com",
                make_account(CipherType::Aes256Gcm, "p2"),
            ),
        ];
        let server = Server::with_users(users);
        assert_eq!(server.users_count(), 2);
    }

    #[test]
    fn server_add_remove_user() {
        let server = Server::with_users(vec![]);
        assert_eq!(server.users_count(), 0);

        server
            .add_user(MemoryUser::new(
                "u@x.com",
                make_account(CipherType::Aes128Gcm, "p"),
            ))
            .expect("add");
        assert_eq!(server.users_count(), 1);

        server.remove_user("u@x.com").expect("remove");
        assert_eq!(server.users_count(), 0);
    }

    #[test]
    fn server_get_user_by_email() {
        let server = Server::with_users(vec![MemoryUser::new(
            "u@x.com",
            make_account(CipherType::Aes128Gcm, "p"),
        )]);
        let u = server.get_user("u@x.com").expect("found");
        assert_eq!(u.email, "u@x.com");
        assert!(server.get_user("nobody@x.com").is_none());
    }

    #[test]
    fn server_handle_udp_roundtrip() {
        let account = make_account(CipherType::Aes128Gcm, "password");
        let server = Server::with_users(vec![MemoryUser::new("u@x.com", account.clone())]);

        let addr = xray_common::net::address::Address::Domain("example.com".to_string());
        let encoded =
            crate::protocol::encode_udp_packet(&account, &addr, 443, b"test payload").expect("encode");

        let (header, data) = server.handle_udp(&encoded).expect("handle");
        assert_eq!(header.address, addr);
        assert_eq!(header.port, 443);
        assert_eq!(data, b"test payload");
    }

    // ---- loopback 互通测试（client ↔ server in-process）----

    #[tokio::test]
    async fn client_server_loopback_aes_128() {
        use crate::client::Client;
        use tokio::net::TcpListener;
        use xray_common::net::address::Address;

        let account = make_account(CipherType::Aes128Gcm, "loopback-pw");

        // server: bind + accept
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let server_account = account.clone();
        let server_handle = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept");
            let (header, mut stream) = read_request(conn, &server_account, "u@x.com", 0)
                .await
                .expect("read_request");

            // 读 body chunk
            let body = stream.read_chunk().await.expect("read body").expect("body");

            // 写响应
            let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
            stream.write_chunk(resp).await.expect("write resp");
            stream.flush().await.expect("flush resp");

            (header, body)
        });

        // client: dial_target + send body + read response
        let client = Client::new(account, "127.0.0.1".to_string(), port);
        let target_addr = Address::Domain("example.com".to_string());
        let mut stream = client.dial_target_for_proxy(&target_addr, 80).await.expect("dial");

        // 发 body
        let http_req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        stream.write_chunk(http_req).await.expect("write body");
        stream.flush().await.expect("flush body");

        // 读响应
        let resp = stream.read_chunk().await.expect("read resp").expect("resp");
        assert_eq!(resp, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");

        // 验证 server 侧
        let (header, body) = server_handle.await.expect("join");
        assert_eq!(header.address, target_addr);
        assert_eq!(header.port, 80);
        assert_eq!(body, http_req);
    }

    #[tokio::test]
    async fn client_server_loopback_aes_256() {
        use crate::client::Client;
        use tokio::net::TcpListener;
        use xray_common::net::address::Address;

        let account = make_account(CipherType::Aes256Gcm, "aes256-loopback");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let server_account = account.clone();
        let server_handle = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept");
            let (_h, mut stream) = read_request(conn, &server_account, "u@x.com", 0)
                .await
                .expect("read_request");
            let body = stream.read_chunk().await.expect("read").expect("body");
            stream.write_chunk(b"resp").await.expect("write");
            stream.flush().await.expect("flush");
            body
        });

        let client = Client::new(account, "127.0.0.1".to_string(), port);
        let target = Address::Domain("test.com".to_string());
        let mut stream = client.dial_target_for_proxy(&target, 443).await.expect("dial");
        stream.write_chunk(b"ping").await.expect("write");
        stream.flush().await.expect("flush");

        let resp = stream.read_chunk().await.expect("read").expect("resp");
        assert_eq!(resp, b"resp");

        let body = server_handle.await.expect("join");
        assert_eq!(body, b"ping");
    }
}
