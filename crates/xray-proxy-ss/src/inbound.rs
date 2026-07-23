//! Shadowsocks 入站适配器：将 SS Server 包装为 dispatcher 可用的入站处理器。
//!
//! 对应 Go `proxy/shadowsocks/inbound.go::Inbound`：
//! Go 端实现 `proxy.Inbound` interface（`Network()`, `Process(TCP/UDP)`），
//! Rust 端因 SS crate 暂不依赖 dispatcher/transport 类型，故提供具体 struct + `handle_conn` 方法，
//! dispatcher 接入方可在外部包一层 trait 桥接（参考 trojan inbound 模式）。

use std::io;

use tokio::net::TcpStream;

use crate::config::MemoryAccount;
use crate::protocol::RequestHeader;
use crate::server::{read_request, Server};
use crate::stream::SSStream;
use crate::validator::MemoryUser;

/// SS 入站适配器：持有 [`Server`]（负责 SS 协议解析 + 用户验证），
/// [`handle_conn`](Self::handle_conn) 解析入站连接并返回目标头 + 加密流。
///
/// 对应 Go `proxy/shadowsocks/inbound::Inbound{validator, users}`。
pub struct SsInbound {
    server: Server,
}

impl SsInbound {
    /// 创建单用户 SS 入站适配器。
    ///
    /// # Arguments
    /// * `account` - SS 账户（cipher + key + password）
    /// * `user_email` - 用户邮箱标识（SS 单用户场景可用任意稳定字符串如 `"u@ss.local"`）
    #[must_use]
    pub fn new(account: MemoryAccount, user_email: impl Into<String>) -> Self {
        let user = MemoryUser::new(user_email, account);
        Self::with_users(vec![user])
    }

    /// 多用户构造（validator 内部维护邮箱→账户索引）。
    ///
    /// # Panics
    /// 用户列表为空时 panic（SS server 至少需要一个用户）。
    #[must_use]
    pub fn with_users(users: Vec<MemoryUser>) -> Self {
        assert!(!users.is_empty(), "SS inbound 至少需要一个用户");
        Self {
            server: Server::with_users(users),
        }
    }

    /// 从已构造的 [`Server`] 创建适配器（复用 processor 配置）。
    #[must_use]
    pub fn with_server(server: Server) -> Self {
        Self { server }
    }

    /// 处理入站 TCP 连接：读 IV + 解密首帧 + 解析目标地址 → 返回目标头 + 加密流。
    ///
    /// 底层调 [`read_request`]。当前以 validator 中**第一个用户**的 account 作为解密 key
    /// （SS AEAD 单用户场景）；多用户场景 dispatcher 应自行遍历 validator 匹配 account，
    /// 然后直接调 [`read_request`]。
    ///
    /// # Errors
    /// 返回 [`io::Error`]（`ErrorKind::Other`）当：
    /// - validator 无用户配置
    /// - SS 协议解析失败（IV/首帧读取、AEAD 初始化、地址解析）
    pub async fn handle_conn(
        &self,
        conn: TcpStream,
    ) -> io::Result<(RequestHeader, SSStream<TcpStream>)> {
        let user = self
            .server
            .validator
            .get_all()
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::other("no SS user configured"))?;

        read_request(conn, &user.account, &user.email)
            .await
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// 返回内部 [`Server`] 引用（供 dispatcher 复用用户管理 API / 测试断言）。
    #[must_use]
    pub fn server(&self) -> &Server {
        &self.server
    }
}

impl std::fmt::Debug for SsInbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsInbound")
            .field("users_count", &self.server.users_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CipherType;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

    /// 构造 AES-128-GCM 测试账户。
    fn make_account() -> MemoryAccount {
        let p = ProtoAccount {
            password: "inbound-test".to_string(),
            cipher_type: CipherType::Aes128Gcm.as_i32(),
            iv_check: false,
        };
        MemoryAccount::from_proto(&p).expect("account")
    }

    #[test]
    fn inbound_constructs_single_user() {
        let ib = SsInbound::new(make_account(), "u@ss.local");
        assert_eq!(ib.server().users_count(), 1);
    }

    #[test]
    fn inbound_with_users_multi() {
        let account = make_account();
        let users = vec![
            MemoryUser::new("u1@x.com", account.clone()),
            MemoryUser::new("u2@x.com", account),
        ];
        let ib = SsInbound::with_users(users);
        assert_eq!(ib.server().users_count(), 2);
    }

    #[test]
    #[should_panic(expected = "至少需要一个用户")]
    fn inbound_with_empty_users_panics() {
        let _ = SsInbound::with_users(vec![]);
    }

    #[test]
    fn inbound_debug_format_includes_count() {
        let ib = SsInbound::new(make_account(), "u@ss.local");
        let s = format!("{ib:?}");
        assert!(s.contains("SsInbound"), "debug should include struct name");
        assert!(
            s.contains("users_count: 1"),
            "debug should expose user count"
        );
    }

    /// 客户端发送垃圾数据：`read_request` 应在 IV 读取或 AEAD 解密阶段失败。
    /// 验证错误传播为 io::Error（非 panic）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inbound_handle_conn_rejects_garbage() {
        let ib = SsInbound::new(make_account(), "u@ss.local");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let listener_addr = listener.local_addr().unwrap();

        let ib_arc = std::sync::Arc::new(ib);
        let ib_clone = ib_arc.clone();
        let server_handle = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept");
            ib_clone.handle_conn(conn).await
        });

        // 发送 64 字节垃圾数据（够长确保 IV 读取不 EOF，但解密必然失败）
        let mut bad = TcpStream::connect(listener_addr).await.expect("connect");
        bad.write_all(&[0u8; 64]).await.expect("write garbage");
        bad.flush().await.expect("flush");
        drop(bad);

        let result = server_handle.await.expect("server task join");
        assert!(
            result.is_err(),
            "garbage input should fail SS handshake with io::Error"
        );
        // 不用 unwrap_err()：Ok 类型 (RequestHeader, SSStream) 中 SSStream 未实现 Debug
        let err = match result { Err(e) => e, Ok(_) => unreachable!("expected error") };
        assert_eq!(err.kind(), io::ErrorKind::Other, "SS error wrapped as Other");
    }
}
