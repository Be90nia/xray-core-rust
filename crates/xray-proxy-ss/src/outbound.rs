//! Shadowsocks 出站适配器：将 SS Client 包装为 dispatcher 可用的出站处理器。
//!
//! 对应 Go `proxy/shadowsocks/outbound.go::Outbound`：
//! Go 端实现 `proxy.Outbound` interface（`Process(Request, *Reply, OutboundHandler)`），
//! Rust 端因 SS crate 暂不依赖 dispatcher/transport 类型，故提供具体 struct + `process` 方法，
//! dispatcher 接入方可在外部包一层 trait 桥接（参考 vless outbound/handler 模式）。

use std::io;

use tokio::net::TcpStream;
use xray_common::net::address::Address;

use crate::client::Client;
use crate::config::MemoryAccount;
use crate::stream::SSStream;

/// SS 出站适配器：持有 [`Client`]（负责 TCP 拨号 + SS 加密），
/// [`process`](Self::process) 把目标地址包装为 SS 加密流。
///
/// 对应 Go `proxy/shadowsocks/outbound::Outbound{server *ServerImpl}`。
#[derive(Clone)]
pub struct SsOutbound {
    client: Client,
}

impl SsOutbound {
    /// 创建 SS 出站适配器。
    ///
    /// # Arguments
    /// * `account` - SS 账户（含 cipher + key + password）
    /// * `server_host` - SS 服务端地址（域名或 IP 字符串）
    /// * `server_port` - SS 服务端端口
    #[must_use]
    pub fn new(account: MemoryAccount, server_host: String, server_port: u16) -> Self {
        Self {
            client: Client::new(account, server_host, server_port),
        }
    }

    /// 从已构造的 [`Client`] 创建适配器（复用 dialer 配置 / 测试场景）。
    #[must_use]
    pub fn with_client(client: Client) -> Self {
        Self { client }
    }

    /// 拨号到 SS 服务端并写目标地址头，返回加密流供上层写 body。
    ///
    /// 底层调 [`Client::dial_target`]：TCP connect → 写随机 IV →
    /// 构造 `SSStream` → 写首帧（SS 地址格式 addr+port）。
    ///
    /// # Errors
    /// 返回 [`io::Error`]（`ErrorKind::Other`）当 TCP 连接失败、
    /// AEAD 初始化失败或写首帧失败。错误信息携带原始 [`crate::error::SsError`] 描述。
    pub async fn process(
        &self,
        addr: &Address,
        port: u16,
    ) -> io::Result<SSStream<TcpStream>> {
        self.client
            .dial_target(addr, port)
            .await
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// 返回内部 [`Client`] 引用（供 dispatcher 复用账户配置 / 测试断言）。
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }
}

impl std::fmt::Debug for SsOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsOutbound")
            .field("client", &self.client)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CipherType;
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

    /// 构造 AES-128-GCM 测试账户。
    fn make_account() -> MemoryAccount {
        let p = ProtoAccount {
            password: "outbound-test".to_string(),
            cipher_type: CipherType::Aes128Gcm.as_i32(),
            iv_check: false,
        };
        MemoryAccount::from_proto(&p).expect("account")
    }

    #[test]
    fn outbound_constructs_and_exposes_client() {
        let ob = SsOutbound::new(make_account(), "127.0.0.1".to_string(), 8388);
        assert_eq!(ob.client().server_host, "127.0.0.1");
        assert_eq!(ob.client().server_port, 8388);
    }

    #[test]
    fn outbound_with_client_preserves_config() {
        let account = make_account();
        let client = Client::new(account, "example.com".to_string(), 9999);
        let ob = SsOutbound::with_client(client);
        assert_eq!(ob.client().server_host, "example.com");
        assert_eq!(ob.client().server_port, 9999);
    }

    #[test]
    fn outbound_debug_format_includes_server() {
        let ob = SsOutbound::new(make_account(), "1.2.3.4".to_string(), 443);
        let s = format!("{ob:?}");
        assert!(s.contains("SsOutbound"), "debug should include struct name");
        assert!(s.contains("1.2.3.4:443"), "debug should include server endpoint");
    }

    #[test]
    fn outbound_clone_is_independent_handle() {
        let ob = SsOutbound::new(make_account(), "host".to_string(), 8080);
        let cloned = ob.clone();
        assert_eq!(cloned.client().server_port, 8080);
        assert_eq!(cloned.client().server_host, "host");
    }

    /// 拨号到刚释放的端口必定失败，验证错误传播路径（非 panic、返回 io::Error）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn outbound_process_to_dead_port_returns_io_error() {
        // 绑定并立即 drop，确保端口已释放（多数 OS 会拒绝连接）
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind temp listener");
        let dead_port = listener.local_addr().unwrap().port();
        drop(listener);

        let ob = SsOutbound::new(make_account(), "127.0.0.1".to_string(), dead_port);
        let result = ob
            .process(&Address::IPv4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 1)
            .await;
        assert!(
            result.is_err(),
            "process to dead SS server port should return io::Error"
        );
        // 不用 unwrap_err()：Ok 类型 SSStream 未实现 Debug
        let err = match result { Err(e) => e, Ok(_) => unreachable!("expected error") };
        assert_eq!(err.kind(), io::ErrorKind::Other, "SS error wrapped as Other");
    }
}
