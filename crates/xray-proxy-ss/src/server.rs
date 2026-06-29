//! Shadowsocks 入站服务器处理器（stub），对应 Go `proxy/shadowsocks/server.go`。
//!
//! Process 流程依赖 `routing::Dispatcher` + `udp::Dispatcher` + `session::Inbound`
//! 等基础设施，当前留 trait 接口 + Noop 实现。

use crate::error::Result;
use crate::protocol::RequestHeader;
use crate::validator::{MemoryUser, Validator};

/// 入站处理器接口。
pub trait InboundProcessor: Send + Sync {
    /// 处理 TCP 连接：解码请求头，返回 RequestHeader 给上层 dispatcher。
    ///
    /// # Errors
    /// - 透传解码错误。
    fn handle_tcp(&self, validator: &Validator, buf: &[u8]) -> Result<RequestHeader>;

    /// 处理 UDP 包：解码数据包，返回 RequestHeader。
    ///
    /// # Errors
    /// - 透传解码错误。
    fn handle_udp(&self, validator: &Validator, payload: &[u8]) -> Result<RequestHeader>;
}

/// No-op 处理器：直接调 protocol 函数。
pub struct NoopInboundProcessor;

impl InboundProcessor for NoopInboundProcessor {
    fn handle_tcp(&self, validator: &Validator, buf: &[u8]) -> Result<RequestHeader> {
        crate::protocol::decode_tcp_request_header(validator, buf)
    }

    fn handle_udp(&self, validator: &Validator, payload: &[u8]) -> Result<RequestHeader> {
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
    pub fn handle_udp(&self, payload: &[u8]) -> Result<RequestHeader> {
        self.processor.handle_udp(&self.validator, payload)
    }
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

        let header = server.handle_udp(&encoded).expect("handle");
        assert_eq!(header.address, addr);
        assert_eq!(header.port, 443);
    }
}
