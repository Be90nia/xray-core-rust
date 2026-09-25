//! VLESS 用户 Validator（对应 Go `proxy/vless/validator.go`）。
//!
//! 维护 UUID → MemoryUser 的索引，支持按 UUID/email 增删查。
//! `MemoryValidator` 是默认实现，用 `parking_lot::RwLock<HashMap>` 替代 Go `sync.Map`。

use std::{collections::HashMap, sync::Arc};

use parking_lot::RwLock;
use xray_common::uuid::UUID;

use crate::{
    account::MemoryAccount,
    error::{Result, VlessError},
};

/// Validator 接口（对应 Go `vless.Validator` interface）。
///
/// 所有方法都是同步的（无 IO），可跨线程共享（`Send + Sync`）。
pub trait Validator: Send + Sync {
    /// 按 UUID 查找用户，未找到返回 `None`。
    fn get(&self, id: &UUID) -> Option<MemoryUser>;

    /// 添加用户；email 非空时必须唯一。
    fn add(&self, u: MemoryUser) -> Result<()>;

    /// 按 email 删除用户。
    fn del(&self, email: &str) -> Result<()>;

    /// 按 email 查找用户。
    fn get_by_email(&self, email: &str) -> Option<MemoryUser>;

    /// 返回所有用户的列表。
    fn get_all(&self) -> Vec<MemoryUser>;

    /// 返回用户数量（Go `GetCount` 语义：只数 email 表）。
    fn get_count(&self) -> i64;

    /// 返回可被 UUID 认证的用户数量（UUID 索引大小）。
    ///
    /// 生产配置的 client 通常不带 email（`get_count` 恒 0，Go 同语义）；
    /// 启动日志/可观测性展示「已载入用户数」应使用本方法。
    fn get_uuid_count(&self) -> i64;
}

/// 运行时 VLESS 用户（对应 Go `protocol.MemoryUser` + 类型化 Account）。
#[derive(Debug, Clone)]
pub struct MemoryUser {
    /// 权限等级（0=普通用户）。
    pub level: u32,
    /// 用户邮箱（唯一标识，可为空）。
    pub email: String,
    /// 已解析的 VLESS 账户。
    pub account: MemoryAccount,
}

impl MemoryUser {
    /// 创建新的 VLESS 内存用户。
    pub fn new(email: impl Into<String>, level: u32, account: MemoryAccount) -> Self {
        Self { email: email.into(), level, account }
    }
}

/// 处理 UUID（对应 Go `ProcessUUID`）：将第 6、7 字节清零，作为 validator 内部 key。
pub fn process_uuid(mut id: [u8; 16]) -> [u8; 16] {
    id[6] = 0;
    id[7] = 0;
    id
}

/// 默认 Validator 实现（对应 Go `MemoryValidator`）。
///
/// 内部用两个 HashMap：`email_index`（email 小写 → 用户）和
/// `uuid_index`（ProcessUUID(UUID) → 用户）。`parking_lot::RwLock` 让多读单写并发安全。
#[derive(Debug, Default)]
pub struct MemoryValidator {
    email_index: RwLock<HashMap<String, MemoryUser>>,
    uuid_index: RwLock<HashMap<[u8; 16], MemoryUser>>,
}

impl MemoryValidator {
    /// 创建空 validator。
    pub fn new() -> Self {
        Self::default()
    }

    fn lookup_processed(&self, processed: [u8; 16]) -> Option<MemoryUser> {
        self.uuid_index.read().get(&processed).cloned()
    }
}

impl Validator for MemoryValidator {
    fn get(&self, id: &UUID) -> Option<MemoryUser> {
        let processed = process_uuid(*id.as_bytes());
        self.lookup_processed(processed)
    }

    fn add(&self, u: MemoryUser) -> Result<()> {
        if !u.email.is_empty() {
            let key = u.email.to_lowercase();
            let mut email_guard = self.email_index.write();
            if email_guard.contains_key(&key) {
                return Err(VlessError::UserAlreadyExists(u.email.clone()));
            }
            email_guard.insert(key, u.clone());
        }
        let uuid_key = process_uuid(*u.account.uuid().as_bytes());
        self.uuid_index.write().insert(uuid_key, u);
        Ok(())
    }

    fn del(&self, email: &str) -> Result<()> {
        if email.is_empty() {
            return Err(VlessError::EmptyEmail);
        }
        let key = email.to_lowercase();
        let user = {
            let mut email_guard = self.email_index.write();
            email_guard.remove(&key).ok_or_else(|| VlessError::UserNotFound(email.to_string()))?
        };
        let uuid_key = process_uuid(*user.account.uuid().as_bytes());
        self.uuid_index.write().remove(&uuid_key);
        Ok(())
    }

    fn get_by_email(&self, email: &str) -> Option<MemoryUser> {
        self.email_index.read().get(&email.to_lowercase()).cloned()
    }

    fn get_all(&self) -> Vec<MemoryUser> {
        self.email_index.read().values().cloned().collect()
    }

    fn get_count(&self) -> i64 {
        self.email_index.read().len() as i64
    }

    fn get_uuid_count(&self) -> i64 {
        self.uuid_index.read().len() as i64
    }
}

/// 便捷构造 `Arc<dyn Validator>`。
pub fn shared_validator() -> Arc<dyn Validator> {
    Arc::new(MemoryValidator::new())
}

#[cfg(test)]
mod tests {
    use xray_proto::xray::proxy::vless::Account as ProtoAccount;

    use super::*;

    fn sample_account(id_str: &str) -> MemoryAccount {
        let p = ProtoAccount { id: id_str.to_string(), ..Default::default() };
        MemoryAccount::from_proto_account(&p).expect("parse account")
    }

    fn sample_user(email: &str, id_str: &str) -> MemoryUser {
        MemoryUser::new(email, 0, sample_account(id_str))
    }

    const UUID_A: &str = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
    const UUID_B: &str = "11111111-2222-3333-4444-555555555555";
    const UUID_C: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn process_uuid_zeroes_bytes_6_and_7() {
        let mut input = [0xAA; 16];
        input[6] = 0x42;
        input[7] = 0x99;
        let out = process_uuid(input);
        assert_eq!(out[6], 0);
        assert_eq!(out[7], 0);
        assert_eq!(out[0], 0xAA);
        assert_eq!(out[15], 0xAA);
    }

    #[test]
    fn add_and_get_by_uuid() {
        let v = MemoryValidator::new();
        let user = sample_user("a@example.com", UUID_A);
        v.add(user.clone()).expect("add");
        let uuid = UUID::parse(UUID_A).expect("parse");
        let got = v.get(&uuid).expect("found");
        assert_eq!(got.email, "a@example.com");
    }

    #[test]
    fn get_returns_none_for_unknown_uuid() {
        let v = MemoryValidator::new();
        let uuid = UUID::parse(UUID_A).expect("parse");
        assert!(v.get(&uuid).is_none());
    }

    #[test]
    fn add_duplicate_email_fails() {
        let v = MemoryValidator::new();
        v.add(sample_user("a@example.com", UUID_A)).expect("add 1");
        match v.add(sample_user("a@example.com", UUID_B)) {
            Err(VlessError::UserAlreadyExists(s)) => assert_eq!(s, "a@example.com"),
            other => panic!("expected UserAlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn add_same_email_different_case_fails() {
        let v = MemoryValidator::new();
        v.add(sample_user("a@example.com", UUID_A)).expect("add 1");
        match v.add(sample_user("A@Example.com", UUID_B)) {
            Err(VlessError::UserAlreadyExists(_)) => {},
            other => panic!("expected UserAlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn add_empty_email_allows_multiple() {
        let v = MemoryValidator::new();
        v.add(sample_user("", UUID_A)).expect("add 1");
        v.add(sample_user("", UUID_B)).expect("add 2");
        assert_eq!(v.get_count(), 0);
    }

    #[test]
    fn uuid_count_counts_uuid_indexed_users() {
        // 无 email 的 client 只进 UUID 索引：get_count（Go GetCount 语义）恒 0，
        // get_uuid_count 反映真实可认证用户数。
        let v = MemoryValidator::new();
        assert_eq!(v.get_uuid_count(), 0);
        v.add(sample_user("", UUID_A)).expect("add 1");
        v.add(sample_user("", UUID_B)).expect("add 2");
        v.add(sample_user("c@example.com", UUID_C)).expect("add 3");
        assert_eq!(v.get_count(), 1);
        assert_eq!(v.get_uuid_count(), 3);
        v.del("c@example.com").expect("del");
        assert_eq!(v.get_uuid_count(), 2);
    }

    #[test]
    fn del_removes_user() {
        let v = MemoryValidator::new();
        v.add(sample_user("a@example.com", UUID_A)).expect("add");
        v.del("a@example.com").expect("del");
        let uuid = UUID::parse(UUID_A).expect("parse");
        assert!(v.get(&uuid).is_none());
        assert!(v.get_by_email("a@example.com").is_none());
    }

    #[test]
    fn del_empty_email_fails() {
        let v = MemoryValidator::new();
        match v.del("") {
            Err(VlessError::EmptyEmail) => {},
            other => panic!("expected EmptyEmail, got {other:?}"),
        }
    }

    #[test]
    fn del_unknown_email_fails() {
        let v = MemoryValidator::new();
        match v.del("nobody@example.com") {
            Err(VlessError::UserNotFound(s)) => assert_eq!(s, "nobody@example.com"),
            other => panic!("expected UserNotFound, got {other:?}"),
        }
    }

    #[test]
    fn get_by_email_case_insensitive() {
        let v = MemoryValidator::new();
        v.add(sample_user("User@Example.com", UUID_A)).expect("add");
        let got = v.get_by_email("user@example.com").expect("found");
        assert_eq!(got.email, "User@Example.com");
    }

    #[test]
    fn get_all_returns_all_users() {
        let v = MemoryValidator::new();
        v.add(sample_user("a@example.com", UUID_A)).expect("add");
        v.add(sample_user("b@example.com", UUID_B)).expect("add");
        let all = v.get_all();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn get_count_tracks_email_users() {
        let v = MemoryValidator::new();
        assert_eq!(v.get_count(), 0);
        v.add(sample_user("a@example.com", UUID_A)).expect("add");
        assert_eq!(v.get_count(), 1);
        v.add(sample_user("b@example.com", UUID_B)).expect("add");
        assert_eq!(v.get_count(), 2);
        v.del("a@example.com").expect("del");
        assert_eq!(v.get_count(), 1);
    }

    #[test]
    fn shared_validator_is_send_sync() {
        let v: Arc<dyn Validator> = shared_validator();
        std::sync::Arc::strong_count(&v);
    }
}
