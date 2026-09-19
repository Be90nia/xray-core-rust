//! Trojan 用户验证器，对应 Go `proxy/trojan/validator.go`。
//!
//! 用 `dashmap` 替代 Go `sync.Map`（双 map：`email → user` + `hex(key) → user`）。
//!
//! # 切片1 范围
//!
//! 提供完整的 Add/Del/Get/GetByEmail/GetAll/GetCount API（独立可测试）。
//! 切片2 待办：接入 server Process 实际校验入站请求头 hash。

use dashmap::DashMap;
use prost::Message as _;
use xray_proto::xray::common::protocol::User as ProtoUser;
use xray_proto::xray::common::serial::TypedMessage;
use xray_proto::xray::proxy::trojan::Account as ProtoAccount;

use crate::config::{hex_string, MemoryAccount, ACCOUNT_TYPE_URL};
use crate::error::{Result, TrojanError};

/// Trojan 运行时用户（账户 + 元数据），对应 Go `protocol.MemoryUser`（Trojan 用法子集）。
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryUser {
    /// 用户邮箱（唯一标识，可为空），对应 Go `MemoryUser.Email`。
    pub email: String,
    /// 用户等级（用于策略查表），对应 Go `MemoryUser.Level`。
    pub level: u32,
    /// Trojan 运行时账户。
    pub account: MemoryAccount,
}

impl MemoryUser {
    /// 构造新用户。
    pub fn new(email: impl Into<String>, level: u32, account: MemoryAccount) -> Self {
        Self {
            email: email.into(),
            level,
            account,
        }
    }

    /// 计算 hex(key) 索引字符串（用作 Validator 内部 `users` map 的 key）。
    pub fn key_hash(&self) -> String {
        hex_string(&self.account.key)
    }

    /// 从 proto `protocol.User` 构造，对应 Go `User.ToMemoryUser()`：
    /// account `TypedMessage` 解码为 trojan `Account`，再经 `AsAccount`
    /// 得运行时账户（password + hexSha224 key）。
    ///
    /// # Errors
    /// account 缺失、type_url 非 trojan Account、payload 解码失败 →
    /// [`TrojanError::InvalidUserAccount`]。
    pub fn from_proto_user(u: &ProtoUser) -> Result<Self> {
        let tm = u.account.as_ref().ok_or(TrojanError::InvalidUserAccount)?;
        if !tm.r#type.ends_with("xray.proxy.trojan.Account") {
            return Err(TrojanError::InvalidUserAccount);
        }
        let acc = ProtoAccount::decode(tm.value.as_slice())
            .map_err(|_| TrojanError::InvalidUserAccount)?;
        Ok(Self::new(u.email.clone(), u.level, MemoryAccount::new(&acc.password)))
    }

    /// 序列化为 proto `protocol.User`：账户经 `ToProto` 编码为
    /// `TypedMessage`（type_url = [`ACCOUNT_TYPE_URL`]，对应 Go
    /// `serial.ToTypedMessage`，Go `infra/conf/trojan.go:137-141` 同构）。
    #[must_use]
    pub fn to_proto_user(&self) -> ProtoUser {
        ProtoUser {
            email: self.email.clone(),
            level: self.level,
            account: Some(TypedMessage {
                r#type: ACCOUNT_TYPE_URL.to_string(),
                value: self.account.to_proto().encode_to_vec(),
            }),
        }
    }
}


/// Trojan 用户验证器：维护 email、hex(key)、md5(key) 三索引。
///
/// 对应 Go `proxy/trojan/validator.go::Validator`（Go 仅前两者；
/// md5 索引服务 trojan v2 草案握手，见 `protocol` 模块文档 v2 节）。
#[derive(Debug, Default)]
pub struct Validator {
    /// email（小写）→ MemoryUser
    email: DashMap<String, MemoryUser>,
    /// hex(sha224(password)) → MemoryUser
    users: DashMap<String, MemoryUser>,
    /// md5(password) → MemoryUser（trojan v2）
    md5_users: DashMap<[u8; 16], MemoryUser>,
}

impl Validator {
    /// 创建空验证器。
    pub fn new() -> Self {
        Self::default()
    }

    /// 添加用户。Email 必须为空或唯一。
    ///
    /// 对应 Go `Validator.Add`。
    ///
    /// # Errors
    /// - [`TrojanError::UserAlreadyExists`]：email 已存在。
    pub fn add(&self, user: MemoryUser) -> Result<()> {
        if !user.email.is_empty() {
            let email_lower = user.email.to_lowercase();
            if self.email.contains_key(&email_lower) {
                return Err(TrojanError::UserAlreadyExists(user.email));
            }
            self.email.insert(email_lower, user.clone());
        }
        let key_hash = user.key_hash();
        self.users.insert(key_hash, user.clone());
        self.md5_users
            .insert(crate::config::md5_key(&user.account.password), user);
        Ok(())
    }

    /// 删除用户（按 email，非空）。
    ///
    /// 对应 Go `Validator.Del`。
    ///
    /// # Errors
    /// - [`TrojanError::EmptyEmail`]：email 为空。
    /// - [`TrojanError::UserNotFoundByEmail`]：email 不存在。
    pub fn del(&self, email: &str) -> Result<()> {
        if email.is_empty() {
            return Err(TrojanError::EmptyEmail);
        }
        let email_lower = email.to_lowercase();
        let (_, user) = self
            .email
            .remove(&email_lower)
            .ok_or_else(|| TrojanError::UserNotFoundByEmail(email.into()))?;
        self.users.remove(&user.key_hash());
        self.md5_users
            .remove(&crate::config::md5_key(&user.account.password));
        Ok(())
    }

    /// 按 hex(key) 查找用户，对应 Go `Validator.Get`。
    pub fn get(&self, key_hash: &str) -> Option<MemoryUser> {
        self.users.get(key_hash).map(|r| r.clone())
    }

    /// 按 email 查找用户，对应 Go `Validator.GetByEmail`。
    pub fn get_by_email(&self, email: &str) -> Option<MemoryUser> {
        let email_lower = email.to_lowercase();
        self.email.get(&email_lower).map(|r| r.clone())
    }

    /// 列出所有用户，对应 Go `Validator.GetAll`。
    pub fn get_all(&self) -> Vec<MemoryUser> {
        self.email
            .iter()
            .map(|r| r.value().clone())
            .collect::<Vec<_>>()
    }

    /// 返回用户总数，对应 Go `Validator.GetCount`。
    pub fn get_count(&self) -> usize {
        self.email.len()
    }

    /// 返回可认证的用户数量（key 索引大小）。
    ///
    /// 生产配置的 client 通常不带 email（`get_count` 恒 0，Go `GetCount`
    /// 同为 email-only 语义）；启动日志展示「已载入用户数」应使用本方法。
    /// 对齐 vless validator 的 `get_uuid_count` 口径。
    pub fn get_key_count(&self) -> usize {
        self.users.len()
    }

    /// 按 56 字节 hex key 直接查找（便捷方法，等价于 `get(&hex_string(key))`）。
    pub fn get_by_key(&self, key: &[u8]) -> Option<MemoryUser> {
        self.get(&hex_string(key))
    }

    /// 按 16 字节 `md5(password)` 查找用户（trojan v2 草案握手）。
    pub fn get_by_md5(&self, key: &[u8; 16]) -> Option<MemoryUser> {
        self.md5_users.get(key).map(|r| r.clone())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(email: &str, password: &str) -> MemoryUser {
        MemoryUser::new(email, 0, MemoryAccount::new(password))
    }

    #[test]
    fn test_add_and_get_by_key() {
        let v = Validator::new();
        let u = user("alice@example.com", "pass1");
        let key_hash = u.key_hash();
        let key = u.account.key;
        v.add(u.clone()).expect("add");
        assert_eq!(v.get_count(), 1);
        assert_eq!(v.get(&key_hash).expect("found").account.password, "pass1");
        assert_eq!(v.get_by_key(&key).expect("found").email, "alice@example.com");
    }

    #[test]
    fn test_add_and_get_by_email() {
        let v = Validator::new();
        let u = user("BOB@example.com", "pass2"); // 大写 email
        v.add(u).expect("add");
        // GetByEmail 应大小写不敏感
        let found = v.get_by_email("bob@example.com").expect("found");
        assert_eq!(found.account.password, "pass2");
        // 任意大小写都能命中
        assert!(v.get_by_email("BOB@EXAMPLE.COM").is_some());
    }

    #[test]
    fn test_add_duplicate_email_fails() {
        let v = Validator::new();
        v.add(user("dup@example.com", "p1")).expect("add 1");
        let err = v.add(user("dup@example.com", "p2")).unwrap_err();
        assert!(matches!(err, TrojanError::UserAlreadyExists(_)));
        // 第一个用户应保留
        assert_eq!(v.get_count(), 1);
    }

    #[test]
    fn test_add_duplicate_password_does_not_replace() {
        // Go sync.Map.LoadOrStore 行为：相同 key 不替换。dashmap insert 会替换，
        // 但 email 已存在先返回错（password 相同 → key_hash 相同），所以走 email 分支报错。
        let v = Validator::new();
        v.add(user("a@x.com", "samepass")).expect("add 1");
        let err = v.add(user("a@x.com", "samepass")).unwrap_err();
        assert!(matches!(err, TrojanError::UserAlreadyExists(_)));
    }

    #[test]
    fn test_add_empty_email_ok() {
        // email 为空允许（与 Go 一致）：仅按 key 索引，不计入 email map 计数
        let v = Validator::new();
        let u = user("", "pass");
        let key = u.account.key;
        v.add(u).expect("empty email ok");
        // Go 端 GetCount 按 email map 计数，空 email 不计入
        assert_eq!(v.get_count(), 0);
        assert!(v.get_by_email("").is_none());
        // 但按 key 仍能查到
        assert!(v.get_by_key(&key).is_some());
        // key 计数口径：空 email 用户可认证，get_key_count 应计入
        assert_eq!(v.get_key_count(), 1);
    }

    #[test]
    fn test_del_success() {
        let v = Validator::new();
        v.add(user("del@x.com", "p")).expect("add");
        assert_eq!(v.get_count(), 1);
        v.del("del@x.com").expect("del");
        assert_eq!(v.get_count(), 0);
        assert!(v.get_by_email("del@x.com").is_none());
    }

    #[test]
    fn test_del_empty_email_fails() {
        let v = Validator::new();
        assert!(matches!(
            v.del(""),
            Err(TrojanError::EmptyEmail)
        ));
    }

    #[test]
    fn test_del_not_found() {
        let v = Validator::new();
        assert!(matches!(
            v.del("ghost@x.com"),
            Err(TrojanError::UserNotFoundByEmail(_))
        ));
    }

    #[test]
    fn test_get_all_and_count() {
        let v = Validator::new();
        v.add(user("a@x.com", "p1")).expect("add");
        v.add(user("b@x.com", "p2")).expect("add");
        v.add(user("c@x.com", "p3")).expect("add");
        assert_eq!(v.get_count(), 3);
        let all = v.get_all();
        assert_eq!(all.len(), 3);
        // 不假设顺序，但应包含所有 email
        let mut emails: Vec<_> = all.iter().map(|u| u.email.as_str()).collect();
        emails.sort();
        assert_eq!(emails, vec!["a@x.com", "b@x.com", "c@x.com"]);
        // key 计数口径与 email 口径在有 email 时一致
        assert_eq!(v.get_key_count(), 3);
    }

    #[test]
    fn test_concurrent_add_del() {
        // dashmap 保证并发安全（与 Go sync.Map 等价）
        use std::sync::Arc;
        use std::thread;

        let v = Arc::new(Validator::new());
        let mut handles = Vec::new();
        for i in 0..10 {
            let v = Arc::clone(&v);
            handles.push(thread::spawn(move || {
                let email = format!("user{i}@x.com");
                v.add(user(&email, &format!("pass{i}"))).expect("add");
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        assert_eq!(v.get_count(), 10);
    }

    #[test]
    fn test_get_by_md5() {
        let v = Validator::new();
        v.add(user("v2@x.com", "secret")).expect("add");

        let key = crate::config::md5_key("secret");
        let hit = v.get_by_md5(&key).expect("md5 key must hit");
        assert_eq!(hit.email, "v2@x.com");

        // 错误密码摘要不命中
        assert!(v.get_by_md5(&crate::config::md5_key("wrong")).is_none());

        // del 后 md5 索引同步失效
        v.del("v2@x.com").expect("del");
        assert!(v.get_by_md5(&key).is_none());
    }
}
