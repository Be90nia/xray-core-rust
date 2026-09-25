//! 协议用户类型
//!
//! 对应 Go 版本 `common/protocol/user.go` + `user.proto`。
//!
//! Go `User.GetTypedAccount()`/`ToMemoryUser()` 依赖 proto 全局实例注册表
//! （`TypedMessage.GetInstance()`），Rust 无对应机制，属各 proxy crate 的
//! 消费方接入任务，此处不移植；`ToProtoUser`（运行时 → proto 方向）无此
//! 依赖，按 Go 语义提供。

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{protocol::account::Account, serial::TypedMessage};

/// 协议用户（proto 镜像），携带账户的原始序列化形式、邮箱和权限等级。
///
/// 对应 Go 版本 `user.proto` 的 `User` 消息：
/// `{ account *serial.TypedMessage; email string; level uint32 }`。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct User {
    account: Option<TypedMessage>,
    email: String,
    level: u32,
}

impl User {
    /// 创建新用户，默认无账户、权限等级 0。
    #[must_use]
    pub fn new(email: impl Into<String>) -> Self {
        Self { account: None, email: email.into(), level: 0 }
    }

    /// 设置账户（序列化形式），返回新的 User。
    #[must_use]
    pub fn with_account(mut self, account: TypedMessage) -> Self {
        self.account = Some(account);
        self
    }

    /// 设置权限等级，返回新的 User。
    #[must_use]
    pub fn with_level(mut self, level: u32) -> Self {
        self.level = level;
        self
    }

    /// 获取账户（序列化形式）引用。
    #[must_use]
    pub fn account(&self) -> Option<&TypedMessage> {
        self.account.as_ref()
    }

    /// 获取邮箱引用。
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }

    /// 获取权限等级。
    #[must_use]
    pub fn level(&self) -> u32 {
        self.level
    }
}

/// 内存用户（运行时形式），持有已解析的账户。
///
/// 对应 Go 版本的 `MemoryUser`：
/// `{ Account Account; Email string; Level uint32 }`（扁平结构）。
/// Account 为各协议解析后的运行时账户（如 vless 的 UUID + cmd_key）。
#[derive(Debug, Clone)]
pub struct MemoryUser {
    account: Option<Arc<dyn Account>>,
    email: String,
    level: u32,
}

impl MemoryUser {
    /// 创建新的内存用户，无账户、权限等级 0。
    #[must_use]
    pub fn new(email: impl Into<String>) -> Self {
        Self { account: None, email: email.into(), level: 0 }
    }

    /// 设置运行时账户，返回新的 MemoryUser。
    #[must_use]
    pub fn with_account(mut self, account: Arc<dyn Account>) -> Self {
        self.account = Some(account);
        self
    }

    /// 设置权限等级，返回新的 MemoryUser。
    #[must_use]
    pub fn with_level(mut self, level: u32) -> Self {
        self.level = level;
        self
    }

    /// 获取运行时账户引用。
    #[must_use]
    pub fn account(&self) -> Option<&Arc<dyn Account>> {
        self.account.as_ref()
    }

    /// 获取邮箱引用。
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }

    /// 获取权限等级。
    #[must_use]
    pub fn level(&self) -> u32 {
        self.level
    }

    /// 转换回 proto 用户。
    ///
    /// 对应 Go 版本的 `ToProtoUser(mu)`：账户经 `Account.ToProto()` 编码为
    /// TypedMessage。Go 对 nil Account 会 panic；此处无账户时 proto 侧
    /// account 字段留空。
    #[must_use]
    pub fn to_proto_user(&self) -> User {
        User {
            account: self.account.as_ref().map(|a| a.to_proto()),
            email: self.email.clone(),
            level: self.level,
        }
    }
}

/// 相等性按用户身份（email + level）判定，不含账户：
/// 与旧实现一致（按 User 比较），账户的相等性用 [`Account::equals`] 判定。
impl PartialEq for MemoryUser {
    fn eq(&self, other: &Self) -> bool {
        self.email == other.email && self.level == other.level
    }
}

impl Eq for MemoryUser {}

impl std::hash::Hash for MemoryUser {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.email.hash(state);
        self.level.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用账户实现（与 account.rs 测试同构）。
    #[derive(Debug)]
    struct TestAccount {
        id: u32,
    }

    impl Account for TestAccount {
        fn equals(&self, other: &dyn Account) -> bool {
            other.as_any().downcast_ref::<TestAccount>().is_some_and(|o| o.id == self.id)
        }

        fn to_proto(&self) -> TypedMessage {
            TypedMessage::new("type.googleapis.com/test.Account", self.id.to_be_bytes().to_vec())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn test_user_new() {
        let user = User::new("test@example.com");
        assert_eq!(user.email(), "test@example.com");
        assert_eq!(user.level(), 0);
        assert_eq!(user.account(), None);
    }

    #[test]
    fn test_user_with_level() {
        let user = User::new("admin@example.com").with_level(10);
        assert_eq!(user.level(), 10);
    }

    #[test]
    fn test_user_with_account() {
        let account = TypedMessage::new("type.googleapis.com/xray.account", vec![1, 2, 3]);
        let user = User::new("test@example.com").with_account(account.clone());
        assert_eq!(user.account(), Some(&account));
    }

    #[test]
    fn test_user_equality() {
        let a = User::new("test@example.com").with_level(5);
        let b = User::new("test@example.com").with_level(5);
        let c = User::new("other@example.com").with_level(5);
        assert_eq!(a, b);
        assert_ne!(a, c);
        // 账户参与 proto User 相等性（普通派生 PartialEq）
        let d = User::new("test@example.com").with_level(5);
        assert_ne!(
            a.with_account(TypedMessage::new("t", vec![1])),
            d.with_account(TypedMessage::new("t", vec![2]))
        );
    }

    #[test]
    fn test_memory_user_new() {
        let mem = MemoryUser::new("test@example.com");
        assert_eq!(mem.email(), "test@example.com");
        assert!(mem.account().is_none());
    }

    #[test]
    fn test_memory_user_with_account_and_level() {
        let mem = MemoryUser::new("test@example.com")
            .with_level(3)
            .with_account(Arc::new(TestAccount { id: 7 }));
        assert_eq!(mem.level(), 3);
        let account = mem.account().expect("account");
        // 账户可用 Account::equals 比较
        assert!(account.equals(&TestAccount { id: 7 }));
        assert!(!account.equals(&TestAccount { id: 8 }));
    }

    #[test]
    fn test_memory_user_equality_by_identity() {
        // 相等性仅基于 email + level（用户身份），不含账户
        let a = MemoryUser::new("test@example.com").with_level(2);
        let b = MemoryUser::new("test@example.com")
            .with_level(2)
            .with_account(Arc::new(TestAccount { id: 1 }));
        assert_eq!(a, b);
        assert_ne!(a, MemoryUser::new("other@example.com").with_level(2));
        assert_ne!(a, MemoryUser::new("test@example.com").with_level(3));
    }

    /// 对应 Go `ToProtoUser`：email/level 透传，账户经 to_proto 编码。
    #[test]
    fn test_to_proto_user() {
        let mem = MemoryUser::new("test@example.com")
            .with_level(5)
            .with_account(Arc::new(TestAccount { id: 9 }));
        let user = mem.to_proto_user();
        assert_eq!(user.email(), "test@example.com");
        assert_eq!(user.level(), 5);
        let account = user.account().expect("encoded account");
        assert_eq!(account.type_url(), "type.googleapis.com/test.Account");
        assert_eq!(account.value(), 9u32.to_be_bytes());
    }

    /// 编译期：MemoryUser 可跨线程共享（validator 常见于多任务运行时）。
    #[test]
    fn test_memory_user_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MemoryUser>();
    }

    #[test]
    fn test_to_proto_user_without_account() {
        let mem = MemoryUser::new("nobody@example.com").with_level(1);
        let user = mem.to_proto_user();
        assert_eq!(user.account(), None);
        assert_eq!(user.email(), "nobody@example.com");
    }

    #[test]
    fn test_serde_roundtrip_user() {
        let user = User::new("test@example.com")
            .with_level(5)
            .with_account(TypedMessage::new("type.googleapis.com/t", vec![1, 2]));
        let json = serde_json::to_string(&user).expect("serialize");
        let deserialized: User = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(user, deserialized);
    }
}
