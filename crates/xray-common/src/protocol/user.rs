//! 协议用户类型
//!
//! 对应 Go 版本 `common/protocol/user.go`，定义用户和内存用户类型。

use serde::{Deserialize, Serialize};

/// 类型化消息占位类型。
///
/// 对应 Go 版本的 `serial.TypedMessage`，用于承载任意 protobuf 消息。
/// 当前为占位实现，后续接入 protobuf 序列化时替换。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedMessage {
    /// 消息类型 URL
    type_url: String,
    /// 消息原始字节
    value: Vec<u8>,
}

impl TypedMessage {
    /// 创建新的类型化消息。
    #[must_use]
    pub fn new(type_url: impl Into<String>, value: Vec<u8>) -> Self {
        Self {
            type_url: type_url.into(),
            value,
        }
    }

    /// 获取类型 URL。
    #[must_use]
    pub fn type_url(&self) -> &str {
        &self.type_url
    }

    /// 获取原始字节。
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// 协议用户，包含邮箱和权限等级。
///
/// 对应 Go 版本的 `User` 结构体。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct User {
    email: String,
    level: u32,
}

impl User {
    /// 创建新用户，默认权限等级为 0。
    #[must_use]
    pub fn new(email: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            level: 0,
        }
    }

    /// 设置权限等级，返回新的 User。
    #[must_use]
    pub fn with_level(mut self, level: u32) -> Self {
        self.level = level;
        self
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

/// 内存用户，关联 User 和其 Account 信息。
///
/// 对应 Go 版本的 `MemoryUser`，用于运行时用户状态管理。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUser {
    user: User,
    account: Option<TypedMessage>,
}

impl MemoryUser {
    /// 创建新的内存用户，不带账户信息。
    #[must_use]
    pub fn new(user: User) -> Self {
        Self {
            user,
            account: None,
        }
    }

    /// 设置账户信息，返回新的 MemoryUser。
    #[must_use]
    pub fn with_account(mut self, account: TypedMessage) -> Self {
        self.account = Some(account);
        self
    }

    /// 获取用户引用。
    #[must_use]
    pub fn user(&self) -> &User {
        &self.user
    }

    /// 获取账户信息引用。
    #[must_use]
    pub fn account(&self) -> Option<&TypedMessage> {
        self.account.as_ref()
    }
}

impl PartialEq for MemoryUser {
    fn eq(&self, other: &Self) -> bool {
        self.user == other.user
    }
}

impl Eq for MemoryUser {}

impl std::hash::Hash for MemoryUser {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.user.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_new() {
        let user = User::new("test@example.com");
        assert_eq!(user.email(), "test@example.com");
        assert_eq!(user.level(), 0);
    }

    #[test]
    fn test_user_with_level() {
        let user = User::new("admin@example.com").with_level(10);
        assert_eq!(user.level(), 10);
    }

    #[test]
    fn test_user_equality() {
        let a = User::new("test@example.com").with_level(5);
        let b = User::new("test@example.com").with_level(5);
        let c = User::new("other@example.com").with_level(5);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_user_clone() {
        let user = User::new("test@example.com").with_level(3);
        let cloned = user.clone();
        assert_eq!(user, cloned);
    }

    #[test]
    fn test_memory_user_new() {
        let user = User::new("test@example.com");
        let mem = MemoryUser::new(user.clone());
        assert_eq!(mem.user(), &user);
        assert_eq!(mem.account(), None);
    }

    #[test]
    fn test_memory_user_with_account() {
        let user = User::new("test@example.com");
        let account = TypedMessage::new("type.googleapis.com/xray.account", vec![1, 2, 3]);
        let mem = MemoryUser::new(user).with_account(account.clone());
        assert!(mem.account().is_some());
        assert_eq!(mem.account().expect("account").type_url(), account.type_url());
    }

    #[test]
    fn test_memory_user_equality_by_user() {
        let user = User::new("test@example.com");
        let a = MemoryUser::new(user.clone());
        let b = MemoryUser::new(user.clone()).with_account(TypedMessage::new("test", vec![]));
        // MemoryUser 相等性仅基于 User
        assert_eq!(a, b);
    }

    #[test]
    fn test_typed_message_new() {
        let msg = TypedMessage::new("type.googleapis.com/test", vec![1, 2, 3]);
        assert_eq!(msg.type_url(), "type.googleapis.com/test");
        assert_eq!(msg.value(), &[1, 2, 3]);
    }

    #[test]
    fn test_serde_roundtrip_user() {
        let user = User::new("test@example.com").with_level(5);
        let json = serde_json::to_string(&user).expect("serialize");
        let deserialized: User = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(user, deserialized);
    }

    #[test]
    fn test_serde_roundtrip_memory_user() {
        let user = User::new("test@example.com").with_level(3);
        let mem = MemoryUser::new(user);
        let json = serde_json::to_string(&mem).expect("serialize");
        let deserialized: MemoryUser = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(mem, deserialized);
    }
}
