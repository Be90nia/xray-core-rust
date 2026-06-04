//! 会话上下文类型
//!
//! 对应 Go 版本 `common/ctx` 包，定义会话标识符和键类型。

/// 会话标识符类型。
pub type SessionID = u32;

/// 会话键，用于在上下文中标识和检索会话相关数据。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub id: SessionID,
}

impl SessionKey {
    /// 创建新的会话键。
    pub fn new(id: SessionID) -> Self {
        Self { id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_key_new() {
        let key = SessionKey::new(42);
        assert_eq!(key.id, 42);
    }

    #[test]
    fn test_session_key_equality() {
        let key1 = SessionKey::new(1);
        let key2 = SessionKey::new(1);
        let key3 = SessionKey::new(2);
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_session_key_clone() {
        let key = SessionKey::new(100);
        let cloned = key.clone();
        assert_eq!(key, cloned);
    }

    #[test]
    fn test_session_key_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(SessionKey::new(1));
        set.insert(SessionKey::new(1));
        set.insert(SessionKey::new(2));
        assert_eq!(set.len(), 2);
    }
}
