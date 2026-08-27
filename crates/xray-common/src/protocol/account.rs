//! 协议账户抽象
//!
//! 对应 Go 版本 `common/protocol/account.go`。
//! Go 消费方：vless/vmess/trojan/shadowsocks/shadowsocks_2022/socks/http/hysteria
//! 各自的 Account/MemoryAccount 实现本 trait（见 `proxy/*/config.go` 的
//! `Equals`/`AsAccount` 方法）。

use std::sync::Arc;

use crate::errors::Error;
use crate::serial::TypedMessage;

/// 用户身份，用于认证。
///
/// 对应 Go 版本的 `Account` 接口：
/// ```go
/// type Account interface {
///     Equals(Account) bool
///     ToProto() proto.Message
/// }
/// ```
/// `ToProto` 在 Go 返回 `proto.Message`；Rust 侧 prost 的 `Message` trait
/// 非 dyn 兼容，故以 `serial::TypedMessage`（类型 URL + 编码字节，等价
/// `serial.ToTypedMessage` 的产物）作为规范承载。
pub trait Account: std::fmt::Debug + Send + Sync {
    /// 判断两个账户是否相同。
    ///
    /// Go 语义：类型不同返回 false；同类型比较关键字段
    /// （如 vless 比较 UUID、trojan 比较 password、ss 比较 key）。
    fn equals(&self, other: &dyn Account) -> bool;

    /// 序列化为带类型标识的 proto 消息。
    fn to_proto(&self) -> TypedMessage;

    /// 返回自身以供下转（`downcast_ref`）。
    ///
    /// Rust 无 Go 的类型断言语法（`another.(*Account)`），
    /// `equals` 实现需要经由本方法取 `dyn Any` 后下转比较。
    fn as_any(&self) -> &dyn std::any::Any;
}
/// 可转换为 [`Account`] 的对象。
///
/// 对应 Go 版本的 `AsAccount` 接口。Go 中 proto 生成的原始 Account
/// （如 `vless.Account`）实现它，转换为运行时 MemoryAccount
/// （如 `vless.MemoryAccount`，含解析后的 UUID/cmd_key）。
pub trait AsAccount {
    /// 转换为运行时账户。
    ///
    /// Go 语义：解析失败（如 UUID 非法）返回 error。
    fn as_account(&self) -> Result<Arc<dyn Account>, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用账户：按 (kind, id) 判等，镜像 Go proxy Account 的典型实现。
    #[derive(Debug)]
    struct TestAccount {
        kind: &'static str,
        id: u32,
    }

    impl Account for TestAccount {
        fn equals(&self, other: &dyn Account) -> bool {
            let Some(other) = other.as_any().downcast_ref::<TestAccount>() else {
                return false;
            };
            self.kind == other.kind && self.id == other.id
        }

        fn to_proto(&self) -> TypedMessage {
            TypedMessage::new(
                format!("type.googleapis.com/test.{}", self.kind),
                self.id.to_be_bytes().to_vec(),
            )
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// proto 原始账户，实现 AsAccount，镜像 Go vless/trojan 的转换模式。
    #[derive(Debug)]
    struct ProtoAccount {
        raw_id: u32,
    }

    impl AsAccount for ProtoAccount {
        fn as_account(&self) -> Result<Arc<dyn Account>, Error> {
            if self.raw_id == 0 {
                // 镜像 Go：vless.Account.AsAccount 对非法 ID 返回 error
                return Err(Error::new("failed to parse account"));
            }
            Ok(Arc::new(TestAccount { kind: "test", id: self.raw_id }))
        }
    }

    #[derive(Debug)]
    struct OtherAccount;

    impl Account for OtherAccount {
        fn equals(&self, other: &dyn Account) -> bool {
            other.as_any().is::<OtherAccount>()
        }
        fn to_proto(&self) -> TypedMessage {
            TypedMessage::new("type.googleapis.com/test.other", vec![])
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
}

    #[test]
    fn test_equals_same_type_and_value() {
        let a = TestAccount { kind: "test", id: 1 };
        let b = TestAccount { kind: "test", id: 1 };
        assert!(a.equals(&b));
        assert!(b.equals(&a));
    }

    #[test]
    fn test_equals_same_type_different_value() {
        let a = TestAccount { kind: "test", id: 1 };
        let b = TestAccount { kind: "test", id: 2 };
        assert!(!a.equals(&b));
    }

    #[test]
    fn test_equals_different_type_returns_false() {
        // 镜像 Go：`another.(*Account)` 类型断言失败 → false
        let a = TestAccount { kind: "test", id: 1 };
        let other = OtherAccount;
        assert!(!a.equals(&other));
        assert!(!other.equals(&a));
    }

    #[test]
    fn test_to_proto_carries_type_and_payload() {
        let a = TestAccount { kind: "test", id: 7 };
        let msg = a.to_proto();
        assert_eq!(msg.type_url(), "type.googleapis.com/test.test");
        assert_eq!(msg.value(), 7u32.to_be_bytes());
    }

    #[test]
    fn test_as_account_success() {
        let proto = ProtoAccount { raw_id: 5 };
        let account = proto.as_account().expect("valid account");
        let same = TestAccount { kind: "test", id: 5 };
        assert!(account.equals(&same));
    }

    #[test]
    fn test_as_account_parse_error() {
        // 镜像 Go vless.Account.AsAccount 的 UUID 解析失败路径
        let proto = ProtoAccount { raw_id: 0 };
        let err = proto.as_account().expect_err("zero id must fail");
        assert!(err.to_string().contains("failed to parse account"));
    }

    #[test]
    fn test_account_is_object_safe_and_shareable() {
        let account: Arc<dyn Account> = Arc::new(TestAccount { kind: "test", id: 3 });
        let cloned = Arc::clone(&account);
        assert!(account.equals(cloned.as_ref()));
        std::thread::spawn(move || {
            assert!(cloned.to_proto().value().len() == 4);
        })
        .join()
        .expect("Send + Sync across thread");
    }
}
