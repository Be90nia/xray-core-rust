//! VLESS 账户定义。
//!
//! 对应 Go 版本 `proxy/vless/account.go`：
//! - `MemoryAccount`：运行时账户（解析自 proto `Account`），持 `protocol::ID`
//! - `Account::as_account()`：proto → 运行时类型
//! - `MemoryAccount::equals()`：账户相等性比较（仅比对 `ID.uuid`）
//! - `MemoryAccount::to_proto()`：运行时 → proto（用于序列化）

use xray_common::{protocol::ID, uuid::UUID};
use xray_proto::xray::{
    app::proxyman::SniffingConfig,
    proxy::vless::{Account as ProtoAccount, Reverse as ProtoReverse},
};

use crate::error::{Result, VlessError};

/// VLESS Reverse 配置（对应 Go `vless.Reverse`）。
#[derive(Debug, Clone, PartialEq)]
pub struct Reverse {
    /// Portal 标识（指向 outbound handler tag）。
    pub tag: String,
    /// 可选 sniffing 配置（proto SniffingConfig 的运行时副本）。
    pub sniffing: Option<SniffingConfig>,
}

impl Reverse {
    /// 从 proto `&Reverse` 转换为运行时 `Reverse`。
    pub fn from_proto(p: &ProtoReverse) -> Self {
        Self { tag: p.tag.clone(), sniffing: p.sniffing.clone() }
    }

    /// 转换回 proto `Reverse`。
    pub fn to_proto(&self) -> ProtoReverse {
        ProtoReverse { tag: self.tag.clone(), sniffing: self.sniffing.clone() }
    }
}

/// 运行时 VLESS 账户（对应 Go `vless.MemoryAccount`）。
#[derive(Debug, Clone)]
pub struct MemoryAccount {
    /// UUID 派生的协议 ID（含 cmd_key）。
    pub id: ID,
    /// Flow 设置，可能为 `xtls-rprx-vision`。
    pub flow: String,
    /// 加密设置字符串（如 `none`、自定义加密名）。
    pub encryption: String,
    /// Xor 加密模式（0=禁用，>0=启用）。
    pub xor_mode: u32,
    /// 会话票据有效期（秒）。
    pub seconds: u32,
    /// Padding 参数字符串。
    pub padding: String,
    /// 可选反向代理配置。
    pub reverse: Option<Reverse>,
    /// 预连接数（Testpre）。
    pub testpre: u32,
    /// 随机种子列表（Testseed）。
    pub testseed: Vec<u32>,
}

impl MemoryAccount {
    /// 将 proto `Account` 解析为运行时 `MemoryAccount`（对应 Go `Account.AsAccount()`）。
    pub fn from_proto_account(a: &ProtoAccount) -> Result<Self> {
        let uuid = UUID::parse(&a.id).ok_or_else(|| VlessError::InvalidUuid(a.id.clone()))?;
        Ok(Self {
            id: ID::new(uuid),
            flow: a.flow.clone(),
            encryption: a.encryption.clone(),
            xor_mode: a.xor_mode,
            seconds: a.seconds,
            padding: a.padding.clone(),
            reverse: a.reverse.as_ref().map(Reverse::from_proto),
            testpre: a.testpre,
            testseed: a.testseed.clone(),
        })
    }

    /// 检查两个账户是否相等（对应 Go `MemoryAccount.Equals`）。
    ///
    /// 仅比对 `id.uuid`（与 Go 行为一致，不比对 alter_ids）。
    pub fn equals(&self, other: &Self) -> bool {
        self.id.uuid() == other.id.uuid()
    }

    /// 转换回 proto `Account`（对应 Go `MemoryAccount.ToProto`）。
    pub fn to_proto(&self) -> ProtoAccount {
        ProtoAccount {
            id: self.id.uuid().to_string(),
            flow: self.flow.clone(),
            encryption: self.encryption.clone(),
            xor_mode: self.xor_mode,
            seconds: self.seconds,
            padding: self.padding.clone(),
            reverse: self.reverse.as_ref().map(Reverse::to_proto),
            testpre: self.testpre,
            testseed: self.testseed.clone(),
        }
    }

    /// 返回内部 UUID 引用。
    pub fn uuid(&self) -> &UUID {
        self.id.uuid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_uuid_str() -> &'static str {
        "66ad4540-b58c-4ad2-9926-ea63445a9b57"
    }

    fn sample_proto_account(flow: &str) -> ProtoAccount {
        ProtoAccount {
            id: sample_uuid_str().to_string(),
            flow: flow.to_string(),
            encryption: "none".to_string(),
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            reverse: None,
            testpre: 0,
            testseed: vec![1, 2, 3],
        }
    }

    #[test]
    fn from_proto_account_parses_uuid() {
        let p = sample_proto_account("");
        let m = MemoryAccount::from_proto_account(&p).expect("parse");
        assert_eq!(m.uuid().to_string(), sample_uuid_str());
        assert_eq!(m.flow, "");
        assert_eq!(m.encryption, "none");
        assert_eq!(m.testseed, vec![1, 2, 3]);
    }

    #[test]
    fn from_proto_account_invalid_uuid() {
        // Go uuid.ParseString 语义：1-30 字节非 UUID 文本派生 v5（合法）；
        // >30 字节非标准格式才是 InvalidUuid。
        let p = ProtoAccount {
            id: "this-id-is-longer-than-thirty-bytes!!".into(),
            ..sample_proto_account("")
        };
        match MemoryAccount::from_proto_account(&p) {
            Err(VlessError::InvalidUuid(s)) => {
                assert_eq!(s, "this-id-is-longer-than-thirty-bytes!!")
            },
            other => panic!("expected InvalidUuid, got {other:?}"),
        }
    }

    #[test]
    fn from_proto_account_short_text_derives_v5() {
        // 对拍 Go：VLESS 自定义短 id（非 UUID 文本）派生 UUIDv5 账户。
        let p = ProtoAccount { id: "not-a-uuid".into(), ..sample_proto_account("") };
        let m = MemoryAccount::from_proto_account(&p).expect("short id derives v5");
        assert_eq!(m.id.uuid().as_bytes()[6] >> 4, 5);
    }

    #[test]
    fn from_proto_account_with_reverse() {
        let p = ProtoAccount {
            reverse: Some(ProtoReverse { tag: "portal".into(), sniffing: None }),
            ..sample_proto_account("")
        };
        let m = MemoryAccount::from_proto_account(&p).expect("parse");
        let r = m.reverse.expect("reverse present");
        assert_eq!(r.tag, "portal");
        assert!(r.sniffing.is_none());
    }

    #[test]
    fn equals_compares_uuid_only() {
        let p1 = sample_proto_account("");
        let p2 = sample_proto_account("xtls-rprx-vision");
        let a = MemoryAccount::from_proto_account(&p1).expect("a");
        let b = MemoryAccount::from_proto_account(&p2).expect("b");
        // 同 UUID 不同 flow —— equals 为 true（与 Go 行为一致）
        assert!(a.equals(&b));
    }

    #[test]
    fn equals_false_for_different_uuid() {
        let p1 = sample_proto_account("");
        let mut p2 = sample_proto_account("");
        p2.id = "11111111-2222-3333-4444-555555555555".into();
        let a = MemoryAccount::from_proto_account(&p1).expect("a");
        let b = MemoryAccount::from_proto_account(&p2).expect("b");
        assert!(!a.equals(&b));
    }

    #[test]
    fn to_proto_roundtrip() {
        let p = sample_proto_account("xtls-rprx-vision");
        let m = MemoryAccount::from_proto_account(&p).expect("parse");
        let p2 = m.to_proto();
        assert_eq!(p2.id, p.id);
        assert_eq!(p2.flow, "xtls-rprx-vision");
        assert_eq!(p2.encryption, "none");
        assert_eq!(p2.testseed, vec![1, 2, 3]);
    }

    #[test]
    fn reverse_from_to_proto_roundtrip() {
        let p = ProtoReverse { tag: "portal-x".into(), sniffing: None };
        let r = Reverse::from_proto(&p);
        let p2 = r.to_proto();
        assert_eq!(p2.tag, p.tag);
        assert_eq!(p2.sniffing, p.sniffing);
    }

    #[test]
    fn uuid_accessor_returns_internal_uuid() {
        let p = sample_proto_account("");
        let m = MemoryAccount::from_proto_account(&p).expect("parse");
        assert_eq!(m.uuid().to_string(), sample_uuid_str());
    }
}
