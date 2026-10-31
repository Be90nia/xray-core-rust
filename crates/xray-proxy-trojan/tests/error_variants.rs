//! 05ac1：Trojan 用户/凭据面的错误变体（此前**零测试覆盖**）。
//!
//! 覆盖（凭据 + 校验器契约，每处一个断言）：
//! - [`TrojanError::InvalidUserAccount`]：`protocol.User` → 运行时用户的三个拒绝点 （缺 account /
//!   type_url 非 trojan / payload 解不出 proto）；
//! - [`TrojanError::EmptyEmail`]（`del` 面）/ [`TrojanError::UserAlreadyExists`] /
//!   [`TrojanError::UserNotFoundByEmail`]：Validator 增删的边界（重复 email 会让 凭据面歧义——同
//!   email 覆盖 = 旧口令静默失效）。
//!
//! 断言的判别力：把 `from_proto_user` 的任一条校验删掉，或让 `Validator::add`
//! 允许重复 email，对应用例即红。

use prost::Message as _;
use xray_proto::xray::{
    common::{protocol::User as ProtoUser, serial::TypedMessage},
    proxy::trojan::Account as ProtoAccount,
};
use xray_proxy_trojan::{MemoryAccount, MemoryUser, TrojanError, Validator};

fn user_with_account(type_url: &str, value: Vec<u8>) -> ProtoUser {
    ProtoUser {
        email: "alice".into(),
        level: 0,
        account: Some(TypedMessage { r#type: type_url.into(), value }),
    }
}

#[test]
fn from_proto_user_rejects_missing_account() {
    let user = ProtoUser { email: "alice".into(), level: 0, account: None };
    let err = MemoryUser::from_proto_user(&user).expect_err("缺 account 必须被拒");
    assert!(matches!(err, TrojanError::InvalidUserAccount), "实际: {err:?}");
}

#[test]
fn from_proto_user_rejects_foreign_type_url() {
    let mut acc = Vec::new();
    ProtoAccount { password: "s3cret".into() }.encode(&mut acc).expect("encode");
    let user = user_with_account("xray.proxy.vless.Account", acc);
    let err = MemoryUser::from_proto_user(&user).expect_err("非 trojan 的 type_url 必须被拒");
    assert!(matches!(err, TrojanError::InvalidUserAccount), "实际: {err:?}");
}

#[test]
fn from_proto_user_rejects_undecodable_payload() {
    // 截断的 protobuf：字段 1 声明 varint 却没有值。
    let user = user_with_account("xray.proxy.trojan.Account", vec![0x08]);
    let err = MemoryUser::from_proto_user(&user).expect_err("payload 解不出必须被拒");
    assert!(matches!(err, TrojanError::InvalidUserAccount), "实际: {err:?}");
}

/// `TrojanError::EmptyEmail` 只属 `del`：Go `Validator.Add`（`proxy/trojan/validator.go`）
/// 对空 email 是**放行**的（空 email = 只按 key 匹配、不进 email 索引的用户），
/// 只有 `Del` 要求 email 非空。本用例把这条语义双向钉住。
#[test]
fn validator_add_allows_empty_email_but_del_rejects_it() {
    let v = Validator::new();
    v.add(MemoryUser::new("", 0, MemoryAccount::new("s3cret")))
        .expect("空 email 的 add 必须成功（Go 语义：不登记 email 索引）");
    // get_count = email 索引大小（Go `GetCount` 语义，空 email 不登记）；
    // 用户本体在 key 索引里：get_key_count 才是「可认证用户数」。
    assert_eq!(v.get_count(), 0, "空 email 不进 email 索引（Go GetCount 语义）");
    assert_eq!(v.get_key_count(), 1, "空 email 用户仍进 key 表，可正常认证");

    let err = v.del("").expect_err("Del 空 email 必须被拒");
    assert!(matches!(err, TrojanError::EmptyEmail), "实际: {err:?}");
}

#[test]
fn validator_rejects_duplicate_email() {
    let v = Validator::new();
    v.add(MemoryUser::new("alice", 0, MemoryAccount::new("first"))).expect("首次 add");
    let err = v
        .add(MemoryUser::new("alice", 0, MemoryAccount::new("second")))
        .expect_err("重复 email 必须被拒（否则同 email 静默覆盖旧凭据）");
    assert!(matches!(&err, TrojanError::UserAlreadyExists(e) if e == "alice"), "实际: {err:?}");
    assert_eq!(v.get_count(), 1, "拒绝后不得留下第二份用户");
}

#[test]
fn validator_delete_unknown_email_reports_not_found() {
    let v = Validator::new();
    let err = v.del("nobody").expect_err("删除不存在的 email 必须报错");
    assert!(matches!(&err, TrojanError::UserNotFoundByEmail(e) if e == "nobody"), "实际: {err:?}");
}
