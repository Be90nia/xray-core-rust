//! 05ac1：VMess 入站 **凭据校验**错误变体（`VmessError::InvalidAuth` 此前零测试覆盖）。
//!
//! `ServerSession::decode_request_header` 的第一步就是 16B authID 查表——
//! 这是 vmess 的凭据校验本体（Go `AuthIDDecoderHolder.Allocate`）。未注册的
//! authID（随机/篡改）必须以 **`VmessError::UserNotFound`** 被拒。
//!
//! 注意分层：`VmessError::InvalidAuth` **不是**凭据校验，而是解密后头部 payload 的
//! FNV1a 校验和不符（`encoding/server.rs:282`，篡改检测）——两者都在凭据/完整性
//! 面上，但触发条件不同，勿混为一谈（审计 F14/§2.1 的变体-位置映射在此处需修正）。
//!
//! 判别力：把 `get_aead` 的 Err 分支改成返回一个默认用户（容错兜底），用例即红。

use xray_proxy_vmess::{
    SessionHistory, TimedUserValidator, VmessError, encoding::server::ServerSession,
};

#[test]
fn unregistered_auth_id_is_rejected() {
    let validator = TimedUserValidator::new();
    let history = SessionHistory::new();
    let mut session = ServerSession::new(&validator, &history);

    // 16B 未注册 authID（UUIDv4 随机等价的固定字面量，逐位确定可回放）。
    let auth_id = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let mut reader = std::io::Cursor::new(auth_id);

    let Err(err) = session.decode_request_header(&mut reader) else {
        panic!("未注册 authID 必须被拒，实际放行");
    };
    assert!(matches!(err, VmessError::UserNotFound), "实际: {err:?}");
}

#[test]
fn truncated_auth_id_is_io_error_not_panic() {
    let validator = TimedUserValidator::new();
    let history = SessionHistory::new();
    let mut session = ServerSession::new(&validator, &history);

    // 只有 8B < 16B：必须走 IO 错误路径（客户端提前断开），不得 panic/放行。
    let mut reader = std::io::Cursor::new(vec![0u8; 8]);
    let Err(err) = session.decode_request_header(&mut reader) else {
        panic!("截断的 authID 必须被拒");
    };
    assert!(matches!(err, VmessError::Io(_)), "实际: {err:?}");
}
