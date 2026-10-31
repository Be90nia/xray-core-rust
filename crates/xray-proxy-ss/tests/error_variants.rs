//! 05ac1：Shadowsocks / SS-2022 凭据面的错误变体（此前**零测试覆盖**）。
//!
//! 覆盖（每处一个断言）：
//! - [`SsError::InvalidCipherName`]：方法名查表失败（`GetCipherMethod` 语义）；
//! - [`SsError::InvalidPassword`]：PSK base64 解码失败 / 长度与 key_size 不匹配—— 后者是 ss2022
//!   **唯一的凭据校验点**（错 PSK 若被放行 = 任何人都能连上）；
//! - [`SsError::EmptyEmail`]：多用户热更加空 email；
//! - 空 PSK 的实际错误变体（`Ss2022Inbound::new` doc 声明 `Ss2022MissingKey`，
//!   本用例把**实际**行为钉住——doc 与实现不符时由本条暴露）。
//!
//! 判别力：把 `derive_psk` 的 key_size 校验删掉（放行短 PSK），长度用例即红；
//! 把 `psk_from_base64` 的 map_err 改成 unwrap/默认值，base64 用例即红。

use xray_proxy_ss::{MultiUserInbound, Ss2022Inbound, Ss2022User, SsError};

/// 32 字节 `b'a'` 的 base64（2022-blake3-aes-256-gcm 的 key_size）。
const PSK32_B64: &str = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";
/// 16 字节 `b'a'` 的 base64（aes-128 的 key_size，对 aes-256 属长度不匹配）。
const PSK16_B64: &str = "YWFhYWFhYWFhYWFhYWFhYQ==";

#[test]
fn unknown_cipher_name_is_rejected() {
    let Err(err) = Ss2022Inbound::new("2022-blake3-bogus", PSK32_B64, "alice") else {
        panic!("未知方法名必须被拒，实际接受");
    };
    assert!(matches!(&err, SsError::InvalidCipherName(n) if n == "2022-blake3-bogus"));
}

#[test]
fn undecodable_psk_base64_is_rejected() {
    let Err(err) = Ss2022Inbound::new("2022-blake3-aes-256-gcm", "not-base64!!", "alice") else {
        panic!("base64 解不出必须被拒，实际接受");
    };
    assert!(matches!(err, SsError::InvalidPassword(_)), "实际: {err:?}");
}

#[test]
fn psk_length_mismatch_is_rejected() {
    let Err(err) = Ss2022Inbound::new("2022-blake3-aes-256-gcm", PSK16_B64, "alice") else {
        panic!("16B PSK 配 32B 方法必须被拒，实际接受");
    };
    match err {
        SsError::InvalidPassword(msg) => {
            assert!(msg.contains("16") && msg.contains("32"), "错误文案须点名两侧长度: {msg}");
        },
        other => panic!("期望 InvalidPassword，实际: {other:?}"),
    }
}

#[test]
fn matching_psk_length_is_accepted() {
    // 对照组：同长度 PSK 必须通过——否则上面的拒绝断言可能只是「一律拒绝」。
    let inbound = Ss2022Inbound::new("2022-blake3-aes-256-gcm", PSK32_B64, "alice")
        .expect("32B PSK 配 aes-256 必须通过");
    assert_eq!(inbound.psk().len(), 32);
}

#[test]
fn empty_psk_error_variant_is_pinned() {
    let Err(err) = Ss2022Inbound::new("2022-blake3-aes-256-gcm", "", "alice") else {
        panic!("空 PSK 必须被拒（Go `Shadowsocks password is not specified.`），实际接受");
    };
    // 现状：走 derive_psk 的长度分支。doc 头声明的是 Ss2022MissingKey——
    // 二者不一致时本条会把差异顶出来（不静默接受任一说法）。
    assert!(matches!(err, SsError::InvalidPassword(_)), "实际: {err:?}");
}

#[test]
fn multi_user_add_rejects_empty_email() {
    let inbound =
        MultiUserInbound::new("2022-blake3-aes-256-gcm", PSK32_B64, vec![]).expect("空用户表合法");
    let err = inbound
        .add_user(Ss2022User { email: String::new(), level: 0, psk: vec![b'a'; 32] })
        .expect_err("空 email 必须被拒");
    assert!(matches!(err, SsError::EmptyEmail), "实际: {err:?}");
}

#[test]
fn multi_user_add_rejects_bad_psk_length() {
    let inbound =
        MultiUserInbound::new("2022-blake3-aes-256-gcm", PSK32_B64, vec![]).expect("空用户表合法");
    let err = inbound
        .add_user(Ss2022User { email: "bob".into(), level: 0, psk: vec![b'a'; 16] })
        .expect_err("短 PSK 必须被拒（否则该用户所有握手都会在解密期静默失败）");
    assert!(matches!(err, SsError::InvalidPassword(_)), "实际: {err:?}");
    assert_eq!(inbound.users_count(), 0, "拒绝后不得留下半成品用户");
}

#[test]
fn multi_user_add_accepts_valid_user_and_lists_it() {
    // 对照组：合法用户必须真的进表（否则上面的拒绝类断言可能是「一律拒绝」）。
    let inbound =
        MultiUserInbound::new("2022-blake3-aes-256-gcm", PSK32_B64, vec![]).expect("空用户表合法");
    inbound
        .add_user(Ss2022User { email: "bob".into(), level: 3, psk: vec![b'b'; 32] })
        .expect("合法用户必须被接受");
    assert_eq!(inbound.users_count(), 1);
    assert_eq!(inbound.user_emails(), vec![("bob".to_string(), 3)]);
}
