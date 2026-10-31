//! 05ac1：SOCKS5 **服务端鉴权**错误变体（此前 `SocksError::AuthFailed` 零测试覆盖）。
//!
//! 三处生产拒绝点（`crates/xray-proxy-socks/src/server.rs`）：
//! ① 密码模式下客户端只提供 0x00 → 选不出方法（**不得回退 0x00**＝认证绕过）；
//! ② 用户名/密码错 → 回 `01 FF` 并报错；
//! ③ auth 子协议版本字节非法 → 报错。
//!
//! 判别力：把 ① 改成「配置了密码但没匹配到就退回 NoAuth」，用例即红（这正是
//! open-proxy 那条路）；把 ② 的 `has_account` 结果反过来，用例即红。

use std::collections::HashMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_proxy_socks::{AuthType, ServerConfig, SocksError, socks5_server_handshake};

const AUTH_PASSWORD: u8 = 0x02;
const AUTH_NOT_REQUIRED: u8 = 0x00;

fn password_config() -> ServerConfig {
    let mut accounts = HashMap::new();
    accounts.insert("alice".to_string(), "s3cret".to_string());
    ServerConfig { auth_type: AuthType::Password, accounts, ..ServerConfig::default() }
}

/// 把客户端字节灌进 duplex，收回「服务端结局（变体名）+ 服务端写出的字节」。
///
/// 用 `tokio::join!` 而非 `tokio::spawn`：坑约束 5 禁裸 spawn（clippy
/// `disallowed_methods` 门），且两侧共用同一 task 就够——duplex 两端变量互不借用。
async fn drive(config: ServerConfig, client_bytes: &[u8]) -> (String, Vec<u8>) {
    let (mut server_side, mut client_side) = tokio::io::duplex(4096);
    let mut server_bytes = Vec::new();

    let (outcome, ()) = tokio::join!(
        async {
            let outcome = match socks5_server_handshake(&mut server_side, &config).await {
                Ok(_) => "Ok".to_string(),
                Err(SocksError::AuthFailed(msg)) => format!("AuthFailed: {msg}"),
                Err(other) => format!("other: {other}"),
            };
            // 显式关链：成功用例里服务端会去读请求帧，不给 EOF 对端就等不到收尾。
            drop(server_side);
            outcome
        },
        async {
            client_side.write_all(client_bytes).await.expect("client write");
            client_side.shutdown().await.expect("client shutdown");
            client_side.read_to_end(&mut server_bytes).await.expect("client read");
        }
    );
    (outcome, server_bytes)
}

#[tokio::test]
async fn password_mode_without_password_method_fails_auth() {
    // 客户端只声明「无需认证」；服务端配了密码 → 必须 05 FF + AuthFailed。
    let (outcome, bytes) = drive(password_config(), &[0x05, 0x01, AUTH_NOT_REQUIRED]).await;
    assert!(outcome.starts_with("AuthFailed"), "实际: {outcome}");
    assert_eq!(bytes, vec![0x05, 0xFF], "必须回 NO ACCEPTABLE METHODS，绝不回落 0x00");
}

#[tokio::test]
async fn wrong_password_fails_auth() {
    let mut client = vec![0x05, 0x01, AUTH_PASSWORD];
    // RFC 1929：VER=1, ULEN, UNAME, PLEN, PASSWD
    client.extend_from_slice(&[0x01, 5]);
    client.extend_from_slice(b"alice");
    client.push(5);
    client.extend_from_slice(b"wrong");

    let (outcome, bytes) = drive(password_config(), &client).await;
    assert!(outcome.contains("invalid username or password"), "实际: {outcome}");
    assert_eq!(
        bytes,
        vec![0x05, AUTH_PASSWORD, 0x01, 0xFF],
        "方法协商回 0x02 后，认证必须回状态 0xFF（失败）"
    );
}

#[tokio::test]
async fn invalid_auth_subprotocol_version_fails_auth() {
    let mut client = vec![0x05, 0x01, AUTH_PASSWORD];
    client.extend_from_slice(&[0x02, 5]); // VER=2 非法
    client.extend_from_slice(b"alice");
    client.push(6);
    client.extend_from_slice(b"s3cret");

    let (outcome, _) = drive(password_config(), &client).await;
    assert!(outcome.contains("invalid auth version"), "实际: {outcome}");
}

#[tokio::test]
async fn correct_password_is_accepted() {
    // 对照组：正确凭据必须过认证并在读请求帧时停下（客户端不再发字节 → 读到 EOF 后
    // 报 IO 错误，即「已越过鉴权」的证据；若鉴权恒失败，outcome 会是 AuthFailed）。
    let mut client = vec![0x05, 0x01, AUTH_PASSWORD];
    client.extend_from_slice(&[0x01, 5]);
    client.extend_from_slice(b"alice");
    client.push(6);
    client.extend_from_slice(b"s3cret");

    let (outcome, bytes) = drive(password_config(), &client).await;
    assert!(!outcome.starts_with("AuthFailed"), "正确凭据不得被判鉴权失败: {outcome}");
    assert_eq!(bytes, vec![0x05, AUTH_PASSWORD, 0x01, 0x00], "认证必须回状态 0x00（成功）");
}
