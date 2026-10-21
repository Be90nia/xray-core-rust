//! `XudpConfig::from_env` 在 Go 名缺席时回落到旧名 `XUDP_BASE_KEY`。
//!
//! 独立测试进程，理由同 `env_basekey.rs`（env 缓存是进程级 LazyLock）。

/// [7u8; 32] 的 base64url（无填充）编码。
const KEY_7_B64: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

#[test]
fn from_env_falls_back_to_legacy_base_key_name() {
    // SAFETY: 本测试二进制只跑这一个用例，进程内无并发 env 访问。
    unsafe { std::env::set_var("XUDP_BASE_KEY", KEY_7_B64) };
    let cfg = xray_xudp::XudpConfig::from_env();
    assert_eq!(cfg.base_key, [7u8; 32], "legacy basekey must be consumed");
}
