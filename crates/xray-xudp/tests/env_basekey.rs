//! `XudpConfig::from_env` 读取 Go 名 `xray.xudp.basekey`。
//!
//! 独立测试进程：`xray_common::platform::env` 的 env 读取是进程级 `LazyLock`
//! （一次解析后缓存），与其它测试共享进程时缓存会被先跑者钉死，`set_var`
//! 再无效（CI ubuntu 实测随机键）。集成测试各有独立进程，行为确定。

/// [7u8; 32] 的 base64url（无填充）编码。
const KEY_7_B64: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

#[test]
fn from_env_reads_go_base_key_name() {
    // SAFETY: 本测试二进制只跑这一个用例，进程内无并发 env 访问。
    unsafe { std::env::set_var("xray.xudp.basekey", KEY_7_B64) };
    let cfg = xray_xudp::XudpConfig::from_env();
    assert_eq!(cfg.base_key, [7u8; 32], "Go-name basekey must be consumed");
}
