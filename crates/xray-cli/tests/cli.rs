//! CLI 集成测试（原 xray-core/tests/cli.rs，b5w；bin 迁至 xray-cli（56m）后随迁）。
//!
//! 验证 `xray` bin 的子命令能正常启动并产生预期输出。

use std::process::Command;

/// `xray` bin 路径（由 cargo 自动注入）。
fn xray_bin() -> String {
    env!("CARGO_BIN_EXE_xray").to_string()
}

#[test]
fn cli_version_outputs_version_string() {
    let output =
        Command::new(xray_bin()).arg("version").output().expect("failed to run xray version");
    assert!(output.status.success(), "xray version should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Xray"), "output should contain 'Xray': {stdout}");
    assert!(stdout.contains("26."), "output should contain version 26.x: {stdout}");
}

#[test]
fn cli_uuid_outputs_valid_uuid_v4() {
    let output = Command::new(xray_bin()).arg("uuid").output().expect("failed to run xray uuid");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let parsed = uuid::Uuid::parse_str(&stdout);
    assert!(parsed.is_ok(), "xray uuid output should be a valid UUID: '{stdout}'");
    assert_eq!(parsed.unwrap().get_version(), Some(uuid::Version::Random), "should be UUID v4");
}

#[test]
fn cli_help_lists_all_subcommands() {
    let output =
        Command::new(xray_bin()).arg("--help").output().expect("failed to run xray --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for cmd in [
        "run",
        "version",
        "uuid",
        "convert",
        "x25519",
        "curve25519",
        "wg",
        "mldsa65",
        "mlkem768",
        "vlessenc",
    ] {
        assert!(stdout.contains(cmd), "help should list '{cmd}' command: {stdout}");
    }
}

/// `xray x25519 -i <0x00..=0x1f>`：与 Go 基线逐字节一致（见 commands/keys.rs 黄金对拍）。
#[test]
fn cli_x25519_from_private_key_matches_go() {
    let output = Command::new(xray_bin())
        .args(["x25519", "-i", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"])
        .output()
        .expect("failed to run xray x25519 -i");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "PrivateKey: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHl8\n\
         Password (PublicKey): j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF8\n\
         Hash32: wzCTZNjYhKndYN54x2fTYV8lSnpIYocwiNdA50-jmiw\n"
    );
}

/// `xray curve25519` 别名与 `x25519` 同实现（随机模式输出三行）。
#[test]
fn cli_curve25519_alias_outputs_key_pair() {
    let output =
        Command::new(xray_bin()).arg("curve25519").output().expect("failed to run xray curve25519");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for prefix in ["PrivateKey: ", "Password (PublicKey): ", "Hash32: "] {
        assert!(stdout.contains(prefix), "curve25519 output should contain '{prefix}': {stdout}");
    }
}

/// `xray wg`：StdEncoding（base64 带 `+/=` 字符与 padding）。
#[test]
fn cli_wg_outputs_std_encoding() {
    let output = Command::new(xray_bin())
        .args(["wg", "-i", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="])
        .output()
        .expect("failed to run xray wg -i");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("PrivateKey: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHl8="),
        "wg should echo clamped key in StdEncoding: {stdout}"
    );
    assert!(
        stdout.contains("Password (PublicKey): j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF8="),
        "wg public key should match Go golden in StdEncoding: {stdout}"
    );
}

/// `xray mldsa65 -i <seed>`：验证公钥与 Go（circl FIPS 204）逐字节一致。
#[test]
fn cli_mldsa65_from_seed_matches_go() {
    let output = Command::new(xray_bin())
        .args(["mldsa65", "-i", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"])
        .output()
        .expect("failed to run xray mldsa65 -i");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let verify = stdout.lines().find(|l| l.starts_with("Verify: ")).expect("Verify line");
    assert_eq!(verify.len(), 8 + 2603, "ML-DSA-65 verify key: 1952B → 2603 b64 chars");
    assert!(
        verify.starts_with("Verify: SGg9kZeOMes93biwRzSC0riKX2JZSf2PWKVh5pa9TCfQ"),
        "mldsa65 verify key should match Go golden prefix: {verify}"
    );
}

/// `xray mlkem768 -i <seed>`：封装公钥与 Hash32 与 Go（crypto/mlkem FIPS 203）一致。
#[test]
fn cli_mlkem768_from_seed_matches_go() {
    let output = Command::new(xray_bin())
        .args([
            "mlkem768",
            "-i",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw",
        ])
        .output()
        .expect("failed to run xray mlkem768 -i");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let client = stdout.lines().find(|l| l.starts_with("Client: ")).expect("Client line");
    assert_eq!(client.len(), 8 + 1579, "ML-KEM-768 ek: 1184B → 1579 b64 chars");
    assert!(
        client.starts_with("Client: KYqhDUI8jdoGnQK8WebN8DoJa4s9pMq5uAykoUkHZyz"),
        "mlkem768 client key should match Go golden prefix: {client}"
    );
    assert!(
        stdout.contains("Hash32: zEsgfXtp_IkVT8_G8LlvmJk5hzORlpvB_i7qA-bziao"),
        "mlkem768 hash32 should match Go golden: {stdout}"
    );
}

/// `xray vlessenc`：9 行固定格式（X25519 对 + ML-KEM-768 对）。
#[test]
fn cli_vlessenc_outputs_config_pair() {
    let output =
        Command::new(xray_bin()).arg("vlessenc").output().expect("failed to run xray vlessenc");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "Choose one Authentication to use, do not mix them.",
        "Authentication: X25519, not Post-Quantum",
        "\"decryption\": \"mlkem768x25519plus.native.600s.",
        "\"encryption\": \"mlkem768x25519plus.native.0rtt.",
        "Authentication: ML-KEM-768, Post-Quantum",
    ] {
        assert!(stdout.contains(needle), "vlessenc output should contain '{needle}': {stdout}");
    }
}

/// 非法长度输入：打印 Go 同款错误消息且退出 0（Go fmt.Println 语义）。
#[test]
fn cli_invalid_input_prints_go_message() {
    for (args, msg) in [
        (vec!["x25519", "-i", "AAAA"], "Invalid length of X25519 private key."),
        (vec!["mldsa65", "-i", "AAAA"], "Invalid length of ML-DSA-65 seed."),
        (vec!["mlkem768", "-i", "AAAA"], "Invalid length of ML-KEM-768 seed."),
    ] {
        let output = Command::new(xray_bin())
            .args(&args)
            .output()
            .expect("failed to run invalid input case");
        assert!(output.status.success(), "{args:?} should exit 0");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            msg,
            "{args:?} should print Go-style message"
        );
    }
}
