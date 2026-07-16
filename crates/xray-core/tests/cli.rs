//! CLI 集成测试（b5w）。
//!
//! 验证 `xray` bin 的子命令能正常启动并产生预期输出。

use std::process::Command;

/// `xray` bin 路径（由 cargo 自动注入）。
fn xray_bin() -> String {
    env!("CARGO_BIN_EXE_xray").to_string()
}

#[test]
fn cli_version_outputs_version_string() {
    let output = Command::new(xray_bin())
        .arg("version")
        .output()
        .expect("failed to run xray version");
    assert!(output.status.success(), "xray version should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Xray"), "output should contain 'Xray': {stdout}");
    assert!(
        stdout.contains("26."),
        "output should contain version 26.x: {stdout}"
    );
}

#[test]
fn cli_uuid_outputs_valid_uuid_v4() {
    let output = Command::new(xray_bin())
        .arg("uuid")
        .output()
        .expect("failed to run xray uuid");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let parsed = uuid::Uuid::parse_str(&stdout);
    assert!(
        parsed.is_ok(),
        "xray uuid output should be a valid UUID: '{stdout}'"
    );
    assert_eq!(
        parsed.unwrap().get_version(),
        Some(uuid::Version::Random),
        "should be UUID v4"
    );
}

#[test]
fn cli_help_lists_all_subcommands() {
    let output = Command::new(xray_bin())
        .arg("--help")
        .output()
        .expect("failed to run xray --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for cmd in ["run", "version", "uuid", "convert", "x25519"] {
        assert!(
            stdout.contains(cmd),
            "help should list '{cmd}' command: {stdout}"
        );
    }
}

#[test]
fn cli_x25519_reports_not_implemented() {
    // 骨架命令应优雅退出而非 panic
    let output = Command::new(xray_bin())
        .arg("x25519")
        .output()
        .expect("failed to run xray x25519");
    assert!(output.status.success(), "x25519 stub should exit 0");
}
