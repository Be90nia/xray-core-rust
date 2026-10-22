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

/// bd vjbq：顶层 `-version`（Go 风格单横线，normalize 归一为 `--version`）必须与
/// `version` 子命令报告同一版本号——此前 clap 硬编码 "26.7.28" 与
/// version_statement 漂移，该误导字符串曾致三起内核身份误认。
#[test]
fn cli_dash_version_matches_version_subcommand() {
    let ver = xray_cli::version::version_string();
    for arg in ["-version", "--version"] {
        let output = Command::new(xray_bin()).arg(arg).output().expect("failed to run xray");
        assert!(output.status.success(), "xray {arg} should exit 0");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(&ver), "xray {arg} must report {ver}, got: {stdout}");
    }
}

/// passwall api.lua:2181 契约：`xray wg | awk -F ': ' '{print $2}'` 后
/// s[1]=私钥、s[2]=公钥——要求第 1/2 行分别是 `PrivateKey: <k>` 与
/// `Password (PublicKey): <k>`（`: ` 分隔，字段 2 可提取）。base64 Std 形态。
#[test]
fn cli_wg_output_passwall_awk_extractable() {
    let output = Command::new(xray_bin()).arg("wg").output().expect("failed to run xray wg");
    assert!(output.status.success(), "xray wg should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 2, "wg must print at least 2 lines: {stdout}");
    // awk -F ': ' 字段 2 提取（Go 同款 `: ` 分隔；StdEncoding 含 padding 字符）。
    let private = lines[0].split_once(": ").map(|(_, v)| v).expect("line 1 must carry ': '");
    let public = lines[1].split_once(": ").map(|(_, v)| v).expect("line 2 must carry ': '");
    assert!(lines[0].starts_with("PrivateKey: "), "line 1 prefix: {}", lines[0]);
    assert!(lines[1].starts_with("Password (PublicKey): "), "line 2 prefix: {}", lines[1]);
    // base64 StdEncoding：44 字符（32 字节）且含 `=` padding。
    assert_eq!(private.len(), 44, "std b64 of 32B: {private}");
    assert!(
        private.ends_with('=') && public.ends_with('='),
        "std b64 padding: {private} / {public}"
    );
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

// ==================== base64 子命令（Go main/commands/all/base64 对拍） ====================

/// 带 stdin 的真跑 helper：piped stdin/stdout/stderr。
fn run_xray_with_stdin(args: &[&str], stdin: &[u8]) -> std::process::Output {
    use std::{io::Write as _, process::Stdio};
    let mut child = Command::new(xray_bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn xray");
    child.stdin.as_mut().expect("stdin piped").write_all(stdin).expect("write stdin");
    child.wait_with_output().expect("wait xray")
}

/// encode 文件：`echo hello > t.txt && xray base64 encode t.txt` → `base64:aGVsbG8K`；
/// 输出回喂 decode 还原原文（Go Encode/Decode 对称）。
#[test]
fn cli_base64_encode_file_then_decode_roundtrip() {
    let file = tempfile::NamedTempFile::new().expect("temp file");
    std::fs::write(file.path(), b"hello\n").expect("write input");
    let path = file.path().to_str().expect("utf8 path");

    let encoded = run_xray_with_stdin(&["base64", "encode", path], b"");
    assert!(encoded.status.success(), "encode should exit 0");
    assert_eq!(
        String::from_utf8_lossy(&encoded.stdout),
        "base64:aGVsbG8K\n",
        "encode output must match Go base64.StdEncoding form"
    );

    let decoded = run_xray_with_stdin(&["base64", "decode", "base64:aGVsbG8K"], b"");
    assert!(decoded.status.success(), "decode should exit 0");
    assert_eq!(decoded.stdout, b"hello\n", "decode must restore original bytes");
}

/// `echo hi | xray base64 encode -gzip -`：带 `base64+gzip:` 前缀，decode 还原 `hi`。
#[test]
fn cli_base64_gzip_stdin_roundtrip() {
    let encoded = run_xray_with_stdin(&["base64", "encode", "-gzip", "-"], b"hi\n");
    assert!(encoded.status.success(), "gzip encode should exit 0");
    let value = String::from_utf8_lossy(&encoded.stdout);
    assert!(value.starts_with("base64+gzip:"), "gzip encode must carry Go GzipPrefix: {value}");

    let decoded = run_xray_with_stdin(&["base64", "decode", value.trim_end()], b"");
    assert!(decoded.status.success(), "gzip decode should exit 0");
    assert_eq!(decoded.stdout, b"hi\n", "gzip decode must restore stdin bytes");
}

/// decode 第二位置参数 output-file：字节写入文件而非 stdout。
#[test]
fn cli_base64_decode_writes_output_file() {
    let out = tempfile::NamedTempFile::new().expect("temp output");
    let out_path = out.path().to_str().expect("utf8 path");
    let result = run_xray_with_stdin(&["base64", "decode", "base64:eA==", out_path], b"");
    assert!(result.status.success(), "decode to file should exit 0");
    assert!(result.stdout.is_empty(), "stdout must stay empty when output-file given");
    assert_eq!(std::fs::read(out_path).expect("read output file"), b"x");
}

/// 非法 base64：Go Fatalf 文本 `failed to decode input: ...` + 退出码 1。
#[test]
fn cli_base64_invalid_value_errors_like_go() {
    let output = run_xray_with_stdin(&["base64", "decode", "!!!"], b"");
    assert_eq!(output.status.code(), Some(1), "Go Fatalf exits 1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to decode input"),
        "stderr must carry Go Fatalf text: {stderr}"
    );
}

/// 输入文件不存在：`failed to read input: ...` + 退出码 1。
#[test]
fn cli_base64_missing_input_file_errors_like_go() {
    let output = run_xray_with_stdin(&["base64", "encode", "no-such-file-xyz-9q"], b"");
    assert_eq!(output.status.code(), Some(1), "Go Fatalf exits 1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to read input"), "stderr must carry Go Fatalf text: {stderr}");
}

/// 帮助对齐：`base64 encode --help` 携带 Go UsageLine 与示例原文；裸 `base64`
/// 无子命令退出 2（Go PrintUsage + SetExitStatus(2) 同码）。
#[test]
fn cli_base64_help_matches_go_usage_lines() {
    let encode_help = run_xray_with_stdin(&["base64", "encode", "--help"], b"");
    assert!(encode_help.status.success());
    let encode_text = format!(
        "{}{}",
        String::from_utf8_lossy(&encode_help.stdout),
        String::from_utf8_lossy(&encode_help.stderr)
    );
    for needle in [
        "xray base64 encode [-gzip] <input-file | - | stdin:>",
        "Encode input-file as Base64 with the base64: prefix.",
        "Use -gzip to compress and output base64+gzip:.",
        "\txray base64 encode input.bin",
        "\txray base64 encode -gzip input.bin",
    ] {
        assert!(encode_text.contains(needle), "encode help must contain {needle:?}: {encode_text}");
    }

    let decode_help = run_xray_with_stdin(&["base64", "decode", "--help"], b"");
    assert!(decode_help.status.success());
    let decode_text = format!(
        "{}{}",
        String::from_utf8_lossy(&decode_help.stdout),
        String::from_utf8_lossy(&decode_help.stderr)
    );
    for needle in [
        "xray base64 decode [-gzip] <value | - | stdin:> [output-file]",
        "Accepts base64:, base64+gzip:, or no prefix; gzip is enabled by base64+gzip: or -gzip.",
        "\txray base64 decode eA== out.bin",
    ] {
        assert!(decode_text.contains(needle), "decode help must contain {needle:?}: {decode_text}");
    }

    let bare = run_xray_with_stdin(&["base64"], b"");
    assert_eq!(bare.status.code(), Some(2), "bare `xray base64` must exit 2 like Go PrintUsage");
}
