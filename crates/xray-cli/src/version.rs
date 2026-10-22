#![allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr)] // CLI version 输出即产品接口
//! `xray version` 命令——输出完整版本声明。
//!
//! 对应 Go `main/version.go` 的 `printVersion`。

use xray_core::version_statement;

/// clap 顶层 `--version` 用的版本串，单一事实源 = `xray_core::version()`。
///
/// 此前 bin 侧硬编码 "26.7.28"（Go 对拍基线版本），与 `version` 子命令输出
/// （`version_statement` 首行）漂移——该误导字符串曾致三起内核身份误认
/// （dig-ss-argo-20261018 §8-1），bd vjbq 起统一取自版本模块。注意 derive
/// `version` 属性按 `clap_builder::Str` 收参（无 `From<String>`），所以版本
/// 串经 builder API（`Command::version`，收 `IntoResettable<StyledStr>`）
/// 在运行期注入，见 bin/xray.rs async_main。
pub fn version_string() -> String {
    xray_core::version()
}

/// clap `Command::version` 注入用的 `'static` 版本串（LazyLock 单次计算，
/// bin/xray.rs async_main deref 注入）。`&**VERSION` 即 `&'static str`。
pub static VERSION: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(xray_core::version);

/// 打印版本声明到 stdout。对应 Go `printVersion()`。
pub fn print_version() {
    for line in version_statement() {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_statement_nonempty() {
        // 验证 version_statement 可调用且非空（实际打印测试见 doctest）。
        let stmts = version_statement();
        assert!(!stmts.is_empty());
        assert!(stmts[0].contains("Xray"));
    }

    /// bd vjbq：`--version` 单行串必须与 `version_statement` 首行同版本号
    /// ——漂移即复现 "26.7.28" vs 26.10.10 的内核身份误认。
    #[test]
    fn version_string_matches_statement_first_line() {
        let v = version_string();
        assert!(
            version_statement()[0].contains(&v),
            "statement first line must carry version(): {} / {}",
            version_statement()[0],
            v
        );
    }
}
