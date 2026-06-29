//! `xray version` 命令——输出完整版本声明。
//!
//! 对应 Go `main/version.go` 的 `printVersion`。

use xray_core::version_statement;

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
}
