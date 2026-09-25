//! Xray 版本信息，对应 Go `core/core.go` 的 `Version_x/y/z` + `Version()` +
//! `VersionStatement()`。
//!
//! Go 端 `init()` 用 `debug.ReadBuildInfo()` 从构建信息注入 commit short SHA。
//! Rust 端用 `option_env!("XRAY_BUILD")` 编译期注入（cargo `-` 风格通过
//! `XRAY_BUILD=abc1234 cargo build` 设置）。

/// 主版本号。对应 Go `Version_x`。
pub const VERSION_X: u8 = 26;

/// 次版本号。对应 Go `Version_y`。
pub const VERSION_Y: u8 = 7;

pub const VERSION_Z: u8 = 28;

/// 内部代号。对应 Go `codename`。
pub const CODENAME: &str = "Xray, Penetrates Everything.";

/// 项目简介。对应 Go `intro`。
pub const INTRO: &str = "A unified platform for anti-censorship.";

/// 默认构建标识。可通过编译期环境变量 `XRAY_BUILD` 覆盖（注入 git short SHA）。
pub const BUILD: &str = match option_env!("XRAY_BUILD") {
    Some(v) => v,
    None => "Custom",
};

/// 返回形如 `"26.7.28"` 的版本字符串。
///
/// 对应 Go `Version()`。注意 Go 文档说明常规发布可省略 `.z`，本 Rust 端始终带 z，
/// 避免下游解析分支。
pub fn version() -> String {
    format!("{VERSION_X}.{VERSION_Y}.{VERSION_Z}")
}

/// 返回完整版本声明列表，每行一个元素。对应 Go `VersionStatement()`。
///
/// 第 0 项是单行版本摘要（`Xray <version> (<codename>) <build> (<rustc> <os>/<arch>)`），
/// 第 1 项是项目简介。下游打印版本时按行输出。
pub fn version_statement() -> Vec<String> {
    // 注：与 Go 不同，Rust 没有等价于 `runtime.Version()` 的稳定 API 暴露
    // 编译器版本；用环境变量在 build.rs 注入是常见做法，但切片1 暂不引 build.rs，
    // 用编译期 `env!` 拿到 rustc 版本（不稳定但足够）。
    let rustc = env!("CARGO_PKG_RUST_VERSION", "CARGO_PKG_RUST_VERSION 未设置");
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    vec![
        format!("Xray {} ({}) {} (rustc {}, {}/{})", version(), CODENAME, BUILD, rustc, os, arch,),
        INTRO.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_string_format() {
        let v = version();
        assert_eq!(v, format!("{VERSION_X}.{VERSION_Y}.{VERSION_Z}"));
        // 三个点号分隔的数字。
        let parts: Vec<&str> = v.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn version_statement_contains_key_info() {
        let stmts = version_statement();
        assert_eq!(stmts.len(), 2);
        let head = &stmts[0];
        assert!(head.contains("Xray"));
        assert!(head.contains(&version()));
        assert!(head.contains(CODENAME));
        assert_eq!(stmts[1], INTRO);
    }

    #[test]
    fn build_default_or_override() {
        // 编译期常量；测试环境下要么是 "Custom"，要么是 env 注入的值。
        // 主要验证 const eval 不 panic。
        let _ = BUILD;
    }

    #[test]
    fn version_constants_are_u8() {
        let _x: u8 = VERSION_X;
        let _y: u8 = VERSION_Y;
        let _z: u8 = VERSION_Z;
        // 编译期断言：版本号非零（Xray 26.x 系列保证）。
        assert!(VERSION_X > 0, "VERSION_X must be nonzero");
    }
}
