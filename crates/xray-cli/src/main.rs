//! # xray CLI 入口
//!
//! 对应 Go `main/main.go`。clap derive 替代 Go 自定义 `base.Command` 框架。
//!
//! ## v4 兼容
//!
//! Go 端 `getArgsV4Compatible` 处理 v4 兼容：无子命令时默认 `run`。
//! Rust 端 clap `Option<Command>` + `unwrap_or(Command::Run)` 实现等价语义。
//!
//! ## 子命令
//!
//! - `xray run [-c config.json] [-confdir dir] [-test] [-dump]` — 运行（默认）
//! - `xray version` — 输出版本信息
//!
//! 工具子命令（`uuid`/`x25519`/`cert`/`hash` 等 50+ 个）留切片2。

use clap::{Parser, Subcommand};

use xray_cli::error::CliError;
use xray_cli::run::{self, RunArgs};
use xray_cli::version;

/// CLI 顶层结构。
#[derive(Parser, Debug)]
#[command(
    name = "xray",
    version = "26.6.1",
    about = "Xray is a platform for building proxies."
)]
struct Cli {
    /// 子命令。未指定时默认 `run`（v4 兼容）。
    #[command(subcommand)]
    command: Option<Command>,
}

/// 子命令枚举。
#[derive(Subcommand, Debug)]
enum Command {
    /// Run Xray with config, the default command.
    Run(RunArgs),

    /// Print version info.
    Version,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    // v4 兼容：无子命令时默认 run
    let command = cli.command.unwrap_or(Command::Run(RunArgs::default()));
    match execute(command) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// 子命令 dispatch。
fn execute(command: Command) -> Result<(), CliError> {
    match command {
        Command::Run(args) => run::execute(args),
        Command::Version => {
            version::print_version();
            Ok(())
        }
    }
}
