//! # xray CLI
//!
//! Xray-core 命令行入口（b5w）。对应 Go `main/commands/all/`。
//!
//! ## 命令
//!
//! - `xray run <config>`     —— 加载配置并启动代理
//! - `xray version`          —— 打印版本信息
//! - `xray uuid`             —— 生成随机 UUID（v4）
//! - `xray convert <input>`  —— 转换配置格式（基础）
//! - `xray x25519`           —— 生成 x25519 密钥对（基础）
//! - `xray curve25519`       —— 同 x25519
//!
//! ## 待办（b5w-future）
//!
//! - `xray api <cmd>`        —— gRPC commander 调用（需 tonic client + commander server）
//! - `xray tls <cmd>`        —— TLS 证书工具
//! - `xray wg <cmd>`         —— WireGuard 密钥工具

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "xray",
    about = "Xray, Penetrates Everything."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 启动 Xray 代理服务
    Run {
        /// 配置文件路径（JSON/YAML/TOML）
        config: PathBuf,
    },
    /// 打印版本信息
    Version,
    /// 生成随机 UUID（v4）
    Uuid,
    /// 转换配置格式（基础占位，b5w-future 实现 proto 输出）
    Convert {
        /// 输入文件路径
        input: PathBuf,
        /// 输出文件路径（缺省打印到 stdout）
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// 生成 x25519 密钥对（基础占位）
    X25519,
    /// curve25519 的别名（同 x25519）
    Curve25519,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run { config } => run(config).await,
        Commands::Version => {
            print_version();
            Ok(())
        }
        Commands::Uuid => {
            println!("{}", uuid::Uuid::new_v4());
            Ok(())
        }
        Commands::Convert { input, output } => convert(input, output).await,
        Commands::X25519 | Commands::Curve25519 => {
            println!(
                "x25519/curve25519 keypair generation: not yet implemented (b5w-future).\n\
                 Requires curve25519-dalek crate integration."
            );
            Ok(())
        }
    }
}

/// 启动代理：加载配置 → start_full → 等待所有 inbound handle。
async fn run(config: PathBuf) -> anyhow::Result<()> {
    // 初始化 tracing 日志（受 RUST_LOG 环境变量控制）
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!(config = %config.display(), "loading config");
    let cfg = xray_conf::load_file(&config)?;
    let built = cfg.build()?;

    tracing::info!(
        inbounds = built.inbounds.len(),
        outbounds = built.outbounds.len(),
        "config built, starting instance"
    );

    let (_instance, _ohm, handles) = xray_core::functions::start_full(&built).await?;

    tracing::info!("Xray started, waiting for Ctrl+C");
    // 等待所有 inbound 任务（永久阻塞直到 Ctrl+C 或所有 inbound 退出）
    for h in handles {
        let _ = h.await;
    }
    tracing::info!("all inbound tasks exited, shutting down");
    Ok(())
}

/// 打印版本信息。对应 Go `PrintVersion()`。
fn print_version() {
    println!("Xray {}", xray_core::version::version());
    println!(
        "({})",
        xray_core::version::CODENAME
    );
    println!(
        "{}",
        xray_core::version::INTRO
    );
}

/// 转换配置格式。当前实现：加载 → 重新序列化为 pretty JSON。
/// TODO b5w-future: 支持 proto 输出格式。
async fn convert(input: PathBuf, output: Option<PathBuf>) -> anyhow::Result<()> {
    let cfg = xray_conf::load_file(&input)?;
    // 重新序列化为 JSON（验证 round-trip）
    let json = serde_json::to_string_pretty(&cfg)?;
    match output {
        Some(path) => {
            std::fs::write(&path, json)?;
            println!("converted config written to {}", path.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}
