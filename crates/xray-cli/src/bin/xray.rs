#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr)] // CLI 可执行入口：错误/结果直写 stderr 即产品接口
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
//! - `xray run` — 运行（默认）
//! - `xray version` — 版本信息
//! - `xray uuid` — 生成 UUID
//! - `xray api <sub>` — API 命令（23 个子命令，Go main/commands/all/api/api.go）
//! - `xray tls <sub>` — TLS 工具
//! - `xray convert <sub>` — 格式转换
//! - `xray x25519`（别名 curve25519）/ `wg` / `mldsa65` / `mlkem768` / `vlessenc` — 密钥生成

use clap::{Parser, Subcommand};
use xray_cli::{
    commands::{
        api_args::*,
        api_exec, keys,
        tool::{self, ConvertCommand, TlsCommand},
    },
    error::CliError,
    run::{self, RunArgs},
    version,
};

/// CLI 顶层结构。
#[derive(Parser, Debug)]
#[command(name = "xray", version = "26.7.28", about = "Xray is a platform for building proxies.")]
struct Cli {
    /// 子命令。未指定时默认 `run`（v4 兼容）。
    #[command(subcommand)]
    command: Option<Command>,
}

/// API 子命令组。
#[derive(Subcommand, Debug)]
enum ApiCommand {
    /// Add an inbound.
    #[command(alias = "adi")]
    AddInbound(AddInboundArgs),

    /// Remove an inbound.
    #[command(alias = "rmi")]
    RemoveInbound(RemoveInboundArgs),

    /// Add an outbound.
    #[command(alias = "ado")]
    AddOutbound(AddOutboundArgs),

    /// Remove an outbound.
    #[command(alias = "rmo")]
    RemoveOutbound(RemoveOutboundArgs),

    /// Add a routing rule.
    #[command(alias = "adrules")]
    AddRule(AddRuleArgs),

    /// Remove a routing rule.
    #[command(alias = "rmrules")]
    RemoveRule(RemoveRuleArgs),

    /// List all inbounds.
    #[command(alias = "lsi")]
    ListInbounds(ListInboundsArgs),

    /// List all outbounds.
    #[command(alias = "lso")]
    ListOutbounds(ListOutboundsArgs),

    /// List all routing rules.
    #[command(alias = "lsrules")]
    ListRules(ListRulesArgs),

    /// Get stats by name.
    Stats(StatsArgs),

    /// Query stats by pattern.
    #[command(alias = "statsquery")]
    StatsQuery(StatsQueryArgs),

    /// Get system stats.
    #[command(alias = "statssys")]
    SysStats(SysStatsArgs),

    /// Restart logger.
    #[command(alias = "restartlogger")]
    RestartLogger(RestartLoggerArgs),

    /// Add a user to an inbound.
    #[command(alias = "adu")]
    AddUser(AddUserArgs),

    /// Remove a user from an inbound.
    #[command(alias = "rmu")]
    RemoveUser(RemoveUserArgs),

    /// Get inbound user info.
    #[command(alias = "inbounduser")]
    InboundUser(InboundUserArgs),

    /// Get inbound user count.
    #[command(alias = "inboundusercount")]
    InboundUserCount(InboundUserCountArgs),

    /// Get balancer info.
    #[command(alias = "bi")]
    BalancerInfo(BalancerInfoArgs),

    /// Override balancer target.
    #[command(alias = "bo")]
    BalancerOverride(BalancerOverrideArgs),

    /// Block source IPs.
    #[command(alias = "sib")]
    SourceIpBlock(SourceIpBlockArgs),

    /// Get online stats for a user.
    #[command(alias = "statsonline")]
    StatsOnline(StatsOnlineArgs),

    /// Get online IP list.
    #[command(alias = "statsonlineiplist")]
    OnlineIpList(OnlineIpListArgs),

    /// Get all online users.
    #[command(alias = "statsgetallonlineusers")]
    OnlineUsers(OnlineUsersArgs),
}

/// 子命令枚举。
#[derive(Subcommand, Debug)]
enum Command {
    /// Run Xray with config, the default command.
    Run(RunArgs),

    /// Print version info.
    Version,

    /// Generate UUID.
    Uuid(tool::UuidArgs),

    /// Generate key pair for X25519 key exchange (REALITY, VLESS Encryption).
    #[command(visible_alias = "curve25519")]
    X25519(keys::X25519Args),

    /// Generate key pair for X25519 key exchange (WireGuard).
    Wg(keys::WgArgs),

    /// Generate key pair for ML-DSA-65 post-quantum signature (REALITY).
    Mldsa65(keys::Mldsa65Args),

    /// Generate key pair for ML-KEM-768 post-quantum key exchange (VLESS Encryption).
    Mlkem768(keys::Mlkem768Args),

    /// Generate decryption/encryption json pair (VLESS Encryption).
    Vlessenc,

    /// API commands to interact with a running Xray instance.
    Api {
        #[command(subcommand)]
        command: ApiCommand,
    },

    /// TLS tool commands.
    Tls {
        #[command(subcommand)]
        command: TlsCommand,
    },

    /// Convert config format.
    Convert {
        #[command(subcommand)]
        command: ConvertCommand,
    },
}

// bd uf2p: mimalloc 全局分配器（feature 默认开；--no-default-features 回退
// 系统分配器）。proxy 小对象密集分配场景公开基准 +5-15%。
// P0 护栏：包一层计数 wrapper，XRAY_ALLOC_STATS=1 时启用进程级统计，
// 默认零开销直通（alloc_stats 模块文档）。
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL_ALLOC: xray_cli::alloc_stats::StatsAlloc<mimalloc::MiMalloc> =
    xray_cli::alloc_stats::StatsAlloc(mimalloc::MiMalloc);

// bd vjbq: Go `base.Command` 的 flag 风格是单横线长名（`-test`/`-config`/`-format`），
// clap 会把 `-test` 拆成短参聚合 `-t -e -s -t` 而报 unexpected argument——passwall
// 启动预检 `xray run -test -c` 即因此阻塞。归一化：已登记长名（含 `-x=v` 形态）
// 补足双横线；未登记 token（真短参聚合如 `-c`）原样保留。
const GO_STYLE_LONG_FLAGS: &[&str] =
    &["config", "confdir", "format", "test", "dump", "unix", "version", "help"];

fn normalize_go_style_args(mut argv: Vec<String>) -> Vec<String> {
    // Go v4 兼容（getArgsV4Compatible）：首个 token 若不是子命令、也非顶层
    // help/version 旗标，则按"默认 run 的参数"处理——插 `run` 到 argv[1]。
    const KNOWN_SUBS: &[&str] = &[
        "run", "version", "uuid", "api", "tls", "convert", "x25519", "curve25519", "wg",
        "mldsa65", "mlkem768", "vlessenc",
    ];
    let needs_run_insert = match argv.get(1) {
        None => true, // 裸 `xray` → 默认 run
        Some(a) => {
            !(KNOWN_SUBS.contains(&a.as_str())
                || matches!(a.as_str(), "-h" | "--help" | "-version" | "--version"))
        },
    };
    if needs_run_insert {
        argv.insert(1, "run".into());
    }
    for tok in argv.iter_mut().skip(1) {
        let Some(name) = tok.strip_prefix('-') else { continue };
        if name.starts_with('-') {
            continue; // 已是双横线长名
        }
        let (base, eq_val) = match name.split_once('=') {
            Some((b, v)) => (b, Some(v)),
            None => (name, None),
        };
        if GO_STYLE_LONG_FLAGS.contains(&base) {
            *tok = match eq_val {
                Some(v) => format!("--{base}={v}"),
                None => format!("--{base}"),
            };
        }
    }
    argv
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // P0 护栏：计数分配器开关解析 + dump 线程（未开 env 时零开销直返）。
    xray_cli::alloc_stats::init();
    // 9tk4：tracing subscriber 不再在此急切初始化（此前固定 EnvFilter "info"
    // 完全绕过 loglevel 配置）。`run` 路径在配置解析后按 `log.loglevel`
    // 推导过滤器（见 run::execute → run::init_tracing）；其余工具子命令
    // 维持原 info 默认。RUST_LOG 仍可覆盖（例:RUST_LOG=xray_tls=debug）。
    // bd xag3③：env 热路径闸门启动期显式解析一次（对齐 Go reloadEnvSettings；
    // LazyLock 首调兜底，此处为显式语义锚点）。
    xray_common::platform::env::reload_env_settings();
    let cli = Cli::parse_from(normalize_go_style_args(std::env::args().collect()));
    // v4 兼容：无子命令时默认 run
    let command = cli.command.unwrap_or(Command::Run(RunArgs::default()));
    if !matches!(command, Command::Run(_)) {
        run::init_tracing("info");
    }
    // P3 护栏（tokio #8065/#8120 教训）：启动期一次性抓取 RuntimeMetrics 快照
    // 并以 tracing::info 输出，便于日志归档 worker 行为基线（park/busy/noop/steal）。
    // 失败仅记 warn，不影响主路径。
    xray_common::runtime_guard::log_runtime_snapshot("startup");
    match execute(command).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // Go main/run.go:82 配置错误退出码 23（systemd 等 init 不重启）。
            // 其他错误（IO / API / 参数）用 1。
            eprintln!("Error: {e}");
            if matches!(
                e,
                CliError::ConfigNotFound(_)
                    | CliError::ConfigLoadFailed(_)
                    | CliError::InvalidConfig(_)
            ) {
                std::process::ExitCode::from(23)
            } else {
                std::process::ExitCode::FAILURE
            }
        },
    }
}

/// API 子命令 dispatch。
async fn execute_api(cmd: &ApiCommand) -> Result<(), CliError> {
    match cmd {
        ApiCommand::AddInbound(args) => api_exec::execute_add_inbound(args).await,
        ApiCommand::RemoveInbound(args) => api_exec::execute_remove_inbound(args).await,
        ApiCommand::AddOutbound(args) => api_exec::execute_add_outbound(args).await,
        ApiCommand::RemoveOutbound(args) => api_exec::execute_remove_outbound(args).await,
        ApiCommand::AddRule(args) => api_exec::execute_add_rule(args).await,
        ApiCommand::RemoveRule(args) => api_exec::execute_remove_rule(args).await,
        ApiCommand::ListInbounds(args) => api_exec::execute_list_inbounds(args).await,
        ApiCommand::ListOutbounds(args) => api_exec::execute_list_outbounds(args).await,
        ApiCommand::ListRules(args) => api_exec::execute_list_rules(args).await,
        ApiCommand::Stats(args) => api_exec::execute_stats(args).await,
        ApiCommand::StatsQuery(args) => api_exec::execute_stats_query(args).await,
        ApiCommand::SysStats(args) => api_exec::execute_sys_stats(args).await,
        ApiCommand::RestartLogger(args) => api_exec::execute_restart_logger(args).await,
        ApiCommand::AddUser(args) => api_exec::execute_add_user(args).await,
        ApiCommand::RemoveUser(args) => api_exec::execute_remove_user(args).await,
        ApiCommand::InboundUser(args) => api_exec::execute_inbound_user(args).await,
        ApiCommand::InboundUserCount(args) => api_exec::execute_inbound_user_count(args).await,
        ApiCommand::BalancerInfo(args) => api_exec::execute_balancer_info(args).await,
        ApiCommand::BalancerOverride(args) => api_exec::execute_balancer_override(args).await,
        ApiCommand::SourceIpBlock(args) => api_exec::execute_source_ip_block(args).await,
        ApiCommand::StatsOnline(args) => api_exec::execute_stats_online(args).await,
        ApiCommand::OnlineIpList(args) => api_exec::execute_online_ip_list(args).await,
        ApiCommand::OnlineUsers(args) => api_exec::execute_online_users(args).await,
    }
}

/// 子命令 dispatch。
async fn execute(command: Command) -> Result<(), CliError> {
    match command {
        Command::Run(args) => run::execute(args).await,
        Command::Version => {
            version::print_version();
            Ok(())
        },
        Command::Uuid(args) => tool::execute_uuid(&args),
        Command::X25519(args) => keys::execute_x25519(&args),
        Command::Wg(args) => keys::execute_wg(&args),
        Command::Mldsa65(args) => keys::execute_mldsa65(&args),
        Command::Mlkem768(args) => keys::execute_mlkem768(&args),
        Command::Vlessenc => keys::execute_vlessenc(),
        Command::Api { command } => execute_api(&command).await,
        Command::Tls { command } => tool::execute_tls(&command).await,
        Command::Convert { command } => tool::execute_convert(&command),
    }
}

#[cfg(test)]
mod go_flag_tests {
    use super::normalize_go_style_args;

    fn v(args: &[&str]) -> Vec<String> {
        normalize_go_style_args(std::iter::once("xray".to_string()).chain(args.iter().map(|s| s.to_string())).collect())
    }

    #[test]
    fn passwall_preset_single_dash_test() {
        // bd vjbq 阻塞场景: passwall 预检 `xray run -test -c cfg`
        assert_eq!(v(&["run", "-test", "-c", "a.json"]),
                   vec!["xray", "run", "--test", "-c", "a.json"]);
    }

    #[test]
    fn default_run_insertion() {
        // 裸 xray → run (Go v4)
        assert_eq!(v(&[]), vec!["xray", "run"]);
        // 前导单横线旗标(非子命令) → 插 run (Go main.go 语义)
        assert_eq!(v(&["-test", "-c", "a.json"]),
                   vec!["xray", "run", "--test", "-c", "a.json"]);
        assert_eq!(v(&["-config=a.json"]),
                   vec!["xray", "run", "--config=a.json"]);
    }

    #[test]
    fn known_long_flags_normalized() {
        assert_eq!(v(&["run", "-config", "a.json", "-format", "json"]),
                   vec!["xray", "run", "--config", "a.json", "--format", "json"]);
        assert_eq!(v(&["run", "-confdir", "/etc/x", "-dump"]),
                   vec!["xray", "run", "--confdir", "/etc/x", "--dump"]);
    }

    #[test]
    fn short_flags_and_subcommands_untouched() {
        // 真短参聚合(未登记名)不动
        assert_eq!(v(&["run", "-c", "a.json"]), vec!["xray", "run", "-c", "a.json"]);
        // 双横线不动
        assert_eq!(v(&["run", "--test"]), vec!["xray", "run", "--test"]);
        // 子命令路径不受影响(uuid 是子命令, 不插 run)
        assert_eq!(v(&["uuid"]), vec!["xray", "uuid"]);
        assert_eq!(v(&["api", "adi", "-server=127.0.0.1:8080"]),
                   vec!["xray", "api", "adi", "-server=127.0.0.1:8080"]);
    }

    #[test]
    fn top_level_help_version_skip_run_insert() {
        assert_eq!(v(&["-h"]), vec!["xray", "-h"]);
        assert_eq!(v(&["-version"]), vec!["xray", "--version"]);
    }
}
