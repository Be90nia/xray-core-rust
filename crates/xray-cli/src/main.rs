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
//! - `xray api <sub>` — API 命令（22 个子命令）
//! - `xray tls <sub>` — TLS 工具
//! - `xray convert <sub>` — 格式转换

use clap::{Parser, Subcommand};

use xray_cli::commands::api_args::*;
use xray_cli::commands::api_exec;
use xray_cli::commands::tool::{self, ConvertCommand, TlsCommand};
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
    #[command(alias = "adr")]
    AddRule(AddRuleArgs),

    /// Remove a routing rule.
    #[command(alias = "rmr")]
    RemoveRule(RemoveRuleArgs),

    /// List all inbounds.
    #[command(alias = "lsi")]
    ListInbounds(ListInboundsArgs),

    /// List all outbounds.
    #[command(alias = "lso")]
    ListOutbounds(ListOutboundsArgs),

    /// List all routing rules.
    #[command(alias = "lsr")]
    ListRules(ListRulesArgs),

    /// Get stats by name.
    Stats(StatsArgs),

    /// Query stats by pattern.
    #[command(alias = "qs")]
    StatsQuery(StatsQueryArgs),

    /// Get system stats.
    #[command(alias = "ss")]
    SysStats(SysStatsArgs),

    /// Restart logger.
    #[command(alias = "rl")]
    RestartLogger(RestartLoggerArgs),

    /// Add a user to an inbound.
    #[command(alias = "adu")]
    AddUser(AddUserArgs),

    /// Remove a user from an inbound.
    #[command(alias = "rmu")]
    RemoveUser(RemoveUserArgs),

    /// Get inbound user info.
    #[command(alias = "iu")]
    InboundUser(InboundUserArgs),

    /// Get inbound user count.
    #[command(alias = "iuc")]
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
    #[command(alias = "so")]
    StatsOnline(StatsOnlineArgs),

    /// Get online IP list.
    #[command(alias = "oil")]
    OnlineIpList(OnlineIpListArgs),

    /// Get all online users.
    #[command(alias = "ou")]
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

/// API 子命令 dispatch。
fn execute_api(cmd: &ApiCommand) -> Result<(), CliError> {
    match cmd {
        ApiCommand::AddInbound(args) => api_exec::execute_add_inbound(args),
        ApiCommand::RemoveInbound(args) => api_exec::execute_remove_inbound(args),
        ApiCommand::AddOutbound(args) => api_exec::execute_add_outbound(args),
        ApiCommand::RemoveOutbound(args) => api_exec::execute_remove_outbound(args),
        ApiCommand::AddRule(args) => api_exec::execute_add_rule(args),
        ApiCommand::RemoveRule(args) => api_exec::execute_remove_rule(args),
        ApiCommand::ListInbounds(args) => api_exec::execute_list_inbounds(args),
        ApiCommand::ListOutbounds(args) => api_exec::execute_list_outbounds(args),
        ApiCommand::ListRules(args) => api_exec::execute_list_rules(args),
        ApiCommand::Stats(args) => api_exec::execute_stats(args),
        ApiCommand::StatsQuery(args) => api_exec::execute_stats_query(args),
        ApiCommand::SysStats(args) => api_exec::execute_sys_stats(args),
        ApiCommand::RestartLogger(args) => api_exec::execute_restart_logger(args),
        ApiCommand::AddUser(args) => api_exec::execute_add_user(args),
        ApiCommand::RemoveUser(args) => api_exec::execute_remove_user(args),
        ApiCommand::InboundUser(args) => api_exec::execute_inbound_user(args),
        ApiCommand::InboundUserCount(args) => api_exec::execute_inbound_user_count(args),
        ApiCommand::BalancerInfo(args) => api_exec::execute_balancer_info(args),
        ApiCommand::BalancerOverride(args) => api_exec::execute_balancer_override(args),
        ApiCommand::SourceIpBlock(args) => api_exec::execute_source_ip_block(args),
        ApiCommand::StatsOnline(args) => api_exec::execute_stats_online(args),
        ApiCommand::OnlineIpList(args) => api_exec::execute_online_ip_list(args),
        ApiCommand::OnlineUsers(args) => api_exec::execute_online_users(args),
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
        Command::Uuid(args) => tool::execute_uuid(&args),
        Command::Api { command } => execute_api(&command),
        Command::Tls { command } => tool::execute_tls(&command),
        Command::Convert { command } => tool::execute_convert(&command),
    }
}