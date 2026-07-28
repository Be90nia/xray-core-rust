//! # API 命令 execute 函数
//!
//! ponytail: gRPC client stub 待 tonic-build 接入，当前所有 API 命令返回 Unimplemented。
//! 以下函数签名与参数已就绪，待 client 可用后替换为真实 gRPC 调用。

use crate::error::CliError;
use super::api_args::*;

/// 生成返回 Unimplemented 的函数体。
/// 用 `let _ = &args` 消除未使用参数警告，不 move 任何字段。
macro_rules! api_stub {
    ($args:expr, $what:expr) => {
        {
            let _ = &$args;
            Err(CliError::Unimplemented { what: $what })
        }
    };
}

/// add-inbound execute。
pub fn execute_add_inbound(args: &AddInboundArgs) -> Result<(), CliError> {
    api_stub!(args.api.server, "api add-inbound: gRPC client (handlerService.AddInbound) not yet wired")
}

/// remove-inbound execute。
pub fn execute_remove_inbound(args: &RemoveInboundArgs) -> Result<(), CliError> {
    api_stub!(args.tag, "api remove-inbound: gRPC client (handlerService.RemoveInbound) not yet wired")
}

/// add-outbound execute。
pub fn execute_add_outbound(args: &AddOutboundArgs) -> Result<(), CliError> {
    api_stub!(args.config, "api add-outbound: gRPC client (handlerService.AddOutbound) not yet wired")
}

/// remove-outbound execute。
pub fn execute_remove_outbound(args: &RemoveOutboundArgs) -> Result<(), CliError> {
    api_stub!(args.tag, "api remove-outbound: gRPC client (handlerService.RemoveOutbound) not yet wired")
}

/// add-rule execute。
pub fn execute_add_rule(args: &AddRuleArgs) -> Result<(), CliError> {
    api_stub!(args.append, "api add-rule: gRPC client (routerService.AddRule) not yet wired")
}

/// remove-rule execute。
pub fn execute_remove_rule(args: &RemoveRuleArgs) -> Result<(), CliError> {
    api_stub!(args.rule_tags, "api remove-rule: gRPC client (routerService.RemoveRule) not yet wired")
}

/// list-inbounds execute。
pub fn execute_list_inbounds(args: &ListInboundsArgs) -> Result<(), CliError> {
    api_stub!(args.only_tags, "api list-inbounds: gRPC client (handlerService.ListInbounds) not yet wired")
}

/// list-outbounds execute。
pub fn execute_list_outbounds(args: &ListOutboundsArgs) -> Result<(), CliError> {
    api_stub!(args.only_tags, "api list-outbounds: gRPC client (handlerService.ListOutbounds) not yet wired")
}

/// list-rules execute。
pub fn execute_list_rules(args: &ListRulesArgs) -> Result<(), CliError> {
    api_stub!(args.api.server, "api list-rules: gRPC client (routerService.ListRule) not yet wired")
}

/// stats execute。
pub fn execute_stats(args: &StatsArgs) -> Result<(), CliError> {
    api_stub!(args.reset, "api stats: gRPC client (statsService.GetStats) not yet wired")
}

/// stats-query execute。
pub fn execute_stats_query(args: &StatsQueryArgs) -> Result<(), CliError> {
    api_stub!(args.reset, "api stats-query: gRPC client (statsService.QueryStats) not yet wired")
}

/// sys-stats execute。
pub fn execute_sys_stats(args: &SysStatsArgs) -> Result<(), CliError> {
    api_stub!(args.api.server, "api sys-stats: gRPC client (statsService.GetSysStats) not yet wired")
}

/// restart-logger execute。
pub fn execute_restart_logger(args: &RestartLoggerArgs) -> Result<(), CliError> {
    api_stub!(args.api.server, "api restart-logger: gRPC client (logService.RestartLogger) not yet wired")
}

/// add-user execute。
pub fn execute_add_user(args: &AddUserArgs) -> Result<(), CliError> {
    api_stub!(args.config, "api add-user: gRPC client (handlerService.AlterInbound) not yet wired")
}

/// remove-user execute。
pub fn execute_remove_user(args: &RemoveUserArgs) -> Result<(), CliError> {
    api_stub!(args.emails, "api remove-user: gRPC client (handlerService.AlterInbound) not yet wired")
}

/// inbound-user execute。
pub fn execute_inbound_user(args: &InboundUserArgs) -> Result<(), CliError> {
    api_stub!(args.email, "api inbound-user: gRPC client (handlerService.GetInboundUsers) not yet wired")
}

/// inbound-user-count execute。
pub fn execute_inbound_user_count(args: &InboundUserCountArgs) -> Result<(), CliError> {
    api_stub!(args.tag, "api inbound-user-count: gRPC client (handlerService.GetInboundUsersCount) not yet wired")
}

/// balancer-info execute。
pub fn execute_balancer_info(args: &BalancerInfoArgs) -> Result<(), CliError> {
    api_stub!(args.balancer, "api balancer-info: gRPC client (routerService.GetBalancerInfo) not yet wired")
}

/// balancer-override execute。
pub fn execute_balancer_override(args: &BalancerOverrideArgs) -> Result<(), CliError> {
    api_stub!(args.remove, "api balancer-override: gRPC client (routerService.OverrideBalancerTarget) not yet wired")
}

/// source-ip-block execute。
pub fn execute_source_ip_block(args: &SourceIpBlockArgs) -> Result<(), CliError> {
    api_stub!(args.ips, "api source-ip-block: gRPC client (routerService.AddRule) not yet wired")
}

/// stats-online execute。
pub fn execute_stats_online(args: &StatsOnlineArgs) -> Result<(), CliError> {
    api_stub!(args.email, "api stats-online: gRPC client (statsService.GetStatsOnline) not yet wired")
}

/// online-ip-list execute。
pub fn execute_online_ip_list(args: &OnlineIpListArgs) -> Result<(), CliError> {
    api_stub!(args.all, "api online-ip-list: gRPC client (statsService.GetStatsOnlineIpList) not yet wired")
}

/// online-users execute。
pub fn execute_online_users(args: &OnlineUsersArgs) -> Result<(), CliError> {
    api_stub!(args.api.server, "api online-users: gRPC client (statsService.GetAllOnlineUsers) not yet wired")
}