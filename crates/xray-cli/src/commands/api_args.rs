//! # API 子命令参数定义
//!
//! 对应 Go `main/commands/all/api/`。通过 gRPC 与 commander 通信。
//!
//! ## 状态
//!
//! xray-proto 仅用 prost-build 生成消息类型，未用 tonic-build 生成 gRPC client stub。
//! 当前阶段所有 API 命令的 execute 返回 [`CliError::Unimplemented`]，
//! 待 tonic-build 接入后补全真实 gRPC 调用。

use clap::Args;

// ---------------------------------------------------------------------------
// 共享参数
// ---------------------------------------------------------------------------

/// API 命令共享参数（对应 Go `api/shared.go` 的 setSharedFlags）。
#[derive(Args, Debug, Clone)]
pub struct ApiSharedArgs {
    /// API server 地址，格式 host:port。
    #[arg(short, long = "server", env = "XRAY_API_SERVER", default_value = "127.0.0.1:8080")]
    pub server: String,

    /// API 调用超时秒数。
    #[arg(short, long = "timeout", env = "XRAY_API_TIMEOUT", default_value_t = 3u64)]
    pub timeout: u64,

    /// 以 JSON 格式输出。
    #[arg(long = "json", default_value_t = false)]
    pub json: bool,
}

impl Default for ApiSharedArgs {
    fn default() -> Self {
        Self { server: "127.0.0.1:8080".to_string(), timeout: 3, json: false }
    }
}

// ---------------------------------------------------------------------------
// 命令参数定义
// ---------------------------------------------------------------------------

/// `xray api add-inbound` - 添加入站。
#[derive(Args, Debug, Clone)]
pub struct AddInboundArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 配置文件路径（支持 `stdin:` 从标准输入读取）。
    pub config: String,
}

/// `xray api remove-inbound` - 移除入站。
#[derive(Args, Debug, Clone)]
pub struct RemoveInboundArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 配置文件路径或 tag 字符串。
    pub tag: String,
}

/// `xray api add-outbound` - 添加出站。
#[derive(Args, Debug, Clone)]
pub struct AddOutboundArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 配置文件路径（支持 `stdin:`）。
    pub config: String,
}

/// `xray api remove-outbound` - 移除出站。
#[derive(Args, Debug, Clone)]
pub struct RemoveOutboundArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 配置文件路径或 tag 字符串。
    pub tag: String,
}

/// `xray api add-rule` - 添加路由规则。
#[derive(Args, Debug, Clone)]
pub struct AddRuleArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 路由配置文件路径。
    pub config: String,
    /// 追加到现有规则末尾而非替换。
    #[arg(long = "append", default_value_t = false)]
    pub append: bool,
}

/// `xray api remove-rule` - 移除路由规则。
#[derive(Args, Debug, Clone)]
pub struct RemoveRuleArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 要移除的规则 tag 列表。
    #[arg(required = true)]
    pub rule_tags: Vec<String>,
}

/// `xray api list-inbounds` - 列出所有入站。
#[derive(Args, Debug, Clone)]
pub struct ListInboundsArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 仅返回 tag 列表。
    #[arg(long = "only-tags", default_value_t = false)]
    pub only_tags: bool,
}

/// `xray api list-outbounds` - 列出所有出站。
#[derive(Args, Debug, Clone)]
pub struct ListOutboundsArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 仅返回 tag 列表。
    #[arg(long = "only-tags", default_value_t = false)]
    pub only_tags: bool,
}

/// `xray api list-rules` - 列出所有路由规则。
#[derive(Args, Debug, Clone)]
pub struct ListRulesArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
}

/// `xray api stats` - 获取统计信息。
#[derive(Args, Debug, Clone)]
pub struct StatsArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 统计项名称。
    #[arg(short, long = "name")]
    pub name: String,
    /// 获取后重置计数器。
    #[arg(long = "reset", default_value_t = false)]
    pub reset: bool,
}

/// `xray api stats-query` - 按模式查询统计信息。
#[derive(Args, Debug, Clone)]
pub struct StatsQueryArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 匹配模式（空字符串匹配全部）。
    #[arg(short, long = "pattern", default_value = "")]
    pub pattern: String,
    /// 查询后重置计数器。
    #[arg(long = "reset", default_value_t = false)]
    pub reset: bool,
}

/// `xray api sys-stats` - 获取系统统计信息。
#[derive(Args, Debug, Clone)]
pub struct SysStatsArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
}

/// `xray api restart-logger` - 重启日志记录器。
#[derive(Args, Debug, Clone)]
pub struct RestartLoggerArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
}

/// `xray api add-user` - 添加入站用户。
#[derive(Args, Debug, Clone)]
pub struct AddUserArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 用户配置文件路径（含 inbound tag 和 users 字段）。
    pub config: String,
}

/// `xray api remove-user` - 移除入站用户。
#[derive(Args, Debug, Clone)]
pub struct RemoveUserArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 入站 tag。
    #[arg(short, long = "tag")]
    pub tag: String,
    /// 用户邮箱列表。
    #[arg(required = true)]
    pub emails: Vec<String>,
}

/// `xray api inbound-user` - 查询入站用户信息。
#[derive(Args, Debug, Clone)]
pub struct InboundUserArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 入站 tag。
    #[arg(short, long = "tag")]
    pub tag: String,
    /// 用户邮箱。
    #[arg(short, long = "email")]
    pub email: String,
}

/// `xray api inbound-user-count` - 查询入站用户数量。
#[derive(Args, Debug, Clone)]
pub struct InboundUserCountArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 入站 tag。
    #[arg(short, long = "tag")]
    pub tag: String,
}

/// `xray api balancer-info` - 查询均衡器信息。
#[derive(Args, Debug, Clone)]
pub struct BalancerInfoArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 均衡器 tag。
    pub balancer: String,
}

/// `xray api balancer-override` - 覆盖均衡器目标。
#[derive(Args, Debug, Clone)]
pub struct BalancerOverrideArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 均衡器 tag。
    #[arg(short, long = "balancer")]
    pub balancer: String,
    /// 移除而非添加覆盖目标。
    #[arg(short, long = "remove", default_value_t = false)]
    pub remove: bool,
    /// 目标出站 tag。
    pub target: String,
}

/// `xray api source-ip-block` - 阻断来源 IP。
#[derive(Args, Debug, Clone)]
pub struct SourceIpBlockArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 入站 tag（可选）。
    #[arg(long = "inbound")]
    pub inbound: Option<String>,
    /// 出站 tag（可选）。
    #[arg(long = "outbound")]
    pub outbound: Option<String>,
    /// 规则 tag，默认 `sourceIpBlock`。
    #[arg(long = "ruletag", default_value = "sourceIpBlock")]
    pub rule_tag: String,
    /// 添加后重置已有规则。
    #[arg(long = "reset", default_value_t = false)]
    pub reset: bool,
    /// 要阻断的 IP 地址列表。
    #[arg(required = true)]
    pub ips: Vec<String>,
}

/// `xray api stats-online` - 查询用户在线状态。
#[derive(Args, Debug, Clone)]
pub struct StatsOnlineArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 用户邮箱。
    #[arg(short, long = "email")]
    pub email: String,
}

/// `xray api online-ip-list` - 查询在线 IP 列表。
#[derive(Args, Debug, Clone)]
pub struct OnlineIpListArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
    /// 用户邮箱（与 `--all` 互斥）。
    #[arg(short, long = "email")]
    pub email: Option<String>,
    /// 查询所有在线用户（与 `--email` 互斥）。
    #[arg(long = "all", default_value_t = false)]
    pub all: bool,
    /// 包含流量统计（仅 `--all` 模式）。
    #[arg(long = "include-traffic", default_value_t = false)]
    pub include_traffic: bool,
    /// 获取后重置计数器（仅 `--all` 模式）。
    #[arg(long = "reset", default_value_t = false)]
    pub reset: bool,
}

/// `xray api online-users` - 获取所有在线用户列表。
#[derive(Args, Debug, Clone)]
pub struct OnlineUsersArgs {
    #[command(flatten)]
    pub api: ApiSharedArgs,
}
