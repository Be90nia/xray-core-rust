#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        clippy::disallowed_macros,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]
// 测试目标统一豁免（print 宏断言 + 测试内裸 spawn 自管 runtime，bd g3cr
// 家规扩展；生产禁令不受影响）
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! # xray-app-router
//!
//! 翻译自 Go 版本 `app/router/`，实现路由引擎：根据规则（域名/IP/端口/协议等）
//! 选定出站 tag 或负载均衡器。
//!
//! ## 当前实现范围
//!
//! **业务核心（独立可测）**：
//! - `Router` 路由器主体（规则匹配 + 负载均衡 + 域名策略 + GeoData 文件加载）
//! - 9 种 `Condition`
//!   匹配器（Domain/IP/Port/Network/User/InboundTag/Protocol/Attribute/ProcessName）
//! - 4 种 `BalancingStrategy`（Random/RoundRobin/LeastPing/LeastLoad）
//! - `WeightManager` 权重管理
//! - `WebhookNotifier` 事件通知（含去重）
//! - `Override` 平衡器目标覆盖
//! - `Rule::build_rule(proto, balancers, geo_loader)`：`GeoDataLoader` 接入后 `geosite`/`geoip`
//!   rule 变体从 dat 文件加载
//!
//! **IO 边界（trait + 占位）**：
//! - `OutboundHandlerSelector`（Go `outbound.HandlerSelector`）：`select_outbounds` 返回
//!   `NotImplemented`
//! - `ObservationProvider`（Go `extension.Observatory`）：`get_observation` 返回 `NotImplemented`
//! - `WebhookNotifier::post`：实际 HTTP POST 留 TODO，事件构造与去重逻辑可独立测试
//! - `ProcessNameMatcher::find_process`：进程查找留 TODO（依赖 OS-specific sysinfo）
//! - `command/`：gRPC RoutingService 留 stub（依赖 stats.Channel + grpc 框架）
//!
//! **等接入**：等 xray-features 统一为手写 boxed future 风格后，再实现
//! `xray_features::routing::Router` trait（当前 trait 用 `#[async_trait]`，
//! 与新 crate 风格不一致）。
//! 对应 Go 源：`app/router/{router,condition,config,balancing,balancing_override,
//! strategy_leastload,strategy_leastping,strategy_random,weight,webhook}.go`

pub mod balancing;
pub mod command;
pub mod condition;
pub mod config;
pub mod context;
pub mod error;
pub mod router;
pub mod rule;
pub mod rule_set;
pub mod strategy_leastload;
pub mod strategy_leastping;
pub mod strategy_random;
pub mod webhook;
pub mod weight;

pub use balancing::{
    Balancer, BalancingStrategy, MemoryObservationProvider, RoundRobinStrategy, SimpleSelector,
};
pub use condition::{Condition, RouterBuildPool};
pub use config::DomainStrategy;
pub use context::{RoutingContext, RoutingData};
pub use error::RouterError;
pub use router::{Route, Router};
pub use rule::Rule;
pub use rule_set::{LoadedRuleSet, RuleSetConfig, RuleSetFormat, RuleSetRegistry, RuleSetType};
pub use strategy_leastload::LeastLoadStrategy;
pub use strategy_leastping::LeastPingStrategy;
pub use strategy_random::RandomStrategy;
pub use webhook::WebhookNotifier;
pub use weight::WeightManager;
