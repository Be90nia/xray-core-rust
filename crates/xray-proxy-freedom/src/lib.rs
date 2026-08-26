//! # xray-proxy-freedom
//!
//! Freedom 出站代理——直接连接目标地址（不走上游代理），Xray 的“直连”出口。
//! 对应 Go `proxy/freedom/`。
//!
//! ## 切片边界（P6-5 切片1）
//!
//! 实现配置层 + FinalRule 纯逻辑匹配 + 默认 CIDR 常量。
//! Handler/Process/dial/retry + IP CIDR 匹配留切片2。

pub mod config;
pub mod dispatcher;
pub mod error;
pub mod fragment;
pub mod handler;
pub mod inbound;
pub mod udp;

pub use config::{
    Config, DestinationOverride, DomainStrategy, FinalRule, FinalRuleConfig, Fragment, Noise, Range,
    RuleAction, ALL_NETWORKS, DEFAULT_BLOCK_PRIVATE_CIDRS, DefaultRuleType,
    get_default_rule_type,
};
pub use error::{FreedomError, Result};
pub use handler::FreedomHandler;
pub use dispatcher::FreedomDispatchBridge;
pub use dispatcher::make_dial_fn as make_freedom_dial_fn;
pub use dispatcher::make_dial_fn_with_config as make_freedom_dial_fn_with_config;
pub use inbound::FreedomInboundHandler;
