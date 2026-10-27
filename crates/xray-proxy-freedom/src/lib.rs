#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))]
// 测试目标统一豁免（print 断言便利）；spawn 走 xray_common::testing（L3
// 闸不豁免），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
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
// P2 批次 B 插件化（差异表 §2.2 第 8 行）：L1/L4 面，wire/splice/finalRules 语义零改动。
pub mod plugin;
pub mod udp;

use std::sync::LazyLock;

use xray_frame::LogFacade;

/// freedom 域日志门面（nn8os 2b 同型处置：裸 tracing 宏 → LogFacade，禁令见
/// clippy.toml tracing 五宏条目）。域 = "freedom"，target `xray_frame::freedom`
/// + mask_secrets。
///
/// crate 级单例（域 = 协议名，全 crate 一个 target）：站点分散在 config/
/// dispatcher/handler/inbound/udp 五模块，逐模块各建一份会重复泄漏 target
/// 字符串且 target 相同——crate 级单份即可（同 wireguard/tun 先例）。
pub(crate) static FREEDOM_LOG: LazyLock<LogFacade> =
    LazyLock::new(|| LogFacade::new("freedom", vec![]));

#[cfg(test)]
pub(crate) mod test_support;

pub use config::{
    ALL_NETWORKS, Config, DEFAULT_BLOCK_PRIVATE_CIDRS, DefaultRuleType, DestinationOverride,
    DomainStrategy, FinalRule, FinalRuleConfig, Fragment, Noise, Range, RuleAction,
    get_default_rule_type,
};
pub use dispatcher::{
    FreedomDispatchBridge, make_dial_fn as make_freedom_dial_fn,
    make_dial_fn_with_config as make_freedom_dial_fn_with_config,
    make_dial_fn_with_sockopt as make_freedom_dial_fn_with_sockopt,
};
pub use error::{FreedomError, Result};
pub use handler::FreedomHandler;
pub use inbound::FreedomInboundHandler;
pub use plugin::FreedomPlugin;
