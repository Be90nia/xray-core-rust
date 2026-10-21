//! Windows WFP 泄漏阻断（对应 Go `proxy/tun/tun_windows_wfp.go`）。
//!
//! 分两层：
//! - [`spec`]：平台无关的过滤器规格层（纯数据 + 纯函数，任意平台可单测）；
//! - FFI 安装层（`cfg(windows)`，后续切片）：把规格翻译成 `Fwpm*` 调用， 动态会话 +
//!   RAII，关闭即删除。
//!
//! 配置入口是 `StackOptions::auto_system_wfp_block_leak`（对应 Go
//! `infra/conf/tun.go:28`，合法值 `dns` / `misconfigtun`）。

pub mod spec;

#[cfg(windows)]
pub mod sys;

pub use spec::{
    Condition, Field, FilterSpec, Layer, LeakFilterInput, MatchType, Value, dns_outside_tun,
    leak_filter_specs,
};
