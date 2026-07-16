//! # Finalmask traffic disguise
//!
//! 对应 Go `transport/internet/finalmask/`。流量伪装框架——把代理流量伪装成
//! 常见协议（TLS/HTTP/WS/...）的特征，规避 DPI 检测。
//!
//! ## 子模块
//!
//! | 模块 | 对应 Go | 功能 | 状态 |
//! |------|---------|------|------|
//! | [`fragment`] | `fragment/` | TCP 分片抗 DPI | 骨架 |
//! | [`custom`] | `header/custom/` | 自定义头注入 | 骨架 |
//! | [`mkcp_disguise`] | `mkcp/` | mkcp 伪装 | 骨架 |
//! | [`noise`] | `noise/` | 噪声填充 | 骨架 |
//! | [`realm`] | `realm/` | realm 协议 | 骨架 |
//! | [`salamander`] | `salamander/` | salamander 编码 | 骨架 |
//! | [`sudoku`] | `sudoku/` | sudoku 编码 | 骨架 |
//! | [`xdns`] | `xdns/` | DNS 伪装传输 | 骨架 |
//! | [`xicmp`] | `xicmp/` | ICMP 伪装 | 骨架 |
//!
//! ## TODO rpn-future
//!
//! 各子模块从骨架升级为完整实现（参考 Go `transport/internet/finalmask/` 对应文件）。

pub mod fragment;
pub mod custom;
pub mod mkcp_disguise;
pub mod noise;
pub mod realm;
pub mod salamander;
pub mod sudoku;
pub mod xdns;
pub mod xicmp;

/// Finalmask 配置。
#[derive(Debug, Clone, Default)]
pub struct FinalmaskConfig {
    /// 启用的伪装模块名（如 "fragment", "noise"）。
    pub enabled_modules: Vec<String>,
}

/// Finalmask 入口——根据配置选择伪装模块。
///
/// TODO rpn-future: 实际实现应建立伪装模块链，按顺序应用。
pub fn apply_finalmask(_config: &FinalmaskConfig) -> std::io::Result<()> {
    Ok(())
}
