#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))]
// 测试目标统一豁免（print 断言便利）；spawn 走 xray_common::testing（L3
// 闸不豁免），生产禁令不受影响
// 713x6 时钟禁令配套：测试耗时断言/夹具用裸时钟读数属测试面（存量不动），
// 生产站点逐点 allow + 理由登记（台账见 reports/audit-2026-10-26/proxy-clock-sweep.md）
#![cfg_attr(test, allow(clippy::disallowed_methods))]
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! VLESS 协议实现。
//!
//! 对应 Go 版本 `proxy/vless/` 包。VLESS 是 Xray 的核心代理协议之一，
//! 同时支持入站（与服务端 freedom 配合）和出站（与客户端 socks 配合）。
//!
//! # 当前实现范围
//!
//! - **完整实现**：
//!   - `account`：`MemoryAccount` + `Reverse` + proto 转换
//!   - `validator`：`Validator` trait + `MemoryValidator`（UUID 索引）
//!   - `encoding`：请求/响应头编解码 + `Addons` + 长度前缀包读写
//!   - `encryption`：XTLS Vision 加密（ml-kem + x25519-dalek + blake3 AEAD + VisionConn splice）
//!   - `dispatcher`：出站拨号/请求头/出入站主体（含 XRV 的 UDP→mux 承载）
//!   - `inbound::server`：入站解码 + fallback + reverse
//!
//! 出站/入站主入口即 `dispatcher::make_dial_fn` 与 `inbound::server::serve_vless`；
//! 早期「Handler + Processor」骨架（IO trait stub）无生产调用方，已删除。

pub mod account;
pub mod dispatcher;
pub mod encoding;
pub mod encryption;
pub mod error;
pub mod inbound;
// P2 批次 B 插件化（差异表 §2.2 第 1 行）：L1/L4 面，encoding/encryption/inbound/outbound wire
// 零改动。
pub mod plugin;
pub mod validator;

pub use account::{MemoryAccount, Reverse};
pub use dispatcher::{VlessOutboundConfig, make_dial_fn as make_vless_dial_fn};
pub use error::VlessError;
pub use inbound::{
    handler::{FallbackDest, FallbackPolicy},
    server::{
        VlessInboundOptions, handle_connection as handle_vless_connection,
        handle_connection_with_fallback, serve_vless,
    },
};
pub use plugin::{VlessLifecycle, VlessPlugin};
pub use validator::{MemoryUser, MemoryValidator, Validator};

/// Flow 常量（对应 Go 的 `vless.None` / `vless.XRV`）。
pub const FLOW_NONE: &str = "none";

/// XTLS Vision flow 标识。
pub const FLOW_XRV: &str = "xtls-rprx-vision";

/// `FLOW_XRV` + `-udp443` 后缀：出站白名单第三值（Go `infra/conf/vless.go:331`）。
///
/// 它**不上 wire**——Go `proxy/vless/outbound/outbound.go:246-251` 把它截成
/// [`FLOW_XRV`] 再编码请求头，仅多一个「放行 UDP/443」开关（放行后经 mux 承载）。
pub const FLOW_XRV_UDP443: &str = "xtls-rprx-vision-udp443";

/// 归一化 VLESS **出站** `flow`：返回 `(上 wire 的 flow, allow_udp443)`。
///
/// 对齐 Go 两处语义：
/// - `infra/conf/vless.go:329-334`：白名单仅 `""` / [`FLOW_XRV`] / [`FLOW_XRV_UDP443`]，其余值
///   Build 硬错（拒启）；
/// - `proxy/vless/outbound/outbound.go:246-251`：`-udp443` 分支先置 `allowUDP443 = true`，再把 flow
///   截成 [`FLOW_XRV`]（`[:16]`）后 fallthrough。
///
/// # Errors
/// 非白名单值 → `Err`（文案对齐 Go `VLESS users: "flow" doesn't support "…"`）。
pub fn normalize_outbound_flow(flow: &str) -> Result<(&'static str, bool), String> {
    match flow {
        "" | FLOW_NONE => Ok(("", false)),
        FLOW_XRV => Ok((FLOW_XRV, false)),
        FLOW_XRV_UDP443 => Ok((FLOW_XRV, true)),
        other => Err(format!(r#"VLESS users: "flow" doesn't support "{other}" in this version"#)),
    }
}

/// VLESS 反向代理固定域名（对应 Go `v1.rvs.cool`）。
pub const RVS_DOMAIN: &str = "v1.rvs.cool";

// 反向代理公共导出（bridge/portal 注册与监控）
pub use inbound::reverse::{PortalConfig, ReverseRegistry};
