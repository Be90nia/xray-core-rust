#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
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
//! - **trait + stub**（IO 边界）：
//!   - `inbound`/`outbound`：Handler `Process` 主入口依赖 dispatcher 全链路集成
//!
//! 加密层 + encoding 已完整实现（127 tests），inbound/outbound 集成待 dispatcher 接入。

pub mod account;
pub mod dispatcher;
pub mod encoding;
pub mod encryption;
pub mod error;
pub mod inbound;
pub mod outbound;
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

/// VLESS 反向代理固定域名（对应 Go `v1.rvs.cool`）。
pub const RVS_DOMAIN: &str = "v1.rvs.cool";

// 反向代理 + 预连接公共导出（bridge/portal 注册与监控）
pub use inbound::reverse::{PortalConfig, ReverseRegistry};
pub use outbound::{
    preconnect::{PreConnectConfig, PreConnectPool},
    reverse::{ReverseConnState, ReverseMonitor},
};
