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
pub mod validator;

pub use account::{MemoryAccount, Reverse};
pub use error::VlessError;
pub use validator::{MemoryUser, MemoryValidator, Validator};
pub use dispatcher::{make_dial_fn as make_vless_dial_fn, VlessOutboundConfig};
pub use inbound::server::{handle_connection as handle_vless_connection, serve_vless, VlessInboundOptions};
pub use inbound::handler::{FallbackDest, FallbackPolicy};

/// Flow 常量（对应 Go 的 `vless.None` / `vless.XRV`）。
pub const FLOW_NONE: &str = "none";

/// XTLS Vision flow 标识。
pub const FLOW_XRV: &str = "xtls-rprx-vision";

/// VLESS 反向代理固定域名（对应 Go `v1.rvs.cool`）。
pub const RVS_DOMAIN: &str = "v1.rvs.cool";

// 反向代理 + 预连接公共导出（bridge/portal 注册与监控）
pub use inbound::reverse::{PortalConfig, ReverseRegistry};
pub use outbound::preconnect::{PreConnectConfig, PreConnectPool};
pub use outbound::reverse::{ReverseConnState, ReverseMonitor};
