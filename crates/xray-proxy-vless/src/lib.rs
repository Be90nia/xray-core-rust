//! VLESS 协议实现。
//!
//! 对应 Go 版本 `proxy/vless/` 包。VLESS 是 Xray 的核心代理协议之一，
//! 同时支持入站（与服务端 freedom 配合）和出站（与客户端 socks 配合）。
//!
//! # 当前实现范围
//!
//! - **完整可测**：
//!   - `account`：`MemoryAccount` + `Reverse` + proto 转换
//!   - `validator`：`Validator` trait + `MemoryValidator`（UUID 索引）
//!   - `encoding`：请求/响应头编解码 + `Addons` + 长度前缀包读写
//! - **trait + stub**（IO 边界）：
//!   - `encryption`：XTLS Vision 加密依赖 Rust 生态尚无的 `mlkem`/`utls`，
//!     以及 `unsafe.Pointer` 提取 TLS conn 内部字段（Rust 无法做到）
//!   - `inbound`/`outbound`：Handler `Process` 主入口依赖 `transport::Link`
//!     + `internet::Dialer` + `retry` + `signal` + `xudp` + `reverse` 全链路
//!
//! 等上层 transport 链路 + 加密 crate 接入后，注入 trait 实现即可激活。

pub mod account;
pub mod encoding;
pub mod encryption;
pub mod error;
pub mod inbound;
pub mod outbound;
pub mod validator;

pub use account::{MemoryAccount, Reverse};
pub use error::VlessError;
pub use validator::{MemoryValidator, Validator};

/// Flow 常量（对应 Go 的 `vless.None` / `vless.XRV`）。
pub const FLOW_NONE: &str = "none";

/// XTLS Vision flow 标识。
pub const FLOW_XRV: &str = "xtls-rprx-vision";
