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
//! VMess 协议实现。
//!
//! 对应 Go 版本 `proxy/vmess/` 包。VMess 是 Xray 的核心代理协议之一，
//! 使用 AEAD（AES-128-GCM 或 ChaCha20-Poly1305）加密请求头，
//! 支持多种 body 加密策略（NONE/AES-128-GCM/ChaCha20-Poly1305/Legacy AES-128-CFB）。
//!
//! # 当前实现范围
//!
//! - **完整可测**（纯算法/协议核心）：
//!   - `account`：`MemoryAccount` + proto 转换 + `Equals`
//!   - `aead`：KDF（嵌套 HMAC-SHA256）+ `CreateAuthID`（AES-128 单块）+ `Seal/Open VMess AEAD
//!     Header` + `AuthIDDecoderHolder`（含反重放）
//!   - `validator`：`TimedUserValidator` 整合 AuthIDDecoderHolder + behaviorSeed
//!     `encoding::auth`：`Authenticate`（FNV1a）+ `GenerateChacha20Poly1305Key` +
//!     `GenerateChunkNonce` + `ShakeSizeParser` + `AEADSizeParser`
//!   - `encoding::server`：`ServerSession::DecodeRequestHeader`（AEAD 完整）+ `SessionHistory`
//!
//! - **trait + stub**（IO 边界，依赖 buf chunk reader/writer + cryption_io 完整链路）：
//!   - `ClientSession::{EncodeRequestBody, DecodeResponseHeader, DecodeResponseBody}`
//!   - `ServerSession::{DecodeRequestBody, EncodeResponseHeader, EncodeResponseBody}`
//!   - `inbound`/`outbound`：Handler `Process` 主入口依赖 `transport::Link` 全链路
//!
//! 等上层 buf chunk 加密包装链 + transport 接入后，注入 trait 实现即可激活。

// async-trait 展开对 trait 脱糖方法加 #[must_use]（其 expand.rs:69），clippy 1.99 起
// 将 Pin<Box<dyn Future>> 判为已 must_use → double_must_use 误报；宏行为非本 crate 可控。
#![allow(clippy::double_must_use)]

pub mod account;
pub mod aead;
pub mod dispatcher;
pub mod encoding;
pub mod error;
pub mod inbound;
pub mod outbound;
// P2 批次 B 插件化（差异表 §2.2 第 2 行）：L1/L4 面，aead/encoding wire 零改动。
pub mod plugin;
pub mod validator;

use std::sync::LazyLock;

use xray_frame::LogFacade;

/// vmess 域日志门面（nn8os 2b 同型处置：裸 tracing 宏 → LogFacade，禁令见
/// clippy.toml tracing 五宏条目）。域 = "vmess"，target `xray_frame::vmess`
/// + mask_secrets。
///
/// crate 级单例（域 = 协议名，全 crate 一个 target）：站点分散在 dispatcher/
/// plugin/aead/inbound 四模块，逐模块各建一份会重复泄漏 target 字符串且
/// target 相同——crate 级单份即可（同 wireguard/tun 先例）。
pub(crate) static VMESS_LOG: LazyLock<LogFacade> =
    LazyLock::new(|| LogFacade::new("vmess", vec![]));

pub use account::MemoryAccount;
pub use dispatcher::{VmessOutboundConfig, make_vmess_dial_fn, parse_vmess_config};
pub use encoding::server::SessionHistory;
pub use error::{Result, VmessError};
pub use inbound::{serve_vmess, server::handle_connection as handle_vmess_connection};
pub use plugin::{VmessLifecycle, VmessPlugin};
pub use validator::{MemoryUser, TimedUserValidator, Validator};

/// VMess 协议版本号（对应 Go 的 `encoding.Version` 常量）。
pub const VERSION: u8 = 1;

/// 请求选项位——从 `xray_common::protocol` 重新导出以保持向后兼容。
///
/// 新代码应直接使用 `xray_common::protocol::request_option::*`。
pub use xray_common::protocol::request_option;

/// 请求命令（与 `xray_common::protocol::Command` 同值，但 VMess 协议层用本枚举
/// 显式表达，避免 Go 端 `RequestCommand` 在 `protocol` 和 `vmess` 包间重复定义）。
///
/// 注意 VMess 没有 VLESS 的 `Rvs`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VmessCommand {
    /// TCP 代理。
    Tcp = 1,
    /// UDP 代理。
    Udp = 2,
    /// 多路复用，地址固定为 `v1.mux.cool`。
    Mux = 3,
}

impl VmessCommand {
    /// 从 u8 数值转换，未知值返回 `None`。
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Tcp),
            2 => Some(Self::Udp),
            3 => Some(Self::Mux),
            _ => None,
        }
    }

    /// 转为 u8 数值。
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl From<xray_common::protocol::Command> for VmessCommand {
    fn from(cmd: xray_common::protocol::Command) -> Self {
        match cmd {
            xray_common::protocol::Command::Tcp => Self::Tcp,
            xray_common::protocol::Command::Udp => Self::Udp,
            xray_common::protocol::Command::Mux => Self::Mux,
        }
    }
}
