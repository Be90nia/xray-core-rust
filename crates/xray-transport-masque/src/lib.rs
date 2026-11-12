#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing；B2 接线时按 splithttp 同款加 LOG/HOT_LOG 门面，
// 本批无日志消费站点，先立该静态会触发 deny(warnings) dead_code）
//! # xray-transport-masque
//!
//! MASQUE 传输——RFC 9484 CONNECT-IP over HTTP/2 胶囊隧道（对应 Go
//! `transport/internet/masque/` + `transport/internet/masque/connectip/`，
//! 裁定基准 v26.11.9 @ 676eaf66）。
//!
//! ## 本 crate 范围（规划 `docs/architecture/xray-frame-masque-实施计划-2026-11-11.md`）
//!
//! 已落地（B0+B1+B2）：
//! - [`capsule`] — CONNECT-IP 胶囊编解码内核（RFC 9297 帧格式 + RFC 9484 四类胶囊 + 上限校验 +
//!   未知类型跳过）
//! - [`config`] — `masqueSettings` 解析（host/path/headers/user-pass/warp）
//! - [`warp`] — WARP 变体（Cloudflare）：自签客户端证书 + 端点公钥 pin + 静态地址
//!   + Cloudflare 请求头 / draft setting 常量（Go `warp.go` 直译）
//! - [`error`] — [`MasqueError`] 分类（ClauseId::ErrorClassifiedNoPanicEscape）
//! - [`register`] — dialer/listener 注册管线（已接聚合口：
//!   `xray_core::register::register_all_transports` 消费 `register_dialer`/`register_listener`）
//! - [`h2`] — CONNECT-IP over h2 extended CONNECT 绑定（hyper，B2.1）
//! - [`connect`] — [`connect::ConnectIpSession`]（地址协商 / IP 包收发 / MTU-ICMP 回灌，B2.2）
//! - [`dialer`] — 客户端拨号（finalmask 接线 + TLS(ALPN=h2) + establish，B2.6）
//!
//! B4 已落地：[`hub`]（服务端 accept）+ [`pool`]（地址池）——规划 §5 B4 收口。
//!
//! ## udf 不适用判定（CLAUDE.md §3.5.5）
//!
//! 胶囊 wire 语义与 masqueSettings 属协议方向件（§3.5.3 明令不进 udf），且全仓仅
//! masque 单消费方——进框架 = 为单消费方造抽象。无 `udf-promotion-candidate`；
//! 唯一例外是 varint（已上浮 `xray_transport::wire::varint`，件头登记候选）。
//!
//! ## 硬约束
//!
//! - h2-only：`security=tls` 且 ALPN 缺省 → 硬错，不静默走 h3（extra 条款 `MASQUE-H2-ONLY`；Go
//!   `hub.go:47-50` 的反向语义）。h3 批次押后（§7 R11）。
//! - `warp`（Cloudflare WARP 变体）已启用：证书/pin/静态地址/Cloudflare 头见 [`warp`]；
//!   已知偏差（PKCS #1 SEC1 私钥、`warp`+`fingerprint` 组合）见该模块文档。

/// B2 日志门面（规划 #21：target `xray_frame::transport::masque`；splithttp 同款
/// LogFacade 形态。本批消费站点 = 胶囊丢弃/会话关闭的 debug 级留痕，无逐包热路径
/// 日志 → 不立 HOT_LOG）。
pub(crate) static LOG: std::sync::LazyLock<xray_frame::logging::LogFacade> =
    std::sync::LazyLock::new(|| xray_frame::logging::LogFacade::new("transport::masque", vec![]));

pub mod capsule;
pub mod config;
pub mod connect;
pub mod dialer;
pub mod error;
pub mod h2;
pub mod hub;
pub mod pool;
pub mod register;
pub mod warp;

pub use config::Config;
pub use error::{MasqueError, Result};
