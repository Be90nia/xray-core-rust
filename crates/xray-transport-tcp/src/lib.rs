#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! TCP transport dialer 注册。
//!
//! 对应 Go `transport/internet/tcp`：建立裸 TCP 连接后按 `streamSettings.security`
//! 包装 TLS / REALITY——与 ws/grpc 等 transport 对称（Go `tcp/dialer.go::Dial`）。
//!
//! ## 为何独立 crate
//!
//! `xray-transport` 核心不能依赖 `xray-tls`（`xray-tls` 已依赖 `xray-transport`，
//! 反向依赖会循环）。因此 TCP 的 security 包装放在本 crate，复用
//! [`register_transport_dialer`](xray_transport::dialer::register_transport_dialer)
//! 机制，与其他 transport 协议对称。

pub mod register;
