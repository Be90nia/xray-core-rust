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
