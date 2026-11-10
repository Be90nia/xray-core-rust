#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
// ⚠️ 顺序敏感（2026-11-04 PM 修）：`warn` 必须在 `allow` **之前**，否则同级的后置 `warn`
// 会把 `cfg_attr(test, allow(..))` 盖掉 —— 该 crate 的「测试目标豁免」曾因此从未生效，
// 导致测试里的 `println!` 被 `deny(warnings)` 升级成错误。
#![warn(clippy::print_stdout, clippy::print_stderr)]
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))]
// 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! # xray-tls
//!
//! TLS 配置层与 uTLS 指纹伪装抽象。翻译自 Go `transport/internet/tls/`。
//!
//! ## 本 crate 范围（业务核心独立可测）
//! - `pin`：证书 SHA-256 哈希（`generate_cert_hash`/`generate_cert_hash_hex`）
//! - `fingerprint`：uTLS 指纹名 → `Fingerprint` enum 路由（`get_fingerprint`）
//! - `config`：`CurveId` + `parse_curve_name` + `is_from_mitm` + `verify_chain` + `Option` 函数模式
//!   + `RandCarrier` 数据结构
//! - `certificate`：证书生成/名称提取 + `certificates[]` 条目解析（usage/entry_certs_and_key）
//! - `ech`：ECH key 二进制 TLV 解析 + keyset 生成 + config list 解析/打包 + JSON 字段 解析 +
//!   `ApplyEch`（btls 客户端实装）+ `EchConfigCache` 数据结构 + `ech_cache_key` （服务端 ECH keys
//!   注册走 `btls_server::build_server_ssl_context_with_ech`， rustls 后端无服务端 ECH ⇒ 配
//!   `echServerKeys` 硬错并指向 btls）
//! - `error`：统一 `TlsError` 枚举
//! - `ocsp_stapling`：OCSP stapling 集成（`OcspStaplerConfig` +
//!   `build_server_config_with_stapling`）
//! - `cert_reload`：服务端证书热重载——周期重读 `certificateFile`/`keyFile` + `HotSlot`
//!   原子换快照（失败保留旧证书）
//! - `inbound_acceptor`：入站 plain-TLS 后端选路——`echServerKeys` 非空 ⇒ btls （BoringSSL），否则
//!   rustls；`echServerKeys` 装配失败即配置期硬错（禁静默回退）
//! - `btls_server`：btls 服务端上下文装配（ECH keys / ALPN / 版本门 / `rejectUnknownSni`）
//!   + 握手（`accept_with_ctx`，装配期 ctx 逐连接复用）
//!
//! ## IO 边界与实现状态
//! - `utls`：标准 rustls 包装的 `Conn`/`UConn`，async 工厂 `client`/`server`/`u_client`
//!   - `u_client` 走 btls（BoringSSL）真实浏览器指纹握手；清单外指纹硬错
//!   - `u_client_with_alpn`：ALPN 覆盖版（ws/httpupgrade，WebsocketHandshakeContext 语义）
//! - `grpc`：`GrpcUtlsCredentials` trait + 工厂函数（返回标准 rustls fallback）
//!
//! ## 后续工作
//! - REALITY 切片 (k9t): 评估接入 watfaq-rustls git 依赖以实现真实指纹伪装
//! - 服务端证书热重载**已实现**（bd 5ctu1）：`server_config::build_server_config` 起 `cert_reload`
//!   托管周期任务，`certificates[].certificateFile/keyFile` 换文件即生效
//! - x509 证书加载（依赖 `x509-parser`）；OCSP stapling 已由 `ocsp-stapler` 实现
//!
//! 参考：Go 版本位于 `E:\Projcet\Xray-core\transport\internet\tls\`。

/// 服务端证书热重载（Go `setupOcspTicker` 的非 OCSP 面；bd 5ctu1）。
mod cert_reload;
pub mod certificate;
pub mod client_config;
pub mod config;
pub mod ech;
pub mod ech_doh;
pub mod ech_https_rr;
pub mod error;
pub mod fingerprint;
#[cfg(feature = "ocsp-stapling")]
pub mod ocsp_stapling;
pub mod pin;
pub mod server_config;
pub use utls::ConnInterface;

pub mod btls_client;
pub mod btls_reality;
/// btls（BoringSSL）服务端 acceptor（bd tce2，opt-in）。
/// iOS 预生成 bindings 无服务端路径依赖问题但按 mygg 教训统一门控。
#[cfg(not(target_os = "ios"))]
pub mod btls_server;
pub mod grpc;
pub mod inbound_acceptor;
#[cfg(test)]
mod stress_tests;
pub mod tls_session_cache;
pub mod utls;
