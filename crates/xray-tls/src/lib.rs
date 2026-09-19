//! # xray-tls
//!
//! TLS 配置层与 uTLS 指纹伪装抽象。翻译自 Go `transport/internet/tls/`。
//!
//! ## 本 crate 范围（业务核心独立可测）
//! - `pin`：证书 SHA-256 哈希（`generate_cert_hash`/`generate_cert_hash_hex`）
//! - `fingerprint`：uTLS 指纹名 → `Fingerprint` enum 路由（`get_fingerprint`）
//! - `config`：`CurveId` + `parse_curve_name` + `is_from_mitm` + `verify_chain` +
//!   `Option` 函数模式 + `RandCarrier` 数据结构
//! - `certificate`：证书生成/名称提取 + `certificates[]` 条目解析（usage/entry_certs_and_key）
//! - `ech`：ECH key 二进制 TLV 解析 + keyset 生成 + config list 解析/打包 + JSON 字段
//!   解析 + `ApplyEch`（btls 客户端实装）+ `EchConfigCache` 数据结构 + `ech_cache_key`
//! - `error`：统一 `TlsError` 枚举
//! - `ocsp_stapling`：OCSP stapling 集成（`OcspStaplerConfig` + `build_server_config_with_stapling`）
//! - `unsafe_conn`：`TLS_CLOSE_TIMEOUT` 常量
//!
//! ## IO 边界与实现状态
//! - `utls`：标准 rustls 包装的 `Conn`/`UConn`，async 工厂 `client`/`server`/`u_client`
//!   - `u_client` 走 btls（BoringSSL）真实浏览器指纹握手；清单外指纹硬错
//!   - `u_client_with_alpn`：ALPN 覆盖版（ws/httpupgrade，WebsocketHandshakeContext 语义）
//! - `grpc`：`GrpcUtlsCredentials` trait + 工厂函数（返回标准 rustls fallback）
//!
//! ## 后续工作
//! - REALITY 切片 (k9t): 评估接入 watfaq-rustls git 依赖以实现真实指纹伪装
//! - TLS 热重载（ArcSwap + 定时任务，第 8 版 handoff 记录的技术债）
//! - x509 证书加载（依赖 `x509-parser`）；OCSP stapling 已由 `ocsp-stapler` 实现
//!
//! 参考：Go 版本位于 `E:\Projcet\Xray-core\transport\internet\tls\`。

pub mod error;
pub mod client_config;
pub mod server_config;
pub mod pin;
pub mod fingerprint;
pub mod certificate;
pub mod config;
pub mod ech;
pub mod ech_doh;
pub mod ech_https_rr;
pub mod unsafe_conn;
#[cfg(feature = "ocsp-stapling")]
pub mod ocsp_stapling;
pub use utls::ConnInterface;

pub mod btls_client;
pub mod btls_reality;
pub mod utls;
pub mod grpc;
#[cfg(test)]
mod stress_tests;
