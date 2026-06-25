//! # xray-tls
//!
//! TLS 配置层与 uTLS 指纹伪装抽象。翻译自 Go `transport/internet/tls/`。
//!
//! ## 本 crate 范围（业务核心独立可测）
//! - `pin`：证书 SHA-256 哈希（`generate_cert_hash`/`generate_cert_hash_hex`）
//! - `fingerprint`：uTLS 指纹名 → `Fingerprint` enum 路由（`get_fingerprint`）
//! - `config`：`CurveId` + `parse_curve_name` + `is_from_mitm` + `verify_chain` +
//!   `Option` 函数模式 + `RandCarrier` 数据结构
//! - `certificate`：`CertificateUsage` enum + 类型安全 wrapper（`is_encipherment` 等）
//! - `ech`：ECH key 二进制 TLV 解析 + `EchConfigCache` 数据结构 + `ech_cache_key`
//! - `error`：统一 `TlsError` 枚举
//! - `unsafe_conn`：`TLS_CLOSE_TIMEOUT` 常量
//! - `utls`/`grpc`：trait 占位（[`ConnInterface`] / [`GrpcUtlsCredentials`]）
//!
//! ## 未实现（IO 边界，留 trait + TODO）
//! 以下部分依赖具体 TLS 实现（rustls）或未就绪的 crate，**本会话不翻译**：
//! - 实际 TLS 握手（`utls::client`/`server`/`u_client` 工厂函数占位返回错误）
//! - uTLS 字节级 ClientHello 伪装（Rust 生态无等价品）
//! - `GetTLSConfig` 组装 `rustls::ClientConfig`（依赖 rustls ECH/stapling 支持）
//! - x509 证书加载/OCSP hot-reload ticker（依赖 `x509-parser` + tokio interval）
//! - ECH DNS 查询（`apply_ech`/`query_record`，依赖 Phase 4 `xray-app-dns`）
//! - gRPC credentials（`grpc::new_grpc_utls`，依赖 Phase 5 `xray-transport-grpc`）
//!
//! ## 关于 "btls + wreq-util" 替代方案
//! 任务描述曾提到用 `btls + wreq-util`（~800行）替代 8000 行自研 uTLS。
//! 实际调研：
//! - `btls 0.5.6` 是 BoringSSL bindings，**无**字节级 ClientHello 控制能力
//! - `wreq 6.0.0-rc.29` 是 HTTP 客户端（含 TLS fingerprint），但抽象层在上层，
//!   不能被代理 TLS 握手复用
//! - Rust 生态目前**没有** `github.com/refraction-networking/utls` 的等价品
//!
//! 因此本会话选择「trait + TODO」策略：所有业务核心翻译完成，IO 边界等生态
//! 成熟或自研后再接，不引入 btls/wreq（会形成不可维护的额外依赖）。
//! 详见 `docs/translation-conventions.md` §10 决策记录。
//!
//! 参考：Go 版本位于 `E:\Projcet\Xray-core\transport\internet\tls\`。

pub mod error;
pub mod pin;
pub mod fingerprint;
pub mod certificate;
pub mod config;
pub mod ech;
pub mod unsafe_conn;
pub mod utls;
pub mod grpc;
