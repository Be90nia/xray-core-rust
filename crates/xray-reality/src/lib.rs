//! # xray-reality
//!
//! REALITY TLS 伪装协议：配置、协议算法与完整握手 IO。翻译自 Go
//! `transport/internet/reality/`（reality.go + config.go）。
//!
//! ## 模块
//! - [`config`]：[`RealityConfig`] strong-typed + [`from_proto`](RealityConfig::from_proto)
//!   + [`ShortId`] / [`LimitFallback`]
//! - [`crypto`]：协议算法（session_id 编码、ECDH auth_key 派生、AES-GCM 加密、
//!   HMAC-SHA512 证书验证），独立可测
//! - [`client`]：[`u_client`](client::u_client) 工厂——btls 浏览器指纹主路径
//!   （`xray_tls::btls_reality::connect_reality`）+ watfaq-rustls fallback（指纹不被
//!   btls 支持时走标准 rustls ClientHello）
//! - [`server`]：[`server_tls`](server::server_tls)——读 ClientHello record → REALITY
//!   验证 → rustls 伪造证书握手；验证失败返回
//!   [`RealityServerOutcome::Invalid`](server::RealityServerOutcome::Invalid) 供调用方 fallback
//! - [`mitm`]：REALITY 证书生成（Go init() 进程级静态模板 + per-connection HMAC 尾部）
//! - [`register`]：transport dialer 注册（tcp/splithttp 的 `security=reality` 生产接线）
//! - [`error`] / [`util`]
//!
//! ## 已知缺口
//! - mldsa65 后量子证书**签名生成**：rustls `ResolvesServerCert::resolve()` 拿不到
//!   ServerHello 字节（见 [`mitm::generate_reality_ed25519_cert_mldsa65`]）。tvky
//!   已落地：X25519MLKEM768 hybrid KX（服务端 key_share 解析）+ mldsa65 公钥派生
//!   + 客户端验签原语；签名生成仍 stub。
//! - http2 spider 爬行（fallback 探测路径；`spider_x` 已解析保留，爬行未实现）
//! - btls 全指纹 e2e 矩阵 `#[ignore]`（btls transcript mismatch，待 fork 注入 API）
//!
//! 参考：Go 基准位于 `D:/Project/Xray-core/transport/internet/reality/`。

pub mod client;
pub mod config;
pub mod error;
pub mod server;
pub mod util;
pub mod crypto;
pub mod mitm;
pub mod register;

pub use config::{
    LimitFallback, RealityConfig, ShortId, SHORT_ID_LEN, X25519_KEY_LEN,
};
pub use error::{RealityError, Result};
pub use util::{get_path_locked, open_key_log_writer};

pub use crypto::{
    AEAD_NONCE_LEN, AUTH_KEY_LEN, HKDF_INFO, HKDF_SALT_LEN, SESSION_ID_LEN,
    MLDSA65_PUBKEY_LEN, MLDSA65_SEED_LEN, MLDSA65_SIG_LEN,
    derive_auth_key, derive_mldsa65_pubkey, encode_session_id, encrypt_session_id,
    verify_mldsa65_signature, verify_reality_certificate,
};
