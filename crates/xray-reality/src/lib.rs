//! # xray-reality
//!
//! REALITY TLS 伪装协议的配置层与签名占位。翻译自 Go
//! `transport/internet/reality/`（reality.go + config.go）。
//!
//! ## 本 crate 范围（业务核心独立可测）
//! - [`config`]：[`RealityConfig`] strong-typed + [`from_proto`](RealityConfig::from_proto)
//!   + [`ShortId`] / [`LimitFallback`]
//! - [`error`]：统一 [`RealityError`] 枚举
//! - [`util`]：[`open_key_log_writer`] + [`get_path_locked`]
//! - [`client`]：[`UConnState`] + [`u_client`](client::u_client) 工厂占位
//! - [`server`]：[`server`](server::server) 工厂占位
//!
//! ## 未实现（IO 边界，留 trait + TODO）
//! 以下部分依赖 uTLS 字节级 ClientHello 控制、`xtls/reality` 库等，**本会话不翻译**：
//! - 实际 uTLS 握手（[`client::u_client`] / [`server::server`] 返回
//!   [`RealityError::UtlsRequired`]）
//! - 字节级 ClientHello 伪装（SessionId 注入到 `hello.Raw`、HandshakeState 访问）
//!   — **协议算法**（session_id 编码、ECDH auth_key 派生、AES-GCM 加密、HMAC-SHA512 证书验证）
//!   已提取到 [`crypto`] 模块独立实现。握手层注入等接入 watfaq-rustls（见 n9e ADR 4.2/4.3）。
//! - `VerifyPeerCertificate` 回调（Go 端通过 reflect+unsafe hack 读 utls 内部字段，
//!   Rust 端需要 TLS 库暴露同等 API）
//! - mldsa65 后量子签名验证（依赖 `circl/sign/mldsa65`）
//! - http2 spider crawler（fallback 模式：路径收集 + RandBetween delays）
//!
//! ## 为什么不直接翻译
//! Rust 生态目前**没有** `github.com/refraction-networking/utls` 的成熟等价品
//! （需要字节级 ClientHello 控制、GREASE、扩展顺序、TLS 1.3 key_share 调整等），
//! 也没有 `github.com/xtls/reality` 的服务端状态机等价品。与 `xray-tls` 的
//! uTLS 占位策略一致：业务核心翻译完成，IO 边界等生态成熟或自研后再接。
//!
//! 参考：Go 版本位于 `E:\Projcet\Xray-core\transport\internet\reality\`。

pub mod client;
pub mod config;
pub mod error;
pub mod server;
pub mod util;
pub mod crypto;

pub use config::{
    LimitFallback, RealityConfig, ShortId, SHORT_ID_LEN, X25519_KEY_LEN,
};
pub use error::{RealityError, Result};
pub use util::{get_path_locked, open_key_log_writer};

pub use crypto::{
    AEAD_NONCE_LEN, AUTH_KEY_LEN, HKDF_INFO, HKDF_SALT_LEN, SESSION_ID_LEN,
    derive_auth_key, encode_session_id, encrypt_session_id, verify_reality_certificate,
};
