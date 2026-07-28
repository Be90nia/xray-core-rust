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
//!   - `aead`：KDF（嵌套 HMAC-SHA256）+ `CreateAuthID`（AES-128 单块）+
//!     `Seal/Open VMess AEAD Header` + `AuthIDDecoderHolder`（含反重放）
//!   - `validator`：`TimedUserValidator` 整合 AuthIDDecoderHolder + behaviorSeed
//!   - `encoding::auth`：`Authenticate`（FNV1a）+ `GenerateChacha20Poly1305Key` +
//!     `GenerateChunkNonce` + `ShakeSizeParser` + `AEADSizeParser` + `NoOpAuthenticator`
//!   - `encoding::client`：`ClientSession::EncodeRequestHeader`（AEAD 完整）
//!   - `encoding::server`：`ServerSession::DecodeRequestHeader`（AEAD 完整）+ `SessionHistory`
//!
//! - **trait + stub**（IO 边界，依赖 buf chunk reader/writer + cryption_io 完整链路）：
//!   - `ClientSession::{EncodeRequestBody, DecodeResponseHeader, DecodeResponseBody}`
//!   - `ServerSession::{DecodeRequestBody, EncodeResponseHeader, EncodeResponseBody}`
//!   - `inbound`/`outbound`：Handler `Process` 主入口依赖 `transport::Link` 全链路
//!
//! 等上层 buf chunk 加密包装链 + transport 接入后，注入 trait 实现即可激活。

pub mod account;
pub mod aead;
pub mod encoding;
pub mod error;
pub mod inbound;
pub mod outbound;
pub mod validator;
pub mod dispatcher;


pub use account::MemoryAccount;
pub use dispatcher::{make_vmess_dial_fn, parse_vmess_config, VmessOutboundConfig};
pub use error::{Result, VmessError};
pub use validator::{MemoryUser, TimedUserValidator, Validator};
pub use inbound::serve_vmess;

/// VMess 协议版本号（对应 Go 的 `encoding.Version` 常量）。
pub const VERSION: u8 = 1;

/// 请求选项位（对应 Go `protocol.RequestOption*`，VMess 复用同一组位定义）。
pub mod request_option {
    /// Chunk stream：body 以 length-prefixed chunk 传输。
    pub const CHUNK_STREAM: u8 = 0x01;
    /// Chunk masking：chunk length 字段用 ShakeSizeParser 异或掩码。
    pub const CHUNK_MASKING: u8 = 0x04;
    /// Global padding：chunk 间插入 padding。
    pub const GLOBAL_PADDING: u8 = 0x08;
    /// Authenticated length：length 字段单独 AEAD 加密。
    pub const AUTHENTICATED_LENGTH: u8 = 0x10;
}

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
