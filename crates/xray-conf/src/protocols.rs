//! 协议层强类型 settings —— 对应 Go `infra/conf` 下各协议的 `*Config` 类型。
//!
//! ## 设计
//!
//! - 每协议一个 inbound / outbound settings 结构体，字段名和 JSON tag 与
//!   Go 端对齐；未知字段默认忽略（保留前向兼容）。
//! - 入站 / 出站各一个 untagged enum：`InboundSettings` / `OutboundSettings`，
//!   反序列化时按内部结构形态自动匹配（serde untagged）。
//! - 反序列化入口通过 [`dispatch_inbound_settings`] / [`dispatch_outbound_settings`]
//!   按 `protocol` 字符串名分派，对应 Go `infra/conf/xray.go` 注册表。
//!
//! ## 协议清单（Go Xray v26.6.1）
//!
//! - 入站（9）：vless / vmess / trojan / shadowsocks（含 2022）/ socks（含 mixed）/
//!   http / dokodemo-door / hysteria / blackhole
//! - 出站（11）：vless / vmess / trojan / shadowsocks / socks / http / freedom /
//!   blackhole / loopback / hysteria / dns
//! - 排除：wireguard / tun 在 `app_config` 已实装；reverse 在 `Config.reverse`
//!   顶层不属于 `settings` 字段。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::common::{Address, Int32Range, NetworkList};

// =========================================================================
// 入站 settings 强类型
// =========================================================================

/// VLESS 入站 settings。对应 Go `VLessInboundConfig`（vless.go:33-40）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VLessInboundSettings {
    /// 用户列表（Go 是 `json.RawMessage`，保留任意扩展字段如 `flow`/`encryption`/`reverse`）。
    #[serde(rename = "clients")]
    pub clients: Vec<Value>,

    /// 旧名 `users`（v26 已废弃但仍兼容）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<Value>>,

    /// 加密方式（`"none"` 或 `mlkem768x25519plus.*`）。
    pub decryption: String,

    /// fallback 配置。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallbacks: Option<Vec<VLessInboundFallbackConfig>>,

    /// 全局 flow（v26 仅支持 `""` 或 `"xtls-rprx-vision"`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,

    /// 流量混淆 seed。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub testseed: Option<Vec<u32>>,
}

/// VLESS 入站 fallback 子结构。对应 Go `VLessInboundFallback`（vless.go:24-31）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VLessInboundFallbackConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// dest 可为端口号（number）或字符串。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xver: Option<u64>,
}

/// VMess 入站 settings。对应 Go `VMessInboundConfig`（vmess.go:61-65）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VMessInboundSettings {
    #[serde(rename = "clients")]
    pub clients: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<VMessDefaultConfig>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VMessDefaultConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
}

/// Trojan 入站 settings。对应 Go `TrojanServerConfig`（trojan.go:113-118）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TrojanInboundSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clients: Option<Vec<TrojanUserConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<TrojanUserConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallbacks: Option<Vec<TrojanInboundFallbackConfig>>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TrojanUserConfig {
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TrojanInboundFallbackConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xver: Option<u64>,
}

/// Shadowsocks 入站 settings（含 SS2022）。对应 Go `ShadowsocksServerConfig`
/// （shadowsocks.go:43-51）。协议分支由 `method` 决定：`blake3-aes-*-gcm` 系列
/// 进 `shadowsocks_2022` build 路径。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShadowsocksInboundSettings {
    #[serde(rename = "method")]
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clients: Option<Vec<ShadowsocksUserConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<ShadowsocksUserConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkList>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShadowsocksUserConfig {
    #[serde(rename = "method", skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// SOCKS5 入站 settings。对应 Go `SocksServerConfig`（socks.go:30-37）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SocksInboundSettings {
    #[serde(rename = "auth", skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<SocksAccountConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<SocksAccountConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<Address>,
    #[serde(rename = "userLevel", skip_serializing_if = "Option::is_none")]
    pub user_level: Option<u32>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SocksAccountConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
}

/// HTTP CONNECT 入站 settings。对应 Go `HTTPServerConfig`（http.go:25-30）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpInboundSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<HttpAccountConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<HttpAccountConfig>>,
    #[serde(rename = "allowTransparent", skip_serializing_if = "Option::is_none")]
    pub allow_transparent: Option<bool>,
    #[serde(rename = "userLevel", skip_serializing_if = "Option::is_none")]
    pub user_level: Option<u32>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpAccountConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
}

/// Dokodemo-door 入站 settings。对应 Go `DokodemoConfig`（dokodemo.go:10-20）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DokodemoDoorInboundSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkList>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_network: Option<NetworkList>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rewrite_address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rewrite_port: Option<u16>,
    #[serde(rename = "portMap", skip_serializing_if = "Option::is_none")]
    pub port_map: Option<HashMap<String, String>>,
    #[serde(rename = "followRedirect", skip_serializing_if = "Option::is_none")]
    pub follow_redirect: Option<bool>,
    #[serde(rename = "userLevel", skip_serializing_if = "Option::is_none")]
    pub user_level: Option<u32>,
}

/// Hysteria2 入站 settings。对应 Go `HysteriaServerConfig`（hysteria.go:40-44）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HysteriaInboundSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clients: Option<Vec<HysteriaUserConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<HysteriaUserConfig>>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HysteriaUserConfig {
    pub auth: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// Blackhole 入站 settings（共用 BlackholeSettings，blackhole.go:24-26）。
pub use BlackholeSettings as BlackholeInboundSettings;

/// 入站 settings untagged enum —— `serde(untagged)` 让内部结构直接匹配 JSON 形态。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InboundSettings {
    Vless(VLessInboundSettings),
    Vmess(VMessInboundSettings),
    Trojan(TrojanInboundSettings),
    Shadowsocks(ShadowsocksInboundSettings),
    /// SOCKS5 + `mixed`（Go xray.go:26 同源注册）。
    #[serde(alias = "mixed")]
    Socks(SocksInboundSettings),
    Http(HttpInboundSettings),
    DokodemoDoor(DokodemoDoorInboundSettings),
    Hysteria(HysteriaInboundSettings),
    Blackhole(BlackholeSettings),
}

// =========================================================================
// 出站 settings 强类型
// =========================================================================

/// VLESS 出站 settings。对应 Go `VLessOutboundConfig`（vless.go:245-258）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VLessOutboundSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vnext: Option<Vec<VLessOutboundVnext>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse: Option<VLessReverseConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub testpre: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub testseed: Option<Vec<u32>>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VLessOutboundVnext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    pub port: u16,
    /// 用户列表（VLESS 协议字段如 flow / encryption / reverse 走 Value）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<Value>>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VLessReverseConfig {
    pub tag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<Value>,
}

/// VMess 出站 settings。对应 Go `VMessOutboundConfig`（vmess.go:115-124）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VMessOutboundSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vnext: Option<Vec<VMessOutboundTarget>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experiments: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VMessOutboundTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<Value>>,
}

/// Trojan 出站 settings。对应 Go `TrojanClientConfig`（trojan.go:31-39）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TrojanOutboundSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub servers: Option<Vec<TrojanServerTarget>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TrojanServerTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
}

/// Shadowsocks 出站 settings（含 SS2022）。对应 Go `ShadowsocksClientConfig`
/// （shadowsocks.go:192-202）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShadowsocksOutboundSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub servers: Option<Vec<ShadowsocksServerTarget>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(rename = "method", skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// UDP-over-TCP（SS 协议）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uot: Option<bool>,
    #[serde(rename = "uotVersion", skip_serializing_if = "Option::is_none")]
    pub uot_version: Option<i32>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShadowsocksServerTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(rename = "method", skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uot: Option<bool>,
    #[serde(rename = "uotVersion", skip_serializing_if = "Option::is_none")]
    pub uot_version: Option<i32>,
}

// =========================================================================
// Shadowsocks method 解析与 Build 语义（Go infra/conf/shadowsocks.go）
// =========================================================================

/// SS method 解析结果，兼作 2022 / 旧 AEAD 分流判定。
///
/// 旧 AEAD 5 组对应 Go `cipherFromString`（shadowsocks.go:17-32，`strings.ToLower`
/// 大小写不敏感 + `aead_*` 别名）；2022 3 方法对应 `shadowaead_2022.List` 精确匹配
/// （shadowsocks.go:60 `C.Contains` 区分大小写——`"2022-BLAKE3-…"` 不命中 2022
/// 分支，落入旧 AEAD 解析后报 unknown cipher method）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowsocksMethod {
    /// 2022-blake3-aes-128-gcm
    Ss2022Aes128Gcm,
    /// 2022-blake3-aes-256-gcm
    Ss2022Aes256Gcm,
    /// 2022-blake3-chacha20-poly1305
    Ss2022ChaCha20Poly1305,
    /// aes-128-gcm / aead_aes_128_gcm
    Aes128Gcm,
    /// aes-256-gcm / aead_aes_256_gcm
    Aes256Gcm,
    /// chacha20-poly1305 / aead_chacha20_poly1305 / chacha20-ietf-poly1305
    ChaCha20Poly1305,
    /// xchacha20-poly1305 / aead_xchacha20_poly1305 / xchacha20-ietf-poly1305
    /// （conf 层识别；独立 cipher 实装为 non-goal）
    XChaCha20Poly1305,
    /// none / plain
    None,
}

impl ShadowsocksMethod {
    /// 解析 method 字符串。未知返回 `None`（对应 Go `CipherType_UNKNOWN` 哨兵，
    /// 由调用方按上下文生成 "unknown/unsupported cipher method" 错误）。
    #[must_use]
    pub fn from_method(name: &str) -> Option<Self> {
        // 2022：精确匹配（Go C.Contains(shadowaead_2022.List, cipher)）。
        match name {
            "2022-blake3-aes-128-gcm" => return Some(Self::Ss2022Aes128Gcm),
            "2022-blake3-aes-256-gcm" => return Some(Self::Ss2022Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => return Some(Self::Ss2022ChaCha20Poly1305),
            _ => {}
        }
        // 旧 AEAD：小写化匹配（Go cipherFromString）。
        match name.to_ascii_lowercase().as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => Some(Self::Aes128Gcm),
            "aes-256-gcm" | "aead_aes_256_gcm" => Some(Self::Aes256Gcm),
            "chacha20-poly1305" | "aead_chacha20_poly1305" | "chacha20-ietf-poly1305" => {
                Some(Self::ChaCha20Poly1305)
            }
            "xchacha20-poly1305" | "aead_xchacha20_poly1305" | "xchacha20-ietf-poly1305" => {
                Some(Self::XChaCha20Poly1305)
            }
            "none" | "plain" => Some(Self::None),
            _ => None,
        }
    }

    /// 是否 SS-2022 系列。
    #[must_use]
    pub fn is_ss2022(self) -> bool {
        matches!(
            self,
            Self::Ss2022Aes128Gcm | Self::Ss2022Aes256Gcm | Self::Ss2022ChaCha20Poly1305
        )
    }
}

/// SS-2022 多用户产物中的用户。对应 Go `shadowsocks_2022.Account{Key}` +
/// `protocol.User`（shadowsocks.go:144-151）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shadowsocks2022User {
    /// 用户 PSK（base64）。
    pub key: String,
    pub email: String,
    pub level: u8,
}

/// 旧 AEAD 产物中的用户。对应 Go `shadowsocks.Account`（shadowsocks.go:72-87）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowsocksAeadUser {
    pub email: String,
    pub level: u8,
    pub password: String,
    pub cipher: ShadowsocksMethod,
}

/// [`ShadowsocksInboundSettings::build`] 产物。对应 Go
/// `ShadowsocksServerConfig.Build()` 的三条输出路径（shadowsocks.go:53-179）；
/// Relay 分支（:160-178）未实装，命中时显式报错。
#[derive(Debug, Clone, PartialEq)]
pub enum ShadowsocksServerBuild {
    /// Go `shadowsocks_2022.ServerConfig` 单用户（:116-123，不校验 key 非空）。
    Ss2022Single {
        method: String,
        key: String,
        email: String,
        network: Option<NetworkList>,
    },
    /// Go `shadowsocks_2022.MultiUserServerConfig`（:132-157）。
    Ss2022MultiUser {
        method: String,
        key: String,
        users: Vec<Shadowsocks2022User>,
        network: Option<NetworkList>,
    },
    /// Go `shadowsocks.ServerConfig` 旧 AEAD（:64-110）。`users` 为空 Vec 对应
    /// Go `Users` 为非 nil 空切片的边界（:67-68 不进循环、也不落顶层账户）。
    LegacyAead {
        users: Vec<ShadowsocksAeadUser>,
        network: Option<NetworkList>,
    },
}

impl ShadowsocksInboundSettings {
    /// 对应 Go `ShadowsocksServerConfig.Build()`（shadowsocks.go:53-113）+
    /// `buildShadowsocks2022`（:115-179）。错误文案与 Go 对齐。
    ///
    /// # Errors
    /// - 多用户 2022 非 aes 方法 / 用户带 method / relay（未实装）
    /// - 旧 AEAD 密码为空、cipher 不支持或未知
    pub fn build(&self) -> crate::error::Result<ShadowsocksServerBuild> {
        // Go :56-58：clients 非 nil 覆盖 users（含空切片）。
        let users = self.clients.as_ref().or(self.users.as_ref()).map(Vec::as_slice);
        if ShadowsocksMethod::from_method(&self.method).is_some_and(|m| m.is_ss2022()) {
            match users {
                None | Some([]) => Ok(ShadowsocksServerBuild::Ss2022Single {
                    method: self.method.clone(),
                    key: self.password.clone().unwrap_or_default(),
                    email: self.email.clone().unwrap_or_default(),
                    network: self.network.clone(),
                }),
                Some(u) => self.build_ss2022_multi(u),
            }
        } else {
            self.build_legacy(users)
        }
    }

    /// Go `buildShadowsocks2022` 多用户分支（:125-157；:125-127 空 method 检查在
    /// Go 不可达——空 method 不会命中 2022 分流——故不复刻）。
    fn build_ss2022_multi(
        &self,
        users: &[ShadowsocksUserConfig],
    ) -> crate::error::Result<ShadowsocksServerBuild> {
        // Go :128-130：多用户仅支持 blake3-aes-*-gcm（chacha 被拒）。
        if !self.method.contains("aes") {
            return Err(crate::error::ConfError::Invalid(
                "shadowsocks 2022 (multi-user): only blake3-aes-*-gcm methods are supported"
                    .into(),
            ));
        }
        // Go :132：users[0].Address 决定 multi vs relay；relay 未实装（non-goal）。
        if users[0].address.is_some() {
            return Err(crate::error::ConfError::Invalid(
                "shadowsocks 2022 (relay): relay server is not supported yet".into(),
            ));
        }
        let mut out = Vec::with_capacity(users.len());
        for user in users {
            // Go :141-143：用户级 method 必须为空。
            if user.method.as_deref().is_some_and(|m| !m.is_empty()) {
                return Err(crate::error::ConfError::Invalid(
                    "shadowsocks 2022 (multi-user): users must have empty method".into(),
                ));
            }
            out.push(Shadowsocks2022User {
                key: user.password.clone().unwrap_or_default(),
                email: user.email.clone().unwrap_or_default(),
                level: user.level.unwrap_or(0),
            });
        }
        Ok(ShadowsocksServerBuild::Ss2022MultiUser {
            method: self.method.clone(),
            key: self.password.clone().unwrap_or_default(),
            users: out,
            network: self.network.clone(),
        })
    }

    /// Go 旧 AEAD 分支（:64-110）。
    fn build_legacy(
        &self,
        users: Option<&[ShadowsocksUserConfig]>,
    ) -> crate::error::Result<ShadowsocksServerBuild> {
        let network = self.network.clone();
        match users {
            Some(u) if !u.is_empty() => {
                let mut out = Vec::with_capacity(u.len());
                for user in u {
                    // Go :76-78：先查密码。
                    let password = user.password.clone().unwrap_or_default();
                    if password.is_empty() {
                        return Err(crate::error::ConfError::Invalid(
                            "Shadowsocks password is not specified.".into(),
                        ));
                    }
                    // Go :79-82：cipher 必须落在 AES_128_GCM..=XCHACHA20_POLY1305
                    // 范围（proto 值 5..=8）——NONE=9 越界被拒、UNKNOWN 被拒。
                    let name = user.method.as_deref().unwrap_or("");
                    let cipher = ShadowsocksMethod::from_method(name).filter(|c| {
                        matches!(
                            c,
                            ShadowsocksMethod::Aes128Gcm
                                | ShadowsocksMethod::Aes256Gcm
                                | ShadowsocksMethod::ChaCha20Poly1305
                                | ShadowsocksMethod::XChaCha20Poly1305
                        )
                    });
                    let cipher = cipher.ok_or_else(|| {
                        crate::error::ConfError::Invalid(format!(
                            "unsupported cipher method: {name}"
                        ))
                    })?;
                    out.push(ShadowsocksAeadUser {
                        email: user.email.clone().unwrap_or_default(),
                        level: user.level.unwrap_or(0),
                        password,
                        cipher,
                    });
                }
                Ok(ShadowsocksServerBuild::LegacyAead { users: out, network })
            }
            // Go :67-68：Users 非 nil 空切片 → 零用户产物（顶层账户不生效）。
            Some(_) => Ok(ShadowsocksServerBuild::LegacyAead {
                users: Vec::new(),
                network,
            }),
            None => {
                let password = self.password.clone().unwrap_or_default();
                if password.is_empty() {
                    return Err(crate::error::ConfError::Invalid(
                        "Shadowsocks password is not specified.".into(),
                    ));
                }
                // Go :102-104：顶层仅拒绝 UNKNOWN（none/plain 合法）。
                let cipher = ShadowsocksMethod::from_method(&self.method).ok_or_else(|| {
                    crate::error::ConfError::Invalid(format!(
                        "unknown cipher method: {}",
                        self.method
                    ))
                })?;
                Ok(ShadowsocksServerBuild::LegacyAead {
                    users: vec![ShadowsocksAeadUser {
                        email: self.email.clone().unwrap_or_default(),
                        level: self.level.unwrap_or(0),
                        password,
                        cipher,
                    }],
                    network,
                })
            }
        }
    }
}

/// [`ShadowsocksOutboundSettings::build`] 产物。对应 Go
/// `ShadowsocksClientConfig.Build()`（shadowsocks.go:204-286）。
#[derive(Debug, Clone, PartialEq)]
pub enum ShadowsocksClientBuild {
    /// Go `shadowsocks_2022.ClientConfig`（:238-245）。`udp_over_tcp`/`version`
    /// 即 uot/uotVersion 字段映射落点，可直转运行时 `UdpOverTcpConfig`。
    Ss2022 {
        address: Address,
        port: u16,
        method: String,
        key: String,
        /// Go `ClientConfig.UdpOverTcp`（:243，`json:"uot"`）。
        udp_over_tcp: bool,
        /// Go `ClientConfig.UdpOverTcpVersion`（:244，`json:"uotVersion"`）。
        udp_over_tcp_version: u32,
    },
    /// Go `shadowsocks.ClientConfig`（:249-283；Go 该分支不携带 UoT 字段）。
    LegacyAead {
        address: Address,
        port: u16,
        level: u8,
        email: String,
        password: String,
        cipher: ShadowsocksMethod,
    },
}

impl ShadowsocksOutboundSettings {
    /// 对应 Go `ShadowsocksClientConfig.Build()`。错误文案与 Go 对齐。
    ///
    /// # Errors
    /// - servers 数量 ≠ 1
    /// - address 缺失 / port 为 0 / password 为空
    /// - 旧 AEAD cipher 未知
    pub fn build(&self) -> crate::error::Result<ShadowsocksClientBuild> {
        // Go :207-220：顶层 address 折叠为单元素 servers（顶层字段优先）。
        let folded;
        let servers: &[ShadowsocksServerTarget] = if self.address.is_some() {
            folded = vec![ShadowsocksServerTarget {
                address: self.address.clone(),
                port: self.port.unwrap_or(0),
                level: self.level,
                email: self.email.clone(),
                method: self.method.clone(),
                password: self.password.clone(),
                uot: self.uot,
                uot_version: self.uot_version,
            }];
            &folded
        } else {
            self.servers.as_deref().unwrap_or(&[])
        };
        // Go :221-223：servers 必须恰好 1 个。
        if servers.len() != 1 {
            return Err(crate::error::ConfError::Invalid(
                r#"Shadowsocks settings: "servers" should have one and only one member. Multiple endpoints in "servers" should use multiple Shadowsocks outbounds and routing balancer instead"#
                    .into(),
            ));
        }
        let server = &servers[0];
        let method = server.method.clone().unwrap_or_default();
        // Go :227：2022 分流。
        if ShadowsocksMethod::from_method(&method).is_some_and(|m| m.is_ss2022()) {
            // Go :228-236 校验顺序：address → port → password。
            let address = server.address.clone().ok_or_else(|| {
                crate::error::ConfError::Invalid(
                    "Shadowsocks server address is not set.".into(),
                )
            })?;
            if server.port == 0 {
                return Err(crate::error::ConfError::Invalid(
                    "Invalid Shadowsocks port.".into(),
                ));
            }
            let key = server.password.clone().unwrap_or_default();
            if key.is_empty() {
                return Err(crate::error::ConfError::Invalid(
                    "Shadowsocks password is not specified.".into(),
                ));
            }
            // Go :243-244：uot/uotVersion → UdpOverTcp 字段映射（int→uint32 环绕语义
            // 与 Go 一致：负数经 `as u32` 回绕）。
            return Ok(ShadowsocksClientBuild::Ss2022 {
                address,
                port: server.port,
                method,
                key,
                udp_over_tcp: server.uot.unwrap_or(false),
                udp_over_tcp_version: server.uot_version.unwrap_or(0) as u32,
            });
        }
        // Go :249-283 旧 AEAD（servers==1 时 :251-252 的 multi-server 2022 检查不可达）。
        let address = server
            .address
            .clone()
            .ok_or_else(|| crate::error::ConfError::Invalid("Shadowsocks server address is not set.".into()))?;
        if server.port == 0 {
            return Err(crate::error::ConfError::Invalid(
                "Invalid Shadowsocks port.".into(),
            ));
        }
        let password = server.password.clone().unwrap_or_default();
        if password.is_empty() {
            return Err(crate::error::ConfError::Invalid(
                "Shadowsocks password is not specified.".into(),
            ));
        }
        let cipher = ShadowsocksMethod::from_method(&method).ok_or_else(|| {
            crate::error::ConfError::Invalid(format!("unknown cipher method: {method}"))
        })?;
        Ok(ShadowsocksClientBuild::LegacyAead {
            address,
            port: server.port,
            level: server.level.unwrap_or(0),
            email: server.email.clone().unwrap_or_default(),
            password,
            cipher,
        })
    }
}

/// SOCKS5 出站 settings。对应 Go `SocksClientConfig`（socks.go:77-85）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SocksOutboundSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub servers: Option<Vec<SocksRemoteConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SocksRemoteConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<Value>>,
}

/// HTTP CONNECT 出站 settings。对应 Go `HTTPClientConfig`（http.go:58-67）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpOutboundSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub servers: Option<Vec<HttpRemoteConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpRemoteConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<Value>>,
}

/// Freedom 出站 settings。对应 Go `FreedomConfig`（freedom.go:19-30）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FreedomOutboundSettings {
    #[serde(rename = "domainStrategy", skip_serializing_if = "Option::is_none")]
    pub domain_strategy: Option<String>,
    /// 旧名（v26 已 deprecated；保留字段向后兼容）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_strategy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
    #[serde(rename = "userLevel", skip_serializing_if = "Option::is_none")]
    pub user_level: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment: Option<FragmentConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noise: Option<NoiseConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noises: Option<Vec<NoiseConfig>>,
    #[serde(rename = "proxyProtocol", skip_serializing_if = "Option::is_none")]
    pub proxy_protocol: Option<u32>,
    /// v26 已迁移到 `final_rules`，保留字段用于触发 Build 阶段警告。
    #[serde(rename = "ipsBlocked", skip_serializing_if = "Option::is_none")]
    pub ips_blocked: Option<crate::common::StringList>,
    #[serde(rename = "finalRules", skip_serializing_if = "Option::is_none")]
    pub final_rules: Option<Vec<FreedomFinalRuleConfig>>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FragmentConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<Int32Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<Int32Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_split: Option<Int32Range>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NoiseConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay: Option<Int32Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apply_to: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FreedomFinalRuleConfig {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkList>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<crate::common::PortList>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<crate::common::StringList>,
    #[serde(rename = "blockDelay", skip_serializing_if = "Option::is_none")]
    pub block_delay: Option<Int32Range>,
}

/// Blackhole 出站 settings。对应 Go `BlackholeConfig`（blackhole.go:24-26）。
///
/// `response` 是 `{ "type": "none" | "http" }` 形态（黑体注册表，blackhole.go:45-52）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BlackholeSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<BlackholeResponseConfig>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BlackholeResponseConfig {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

/// Loopback 出站 settings。对应 Go `LoopbackConfig`（loopback.go:8-10）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoopbackOutboundSettings {
    #[serde(rename = "inboundTag")]
    pub inbound_tag: String,
}

/// Hysteria2 出站 settings。对应 Go `HysteriaClientConfig`（hysteria.go:13-17）。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HysteriaOutboundSettings {
    pub version: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// DNS 出站 settings。简化字段保留必要项，对应 dns.go `DNSConfig`。
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsOutboundSettings {
    /// DNS 服务器列表。简化为 `Vec<Value>`，允许原始 JSON 形态透传。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub servers: Option<Vec<Value>>,
    #[serde(rename = "queryStrategy", skip_serializing_if = "Option::is_none")]
    pub query_strategy: Option<String>,
    #[serde(rename = "disableCache", skip_serializing_if = "Option::is_none")]
    pub disable_cache: Option<bool>,
    #[serde(rename = "disableFallback", skip_serializing_if = "Option::is_none")]
    pub disable_fallback: Option<bool>,
}

/// 出站 settings untagged enum。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OutboundSettings {
    Vless(VLessOutboundSettings),
    Vmess(VMessOutboundSettings),
    Trojan(TrojanOutboundSettings),
    Shadowsocks(ShadowsocksOutboundSettings),
    Socks(SocksOutboundSettings),
    Http(HttpOutboundSettings),
    Freedom(FreedomOutboundSettings),
    Blackhole(BlackholeSettings),
    Loopback(LoopbackOutboundSettings),
    Hysteria(HysteriaOutboundSettings),
    Dns(DnsOutboundSettings),
}

// =========================================================================
// 协议名 → settings enum 变体的统一入口
// =========================================================================

#[inline]
fn opt<T: serde::de::DeserializeOwned>(v: Value) -> Result<Option<T>, serde_json::Error> {
    Ok(Some(serde_json::from_value::<T>(v)?))
}

/// 按 Go `protocol` 字段名将 JSON `Value` 转换为对应的出站 settings。
pub fn dispatch_outbound_settings(protocol: &str, v: Value) -> Result<Option<OutboundSettings>, serde_json::Error> {
    let out = match protocol {
        "vless" => opt::<VLessOutboundSettings>(v)?.map(OutboundSettings::Vless),
        "vmess" => opt::<VMessOutboundSettings>(v)?.map(OutboundSettings::Vmess),
        "trojan" => opt::<TrojanOutboundSettings>(v)?.map(OutboundSettings::Trojan),
        "shadowsocks" => opt::<ShadowsocksOutboundSettings>(v)?.map(OutboundSettings::Shadowsocks),
        "socks" => opt::<SocksOutboundSettings>(v)?.map(OutboundSettings::Socks),
        "http" => opt::<HttpOutboundSettings>(v)?.map(OutboundSettings::Http),
        "freedom" | "direct" => opt::<FreedomOutboundSettings>(v)?.map(OutboundSettings::Freedom),
        "blackhole" | "block" => opt::<BlackholeSettings>(v)?.map(OutboundSettings::Blackhole),
        "loopback" => opt::<LoopbackOutboundSettings>(v)?.map(OutboundSettings::Loopback),
        "hysteria" => opt::<HysteriaOutboundSettings>(v)?.map(OutboundSettings::Hysteria),
        "dns" => opt::<DnsOutboundSettings>(v)?.map(OutboundSettings::Dns),
        _ => None,
    };
    Ok(out)
}

/// 按 Go `protocol` 字段名将 JSON `Value` 转换为对应的入站 settings。
pub fn dispatch_inbound_settings(protocol: &str, v: Value) -> Result<Option<InboundSettings>, serde_json::Error> {
    let out = match protocol {
        "vless" => opt::<VLessInboundSettings>(v)?.map(InboundSettings::Vless),
        "vmess" => opt::<VMessInboundSettings>(v)?.map(InboundSettings::Vmess),
        "trojan" => opt::<TrojanInboundSettings>(v)?.map(InboundSettings::Trojan),
        "shadowsocks" => opt::<ShadowsocksInboundSettings>(v)?.map(InboundSettings::Shadowsocks),
        "socks" | "mixed" => opt::<SocksInboundSettings>(v)?.map(InboundSettings::Socks),
        "http" => opt::<HttpInboundSettings>(v)?.map(InboundSettings::Http),
        "dokodemo-door" => opt::<DokodemoDoorInboundSettings>(v)?.map(InboundSettings::DokodemoDoor),
        "hysteria" => opt::<HysteriaInboundSettings>(v)?.map(InboundSettings::Hysteria),
        "blackhole" | "block" => opt::<BlackholeSettings>(v)?.map(InboundSettings::Blackhole),
        _ => None,
    };
    Ok(out)
}

// =========================================================================
// 测试
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_settings_round_trip_all_protocols() {
        let cases: &[(&str, &str)] = &[
            (
                "vless",
                r#"{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","email":"a@b"}]}"#,
            ),
            (
                "vmess",
                r#"{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","security":"aes-128-gcm"}]}"#,
            ),
            (
                "trojan",
                r#"{"clients":[{"password":"test-pass-12345","email":"a@b"}]}"#,
            ),
            (
                "shadowsocks",
                r#"{"method":"aes-256-gcm","password":"secret","network":["tcp","udp"]}"#,
            ),
            (
                "shadowsocks",
                // SS2022 入口靠 method 字段名"2022-blake3-aes-*-gcm" 触发。
                r#"{"method":"2022-blake3-aes-256-gcm","password":"AAAA"}"#,
            ),
            (
                "socks",
                r#"{"auth":"password","accounts":[{"user":"u","pass":"p"}],"udp":true}"#,
            ),
            (
                "http",
                r#"{"accounts":[{"user":"u","pass":"p"}],"allowTransparent":true}"#,
            ),
            (
                "dokodemo-door",
                r#"{"address":"example.com","port":80,"network":["tcp"],"followRedirect":true}"#,
            ),
            (
                "hysteria",
                r#"{"version":2,"users":[{"auth":"secret-token"}]}"#,
            ),
        ];
        for (proto, raw) in cases {
            let v: Value = serde_json::from_str(raw).unwrap();
            let parsed = dispatch_inbound_settings(proto, v.clone())
                .unwrap()
                .unwrap_or_else(|| panic!("{proto} dispatch returned None"));
            let back = serde_json::to_value(&parsed).unwrap();
            assert_eq!(back, v, "round-trip mismatch for {proto}: {raw}");
        }
    }

    #[test]
    fn outbound_settings_round_trip_all_protocols() {
        let cases: &[(&str, &str)] = &[
            (
                "vless",
                r#"{"vnext":[{"address":"example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision","encryption":"none"}]}]}"#,
            ),
            (
                "vmess",
                r#"{"vnext":[{"address":"example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","security":"aes-128-gcm"}]}]}"#,
            ),
            (
                "trojan",
                r#"{"servers":[{"address":"example.com","port":443,"password":"test-pass-12345"}]}"#,
            ),
            (
                "shadowsocks",
                r#"{"servers":[{"address":"example.com","port":8388,"method":"aes-256-gcm","password":"secret","uot":false}]}"#,
            ),
            (
                "shadowsocks",
                r#"{"servers":[{"address":"example.com","port":8388,"method":"2022-blake3-aes-256-gcm","password":"secret"}]}"#,
            ),
            (
                "socks",
                r#"{"servers":[{"address":"example.com","port":1080,"users":[{"user":"u","pass":"p"}]}]}"#,
            ),
            (
                "http",
                r#"{"servers":[{"address":"example.com","port":8080}],"headers":{"User-Agent":"curl/7.88"}}"#,
            ),
            (
                "freedom",
                r#"{"domainStrategy":"UseIP","userLevel":0}"#,
            ),
            (
                "blackhole",
                r#"{"response":{"type":"http"}}"#,
            ),
            (
                "loopback",
                r#"{"inboundTag":"in"}"#,
            ),
            (
                "hysteria",
                r#"{"version":2,"address":"example.com","port":443}"#,
            ),
            (
                "dns",
                r#"{"servers":[{"address":"1.1.1.1","port":53}],"queryStrategy":"UseIP"}"#,
            ),
        ];
        for (proto, raw) in cases {
            let v: Value = serde_json::from_str(raw).unwrap();
            let parsed = dispatch_outbound_settings(proto, v.clone())
                .unwrap()
                .unwrap_or_else(|| panic!("{proto} dispatch returned None"));
            let back = serde_json::to_value(&parsed).unwrap();
            assert_eq!(back, v, "round-trip mismatch for {proto}: {raw}");
        }
    }

    #[test]
    fn inbound_unknown_protocol_returns_none() {
        let v: Value = serde_json::from_str("{}").unwrap();
        let parsed = dispatch_inbound_settings("wireguard", v).unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn outbound_unknown_protocol_returns_none() {
        let v: Value = serde_json::from_str("{}").unwrap();
        let parsed = dispatch_outbound_settings("wireguard", v).unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn outbound_freedom_fragment_preserves_complex_payload() {
        let raw = r#"{
            "domainStrategy": "UseIPv4",
            "userLevel": 0,
            "fragment": {
                "packets": "tlshello",
                "length": "100-200",
                "interval": "10-20"
            },
            "finalRules": [
                {"action": "block", "network": ["tcp"], "port": "25,587"}
            ]
        }"#;
        let v: Value = serde_json::from_str(raw).unwrap();
        let parsed = dispatch_outbound_settings("freedom", v.clone()).unwrap().unwrap();
        let back = serde_json::to_value(&parsed).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn socks_mixed_alias_dispatches_to_socks_inbound() {
        let v: Value = serde_json::from_str(r#"{"auth":"noauth","udp":false}"#).unwrap();
        let parsed = dispatch_inbound_settings("mixed", v.clone()).unwrap().unwrap();
        assert!(matches!(parsed, InboundSettings::Socks(_)));
    }

    #[test]
    fn freedom_direct_alias_dispatches_to_freedom_outbound() {
        let v: Value = serde_json::from_str(r#"{"domainStrategy":"AsIs"}"#).unwrap();
        let parsed = dispatch_outbound_settings("direct", v).unwrap().unwrap();
        assert!(matches!(parsed, OutboundSettings::Freedom(_)));
    }

    #[test]
    fn block_alias_dispatches_to_blackhole() {
        let v: Value = serde_json::from_str(r#"{"response":{"type":"none"}}"#).unwrap();
        assert!(matches!(
            dispatch_outbound_settings("block", v.clone()).unwrap().unwrap(),
            OutboundSettings::Blackhole(_)
        ));
        assert!(matches!(
            dispatch_inbound_settings("block", v).unwrap().unwrap(),
            InboundSettings::Blackhole(_)
        ));
    }

    #[test]
    fn vless_outbound_reverse_field_round_trips() {
        let raw = r#"{
            "vnext": [{"address": "example.com", "port": 443, "users": []}],
            "reverse": {"tag": "r-tag"}
        }"#;
        let v: Value = serde_json::from_str(raw).unwrap();
        let parsed = dispatch_outbound_settings("vless", v.clone()).unwrap().unwrap();
        let back = serde_json::to_value(&parsed).unwrap();
        assert_eq!(back["reverse"]["tag"], "r-tag");
    }

    #[test]
    fn vless_inbound_fallback_dest_accepts_string_or_uint() {
        let raw_num = r#"{"fallbacks":[{"dest":8080,"xver":1}]}"#;
        let raw_str = r#"{"fallbacks":[{"dest":"localhost:8080","xver":1}]}"#;
        for raw in [raw_num, raw_str] {
            let v: Value = serde_json::from_str(raw).unwrap();
            let parsed = dispatch_inbound_settings("vless", v).unwrap().unwrap();
            if let InboundSettings::Vless(s) = parsed {
                assert!(s.fallbacks.is_some());
            } else {
                panic!("expected VLess variant");
            }
        }
    }

    #[test]
    fn hysteria2_inbound_clients_and_users_preserved_separately() {
        let raw_users = r#"{"version":2,"users":[{"auth":"tok"}]}"#;
        let raw_clients = r#"{"version":2,"clients":[{"auth":"tok"}]}"#;
        let v_users: Value = serde_json::from_str(raw_users).unwrap();
        let v_clients: Value = serde_json::from_str(raw_clients).unwrap();
        let parsed_users = dispatch_inbound_settings("hysteria", v_users).unwrap().unwrap();
        let parsed_clients = dispatch_inbound_settings("hysteria", v_clients).unwrap().unwrap();
        let back_users = serde_json::to_value(&parsed_users).unwrap();
        let back_clients = serde_json::to_value(&parsed_clients).unwrap();
        assert_eq!(back_users["users"][0]["auth"], "tok");
        assert!(back_users.get("clients").is_none());
        assert_eq!(back_clients["clients"][0]["auth"], "tok");
        assert!(back_clients.get("users").is_none());
    }

    #[test]
    fn vless_inbound_settings_dispatch_via_protocol_name() {
        // 注：InboundDetourConfig.settings 当前仍是 Option<Value>（兼容 built.rs 透传），
        // 强类型 dispatch 由 `crate::protocols::dispatch_inbound_settings` 提供。
        let json = r#"{
            "protocol": "vless",
            "port": 443,
            "tag": "in",
            "settings": {
                "decryption": "none",
                "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}]
            }
        }"#;
        let cfg: crate::config::InboundDetourConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.protocol, "vless");
        assert_eq!(cfg.tag, "in");
        let typed = dispatch_inbound_settings(&cfg.protocol, cfg.settings.clone().unwrap())
            .unwrap()
            .unwrap();
        assert!(matches!(typed, InboundSettings::Vless(_)));
    }

    #[test]
    fn freedom_outbound_settings_dispatch_via_protocol_name() {
        let json = r#"{
            "protocol": "freedom",
            "tag": "direct",
            "settings": {"domainStrategy": "AsIs"}
        }"#;
        let cfg: crate::config::OutboundDetourConfig = serde_json::from_str(json).unwrap();
        let typed = dispatch_outbound_settings(&cfg.protocol, cfg.settings.clone().unwrap())
            .unwrap()
            .unwrap();
        assert!(matches!(typed, OutboundSettings::Freedom(_)));
    }

    #[test]
    fn shadowsocks_method_from_name_covers_go_five_groups() {
        // Go cipherFromString（shadowsocks.go:17-32）5 组 + 大小写不敏感 + 别名。
        let cases = &[
            ("aes-128-gcm", ShadowsocksMethod::Aes128Gcm),
            ("aead_aes_128_gcm", ShadowsocksMethod::Aes128Gcm),
            ("AES-128-GCM", ShadowsocksMethod::Aes128Gcm),
            ("aes-256-gcm", ShadowsocksMethod::Aes256Gcm),
            ("aead_aes_256_gcm", ShadowsocksMethod::Aes256Gcm),
            ("chacha20-poly1305", ShadowsocksMethod::ChaCha20Poly1305),
            ("aead_chacha20_poly1305", ShadowsocksMethod::ChaCha20Poly1305),
            ("chacha20-ietf-poly1305", ShadowsocksMethod::ChaCha20Poly1305),
            ("xchacha20-poly1305", ShadowsocksMethod::XChaCha20Poly1305),
            ("aead_xchacha20_poly1305", ShadowsocksMethod::XChaCha20Poly1305),
            ("none", ShadowsocksMethod::None),
            ("plain", ShadowsocksMethod::None),
        ];
        for (name, want) in cases {
            assert_eq!(ShadowsocksMethod::from_method(name), Some(*want), "{name}");
        }
        // 2022 3 方法精确匹配（shadowaead_2022.List，:60）。
        assert_eq!(
            ShadowsocksMethod::from_method("2022-blake3-aes-128-gcm"),
            Some(ShadowsocksMethod::Ss2022Aes128Gcm)
        );
        assert_eq!(
            ShadowsocksMethod::from_method("2022-blake3-aes-256-gcm"),
            Some(ShadowsocksMethod::Ss2022Aes256Gcm)
        );
        assert_eq!(
            ShadowsocksMethod::from_method("2022-blake3-chacha20-poly1305"),
            Some(ShadowsocksMethod::Ss2022ChaCha20Poly1305)
        );
        // 2022 名大小写敏感：大写变体不命中 2022，落入旧 AEAD 解析失败（UNKNOWN）。
        assert_eq!(ShadowsocksMethod::from_method("2022-BLAKE3-AES-128-GCM"), None);
        assert_eq!(ShadowsocksMethod::from_method("rc4-md5"), None);
        // 分流判定。
        assert!(ShadowsocksMethod::Ss2022ChaCha20Poly1305.is_ss2022());
        assert!(!ShadowsocksMethod::Aes256Gcm.is_ss2022());
    }

    #[test]
    fn shadowsocks_outbound_uot_uot_version_round_trip() {
        // servers[0] 携带 uot/uotVersion → Ss2022 产物字段映射（Go :243-244）。
        let raw = r#"{"servers":[{"address":"ss.example.com","port":8388,
            "method":"2022-blake3-aes-256-gcm","password":"aGk=",
            "uot":true,"uotVersion":1}]}"#;
        let s: ShadowsocksOutboundSettings = serde_json::from_str(raw).unwrap();
        // serde round-trip 不丢字段。
        let back = serde_json::to_value(&s).unwrap();
        assert_eq!(back["servers"][0]["uot"], true);
        assert_eq!(back["servers"][0]["uotVersion"], 1);
        match s.build().unwrap() {
            ShadowsocksClientBuild::Ss2022 {
                udp_over_tcp,
                udp_over_tcp_version,
                ..
            } => {
                assert!(udp_over_tcp);
                assert_eq!(udp_over_tcp_version, 1);
            }
            other => panic!("expected Ss2022, got {other:?}"),
        }

        // 顶层 address 折叠路径（Go :207-220）同样携带 uot。
        let folded = r#"{"address":"ss.example.com","port":8388,
            "method":"2022-blake3-aes-256-gcm","password":"aGk=",
            "uot":true,"uotVersion":2}"#;
        let s: ShadowsocksOutboundSettings = serde_json::from_str(folded).unwrap();
        match s.build().unwrap() {
            ShadowsocksClientBuild::Ss2022 {
                udp_over_tcp,
                udp_over_tcp_version,
                ..
            } => {
                assert!(udp_over_tcp);
                assert_eq!(udp_over_tcp_version, 2);
            }
            other => panic!("expected Ss2022, got {other:?}"),
        }

        // 缺省 uot → false/0（Go 零值）。
        let plain = r#"{"servers":[{"address":"ss.example.com","port":8388,
            "method":"2022-blake3-aes-256-gcm","password":"aGk="}]}"#;
        let s: ShadowsocksOutboundSettings = serde_json::from_str(plain).unwrap();
        match s.build().unwrap() {
            ShadowsocksClientBuild::Ss2022 {
                udp_over_tcp,
                udp_over_tcp_version,
                ..
            } => {
                assert!(!udp_over_tcp);
                assert_eq!(udp_over_tcp_version, 0);
            }
            other => panic!("expected Ss2022, got {other:?}"),
        }
    }

    #[test]
    fn shadowsocks_inbound_users_multi_chacha_rejected() {
        // Go :128-130：多用户仅支持 blake3-aes-*-gcm，chacha 报错。
        let raw = r#"{"method":"2022-blake3-chacha20-poly1305","password":"aGk=",
            "users":[{"password":"dXNlcg=="}]}"#;
        let s: ShadowsocksInboundSettings = serde_json::from_str(raw).unwrap();
        let err = s.build().unwrap_err().to_string();
        assert!(
            err.contains("only blake3-aes-*-gcm methods are supported"),
            "got: {err}"
        );
    }

    #[test]
    fn shadowsocks_inbound_users_multi_aes_builds_multi_user() {
        // Go :132-157：无 relay address 的多用户 → MultiUserServerConfig。
        let raw = r#"{"method":"2022-blake3-aes-256-gcm","password":"c2VydmVy",
            "users":[{"password":"dXNlcjE=","email":"a@b","level":2},
                     {"password":"dXNlcjI="}]}"#;
        let s: ShadowsocksInboundSettings = serde_json::from_str(raw).unwrap();
        match s.build().unwrap() {
            ShadowsocksServerBuild::Ss2022MultiUser { method, key, users, .. } => {
                assert_eq!(method, "2022-blake3-aes-256-gcm");
                assert_eq!(key, "c2VydmVy");
                assert_eq!(users.len(), 2);
                assert_eq!(users[0].key, "dXNlcjE=");
                assert_eq!(users[0].email, "a@b");
                assert_eq!(users[0].level, 2);
                assert_eq!(users[1].key, "dXNlcjI=");
            }
            other => panic!("expected Ss2022MultiUser, got {other:?}"),
        }
    }

    #[test]
    fn shadowsocks_inbound_single_2022_and_relay_rejected() {
        // 无 users → shadowsocks_2022.ServerConfig 单用户（Go :116-123）。
        let raw = r#"{"method":"2022-blake3-aes-256-gcm","password":"aGk=","email":"s@x"}"#;
        let s: ShadowsocksInboundSettings = serde_json::from_str(raw).unwrap();
        match s.build().unwrap() {
            ShadowsocksServerBuild::Ss2022Single { method, key, email, .. } => {
                assert_eq!(method, "2022-blake3-aes-256-gcm");
                assert_eq!(key, "aGk=");
                assert_eq!(email, "s@x");
            }
            other => panic!("expected Ss2022Single, got {other:?}"),
        }
        // users[0].address 存在 → relay 分支（non-goal，显式报错）。
        let relay = r#"{"method":"2022-blake3-aes-256-gcm","password":"aGk=",
            "users":[{"password":"dXNlcg==","address":"127.0.0.1","port":8389}]}"#;
        let s: ShadowsocksInboundSettings = serde_json::from_str(relay).unwrap();
        let err = s.build().unwrap_err().to_string();
        assert!(err.contains("relay"), "got: {err}");
        // 多用户用户级 method 必须为空（Go :141-143）。
        let with_method = r#"{"method":"2022-blake3-aes-256-gcm","password":"aGk=",
            "users":[{"password":"dXNlcg==","method":"aes-256-gcm"}]}"#;
        let s: ShadowsocksInboundSettings = serde_json::from_str(with_method).unwrap();
        let err = s.build().unwrap_err().to_string();
        assert!(err.contains("users must have empty method"), "got: {err}");
    }

    #[test]
    fn shadowsocks_inbound_legacy_top_level_and_per_user() {
        // 顶层单账户：none/plain 合法（Go :102-104 仅拒 UNKNOWN）。
        let raw = r#"{"method":"none","password":"p"}"#;
        let s: ShadowsocksInboundSettings = serde_json::from_str(raw).unwrap();
        match s.build().unwrap() {
            ShadowsocksServerBuild::LegacyAead { users, .. } => {
                assert_eq!(users.len(), 1);
                assert_eq!(users[0].cipher, ShadowsocksMethod::None);
            }
            other => panic!("expected LegacyAead, got {other:?}"),
        }
        // 顶层未知 cipher 报错。
        let raw = r#"{"method":"rc4-md5","password":"p"}"#;
        let s: ShadowsocksInboundSettings = serde_json::from_str(raw).unwrap();
        let err = s.build().unwrap_err().to_string();
        assert!(err.contains("unknown cipher method"), "got: {err}");
        // 顶层密码为空报错。
        let raw = r#"{"method":"aes-256-gcm"}"#;
        let s: ShadowsocksInboundSettings = serde_json::from_str(raw).unwrap();
        let err = s.build().unwrap_err().to_string();
        assert!(err.contains("password is not specified"), "got: {err}");

        // per-user：合法 AEAD（chacha 亦合法，Go 范围 5..=8 含 CHACHA=7）。
        let raw = r#"{"method":"aes-256-gcm","users":[
            {"method":"chacha20-poly1305","password":"u1","email":"a@b"},
            {"method":"aes-128-gcm","password":"u2"}]}"#;
        let s: ShadowsocksInboundSettings = serde_json::from_str(raw).unwrap();
        match s.build().unwrap() {
            ShadowsocksServerBuild::LegacyAead { users, .. } => {
                assert_eq!(users.len(), 2);
                assert_eq!(users[0].cipher, ShadowsocksMethod::ChaCha20Poly1305);
                assert_eq!(users[0].email, "a@b");
                assert_eq!(users[1].cipher, ShadowsocksMethod::Aes128Gcm);
            }
            other => panic!("expected LegacyAead, got {other:?}"),
        }
        // per-user none 越界被拒（proto NONE=9 > XCHACHA=8，Go :79-81）。
        let raw = r#"{"method":"aes-256-gcm","users":[{"method":"none","password":"u"}]}"#;
        let s: ShadowsocksInboundSettings = serde_json::from_str(raw).unwrap();
        let err = s.build().unwrap_err().to_string();
        assert!(err.contains("unsupported cipher method"), "got: {err}");
        // per-user 密码为空优先于 cipher 检查（Go :76-78）。
        let raw = r#"{"method":"aes-256-gcm","users":[{"method":"aes-256-gcm"}]}"#;
        let s: ShadowsocksInboundSettings = serde_json::from_str(raw).unwrap();
        let err = s.build().unwrap_err().to_string();
        assert!(err.contains("password is not specified"), "got: {err}");

        // clients 覆盖 users（Go :56-58），含空 clients 压成空 users 的 Go 边界。
        let raw = r#"{"method":"aes-256-gcm","password":"top",
            "users":[{"method":"aes-256-gcm","password":"u"}],
            "clients":[]}"#;
        let s: ShadowsocksInboundSettings = serde_json::from_str(raw).unwrap();
        match s.build().unwrap() {
            ShadowsocksServerBuild::LegacyAead { users, .. } => assert!(users.is_empty()),
            other => panic!("expected LegacyAead, got {other:?}"),
        }
    }

    #[test]
    fn shadowsocks_outbound_servers_rules_and_legacy() {
        // servers ≠ 1 报错（Go :221-223）。
        let raw = r#"{"servers":[
            {"address":"a","port":1,"method":"aes-256-gcm","password":"p"},
            {"address":"b","port":2,"method":"aes-256-gcm","password":"p"}]}"#;
        let s: ShadowsocksOutboundSettings = serde_json::from_str(raw).unwrap();
        let err = s.build().unwrap_err().to_string();
        assert!(err.contains("one and only one member"), "got: {err}");
        let s: ShadowsocksOutboundSettings = serde_json::from_str("{}").unwrap();
        assert!(s.build().unwrap_err().to_string().contains("one and only one member"));

        // 旧 AEAD 单 server（Go :249-283，不带 UoT 字段）。
        let raw = r#"{"servers":[{"address":"ss.example.com","port":8388,
            "method":"aes-256-gcm","password":"secret","level":3,"email":"a@b"}]}"#;
        let s: ShadowsocksOutboundSettings = serde_json::from_str(raw).unwrap();
        match s.build().unwrap() {
            ShadowsocksClientBuild::LegacyAead {
                address,
                port,
                level,
                email,
                password,
                cipher,
            } => {
                assert_eq!(address, Address("ss.example.com".into()));
                assert_eq!(port, 8388);
                assert_eq!(level, 3);
                assert_eq!(email, "a@b");
                assert_eq!(password, "secret");
                assert_eq!(cipher, ShadowsocksMethod::Aes256Gcm);
            }
            other => panic!("expected LegacyAead, got {other:?}"),
        }
        // 旧 AEAD 未知 cipher / 空 password / port 0。
        let raw = r#"{"servers":[{"address":"a","port":8388,"method":"rc4-md5","password":"p"}]}"#;
        let s: ShadowsocksOutboundSettings = serde_json::from_str(raw).unwrap();
        assert!(s.build().unwrap_err().to_string().contains("unknown cipher method"));
        let raw = r#"{"servers":[{"address":"a","port":8388,"method":"aes-256-gcm"}]}"#;
        let s: ShadowsocksOutboundSettings = serde_json::from_str(raw).unwrap();
        assert!(s
            .build()
            .unwrap_err()
            .to_string()
            .contains("password is not specified"));
        let raw = r#"{"servers":[{"address":"a","port":0,"method":"aes-256-gcm","password":"p"}]}"#;
        let s: ShadowsocksOutboundSettings = serde_json::from_str(raw).unwrap();
        assert!(s.build().unwrap_err().to_string().contains("Invalid Shadowsocks port"));
    }
}

