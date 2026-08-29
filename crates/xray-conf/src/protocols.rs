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
}

