//! WireGuard 配置。
//!
//! 对应 Go `proxy/wireguard/config.go` + `config.proto`。
//!
//! ## 字段
//!
//! ### DeviceConfig
//! | 字段 | 用途 |
//! |------|------|
//! | `secret_key` | WireGuard 私钥（hex 编码 64 字符 = 32 字节） |
//! | `endpoint` | interface 地址（CIDR 或纯 IP） |
//! | `peers` | 对端配置列表 |
//! | `mtu` | MTU，默认 1420 |
//! | `num_workers` | WireGuard 工作线程数 |
//! | `reserved` | WireGuard reserved 字段（3 字节，用于混淆） |
//! | `is_client` | 客户端（出站）or 服务端（入站） |
//! | `no_kernel_tun` | 强制使用 userspace TUN（gVisor），不用内核 TUN |
//!
//! ### PeerConfig
//! | 字段 | 用途 |
//! |------|------|
//! | `public_key` | 对端公钥（hex 64 字符） |
//! | `pre_shared_key` | 可选 PSK（hex 64 字符） |
//! | `endpoint` | 对端地址 `host:port` |
//! | `keep_alive` | 心跳间隔（秒），0=禁用 |
//! | `allowed_ips` | 允许的源 IP CIDR 列表 |

use crate::error::{Result, WgError};

/// 对端配置。对应 proto `xray.proxy.wireguard.PeerConfig` + Go `WireGuardPeerConfig`
/// 的 `level`/`email`（wireguard.go:24-25：服务端形态经 `protocol.User` 供
/// policy/stats 分级；proto 本体无此二字段，仅存于本配置层）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerConfig {
    /// 对端公钥（hex 64 字符）。
    pub public_key: String,
    /// 可选 PSK（hex 64 字符）。
    pub pre_shared_key: String,
    /// 对端地址 `host:port`。
    pub endpoint: String,
    /// 心跳间隔（秒）。0=禁用。
    pub keep_alive: u32,
    /// 允许的源 IP CIDR 列表。
    pub allowed_ips: Vec<String>,
    /// 用户等级（per-user policy 分级）。对应 Go `WireGuardPeerConfig.Level`。
    pub level: u32,
    /// 用户邮箱标识（stats 计数键）。对应 Go `WireGuardPeerConfig.Email`。
    pub email: String,
}

/// 设备配置。对应 proto `xray.proxy.wireguard.DeviceConfig`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceConfig {
    /// WireGuard 私钥（hex 64 字符）。
    pub secret_key: String,
    /// interface 地址（CIDR 或纯 IP）。
    pub endpoint: Vec<String>,
    /// 对端配置列表。
    pub peers: Vec<PeerConfig>,
    /// MTU。0=默认 1420。
    pub mtu: i32,
    /// WireGuard 工作线程数。
    pub num_workers: i32,
    /// reserved 字段（3 字节，用于混淆）。
    pub reserved: Vec<u8>,
    /// 客户端（出站）or 服务端（入站）。
    pub is_client: bool,
    /// 强制 userspace TUN。
    pub no_kernel_tun: bool,
    /// 隧道内 DNS 服务器（Go c7e569b0 `remoteDNS` → DeviceConfig.DNS）。
    ///
    /// 语义（Go efc9e6da 删除 "local" 模式后）：
    /// - 空 → 默认 Cloudflare 四址（`TUNNEL_DNS_SERVERS`）
    /// - `["local"]` → 已废弃：警告后回落默认隧道 DNS（Go 侧删除，Rust 保翻不硬错）
    /// - 其余 → 逐项 IP 字面量，作为隧道内 DNS 查询目标
    pub dns: Vec<String>,
}

impl DeviceConfig {
    /// MTU 默认值（与 Go boringtun 一致）。
    pub const DEFAULT_MTU: i32 = 1420;

    /// 获取有效 MTU（0 时返回默认 1420）。
    #[must_use]
    pub fn effective_mtu(&self) -> i32 {
        if self.mtu == 0 { Self::DEFAULT_MTU } else { self.mtu }
    }

    /// 从 prost 生成的 proto DeviceConfig 构造。
    pub fn from_proto(p: xray_proto::xray::proxy::wireguard::DeviceConfig) -> Result<Self> {
        Ok(Self {
            secret_key: p.secret_key,
            endpoint: p.endpoint,
            peers: p
                .peers
                .into_iter()
                .map(|peer| PeerConfig {
                    public_key: peer.public_key,
                    pre_shared_key: peer.pre_shared_key,
                    endpoint: peer.endpoint,
                    keep_alive: peer.keep_alive,
                    allowed_ips: peer.allowed_ips,
                    // proto 层无 level/email（Go 同样只存配置层）。
                    level: 0,
                    email: String::new(),
                })
                .collect(),
            mtu: p.mtu,
            num_workers: p.num_workers,
            reserved: p.reserved,
            is_client: p.is_client,
            no_kernel_tun: p.no_kernel_tun,
            dns: p.dns,
        })
    }

    /// 转换为 prost DeviceConfig（用于序列化）。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::proxy::wireguard::DeviceConfig {
        xray_proto::xray::proxy::wireguard::DeviceConfig {
            secret_key: self.secret_key.clone(),
            endpoint: self.endpoint.clone(),
            peers: self
                .peers
                .iter()
                .map(|peer| xray_proto::xray::proxy::wireguard::PeerConfig {
                    public_key: peer.public_key.clone(),
                    pre_shared_key: peer.pre_shared_key.clone(),
                    endpoint: peer.endpoint.clone(),
                    keep_alive: peer.keep_alive,
                    allowed_ips: peer.allowed_ips.clone(),
                })
                .collect(),
            mtu: self.mtu,
            num_workers: self.num_workers,
            reserved: self.reserved.clone(),
            is_client: self.is_client,
            no_kernel_tun: self.no_kernel_tun,
            dns: self.dns.clone(),
        }
    }

    /// 解析 `dns` 字段语义（Go efc9e6da 删除 "local" 模式后）。
    ///
    /// - 空 → [`DnsConfig::Default`]（Cloudflare 四址）
    /// - `["local"]` → 已废弃（Go 删除后 `netip.MustParseAddr` 直接 panic；Rust 保翻
    ///   先例不硬错）：警告后回落 [`DnsConfig::Default`] 隧道 DNS
    /// - 其余 → [`DnsConfig::Servers`]（非法 IP 字面量报错；Go 侧 `netip.MustParseAddr` 直接
    ///   panic，Rust 侧返回错误更合理）
    pub fn resolve_dns(&self) -> Result<DnsConfig> {
        match self.dns.as_slice() {
            [] => Ok(DnsConfig::Default),
            [s] if s == "local" => {
                tracing::warn!(
                    "wireguard outbound: remoteDNS \"local\" is deprecated (removed upstream, \
                     efc9e6da); falling back to default tunnel DNS"
                );
                Ok(DnsConfig::Default)
            },
            entries => {
                let mut servers = Vec::with_capacity(entries.len());
                for e in entries {
                    let ip: std::net::IpAddr = e.parse().map_err(|_| {
                        WgError::InvalidConfig(format!("remoteDNS: invalid IP: {e}"))
                    })?;
                    servers.push(ip);
                }
                Ok(DnsConfig::Servers(servers))
            },
        }
    }
}

/// `remoteDNS` 解析结果（Go client.go `dnses` 列表的 Rust 形态；efc9e6da 后无 "local" 模式）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsConfig {
    /// 未配置 → Cloudflare 默认四址。
    Default,
    /// 显式服务器列表（隧道内查询目标）。
    Servers(Vec<std::net::IpAddr>),
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== DeviceConfig =====

    #[test]
    fn effective_mtu_default_when_zero() {
        let cfg = DeviceConfig { mtu: 0, ..Default::default() };
        assert_eq!(cfg.effective_mtu(), DeviceConfig::DEFAULT_MTU);
        assert_eq!(cfg.effective_mtu(), 1420);
    }

    #[test]
    fn effective_mtu_passthrough_when_set() {
        let cfg = DeviceConfig { mtu: 1280, ..Default::default() };
        assert_eq!(cfg.effective_mtu(), 1280);
    }

    #[test]
    fn proto_roundtrip_full_config() {
        let cfg = DeviceConfig {
            secret_key: "aabbccdd".repeat(8), // 32 字节 hex
            endpoint: vec!["10.0.0.1/32".into(), "fd00::1/128".into()],
            peers: vec![PeerConfig {
                public_key: "eeff0011".repeat(8),
                pre_shared_key: String::new(),
                endpoint: "1.2.3.4:51820".into(),
                keep_alive: 25,
                allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
                level: 0,
                email: String::new(),
            }],
            mtu: 1280,
            num_workers: 4,
            reserved: vec![0, 0, 0],
            is_client: true,
            no_kernel_tun: false,
            dns: vec!["1.1.1.1".into(), "8.8.8.8".into()],
        };
        let proto = cfg.to_proto();
        let cfg2 = DeviceConfig::from_proto(proto).unwrap();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn resolve_dns_semantics() {
        // Go efc9e6da：空 → 默认；["local"] 已废弃（警告+回落默认隧道 DNS，不硬错）；
        // 其余按 IP 解析。
        let mut cfg = DeviceConfig::default();
        assert_eq!(cfg.resolve_dns().unwrap(), DnsConfig::Default);

        cfg.dns = vec!["local".into()];
        assert_eq!(cfg.resolve_dns().unwrap(), DnsConfig::Default);

        cfg.dns = vec!["1.1.1.1".into(), "2606:4700:4700::1111".into()];
        assert_eq!(
            cfg.resolve_dns().unwrap(),
            DnsConfig::Servers(vec![
                "1.1.1.1".parse().unwrap(),
                "2606:4700:4700::1111".parse().unwrap(),
            ])
        );

        cfg.dns = vec!["dns.google".into()];
        let err = cfg.resolve_dns().unwrap_err();
        assert!(err.to_string().contains("invalid IP"), "{err}");
    }

    #[test]
    fn proto_roundtrip_empty_config() {
        let cfg = DeviceConfig::default();
        let proto = cfg.to_proto();
        let cfg2 = DeviceConfig::from_proto(proto).unwrap();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn default_config_is_client_false() {
        let cfg = DeviceConfig::default();
        assert!(!cfg.is_client);
        assert!(!cfg.no_kernel_tun);
        assert_eq!(cfg.mtu, 0);
        assert!(cfg.endpoint.is_empty());
        assert!(cfg.peers.is_empty());
    }
}
