//! TUN 配置与抽象。
//!
//! 对应 Go `proxy/tun/config.go` + `tun.go` + `stack.go`。
//!
//! ## 切片边界（P6-6 切片1）
//!
//! TUN 没有独立 proto Config（配置在 `infra/conf` 中作为 `TunConfig`，仅 name+MTU）。
//! 切片1 实现纯逻辑部分：
//!
//! - [`score`] — 网络接口评分（用于选择默认出口接口），对应 Go `config.go::score`
//! - [`StackOptions`] — netstack 配置，对应 Go `stack.go::StackOptions`
//! - [`Tun`] / [`Stack`] trait — 设备与协议栈抽象，对应 Go `tun.go::Tun` / `stack.go::Stack`
//!
//! 切片2 待办：`InterfaceUpdater`（依赖 `if-addrs` crate 或 platform-specific syscall）+
//! 平台 TUN 设备实现（Linux /dev/net/tun、Windows wintun、macOS utun、FreeBSD tun）+
//! gVisor netstack / smoltcp-netstack 集成 + TCP/UDP 包处理。

use std::time::Duration;

use xray_proto::xray::proxy::tun::Config as ProtoConfig;

use crate::error::{Result, TunError};

/// 网络接口评分。用于 [`InterfaceUpdater`](crate#切片边界) 在未指定接口名时
/// 自动选择最可能的默认出口接口。
///
/// 评分规则（与 Go `config.go::score` 一致）：
/// - 接口名（小写）包含 `"wlan"` 或 `"wi-fi"` → +2（无线网卡优先）
/// - 任一地址以 `"192.168."` 开头 → +1（典型家庭/办公网关）
///
/// # 参数
///
/// - `iface_name`：接口名（如 `"wlan0"`、`"eth0"`、`"Wi-Fi"`）。
/// - `addr_strs`：接口绑定的地址字符串列表（如 `["192.168.1.100/24", "fe80::1"]`）。
///
/// # 返回
///
/// 总分（≥0）。分数越高越优先被选为出口接口。
///
/// 对应 Go `score(iface *net.Interface, addrs []net.Addr) int`。
#[must_use]
pub fn score(iface_name: &str, addr_strs: &[&str]) -> i32 {
    let mut s = 0;
    let name_lower = iface_name.to_ascii_lowercase();
    if name_lower.contains("wlan") || name_lower.contains("wi-fi") {
        s += 2;
    }
    for addr in addr_strs {
        if addr.starts_with("192.168.") {
            s += 1;
            break;
        }
    }
    s
}

/// TUN 设备抽象。对应 Go `tun.go::Tun` interface。
///
/// 实现者负责平台特定的 TUN 设备创建与读写：
/// - **Linux**：`/dev/net/tun` + ioctl
/// - **Windows**：`wintun.dll`
/// - **macOS/iOS**：`utun`（NetworkExtension / 系统调用）
/// - **FreeBSD**：`tun(4)` 设备
/// - **Android**：`VpnService` API（fd 通过环境变量 `XRAY_TUN_FD` 传入）
///
/// 切片2 提供具体实现。
pub trait Tun: Send + Sync {
    /// 启动设备（打开 fd / 注册适配器）。
    fn start(&self) -> Result<()>;

    /// 关闭设备（释放 fd / 适配器）。
    fn close(&self) -> Result<()>;

    /// 设备名（如 `"xray0"`、`"utun10"`）。
    fn name(&self) -> Result<String>;

    /// 设备接口索引（OS 级 ifindex）。
    fn index(&self) -> Result<i32>;
    // new_endpoint() 留切片2：依赖 gVisor stack.LinkEndpoint 或 smoltcp 等价品。
}

/// IP 协议栈抽象。对应 Go `stack.go::Stack` interface。
///
/// 实现者负责把 TUN 设备的原始 IP 包桥接到 Xray 的 TCP/UDP stream：
/// - **Go 端**：gVisor netstack（`gvisor.dev/gvisor/pkg/tcpip/stack`）
/// - **Rust 端候选**：`smoltcp` + `netstack-smoltcp` crate
///
/// 切片2 提供具体实现。
pub trait Stack: Send + Sync {
    /// 启动协议栈（开始处理 TUN 输入的 IP 包）。
    fn start(&self) -> Result<()>;

    /// 关闭协议栈（释放所有连接资源）。
    fn close(&self) -> Result<()>;
}

/// 协议栈配置。对应 Go `stack.go::StackOptions` + `infra/conf/tun.go::TunConfig`。
pub struct StackOptions {
    /// TUN 设备（trait object）。
    ///
    /// 切片1 不强制具体实现，调用方在切片2 注入平台特定设备。
    pub tun: Option<Box<dyn Tun>>,
    /// 空闲连接超时。对应 Go `IdleTimeout time.Duration`。
    pub idle_timeout: Duration,
    /// 设备名。JSON `"name"`，空/缺省 → `"xray0"`（Go infra/conf/tun.go:34-36）。
    pub name: String,
    /// MTU。JSON `"mtu"`，0/缺省 → 1500（Go infra/conf/tun.go:37-39）。
    pub mtu: u32,
    /// 接口地址 CIDR 列表（如 `"10.0.0.1/24"`）。JSON `"gateway"`——Go 侧即接口地址
    /// （Windows `SetIPAddresses`，tun_windows.go:117-123；Darwin `setIPAddress`，tun_darwin.go:248）。
    pub gateway: Vec<String>,
    /// DNS 服务器。JSON `"dns"`（Go tun_windows.go:163-175 SetDNS；Linux 由外部配置）。
    pub dns: Vec<String>,
    /// 用户级别。JSON `"userLevel"`。
    pub user_level: u32,
    /// 自动路由表。JSON `"autoSystemRoutingTable"`。
    pub auto_system_routing_table: Vec<String>,
    /// 自动出口接口。JSON `"autoOutboundsInterface"`；
    /// autoSystemRoutingTable 非空而未指定时归一化为 `"auto"`（Go infra/conf/tun.go:30-32）。
    pub auto_outbounds_interface: Option<String>,
}

impl Default for StackOptions {
    fn default() -> Self {
        Self {
            tun: None,
            // 与 Go 默认一致：30 秒空闲超时（Go 端在实际使用时由上层设置）。
            idle_timeout: Duration::from_secs(30),
            name: "xray0".to_string(),
            mtu: 1500,
            gateway: Vec::new(),
            dns: Vec::new(),
            user_level: 0,
            auto_system_routing_table: Vec::new(),
            auto_outbounds_interface: None,
        }
    }
}

impl StackOptions {
    /// 从 inbound settings JSON 解析设备参数。
    ///
    /// 对应 Go `infra/conf/tun.go::TunConfig.Build`（JSON 字段与默认值逐一对齐）；
    /// `tun` 设备 trait 不来自 JSON，由调用方注入。
    pub fn parse_json(data: &[u8]) -> Result<Self> {
        let mut opts = Self::default();
        if data.is_empty() {
            return Ok(opts);
        }
        let v: serde_json::Value = serde_json::from_slice(data)
            .map_err(|e| TunError::InvalidConfig(format!("tun config: {e}")))?;
        if let Some(s) = v.get("name").and_then(|x| x.as_str()) {
            opts.name = s.to_string();
        }
        if let Some(n) = v.get("mtu").and_then(|x| x.as_u64()) {
            if n > u64::from(u16::MAX) {
                return Err(TunError::InvalidConfig(format!("mtu: {n} exceeds 65535")));
            }
            opts.mtu = n as u32;
        }
        if let Some(arr) = v.get("gateway").and_then(|x| x.as_array()) {
            opts.gateway = str_list(arr, "gateway")?;
        }
        if let Some(arr) = v.get("dns").and_then(|x| x.as_array()) {
            opts.dns = str_list(arr, "dns")?;
        }
        if let Some(n) = v.get("userLevel").and_then(|x| x.as_u64()) {
            opts.user_level = n as u32;
        }
        if let Some(arr) = v.get("autoSystemRoutingTable").and_then(|x| x.as_array()) {
            opts.auto_system_routing_table = str_list(arr, "autoSystemRoutingTable")?;
        }
        if let Some(s) = v.get("autoOutboundsInterface").and_then(|x| x.as_str()) {
            opts.auto_outbounds_interface = Some(s.to_string());
        }
        // idleTimeout：Rust 扩展（Go TunConfig 无此字段）；数字（秒）或 "30s"/"5m"。
        if let Some(val) = v.get("idleTimeout") {
            opts.idle_timeout = parse_duration_value(val, "idleTimeout")?;
        }
        // Build 归一化（Go infra/conf/tun.go:30-39）
        if !opts.auto_system_routing_table.is_empty() && opts.auto_outbounds_interface.is_none() {
            opts.auto_outbounds_interface = Some("auto".to_string());
        }
        if opts.name.is_empty() {
            opts.name = "xray0".to_string();
        }
        if opts.mtu == 0 {
            opts.mtu = 1500;
        }
        Ok(opts)
    }

    /// 首个 IPv4 gateway CIDR → (addr, prefix)。
    #[must_use]
    pub fn ipv4_gateway(&self) -> Option<(std::net::Ipv4Addr, u8)> {
        self.gateway.iter().find_map(|g| match parse_ip_cidr(g) {
            Some((std::net::IpAddr::V4(a), p)) => Some((a, p)),
            _ => None,
        })
    }

    /// 设备 IPv4 地址：gateway 首个 v4 CIDR；无 v4 gateway 时默认 10.0.0.1/24
    /// （Go 无此默认——Linux 由外部配置地址；smoltcp netstack 需要本地地址）。
    #[must_use]
    pub fn device_ipv4(&self) -> (std::net::Ipv4Addr, u8) {
        self.ipv4_gateway()
            .unwrap_or((std::net::Ipv4Addr::new(10, 0, 0, 1), 24))
    }

    /// netstack 本地地址列表：gateway 全部 CIDR（v4+v6）；空则设备默认 v4。
    #[must_use]
    pub fn local_cidrs(&self) -> Vec<smoltcp::wire::IpCidr> {
        let cidrs: Vec<_> = self
            .gateway
            .iter()
            .filter_map(|g| parse_ip_cidr(g))
            .map(|(addr, prefix)| match addr {
                std::net::IpAddr::V4(a) => smoltcp::wire::IpCidr::new(
                    smoltcp::wire::IpAddress::Ipv4(crate::netstack::to_smoltcp_v4(a)),
                    prefix,
                ),
                std::net::IpAddr::V6(a) => smoltcp::wire::IpCidr::new(
                    smoltcp::wire::IpAddress::Ipv6(crate::netstack::to_smoltcp_v6(a)),
                    prefix,
                ),
            })
            .collect();
        if cidrs.is_empty() {
            let (v4, prefix) = self.device_ipv4();
            vec![smoltcp::wire::IpCidr::new(
                smoltcp::wire::IpAddress::Ipv4(crate::netstack::to_smoltcp_v4(v4)),
                prefix,
            )]
        } else {
            cidrs
        }
    }
}

// ===== proto Config 互转（bd v5g：proxy.tun.Config 7 字段） =====

impl StackOptions {
    /// 从 prost `Config` 构造（7 字段 + Go `TunConfig.Build()` 归一化）。
    ///
    /// 对应 Go `infra/conf/tun.go:18-40`：
    /// - `auto_system_routing_table` 非空且未指定 interface → `"auto"`
    /// - `name` 空 → `"xray0"`
    /// - `MTU` 0 → 1500
    ///
    /// `tun` 设备与 `idle_timeout` 不来自 proto，保持默认（由调用方注入/覆盖）。
    #[must_use]
    pub fn from_proto(p: &ProtoConfig) -> Self {
        let mut name = p.name.clone();
        let mut mtu = p.mtu;
        let auto_outbounds_interface = if p.auto_outbounds_interface.is_empty() {
            None
        } else {
            Some(p.auto_outbounds_interface.clone())
        };
        // Build 归一化（Go infra/conf/tun.go:30-39）
        let auto_outbounds_interface = if !p.auto_system_routing_table.is_empty()
            && auto_outbounds_interface.is_none()
        {
            Some("auto".to_string())
        } else {
            auto_outbounds_interface
        };
        if name.is_empty() {
            name = "xray0".to_string();
        }
        if mtu == 0 {
            mtu = 1500;
        }
        Self {
            name,
            mtu,
            gateway: p.gateway.clone(),
            dns: p.dns.clone(),
            user_level: p.user_level,
            auto_system_routing_table: p.auto_system_routing_table.clone(),
            auto_outbounds_interface,
            ..Self::default()
        }
    }

    /// 转换为 prost `Config`（7 字段；`auto_outbounds_interface` None → `""`）。
    ///
    /// 已归一化的运行时值（name/mtu 默认、interface "auto"）按当前值写回。
    #[must_use]
    pub fn to_proto(&self) -> ProtoConfig {
        ProtoConfig {
            name: self.name.clone(),
            mtu: self.mtu,
            gateway: self.gateway.clone(),
            dns: self.dns.clone(),
            user_level: self.user_level,
            auto_system_routing_table: self.auto_system_routing_table.clone(),
            auto_outbounds_interface: self
                .auto_outbounds_interface
                .clone()
                .unwrap_or_default(),
        }
    }
}

/// JSON 字符串数组 → Vec<String>。
fn str_list(arr: &[serde_json::Value], field: &str) -> Result<Vec<String>> {
    arr.iter()
        .map(|x| {
            x.as_str()
                .map(String::from)
                .ok_or_else(|| TunError::InvalidConfig(format!("{field}: expected string array")))
        })
        .collect()
}

/// 解析 duration 值：数字=秒，字符串="30s"/"5m"/"1h"。
fn parse_duration_value(val: &serde_json::Value, field: &str) -> Result<Duration> {
    match val {
        serde_json::Value::Number(n) => {
            let secs = n.as_u64().ok_or_else(|| {
                TunError::InvalidConfig(format!("{field}: not a positive integer"))
            })?;
            Ok(Duration::from_secs(secs))
        }
        serde_json::Value::String(s) => parse_duration_suffix(s, field),
        _ => Err(TunError::InvalidConfig(format!(
            "{field}: expected number or string"
        ))),
    }
}

/// 解析 CIDR（`"10.0.0.1/24"` / `"fd00::1/64"`）→ (addr, prefix)。
///
/// prefix 超界（v4 >32 / v6 >128）或格式非法返回 None。
/// 对应 Go `netip.ParsePrefix`（tun_windows.go:120、tun_darwin.go:248）。
#[must_use]
pub fn parse_ip_cidr(s: &str) -> Option<(std::net::IpAddr, u8)> {
    let (addr, prefix) = s.split_once('/')?;
    let addr: std::net::IpAddr = addr.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (prefix <= max).then_some((addr, prefix))
}

/// 解析带后缀的 duration 字符串（"30s"/"5m"/"1h"/"2h30m"）。
fn parse_duration_suffix(s: &str, field: &str) -> Result<Duration> {
    let mut total_secs: u64 = 0;
    let mut num_buf = String::new();
    for ch in s.chars() {
        match ch {
            '0'..='9' => num_buf.push(ch),
            's' | 'm' | 'h' => {
                let n: u64 = num_buf.parse().map_err(|_| {
                    TunError::InvalidConfig(format!("{field}: bad number in '{s}'"))
                })?;
                let mult = match ch {
                    's' => 1,
                    'm' => 60,
                    _ => 3600,
                };
                total_secs += n * mult;
                num_buf.clear();
            }
            _ => {
                return Err(TunError::InvalidConfig(format!(
                    "{field}: unknown suffix '{ch}' in '{s}'"
                )));
            }
        }
    }
    // 无后缀的尾部数字视为秒
    if !num_buf.is_empty() {
        let n: u64 = num_buf.parse().map_err(|_| {
            TunError::InvalidConfig(format!("{field}: trailing number in '{s}'"))
        })?;
        total_secs += n;
    }
    Ok(Duration::from_secs(total_secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== score 函数 =====

    #[test]
    fn score_wlan_interface_gets_bonus() {
        assert_eq!(score("wlan0", &["192.168.1.100/24"]), 3); // +2 wlan +1 192.168
        assert_eq!(score("WLAN0", &[]), 2); // 大小写不敏感
        assert_eq!(score("Wi-Fi", &[]), 2); // 连字符变体
        assert_eq!(score("wi-fi-adapter", &[]), 2);
    }

    #[test]
    fn score_ethernet_with_192168() {
        assert_eq!(score("eth0", &["192.168.0.5/24"]), 1);
        assert_eq!(score("en0", &["10.0.0.1/8"]), 0); // 非 192.168 不加分
    }

    #[test]
    fn score_no_match_returns_zero() {
        assert_eq!(score("lo", &["127.0.0.1/8"]), 0);
        assert_eq!(score("tun0", &["10.0.0.1/30"]), 0);
    }

    #[test]
    fn score_192168_only_counted_once() {
        // 多个 192.168 地址也只 +1（与 Go break 一致）
        assert_eq!(
            score("eth0", &["192.168.1.1/24", "192.168.2.1/24"]),
            1
        );
    }

    #[test]
    fn score_empty_addrs() {
        assert_eq!(score("wlan0", &[]), 2);
        assert_eq!(score("eth0", &[]), 0);
    }

    // ===== StackOptions =====

    #[test]
    fn stack_options_default_idle_timeout_30s() {
        let opts = StackOptions::default();
        assert_eq!(opts.idle_timeout, Duration::from_secs(30));
        assert!(opts.tun.is_none());
    }

    #[test]
    fn stack_options_custom_idle_timeout() {
        let opts = StackOptions {
            idle_timeout: Duration::from_secs(120),
            ..Default::default()
        };
        assert_eq!(opts.idle_timeout, Duration::from_secs(120));
    }

    // ===== parse_json（Go infra/conf/tun.go 对齐） =====

    #[test]
    fn parse_json_empty_data_returns_defaults() {
        let opts = StackOptions::parse_json(b"").unwrap();
        assert_eq!(opts.name, "xray0"); // Go tun.go:34-36
        assert_eq!(opts.mtu, 1500); // Go tun.go:37-39
        assert_eq!(opts.idle_timeout, Duration::from_secs(30));
        assert!(opts.gateway.is_empty());
        assert!(opts.auto_outbounds_interface.is_none());
    }

    #[test]
    fn parse_json_full_fields() {
        let json = br#"{
            "name": "utun10",
            "mtu": 1280,
            "gateway": ["172.16.0.1/24", "fd00::1/64"],
            "dns": ["1.1.1.1"],
            "userLevel": 2,
            "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
            "autoOutboundsInterface": "eth0",
            "idleTimeout": "2m"
        }"#;
        let opts = StackOptions::parse_json(json).unwrap();
        assert_eq!(opts.name, "utun10");
        assert_eq!(opts.mtu, 1280);
        assert_eq!(opts.gateway, vec!["172.16.0.1/24", "fd00::1/64"]);
        assert_eq!(opts.dns, vec!["1.1.1.1"]);
        assert_eq!(opts.user_level, 2);
        assert_eq!(opts.auto_system_routing_table, vec!["0.0.0.0/0", "::/0"]);
        assert_eq!(opts.auto_outbounds_interface.as_deref(), Some("eth0"));
        assert_eq!(opts.idle_timeout, Duration::from_secs(120));
    }

    #[test]
    fn parse_json_empty_name_and_zero_mtu_normalized() {
        // Go Build()：name==""→xray0、MTU==0→1500（tun.go:34-39）
        let opts = StackOptions::parse_json(br#"{"name":"","mtu":0}"#).unwrap();
        assert_eq!(opts.name, "xray0");
        assert_eq!(opts.mtu, 1500);
    }

    #[test]
    fn parse_json_routing_table_implies_auto_interface() {
        // Go tun.go:30-32：autoSystemRoutingTable 非空且未指定 interface → "auto"
        let opts = StackOptions::parse_json(br#"{"autoSystemRoutingTable":["0.0.0.0/0"]}"#).unwrap();
        assert_eq!(opts.auto_outbounds_interface.as_deref(), Some("auto"));
        // 显式指定则不覆盖
        let opts =
            StackOptions::parse_json(br#"{"autoSystemRoutingTable":["0.0.0.0/0"],"autoOutboundsInterface":"wlan0"}"#)
                .unwrap();
        assert_eq!(opts.auto_outbounds_interface.as_deref(), Some("wlan0"));
    }

    #[test]
    fn parse_json_invalid() {
        assert!(StackOptions::parse_json(b"not json").is_err());
        // mtu 超 u16（设备 MTU 上限 65535）
        assert!(StackOptions::parse_json(br#"{"mtu":70000}"#).is_err());
        // gateway 非字符串数组
        assert!(StackOptions::parse_json(br#"{"gateway":[42]}"#).is_err());
        // idleTimeout 非法后缀
        assert!(StackOptions::parse_json(br#"{"idleTimeout":"3x"}"#).is_err());
    }

    // ===== 设备参数派生 =====

    #[test]
    fn device_ipv4_from_gateway() {
        let opts = StackOptions::parse_json(br#"{"gateway":["172.16.0.1/24","fd00::1/64"]}"#).unwrap();
        let (addr, prefix) = opts.device_ipv4();
        assert_eq!(addr, std::net::Ipv4Addr::new(172, 16, 0, 1));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn device_ipv4_default_without_v4_gateway() {
        for json in ["{}", r#"{"gateway":["fd00::1/64"]}"#] {
            let opts = StackOptions::parse_json(json.as_bytes()).unwrap();
            let (addr, prefix) = opts.device_ipv4();
            assert_eq!(addr, std::net::Ipv4Addr::new(10, 0, 0, 1));
            assert_eq!(prefix, 24);
        }
    }

    #[test]
    fn local_cidrs_all_gateways() {
        let opts = StackOptions::parse_json(br#"{"gateway":["172.16.0.1/24","fd00::1/64"]}"#).unwrap();
        let cidrs = opts.local_cidrs();
        assert_eq!(cidrs.len(), 2);
        assert_eq!(cidrs[0], smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(172, 16, 0, 1)), 24));
        assert_eq!(cidrs[1], smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::new(
                0xfd00, 0, 0, 0, 0, 0, 0, 1)), 64));
    }

    #[test]
    fn local_cidrs_empty_falls_back_to_device_default() {
        let opts = StackOptions::parse_json(b"{}").unwrap();
        let cidrs = opts.local_cidrs();
        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0], smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1)), 24));
    }

    // ===== parse_ip_cidr =====

    #[test]
    fn parse_ip_cidr_valid() {
        let (a4, p4) = parse_ip_cidr("10.1.2.3/24").unwrap();
        assert_eq!(a4, std::net::IpAddr::from(std::net::Ipv4Addr::new(10, 1, 2, 3)));
        assert_eq!(p4, 24);
        let (a6, p6) = parse_ip_cidr("fd00::1/64").unwrap();
        assert_eq!(
            a6,
            std::net::IpAddr::from(std::net::Ipv6Addr::from_segments([
                0xfd00, 0, 0, 0, 0, 0, 0, 1
            ]))
        );
        assert_eq!(p6, 64);
    }

    #[test]
    fn parse_ip_cidr_invalid() {
        assert!(parse_ip_cidr("10.0.0.1").is_none()); // 无前缀
        assert!(parse_ip_cidr("10.0.0.1/33").is_none()); // v4 前缀超界
        assert!(parse_ip_cidr("fd00::1/129").is_none()); // v6 前缀超界
        assert!(parse_ip_cidr("not-an-ip/24").is_none());
        assert!(parse_ip_cidr("10.0.0.1/abc").is_none());
    }

    // ===== trait 声明编译验证 =====

    struct DummyTun;
    impl Tun for DummyTun {
        fn start(&self) -> Result<()> {
            Ok(())
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
        fn name(&self) -> Result<String> {
            Ok("dummy0".into())
        }
        fn index(&self) -> Result<i32> {
            Ok(0)
        }
    }

    #[test]
    fn tun_trait_can_be_implemented() {
        let tun = DummyTun;
        assert_eq!(tun.name().unwrap(), "dummy0");
        assert_eq!(tun.index().unwrap(), 0);
        tun.start().unwrap();
        tun.close().unwrap();
    }

    struct DummyStack;
    impl Stack for DummyStack {
        fn start(&self) -> Result<()> {
            Ok(())
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stack_trait_can_be_implemented() {
        let s = DummyStack;
        s.start().unwrap();
        s.close().unwrap();
    }

    // ===== from_proto/to_proto（bd v5g：proxy.tun.Config 7 字段） =====

    fn full_proto_config() -> ProtoConfig {
        ProtoConfig {
            name: "tun0".into(),
            mtu: 1400,
            gateway: vec!["10.0.0.1/24".into(), "fd00::1/64".into()],
            dns: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            user_level: 1,
            auto_system_routing_table: vec!["60".into()],
            auto_outbounds_interface: "wlan0".into(),
        }
    }

    #[test]
    fn stack_options_proto_roundtrip_all_fields() {
        let p = full_proto_config();
        let opts = StackOptions::from_proto(&p);
        // 字段映射完整性（7 字段逐一断言）
        assert_eq!(opts.name, "tun0");
        assert_eq!(opts.mtu, 1400);
        assert_eq!(opts.gateway, vec!["10.0.0.1/24".to_string(), "fd00::1/64".to_string()]);
        assert_eq!(opts.dns, vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]);
        assert_eq!(opts.user_level, 1);
        assert_eq!(opts.auto_system_routing_table, vec!["60".to_string()]);
        assert_eq!(opts.auto_outbounds_interface.as_deref(), Some("wlan0"));
        // 双向 round-trip（proto 等价断言：StackOptions 含 dyn Tun 不可 derive）
        assert_eq!(opts.to_proto(), StackOptions::from_proto(&opts.to_proto()).to_proto());
    }

    #[test]
    fn from_proto_applies_go_build_defaults() {
        // Go infra/conf/tun.go:30-39：name 空→xray0、mtu 0→1500、
        // routing table 非空且未指定 interface→auto
        let p = ProtoConfig {
            auto_system_routing_table: vec!["60".into()],
            ..ProtoConfig::default()
        };
        let opts = StackOptions::from_proto(&p);
        assert_eq!(opts.name, "xray0");
        assert_eq!(opts.mtu, 1500);
        assert_eq!(opts.auto_outbounds_interface.as_deref(), Some("auto"));
    }

    #[test]
    fn from_proto_none_interface_stays_none_without_routing_table() {
        let opts = StackOptions::from_proto(&ProtoConfig::default());
        assert_eq!(opts.auto_outbounds_interface, None);
        assert_eq!(opts.to_proto().auto_outbounds_interface, "");
    }

    #[test]
    fn json_and_proto_produce_equivalent_options() {
        // JSON（Go infra/conf TunConfig JSON tag）与 proto（Build 产物）
        // 表达同一配置 → 运行时 StackOptions 等价（proto 侧含 Build 归一化）
        let json = br#"{
            "name": "tun0", "mtu": 1400,
            "gateway": ["10.0.0.1/24", "fd00::1/64"],
            "dns": ["1.1.1.1", "8.8.8.8"],
            "userLevel": 1,
            "autoSystemRoutingTable": ["60"],
            "autoOutboundsInterface": "wlan0"
        }"#;
        let from_json = StackOptions::parse_json(json).unwrap();
        let from_proto = StackOptions::from_proto(&full_proto_config());
        assert_eq!(from_json.name, from_proto.name);
        assert_eq!(from_json.mtu, from_proto.mtu);
        assert_eq!(from_json.gateway, from_proto.gateway);
        assert_eq!(from_json.dns, from_proto.dns);
        assert_eq!(from_json.user_level, from_proto.user_level);
        assert_eq!(
            from_json.auto_system_routing_table,
            from_proto.auto_system_routing_table
        );
        assert_eq!(
            from_json.auto_outbounds_interface,
            from_proto.auto_outbounds_interface
        );
    }
}
