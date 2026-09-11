//! WireGuard 协议纯函数——endpoint 解析 + IPC 请求序列化。
//!
//! 对应 Go `proxy/wireguard/wireguard.go` 的 `parseEndpoints` 与 `createIPCRequest`。
//! 这两个函数完全独立可测，不依赖任何网络 IO。

use std::net::IpAddr;

use crate::config::DeviceConfig;
use crate::error::{Result, WgError};

/// `parseEndpoints` 的返回：解析后的 endpoint 列表 + 双栈标志。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEndpoints {
    /// 解析后的 IP 地址列表（与输入顺序一致）。
    pub addrs: Vec<IpAddr>,
    /// 是否含至少一个 IPv4。
    pub has_v4: bool,
    /// 是否含至少一个 IPv6。
    pub has_v6: bool,
}

/// 每个元素可以是：
/// - 纯 IP（如 `"10.0.0.1"`）—— 直接 parse
/// - CIDR（如 `"10.0.0.1/24"`）—— 收敛为地址本体（Go client.go:88-97
///   `netip.ParsePrefix` 宽容接受任意合法掩码后取 `prefix.Addr()`；掩码仅做
///   范围校验 v4 0..=32 / v6 0..=128，bd 7v0k②）
pub fn parse_endpoints(config: &DeviceConfig) -> Result<ParsedEndpoints> {
    let mut addrs = Vec::with_capacity(config.endpoint.len());
    let mut has_v4 = false;
    let mut has_v6 = false;

    for str_addr in &config.endpoint {
        let addr = if str_addr.contains('/') {
            // CIDR 解析：手动 split，避免引入 ipnet/cidr 依赖
            let (addr_str, prefix_str) = str_addr
                .split_once('/')
                .ok_or_else(|| WgError::InvalidEndpoint(str_addr.clone()))?;
            let addr: IpAddr = addr_str
                .parse()
                .map_err(|_| WgError::InvalidEndpoint(str_addr.clone()))?;
            let prefix_len: u32 = prefix_str
                .parse()
                .map_err(|_| WgError::InvalidEndpoint(str_addr.clone()))?;
            // 掩码范围校验（wg-quick 习惯写法 10.0.0.2/24 收敛为地址本体）
            let max_bits = if addr.is_ipv4() { 32 } else { 128 };
            if prefix_len > max_bits {
                return Err(WgError::InvalidSubnetMask(str_addr.clone()));
            }
            addr
        } else {
            str_addr
                .parse::<IpAddr>()
                .map_err(|_| WgError::InvalidEndpoint(str_addr.clone()))?
        };
        if addr.is_ipv4() {
            has_v4 = true;
        } else {
            has_v6 = true;
        }
        addrs.push(addr);
    }

    Ok(ParsedEndpoints {
        addrs,
        has_v4,
        has_v6,
    })
}

/// 服务端 listen_port 占位常量（与 Go 一致，实际端口由 Xray listener 控制）。
///
/// Go 端注释："placeholder, we'll handle actual port listening on Xray"。
pub const SERVER_LISTEN_PORT_PLACEHOLDER: u32 = 1337;

/// 把 `DeviceConfig` 序列化为 WireGuard IPC 请求字符串。
///
/// 格式（每行 `key=value\n`）：
/// ```text
/// private_key=<hex>
/// listen_port=1337              # 仅服务端，占位
/// public_key=<hex>              # 每个 peer
/// preshared_key=<hex>           # peer 可选
/// endpoint=<host:port>          # peer 可选
/// allowed_ip=<cidr>             # peer 可多个
/// persistent_keepalive_interval=N  # peer 可选，N!=0 才输出
/// ```
///
/// 对应 Go `createIPCRequest`。boringtun/wireguard-rs 通过 IPC API 接收此字符串配置设备。
#[must_use]
pub fn create_ipc_request(config: &DeviceConfig) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("private_key=");
    out.push_str(&config.secret_key);
    out.push('\n');

    if !config.is_client {
        // 服务端：占位 listen_port，实际监听由 Xray listener 处理。
        out.push_str(&format!(
            "listen_port={}\n",
            SERVER_LISTEN_PORT_PLACEHOLDER
        ));
    }

    for peer in &config.peers {
        if !peer.public_key.is_empty() {
            out.push_str("public_key=");
            out.push_str(&peer.public_key);
            out.push('\n');
        }

        if !peer.pre_shared_key.is_empty() {
            out.push_str("preshared_key=");
            out.push_str(&peer.pre_shared_key);
            out.push('\n');
        }

        if !peer.endpoint.is_empty() {
            out.push_str("endpoint=");
            out.push_str(&peer.endpoint);
            out.push('\n');
        }

        for ip in &peer.allowed_ips {
            out.push_str("allowed_ip=");
            out.push_str(ip);
            out.push('\n');
        }

        if peer.keep_alive != 0 {
            out.push_str(&format!(
                "persistent_keepalive_interval={}\n",
                peer.keep_alive
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PeerConfig;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn make_config(endpoints: &[&str]) -> DeviceConfig {
        DeviceConfig {
            endpoint: endpoints.iter().map(|s| (*s).to_string()).collect(),
            ..Default::default()
        }
    }

    // ===== parse_endpoints =====

    #[test]
    fn parse_plain_ipv4() {
        let cfg = make_config(&["10.0.0.1"]);
        let parsed = parse_endpoints(&cfg).unwrap();
        assert_eq!(parsed.addrs.len(), 1);
        assert_eq!(
            parsed.addrs[0],
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert!(parsed.has_v4);
        assert!(!parsed.has_v6);
    }

    #[test]
    fn parse_plain_ipv6() {
        let cfg = make_config(&["fd00::1"]);
        let parsed = parse_endpoints(&cfg).unwrap();
        assert_eq!(parsed.addrs.len(), 1);
        assert_eq!(
            parsed.addrs[0],
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
        );
        assert!(!parsed.has_v4);
        assert!(parsed.has_v6);
    }

    #[test]
    fn parse_cidr_v4_correct_mask() {
        let cfg = make_config(&["10.0.0.1/32"]);
        let parsed = parse_endpoints(&cfg).unwrap();
        assert!(parsed.has_v4);
        assert_eq!(
            parsed.addrs[0],
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn parse_cidr_v6_correct_mask() {
        let cfg = make_config(&["fd00::1/128"]);
        let parsed = parse_endpoints(&cfg).unwrap();
        assert!(parsed.has_v6);
    }

    #[test]
    fn parse_cidr_wide_mask_converges_to_host_addr() {
        // bd 7v0k②：wg-quick 习惯写法 10.0.0.2/24 Go 起 Rust 拒——现宽容收敛
        let cfg = make_config(&["10.0.0.2/24", "fd00::1/64"]);
        let parsed = parse_endpoints(&cfg).unwrap();
        assert_eq!(parsed.addrs[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(
            parsed.addrs[1],
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
        );
        assert!(parsed.has_v4);
        assert!(parsed.has_v6);
    }

    #[test]
    fn parse_cidr_out_of_range_mask_rejected() {
        let cfg = make_config(&["10.0.0.1/33"]);
        let err = parse_endpoints(&cfg).unwrap_err();
        assert!(matches!(err, WgError::InvalidSubnetMask(_)));
        let cfg = make_config(&["fd00::1/129"]);
        let err = parse_endpoints(&cfg).unwrap_err();
        assert!(matches!(err, WgError::InvalidSubnetMask(_)));
    }

    #[test]
    fn parse_invalid_string_rejected() {
        let cfg = make_config(&["not-an-ip"]);
        let err = parse_endpoints(&cfg).unwrap_err();
        assert!(matches!(err, WgError::InvalidEndpoint(_)));
    }

    #[test]
    fn parse_dual_stack_detected() {
        let cfg = make_config(&["10.0.0.1/32", "fd00::1/128"]);
        let parsed = parse_endpoints(&cfg).unwrap();
        assert!(parsed.has_v4);
        assert!(parsed.has_v6);
        assert_eq!(parsed.addrs.len(), 2);
    }

    #[test]
    fn parse_empty_endpoints() {
        let cfg = DeviceConfig::default();
        let parsed = parse_endpoints(&cfg).unwrap();
        assert!(parsed.addrs.is_empty());
        assert!(!parsed.has_v4);
        assert!(!parsed.has_v6);
    }

    // ===== create_ipc_request =====

    #[test]
    fn ipc_request_client_basic() {
        let cfg = DeviceConfig {
            secret_key: "aabb".repeat(16), // 32 字节 hex
            is_client: true,
            ..Default::default()
        };
        let ipc = create_ipc_request(&cfg);
        assert!(ipc.starts_with("private_key=aabb"));
        assert!(!ipc.contains("listen_port")); // 客户端不含
        assert!(ipc.ends_with('\n'));
    }

    #[test]
    fn ipc_request_server_has_listen_port() {
        let cfg = DeviceConfig {
            secret_key: "abcd".repeat(16),
            is_client: false,
            ..Default::default()
        };
        let ipc = create_ipc_request(&cfg);
        assert!(ipc.contains("listen_port=1337"));
    }

    #[test]
    fn ipc_request_includes_peer_fields() {
        let cfg = DeviceConfig {
            secret_key: "00".repeat(16),
            is_client: true,
            peers: vec![PeerConfig {
                public_key: "11".repeat(16),
                pre_shared_key: "22".repeat(16),
                endpoint: "1.2.3.4:51820".into(),
                keep_alive: 25,
                allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
                level: 0,
                email: String::new(),
            }],
            ..Default::default()
        };
        let ipc = create_ipc_request(&cfg);
        assert!(ipc.contains("public_key=1111"));
        assert!(ipc.contains("preshared_key=2222"));
        assert!(ipc.contains("endpoint=1.2.3.4:51820"));
        assert!(ipc.contains("allowed_ip=0.0.0.0/0"));
        assert!(ipc.contains("allowed_ip=::/0"));
        assert!(ipc.contains("persistent_keepalive_interval=25"));
    }

    #[test]
    fn ipc_request_skips_empty_optional_fields() {
        let cfg = DeviceConfig {
            secret_key: "ab".repeat(16),
            is_client: true,
            peers: vec![PeerConfig {
                public_key: String::new(),    // 空，跳过
                pre_shared_key: String::new(), // 空，跳过
                endpoint: String::new(),       // 空，跳过
                keep_alive: 0,                 // 0，跳过
                allowed_ips: vec![],
                level: 0,
                email: String::new(),
            }],
            ..Default::default()
        };
        let ipc = create_ipc_request(&cfg);
        assert!(!ipc.contains("public_key"));
        assert!(!ipc.contains("preshared_key"));
        assert!(!ipc.contains("endpoint="));
        assert!(!ipc.contains("allowed_ip"));
        assert!(!ipc.contains("persistent_keepalive"));
    }

    #[test]
    fn ipc_request_multiple_peers() {
        let cfg = DeviceConfig {
            secret_key: "00".repeat(16),
            is_client: true,
            peers: vec![
                PeerConfig {
                    public_key: "aa".repeat(16),
                    endpoint: "1.1.1.1:51820".into(),
                    ..Default::default()
                },
                PeerConfig {
                    public_key: "bb".repeat(16),
                    endpoint: "2.2.2.2:51820".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let ipc = create_ipc_request(&cfg);
        assert_eq!(ipc.matches("public_key=").count(), 2);
        assert_eq!(ipc.matches("endpoint=").count(), 2);
    }

    #[test]
    fn ipc_request_format_key_value_newline() {
        // 每行必须是 key=value\n 格式
        let cfg = DeviceConfig {
            secret_key: "abcd".repeat(16),
            is_client: true,
            ..Default::default()
        };
        let ipc = create_ipc_request(&cfg);
        for line in ipc.lines() {
            assert!(
                line.contains('='),
                "line without '=': {line:?}"
            );
        }
    }

    #[test]
    fn listen_port_constant_matches_go() {
        // Go 端硬编码 1337
        assert_eq!(SERVER_LISTEN_PORT_PLACEHOLDER, 1337);
    }
}
