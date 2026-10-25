//! # UPnP IGD / NAT-PMP 端口映射客户端（对应 Go `realm/portmap.go`，go-nat 等价面）
//!
//! realm 是 UDP 打洞方案，NAT 不给面子时需要网关替我们把本地 UDP 端口映射到公网：
//!
//! - 后端 A [`natpmp`]：RFC 6886（UDP 5351），**优先**——报文最小、无 XML；
//! - 后端 B [`upnp`]：SSDP 发现 + device description + SOAP，NAT-PMP 不可用时回退。
//!
//! 语义对齐 Go：
//! - 缺省 timeout 10s / lifetime 10min；0 = 缺省，负数 = 配置错误（`from_secs`）；
//! - [`PortMapper::new`] = 发现网关 + 立即建一次映射（发现或首映射失败 → `Err`）；
//! - [`PortMapper::renew`] 返回「外部地址是否变化」；[`PortMapper::close`] 删映射；
//! - [`port_map_loop`] = 续租循环，interval = lifetime/2，退出前删映射。
//!
//! 失败路径全部 fail-visible：找不到网关 / 网关拒绝（结果码/UPnPError 原文）/
//! 超时都带原因返回，调用方（realm conn）记 warn 但**不中断连接**（Go 同款）。

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;

pub mod natpmp;
pub mod upnp;

#[cfg(test)]
mod test_support;

/// 缺省网关操作超时（Go `defaultPortMapTimeout`）。
pub const DEFAULT_PORT_MAP_TIMEOUT: Duration = Duration::from_secs(10);
/// 缺省映射租期（Go `defaultPortMapLifetime`）。
pub const DEFAULT_PORT_MAP_LIFETIME: Duration = Duration::from_secs(600);

/// JSON `portMapping` 段（Go `realm.PortMapping` proto：enabled/timeout/lifetime）。
///
/// `timeout_secs`/`lifetime_secs` 为秒（proto int64 语义）；0 = 用缺省值。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PortMapping {
    pub enabled: bool,
    pub timeout_secs: i64,
    pub lifetime_secs: i64,
}

/// 已归一化的端口映射参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMapConfig {
    pub timeout: Duration,
    pub lifetime: Duration,
}

impl PortMapConfig {
    /// Go `PortMapConfig.withDefaults`：0 → 缺省，负数 → 错误。
    pub fn from_secs(timeout_secs: i64, lifetime_secs: i64) -> io::Result<Self> {
        if timeout_secs < 0 {
            return Err(invalid_input("port mapping: timeout must not be negative"));
        }
        if lifetime_secs < 0 {
            return Err(invalid_input("port mapping: lifetime must not be negative"));
        }
        Ok(Self {
            timeout: if timeout_secs == 0 {
                DEFAULT_PORT_MAP_TIMEOUT
            } else {
                Duration::from_secs(timeout_secs.unsigned_abs())
            },
            lifetime: if lifetime_secs == 0 {
                DEFAULT_PORT_MAP_LIFETIME
            } else {
                Duration::from_secs(lifetime_secs.unsigned_abs())
            },
        })
    }
}

/// 端口映射后端。
enum Gateway {
    NatPmp(natpmp::Client),
    Upnp(upnp::Client),
}

impl Gateway {
    fn kind(&self) -> &'static str {
        match self {
            Self::NatPmp(_) => "NAT-PMP",
            Self::Upnp(_) => "UPnP",
        }
    }
}

/// 发现端点（生产 = 系统默认网关 + SSDP 组播；单测注入本地 stub）。
#[derive(Debug, Clone)]
pub(crate) struct Endpoints {
    natpmp: Result<SocketAddrV4, String>,
    ssdp: SocketAddrV4,
}

impl Endpoints {
    pub(crate) fn system() -> Self {
        Self {
            natpmp: default_ipv4_gateway()
                .map(|gateway| SocketAddrV4::new(gateway, natpmp::NATPMP_PORT))
                .map_err(|e| format!("{e}")),
            ssdp: upnp::SSDP_ADDR,
        }
    }
}

/// 网关端口映射（一次发现后常驻；不自己续租，调用方按 [`port_map_loop`] 续租）。
pub struct PortMapper {
    gateway: Gateway,
    internal_port: u16,
    config: PortMapConfig,
    external: Mutex<Option<SocketAddr>>,
}

impl PortMapper {
    /// 发现网关并立刻建立一次 UDP 映射（Go `NewPortMapper`）。
    pub async fn new(internal_port: u16, config: PortMapConfig) -> io::Result<Self> {
        Self::new_with(internal_port, config, Endpoints::system()).await
    }

    pub(crate) async fn new_with(
        internal_port: u16,
        config: PortMapConfig,
        endpoints: Endpoints,
    ) -> io::Result<Self> {
        if internal_port == 0 {
            return Err(invalid_input("port mapping: internal port must not be zero"));
        }
        // 1) NAT-PMP 优先
        let natpmp_reason = match &endpoints.natpmp {
            Ok(server) => match discover_natpmp(*server, &config).await {
                Ok(client) => {
                    return Self::finish(Gateway::NatPmp(client), internal_port, config).await;
                },
                Err(e) => format!("NAT-PMP {server}: {e}"),
            },
            Err(reason) => format!("NAT-PMP: {reason}"),
        };
        // 2) UPnP 回退；两路都失败 → 一条错误带两边原因
        let upnp = upnp::Client::discover(endpoints.ssdp, config.timeout).await.map_err(|e| {
            io::Error::other(format!(
                "port mapping: no usable gateway ({natpmp_reason}; UPnP: {e})"
            ))
        })?;
        Self::finish(Gateway::Upnp(upnp), internal_port, config).await
    }

    /// 网关选定后建一次映射（Go `NewPortMapper` 里的 `Renew`）。
    async fn finish(
        gateway: Gateway,
        internal_port: u16,
        config: PortMapConfig,
    ) -> io::Result<Self> {
        let mapper = Self { gateway, internal_port, config, external: Mutex::new(None) };
        mapper.renew().await?;
        Ok(mapper)
    }

    /// 重新请求映射并刷新外部地址；返回外部地址是否变化。
    pub async fn renew(&self) -> io::Result<bool> {
        let lifetime_secs = u32::try_from(self.config.lifetime.as_secs()).map_err(|_| {
            invalid_input(format!(
                "port mapping: lifetime {:?} exceeds the 32-bit seconds field",
                self.config.lifetime
            ))
        })?;
        let external =
            match &self.gateway {
                Gateway::NatPmp(client) => {
                    let mapping = client
                        .add_udp_mapping(self.internal_port, self.internal_port, lifetime_secs)
                        .await
                        .map_err(|e| io::Error::other(format!("add port mapping failed: {e}")))?;
                    let ip = client.external_address().await.map_err(|e| {
                        io::Error::other(format!("get external address failed: {e}"))
                    })?;
                    usable_external(IpAddr::V4(ip), mapping.external_port)?
                },
                Gateway::Upnp(client) => {
                    let external_port = client
                        .add_udp_mapping(self.internal_port, lifetime_secs)
                        .await
                        .map_err(|e| io::Error::other(format!("add port mapping failed: {e}")))?;
                    let ip = client.get_external_address().await.map_err(|e| {
                        io::Error::other(format!("get external address failed: {e}"))
                    })?;
                    usable_external(IpAddr::V4(ip), external_port)?
                },
            };
        let mut guard = self.external.lock();
        let changed = guard.as_ref() != Some(&external);
        *guard = Some(external);
        Ok(changed)
    }

    /// 网关报告的外部地址（首次 `renew` 成功前为 `None`）。
    pub fn external_addr(&self) -> Option<SocketAddr> {
        *self.external.lock()
    }

    pub fn internal_port(&self) -> u16 {
        self.internal_port
    }

    pub fn lifetime(&self) -> Duration {
        self.config.lifetime
    }

    /// 后端类型（"NAT-PMP" / "UPnP"，Go `GatewayType`）。
    pub fn gateway_type(&self) -> &'static str {
        self.gateway.kind()
    }

    /// 删除映射（best-effort，错误照常上抛给调用方记录）。
    pub async fn close(&self) -> io::Result<()> {
        let external_port = self.external.lock().map_or(self.internal_port, |addr| addr.port());
        match &self.gateway {
            Gateway::NatPmp(client) => {
                client.delete_udp_mapping(self.internal_port, external_port).await.map(|_| ())
            },
            Gateway::Upnp(client) => client.delete_udp_mapping(external_port).await,
        }
    }
}

/// 续租循环（Go `portMapLoop`）：interval = lifetime/2，缺省退 1min；
/// 失败只记一次 warn、恢复记一次 warn；退出前删映射。
pub async fn port_map_loop(mapper: &PortMapper, cancel: &Arc<AtomicBool>) {
    let half = mapper.lifetime() / 2;
    let interval = if half.is_zero() { Duration::from_secs(60) } else { half };
    let mut ticker = tokio::time::interval(interval);
    // 不补发：卡顿后不连发追赶（udf scheduler 同姿态）
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut failing = false;
    loop {
        tokio::select! {
            _ = ticker.tick() => {},
            () = wait_cancelled(cancel) => break,
        }
        match mapper.renew().await {
            Ok(changed) => {
                if failing {
                    crate::LOG.warn(format!(
                        "[realm] [port mapping] [{}] renewal recovered",
                        mapper.internal_port()
                    ));
                    failing = false;
                }
                crate::LOG.debug(format!(
                    "[realm] [port mapping] [{}] external {:?}, changed {changed}",
                    mapper.internal_port(),
                    mapper.external_addr()
                ));
            },
            Err(e) => {
                if cancel.load(Ordering::Acquire) {
                    break;
                }
                if !failing {
                    crate::LOG.warn(format!(
                        "[realm] [port mapping] [{}] renewal failed: {e}",
                        mapper.internal_port()
                    ));
                    failing = true;
                }
            },
        }
    }
    match mapper.close().await {
        Ok(()) => crate::LOG
            .debug(format!("[realm] [port mapping] [{}] mapping removed", mapper.internal_port())),
        Err(e) => crate::LOG.warn(format!(
            "[realm] [port mapping] [{}] remove failed: {e}",
            mapper.internal_port()
        )),
    };
}

/// 挂起直到 cancel 置位（100ms 轮询；调用方只关心「停机快于一个租期」）。
async fn wait_cancelled(cancel: &Arc<AtomicBool>) {
    while !cancel.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn discover_natpmp(
    server: SocketAddrV4,
    config: &PortMapConfig,
) -> io::Result<natpmp::Client> {
    let client = natpmp::Client::connect(server, config.timeout).await?;
    // 公网地址请求兼作「网关确实说 NAT-PMP」探针（Go DiscoverGateway 同判据）
    client.external_address().await?;
    Ok(client)
}

/// Go `Renew` 的外部地址校验：unspecified/loopback = 网关答复不可用。
fn usable_external(ip: IpAddr, port: u16) -> io::Result<SocketAddr> {
    if ip.is_unspecified() || ip.is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("gateway returned unusable external address: {ip}"),
        ));
    }
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway returned unusable external port 0",
        ));
    }
    Ok(SocketAddr::new(ip, port))
}

fn invalid_input(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

/// 默认 IPv4 网关（NAT-PMP 必须发往网关，RFC 6886 §3）。
///
/// Linux 读 `/proc/net/route`；Windows 走 `GetIpForwardTable`；其余平台显式
/// `Unsupported`（调用方回退 UPnP，不静默）。
#[cfg(target_os = "linux")]
fn default_ipv4_gateway() -> io::Result<Ipv4Addr> {
    let table = std::fs::read_to_string("/proc/net/route")?;
    parse_proc_net_route(&table).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "no IPv4 default route in /proc/net/route")
    })
}

#[cfg(windows)]
fn default_ipv4_gateway() -> io::Result<Ipv4Addr> {
    windows_route::default_gateway()
}

#[cfg(not(any(target_os = "linux", windows)))]
fn default_ipv4_gateway() -> io::Result<Ipv4Addr> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "default IPv4 gateway lookup is not implemented for this platform",
    ))
}

/// `/proc/net/route` 里的默认路由网关（最 metric 小者）。
///
/// 行格式（表头之外）：`Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT`，
/// Destination/Mask/Gateway 为 16 进制、**主机字节序**（小端）。
#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_route(table: &str) -> Option<Ipv4Addr> {
    let mut best: Option<(u32, Ipv4Addr)> = None;
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[1] != "00000000" {
            continue;
        }
        let gateway = u32::from_str_radix(fields[2], 16).ok()?;
        let metric = fields[6].parse::<u32>().ok()?;
        let addr = Ipv4Addr::from(gateway.to_le_bytes());
        if addr.is_unspecified() {
            continue;
        }
        if best.is_none_or(|(best_metric, _)| metric < best_metric) {
            best = Some((metric, addr));
        }
    }
    best.map(|(_, addr)| addr)
}

#[cfg(windows)]
mod windows_route {
    use std::{io, mem::size_of, net::Ipv4Addr};

    use windows_sys::Win32::{
        Foundation::NO_ERROR,
        NetworkManagement::IpHelper::{GetIpForwardTable, MIB_IPFORWARDROW, MIB_IPFORWARDTABLE},
    };

    /// `GetIpForwardTable` 里 dwForwardDest/dwForwardMask 全 0 = 默认路由。
    pub(super) fn default_gateway() -> io::Result<Ipv4Addr> {
        let row_size = size_of::<MIB_IPFORWARDROW>();
        let mut size: u32 = 0;
        // 首次调用只探所需缓冲大小（表 = 头部 dwNumEntries + rows）
        let probe = unsafe { GetIpForwardTable(std::ptr::null_mut(), &mut size, 0) };
        if probe != NO_ERROR && size == 0 {
            return Err(io::Error::other(format!("GetIpForwardTable size probe failed: {probe}")));
        }
        let mut buf = vec![0u32; size as usize / size_of::<u32>() + row_size / size_of::<u32>()];
        let ret = unsafe {
            GetIpForwardTable(buf.as_mut_ptr().cast::<MIB_IPFORWARDTABLE>(), &mut size, 0)
        };
        if ret != NO_ERROR {
            return Err(io::Error::other(format!("GetIpForwardTable failed: {ret}")));
        }
        let header = unsafe { &*buf.as_ptr().cast::<MIB_IPFORWARDTABLE>() };
        let max_rows = (buf.len() * size_of::<u32>() - size_of::<u32>()) / row_size;
        let rows = unsafe {
            std::slice::from_raw_parts(
                header.table.as_ptr(),
                (header.dwNumEntries as usize).min(max_rows),
            )
        };
        let mut best: Option<(u32, Ipv4Addr)> = None;
        for row in rows {
            if row.dwForwardDest != 0 || row.dwForwardMask != 0 {
                continue;
            }
            // dwForwardNextHop 是网络字节序，按内存顺序还原
            let gateway = Ipv4Addr::from(row.dwForwardNextHop.to_ne_bytes());
            if gateway.is_unspecified() || gateway.is_loopback() {
                continue;
            }
            if best.is_none_or(|(metric, _)| row.dwForwardMetric1 < metric) {
                best = Some((row.dwForwardMetric1, gateway));
            }
        }
        best.map(|(_, gateway)| gateway).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no IPv4 default route in the forward table")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalmask::realm::portmap::test_support::{
        DESCRIPTION_XML, HttpStub, NatPmpStub, SsdpStub,
    };

    /// 网关响应报文（op 同 natpmp 私有编码）。
    fn natpmp_response(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8, opcode | 0x80, 0, 0];
        packet.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    /// 一个「正常」NAT-PMP 网关：op0 → 公网 IP；op1 → 回填 internal + 请求 lifetime。
    fn natpmp_responder(req: &[u8]) -> Option<Vec<u8>> {
        match req[1] {
            0 => Some(natpmp_response(0, &[203, 0, 113, 77])),
            1 => {
                let mut payload = vec![req[8], req[9], req[10], req[11]];
                payload.extend_from_slice(&req[12..16]);
                Some(natpmp_response(1, &payload))
            },
            _ => None,
        }
    }

    /// 死端点（绑定后立刻释放：后续请求得到 ICMP 不可达/无应答）。
    async fn dead_udp_addr() -> SocketAddrV4 {
        let sock = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind");
        match sock.local_addr().expect("addr") {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => unreachable!("v4 bind"),
        }
    }

    async fn upnp_http_stub() -> HttpStub {
        HttpStub::spawn(|req| match req.path.as_str() {
            "/rootDesc.xml" => (200, DESCRIPTION_XML.to_string()),
            "/ctl/IPConn" => {
                let action = req.header("SOAPAction").unwrap_or_default();
                if action.contains("GetExternalIPAddress") {
                    (
                        200,
                        "<r><NewExternalIPAddress>198.51.100.5</NewExternalIPAddress></r>"
                            .to_string(),
                    )
                } else {
                    (200, "<r/>".to_string())
                }
            },
            _ => (404, "<nope/>".to_string()),
        })
        .await
    }

    #[test]
    fn config_from_secs_zero_uses_defaults_and_negative_rejects() {
        let defaults = PortMapConfig::from_secs(0, 0).expect("defaults");
        assert_eq!(defaults.timeout, DEFAULT_PORT_MAP_TIMEOUT);
        assert_eq!(defaults.lifetime, DEFAULT_PORT_MAP_LIFETIME);
        assert!(PortMapConfig::from_secs(-1, 0).is_err());
        assert!(PortMapConfig::from_secs(0, -1).is_err());
        assert_eq!(
            PortMapConfig::from_secs(3, 7).expect("explicit"),
            PortMapConfig { timeout: Duration::from_secs(3), lifetime: Duration::from_secs(7) }
        );
    }

    #[test]
    fn proc_net_route_picks_lowest_metric_default_route() {
        let table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
wlan0\t00000000\t0102A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
";
        // 0101A8C0 小端 = 192.168.1.1（metric 100 胜过 600）
        assert_eq!(parse_proc_net_route(table), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(parse_proc_net_route("Iface\tDestination\n"), None);
        // 无默认路由（只有具体网段）
        let no_default = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\neth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(parse_proc_net_route(no_default), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mapper_prefers_natpmp_when_gateway_answers() {
        let stub = NatPmpStub::spawn(natpmp_responder).await;
        let endpoints = Endpoints {
            natpmp: Ok(stub.addr),
            // SSDP 指向死端点：一旦回退到这里就会失败，从而证明走的是 NAT-PMP
            ssdp: dead_udp_addr().await,
        };
        let mapper =
            PortMapper::new_with(8080, PortMapConfig::from_secs(1, 600).expect("cfg"), endpoints)
                .await
                .expect("mapper");
        assert_eq!(mapper.gateway_type(), "NAT-PMP");
        assert_eq!(mapper.internal_port(), 8080);
        assert_eq!(mapper.external_addr(), Some("203.0.113.77:8080".parse().expect("addr")));

        // renew：网关回同样外部地址 → changed = false
        assert!(!mapper.renew().await.expect("renew"));
        mapper.close().await.expect("close");

        let requests = stub.requests();
        // op0 探针 + 首映射 + 一次 renew 映射 + 删除 + 每次 renew 后的 op0
        assert!(requests.len() >= 4, "requests: {requests:?}");
        let adds: Vec<&Vec<u8>> = requests.iter().filter(|r| r[1] == 1).collect();
        assert_eq!(
            u32::from_be_bytes([adds[0][12], adds[0][13], adds[0][14], adds[0][15]]),
            600,
            "first mapping must carry configured lifetime"
        );
        let last = adds.last().expect("delete request");
        assert_eq!(
            u32::from_be_bytes([last[12], last[13], last[14], last[15]]),
            0,
            "close must send lifetime 0"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mapper_detects_external_address_change() {
        // 前两次 op0（发现探针 + 首映射后的查询）→ ...77；其后 → ...78
        let probes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&probes);
        let stub = NatPmpStub::spawn(move |req| {
            if req[1] == 1 {
                let mut payload = vec![req[8], req[9], req[10], req[11]];
                payload.extend_from_slice(&req[12..16]);
                return Some(natpmp_response(1, &payload));
            }
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let ip: [u8; 4] = if n < 2 { [203, 0, 113, 77] } else { [203, 0, 113, 78] };
            Some(natpmp_response(0, &ip))
        })
        .await;
        let endpoints = Endpoints { natpmp: Ok(stub.addr), ssdp: dead_udp_addr().await };
        let mapper =
            PortMapper::new_with(9000, PortMapConfig::from_secs(1, 600).expect("cfg"), endpoints)
                .await
                .expect("mapper");
        assert_eq!(mapper.external_addr(), Some("203.0.113.77:9000".parse().expect("addr")));
        assert!(mapper.renew().await.expect("renew"), "external address changed → true");
        assert_eq!(mapper.external_addr(), Some("203.0.113.78:9000".parse().expect("addr")));
        assert!(!mapper.renew().await.expect("renew"), "unchanged → false");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mapper_falls_back_to_upnp_when_natpmp_silent() {
        let http = upnp_http_stub().await;
        let ssdp = SsdpStub::spawn(format!("http://{}/rootDesc.xml", http.addr)).await;
        let endpoints = Endpoints { natpmp: Ok(dead_udp_addr().await), ssdp: ssdp.addr };
        let mapper =
            PortMapper::new_with(8080, PortMapConfig::from_secs(1, 600).expect("cfg"), endpoints)
                .await
                .expect("mapper");
        assert_eq!(mapper.gateway_type(), "UPnP");
        assert_eq!(mapper.external_addr(), Some("198.51.100.5:8080".parse().expect("addr")));
        // UPnP 添加映射请求带 600s 租期
        let add = http
            .requests()
            .into_iter()
            .find(|r| r.header("SOAPAction").unwrap_or_default().contains("AddPortMapping"))
            .expect("add request");
        assert!(add.body.contains("<NewLeaseDuration>600</NewLeaseDuration>"), "{}", add.body);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mapper_no_gateway_is_fail_visible() {
        let ssdp = dead_udp_addr().await;
        let endpoints = Endpoints { natpmp: Ok(ssdp), ssdp };
        let err =
            PortMapper::new_with(8080, PortMapConfig::from_secs(1, 600).expect("cfg"), endpoints)
                .await
                .err()
                .expect("no gateway must fail");
        let msg = err.to_string();
        assert!(msg.contains("no usable gateway"), "{msg}");
        assert!(msg.contains("NAT-PMP"), "{msg}");
        assert!(msg.contains("UPnP"), "{msg}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn renew_loop_renews_then_deletes_on_cancel() {
        let stub = NatPmpStub::spawn(natpmp_responder).await;
        let endpoints = Endpoints { natpmp: Ok(stub.addr), ssdp: dead_udp_addr().await };
        // lifetime 1s → 续租间隔 500ms
        let mapper =
            PortMapper::new_with(8080, PortMapConfig::from_secs(1, 1).expect("cfg"), endpoints)
                .await
                .expect("mapper");
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_loop = Arc::clone(&cancel);
        let handle = tokio::spawn(async move {
            port_map_loop(&mapper, &cancel_loop).await;
        });
        // 等至少两次续租（500ms 间隔）
        tokio::time::sleep(Duration::from_millis(1_300)).await;
        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("loop exits")
            .expect("join");

        let requests = stub.requests();
        let adds: Vec<&Vec<u8>> = requests.iter().filter(|r| r[1] == 1).collect();
        let renewals =
            adds.iter().filter(|r| u32::from_be_bytes([r[12], r[13], r[14], r[15]]) == 1).count();
        assert!(renewals >= 3, "init + ≥2 renewals, saw {renewals} adds: {adds:?}");
        let delete = adds.last().expect("delete request");
        assert_eq!(
            u32::from_be_bytes([delete[12], delete[13], delete[14], delete[15]]),
            0,
            "loop exit must delete the mapping"
        );
    }

    /// 真机探针（默认 `#[ignore]`，只读：不建映射、不改网关状态）。
    /// 跑法：`cargo test -p xray-transport --lib -- real_gateway_probe --ignored --nocapture`
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "touches the host network (read-only probes)"]
    #[allow(clippy::print_stdout)] // 真机取证输出（--nocapture 人眼核对）
    async fn real_gateway_probe() {
        match default_ipv4_gateway() {
            Ok(gateway) => {
                println!("default IPv4 gateway = {gateway}");
                let server = SocketAddrV4::new(gateway, natpmp::NATPMP_PORT);
                match natpmp::Client::connect(server, Duration::from_secs(2)).await {
                    Ok(client) => match client.external_address().await {
                        Ok(ip) => println!("NAT-PMP {server} external address = {ip}"),
                        Err(e) => println!("NAT-PMP {server} no answer: {e}"),
                    },
                    Err(e) => println!("NAT-PMP {server} connect failed: {e}"),
                }
            },
            Err(e) => println!("default IPv4 gateway unavailable: {e}"),
        }
        match upnp::Client::discover(upnp::SSDP_ADDR, Duration::from_secs(3)).await {
            Ok(_) => println!("UPnP IGD discovered at {}", upnp::SSDP_ADDR),
            Err(e) => println!("UPnP discovery failed: {e}"),
        }
    }
}
