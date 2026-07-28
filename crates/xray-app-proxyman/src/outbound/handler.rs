//! 出站 handler 实现
//!
//! 对应 Go `app/proxyman/outbound/handler.go` 与 `app/proxyman/outbound/uot.go`。
//!
//! ## 当前实现范围
//!
//! 业务核心（独立可测）：
//! - [`OutboundHandlerEntry`] — Go `Handler struct`：配置载体（tag / sender / proxy_type_url /
//!   mux 启用 / xudp 启用 / UDP 443 策略 / 流量计数器）
//! - [`parse_random_ip`] — Go `ParseRandomIP`：CIDR 子网内随机 IP（纯函数）
//! - [`get_uo_t_connection`] — Go `getUoTConnection`：UoT (UDP over TCP) 连接
//!
//! IO 边界（trait + TODO 占位）：
//! - `dispatch` — 依赖 `transport.Link` + 代理 + mux + xudp + DNS LookupForIP
//! - `dial` — 依赖 transport Dialer + TLS Client + UoT

use crate::error::ProxymanError;
use crate::inbound::PinFuture;
use crate::outbound::OutboundHandler;
use crate::stats::{Counter, StatsProvider, outbound_downlink_name, outbound_uplink_name};
use ipnet::IpNet;
use rand::Rng;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use xray_proto::xray::app::proxyman::{MultiplexingConfig, SenderConfig};

// ── UoT 常量 ──────────────────────────────────────────────────

/// UoT v1 魔术域名（对应 Go `uot.MagicAddress`）。
const UOT_MAGIC_ADDRESS: &str = "UoT";

/// UoT Legacy 魔术域名（对应 Go `uot.LegacyMagicAddress`）。
const UOT_LEGACY_MAGIC_ADDRESS: &str = "UoTL";

/// UoT 版本。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UotVersion {
    /// 当前版本（MagicAddress）。
    Current,
    /// 旧版（LegacyMagicAddress）。
    Legacy,
}

/// XUDP 对 UDP 443 流量的处理策略（对应 Go `string` 字面量 `"reject" / "allow" / "skip"`）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Udp443Policy {
    /// 拒绝（默认）
    #[default]
    Reject,
    /// 允许走 mux
    Allow,
    /// 跳过 mux 走 outbound
    Skip,
}

impl Udp443Policy {
    /// 从 proto 字符串解析（Go 原版直接用字符串比较）
    #[must_use]
    pub fn from_proto_str(s: &str) -> Self {
        match s {
            "allow" => Self::Allow,
            "skip" => Self::Skip,
            _ => Self::Reject,
        }
    }

    /// 是否拒绝 UDP/443
    pub fn is_reject(self) -> bool {
        matches!(self, Self::Reject)
    }

    /// 是否跳过 mux
    pub fn is_skip(self) -> bool {
        matches!(self, Self::Skip)
    }
}

/// mux/xudp 启用状态（对应 Go `mux.ClientManager.Enabled bool`）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MuxState {
    /// mux 是否启用
    pub enabled: bool,
    /// 最大并发连接（Go `Concurrency=0` 默认补 8）
    pub concurrency: u32,
}

impl MuxState {
    /// 从 proto `MultiplexingConfig` 解析（对应 Go `NewHandler` 内的 mux 初始化逻辑）
    ///
    /// Go 语义：
    /// - `concurrency < 0` → ClientManager.Enabled = false（explicitly disabled）
    /// - `concurrency == 0` → 默认补 8
    /// - `concurrency > 0` → 启用，按指定并发
    #[must_use]
    pub fn from_proto(cfg: Option<&MultiplexingConfig>) -> Option<Self> {
        let cfg = cfg?;
        if !cfg.enabled {
            return None;
        }
        let concurrency = if cfg.concurrency < 0 {
            return Some(Self {
                enabled: false,
                concurrency: 0,
            });
        } else if cfg.concurrency == 0 {
            8
        } else {
            u32::try_from(cfg.concurrency).unwrap_or(8)
        };
        Some(Self {
            enabled: true,
            concurrency,
        })
    }
}

/// 出站 handler 实体（对应 Go `app/proxyman/outbound.Handler struct`）
///
/// 持有 tag / SenderConfig 引用 / proxy 类型 URL / mux·xudp 状态 / UDP443 策略 / 流量计数器。
/// `dispatch` 与 `dial` 依赖 transport 全链路，留 trait + TODO。
pub struct OutboundHandlerEntry {
    tag: String,
    sender_config: Option<SenderConfig>,
    proxy_type_url: String,
    mux: MuxState,
    xudp: Option<MuxState>,
    udp443: Udp443Policy,
    uplink_counter: Option<Arc<dyn Counter>>,
    downlink_counter: Option<Arc<dyn Counter>>,
}

impl std::fmt::Debug for OutboundHandlerEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundHandlerEntry")
            .field("tag", &self.tag)
            .field("proxy_type_url", &self.proxy_type_url)
            .field("mux", &self.mux)
            .field("xudp", &self.xudp)
            .field("udp443", &self.udp443)
            .field("has_uplink_counter", &self.uplink_counter.is_some())
            .field("has_downlink_counter", &self.downlink_counter.is_some())
            .finish()
    }
}

impl OutboundHandlerEntry {
    /// 构造（对应 Go `NewHandler(ctx, *core.OutboundHandlerConfig) (Handler, error)`）
    ///
    /// `sender_config` 为 `None` 等价于 Go 的 `config.SenderSettings == nil`。
    /// `proxy_type_url` 对应 Go `proxyConfig` 的 proto 类型 URL。
    /// `stats` 决定是否拉取流量计数器。
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tag: impl Into<String>,
        sender_config: Option<SenderConfig>,
        proxy_type_url: impl Into<String>,
        stats: Option<&dyn StatsProvider>,
    ) -> Self {
        let tag_str: String = tag.into();
        let (mux, xudp, udp443) = match sender_config.as_ref().and_then(|s| s.multiplex_settings.as_ref()) {
            Some(m) => (
                MuxState::from_proto(Some(m)).unwrap_or_default(),
                Self::xudp_state_from_proto(m),
                Udp443Policy::from_proto_str(&m.xudp_proxy_udp443),
            ),
            None => (MuxState::default(), None, Udp443Policy::default()),
        };
        let (up, down) = match stats {
            Some(p) if !tag_str.is_empty() => (
                p.get_counter(&outbound_uplink_name(&tag_str)),
                p.get_counter(&outbound_downlink_name(&tag_str)),
            ),
            _ => (None, None),
        };
        Self {
            tag: tag_str,
            sender_config,
            proxy_type_url: proxy_type_url.into(),
            mux,
            xudp,
            udp443,
            uplink_counter: up,
            downlink_counter: down,
        }
    }

    /// xudp 状态（Go 语义：xudp_concurrency < 0 disabled，== 0 不创建 xudp ClientManager，> 0 启用）
    fn xudp_state_from_proto(m: &MultiplexingConfig) -> Option<MuxState> {
        if m.xudp_concurrency < 0 {
            return Some(MuxState {
                enabled: false,
                concurrency: 0,
            });
        }
        if m.xudp_concurrency == 0 {
            // Go: h.xudp = nil
            return None;
        }
        Some(MuxState {
            enabled: true,
            concurrency: u32::try_from(m.xudp_concurrency).unwrap_or(8),
        })
    }

    /// mux 状态
    #[must_use]
    pub fn mux(&self) -> MuxState {
        self.mux
    }

    /// xudp 状态（None 表示 Go `h.xudp = nil`）
    #[must_use]
    pub fn xudp(&self) -> Option<MuxState> {
        self.xudp
    }

    /// UDP 443 策略
    #[must_use]
    pub fn udp443_policy(&self) -> Udp443Policy {
        self.udp443
    }

    /// 引用 SenderConfig
    #[must_use]
    pub fn sender_config(&self) -> Option<&SenderConfig> {
        self.sender_config.as_ref()
    }

    /// 引用 uplink counter
    #[must_use]
    pub fn uplink_counter(&self) -> Option<&Arc<dyn Counter>> {
        self.uplink_counter.as_ref()
    }

    /// 引用 downlink counter
    #[must_use]
    pub fn downlink_counter(&self) -> Option<&Arc<dyn Counter>> {
        self.downlink_counter.as_ref()
    }

    /// 获取 UoT (UDP over TCP) 连接。
    ///
    /// 对应 Go `Handler.getUoTConnection(ctx, dest)`。
    /// 当目标地址是 UoT 魔术域名时，创建 UDP socket 并包装为 UoT 连接。
    ///
    /// # Errors
    /// - [`ProxymanError::NilDestination`]：目标地址为空
    /// - [`ProxymanError::NotUoTDestination`]：目标地址不是 UoT 魔术域名
    /// - [`ProxymanError::ListenSocketFailed`]：UDP socket 绑定失败
    pub async fn get_uo_t_connection(
        &self,
        dest_domain: Option<&str>,
    ) -> Result<(UdpSocket, UotVersion), ProxymanError> {
        let domain = dest_domain.ok_or(ProxymanError::NilDestination)?;
        if domain.is_empty() {
            return Err(ProxymanError::NilDestination);
        }

        // 判断 UoT 版本
        let version = if domain == UOT_MAGIC_ADDRESS {
            UotVersion::Current
        } else if domain == UOT_LEGACY_MAGIC_ADDRESS {
            UotVersion::Legacy
        } else {
            return Err(ProxymanError::NotUoTDestination);
        };

        // 绑定 UDP socket（对应 Go internet.ListenSystemPacket）
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| ProxymanError::ListenSocketFailed(e.to_string()))?;

        // ponytail: Go 用 uot.NewServerConn(packetConn, uotVersion) 包装。
        // Rust 端无 sing uot crate，直接返回 (socket, version)，由上层桥接。
        // 升级路径：实现 UoT ServerConn 包装层。
        Ok((socket, version))
    }
}

impl OutboundHandler for OutboundHandlerEntry {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn start(&self) -> PinFuture<Result<(), ProxymanError>> {
        // ponytail: Go Handler.Start() 是空函数（直接 return nil）
        Box::pin(async { Ok(()) })
    }

    fn close(&self) -> PinFuture<Result<(), ProxymanError>> {
        // ponytail: Go Close 关闭 mux + proxy；Rust 端 mux/proxy 未注入，返回 Ok
        Box::pin(async { Ok(()) })
    }

    fn sender_type_url(&self) -> Option<&str> {
        if self.sender_config.is_some() {
            Some("xray.app.proxyman.SenderConfig")
        } else {
            None
        }
    }

    fn proxy_type_url(&self) -> &str {
        &self.proxy_type_url
    }
}

/// 在 CIDR 子网内随机一个 IP（对应 Go `ParseRandomIP(addr, prefix) net.Address`）
///
/// Go 实现：把 `addr.IP() + "/" + prefix` 解析成 `*net.IPNet`，在子网大小内随机偏移，
/// 加到起始 IP 上返回。
///
/// Rust 端用 [`ipnet::IpNet`] + `rand::Rng::gen_range` 实现。
///
/// # Errors
/// - [`ProxymanError::Other`]：CIDR 字符串无法解析
#[allow(clippy::module_name_repetitions)]
pub fn parse_random_ip(ip: IpAddr, prefix: u8) -> Result<IpAddr, ProxymanError> {
    let net = IpNet::new(ip, prefix).map_err(|e| ProxymanError::Other(e.to_string()))?;
    let start = network_start(&net);
    let subnet_size = subnet_offset_count(&net);

    let mut rng = rand::rng();
    let offset: u128 = rng.random_range(0..subnet_size);
    add_offset(start, offset)
}

/// 取 CIDR 的网络起始地址（u128，v4 zero-extended）
fn network_start(net: &IpNet) -> u128 {
    match net {
        IpNet::V4(n) => u32::from(n.network()).into(),
        IpNet::V6(n) => u128::from(n.network()),
    }
}

/// 取 CIDR 内可用的"主机数"（不含 network/broadcast，但 Go 不区分，按 2^(bits-prefix) 算）
fn subnet_offset_count(net: &IpNet) -> u128 {
    let bits = match net {
        IpNet::V4(_) => 32,
        IpNet::V6(_) => 128,
    };
    let prefix = u32::from(net.prefix_len());
    if prefix >= bits {
        return 1;
    }
    1u128 << (bits - prefix)
}

/// 起始地址 + 偏移（溢出回绕；v4 仅用低 32 位）
fn add_offset(start: u128, offset: u128) -> Result<IpAddr, ProxymanError> {
    // v4 范围检查
    if start <= u32::MAX.into() {
        let s32 = u32::try_from(start).unwrap_or(u32::MAX);
        let off32 = u32::try_from(offset).unwrap_or(u32::MAX);
        let v = s32.wrapping_add(off32);
        Ok(IpAddr::V4(v.into()))
    } else {
        let v = start.wrapping_add(offset);
        Ok(IpAddr::V6(v.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::NoopStatsProvider;
    use std::sync::atomic::{AtomicI64, Ordering};

    struct TestCounter(AtomicI64);
    impl Counter for TestCounter {
        fn value(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
        fn add(&self, d: i64) -> i64 {
            self.0.fetch_add(d, Ordering::SeqCst) + d
        }
    }

    #[test]
    fn udp443_default_is_reject() {
        assert!(matches!(Udp443Policy::default(), Udp443Policy::Reject));
    }

    #[test]
    fn udp443_from_proto_str_all_variants() {
        assert!(matches!(
            Udp443Policy::from_proto_str("reject"),
            Udp443Policy::Reject
        ));
        assert!(matches!(
            Udp443Policy::from_proto_str("allow"),
            Udp443Policy::Allow
        ));
        assert!(matches!(
            Udp443Policy::from_proto_str("skip"),
            Udp443Policy::Skip
        ));
        assert!(matches!(
            Udp443Policy::from_proto_str("garbage"),
            Udp443Policy::Reject
        ));
        assert!(matches!(Udp443Policy::from_proto_str(""), Udp443Policy::Reject));
    }

    #[test]
    fn udp443_predicates() {
        assert!(Udp443Policy::Reject.is_reject());
        assert!(!Udp443Policy::Allow.is_reject());
        assert!(Udp443Policy::Skip.is_skip());
        assert!(!Udp443Policy::Allow.is_skip());
    }

    #[test]
    fn mux_state_default_disabled() {
        let s = MuxState::default();
        assert!(!s.enabled);
        assert_eq!(s.concurrency, 0);
    }

    #[test]
    fn mux_state_from_proto_none_when_not_enabled() {
        let mut m = MultiplexingConfig::default();
        m.enabled = false;
        assert!(MuxState::from_proto(Some(&m)).is_none());
    }

    #[test]
    fn mux_state_from_proto_concurrency_zero_defaults_to_8() {
        let mut m = MultiplexingConfig::default();
        m.enabled = true;
        m.concurrency = 0;
        let s = MuxState::from_proto(Some(&m)).unwrap();
        assert!(s.enabled);
        assert_eq!(s.concurrency, 8);
    }

    #[test]
    fn mux_state_from_proto_negative_disabled() {
        let mut m = MultiplexingConfig::default();
        m.enabled = true;
        m.concurrency = -1;
        let s = MuxState::from_proto(Some(&m)).unwrap();
        assert!(!s.enabled);
    }

    #[test]
    fn mux_state_from_proto_positive_preserved() {
        let mut m = MultiplexingConfig::default();
        m.enabled = true;
        m.concurrency = 16;
        let s = MuxState::from_proto(Some(&m)).unwrap();
        assert!(s.enabled);
        assert_eq!(s.concurrency, 16);
    }

    #[test]
    fn entry_new_no_sender_no_mux() {
        let e = OutboundHandlerEntry::new("tag", None, "xray.proxy.direct.Config", None);
        assert_eq!(e.tag(), "tag");
        assert_eq!(e.proxy_type_url(), "xray.proxy.direct.Config");
        assert!(!e.mux().enabled);
        assert!(e.xudp().is_none());
        assert!(matches!(e.udp443_policy(), Udp443Policy::Reject));
        assert!(e.sender_config().is_none());
        assert!(e.uplink_counter().is_none());
    }

    #[test]
    fn entry_new_with_multiplexing() {
        let mut sender = SenderConfig::default();
        let mut mux = MultiplexingConfig::default();
        mux.enabled = true;
        mux.concurrency = 16;
        mux.xudp_concurrency = 4;
        mux.xudp_proxy_udp443 = "skip".to_string();
        sender.multiplex_settings = Some(mux);

        let e = OutboundHandlerEntry::new("t", Some(sender), "xray.test", None);
        assert!(e.mux().enabled);
        assert_eq!(e.mux().concurrency, 16);
        assert_eq!(e.xudp().unwrap().concurrency, 4);
        assert!(e.udp443_policy().is_skip());
    }

    #[test]
    fn entry_xudp_zero_returns_none() {
        let mut sender = SenderConfig::default();
        let mut mux = MultiplexingConfig::default();
        mux.enabled = true;
        mux.xudp_concurrency = 0;
        sender.multiplex_settings = Some(mux);

        let e = OutboundHandlerEntry::new("t", Some(sender), "xray.test", None);
        assert!(e.xudp().is_none());
    }

    #[test]
    fn entry_xudp_negative_disabled() {
        let mut sender = SenderConfig::default();
        let mut mux = MultiplexingConfig::default();
        mux.enabled = true;
        mux.xudp_concurrency = -1;
        sender.multiplex_settings = Some(mux);

        let e = OutboundHandlerEntry::new("t", Some(sender), "xray.test", None);
        let x = e.xudp().unwrap();
        assert!(!x.enabled);
    }

    #[test]
    fn entry_sender_type_url_some_when_config_present() {
        let e = OutboundHandlerEntry::new(
            "t",
            Some(SenderConfig::default()),
            "xray.test",
            Some(&NoopStatsProvider),
        );
        assert!(e.sender_type_url().is_some());
    }

    #[test]
    fn entry_sender_type_url_none_when_config_absent() {
        let e = OutboundHandlerEntry::new("t", None, "xray.test", None);
        assert!(e.sender_type_url().is_none());
    }

    #[tokio::test]
    async fn entry_start_close_are_noop() {
        let e = OutboundHandlerEntry::new("t", None, "xray.test", None);
        assert!(e.start().await.is_ok());
        assert!(e.close().await.is_ok());
    }

    // ========== parse_random_ip ==========

    #[test]
    fn parse_random_ip_v4_in_subnet() {
        let ip = parse_random_ip("10.0.0.0".parse().unwrap(), 8).unwrap();
        assert!(ip.is_ipv4());
        let octets = match ip {
            IpAddr::V4(v4) => v4.octets(),
            _ => unreachable!(),
        };
        assert_eq!(octets[0], 10);
    }

    #[test]
    fn parse_random_ip_v4_prefix_32_returns_self() {
        let ip = parse_random_ip("192.168.1.1".parse().unwrap(), 32).unwrap();
        assert_eq!(ip.to_string(), "192.168.1.1");
    }

    #[test]
    fn parse_random_ip_v4_prefix_30_in_range() {
        // 192.168.1.0/30 = .0 .1 .2 .3
        for _ in 0..20 {
            let ip = parse_random_ip("192.168.1.0".parse().unwrap(), 30).unwrap();
            let last = match ip {
                IpAddr::V4(v) => v.octets()[3],
                _ => panic!("expected v4"),
            };
            assert!(last <= 3, "got {last}");
        }
    }

    #[test]
    fn parse_random_ip_v6_in_subnet() {
        let ip = parse_random_ip("2001:db8::".parse().unwrap(), 64).unwrap();
        assert!(ip.is_ipv6());
    }

    #[test]
    fn parse_random_ip_distribution() {
        // 多次采样确认覆盖多个值（非确定性测试，但 prefix 16 有 65536 个槽，20 次应至少 2 个不同）
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            let ip = parse_random_ip("10.0.0.0".parse().unwrap(), 16).unwrap();
            seen.insert(ip.to_string());
        }
        assert!(seen.len() >= 2, "expected variation, got {} unique", seen.len());
    }

    #[test]
    fn parse_random_ip_invalid_prefix_overflow() {
        // prefix > 128 走 IpNet::new 报错路径
        let r = parse_random_ip("10.0.0.0".parse().unwrap(), 33);
        assert!(r.is_err());
    }
}
