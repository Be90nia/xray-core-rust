//! finalmask `filter` 掩码（Go `transport/internet/finalmask/filter`）。
//!
//! 纯服务端准入控制，**无 wire 语义**：TCP 在 accept 后按源 IP 决定是否放行，
//! UDP 在 `recv_from` 后按源 IP 丢弃数据。client 侧四个 wrap 方法原样返回
//! 连接（Go 同：过滤只作用于服务端入站）。两表皆空 ⇒ 恒透传（不包装）。
//!
//! # TCP 半边与 Go 的接口差
//!
//! Go 的 TCP 过滤是 `Listen(inner)`——在 accept 循环里、先于任何 per-conn mask。
//! 本仓 [`Tcpmask`] 无 listener 钩子，改用
//! [`wrap_conn_server_with_addrs`](Tcpmask::wrap_conn_server_with_addrs) 表达：
//! 命中即 drop 底层连接（对端立即收到 FIN/RST）并返回一个**立即 EOF** 的替身，
//! 等价 Go `conn.Close(); continue`。
//!
//! 为什么不用 `Err`：生产入站 accept 循环（`InboundTcpListener::accept_masked`，
//! vless/vmess/trojan/dokodemo 的 serve 循环）把 `Err` 记 `warn!`——攻击者换源 IP
//! 重连即刷屏；且 `Err` 在本仓的语义是「mask 构造失败」，与「该来源被拒」不同族
//! （被拒是正常业务流，不是错误）。
//!
//! 链式包装是逆序的（`apply_tcpmasks`）：`tcp` 数组里 filter 排首位时被最后包装
//! = 最外层（= Go 语义）。排在别处判定结果不变，只是内层 mask 会先在被拒连接上
//! 起泵、随后立刻 EOF。

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_geodata::{
    matcher::ip::{DynamicIPMatcher, IP_REG, IPMatcher, IpRegistry},
    rule_parser::parse_ip_rules,
};

use super::{AsyncIo, ConnAddrs, Tcpmask, UdpIo, Udpmask, mask_err};

/// 源 IP 判定策略（Go `filter` 结构体：`blocked` / `allowed` 两张 matcher 表）。
///
/// 持 [`DynamicIPMatcher`]（经 `IP_REG.build_ip_matcher` 登记）而非不登记的
/// `Box<dyn IPMatcher>`：Go 的 filter 同样把 matcher 交给 `geodata.IPReg` 托管，
/// `IPReg.Reload` 后（`ReloadBothRegistries`）过滤规则跟着资产一起热更新。
pub struct FilterPolicy {
    blocked: Option<Arc<DynamicIPMatcher>>,
    allowed: Option<Arc<DynamicIPMatcher>>,
}

impl FilterPolicy {
    /// 是否拒绝该来源（Go `filter.rejects`，逐分支对齐）。
    ///
    /// 未知来源（`None`，如 unix 连接没有 SocketAddr）无法满足白名单 ⇒ 有白名单
    /// 即拒（Go `default:` 分支同）。4-in-6 地址先归一到 IPv4：Go 在 matcher 内部
    /// 走 `net.IP.To4()`（`ip_matcher.go:195`），不归一会让双栈监听端看到的
    /// `::ffff:1.2.3.4` 漏掉 v4 规则（Go 命中、本仓不命中 = 语义分叉）。
    #[must_use]
    pub fn rejects(&self, peer: Option<SocketAddr>) -> bool {
        let Some(peer) = peer else {
            return self.allowed.is_some();
        };
        let ip = peer.ip().to_canonical();
        if self.blocked.as_ref().is_some_and(|blocked| blocked.match_ip(ip)) {
            return true;
        }
        self.allowed.as_ref().is_some_and(|allowed| !allowed.match_ip(ip))
    }
}

/// finalmask `filter` 掩码。
///
/// `policy == None`（两表皆空）= 恒透传：Go `buildFilter()` 此时返回 nil，所有包装
/// 直接跳过；本仓同样不包装（TCP 原样返回连接、UDP 原样返回 socket）。
pub struct FilterConfig {
    policy: Option<Arc<FilterPolicy>>,
}

impl FilterConfig {
    /// 从规则字符串表构造（Go `filter.Config.buildFilter` + `geodata.ParseIPRules`）。
    ///
    /// 两表皆空 → 恒透传掩码；单条规则非法 → 硬错（Go 在 `Build` 期即报错——
    /// 静默丢规则会把「拦一批」变成「一条没拦」或「全拦」）。
    pub fn from_rules(blocked: Option<&[String]>, allowed: Option<&[String]>) -> io::Result<Self> {
        Self::from_rules_with(&IP_REG, blocked, allowed)
    }

    /// 指定注册表的形态（测试注入自定资产目录用；生产走 [`Self::from_rules`]）。
    pub fn from_rules_with(
        registry: &IpRegistry,
        blocked: Option<&[String]>,
        allowed: Option<&[String]>,
    ) -> io::Result<Self> {
        let blocked = build_matcher(registry, blocked, "blockedSourceIPs")?;
        let allowed = build_matcher(registry, allowed, "allowedSourceIPs")?;
        if blocked.is_none() && allowed.is_none() {
            return Ok(Self { policy: None });
        }
        Ok(Self { policy: Some(Arc::new(FilterPolicy { blocked, allowed })) })
    }
}

/// 单表规则 → matcher（空表 = `None`，对应 Go 该字段 nil）。
///
/// 规则串经 `geodata::rule_parser::parse_ip_rules`（`!` 反向 / CIDR / `geoip:` /
/// `ext:` / `ext-ip:`），再用注册表构造——等价 Go
/// `geodata.IPReg.BuildIPMatcher(c.BlockedSourceIps)`：资产缺失 / 代号不存在 ⇒
/// 报错（Go 同，不静默退空集）。
fn build_matcher(
    registry: &IpRegistry,
    rules: Option<&[String]>,
    label: &str,
) -> io::Result<Option<Arc<DynamicIPMatcher>>> {
    let Some(rules) = rules.filter(|rules| !rules.is_empty()) else {
        return Ok(None);
    };
    let parsed = parse_ip_rules(rules, registry.datadir())
        .map_err(|e| mask_err(format!("finalmask: filter: \"{label}\": {e}")))?;
    registry
        .build_ip_matcher(&parsed)
        .map(Some)
        .map_err(|e| mask_err(format!("finalmask: filter: \"{label}\": {e}")))
}

impl std::fmt::Debug for FilterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // matcher 内部结构不可读，只报有没有配策略。
        f.debug_struct("FilterConfig").field("has_policy", &self.policy.is_some()).finish()
    }
}

impl Tcpmask for FilterConfig {
    fn wrap_conn_client(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>> {
        // Go `WrapConnClient` 原样返回（过滤只作用于服务端入站）。
        Ok(raw)
    }

    fn wrap_conn_server(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>> {
        self.wrap_conn_server_with_addrs(raw, ConnAddrs::default())
    }

    fn wrap_conn_server_with_addrs(
        &self,
        raw: Box<dyn AsyncIo>,
        addrs: ConnAddrs,
    ) -> io::Result<Box<dyn AsyncIo>> {
        let Some(policy) = &self.policy else {
            return Ok(raw);
        };
        if !policy.rejects(addrs.remote) {
            return Ok(raw);
        }
        // 拒绝 = 立刻关闭（Go `conn.Close()`）：drop 掉底层连接让对端立即收到
        // FIN/RST，替身只负责让上层读到 EOF 后自行收尾。
        drop(raw);
        Ok(Box::new(RejectedConn))
    }
}

impl Udpmask for FilterConfig {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        // Go `WrapPacketConnClient` 原样返回。
        Ok(raw)
    }

    fn wrap_packet_conn_server(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        let Some(policy) = &self.policy else {
            return Ok(raw);
        };
        Ok(Box::new(FilteredUdpIo { inner: raw, policy: Arc::clone(policy) }))
    }
}

/// 被拒连接的替身：读恒 EOF，写恒 `BrokenPipe`（底层 socket 已 close）。
struct RejectedConn;

impl AsyncRead for RejectedConn {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 读 0 字节 = EOF。
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RejectedConn {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// 过滤 `recv_from`：被拒来源的数据直接丢弃，上层读不到（Go `packetConn.ReadFrom`）。
struct FilteredUdpIo {
    inner: Box<dyn UdpIo>,
    policy: Arc<FilterPolicy>,
}

#[async_trait]
impl UdpIo for FilteredUdpIo {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(buf, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            // 错误原样上抛：Go `ReadFrom` 的 `if err != nil { return 0, nil, err }`
            // 与「data+err 同时返回」的旁路都收敛到同一条错误传播（Rust 的
            // `recv_from` 不会同时给出数据和错误），禁吞错后继续循环。
            let (n, addr) = self.inner.recv_from(buf).await?;
            if self.policy.rejects(Some(addr)) {
                continue;
            }
            return Ok((n, addr));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        net::{IpAddr, Ipv4Addr},
    };

    use parking_lot::Mutex;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    fn peer(ip: &str) -> Option<SocketAddr> {
        Some(SocketAddr::new(ip.parse::<IpAddr>().unwrap(), 1234))
    }

    fn policy(blocked: &[&str], allowed: &[&str]) -> FilterConfig {
        let owned = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        FilterConfig::from_rules(Some(&owned(blocked)), Some(&owned(allowed))).unwrap()
    }

    /// 服务端包装一次往返：返回 `(对端写入是否成功, 服务端读到的数据)`。
    ///
    /// 被拒时底层连接已在包装期 drop ⇒ 对端写必 `BrokenPipe`（等价 Go `conn.Close()`
    /// 后对端收到 RST）、服务端读必 EOF；放行时两者都正常。
    async fn wrapped_exchange(cfg: &FilterConfig, remote: &str) -> (bool, io::Result<Vec<u8>>) {
        let (mut client, server) = tokio::io::duplex(16);
        let addrs = ConnAddrs { local: None, remote: peer(remote) };
        let mut masked: Box<dyn AsyncIo> =
            cfg.wrap_conn_server_with_addrs(Box::new(server), addrs).unwrap();
        let wrote = client.write_all(b"hi").await.is_ok();
        let mut buf = [0u8; 2];
        let read = masked.read_exact(&mut buf).await.map(|_n| buf.to_vec());
        (wrote, read)
    }

    fn pass(outcome: (bool, io::Result<Vec<u8>>)) -> Vec<u8> {
        let (wrote, read) = outcome;
        assert!(wrote, "放行时对端必须能写");
        read.expect("放行时服务端必须读到数据")
    }

    fn rejected(outcome: (bool, io::Result<Vec<u8>>)) {
        assert!(!outcome.0, "被拒时底层连接已关闭，对端写必须失败");
        assert_eq!(
            outcome.1.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof,
            "被拒时服务端读到 EOF"
        );
    }

    /// ① 两表皆空 = 恒透传（不包装、恒不拒）。
    #[tokio::test]
    async fn empty_tables_pass_every_peer_through() {
        let cfg = FilterConfig::from_rules(None, Some(&[])).unwrap();
        assert!(cfg.policy.is_none(), "两表皆空 ⇒ 不持有 policy（Go buildFilter 返回 nil）");
        for remote in ["10.1.2.3", "::1", "127.0.0.1"] {
            assert_eq!(pass(wrapped_exchange(&cfg, remote).await), b"hi");
        }
    }

    /// ② blocked 命中 ⇒ 拒（对端读到 EOF）。
    #[tokio::test]
    async fn blocked_source_is_rejected() {
        let cfg = policy(&["10.0.0.0/8"], &[]);
        rejected(wrapped_exchange(&cfg, "10.1.2.3").await);
        assert_eq!(pass(wrapped_exchange(&cfg, "192.0.2.9").await), b"hi", "非 blocked 放行");
    }

    /// ③ 白名单外 ⇒ 拒；白名单内 ⇒ 放行。
    #[tokio::test]
    async fn allowlist_rejects_outsiders() {
        let cfg = policy(&[], &["192.0.2.0/24"]);
        assert_eq!(pass(wrapped_exchange(&cfg, "192.0.2.7").await), b"hi");
        rejected(wrapped_exchange(&cfg, "10.1.2.3").await);
    }

    /// ④ blocked 与 allowed 同时命中 ⇒ blocked 优先（拒）。
    #[tokio::test]
    async fn blocked_wins_over_allowed() {
        let cfg = policy(&["10.0.0.0/8"], &["10.0.0.0/8"]);
        assert!(cfg.policy.as_ref().unwrap().rejects(peer("10.1.2.3")), "blocked 必须先判定");
        rejected(wrapped_exchange(&cfg, "10.1.2.3").await);
    }

    /// 未知来源（无 SocketAddr，如 unix 连接）无法满足白名单 ⇒ 有白名单即拒。
    #[test]
    fn unknown_source_cannot_satisfy_allowlist() {
        assert!(
            !policy(&["10.0.0.0/8"], &[]).policy.as_ref().unwrap().rejects(None),
            "只有黑名单 ⇒ 放行"
        );
        assert!(policy(&[], &["192.0.2.0/24"]).policy.as_ref().unwrap().rejects(None));
    }

    /// 4-in-6 归一：Go matcher 内部走 `net.IP.To4()`，双栈监听端的 v4-mapped 来源
    /// 必须命中 v4 规则。
    #[test]
    fn ipv4_mapped_source_matches_v4_rule() {
        let cfg = policy(&["10.0.0.0/8"], &[]);
        assert!(cfg.policy.as_ref().unwrap().rejects(peer("::ffff:10.1.2.3")));
    }

    /// 非法 CIDR 仍硬错；`geoip:` / `ext-ip:` 规则**不再**被本地拒绝，而是交给
    /// geodata 解析层（资产缺失时报可诊断的资产错误，带文件名）。
    #[test]
    fn invalid_cidr_rejects_and_geoip_goes_to_geodata() {
        let one = |s: &str| vec![s.to_string()];
        let err = FilterConfig::from_rules(Some(&one("10.0.0.0/33")), None).unwrap_err();
        assert!(err.to_string().contains("blockedSourceIPs"), "{err}");
        let err =
            FilterConfig::from_rules(Some(&one("ext-ip:no-such-file.dat:CN")), None).unwrap_err();
        let msg = err.to_string();
        // 走的是资产加载层（Go 同错误形态：open xxx.dat 失败）；不再是旧的本地拒绝。
        assert!(!msg.contains("geodata loader"), "不得再走旧的本地拒绝路径：{msg}");
        assert!(msg.contains("文件") || msg.contains("IO"), "错误须来自资产加载层：{msg}");
    }

    /// 端到端（不依赖全局资产）：自定资产目录放 `geoip:CN` ⇒ filter 真按 geoip 拒绝
    /// 来源。等价 Go `geodata.IPReg.BuildIPMatcher(c.BlockedSourceIps)`。
    #[test]
    fn geoip_rule_blocks_matching_source() {
        let dir = tmp_dir("filter_geoip");
        write_geoip_dat(&dir, ("CN", 103, 8));
        let registry = IpRegistry::with_datadir(dir);
        let one = |s: &str| vec![s.to_string()];
        let cfg = FilterConfig::from_rules_with(&registry, Some(&one("geoip:CN")), None).unwrap();
        let policy = cfg.policy.as_ref().unwrap();
        assert!(policy.rejects(peer("103.1.2.3")), "geoip:CN 必须拦 CN 段来源");
        assert!(!policy.rejects(peer("8.8.8.8")), "非 CN 段不得被拦");
    }

    fn tmp_dir(label: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("xray_transport_filter_{label}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 最小 geoip.dat：`GeoIpList{ entry: [{country_code, cidr}] }` 的 prost 编码。
    fn write_geoip_dat(dir: &std::path::Path, entry: (&str, u8, u32)) {
        use prost::Message as _;
        use xray_geodata::pb::{Cidr, GeoIp, GeoIpList};
        let (code, first_octet, prefix) = entry;
        let mut geo = GeoIp::new(code);
        geo.cidr = vec![Cidr::new(vec![first_octet, 0, 0, 0], prefix)];
        let list = GeoIpList::new().with_entry(geo);
        let bytes = list.encode_to_vec();
        std::fs::write(dir.join(xray_geodata::rule_parser::DEFAULT_GEOIP_DAT), bytes).unwrap();
    }

    /// ⑤ UDP：被拒来源的包不交给上层（`recv_from` 跳过并继续读）。
    #[tokio::test]
    async fn udp_drops_rejected_source_packets() {
        let scripted = ScriptedUdpIo::new(vec![
            (b"blocked".to_vec(), SocketAddr::new(Ipv4Addr::new(10, 1, 2, 3).into(), 1)),
            (b"allowed".to_vec(), SocketAddr::new(Ipv4Addr::new(192, 0, 2, 9).into(), 2)),
        ]);
        let cfg = policy(&["10.0.0.0/8"], &[]);
        let conn = cfg.wrap_packet_conn_server(Box::new(scripted), 0, 0).unwrap();
        let mut buf = [0u8; 16];
        let (n, addr) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"allowed", "被拒来源的包必须被跳过");
        assert_eq!(addr.ip(), Ipv4Addr::new(192, 0, 2, 9));
    }

    /// 空白名单 + UDP ⇒ 原样返回（不包装，Go 同）。
    #[tokio::test]
    async fn udp_empty_tables_do_not_wrap() {
        let cfg = policy(&[], &[]);
        let scripted = ScriptedUdpIo::new(vec![(
            b"x".to_vec(),
            SocketAddr::new(Ipv4Addr::new(10, 1, 2, 3).into(), 1),
        )]);
        let conn = cfg.wrap_packet_conn_server(Box::new(scripted), 0, 0).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(conn.recv_from(&mut buf).await.unwrap().0, 1);
    }

    /// 脚本化 `UdpIo`：按序吐出预置 `(载荷, 来源)`，队列空后返回 EOF 类错误。
    struct ScriptedUdpIo {
        packets: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    }

    impl ScriptedUdpIo {
        fn new(packets: Vec<(Vec<u8>, SocketAddr)>) -> Self {
            Self { packets: Mutex::new(packets.into()) }
        }
    }

    #[async_trait]
    impl UdpIo for ScriptedUdpIo {
        async fn send_to(&self, buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            Ok(buf.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let Some((payload, addr)) = self.packets.lock().pop_front() else {
                return Err(io::ErrorKind::UnexpectedEof.into());
            };
            let n = payload.len().min(buf.len());
            buf[..n].copy_from_slice(&payload[..n]);
            Ok((n, addr))
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        }
    }
}
