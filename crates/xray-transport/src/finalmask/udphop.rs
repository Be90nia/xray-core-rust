//! # udphop —— UDP 端口跳跃伪装（对应 Go `transport/internet/finalmask/udphop/`）
//!
//! client-only 连接级 mask：周期性换本地 UDP socket（`intervallocal`，新源端口）
//! 和/或改写目的地址（`intervalremote` 每跳重随机 / `perconnremote` 仅首包随机
//! 一次），IP 从 `remoteIPs` 前缀池随机取、端口从 `remotePorts` 池随机取。对应
//! Go `udphop/conn.go` `udpHopConn`：写侧恒发往当前目标（忽略 caller 传入 addr，
//! 与 Go `WriteTo` 同构），读侧聚合新旧 socket 的包（上一跳 socket 保留收在途
//! 包，再下一跳时关闭，对应 Go `pre.Close()`）。
//!
//! Go `WrapPacketConnServer` 直接报 "udphop: client only"（config.go:15-17），
//! server 侧同构拒绝。
//!
//! 与 Go 的已知差异（刻意收敛，勿当 bug 改）：①首跳沿用 transport 已拨 raw
//! socket 以保留其拨号选项，hop 新 socket 走裸 bind——Go 每跳经 `Dialer.DialUDP`
//! 带 sockopt 重拨，Rust [`Udpmask`] seam 无 dialer；②Go `SetDeadline` 族在
//! Rust [`UdpIo`] trait 无对应，省略。

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use parking_lot::Mutex;
use rand::{Rng, RngCore};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle};

use super::{UDP_SIZE, UdpIo, Udpmask};

/// udphop 配置（对应 Go `udphop.Config` protobuf + `UDPHop.Build` 产物）。
///
/// `remote_ips` 为已解析的 `(网络地址, 前缀位长)`；`interval_min/max` 单位秒，
/// 两端含（Go `RandBetween(min, max+1)` 半开区间同构）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdphopConfig {
    /// `intervallocal`：每跳重拨本地 socket（换源端口）。
    pub local: bool,
    /// `intervalremote`：每跳重随机目标 IP/端口。
    pub remote: bool,
    /// `perconnremote`：仅首包随机一次目标，之后不再跳变。
    pub remote_once: bool,
    pub interval_min: i64,
    pub interval_max: i64,
    pub remote_ips: Vec<(IpAddr, u8)>,
    pub remote_ports: Vec<u32>,
}

impl Udpmask for UdphopConfig {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        // Go NewUDPHopConn（conn.go:56-58）同名校验。
        if self.interval_min < 5 || self.interval_max < 5 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid interval"));
        }
        Ok(Box::new(UdpHopConn::new(raw, self)))
    }

    fn wrap_packet_conn_server(
        &self,
        _raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        // Go udphop/config.go:15-17 同款错误面。
        Err(io::Error::new(io::ErrorKind::InvalidInput, "udphop: client only"))
    }
}

/// 单个活跃 socket + 其收包转发任务（对应 Go 每个 dial 出的 conn 一个 recv 协程）。
struct HopSocket {
    io: Arc<dyn UdpIo>,
    recv_task: JoinHandle<()>,
}

struct HopCore {
    /// 当前发送目标（首个 send_to 的 caller addr 经 remote/remoteOnce 随机化的
    /// 结果，对应 Go `udpHopConn.addr`）。
    target: Option<SocketAddr>,
    cur: HopSocket,
    /// 上一跳 socket：保留收在途包，再下一跳时关闭（对应 Go `pre`）。
    prev: Option<HopSocket>,
}

/// hop 任务与 UdpIo 实现共享的状态 + 配置快照。
struct HopShared {
    core: Mutex<HopCore>,
    tx: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
    local: bool,
    remote: bool,
    remote_once: bool,
    interval_min: i64,
    interval_max: i64,
    remote_ips: Vec<(IpAddr, u8)>,
    remote_ports: Vec<u32>,
}

/// udphop 连接（对应 Go `udpHopConn`，client-only）。
pub struct UdpHopConn {
    shared: Arc<HopShared>,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
    hop_task: Option<JoinHandle<()>>,
}

impl UdpHopConn {
    fn new(raw: Box<dyn UdpIo>, cfg: &UdphopConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let raw: Arc<dyn UdpIo> = Arc::from(raw);
        let cur = HopSocket { recv_task: spawn_forwarder(Arc::clone(&raw), tx.clone()), io: raw };
        let shared = Arc::new(HopShared {
            core: Mutex::new(HopCore { target: None, cur, prev: None }),
            tx,
            local: cfg.local,
            remote: cfg.remote,
            remote_once: cfg.remote_once,
            interval_min: cfg.interval_min,
            interval_max: cfg.interval_max,
            remote_ips: cfg.remote_ips.clone(),
            remote_ports: cfg.remote_ports.clone(),
        });
        // 仅在确有跳变维度时起周期任务；remoteOnce-only 时 Go 的 ticker 空转，此处直接省略。
        let hop_task = if shared.local || shared.remote {
            let s = Arc::clone(&shared);
            Some(tokio::spawn(async move {
                loop {
                    // Go RandBetween(from>to 时交换)；校验保证 >=5，.max(0) 防 i64 负值转 u64。
                    let (lo, hi) =
                        (s.interval_min.min(s.interval_max), s.interval_max.max(s.interval_min));
                    let secs = rand::rng().random_range(lo..=hi).max(0);
                    tokio::time::sleep(Duration::from_secs(secs as u64)).await;
                    hop_once_shared(&s).await;
                }
            }))
        } else {
            None
        };
        Self { shared, rx: tokio::sync::Mutex::new(rx), hop_task }
    }

    /// 执行一次跳变（hop 循环体；仅测试用——确定性驱动单次跳变，不等真实间隔）。
    #[cfg(test)]
    async fn hop_once(&self) {
        hop_once_shared(&self.shared).await;
    }

    /// 首包目标（对应 Go NewUDPHopConn dial 前的 dest 随机化）。
    fn initial_target(&self, base: SocketAddr) -> SocketAddr {
        if !(self.shared.remote || self.shared.remote_once) {
            return base;
        }
        hop_target(base, &self.shared.remote_ips, &self.shared.remote_ports)
    }
}

/// hop 循环体：remote 重随机目标；local 拨新 socket 换源端口（旧 socket 保留
/// 收包，上一跳关闭）。
async fn hop_once_shared(s: &HopShared) {
    let base = match s.core.lock().target {
        Some(t) => t,
        // 尚未发送过：Go c.addr 在 dial 时已定，Rust 首包才知基址——无可跳，跳过。
        None => return,
    };
    let new_target = if s.remote { hop_target(base, &s.remote_ips, &s.remote_ports) } else { base };
    if !s.local {
        if s.remote {
            // remote-only：同一 socket，仅改写目标（Go hop 不重拨）。
            s.core.lock().target = Some(new_target);
        }
        return;
    }
    // local：拨新本地 socket（裸 bind 等价 Go DialUDP 重拨的 socket 生命周期语义）。
    let sock = match bind_unspecified(new_target).await {
        Ok(sock) => sock,
        Err(e) => {
            // Go：dial 失败还原 addr + 记 "hop err"，保持当前 socket。
            crate::LOG.warn(format!("target={new_target} error={e} xmc udphop hop dial failed"));
            return;
        },
    };
    let io: Arc<dyn UdpIo> = Arc::new(sock);
    let fresh = HopSocket { recv_task: spawn_forwarder(Arc::clone(&io), s.tx.clone()), io };
    let mut core = s.core.lock();
    core.target = Some(new_target);
    let old_cur = std::mem::replace(&mut core.cur, fresh);
    if let Some(p) = core.prev.take() {
        p.recv_task.abort(); // 关闭上一跳 socket（Go pre.Close()）
    }
    core.prev = Some(old_cur);
}

/// 目标重随机化：remoteIPs 前缀池随机取 IP、remotePorts 随机取端口；池空保持原值
/// （对应 Go NewUDPHopConn/hop 的 dest 字段更新）。
fn hop_target(base: SocketAddr, ips: &[(IpAddr, u8)], ports: &[u32]) -> SocketAddr {
    let mut ip = base.ip();
    let mut port = base.port();
    if !ips.is_empty() {
        let (p, bits) = ips[rand::rng().random_range(0..ips.len())];
        ip = rand_prefix(p, bits);
    }
    if !ports.is_empty() {
        // Go net.Port(uint32)→uint16 同为截断转换。
        port = ports[rand::rng().random_range(0..ports.len())] as u16;
    }
    SocketAddr::new(ip, port)
}

/// 前缀内随机 IP（对齐 Go `udphop/conn.go` `randPrefix`）：单 IP 前缀原样返回；
/// 否则网络位保持、主机位全随机（边界字节按位掩码部分随机）。
fn rand_prefix(addr: IpAddr, bits: u8) -> IpAddr {
    let max_bits = if addr.is_ipv4() { 32 } else { 128 };
    if bits >= max_bits {
        return addr;
    }
    let mut b = [0u8; 16];
    let len = match addr {
        IpAddr::V4(v) => {
            b[..4].copy_from_slice(&v.octets());
            4
        },
        IpAddr::V6(v) => {
            b = v.octets();
            16
        },
    };
    let mut rnd = [0u8; 16];
    rand::rng().fill_bytes(&mut rnd[..len]);
    let (i, j) = ((bits / 8) as usize, (bits % 8) as u32);
    if i + 1 < len {
        b[i + 1..len].copy_from_slice(&rnd[i + 1..len]);
    }
    // j==0 时 Go byte(0xff<<8) 自然溢出为 0（整字节随机）；u32 移位同构，避开
    // Rust u8 移位溢出 panic。
    let mask = ((0xffu32 << (8 - j)) & 0xff) as u8;
    b[i] = (b[i] & mask) | (rnd[i] & !mask);
    match addr {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])),
        IpAddr::V6(_) => IpAddr::V6(b.into()),
    }
}

/// bind 到与目标同族的未指定地址（等价 Go 重拨时的本地源选取）。
async fn bind_unspecified(target: SocketAddr) -> io::Result<UdpSocket> {
    let bind = if target.is_ipv4() {
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
    } else {
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
    };
    UdpSocket::bind(bind).await
}

/// 单 socket 收包转发任务：所有包推入共享队列（对应 Go recv 协程 + readCh）。
/// Err 退出 = 该 socket 被丢弃/关闭（每跳常规拆线），对应 Go recv 的 closed 分支。
fn spawn_forwarder(
    io: Arc<dyn UdpIo>,
    tx: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_SIZE];
        while let Ok((n, addr)) = io.recv_from(&mut buf).await {
            if tx.send((buf[..n].to_vec(), addr)).is_err() {
                break; // 接收端已关闭（连接丢弃）
            }
        }
    })
}

#[async_trait]
impl UdpIo for UdpHopConn {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        // Go WriteTo 恒发往 c.addr、忽略 caller addr——首个 caller addr 作为基址。
        let (io, target) = {
            let mut core = self.shared.core.lock();
            let target = *core.target.get_or_insert_with(|| self.initial_target(addr));
            (Arc::clone(&core.cur.io), target)
        };
        io.send_to(buf, target).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (data, addr) = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "udphop conn closed"))?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((n, addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.shared.core.lock().cur.io.local_addr()
    }
}

impl Drop for UdpHopConn {
    fn drop(&mut self) {
        if let Some(t) = self.hop_task.take() {
            t.abort();
        }
        let mut core = self.shared.core.lock();
        core.cur.recv_task.abort();
        if let Some(p) = core.prev.take() {
            p.recv_task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(local: bool, remote: bool, remote_once: bool) -> UdphopConfig {
        UdphopConfig {
            local,
            remote,
            remote_once,
            interval_min: 30,
            interval_max: 30,
            remote_ips: Vec::new(),
            remote_ports: Vec::new(),
        }
    }

    /// 前缀随机化对齐 Go randPrefix：网络位恒定、主机位变化、单 IP 原样。
    #[test]
    fn rand_prefix_respects_prefix_bits() {
        // /32 单 IP：恒等
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(rand_prefix(ip, 32), ip);
        assert_eq!(rand_prefix(ip, 33), ip);
        // 裸 IP 补全长（Build 侧保证，rand_prefix 对 >=max 恒等）
        assert_eq!(rand_prefix(ip, 255), ip);

        // /24：前三字节恒定、末字节随机
        let base: IpAddr = "10.1.2.0".parse().unwrap();
        for _ in 0..200 {
            let r = rand_prefix(base, 24);
            let o = match r {
                IpAddr::V4(v) => v.octets(),
                _ => panic!("v4 expected"),
            };
            assert_eq!(&o[..3], &[10, 1, 2]);
        }
        // /16：前两字节恒定
        for _ in 0..50 {
            let r = rand_prefix(base, 16);
            let o = match r {
                IpAddr::V4(v) => v.octets(),
                _ => panic!("v4 expected"),
            };
            assert_eq!(&o[..2], &[10, 1]);
        }
        // /25：末字节高 1 位保持（10.1.2.0/25 → 末字节 < 128）
        for _ in 0..50 {
            let r = rand_prefix(base, 25);
            let o = match r {
                IpAddr::V4(v) => v.octets(),
                _ => panic!("v4 expected"),
            };
            assert!(o[3] < 128, "host bit beyond /25 leaked: {o:?}");
        }
        // v6 /112：前 14 字节恒定
        let v6: IpAddr = "2001:db8::".parse().unwrap();
        for _ in 0..50 {
            let r = rand_prefix(v6, 112);
            let o = match r {
                IpAddr::V6(v) => v.octets(),
                _ => panic!("v6 expected"),
            };
            assert_eq!(
                &o[..14],
                &match v6 {
                    IpAddr::V6(x) => x.octets(),
                    _ => unreachable!(),
                }[..14]
            );
        }
    }

    /// interval 下限校验（Go conn.go:56-58 "invalid interval"）。
    #[tokio::test]
    async fn wrap_rejects_interval_under_five() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bad = UdphopConfig { interval_min: 4, ..cfg(true, false, false) };
        let err = bad
            .wrap_packet_conn_client(Box::new(client), 0, 0)
            .err()
            .expect("must reject interval<5");
        assert_eq!(err.to_string(), "invalid interval");
        let bad_max = UdphopConfig { interval_max: 4, ..cfg(true, false, false) };
        assert!(bad_max.wrap_packet_conn_client(Box::new(server), 0, 0).is_err());
    }

    /// server 侧同构拒绝（Go config.go:15-17 "udphop: client only"）。
    #[tokio::test]
    async fn server_side_is_client_only() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let err = cfg(true, false, false)
            .wrap_packet_conn_server(Box::new(server), 0, 0)
            .err()
            .expect("server wrap must reject");
        assert_eq!(err.to_string(), "udphop: client only");
    }

    /// local 跳变端到端：hop 换源端口，双向数据不中断（回复经新 socket 收到）。
    /// 直接构造具体类型以便驱动 hop_once（wrap 校验路径由其余测试覆盖）。
    #[tokio::test]
    async fn local_hop_changes_source_port_and_keeps_flow() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let conn = UdpHopConn::new(Box::new(client), &cfg(true, false, false));
        let roundtrip = async {
            conn.send_to(b"ping1", server_addr).await.unwrap();
            let mut buf = vec![0u8; 1500];
            let (n, peer1) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping1");

            conn.hop_once().await;
            conn.send_to(b"ping2", server_addr).await.unwrap();
            let (n, peer2) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping2");
            assert_ne!(peer1, peer2, "local hop must change source port");

            server.send_to(b"pong", peer2).await.unwrap();
            let (n, from) = conn.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"pong");
            // 回包源 = 服务端地址；能收到即证明新 socket 的转发任务在收（旧 socket
            // 不会收到定向发往 peer2 的回包）。
            assert_eq!(from, server_addr);
        };
        tokio::time::timeout(Duration::from_secs(10), roundtrip)
            .await
            .expect("udphop local hop roundtrip should complete well under 10s");
    }

    /// remoteOnce：首包重写目标（caller addr 被忽略，Go WriteTo 同构）——发往
    /// 无关地址的包按 remoteIPs/remotePorts 随机化结果落到真服务端。remoteIPs 用
    /// /32 单 IP（rand_prefix 单 IP 路径恒等返回）；server 绑定具体地址时，/8
    /// 随机出的 127.x.y.z 不会送达（bind 语义），端到端随机 IP 需 server 绑
    /// 0.0.0.0，此处不展开。
    #[tokio::test]
    async fn remote_once_rewrites_destination() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let conf = UdphopConfig {
            remote_once: true,
            remote_ips: vec![("127.0.0.1".parse().unwrap(), 32)],
            remote_ports: vec![u32::from(server_addr.port())],
            ..cfg(false, false, true)
        };
        let conn: Box<dyn UdpIo> = conf.wrap_packet_conn_client(Box::new(client), 0, 0).unwrap();

        // caller addr 故意指向不存在的端口：目标必须被改写到真服务端。
        let dummy: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let roundtrip = async {
            conn.send_to(b"hop-payload", dummy).await.unwrap();
            let mut buf = vec![0u8; 1500];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hop-payload");
            assert_ne!(peer.port(), 0, "source port must be ephemeral");

            server.send_to(b"hop-reply", peer).await.unwrap();
            let (n, _) = conn.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hop-reply");
        };
        tokio::time::timeout(Duration::from_secs(10), roundtrip)
            .await
            .expect("udphop remoteOnce roundtrip should complete well under 10s");
    }
}
