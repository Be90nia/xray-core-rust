//! # Salamander UDP 混淆 socket 包装（bd Xray-core-rust-6op）
//!
//! 对应 Go `transport/internet/hysteria/dialer.go:170-179`：QUIC 的 UDP socket
//! 在交给 `quic.Transport` 前用 `udpmaskManager.WrapPacketConnClient/Server` 包
//! salamander（包格式 `[8B salt][XOR(payload, BLAKE2b-256(PSK||salt))]`，每包新 salt，
//! PSK ≥ 4 字节）。client 与 server 包装对称（Go `NewSalamanderConnServer` 直接复用
//! client 构造），两端 PSK 相同即可互通。
//!
//! Rust 侧 quinn 0.11 的对应注入点是 `Endpoint::new_with_abstract_socket`：
//! 本模块 [`SalamanderSocket`] 实现 `quinn::AsyncUdpSocket`，收发两个方向都过 XOR：
//! - 发送 `try_send`：`salt || XOR(contents)` 后 `try_send_to`
//! - 接收 `poll_recv`：`recv_from` → 剥 salt + XOR 回明文 → 写入 quinn 缓冲； 长度 ≤ salt
//!   的短包丢弃继续读（对齐 Go `headerManagerConn.ReadFrom` 的 drop-and-continue
//!   语义，finalmask.go:134-137）
//!
//! GSO/GRO/ECN 不透传：`max_transmit_segments`/`max_receive_segments` 保持默认 1，
//! quinn 不会构造多段 Transmit；`may_fragment()==true` 使 quinn 关闭路径 MTU 探测
//! （salamander 每包 +8B salt，不探测更稳妥）。XOR 本体复用
//! `xray_transport::finalmask::salamander::SalamanderObfuscator`（非重写）。

use std::{
    io,
    io::IoSliceMut,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use parking_lot::Mutex;
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use tokio::net::UdpSocket;
use xray_transport::finalmask::{salamander::SalamanderObfuscator, salamander_gecko::GeckoConfig};

/// 单个 wire datagram 缓冲上限：QUIC `max_udp_payload_size` 上限 64KiB + salt。
const MAX_WIRE_DATAGRAM: usize = 64 * 1024 + 8;

/// salamander salt 长度（对齐 Go `smSaltLen`；仅用于短包判定文档）。
const SALT_LEN: usize = 8;

/// Hysteria QUIC 路径的 UDP 混淆配置（对应 Go `udpmaskManager` 包裹的 mask，
/// 当前支持 salamander 与其 Gecko 分片子模式）。
#[derive(Clone)]
pub enum UdpObfs {
    /// Salamander XOR（对应 Go `salamander.Config`）。
    Salamander(Arc<SalamanderObfuscator>),
    /// Gecko 分片模式（对应 Go `salamander.GeckoConfig`，`packetSize` 配置切换）。
    Gecko(GeckoConfig),
}

/// 手动 Debug（`SalamanderObfuscator` 未实现 Debug；只打印变体名与 Gecko 参数）。
impl std::fmt::Debug for UdpObfs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpObfs::Salamander(_) => f.write_str("Salamander(..)"),
            UdpObfs::Gecko(cfg) => f.debug_tuple("Gecko").field(cfg).finish(),
        }
    }
}

impl UdpObfs {
    /// client 侧构造 quinn endpoint（socket 已包混淆，等价 `Endpoint::client`）。
    ///
    /// # Errors
    /// socket bind 失败 / 混淆参数非法（Gecko 的 PSK 与分片参数在 bind 时校验）。
    pub async fn client_endpoint(
        &self,
        bind_addr: SocketAddr,
        sockopt: &xray_transport::sockopt::SocketOptions,
    ) -> io::Result<quinn::Endpoint> {
        match self {
            UdpObfs::Salamander(obfs) => {
                SalamanderSocket::bind(obfs.clone(), bind_addr, sockopt).await?.client_endpoint()
            },
            UdpObfs::Gecko(cfg) => crate::gecko_socket::GeckoSocket::bind(cfg, bind_addr, sockopt)
                .await?
                .client_endpoint(),
        }
    }

    /// server 侧构造 quinn endpoint（socket 已包混淆，等价 `Endpoint::server`）。
    ///
    /// # Errors
    /// 同 [`UdpObfs::client_endpoint`]。
    pub async fn server_endpoint(
        &self,
        server_config: quinn::ServerConfig,
        bind_addr: SocketAddr,
        sockopt: &xray_transport::sockopt::SocketOptions,
    ) -> io::Result<quinn::Endpoint> {
        match self {
            UdpObfs::Salamander(obfs) => SalamanderSocket::bind(obfs.clone(), bind_addr, sockopt)
                .await?
                .server_endpoint(server_config),
            UdpObfs::Gecko(cfg) => crate::gecko_socket::GeckoSocket::bind(cfg, bind_addr, sockopt)
                .await?
                .server_endpoint(server_config),
        }
    }
}

/// 包 salamander XOR 的 quinn UDP socket。
///
/// 经 [`quinn::Endpoint::new_with_abstract_socket`] 注入；构造用 [`SalamanderSocket::bind`]。
pub struct SalamanderSocket {
    io: Arc<UdpSocket>,
    obfs: Arc<SalamanderObfuscator>,
    /// 发送暂存（salt+XOR 后的 wire 包），避免逐包分配。
    send_scratch: Mutex<Vec<u8>>,
    /// 接收暂存（wire 包先落此处，剥 salt 后拷入 quinn 缓冲——quinn 缓冲按明文大小分配）。
    recv_scratch: Mutex<Vec<u8>>,
}

impl std::fmt::Debug for SalamanderSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SalamanderSocket")
            .field("local", &self.io.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl SalamanderSocket {
    /// bind UDP socket 并包装 salamander 混淆器。
    ///
    /// 必须在 tokio runtime 上下文内调用（socket 经
    /// [`xray_transport::sockopt::bind_udp_endpoint`] 创建后转 tokio）。
    pub async fn bind(
        obfs: Arc<SalamanderObfuscator>,
        bind_addr: SocketAddr,
        sockopt: &xray_transport::sockopt::SocketOptions,
    ) -> io::Result<Arc<Self>> {
        let std_sock = xray_transport::sockopt::bind_udp_endpoint(bind_addr, sockopt)?;
        Ok(Arc::new(Self {
            io: Arc::new(UdpSocket::from_std(std_sock)?),
            obfs,
            send_scratch: Mutex::new(vec![0u8; MAX_WIRE_DATAGRAM]),
            recv_scratch: Mutex::new(vec![0u8; MAX_WIRE_DATAGRAM]),
        }))
    }

    /// 构造注入 quinn 用的 endpoint（client 侧，`server_config = None`）。
    ///
    /// 等价 `Endpoint::client(bind_addr)`，仅 socket 换成 salamander 包装。
    pub fn client_endpoint(self: &Arc<Self>) -> io::Result<quinn::Endpoint> {
        endpoint_with_socket(None, self.clone())
    }

    /// 构造注入 quinn 用的 endpoint（server 侧）。
    ///
    /// 等价 `Endpoint::server(server_config, bind_addr)`，仅 socket 换成 salamander 包装。
    pub fn server_endpoint(
        self: &Arc<Self>,
        server_config: quinn::ServerConfig,
    ) -> io::Result<quinn::Endpoint> {
        endpoint_with_socket(Some(server_config), self.clone())
    }
}

/// `new_with_abstract_socket` 公共路径（client/server 唯一差别是 `server_config`；
/// salamander / gecko 两种包装 socket 共用）。
pub(crate) fn endpoint_with_socket<S: AsyncUdpSocket>(
    server_config: Option<quinn::ServerConfig>,
    socket: Arc<S>,
) -> io::Result<quinn::Endpoint> {
    let runtime = quinn::default_runtime()
        .ok_or_else(|| io::Error::other("no async runtime found for quinn endpoint"))?;
    quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        server_config,
        socket,
        runtime,
    )
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(WritablePoller::new(self.io.clone()))
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            // max_transmit_segments()==1 时 quinn 不应构造多段 Transmit
            return Err(io::Error::other(
                "salamander socket: multi-segment (GSO) transmit unsupported",
            ));
        }
        let mut out = self.send_scratch.lock();
        let n = self.obfs.obfuscate(transmit.contents, &mut out);
        if n == 0 {
            return Err(io::Error::other("salamander obfuscate: transmit too large"));
        }
        self.io.try_send_to(&out[..n], transmit.destination).map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            // 就绪注册（WouldBlock 时挂 waker，Pending 返回）
            match self.io.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => {},
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            // try_recv_from 内部即 try_io(READABLE)，WouldBlock 时正确清除就绪状态。
            // 收到包：剥 salt+XOR 写入 quinn 缓冲；短包（≤ salt）丢弃继续读。
            let decoded = {
                let mut raw = self.recv_scratch.lock();
                self.io.try_recv_from(&mut raw[..]).map(|(n, addr)| {
                    let payload = self.obfs.deobfuscate(&raw[..n], &mut *bufs[0]);
                    (payload, addr)
                })
            };
            match decoded {
                Ok((payload, addr)) if payload > 0 => {
                    meta[0] =
                        RecvMeta { addr, len: payload, stride: payload, ecn: None, dst_ip: None };
                    return Poll::Ready(Ok(1));
                },
                Ok(_) => continue, // Short packet (≤ salt) dropped, keep reading
                Err(_) => continue, /* WouldBlock → hang waker; other IO errors retry same as
                                     * quinn tokio impl */
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

/// 写就绪 poller——逐字复刻 quinn 私有 `UdpPollHelper`（runtime.rs:105-154）：
/// 首次 poll 创建 `writable()` future，Ready 后丢弃、下次 poll 重建。
pub(crate) struct WritablePoller {
    io: Arc<UdpSocket>,
    fut: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
}

impl WritablePoller {
    pub(crate) fn new(io: Arc<UdpSocket>) -> Self {
        Self { io, fut: None }
    }
}

impl UdpPoller for WritablePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.fut.is_none() {
            // future 持有 socket 句柄 clone（async block 内持有 → 'static）
            let io = Arc::clone(&this.io);
            this.fut = Some(Box::pin(async move { io.writable().await }));
        }
        let result = this.fut.as_mut().unwrap().as_mut().poll(cx);
        if result.is_ready() {
            this.fut = None;
        }
        result
    }
}

impl std::fmt::Debug for WritablePoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WritablePoller").finish_non_exhaustive()
    }
}

/// 从 `streamSettings.finalmask` JSON 提取 UDP 混淆配置（hysteria QUIC 路径）。
///
/// 对应 Go `infra/conf`：`finalmask.udp[]` 每项 `{"type", "settings"}`，
/// `type == "salamander"` → `Salamander.Build()`（transport_finalmask.go:638-652）：
/// `settings.packetSize` 缺省/`To == 0` → [`UdpObfs::Salamander`]；
/// `To > 0` → Gecko 分片模式 [`UdpObfs::Gecko`]（校验 `From > 0 && To <= 2048`）。
///
/// - 无 `finalmask` / 无 `udp` 数组 / 空数组 → `Ok(None)`（不包装，行为不变）
/// - `settings.password`（≥4 字节，两种模式同要求）提前构造校验
/// - 其它 mask type：报错（不静默丢配置，与 `parse_finalmask_udp_chain` 策略一致）
///
/// # Errors
/// `InvalidInput`：未知 type / packetSize 非法 / 多条目 / PSK 过短。
pub fn parse_udp_obfs(finalmask_json: Option<&serde_json::Value>) -> io::Result<Option<UdpObfs>> {
    let Some(v) = finalmask_json else { return Ok(None) };
    let Some(udp) = v.get("udp").and_then(|u| u.as_array()) else {
        return Ok(None);
    };
    let mut result: Option<UdpObfs> = None;
    for entry in udp {
        let ty = entry.get("type").and_then(|t| t.as_str()).unwrap_or_default();
        if ty != "salamander" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "hysteria finalmask: unsupported udp mask type {ty:?} \
                     (supported: salamander)"
                ),
            ));
        }
        let settings = entry.get("settings").cloned().unwrap_or_default();
        let password = settings.get("password").and_then(|p| p.as_str()).unwrap_or_default();
        // PSK 校验（Go Build 两种模式共享 SalamanderObfuscator 前置条件 ≥4B）
        let obfs = SalamanderObfuscator::new(password.as_bytes()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("hysteria finalmask salamander: {e}"),
            )
        })?;
        let kind = match packet_size_range(settings.get("packetSize"))? {
            // Go transport_finalmask.go:639：`To > 0` 才切 Gecko；To <= 0（含缺省/""）
            // 短路回 plain salamander，不做区间校验
            Some((from, to)) if to > 0 => {
                // Go transport_finalmask.go:640-642
                if from <= 0 || to > 2048 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "hysteria finalmask: gecko: invalid min/max packet size",
                    ));
                }
                UdpObfs::Gecko(GeckoConfig {
                    password: password.to_owned(),
                    min_packet_size: from as u32,
                    max_packet_size: to as u32,
                })
            },
            _ => UdpObfs::Salamander(Arc::new(obfs)),
        };
        if result.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria finalmask: multiple salamander entries unsupported",
            ));
        }
        result = Some(kind);
    }
    Ok(result)
}

/// Go `Int32Range`（common.go:316-341 + ParseRangeString）：仅接受整数或
/// `"a-b"` 字符串（支持负数 / `""`→(0,0)）；`{from,to}` 对象**不是** Int32Range
/// 合法形态（Go 直接报错）；from>to 时交换（ensureOrder）。
///
/// 缺失 → `Ok(None)`（= 不启用 Gecko）。非法 → `InvalidInput`。
fn packet_size_range(v: Option<&serde_json::Value>) -> io::Result<Option<(i64, i64)>> {
    let Some(v) = v else { return Ok(None) };
    let (left, right) = if let Some(n) = v.as_i64() {
        (n, n)
    } else if let Some(s) = v.as_str() {
        parse_range_string(s)?
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hysteria finalmask: invalid packetSize, expected integer or \"from-to\" string",
        ));
    };
    Ok(Some((left.min(right), left.max(right))))
}

/// Go `ParseRangeString`（common.go:355-380）：`"114"`→(114,114)、`""`→(0,0)、
/// `"114-514"`/`"-114-514"`/`"-1919--810"`；非法字符串报错。
fn parse_range_string(s: &str) -> io::Result<(i64, i64)> {
    if let Ok(n) = s.parse::<i64>() {
        return Ok((n, n));
    }
    if s.is_empty() {
        return Ok((0, 0));
    }
    // 处理 "-114-514" / "-1919--810"（首个负号属于左值）
    let (l, r) = match s.strip_prefix('-') {
        Some(rest) => match rest.split_once('-') {
            Some((a, b)) => (format!("-{a}"), b.to_owned()),
            None => return Err(invalid_range(s)),
        },
        None => match s.split_once('-') {
            Some((a, b)) => (a.to_owned(), b.to_owned()),
            None => return Err(invalid_range(s)),
        },
    };
    let left = l.parse::<i64>().map_err(|_| invalid_range(s))?;
    let right = r.parse::<i64>().map_err(|_| invalid_range(s))?;
    Ok((left, right))
}

fn invalid_range(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("invalid range string: {s}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noop_cx() -> Context<'static> {
        Context::from_waker(std::task::Waker::noop())
    }

    fn test_obfs() -> Arc<SalamanderObfuscator> {
        Arc::new(SalamanderObfuscator::new(b"unit-test-psk").unwrap())
    }

    #[tokio::test]
    async fn try_send_wraps_salt_and_xor() {
        let sock = SalamanderSocket::bind(
            test_obfs(),
            "127.0.0.1:0".parse().unwrap(),
            &Default::default(),
        )
        .await
        .unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap()).await.unwrap();
        let plain = b"plaintext quic packet";

        // AsyncUdpSocket 契约：try_send 可能 WouldBlock，先经 poller 等写就绪
        // （生产路径 quinn endpoint driver 同样先 poll_writable 再 try_send）
        let mut poller = sock.clone().create_io_poller();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(500);
        loop {
            let mut cx = noop_cx();
            if let Poll::Ready(r) = poller.as_mut().poll_writable(&mut cx) {
                r.unwrap();
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "socket never writable");
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        sock.try_send(&Transmit {
            destination: peer.local_addr().unwrap(),
            ecn: None,
            contents: plain,
            segment_size: None,
            src_ip: None,
        })
        .unwrap();

        let mut wire = vec![0u8; 64 * 1024];
        let n = peer.recv(&mut wire).await.unwrap();
        assert_eq!(n, plain.len() + SALT_LEN, "wire = salt + ciphertext");

        // 独立 obfuscator（同 PSK）解出明文——发送方向确实过 XOR
        let mut decoded = vec![0u8; n];
        let dn = test_obfs().deobfuscate(&wire[..n], &mut decoded);
        assert_eq!(&decoded[..dn], plain);
        // 明文不应在 wire 上裸奔
        assert!(!wire[..n].windows(plain.len()).any(|w| w == plain));
    }

    #[tokio::test]
    async fn poll_recv_unwraps_inbound() {
        let sock = SalamanderSocket::bind(
            test_obfs(),
            "127.0.0.1:0".parse().unwrap(),
            &Default::default(),
        )
        .await
        .unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap()).await.unwrap();

        // 对端用 salamander 加密后发来
        let plain = b"server response";
        let mut wire = vec![0u8; plain.len() + SALT_LEN];
        let wn = test_obfs().obfuscate(plain, &mut wire);
        peer.send_to(&wire[..wn], sock.local_addr().unwrap()).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let mut iovs = [IoSliceMut::new(&mut buf)];
        let mut metas = [RecvMeta::default()];
        // 就绪可能需等一拍：轮询直到 Ready（500ms 上限）
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(500);
        let n = loop {
            let mut cx = noop_cx();
            if let Poll::Ready(r) = sock.poll_recv(&mut cx, &mut iovs, &mut metas) {
                break r.unwrap();
            }
            assert!(tokio::time::Instant::now() < deadline, "obfuscated packet not received");
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        };
        assert_eq!(n, 1);
        assert_eq!(metas[0].len, plain.len());
        assert_eq!(metas[0].stride, plain.len());
        assert_eq!(&buf[..plain.len()], plain);
    }

    #[tokio::test]
    async fn poll_recv_drops_short_packet_then_recovers() {
        let sock = SalamanderSocket::bind(
            test_obfs(),
            "127.0.0.1:0".parse().unwrap(),
            &Default::default(),
        )
        .await
        .unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap()).await.unwrap();
        let dst = sock.local_addr().unwrap();

        // 短包（≤8B）：应被丢弃，poll 返回 Pending
        peer.send_to(b"tiny", dst).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let mut buf = vec![0u8; 1500];
        let mut iovs = [IoSliceMut::new(&mut buf)];
        let mut metas = [RecvMeta::default()];
        let mut cx = noop_cx();
        assert!(matches!(sock.poll_recv(&mut cx, &mut iovs, &mut metas), Poll::Pending));

        // 随后好包正常恢复
        let plain = b"good packet after drop";
        let mut wire = vec![0u8; plain.len() + SALT_LEN];
        let wn = test_obfs().obfuscate(plain, &mut wire);
        peer.send_to(&wire[..wn], dst).await.unwrap();

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(500);
        loop {
            let mut cx = noop_cx();
            if let Poll::Ready(r) = sock.poll_recv(&mut cx, &mut iovs, &mut metas) {
                assert_eq!(r.unwrap(), 1);
                assert_eq!(metas[0].len, plain.len());
                assert_eq!(&buf[..plain.len()], plain);
                return;
            }
            assert!(tokio::time::Instant::now() < deadline, "good packet not recovered");
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }

    #[test]
    fn parse_udp_obfs_none_cases() {
        assert!(parse_udp_obfs(None).unwrap().is_none());
        let v: serde_json::Value = serde_json::from_str(r#"{"tcp":[]}"#).unwrap();
        assert!(parse_udp_obfs(Some(&v)).unwrap().is_none());
        let v: serde_json::Value = serde_json::from_str(r#"{"udp":[]}"#).unwrap();
        assert!(parse_udp_obfs(Some(&v)).unwrap().is_none());
    }

    #[test]
    fn parse_udp_obfs_plain_salamander() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"udp":[{"type":"salamander","settings":{"password":"obfs-secret-1"}}]}"#,
        )
        .unwrap();
        assert!(matches!(parse_udp_obfs(Some(&v)).unwrap(), Some(UdpObfs::Salamander(_))));
        // packetSize To==0 的各形态 → 仍是 plain salamander（Go Build 同语义）
        for ps in ["0", "\"0\"", "\"\""] {
            let v: serde_json::Value = serde_json::from_str(&format!(
                r#"{{"udp":[{{"type":"salamander","settings":{{"password":"obfs-secret-1","packetSize":{ps}}}}}]}}"#
            ))
            .unwrap();
            assert!(
                matches!(parse_udp_obfs(Some(&v)).unwrap(), Some(UdpObfs::Salamander(_))),
                "ps={ps}"
            );
        }
    }

    #[test]
    fn parse_udp_obfs_gecko_mode() {
        // 字符串区间形态（Go Int32Range 唯一字符串路径）
        let v: serde_json::Value = serde_json::from_str(
            r#"{"udp":[{"type":"salamander","settings":{"password":"obfs-secret-1","packetSize":"512-1200"}}]}"#,
        )
        .unwrap();
        match parse_udp_obfs(Some(&v)).unwrap() {
            Some(UdpObfs::Gecko(cfg)) => {
                assert_eq!(cfg.password, "obfs-secret-1");
                assert_eq!((cfg.min_packet_size, cfg.max_packet_size), (512, 1200));
            },
            other => panic!("expected gecko, got {other:?}"),
        }
        // 整数形态 → from=to
        let v: serde_json::Value = serde_json::from_str(
            r#"{"udp":[{"type":"salamander","settings":{"password":"obfs-secret-1","packetSize":1500}}]}"#,
        )
        .unwrap();
        match parse_udp_obfs(Some(&v)).unwrap() {
            Some(UdpObfs::Gecko(cfg)) => {
                assert_eq!((cfg.min_packet_size, cfg.max_packet_size), (1500, 1500));
            },
            other => panic!("expected gecko, got {other:?}"),
        }
        // from>to 交换（Go ensureOrder）
        let v: serde_json::Value = serde_json::from_str(
            r#"{"udp":[{"type":"salamander","settings":{"password":"obfs-secret-1","packetSize":"1200-512"}}]}"#,
        )
        .unwrap();
        match parse_udp_obfs(Some(&v)).unwrap() {
            Some(UdpObfs::Gecko(cfg)) => {
                assert_eq!((cfg.min_packet_size, cfg.max_packet_size), (512, 1200));
            },
            other => panic!("expected gecko, got {other:?}"),
        }
    }

    #[test]
    fn parse_udp_obfs_rejects_bad_config() {
        // 未知 type
        let v: serde_json::Value =
            serde_json::from_str(r#"{"udp":[{"type":"noise","settings":{}}]}"#).unwrap();
        assert!(parse_udp_obfs(Some(&v)).is_err());
        // PSK 过短（< 4 字节）
        let v: serde_json::Value =
            serde_json::from_str(r#"{"udp":[{"type":"salamander","settings":{"password":"ab"}}]}"#)
                .unwrap();
        assert!(parse_udp_obfs(Some(&v)).is_err());
        // packetSize 对象形态：Go Int32Range 只收整数/字符串，对象直接报错
        let v: serde_json::Value = serde_json::from_str(
            r#"{"udp":[{"type":"salamander","settings":{"password":"obfs-secret-1","packetSize":{"from":512,"to":1200}}}]}"#,
        )
        .unwrap();
        assert!(parse_udp_obfs(Some(&v)).is_err());
        // Gecko 区间非法：From <= 0 / To > 2048（Go transport_finalmask.go:640）
        for ps in ["\"0-1200\"", "\"-512-1200\"", "\"512-2049\"", "\"512-4096\""] {
            let v: serde_json::Value = serde_json::from_str(&format!(
                r#"{{"udp":[{{"type":"salamander","settings":{{"password":"obfs-secret-1","packetSize":{ps}}}}}]}}"#
            ))
            .unwrap();
            assert!(parse_udp_obfs(Some(&v)).is_err(), "ps={ps}");
        }
        // 多条 salamander
        let v: serde_json::Value = serde_json::from_str(
            r#"{"udp":[{"type":"salamander","settings":{"password":"obfs-secret-1"}},{"type":"salamander","settings":{"password":"obfs-secret-2"}}]}"#,
        )
        .unwrap();
        assert!(parse_udp_obfs(Some(&v)).is_err());
    }
}
