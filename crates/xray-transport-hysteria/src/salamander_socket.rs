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
//! - 接收 `poll_recv`：`recv_from` → 剥 salt + XOR 回明文 → 写入 quinn 缓冲；
//!   长度 ≤ salt 的短包丢弃继续读（对齐 Go `headerManagerConn.ReadFrom` 的
//!   drop-and-continue 语义，finalmask.go:134-137）
//!
//! GSO/GRO/ECN 不透传：`max_transmit_segments`/`max_receive_segments` 保持默认 1，
//! quinn 不会构造多段 Transmit；`may_fragment()==true` 使 quinn 关闭路径 MTU 探测
//! （salamander 每包 +8B salt，不探测更稳妥）。XOR 本体复用
//! `xray_transport::finalmask::salamander::SalamanderObfuscator`（非重写）。

use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::net::UdpSocket;
use xray_transport::finalmask::salamander::SalamanderObfuscator;

/// 单个 wire datagram 缓冲上限：QUIC `max_udp_payload_size` 上限 64KiB + salt。
const MAX_WIRE_DATAGRAM: usize = 64 * 1024 + 8;

/// salamander salt 长度（对齐 Go `smSaltLen`；仅用于短包判定文档）。
const SALT_LEN: usize = 8;

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
    /// 必须在 tokio runtime 上下文内调用（`UdpSocket::bind` 注册 reactor）。
    pub async fn bind(obfs: Arc<SalamanderObfuscator>, bind_addr: SocketAddr) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            io: Arc::new(UdpSocket::bind(bind_addr).await?),
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

/// `new_with_abstract_socket` 公共路径（client/server 唯一差别是 `server_config`）。
fn endpoint_with_socket(
    server_config: Option<quinn::ServerConfig>,
    socket: Arc<SalamanderSocket>,
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
        Box::pin(WritablePoller {
            io: self.io.clone(),
            fut: None,
        })
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
                Poll::Ready(Ok(())) => {}
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
                    meta[0] = RecvMeta {
                        addr,
                        len: payload,
                        stride: payload,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
                Ok(_) => continue, // Short packet (≤ salt) dropped, keep reading
                Err(_) => continue, // WouldBlock → hang waker; other IO errors retry same as quinn tokio impl
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

/// 写就绪 poller——逐字复刻 quinn 私有 `UdpPollHelper`（runtime.rs:105-154）：
/// 首次 poll 创建 `writable()` future，Ready 后丢弃、下次 poll 重建。
struct WritablePoller {
    io: Arc<UdpSocket>,
    fut: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
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

/// 从 `streamSettings.finalmask` JSON 提取 salamander 混淆器（hysteria UDP 路径）。
///
/// 对应 Go `infra/conf`：`finalmask.udp[]` 每项 `{"type", "settings"}`，
/// `type == "salamander"` → `salamander.Config{Password}` → 包装 UDP socket
/// （memory_settings.go:70-80 `Udpmasks` → dialer.go:170 `c.udpmaskManager != nil`）。
///
/// - 无 `finalmask` / 无 `udp` 数组 / 空数组 → `Ok(None)`（不包装，行为不变）
/// - `salamander` + `settings.password`（≥4 字节）→ `Some(obfuscator)`
/// - 其它 mask type：报错（不静默丢配置，与 `parse_finalmask_udp_chain` 策略一致）
/// - `settings.packetSize`：Go 侧切换 Gecko 分片模式（transport_internet.go:1761），
///   hysteria QUIC 路径未实现 → 报错
///
/// # Errors
/// `InvalidInput`：未知 type / Gecko 配置 / 多条 salamander / PSK 过短。
pub fn parse_salamander_obfs(
    finalmask_json: Option<&serde_json::Value>,
) -> io::Result<Option<Arc<SalamanderObfuscator>>> {
    let Some(v) = finalmask_json else { return Ok(None) };
    let Some(udp) = v.get("udp").and_then(|u| u.as_array()) else {
        return Ok(None);
    };
    let mut result: Option<Arc<SalamanderObfuscator>> = None;
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
        if settings.get("packetSize").is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria finalmask: salamander gecko mode (packetSize) unsupported",
            ));
        }
        let password = settings.get("password").and_then(|p| p.as_str()).unwrap_or_default();
        let obfs = SalamanderObfuscator::new(password.as_bytes()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("hysteria finalmask salamander: {e}"),
            )
        })?;
        if result.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria finalmask: multiple salamander entries unsupported",
            ));
        }
        result = Some(Arc::new(obfs));
    }
    Ok(result)
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
        let sock = SalamanderSocket::bind(test_obfs(), "127.0.0.1:0".parse().unwrap()).await.unwrap();
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
        let sock = SalamanderSocket::bind(test_obfs(), "127.0.0.1:0".parse().unwrap()).await.unwrap();
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
        let sock = SalamanderSocket::bind(test_obfs(), "127.0.0.1:0".parse().unwrap()).await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap()).await.unwrap();
        let dst = sock.local_addr().unwrap();

        // 短包（≤8B）：应被丢弃，poll 返回 Pending
        peer.send_to(b"tiny", dst).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let mut buf = vec![0u8; 1500];
        let mut iovs = [IoSliceMut::new(&mut buf)];
        let mut metas = [RecvMeta::default()];
        let mut cx = noop_cx();
        assert!(matches!(
            sock.poll_recv(&mut cx, &mut iovs, &mut metas),
            Poll::Pending
        ));

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
    fn parse_salamander_none_cases() {
        assert!(parse_salamander_obfs(None).unwrap().is_none());
        let v: serde_json::Value = serde_json::from_str(r#"{"tcp":[]}"#).unwrap();
        assert!(parse_salamander_obfs(Some(&v)).unwrap().is_none());
        let v: serde_json::Value = serde_json::from_str(r#"{"udp":[]}"#).unwrap();
        assert!(parse_salamander_obfs(Some(&v)).unwrap().is_none());
    }

    #[test]
    fn parse_salamander_found() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"udp":[{"type":"salamander","settings":{"password":"obfs-secret-1"}}]}"#,
        )
        .unwrap();
        assert!(parse_salamander_obfs(Some(&v)).unwrap().is_some());
    }

    #[test]
    fn parse_salamander_rejects_bad_config() {
        // 未知 type
        let v: serde_json::Value =
            serde_json::from_str(r#"{"udp":[{"type":"noise","settings":{}}]}"#).unwrap();
        assert!(parse_salamander_obfs(Some(&v)).is_err());
        // PSK 过短（< 4 字节）
        let v: serde_json::Value = serde_json::from_str(
            r#"{"udp":[{"type":"salamander","settings":{"password":"ab"}}]}"#,
        )
        .unwrap();
        assert!(parse_salamander_obfs(Some(&v)).is_err());
        // Gecko 模式未实现
        let v: serde_json::Value = serde_json::from_str(
            r#"{"udp":[{"type":"salamander","settings":{"password":"obfs-secret-1","packetSize":{"from":512,"to":1200}}}]}"#,
        )
        .unwrap();
        assert!(parse_salamander_obfs(Some(&v)).is_err());
        // 多条 salamander
        let v: serde_json::Value = serde_json::from_str(
            r#"{"udp":[{"type":"salamander","settings":{"password":"obfs-secret-1"}},{"type":"salamander","settings":{"password":"obfs-secret-2"}}]}"#,
        )
        .unwrap();
        assert!(parse_salamander_obfs(Some(&v)).is_err());
    }
}
