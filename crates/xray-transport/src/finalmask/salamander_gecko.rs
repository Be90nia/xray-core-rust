//! # Salamander Gecko 子模式（QUIC 长头部分片重组）
//!
//! 对应 Go `transport/internet/finalmask/salamander/gecko.go` + `conn.go` 的 Gecko 部分。
//!
//! ## 原理
//!
//! 在 Salamander BLAKE2b-256 XOR 混淆之上，把 QUIC 长头包（首字节 `0x80` 位 set）
//! 拆成 2-8 个分片，每个分片加 Gecko frame header 后再 Salamander 加密发出。
//! 接收端按 `(src_addr, msg_id)` 重组，全部分片到齐后还原原始 QUIC 包。
//! QUIC 短头包透传。
//!
//! ## 内存限制
//!
//! - 全局 reassembly 表上限 4096 条（LRU 驱逐）
//! - 每个 source 地址上限 8 条
//! - 单条 TTL = 8 秒，后台 GC ticker = 4 秒

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;
use rand::{Rng, RngCore};
use tokio::task::AbortHandle;

use super::salamander::SalamanderObfuscator;
use super::{UdpIo, Udpmask, UDP_SIZE};

/// Gecko frame header 标志位（首字节高 bit set = 分片帧）。
const GECKO_FLAG_FRAGMENT: u8 = 0x80;
/// Gecko frame header 固定长度（5 字节：flag + msgID + chunkIdx/total + padLen u16）。
const GECKO_HEADER_SIZE: usize = 5;
/// 单 source 地址最大 reassembly 条目数。
const GECKO_MAX_PER_SOURCE: usize = 8;
/// 全局最大 reassembly 条目数（超限时 LRU 驱逐）。
const GECKO_MAX_REASSEMBLY: usize = 4096;
/// reassembly 缓冲区大小。
const GECKO_BUFFER_SIZE: usize = 2048;
/// 单条 reassembly 默认最小包大小。
const GECKO_DEFAULT_MIN_PACKET: u32 = 512;
/// 单条 reassembly 默认最大包大小。
const GECKO_DEFAULT_MAX_PACKET: u32 = 1200;
/// reassembly TTL（超时丢弃）。
const GECKO_REASSEMBLY_TTL: Duration = Duration::from_secs(8);
/// GC ticker 周期。
const GECKO_GC_INTERVAL: Duration = Duration::from_secs(4);
/// 分片块数下限。
const GECKO_MIN_FRAGMENT_CHUNKS: usize = 2;
/// 分片块数上限。
const GECKO_MAX_FRAGMENT_CHUNKS: usize = 8;
/// Salamander salt 长度。
const SM_SALT_LEN: usize = 8;

/// Gecko frame header（对应 Go `frameHeader`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub pad_len: u16,
    pub msg_id: u8,
    pub chunk_idx: u8,
    pub total_chunks: u8,
}

/// 编码 frame 到 `out`（对应 Go `encodeFrame`）。
///
/// `out` 长度必须 ≥ `GECKO_HEADER_SIZE + pad_len + payload.len()`。
///
/// # Errors
/// - `InvalidData`：`total_chunks` 不在 `[2, 8]`，或 `chunk_idx >= total_chunks`，或 `out` 过短。
pub fn encode_frame(h: &FrameHeader, payload: &[u8], out: &mut [u8]) -> io::Result<usize> {
    if h.total_chunks < GECKO_MIN_FRAGMENT_CHUNKS as u8
        || h.total_chunks > GECKO_MAX_FRAGMENT_CHUNKS as u8
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gecko: total_chunks out of range [2, 8]",
        ));
    }
    if h.chunk_idx >= h.total_chunks {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gecko: chunk_idx >= total_chunks",
        ));
    }
    let needed = GECKO_HEADER_SIZE + h.pad_len as usize + payload.len();
    if out.len() < needed {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gecko: out buffer truncated",
        ));
    }
    out[0] = GECKO_FLAG_FRAGMENT;
    out[1] = h.msg_id;
    out[2] = (h.chunk_idx << 4) | (h.total_chunks & 0x0F);
    out[3..5].copy_from_slice(&h.pad_len.to_be_bytes());
    // 填充随机 padding
    rand::rng().fill_bytes(&mut out[GECKO_HEADER_SIZE..GECKO_HEADER_SIZE + h.pad_len as usize]);
    out[GECKO_HEADER_SIZE + h.pad_len as usize..needed].copy_from_slice(payload);
    Ok(needed)
}

/// 解码 frame，返回 `(header, payload_start, payload_len)`（对应 Go `decodeFrame`）。
///
/// payload 是 `in[payload_start..payload_start + payload_len]`。
///
/// # Errors
/// - `InvalidData`：长度不足、flag 位未 set、字段越界。
pub fn decode_frame(input: &[u8]) -> io::Result<(FrameHeader, usize, usize)> {
    if input.len() < GECKO_HEADER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gecko: frame truncated",
        ));
    }
    if input[0] & GECKO_FLAG_FRAGMENT == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gecko: not a fragment frame",
        ));
    }
    let h = FrameHeader {
        msg_id: input[1],
        chunk_idx: input[2] >> 4,
        total_chunks: input[2] & 0x0F,
        pad_len: u16::from_be_bytes([input[3], input[4]]),
    };
    if h.total_chunks < GECKO_MIN_FRAGMENT_CHUNKS as u8
        || h.total_chunks > GECKO_MAX_FRAGMENT_CHUNKS as u8
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gecko: total_chunks out of range [2, 8]",
        ));
    }
    if h.chunk_idx >= h.total_chunks {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gecko: chunk_idx >= total_chunks",
        ));
    }
    let payload_start = GECKO_HEADER_SIZE + h.pad_len as usize;
    if payload_start > input.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gecko: padding exceeds frame",
        ));
    }
    Ok((h, payload_start, input.len()))
}

/// Gecko 配置（对应 Go `salamander.GckoConfig`）。
#[derive(Debug, Clone, Default)]
pub struct GeckoConfig {
    /// PSK（password），最少 4 字节。
    pub password: String,
    /// 目标最小包大小（0 = 默认 512）。
    pub min_packet_size: u32,
    /// 目标最大包大小（0 = 默认 1200）。
    pub max_packet_size: u32,
}

/// reassembly 表 key（对应 Go `reassemblyKey`）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReassemblyKey {
    addr: String,
    msg_id: u8,
}

/// reassembly 表项（对应 Go `reassemblyEntry`）。
struct ReassemblyEntry {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    total: u8,
    deadline: Instant,
}

/// GeckoConn 共享状态（GC task 与 conn 共享）。
#[derive(Default)]
struct GeckoState {
    reassembly: HashMap<ReassemblyKey, ReassemblyEntry>,
    per_source: HashMap<String, usize>,
}

/// Gecko PacketConn 包装（对应 Go `geckoConn`）。
pub struct GeckoConn {
    inner: Box<dyn UdpIo>,
    obfs: SalamanderObfuscator,
    min_pkt: usize,
    max_pkt: usize,
    msg_id: AtomicU32,
    state: Arc<Mutex<GeckoState>>,
    gc_abort: AbortHandle,
}

impl GeckoConn {
    /// 构造 GeckoConn，启动 GC 后台 task。
    ///
    /// # Errors
    /// - `InvalidInput`：PSK 过短，或 min/max packet 非法。
    pub fn new(config: &GeckoConfig, raw: Box<dyn UdpIo>) -> io::Result<Self> {
        let obfs = SalamanderObfuscator::new(config.password.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut min_pkt = config.min_packet_size;
        let mut max_pkt = config.max_packet_size;
        if min_pkt == 0 {
            min_pkt = GECKO_DEFAULT_MIN_PACKET;
        }
        if max_pkt == 0 {
            max_pkt = GECKO_DEFAULT_MAX_PACKET;
        }
        if min_pkt == 0 || min_pkt > max_pkt || max_pkt as usize > GECKO_BUFFER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gecko: invalid min/max packet size",
            ));
        }
        let state = Arc::new(Mutex::new(GeckoState::default()));
        let gc_abort = spawn_gc_task(state.clone());
        Ok(Self {
            inner: raw,
            obfs,
            min_pkt: min_pkt as usize,
            max_pkt: max_pkt as usize,
            msg_id: AtomicU32::new(0),
            state,
            gc_abort,
        })
    }

    /// 下一个 msg_id（u8 wrap-around，对应 Go `atomic.Uint32.Add(1)` 强转 u8）。
    fn next_msg_id(&self) -> u8 {
        let v = self.msg_id.fetch_add(1, Ordering::Relaxed);
        v as u8
    }

    /// 随机分片块数 `[2, 8]`（对应 Go `randomFragmentChunks`）。
    fn random_fragment_chunks() -> usize {
        rand::rng().random_range(GECKO_MIN_FRAGMENT_CHUNKS..=GECKO_MAX_FRAGMENT_CHUNKS)
    }

    /// 随机 padding 长度（对应 Go `randomPadLen`）。
    ///
    /// 使最终包大小落入 `[min_pkt, max_pkt]`，否则返回 0（不加 padding）。
    fn random_pad_len(&self, chunk_len: usize) -> usize {
        let base = SM_SALT_LEN + GECKO_HEADER_SIZE + chunk_len;
        let lo = self.min_pkt.max(base);
        if lo > self.max_pkt {
            return 0;
        }
        let extra = self.max_pkt - lo + 1;
        lo - base + rand::rng().random_range(0..extra)
    }

    /// Salamander-obfuscate 后写入 inner（对应 Go `writeObfs`）。
    async fn write_obfs(&self, p: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let mut out = vec![0u8; p.len() + SM_SALT_LEN];
        let n = self.obfs.obfuscate(p, &mut out);
        if n == 0 {
            return Err(io::Error::other("gecko: obfuscate produced 0"));
        }
        self.inner.send_to(&out[..n], addr).await
    }

    /// Salamander-deobfuscate 读取（对应 Go `readObfs`）。
    ///
    /// 过短包（< salt）丢弃继续读。
    async fn read_obfs(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let mut raw = vec![0u8; buf.len() + SM_SALT_LEN];
            let (n, addr) = self.inner.recv_from(&mut raw).await?;
            if n < SM_SALT_LEN {
                continue;
            }
            let payload_len = self.obfs.deobfuscate(&raw[..n], buf);
            if payload_len == 0 {
                continue;
            }
            return Ok((payload_len, addr));
        }
    }

    /// 分片写入 QUIC 长头包（对应 Go `writeFragmented`）。
    async fn write_fragmented(&self, p: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let chunks = Self::random_fragment_chunks();
        let chunk_size = p.len() / chunks;
        let msg_id = self.next_msg_id();
        for i in 0..chunks {
            let start = i * chunk_size;
            let end = if i < chunks - 1 {
                start + chunk_size
            } else {
                p.len()
            };
            let chunk = &p[start..end];
            let pad_len = self.random_pad_len(chunk.len());
            let mut frame = vec![0u8; GECKO_HEADER_SIZE + pad_len + chunk.len()];
            let n = encode_frame(
                &FrameHeader {
                    pad_len: pad_len as u16,
                    msg_id,
                    chunk_idx: i as u8,
                    total_chunks: chunks as u8,
                },
                chunk,
                &mut frame,
            )?;
            self.write_obfs(&frame[..n], addr).await?;
        }
        Ok(p.len())
    }

    /// 接收并处理分片（对应 Go `acceptChunk`）。
    ///
    /// 返回 `Some(reassembled)` 当全部分片到齐，否则 `None`（继续读）。
    fn accept_chunk(&self, key: &ReassemblyKey, h: &FrameHeader, payload: &[u8]) -> Option<Vec<u8>> {
        let mut state = self.state.lock();
        // 已存在 → 校验 total 一致；不存在 → 新建（检查 cap）
        let exists = state.reassembly.contains_key(key);
        if !exists {
            if state.per_source.get(&key.addr).copied().unwrap_or(0) >= GECKO_MAX_PER_SOURCE {
                return None;
            }
            if state.reassembly.len() >= GECKO_MAX_REASSEMBLY {
                evict_oldest(&mut state);
            }
            state.reassembly.insert(
                key.clone(),
                ReassemblyEntry {
                    chunks: vec![None; h.total_chunks as usize],
                    received: 0,
                    total: h.total_chunks,
                    deadline: Instant::now() + GECKO_REASSEMBLY_TTL,
                },
            );
            *state.per_source.entry(key.addr.clone()).or_insert(0) += 1;
        } else if state.reassembly[key].total != h.total_chunks {
            return None;
        }

        let entry = state.reassembly.get_mut(key).unwrap();
        let idx = h.chunk_idx as usize;
        if idx >= entry.chunks.len() || entry.chunks[idx].is_some() {
            return None;
        }
        entry.chunks[idx] = Some(payload.to_vec());
        entry.received += 1;
        if (entry.received as u8) < entry.total {
            return None;
        }

        // 全部分片到齐 → 重组
        let mut out = Vec::new();
        for c in entry.chunks.drain(..).flatten() {
            out.extend(c);
        }
        drop_entry(&mut state, key);
        Some(out)
    }
}

impl Drop for GeckoConn {
    fn drop(&mut self) {
        // GC task 持有 Arc<Mutex<GeckoState>>，GeckoConn drop 时 abort 它。
        self.gc_abort.abort();
    }
}

impl Udpmask for GeckoConfig {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        let conn = GeckoConn::new(self, raw)?;
        Ok(Box::new(conn))
    }

    fn wrap_packet_conn_server(
        &self,
        raw: Box<dyn UdpIo>,
        level: usize,
        level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        self.wrap_packet_conn_client(raw, level, level_count)
    }
}

#[async_trait]
impl UdpIo for GeckoConn {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if buf[0] & 0x80 != 0 {
            // QUIC 长头 → 分片
            self.write_fragmented(buf, addr).await
        } else {
            // QUIC 短头 → 透传（仅 Salamander 加密）
            self.write_obfs(buf, addr).await
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut raw = vec![0u8; UDP_SIZE];
        loop {
            let (n, addr) = self.read_obfs(&mut raw).await?;
            if n == 0 {
                continue;
            }
            // 顶位 0 → 短头包/垃圾，透传给 QUIC 处理
            if raw[0] & 0x80 == 0 {
                let len = n.min(buf.len());
                buf[..len].copy_from_slice(&raw[..len]);
                return Ok((len, addr));
            }
            // 顶位 1 → Gecko 分片帧
            let (header, payload_start, payload_end) = match decode_frame(&raw[..n]) {
                Ok(v) => v,
                Err(_) => continue, // malformed，静默丢弃
            };
            let key = ReassemblyKey {
                addr: addr.to_string(),
                msg_id: header.msg_id,
            };
            match self.accept_chunk(&key, &header, &raw[payload_start..payload_end]) {
                Some(data) => {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    return Ok((len, addr));
                }
                None => continue, // 等待更多分片
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

// =============================================================================
// 状态操作 helper（GC task 与 accept_chunk 共用）
// =============================================================================

/** 删除一条 reassembly 表项（同步更新 per_source 计数）。 */
fn drop_entry(state: &mut GeckoState, key: &ReassemblyKey) {
    if state.reassembly.remove(key).is_some() {
        let dec = state.per_source.get_mut(&key.addr);
        if let Some(count) = dec {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.per_source.remove(&key.addr);
            }
        }
    }
}

/** 全局 cap 触发时驱逐最旧（deadline 最早）的 entry（对应 Go `evictOldestLocked`）。 */
fn evict_oldest(state: &mut GeckoState) {
    let oldest_key = state
        .reassembly
        .iter()
        .min_by_key(|(_, e)| e.deadline)
        .map(|(k, _)| k.clone());
    if let Some(k) = oldest_key {
        drop_entry(state, &k);
    }
}

/// 后台 GC task：周期性扫描过期 entry（对应 Go `gcLoop`）。
fn spawn_gc_task(state: Arc<Mutex<GeckoState>>) -> AbortHandle {
    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(GECKO_GC_INTERVAL);
        interval.tick().await; // 跳过立即触发的首次
        loop {
            interval.tick().await;
            let mut s = state.lock();
            let now = Instant::now();
            let expired: Vec<ReassemblyKey> = s
                .reassembly
                .iter()
                .filter(|(_, e)| now > e.deadline)
                .map(|(k, _)| k.clone())
                .collect();
            for k in expired {
                drop_entry(&mut s, &k);
            }
        }
    });
    handle.abort_handle()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_frame_roundtrip() {
        let payload = b"hello gecko";
        let h = FrameHeader {
            pad_len: 4,
            msg_id: 7,
            chunk_idx: 1,
            total_chunks: 3,
        };
        let mut out = vec![0u8; GECKO_HEADER_SIZE + 4 + payload.len()];
        let n = encode_frame(&h, payload, &mut out).unwrap();
        assert_eq!(n, out.len());

        let (h2, start, end) = decode_frame(&out).unwrap();
        assert_eq!(h2, h);
        assert_eq!(&out[start..end], payload);
    }

    #[test]
    fn encode_frame_rejects_bad_total() {
        let h = FrameHeader {
            pad_len: 0,
            msg_id: 0,
            chunk_idx: 0,
            total_chunks: 1, // < 2
        };
        let mut out = [0u8; 16];
        assert!(encode_frame(&h, b"x", &mut out).is_err());

        let h2 = FrameHeader {
            pad_len: 0,
            msg_id: 0,
            chunk_idx: 0,
            total_chunks: 9, // > 8
        };
        assert!(encode_frame(&h2, b"x", &mut out).is_err());
    }

    #[test]
    fn encode_frame_rejects_chunk_idx_ge_total() {
        let h = FrameHeader {
            pad_len: 0,
            msg_id: 0,
            chunk_idx: 3,
            total_chunks: 3,
        };
        let mut out = [0u8; 16];
        assert!(encode_frame(&h, b"x", &mut out).is_err());
    }

    #[test]
    fn decode_frame_rejects_non_fragment() {
        let mut input = [GECKO_FLAG_FRAGMENT; GECKO_HEADER_SIZE];
        input[0] = 0; // 清掉 flag 位
        assert!(decode_frame(&input).is_err());
    }

    #[test]
    fn decode_frame_rejects_truncated() {
        assert!(decode_frame(&[0x80, 1]).is_err()); // < 5 字节
    }

    #[test]
    fn random_fragment_chunks_in_range() {
        for _ in 0..100 {
            let n = GeckoConn::random_fragment_chunks();
            assert!((GECKO_MIN_FRAGMENT_CHUNKS..=GECKO_MAX_FRAGMENT_CHUNKS).contains(&n));
        }
    }

    #[tokio::test]
    async fn random_pad_len_respects_bounds() {
        let conn = mock_conn_with_bounds(100, 200);
        // chunk_len=10 → base = 8+5+10 = 23
        // pad 应使最终大小 (8 + 5 + pad + 10) ∈ [100, 200]
        for _ in 0..100 {
            let pad = conn.random_pad_len(10);
            let total = SM_SALT_LEN + GECKO_HEADER_SIZE + pad + 10;
            assert!(total >= 100 && total <= 200, "total={total}, pad={pad}");
        }
    }

    #[tokio::test]
    async fn random_pad_len_zero_when_base_exceeds_max() {
        let conn = mock_conn_with_bounds(50, 60);
        // chunk_len=100 → base=113 > max=60 → pad 应为 0
        assert_eq!(conn.random_pad_len(100), 0);
    }

    /// 构造一个 mock GeckoConn（绕过 UdpIo，仅测 pad/bounds）。
    fn mock_conn_with_bounds(min_pkt: u32, max_pkt: u32) -> GeckoConn {
        // 注入 dummy inner：用 closure mock 不现实，直接构造字段
        // 通过 GeckoConfig::new 走完整流程，inner 是 MockUdpIo。
        let cfg = GeckoConfig {
            password: "test-password-123".into(),
            min_packet_size: min_pkt,
            max_packet_size: max_pkt,
        };
        let inner: Box<dyn UdpIo> = Box::new(MockUdpIo);
        GeckoConn::new(&cfg, inner).unwrap()
    }

    struct MockUdpIo;

    #[async_trait]
    impl UdpIo for MockUdpIo {
        async fn send_to(&self, _: &[u8], _: SocketAddr) -> io::Result<usize> {
            Ok(0)
        }
        async fn recv_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::new(io::ErrorKind::Other, "mock"))
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Err(io::Error::new(io::ErrorKind::Other, "mock"))
        }
    }

    #[tokio::test]
    async fn gecko_roundtrip_quic_long_header() {
        // 端到端：gecko client 发，gecko server 收 → 还原
        use tokio::net::UdpSocket;

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let cfg = GeckoConfig {
            password: "roundtrip-password".into(),
            ..Default::default()
        };
        let gecko_client: Box<dyn UdpIo> = cfg
            .wrap_packet_conn_client(Box::new(client), 0, 0)
            .unwrap();
        let gecko_server: Box<dyn UdpIo> = cfg
            .wrap_packet_conn_server(Box::new(server), 0, 0)
            .unwrap();

        // QUIC 长头包：首字节 & 0x80 != 0
        let original: Vec<u8> = std::iter::once(0x80u8)
            .chain(std::iter::repeat_n(0xAB, 100))
            .collect();
        gecko_client
            .send_to(&original, server_addr)
            .await
            .unwrap();

        let mut buf = vec![0u8; UDP_SIZE];
        let (n, _) = gecko_server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &original);
    }

    #[tokio::test]
    async fn gecko_short_header_passthrough() {
        use tokio::net::UdpSocket;

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let cfg = GeckoConfig {
            password: "roundtrip-password".into(),
            ..Default::default()
        };
        let gecko_client: Box<dyn UdpIo> = cfg
            .wrap_packet_conn_client(Box::new(client), 0, 0)
            .unwrap();
        let gecko_server: Box<dyn UdpIo> = cfg
            .wrap_packet_conn_server(Box::new(server), 0, 0)
            .unwrap();

        // QUIC 短头包：首字节 & 0x80 == 0
        let original: Vec<u8> = vec![0x40, 1, 2, 3, 4, 5];
        gecko_client
            .send_to(&original, server_addr)
            .await
            .unwrap();

        let mut buf = vec![0u8; UDP_SIZE];
        let (n, _) = gecko_server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &original);
    }
}
