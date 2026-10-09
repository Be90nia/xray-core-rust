//! # Noise UDP 噪声注入（对应 Go `noise/`）
//!
//! 在 UDP 真实包发送前，按地址周期性注入随机噪声包，维持流量特征对抗分析。

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use parking_lot::Mutex;
use rand::{RngCore, rng};

use super::{UdpIo, Udpmask};

/// exp 段类型（Go `noise.Segment_Kind`）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NoiseSegmentKind {
    /// 固定字节串（`<b hex>`）。
    #[default]
    Bytes,
    /// 随机字节（`<r lo-hi>`）。
    Random,
    /// 随机 ASCII 字母（`<rc lo-hi>`）。
    RandomAscii,
    /// 随机数字（`<rd lo-hi>`）。
    RandomDigit,
    /// 4 字节 BE Unix 时间戳（`<t>`）。
    Timestamp,
    /// 4 字节 BE 自增计数器，从 1 开始（`<c>`）。
    Counter,
    /// 8 字节随机 nonce（`<n>`）。
    Nonce,
}

/// exp 表达式段（Go `noise.Segment`）。按 `kind` 求值为字节串后拼接。
#[derive(Debug, Clone, Default)]
pub struct NoiseSegment {
    pub kind: NoiseSegmentKind,
    /// `Bytes` 段的字节内容；其余 kind 为空。
    pub bytes: Vec<u8>,
    /// 随机尺寸下限（Random/RandomAscii/RandomDigit）。
    pub min_size: i64,
    /// 随机尺寸上限（闭区间）。
    pub max_size: i64,
}

/// Noise Item（对应 Go `noise.Item` protobuf）。
#[derive(Debug, Clone, Default)]
pub struct NoiseItem {
    /// 随机噪声长度下限（>0 时生成随机噪声，否则发 `packet`）。
    pub rand_min: i64,
    /// 随机噪声长度上限。
    pub rand_max: i64,
    /// 随机字节取值下限。
    pub rand_range_min: i32,
    /// 随机字节取值上限。
    pub rand_range_max: i32,
    /// 固定噪声包（`rand_max == 0` 且 `segments` 为空时使用）。
    pub packet: Vec<u8>,
    /// 发包后延迟下限（毫秒）。
    pub delay_min: i64,
    /// 发包后延迟上限（毫秒）。
    pub delay_max: i64,
    /// exp 表达式段（`type: "exp"`；非空时替代 rand/packet legacy 形态）。
    pub segments: Vec<NoiseSegment>,
}

/// Noise 配置（对应 Go `noise.Config`）。
#[derive(Debug, Clone, Default)]
pub struct NoiseConfig {
    /// 噪声重置周期下限（秒）。
    pub reset_min: i64,
    /// 噪声重置周期上限（秒，>0 启用周期重置）。
    pub reset_max: i64,
    /// 噪声包序列。
    pub items: Vec<NoiseItem>,
}

impl Udpmask for NoiseConfig {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        Ok(Box::new(NoiseConn::new(self.clone(), raw)))
    }

    fn wrap_packet_conn_server(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        Ok(Box::new(NoiseConn::new(self.clone(), raw)))
    }
}

/// Noise 包装的 PacketConn（对应 Go `noiseConn`）。
struct NoiseConn {
    inner: Box<dyn UdpIo>,
    config: NoiseConfig,
    /// 每 addr 的噪声重置过期时间（对应 Go `m map[string]time.Time`）。
    last_expire: Mutex<HashMap<String, Instant>>,
    /// `<c>` 段自增计数器（Go `atomic.Uint32`，从 1 开始）。
    counter: AtomicU32,
}

impl NoiseConn {
    fn new(config: NoiseConfig, inner: Box<dyn UdpIo>) -> Self {
        Self { inner, config, last_expire: Mutex::new(HashMap::new()), counter: AtomicU32::new(0) }
    }

    /// Go `noiseConn.buildPacket`：segments 非空逐段求值拼接；否则 legacy
    /// （`rand_max > 0` 随机字节，否则固定 packet）。
    fn build_packet(&self, item: &NoiseItem) -> Vec<u8> {
        if item.segments.is_empty() {
            if item.rand_max > 0 {
                // Go RandBetween(min, max) 半开 [min, max) → 闭区间版传 max-1。
                let len =
                    rand_between(item.rand_min, item.rand_max.saturating_sub(1)).max(0) as usize;
                let mut noise = vec![0u8; len];
                fill_random_range(&mut noise, item.rand_range_min as u8, item.rand_range_max as u8);
                return noise;
            }
            return item.packet.clone();
        }
        let mut out = Vec::new();
        for seg in &item.segments {
            out.extend_from_slice(&self.build_segment(seg));
        }
        out
    }

    /// Go `noiseConn.buildSegment`：按 kind 求值单段字节串。
    fn build_segment(&self, seg: &NoiseSegment) -> Vec<u8> {
        match seg.kind {
            NoiseSegmentKind::Bytes => return seg.bytes.clone(),
            NoiseSegmentKind::Timestamp => {
                let secs =
                    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                return (secs as u32).to_be_bytes().to_vec();
            },
            NoiseSegmentKind::Counter => {
                // Go Add(1) 返回新值；wrapping 对齐 atomic 溢出语义。
                return self
                    .counter
                    .fetch_add(1, Ordering::Relaxed)
                    .wrapping_add(1)
                    .to_be_bytes()
                    .to_vec();
            },
            NoiseSegmentKind::Nonce => {
                let mut b = [0u8; 8];
                rng().fill_bytes(&mut b);
                return b.to_vec();
            },
            NoiseSegmentKind::Random
            | NoiseSegmentKind::RandomAscii
            | NoiseSegmentKind::RandomDigit => {},
        }
        const ASCII_LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        // Go RandBetween(MinSize, MaxSize+1) 半开 [min, max+1) → 闭区间 [min, max]。
        let size = rand_between(seg.min_size, seg.max_size).max(0) as usize;
        let mut buf = vec![0u8; size];
        rng().fill_bytes(&mut buf);
        match seg.kind {
            NoiseSegmentKind::RandomAscii => {
                for b in &mut buf {
                    *b = ASCII_LETTERS[(*b as usize) % ASCII_LETTERS.len()];
                }
            },
            NoiseSegmentKind::RandomDigit => {
                for b in &mut buf {
                    *b = b'0' + (*b % 10);
                }
            },
            _ => {},
        }
        buf
    }
}

#[async_trait]
impl UdpIo for NoiseConn {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        // 判断是否需要注入噪声（对应 Go `t.IsZero() || (ResetMax > 0 && now.After(t))`）
        let need_inject = {
            let mut map = self.last_expire.lock();
            let now = Instant::now();
            let expire = map.entry(addr.to_string()).or_insert(now);
            let expired = *expire <= now;
            let ttl_secs = if self.config.reset_max > 0 {
                rand_between(self.config.reset_min, self.config.reset_max).max(0) as u64
            } else {
                0
            };
            *expire = now + Duration::from_secs(ttl_secs);
            expired
        };

        if need_inject {
            for item in &self.config.items {
                let _ = self.inner.send_to(&self.build_packet(item), addr).await;
                let delay = rand_between(item.delay_min, item.delay_max).max(0) as u64;
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
            }
        }

        self.inner.send_to(buf, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

/// `[min, max]` 闭区间随机（`max <= min` 时返回 `min`）。
fn rand_between(min: i64, max: i64) -> i64 {
    if max <= min {
        return min;
    }
    use rand::Rng;
    rand::rng().random_range(min..=max)
}

/// 填充 `buf` 为 `[lo, hi]` 范围内的随机字节（`hi < lo` 时用 `lo`）。
fn fill_random_range(buf: &mut [u8], lo: u8, hi: u8) {
    let mut r = rng();
    if hi < lo {
        buf.fill(lo);
        return;
    }
    let range = (hi - lo) as u16 + 1; // u16 避免溢出
    for b in buf.iter_mut() {
        let mut rand_byte = [0u8; 1];
        r.fill_bytes(&mut rand_byte);
        *b = lo + (rand_byte[0] as u16 % range) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_random_range_respects_bounds() {
        let mut buf = vec![0u8; 1000];
        fill_random_range(&mut buf, 10, 20);
        for &b in &buf {
            assert!((10..=20).contains(&b), "byte {b} out of range");
        }
    }

    #[test]
    fn fill_random_range_lo_gt_hi_uses_lo() {
        let mut buf = vec![0u8; 10];
        fill_random_range(&mut buf, 50, 30);
        assert!(buf.iter().all(|&b| b == 50));
    }

    #[test]
    fn rand_between_bounds() {
        for _ in 0..100 {
            let v = rand_between(10, 20);
            assert!((10..=20).contains(&v));
        }
    }

    // --- build_segment / build_packet（Go conn_test.go 对齐）---

    fn conn() -> NoiseConn {
        NoiseConn::new(NoiseConfig::default(), Box::new(MockUdpIo::default()))
    }

    #[test]
    fn build_segment_bytes_passthrough() {
        let got = conn().build_segment(&NoiseSegment {
            kind: NoiseSegmentKind::Bytes,
            bytes: vec![0x0d, 0x0a, 0x0d, 0x0a],
            ..Default::default()
        });
        assert_eq!(got, vec![0x0d, 0x0a, 0x0d, 0x0a]);
    }

    #[test]
    fn build_segment_timestamp_is_4byte_current_unix() {
        let before =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                as u32;
        let got = conn().build_segment(&NoiseSegment {
            kind: NoiseSegmentKind::Timestamp,
            ..Default::default()
        });
        assert_eq!(got.len(), 4);
        let ts = u32::from_be_bytes(got.try_into().unwrap());
        assert!(ts >= before && ts <= before + 5, "ts {ts} vs before {before}");
    }

    #[test]
    fn build_segment_counter_increments_from_one() {
        let c = conn();
        let first = c
            .build_segment(&NoiseSegment { kind: NoiseSegmentKind::Counter, ..Default::default() });
        let second = c
            .build_segment(&NoiseSegment { kind: NoiseSegmentKind::Counter, ..Default::default() });
        assert_eq!(u32::from_be_bytes(first.try_into().unwrap()), 1);
        assert_eq!(u32::from_be_bytes(second.try_into().unwrap()), 2);
    }

    #[test]
    fn build_segment_nonce_8bytes_distinct() {
        let c = conn();
        let a =
            c.build_segment(&NoiseSegment { kind: NoiseSegmentKind::Nonce, ..Default::default() });
        let b =
            c.build_segment(&NoiseSegment { kind: NoiseSegmentKind::Nonce, ..Default::default() });
        assert_eq!(a.len(), 8);
        assert_eq!(b.len(), 8);
        assert_ne!(a, b);
    }

    #[test]
    fn build_segment_random_families_respect_size_and_charset() {
        let c = conn();
        for _ in 0..50 {
            assert_eq!(
                c.build_segment(&NoiseSegment {
                    kind: NoiseSegmentKind::Random,
                    min_size: 24,
                    max_size: 24,
                    ..Default::default()
                })
                .len(),
                24
            );
            let n = c
                .build_segment(&NoiseSegment {
                    kind: NoiseSegmentKind::Random,
                    min_size: 20,
                    max_size: 32,
                    ..Default::default()
                })
                .len();
            assert!((20..=32).contains(&n));
            for &b in &c.build_segment(&NoiseSegment {
                kind: NoiseSegmentKind::RandomAscii,
                min_size: 40,
                max_size: 40,
                ..Default::default()
            }) {
                assert!(b.is_ascii_alphabetic(), "not a letter: {b}");
            }
            for &b in &c.build_segment(&NoiseSegment {
                kind: NoiseSegmentKind::RandomDigit,
                min_size: 40,
                max_size: 40,
                ..Default::default()
            }) {
                assert!(b.is_ascii_digit(), "not a digit: {b}");
            }
        }
    }

    #[test]
    fn build_packet_composite_and_legacy() {
        let c = conn();
        let item = NoiseItem {
            segments: vec![
                NoiseSegment {
                    kind: NoiseSegmentKind::Bytes,
                    bytes: vec![0x0d, 0x0a, 0x0d, 0x0a],
                    ..Default::default()
                },
                NoiseSegment { kind: NoiseSegmentKind::Timestamp, ..Default::default() },
                NoiseSegment {
                    kind: NoiseSegmentKind::Random,
                    min_size: 24,
                    max_size: 24,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let got = c.build_packet(&item);
        assert_eq!(got.len(), 4 + 4 + 24);
        assert_eq!(&got[..4], &[0x0d, 0x0a, 0x0d, 0x0a]);

        // legacy：packet 原样 / rand 尺寸。
        assert_eq!(
            c.build_packet(&NoiseItem { packet: vec![1, 2, 3], ..Default::default() }),
            vec![1, 2, 3]
        );
        assert_eq!(
            c.build_packet(&NoiseItem { rand_min: 16, rand_max: 17, ..Default::default() }).len(),
            16
        );
    }

    use std::sync::Arc;

    #[tokio::test]
    async fn noise_injects_then_real_packet() {
        // Arc 共享状态：Mock 记录到 Arc，测试直接检查
        let packets: Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>> = Arc::new(Mutex::new(vec![]));
        let mock = MockUdpIo { packets: packets.clone() };
        let config = NoiseConfig {
            reset_max: 10,
            items: vec![NoiseItem {
                rand_min: 5,
                rand_max: 5,
                packet: vec![],
                delay_min: 0,
                delay_max: 0,
                ..Default::default()
            }],
            ..Default::default()
        };
        let conn = NoiseConn::new(config, Box::new(mock));
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        conn.send_to(b"real", addr).await.unwrap();
        let sent = packets.lock();
        // 噪声包(5字节) + 真实包(4字节)
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].0.len(), 5); // 噪声
        assert_eq!(sent[1].0, b"real"); // 真实
    }

    // --- Mock UdpIo（Arc 共享状态，测试直接检查发送记录）---
    #[derive(Default)]
    struct MockUdpIo {
        packets: Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>,
    }

    #[async_trait]
    impl UdpIo for MockUdpIo {
        async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
            self.packets.lock().push((buf.to_vec(), addr));
            Ok(buf.len())
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "mock"))
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
    }
}
