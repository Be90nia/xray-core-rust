//! # Noise UDP 噪声注入（对应 Go `noise/`）
//!
//! 在 UDP 真实包发送前，按地址周期性注入随机噪声包，维持流量特征对抗分析。

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use parking_lot::Mutex;
use rand::{RngCore, rng};

use super::{UdpIo, Udpmask};

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
    /// 固定噪声包（`rand_max == 0` 时使用）。
    pub packet: Vec<u8>,
    /// 发包后延迟下限（毫秒）。
    pub delay_min: i64,
    /// 发包后延迟上限（毫秒）。
    pub delay_max: i64,
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
}

impl NoiseConn {
    fn new(config: NoiseConfig, inner: Box<dyn UdpIo>) -> Self {
        Self { inner, config, last_expire: Mutex::new(HashMap::new()) }
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
                if item.rand_max > 0 {
                    let len = rand_between(item.rand_min, item.rand_max).max(0) as usize;
                    let mut noise = vec![0u8; len];
                    fill_random_range(
                        &mut noise,
                        item.rand_range_min as u8,
                        item.rand_range_max as u8,
                    );
                    let _ = self.inner.send_to(&noise, addr).await;
                } else {
                    let _ = self.inner.send_to(&item.packet, addr).await;
                }
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
