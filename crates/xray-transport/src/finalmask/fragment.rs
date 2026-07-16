//! # Fragment TCP 分片（对应 Go `fragment/`）
//!
//! 在 TCP 写入时把首包（TLS ClientHello）拆成多个小片段+延迟，绕过基于首包特征的 DPI。
//! 读方向透明透传。

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::select;

use super::{AsyncIo, Tcpmask, UDP_SIZE};

/// Fragment 配置（对应 Go `fragment.Config` protobuf）。
#[derive(Debug, Clone, Default)]
pub struct FragmentConfig {
    /// 触发分片的包序号区间起始（0 = 特殊语义，配合 packets_to=1 走 TLS ClientHello 检测）。
    pub packets_from: u64,
    /// 触发分片的包序号区间结束。
    pub packets_to: u64,
    /// 最大分片数下限（0 = 不限）。
    pub max_split_min: i64,
    /// 最大分片数上限。
    pub max_split_max: i64,
    /// 每段长度下限（按 split 索引取，超界 clamp 到末项）。
    pub lengths_min: Vec<i64>,
    /// 每段长度上限。
    pub lengths_max: Vec<i64>,
    /// 每段延迟下限（毫秒）。
    pub delays_min: Vec<i64>,
    /// 每段延迟上限。
    pub delays_max: Vec<i64>,
}

impl FragmentConfig {
    /// 第 seg_idx 段长度区间，超界 clamp 到末项（对应 Go `lengthForSegment`）。
    fn length_for_segment(&self, seg_idx: usize) -> (i64, i64) {
        let len = self.lengths_min.len();
        if len == 0 {
            return (0, 0);
        }
        let idx = seg_idx.min(len - 1);
        (self.lengths_min[idx], self.lengths_max[idx])
    }

    /// 第 seg_idx 段延迟区间（对应 Go `delayForSegment`）。
    fn delay_for_segment(&self, seg_idx: usize) -> (i64, i64) {
        let len = self.delays_min.len();
        if len == 0 {
            return (0, 0);
        }
        let idx = seg_idx.min(len - 1);
        (self.delays_min[idx], self.delays_max[idx])
    }

    /// 仅当 delays_max 恰好一项且为 0 时合并 ClientHello 分片（对应 Go `mergeTlsHelloSegments`）。
    fn merge_tls_hello(&self) -> bool {
        self.delays_max.len() == 1 && self.delays_max[0] == 0
    }
}

impl Tcpmask for FragmentConfig {
    fn wrap_conn_client(
        &self,
        raw: Box<dyn AsyncIo>,
    ) -> io::Result<Box<dyn AsyncIo>> {
        let (client, server) = tokio::io::duplex(UDP_SIZE * 2);
        let config = self.clone();
        tokio::spawn(fragment_bridge(raw, server, config, false));
        Ok(Box::new(client))
    }

    fn wrap_conn_server(
        &self,
        raw: Box<dyn AsyncIo>,
    ) -> io::Result<Box<dyn AsyncIo>> {
        let (client, server) = tokio::io::duplex(UDP_SIZE * 2);
        let config = self.clone();
        tokio::spawn(fragment_bridge(raw, server, config, true));
        Ok(Box::new(client))
    }
}

/// 桥接 task：inner ↔ duplex pipe。
///
/// inner→pipe 方向透明透传；pipe→inner 方向走分片逻辑（对应 Go `fragmentConn.Write`）。
/// 用 `tokio::select!` 并发处理双向，避免手写 `poll_write` 状态机。
async fn fragment_bridge(
    inner: Box<dyn AsyncIo>,
    mut pipe: tokio::io::DuplexStream,
    config: FragmentConfig,
    _server: bool,
) {
    let (mut inner_r, mut inner_w) = tokio::io::split(inner);
    let mut read_buf = vec![0u8; UDP_SIZE];
    let mut write_buf = vec![0u8; UDP_SIZE];
    let mut count = 0u64;
    loop {
        select! {
            // inner → pipe：读透传
            r = inner_r.read(&mut read_buf) => {
                match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if pipe.write_all(&read_buf[..n]).await.is_err() { break; }
                    }
                }
            }
            // pipe → inner：写分片
            r = pipe.read(&mut write_buf) => {
                match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        count += 1;
                        if write_fragmented(&mut inner_w, &write_buf[..n], &config, count)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// 分片写入（对应 Go `fragmentConn.Write`）。
///
/// 返回写入的字节数（成功时 = `p.len()`）。
async fn write_fragmented<W: AsyncWrite + Unpin>(
    w: &mut W,
    p: &[u8],
    config: &FragmentConfig,
    count: u64,
) -> io::Result<usize> {
    // Case 1：packets_from==0 && packets_to==1 → TLS ClientHello 特殊分片
    if config.packets_from == 0 && config.packets_to == 1 {
        if count != 1 || p.len() <= 5 || p[0] != 22 {
            // 非 ClientHello 或非首包，直通
            return write_all_and_len(w, p).await;
        }
        let record_len = 5 + (((p[3] as usize) << 8) | p[4] as usize);
        if p.len() < record_len {
            return write_all_and_len(w, p).await;
        }
        let data = &p[5..record_len];
        let merge = config.merge_tls_hello();
        let max_split = rand_between(config.max_split_min, config.max_split_max);
        let mut buff = vec![0u8; 2048];
        let mut hello: Vec<u8> = Vec::new();
        let mut split_num = 0i64;
        let mut from = 0usize;
        loop {
            let (lmin, lmax) = config.length_for_segment(split_num as usize);
            let mut to = from + rand_between(lmin, lmax) as usize;
            if to > data.len() || (max_split > 0 && split_num + 1 >= max_split) {
                to = data.len();
            }
            let l = to - from;
            if 5 + l > buff.len() {
                buff.resize(5 + l, 0);
            }
            buff[..3].copy_from_slice(&p[..3]);
            buff[5..5 + l].copy_from_slice(&data[from..to]);
            from = to;
            buff[3] = (l >> 8) as u8;
            buff[4] = l as u8;
            if merge {
                hello.extend_from_slice(&buff[..5 + l]);
            } else {
                let (dmin, dmax) = config.delay_for_segment(split_num as usize);
                w.write_all(&buff[..5 + l]).await?;
                if dmax > 0 {
                    let delay = rand_between(dmin, dmax).max(0) as u64;
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
            }
            split_num += 1;
            if from == data.len() {
                if !hello.is_empty() {
                    w.write_all(&hello).await?;
                }
                if p.len() > record_len {
                    w.write_all(&p[record_len..]).await?;
                }
                return Ok(p.len());
            }
        }
    }

    // Case 2：按 packets_from/to 区间分片
    if config.packets_from != 0 && (count < config.packets_from || count > config.packets_to) {
        return write_all_and_len(w, p).await;
    }
    let max_split = rand_between(config.max_split_min, config.max_split_max);
    let mut split_num = 0i64;
    let mut from = 0usize;
    loop {
        let (lmin, lmax) = config.length_for_segment(split_num as usize);
        let mut to = from + rand_between(lmin, lmax) as usize;
        if to > p.len() || (max_split > 0 && split_num + 1 >= max_split) {
            to = p.len();
        }
        w.write_all(&p[from..to]).await?;
        from = to;
        let (dmin, dmax) = config.delay_for_segment(split_num as usize);
        if dmax > 0 {
            let delay = rand_between(dmin, dmax).max(0) as u64;
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        split_num += 1;
        if from >= p.len() {
            return Ok(p.len());
        }
    }
}

/// `write_all` + 返回 `p.len()`。
async fn write_all_and_len<W: AsyncWrite + Unpin>(w: &mut W, p: &[u8]) -> io::Result<usize> {
    w.write_all(p).await?;
    Ok(p.len())
}

/// `[min, max]` 闭区间随机（`max <= min` 时返回 `min`）。
fn rand_between(min: i64, max: i64) -> i64 {
    if max <= min {
        return min;
    }
    use rand::Rng;
    rand::rng().random_range(min..=max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_for_segment_clamps() {
        let c = FragmentConfig {
            lengths_min: vec![10, 20],
            lengths_max: vec![15, 25],
            ..Default::default()
        };
        assert_eq!(c.length_for_segment(0), (10, 15));
        assert_eq!(c.length_for_segment(1), (20, 25));
        assert_eq!(c.length_for_segment(5), (20, 25)); // clamp
    }

    #[test]
    fn merge_tls_hello_only_when_single_zero_delay() {
        let c = FragmentConfig {
            delays_max: vec![0],
            ..Default::default()
        };
        assert!(c.merge_tls_hello());
        let c2 = FragmentConfig {
            delays_max: vec![0, 10],
            ..Default::default()
        };
        assert!(!c2.merge_tls_hello());
        let c3 = FragmentConfig {
            delays_max: vec![5],
            ..Default::default()
        };
        assert!(!c3.merge_tls_hello());
    }

    #[tokio::test]
    async fn passthrough_when_not_tls_hello() {
        // 非 ClientHello 数据应原样写入
        let (mut tx, mut rx) = tokio::io::duplex(1024);
        let config = FragmentConfig {
            packets_from: 0,
            packets_to: 1,
            ..Default::default()
        };
        let data = b"GET / HTTP/1.1\r\n";
        let n = write_fragmented(&mut tx, data, &config, 1).await.unwrap();
        assert_eq!(n, data.len());
        drop(tx);
        let mut received = Vec::new();
        rx.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, data);
    }

    #[tokio::test]
    async fn passthrough_outside_packet_range() {
        let (mut tx, mut rx) = tokio::io::duplex(1024);
        let config = FragmentConfig {
            packets_from: 5,
            packets_to: 10,
            ..Default::default()
        };
        let data = b"hello";
        // count=1 在 [5,10] 之外，应直通
        let n = write_fragmented(&mut tx, data, &config, 1).await.unwrap();
        assert_eq!(n, data.len());
        drop(tx);
        let mut received = Vec::new();
        rx.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, data);
    }

    #[test]
    fn rand_between_bounds() {
        for _ in 0..100 {
            let v = rand_between(10, 20);
            assert!((10..=20).contains(&v));
        }
        assert_eq!(rand_between(5, 5), 5);
        assert_eq!(rand_between(10, 3), 10); // max < min → min
    }
}
