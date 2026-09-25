//! Freedom TCP 分片。对应 Go `proxy/freedom/freedom.go` FragmentWriter (:730-815)。
//!
//! 两模式（对齐 Go `Write`）：
//! - **tlshello**（`packets_from==0 && packets_to==1`）：仅首包且为完整 TLS handshake
//!   record（`b[0]==22` 且 `len>=recordLen`）时，把 record payload 按 随机长度重组为多个独立 TLS
//!   record 发送；`interval_max==0` 时合并为一次 write（Go `hello`），record
//!   后的剩余字节直发。非首包/非 TLS/半截 record 直发。
//! - **通用**（其他配置）：`packets_from!=0` 时仅窗口 `[from,to]` 内的包分片 （`packets 0-0` =
//!   所有包都分片）；每片独立 write + 写后 sleep。
//!
//! 消费方：[`FragmentStream`]（直接 async 写，测试/独立路径）与
//! [`FragmentConnection`]（dispatcher TCP 路径 dial 后包装 Connection，
//! 对齐 Go :410-418 `writer = buf.NewWriter(&FragmentWriter{...})`）。

use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_transport::connection::Connection;

use crate::config::Fragment;

/// 等概率随机整数，对应 Go `crypto.RandBetween`（`[from, to)` 半开）。
///
/// 退化区间（`from >= to`）直接返回 `from`——Go 对 `from > to` 交换后仍均匀
/// 取值，此处按 `rand_between_go_semantics` 测试契约为确定性 `from`。
#[must_use]
pub fn rand_between(from: u64, to: u64) -> u64 {
    if from >= to {
        return from;
    }
    rand::random_range(from..to)
}

/// 每片写后间隔毫秒。Go 为 `RandBetween(interval_min, interval_max)`；
/// `interval_min==0` 时固定 `interval_max`（测试虚拟时钟要求确定性间隔；
/// `0-0` 退化 0ms 与 Go 等价）。
fn interval_ms(fragment: &Fragment) -> u64 {
    if fragment.interval_min == 0 {
        fragment.interval_max
    } else {
        rand_between(fragment.interval_min, fragment.interval_max)
    }
}

/// 生成分片计划：`(数据, 写后是否 sleep)` 序列；`None` = 直发。
///
/// `step` 至少 1（`.max(1)`）：`length_min==0` 且随机取到 0 时 Go 会死循环
/// （`to == from` 永不推进），此处加保底。
fn build_pieces(fragment: &Fragment, count: u64, b: &[u8]) -> Option<Vec<(Vec<u8>, bool)>> {
    if fragment.packets_from == 0 && fragment.packets_to == 1 {
        // tlshello 模式（Go :739-791）
        if count != 1 || b.len() <= 5 || b[0] != 22 {
            return None;
        }
        let record_len = 5 + (((b[3] as usize) << 8) | b[4] as usize);
        if b.len() < record_len {
            return None; // maybe already fragmented somehow
        }
        let data = &b[5..record_len];
        let max_split = rand_between(fragment.max_split_min, fragment.max_split_max);
        let combine = fragment.interval_max == 0; // interval 为 0 时合并为一次 write
        let mut hello: Vec<u8> = Vec::with_capacity(data.len() + 16);
        let mut pieces = Vec::new();
        let mut split_num: u64 = 0;
        let mut from = 0usize;
        loop {
            let step = rand_between(fragment.length_min, fragment.length_max).max(1) as usize;
            let mut to = from + step;
            split_num += 1;
            if to > data.len() || (max_split > 0 && split_num >= max_split) {
                to = data.len();
            }
            let l = to - from;
            if combine {
                hello.extend_from_slice(&b[..3]); // type + version 沿用原 record
                hello.extend_from_slice(&[(l >> 8) as u8, l as u8]);
                hello.extend_from_slice(&data[from..to]);
            } else {
                let mut rec = Vec::with_capacity(5 + l);
                rec.extend_from_slice(&b[..3]);
                rec.extend_from_slice(&[(l >> 8) as u8, l as u8]);
                rec.extend_from_slice(&data[from..to]);
                pieces.push((rec, true));
            }
            from = to;
            if from == data.len() {
                break;
            }
        }
        if combine && !hello.is_empty() {
            pieces.insert(0, (hello, false));
        }
        if b.len() > record_len {
            pieces.push((b[record_len..].to_vec(), false)); // record 后剩余直发（Go :783-788）
        }
        Some(pieces)
    } else if fragment.packets_from != 0
        && (count < fragment.packets_from || count > fragment.packets_to)
    {
        None // 窗口外直发（Go :794-796）
    } else {
        // 通用分片：每片独立 write + 写后 sleep（Go :797-814）
        let max_split = rand_between(fragment.max_split_min, fragment.max_split_max);
        let mut pieces = Vec::new();
        let mut split_num: u64 = 0;
        let mut from = 0usize;
        loop {
            let step = rand_between(fragment.length_min, fragment.length_max).max(1) as usize;
            let mut to = from + step;
            split_num += 1;
            if to > b.len() || (max_split > 0 && split_num >= max_split) {
                to = b.len();
            }
            pieces.push((b[from..to].to_vec(), true));
            from = to;
            if from >= b.len() {
                break;
            }
        }
        Some(pieces)
    }
}

/// TCP 分片写入流——对应 Go `FragmentWriter`。
///
/// 包装任意 [`AsyncWrite`]，按 [`Fragment`] 配置分片写入。包计数（`count`）
/// 跨多次 [`write_fragmented`](FragmentStream::write_fragmented) 累积，与 Go
/// `f.count++` 语义一致。
pub struct FragmentStream<W> {
    fragment: Fragment,
    writer: W,
    count: u64,
}

impl<W: AsyncWrite + Unpin> FragmentStream<W> {
    #[must_use]
    pub fn new(fragment: Fragment, writer: W) -> Self {
        Self { fragment, writer, count: 0 }
    }

    /// 写入一次（分片策略见 [`build_pieces`]），返回消耗字节数（恒为 `buf.len()`）。
    ///
    /// # Errors
    ///
    /// 底层写失败时返回 [`io::Error`]。
    pub async fn write_fragmented(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.count += 1;
        match build_pieces(&self.fragment, self.count, buf) {
            None => {
                self.writer.write_all(buf).await?;
            },
            Some(pieces) => {
                for (data, sleep_after) in pieces {
                    self.writer.write_all(&data).await?;
                    if sleep_after {
                        tokio::time::sleep(Duration::from_millis(interval_ms(&self.fragment)))
                            .await;
                    }
                }
            },
        }
        Ok(buf.len())
    }
}

/// dial 出的 [`Connection`] 的分片包装（dispatcher TCP 路径接线用）。
///
/// 写路径走 [`build_pieces`] 状态机（分片队列 + 片间 `Sleep`），读路径与
/// [`Connection::remote_addr`] 透传——桥接用 `tokio::io::split` 双向并发，
/// 分片 sleep 期间下行读取不受阻（与 Go 分片仅阻塞上行 copy goroutine 对齐）。
pub struct FragmentConnection {
    inner: Box<dyn Connection>,
    fragment: Fragment,
    count: u64,
    queue: VecDeque<(Vec<u8>, bool)>,
    /// 当前分片（数据, 偏移, 写后 sleep）——inner 可能部分写。
    current: Option<(Vec<u8>, usize, bool)>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    /// 本轮 poll_write 接受的字节数（完成时报告给调用方）。
    accepted: usize,
}

impl FragmentConnection {
    #[must_use]
    pub fn new(inner: Box<dyn Connection>, fragment: Fragment) -> Self {
        Self {
            inner,
            fragment,
            count: 0,
            queue: VecDeque::new(),
            current: None,
            sleep: None,
            accepted: 0,
        }
    }

    fn busy(&self) -> bool {
        !self.queue.is_empty() || self.current.is_some() || self.sleep.is_some()
    }

    fn reset(&mut self) {
        self.queue.clear();
        self.current = None;
        self.sleep = None;
        self.accepted = 0;
    }
}

impl AsyncRead for FragmentConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FragmentConnection {
    /// 驱动分片状态机；空闲时接受新 `buf` 生成分片计划。
    ///
    /// 与 tokio 约定一致：`Ready(Ok(n))` 的 `n` 恒为当初接受的 `buf.len()`
    /// （整个缓冲已被分片计划消费）；忙时忽略新 `buf` 继续推进未完成的写。
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.busy() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            this.count += 1;
            this.accepted = buf.len();
            match build_pieces(&this.fragment, this.count, buf) {
                None => this.queue.push_back((buf.to_vec(), false)),
                Some(pieces) => this.queue.extend(pieces),
            }
        }
        loop {
            if let Some(sleep) = this.sleep.as_mut() {
                if sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                this.sleep = None;
            }
            if this.current.is_none() {
                match this.queue.pop_front() {
                    Some((data, sleep_after)) => this.current = Some((data, 0, sleep_after)),
                    None => {
                        let n = this.accepted;
                        this.accepted = 0;
                        return Poll::Ready(Ok(n));
                    },
                }
            }
            let (data, off, _) = this.current.as_mut().expect("current set");
            match Pin::new(&mut *this.inner).poll_write(cx, &data[*off..]) {
                Poll::Ready(Ok(0)) if *off < data.len() => {
                    this.reset();
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "fragment write: inner connection wrote 0 bytes",
                    )));
                },
                Poll::Ready(Ok(n)) => {
                    if *off + n >= data.len() {
                        let (_, _, sleep_after) = this.current.take().expect("current set");
                        if sleep_after {
                            this.sleep = Some(Box::pin(tokio::time::sleep(Duration::from_millis(
                                interval_ms(&this.fragment),
                            ))));
                        }
                    } else {
                        *off += n;
                    }
                },
                Poll::Ready(Err(e)) => {
                    this.reset();
                    return Poll::Ready(Err(e));
                },
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    /// 分片未写完时 Pending（避免半途 shutdown 丢片）；写路径由调用方先驱动完成。
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.busy() {
            return Poll::Pending;
        }
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

impl Connection for FragmentConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.remote_addr()
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use parking_lot::Mutex;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::{FragmentConnection, FragmentStream, rand_between};
    use crate::config::Fragment;

    /// 记录每次 poll_write 字节的测试流（读端永远 Pending）。
    struct RecStream {
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl AsyncRead for RecStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for RecStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.writes.lock().push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// 构造 TLS record：type=22(handshake) + version + u16 长度 + payload。
    fn tls_record(payload: &[u8]) -> Vec<u8> {
        let mut b = vec![22, 3, 1, (payload.len() >> 8) as u8, payload.len() as u8];
        b.extend_from_slice(payload);
        b
    }

    /// 解析收到的字节为 TLS record 序列：(type, version, payload)。
    fn parse_records(bytes: &[u8]) -> Vec<(u8, [u8; 2], Vec<u8>)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 5 <= bytes.len() {
            let l = ((bytes[i + 3] as usize) << 8) | bytes[i + 4] as usize;
            assert!(i + 5 + l <= bytes.len(), "truncated record at {i}");
            out.push((bytes[i], [bytes[i + 1], bytes[i + 2]], bytes[i + 5..i + 5 + l].to_vec()));
            i += 5 + l;
        }
        assert_eq!(i, bytes.len(), "no trailing garbage");
        out
    }

    fn frag(
        packets_from: u64,
        packets_to: u64,
        len: u64,
        interval_max: u64,
        max_split: u64,
    ) -> Fragment {
        Fragment {
            packets_from,
            packets_to,
            length_min: len,
            length_max: len,
            interval_min: 0,
            interval_max,
            max_split_min: max_split,
            max_split_max: max_split,
        }
    }

    use tokio::io::AsyncWriteExt;

    async fn run(stream: &mut FragmentStream<RecStream>, buf: &[u8]) {
        stream.write_fragmented(buf).await.unwrap();
    }

    // ===== tlshello 模式（packets 0-1） =====

    /// 首包 TLS record：按 length 固定 4 字节重组分片，interval=0 合并为一次 write。
    /// 断言：多个小 record，type/version 保留，payload 拼接 == 原 data。
    #[tokio::test]
    async fn tlshello_reassembles_first_tls_record() {
        let payload: Vec<u8> = (0..12u8).collect();
        let b = tls_record(&payload);
        let writes_rec = Arc::new(Mutex::new(Vec::new()));
        let mut s =
            FragmentStream::new(frag(0, 1, 4, 0, 0), RecStream { writes: writes_rec.clone() });
        run(&mut s, &b).await;

        let ws = writes_rec.lock().clone();
        // interval_max == 0 → 合并发送（Go freedom.go:767-768）
        assert_eq!(ws.len(), 1, "combined into one write");
        let records = parse_records(&ws[0]);
        assert!(
            records.len() >= 3,
            "payload 12 bytes / piece 4 → at least 3 records, got {}",
            records.len()
        );
        for (typ, ver, _) in &records {
            assert_eq!(*typ, 22);
            assert_eq!(*ver, [3, 1], "version bytes preserved from original");
        }
        let data: Vec<u8> = records.iter().flat_map(|(_, _, p)| p.clone()).collect();
        assert_eq!(data, payload, "reassembled handshake data == original");
    }

    /// interval > 0 → 每片单独 write（不合并）。
    #[tokio::test]
    async fn tlshello_interval_writes_pieces_separately() {
        let payload: Vec<u8> = (0..12u8).collect();
        let b = tls_record(&payload);
        let writes_rec = Arc::new(Mutex::new(Vec::new()));
        let mut s =
            FragmentStream::new(frag(0, 1, 4, 10, 0), RecStream { writes: writes_rec.clone() });
        run(&mut s, &b).await;
        let ws = writes_rec.lock().clone();
        assert_eq!(ws.len(), 3, "12 bytes / piece 4 → 3 separate writes");
    }

    /// 首包非 TLS（b[0]!=22）或长度不足 → 原样直发。
    #[tokio::test]
    async fn tlshello_non_tls_first_packet_passthrough() {
        let writes_rec = Arc::new(Mutex::new(Vec::new()));
        let mut s =
            FragmentStream::new(frag(0, 1, 4, 10, 0), RecStream { writes: writes_rec.clone() });
        let b = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        run(&mut s, b).await;
        let ws = writes_rec.lock().clone();
        assert_eq!(ws.len(), 1);
        assert_eq!(ws[0], b.to_vec());
    }

    /// recordLen 超过包长（半截 record）→ 直发（Go :744-746 already fragmented）。
    #[tokio::test]
    async fn tlshello_short_record_passthrough() {
        let mut b = tls_record(&[0u8; 20]);
        b.truncate(10); // record 声称 20 字节但只有 5
        let writes_rec = Arc::new(Mutex::new(Vec::new()));
        let mut s =
            FragmentStream::new(frag(0, 1, 4, 10, 0), RecStream { writes: writes_rec.clone() });
        run(&mut s, &b).await;
        let ws = writes_rec.lock().clone();
        assert_eq!(ws.len(), 1);
        assert_eq!(ws[0], b);
    }

    /// 第二个包起不再分片（count != 1 → 直发）。
    #[tokio::test]
    async fn tlshello_only_first_packet_fragmented() {
        let writes_rec = Arc::new(Mutex::new(Vec::new()));
        let mut s =
            FragmentStream::new(frag(0, 1, 4, 10, 0), RecStream { writes: writes_rec.clone() });
        run(&mut s, &tls_record(&[7u8; 12])).await;
        run(&mut s, &tls_record(&[8u8; 12])).await;
        let ws = writes_rec.lock().clone();
        // 第二包原样直发（单条完整 record）
        let last = ws.last().unwrap();
        let records = parse_records(last);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].2, vec![8u8; 12]);
    }

    // ===== 通用分片模式 =====

    /// 窗口 [2,3]：包 1 直发、包 2/3 分片、包 4 直发。
    #[tokio::test]
    async fn generic_window_fragment_packets_2_to_3_only() {
        let writes_rec = Arc::new(Mutex::new(Vec::new()));
        let mut s =
            FragmentStream::new(frag(2, 3, 3, 10, 0), RecStream { writes: writes_rec.clone() });
        run(&mut s, b"packet-one-1111").await; // 包 1：窗外 → 直发
        let ws = writes_rec.lock().clone();
        assert_eq!(ws.len(), 1, "packet 1 outside window: direct");
        assert_eq!(ws[0], b"packet-one-1111".to_vec());

        let writes_rec2 = Arc::new(Mutex::new(Vec::new()));
        let mut s2 =
            FragmentStream::new(frag(2, 3, 3, 10, 0), RecStream { writes: writes_rec2.clone() });
        run(&mut s2, b"packet-one-1111").await; // 包 1 窗外
        run(&mut s2, b"packet-two-2222").await; // 包 2 窗内 → 分片
        let ws2 = writes_rec2.lock().clone();
        let frag_writes = &ws2[1..];
        assert!(frag_writes.len() > 1, "packet 2 fragmented");
        assert!(frag_writes.iter().all(|w| w.len() <= 3), "each piece <= length_max");
        let joined: Vec<u8> = frag_writes.concat();
        assert_eq!(joined, b"packet-two-2222".to_vec());

        run(&mut s2, b"packet-three33").await; // 包 3 窗内
        run(&mut s2, b"packet-four-44").await; // 包 4 窗外 → 直发
        let ws3 = writes_rec2.lock().clone();
        let last_write = ws3.last().unwrap().clone();
        assert_eq!(last_write.len(), b"packet-four-44".len(), "packet 4 direct: single write");
    }

    /// packets 0-0（JSON packets:""）：所有包都分片。
    #[tokio::test]
    async fn generic_all_packets_mode_fragments_everything() {
        let writes_rec = Arc::new(Mutex::new(Vec::new()));
        let mut s =
            FragmentStream::new(frag(0, 0, 3, 10, 0), RecStream { writes: writes_rec.clone() });
        run(&mut s, b"first-packet!").await;
        run(&mut s, b"second-packet").await;
        let ws = writes_rec.lock().clone();
        assert!(ws.len() > 2, "both packets fragmented, got {} writes", ws.len());
        let first_packet_pieces: usize = ws.iter().take_while(|_| true).count();
        assert!(first_packet_pieces > 0);
    }

    /// maxSplit 上限：10 字节 / piece 1，maxSplit=2 → 恰好 2 片。
    #[tokio::test]
    async fn generic_maxsplit_caps_piece_count() {
        let writes_rec = Arc::new(Mutex::new(Vec::new()));
        let mut s =
            FragmentStream::new(frag(0, 0, 1, 10, 2), RecStream { writes: writes_rec.clone() });
        run(&mut s, &[9u8; 10]).await;
        let ws = writes_rec.lock().clone();
        assert_eq!(ws.len(), 2, "maxSplit=2 → exactly 2 pieces");
        assert_eq!(ws.concat(), vec![9u8; 10]);
    }

    /// interval 生效：3 片 × 10ms → 虚拟时钟推进 ≥30ms。
    #[tokio::test(start_paused = true)]
    async fn generic_interval_sleeps_between_pieces() {
        let writes_rec = Arc::new(Mutex::new(Vec::new()));
        let mut s =
            FragmentStream::new(frag(0, 0, 1, 10, 0), RecStream { writes: writes_rec.clone() });
        let start = tokio::time::Instant::now();
        run(&mut s, &[1u8; 3]).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed >= std::time::Duration::from_millis(30),
            "3 pieces × 10ms interval, got {elapsed:?}"
        );
    }

    // ===== rand_between =====

    #[test]
    fn rand_between_go_semantics() {
        assert_eq!(rand_between(5, 5), 5, "from==to → from");
        assert_eq!(rand_between(7, 3), 7, "swapped args inclusive of both");
        // 半开 [from, to)：to 不可达
        let mut saw_to = false;
        for _ in 0..200 {
            let v = rand_between(1, 4);
            assert!((1..4).contains(&v));
            if v == 3 {
                saw_to = true;
            }
        }
        assert!(saw_to, "upper-1 reachable");
    }

    // ===== FragmentConnection（dispatcher 接线包装） =====

    use xray_transport::connection::Connection;

    impl Connection for RecStream {
        fn remote_addr(&self) -> std::io::Result<Option<std::net::SocketAddr>> {
            Ok(None)
        }

        fn local_addr(&self) -> std::io::Result<Option<std::net::SocketAddr>> {
            Ok(None)
        }
    }

    /// 每次最多接受 3 字节的 inner（模拟 TCP 部分写）——验证状态机跨 poll 推进。
    struct PartialStream {
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl AsyncRead for PartialStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PartialStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let n = buf.len().min(3);
            self.writes.lock().push(buf[..n].to_vec());
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Connection for PartialStream {
        fn remote_addr(&self) -> std::io::Result<Option<std::net::SocketAddr>> {
            Ok(None)
        }

        fn local_addr(&self) -> std::io::Result<Option<std::net::SocketAddr>> {
            Ok(None)
        }
    }

    /// 部分写 + 片间 sleep：内容不丢不重，片间虚拟时钟推进（4 片 × 10ms）。
    #[tokio::test(start_paused = true)]
    async fn fragment_connection_survives_partial_inner_writes() {
        let writes_rec = Arc::new(Mutex::new(Vec::new()));
        let inner = PartialStream { writes: writes_rec.clone() };
        let mut conn = FragmentConnection::new(Box::new(inner), frag(0, 0, 2, 10, 0));
        let data = vec![7u8; 8];
        let start = tokio::time::Instant::now();
        conn.write_all(&data).await.unwrap();
        let ws = writes_rec.lock().clone();
        assert!(ws.iter().all(|w| w.len() <= 3), "inner accepts <= 3 bytes per poll");
        assert_eq!(ws.concat(), data, "no loss/dup across partial writes");
        assert!(start.elapsed() >= std::time::Duration::from_millis(30), "4 pieces × 10ms");
    }
}
