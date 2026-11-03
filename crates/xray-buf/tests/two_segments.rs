//! `write_two_segments` / `write_segments` 线序与分批纪律测试。
//!
//! 8 段上限：≤8 段一次向量写；>8 段分批多次写（绝不合并成单块）。字节序恒定。

use std::{
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncReadExt, AsyncWrite, DuplexStream};
use xray_buf::writer::{MAX_SEGMENTS_PER_WRITE, write_segments, write_two_segments};

/// 计数包装：每次 `poll_write_vectored` = 我们发出的一"批"。
///
/// 实现上把整批 iovec 全部写入内层（合法：返回 n ≤ 总量），因此批次数只反映
/// **本层发了多少批**，与 syscall 内部行为无关。
struct CountingWriter {
    inner: DuplexStream,
    vectored: bool,
    batches: usize,
}

impl CountingWriter {
    fn new(inner: DuplexStream, vectored: bool) -> Self {
        Self { inner, vectored, batches: 0 }
    }
}

impl AsyncWrite for CountingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        me.batches += 1;
        let mut total = 0;
        for b in bufs.iter().filter(|b| !b.is_empty()) {
            match Pin::new(&mut me.inner).poll_write(cx, b) {
                Poll::Ready(Ok(n)) => {
                    total += n;
                    if n < b.len() {
                        return Poll::Ready(Ok(total));
                    }
                },
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    return if total == 0 { Poll::Pending } else { Poll::Ready(Ok(total)) };
                },
            }
        }
        Poll::Ready(Ok(total))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.vectored
    }
}

/// 两段帧：对端读到的字节序列 == 手工拼接的 `[head][body]`。
#[tokio::test]
async fn two_segments_wire_order() {
    let (sink, mut peer) = tokio::io::duplex(64 * 1024);
    let mut w = CountingWriter::new(sink, true);

    let head: [u8; 2] = [0x00, 0x05];
    let body: [u8; 5] = *b"hello";
    write_two_segments(&mut w, &head, &body).await.expect("write_two_segments");

    let mut expect: Vec<u8> = Vec::new();
    expect.extend_from_slice(&head);
    expect.extend_from_slice(&body);

    let mut got = vec![0u8; expect.len()];
    peer.read_exact(&mut got).await.expect("read_exact");
    assert_eq!(got, expect, "线序必须是 [head][body]");
    assert_eq!(w.batches, 1, "两段必须一次向量写发出");
}

/// 段数 = 8（上限）：一批写完。
#[tokio::test]
async fn segments_at_limit_single_batch() {
    assert_eq!(MAX_SEGMENTS_PER_WRITE, 8);
    let (sink, mut peer) = tokio::io::duplex(64 * 1024);
    let mut w = CountingWriter::new(sink, true);

    let segs: [[u8; 3]; MAX_SEGMENTS_PER_WRITE] = core::array::from_fn(|i| [i as u8 + 1; 3]);
    let refs: Vec<&[u8]> = segs.iter().map(|s| &s[..]).collect();
    write_segments(&mut w, &refs).await.expect("write_segments");

    let mut expect: Vec<u8> = Vec::new();
    for s in &segs {
        expect.extend_from_slice(s);
    }
    let mut got = vec![0u8; expect.len()];
    peer.read_exact(&mut got).await.expect("read_exact");
    assert_eq!(got, expect, "8 段线序不变");
    assert_eq!(w.batches, 1, "8 段必须一批写完");
}

/// 段数 = 9（超限）：分批两次写，字节序仍正确（不合并成单块）。
#[tokio::test]
async fn segments_over_limit_batched() {
    let (sink, mut peer) = tokio::io::duplex(64 * 1024);
    let mut w = CountingWriter::new(sink, true);

    let segs: [[u8; 3]; MAX_SEGMENTS_PER_WRITE + 1] = core::array::from_fn(|i| [i as u8 + 1; 3]);
    let refs: Vec<&[u8]> = segs.iter().map(|s| &s[..]).collect();
    write_segments(&mut w, &refs).await.expect("write_segments");

    let mut expect: Vec<u8> = Vec::new();
    for s in &segs {
        expect.extend_from_slice(s);
    }
    let mut got = vec![0u8; expect.len()];
    peer.read_exact(&mut got).await.expect("read_exact");
    assert_eq!(got, expect, "9 段线序不变");
    assert_eq!(w.batches, 2, "超限必须分批两次写（8 + 1），绝不合并成一块");
}

/// 底层不支持 vectored（TLS 包装层形态）：退化为逐段顺序写，字节序不变。
#[tokio::test]
async fn non_vectored_sink_falls_back_to_sequential() {
    let (sink, mut peer) = tokio::io::duplex(64 * 1024);
    let mut w = CountingWriter::new(sink, false);

    write_two_segments(&mut w, b"abc", b"defgh").await.expect("write_two_segments");

    let mut got = [0u8; 8];
    peer.read_exact(&mut got).await.expect("read_exact");
    assert_eq!(&got, b"abcdefgh");
    assert_eq!(w.batches, 0, "非 vectored 底层不得走向量写分支");
}

/// 空段被跳过，不影响线序。
#[tokio::test]
async fn empty_segment_skipped() {
    let (sink, mut peer) = tokio::io::duplex(1024);
    let mut w = CountingWriter::new(sink, true);

    write_two_segments(&mut w, b"", b"body").await.expect("write_two_segments");

    let mut got = [0u8; 4];
    peer.read_exact(&mut got).await.expect("read_exact");
    assert_eq!(&got, b"body");
}
