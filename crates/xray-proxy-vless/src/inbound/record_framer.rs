//! TLS 记录对齐读包装（record-framer）。
//!
//! rustls 的 deframer 每次读底层 socket 是贪婪的（`DeframerVecBuffer::read`
//! 以 4KB+ 容量调用一次 `read`，kernel 缓冲里有多少拉多少）。当对端 vision
//! 客户端发完 DIRECT 帧（一条完整 TLS 隧道记录）后立即切裸流直写（Go
//! `VisionWriter.WriteMultiBuffer` 的 `switchToDirectCopy` 分支，两次写间隔
//! 微秒级），同一次 recv 会把「DIRECT 帧 TLS 记录 + 其后的端到端裸字节」
//! 一并拉进 rustls deframer：裸尾被当隧道记录解密（DecryptError/BadRecordMac
//! fatal）或作为半记录永久滞留 deframer——两种形态都毁掉 vision DIRECT
//! 切换，且字节不可恢复（bd jeu9 Linux CI 两次确定性挂 / e0ni）。
//!
//! Go 无此问题：crypto/tls `readFromUntil` 按当前记录精确读取，且切 DIRECT
//! 前经 unsafe 反射回收 tls.Conn 私有 input/rawInput 残余
//! （proxy/vless/inbound/inbound.go:583-586 + proxy/proxy.go
//! `switchToDirectCopy` 分支）。rustls 无公开 API 触达 deframer 内部缓冲，
//! 唯一对齐形态 = 在其下垫一层记录对齐读：每次 `poll_read` 只交付「当前
//! TLS 记录尚缺的字节」，记录边界之后的字节不消费，留在内核 socket 缓冲。
//! 切 DIRECT 后 VisionConn 封读 inner（txno-splice 语义），raw TCP 克隆
//! （`dup_tcp_stream` 与本层共享内核缓冲游标）天然读到完整裸流——等价于
//! Go 的 readFromUntil+反射回收组合，且无需任何 unsafe。
//!
//! 该包装不解析/校验记录内容（type/version 不检查）：framer 只在「上层仍
//! 在隧道模式」期间被调用，那些字节必然是合法隧道记录；DIRECT 切换后
//! VisionConn 不再读本层，裸尾永远不会进入状态机。

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// TLS 记录头长度：type(1) + version(2) + length(2)。
const HEADER_LEN: usize = 5;

/// 记录对齐读状态机：
/// - `body_remaining == 0 && have < HEADER_LEN`：攒记录头。
/// - `body_remaining > 0`：按记录体剩余量限长直读。
pub(crate) struct RecordFramer<S> {
    sock: S,
    /// 记录头积累缓冲（跨 poll 存活：头可能分多个 TCP 段到达）。
    hdr: [u8; HEADER_LEN],
    /// `hdr` 中已读入且已交付的字节数。
    have: usize,
    /// 当前记录体尚未消费的字节数；0 表示不在记录体中。
    body_remaining: usize,
}

impl<S> RecordFramer<S> {
    pub(crate) fn new(sock: S) -> Self {
        Self { sock, hdr: [0u8; HEADER_LEN], have: 0, body_remaining: 0 }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordFramer<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.body_remaining == 0 {
            // 记录头阶段：读入 hdr 缺口，同时把字节交付给 caller。
            // caller（rustls deframer）每次 prepare_read 后容量 ≥4KB，
            // 恒能容纳 ≤5B 的头，无需部分交付回退路径。
            let mut rb = ReadBuf::new(&mut this.hdr[this.have..]);
            match Pin::new(&mut this.sock).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {},
                other => return other,
            }
            let n = rb.filled().len();
            if n == 0 {
                // EOF（可能带着半个头）：字节语义与直连一致——已交付部分
                // 已进 deframer，rustls 按截断流处理。
                return Poll::Ready(Ok(()));
            }
            buf.put_slice(&this.hdr[this.have..this.have + n]);
            this.have += n;
            if this.have == HEADER_LEN {
                let len = u16::from_be_bytes([this.hdr[3], this.hdr[4]]) as usize;
                this.body_remaining = len;
                this.have = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // 记录体阶段：限长读——只消费到当前记录边界，之后的字节（可能是
        // DIRECT 帧后的端到端裸流）留在内核缓冲。
        let want = this.body_remaining.min(buf.remaining());
        let unfilled = buf.initialize_unfilled();
        let mut rb = ReadBuf::new(&mut unfilled[..want]);
        match Pin::new(&mut this.sock).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => {},
            other => return other,
        }
        let n = rb.filled().len();
        buf.advance(n);
        this.body_remaining -= n;
        Poll::Ready(Ok(()))
    }
}

// 写路径无过读问题：DIRECT 帧是服务端读方向的事，写侧直透 socket。
impl<S: AsyncWrite + Unpin> AsyncWrite for RecordFramer<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().sock).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().sock).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().sock).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// 构造一条 TLS 记录字节（头 + 体），`typ` 随意（framer 不校验）。
    fn record(typ: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![typ, 0x03, 0x03];
        v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    /// framer 单次 poll_read 只交付一个阶段（头或体的一段），与 rustls
    /// deframer 的消费形态一致（循环 read 拼完整记录）。这里同样循环读。
    async fn read_n<S: AsyncRead + Unpin>(
        framer: &mut RecordFramer<S>,
        out: &mut [u8],
        want: usize,
    ) -> usize {
        let mut got = 0;
        while got < want {
            let n = framer.read(&mut out[got..]).await.unwrap();
            assert!(n > 0, "EOF after {got}/{want} bytes");
            got += n;
        }
        got
    }

    /// 核心不变量：即使底层一次到达「记录 A + 记录 B + 裸尾」合流字节，
    /// 单次 poll_read 也只交付到记录 A 边界为止；后续读取按序推进，字节
    /// 一字不丢。这等价于 Go readFromUntil 的读取纪律。
    #[tokio::test]
    async fn framer_delivers_exactly_one_record_per_read_despite_coalescing() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let rec_a = record(0x17, b"DIRECT-FRAME");
        let rec_b = record(0x17, b"next-tunnel-record");
        let raw_tail = b"END-TO-END-RAW-TAIL";
        // 一次性合流写入：模拟 Go client 的 DIRECT 帧写 + 裸写同段到达。
        tx.write_all(&rec_a).await.unwrap();
        tx.write_all(&rec_b).await.unwrap();
        tx.write_all(raw_tail).await.unwrap();
        tx.flush().await.unwrap();
        drop(tx);

        let mut framer = RecordFramer::new(rx);
        let mut out = vec![0u8; 4096];
        let n = read_n(&mut framer, &mut out, rec_a.len()).await;
        assert_eq!(&out[..n], &rec_a[..], "必须恰好停在记录 A 边界");

        // 继续读按序推进到记录 B（封读语义在 VisionConn，framer 自身无状态阻止）。
        let n = read_n(&mut framer, &mut out, rec_b.len()).await;
        assert_eq!(&out[..n], &rec_b[..]);
    }

    /// 记录头分片到达（2B + 3B）时正确重组，不丢字节、不越界。
    #[tokio::test]
    async fn framer_reassembles_split_record_header() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let rec = record(0x16, b"handshake-ish");
        tx.write_all(&rec[..2]).await.unwrap();
        tx.flush().await.unwrap();
        drop(tx); // 之后 EOF

        let mut framer = RecordFramer::new(rx);
        // 半个头 + EOF：首读只拿到 2B（不阻塞等待，EOF 语义透传）。
        let mut out = vec![0u8; 4096];
        let n = framer.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], &rec[..2]);

        // EOF：0 字节填充。
        let n = framer.read(&mut out).await.unwrap();
        assert_eq!(n, 0, "EOF 必须透传为 0 字节");
    }

    /// 零长记录（len=0，合法 TLS 记录）不卡死状态机：头后立即回头阶段。
    #[tokio::test]
    async fn framer_handles_zero_length_record() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let empty = record(0x17, b"");
        let rec = record(0x17, b"data");
        tx.write_all(&empty).await.unwrap();
        tx.write_all(&rec).await.unwrap();
        tx.flush().await.unwrap();
        drop(tx);

        let mut framer = RecordFramer::new(rx);
        let mut out = vec![0u8; 4096];
        let n = read_n(&mut framer, &mut out, HEADER_LEN).await;
        assert_eq!(n, HEADER_LEN, "零长记录只交付 5B 头");
        let n = read_n(&mut framer, &mut out, rec.len()).await;
        assert_eq!(&out[..n], &rec[..], "零长记录后状态机正常推进");
    }

    /// 写路径透传：caller 写入的字节原样到达对端。
    #[tokio::test]
    async fn framer_passes_writes_through() {
        let (mut tx, mut rx) = tokio::io::duplex(64);
        {
            let mut framer = RecordFramer::new(&mut tx);
            framer.write_all(b"plain-bytes").await.unwrap();
            framer.flush().await.unwrap();
        }
        let mut out = vec![0u8; 64];
        let n = rx.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"plain-bytes");
    }
}
