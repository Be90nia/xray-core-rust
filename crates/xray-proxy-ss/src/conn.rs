//! SS 出站直挂连接：读写两半各自直挂 SS wire（**删 duplex 中转层**）。
//!
//! 旧实现（[`crate::dispatcher::SsConnection`] + `pump_ss_stream`）：
//! `tokio::io::duplex(64KiB)` + **单任务 `select!` 泵**——每方向多一遍中转 memcpy
//! （duplex 环）+ 一次 task 唤醒，且**双向被同一任务的 `select!` 串行推进**
//! （`slow-root-cause.md` §R3：本仓 `nanosleep` 3814 次 / 27x futex 的结构指纹）。
//!
//! 新实现（本文件）：直接实现 `AsyncRead`/`AsyncWrite`：
//! - **读半**：wire 字节直落 `BytesMut` spare 区 → [`SSStream::try_open_chunk`] 原地解密 →
//!   交付调用方（**零中转拷贝**）；
//! - **写半**：明文进 64KiB 暂存 → [`SSStream::seal_chunk_in_place`] **原地 seal** →
//!   `[sealed_size][ciphertext+tag]` 两段向量写直落 wire。
//!
//! 两个方向由 bridge 的上行/下行两个任务**各自独立**驱动（不再有单任务 `select!`
//! 串行推进），读写的 `&mut` 互斥由 `tokio::io::split` 的轮询级锁保证。
//!
//! **wire 不变量**：帧格式 / 序号 / 加密顺序与旧泵**逐字节一致**——seal 逻辑复用
//! [`SSStream::seal_chunk_in_place`]（与旧 `write_chunk_in_place` 同源同一份代码），
//! SS-2022 请求头复用 [`SSStream::build_client_2022_header`]（与旧
//! `emit_pending_client_2022` 同源）。

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_buf::buffer::Buffer;
use xray_transport::connection::Connection;

use crate::{
    error::SsError,
    stream::{ChunkOut, SSStream},
};

/// 上行明文暂存块尺寸（与旧 pump 的 `up_buf` 同值 ⇒ 帧长分布不变）。
const STAGE_SIZE: usize = 64 * 1024;

/// 下行 wire 缓冲预留（与旧 pump 的 `pending.reserve` 同值）。
const DOWN_RESERVE: usize = 16 * 1024;

/// SS-2022 客户端请求头空闲兜底延时（与旧 pump 的 `hdr_timer` 同值）。
const IDLE_HEADER_DELAY: std::time::Duration = std::time::Duration::from_millis(200);

/// 待落线的密文输出态。
#[derive(Debug, Clone, Copy)]
enum Out {
    /// 无待落线内容。
    Idle,
    /// SS-2022 请求头：整块字节在 `head`（**单段写出**，等价旧泵的一次 `write_all`）。
    Header {
        /// `head` 已写字节数。
        done: usize,
    },
    /// 常规 chunk：`head` = sealed size 段（2B+tag），`stage` = 密文+tag 载荷。
    Chunk {
        /// size 段已写字节数。
        head_done: usize,
        /// 载荷已写字节数。
        body_done: usize,
    },
}

/// SS 出站连接：读写两半直挂 SS wire。
///
/// 取代旧的「duplex + 单任务泵」中转层：上行明文直接进 64KiB 暂存并原地 seal
/// 落线；下行 wire 字节直接解帧交付。双向由调用方（bridge）的两个独立任务驱动。
pub struct SsStreamConn {
    /// SS chunk 流（读写 AEAD/序号分列，见 [`SSStream`]）。
    ss: SSStream<Box<dyn Connection>>,
    /// 下行：已解出的明文待交付（chunk 大于调用方缓冲时保留余量）。
    plain: Bytes,
    /// 下行：未解帧的 wire 字节（`split_to` 切帧为 O(1)）。
    pending: BytesMut,
    /// 上行：明文暂存（seal 时原地覆写为密文；落线完成后 `clear` 复用）。
    stage: Buffer,
    /// 上行：暂存区内的明文字节数。
    staged: usize,
    /// 上行：待落线的头部字节（sealed size 段；SS-2022 请求头时为整块）。
    head: Vec<u8>,
    /// 上行：待落线状态。
    out: Out,
    /// SS-2022 客户端请求头空闲兜底定时器（仅首写待发时存在）。
    idle: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl SsStreamConn {
    /// 从已写完首帧（addr+port）的 `SSStream` 构造。
    ///
    /// SS-2022 客户端的请求头在此登记为**首写待发**（与旧泵一致）：首段明文与
    /// 请求头合并单次写出；上游 200ms 内无数据时兜底发 padding-only 请求头
    /// （server-speaks-first 目标否则双向等死锁）。
    #[must_use]
    pub fn new(stream: SSStream<Box<dyn Connection>>) -> Self {
        let idle = stream
            .has_pending_client_2022()
            .then(|| Box::pin(tokio::time::sleep(IDLE_HEADER_DELAY)));
        Self {
            ss: stream,
            plain: Bytes::new(),
            pending: BytesMut::new(),
            stage: Buffer::new_pooled(STAGE_SIZE),
            staged: 0,
            head: Vec::new(),
            out: Out::Idle,
            idle,
        }
    }

    /// 单 chunk 明文载荷上限（与旧 pump 的 `up_cap` 同式：暂存容量 - tag 空间，
    /// 且 ≤ u16 长度域上限）。
    fn up_cap(&self) -> usize {
        self.stage.capacity().saturating_sub(self.ss.tag_size()).min(self.ss.max_chunk_payload())
    }

    /// 把暂存明文封成一个待落线单元（原地 seal，零载荷拷贝）。
    fn seal_stage(&mut self) -> Result<(), SsError> {
        if self.ss.has_pending_client_2022() {
            // SS-2022 首写：请求头（prefix + sealed fixed + sealed var，并入首段
            // payload）**单块写出**（Go `WriteTCPRequest` 的 handshakeBuf 单写语义）。
            let (wire, used) = {
                let payload = self.stage.bytes();
                self.ss.build_client_2022_header(payload)?
            };
            self.head.clear();
            self.head.extend_from_slice(&wire);
            if used > 0 {
                self.stage.advance(used);
                self.staged -= used;
                // 余量前移复位：`Buffer` 的 `advance` 不回卷起点，留着会让后续写入
                // 按 `capacity - end` 算空间 → 少算 `used` 字节。首写一次性拷贝。
                let rest = self.stage.bytes().to_vec();
                self.stage.clear();
                if !rest.is_empty() {
                    self.stage.writable_bytes()[..rest.len()].copy_from_slice(&rest);
                    self.stage.advance_write(rest.len());
                }
            }
            self.out = Out::Header { done: 0 };
        } else {
            self.ss.seal_chunk_in_place(&mut self.stage)?;
            self.head.clear();
            self.head.extend_from_slice(self.ss.sealed_size_chunk());
            self.out = Out::Chunk { head_done: 0, body_done: 0 };
            self.staged = 0;
        }
        Ok(())
    }

    /// 推进待落线内容（写 wire）。返回 `Pending` 表示 wire 未就绪。
    fn poll_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.out {
                Out::Idle => return Poll::Ready(Ok(())),
                Out::Header { done } => {
                    let total = self.head.len();
                    if done >= total {
                        self.out = Out::Idle;
                        continue;
                    }
                    let n = match Self::poll_write_bytes(
                        self.ss.get_mut(),
                        cx,
                        &[&self.head[done..]],
                    ) {
                        Poll::Ready(Ok(n)) => n,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    };
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    let Out::Header { done } = &mut self.out else {
                        unreachable!("out 态在 poll 内不变");
                    };
                    *done += n;
                    if *done >= total {
                        self.out = Out::Idle;
                        // 旧泵每块落线后 flush 底层（TLS 记录上线）。
                        match self.poll_flush_inner(cx) {
                            Poll::Ready(Ok(())) => {},
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                },
                Out::Chunk { head_done, body_done } => {
                    let head_len = self.head.len();
                    let body_len = self.stage.len();
                    let head_rest = &self.head[head_done..];
                    let body_rest = &self.stage.bytes()[body_done..];
                    if head_rest.is_empty() && body_rest.is_empty() {
                        self.out = Out::Idle;
                        continue;
                    }
                    let n = match Self::poll_write_bytes(
                        self.ss.get_mut(),
                        cx,
                        &[head_rest, body_rest],
                    ) {
                        Poll::Ready(Ok(n)) => n,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    };
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    let mut head_done = head_done;
                    let mut body_done = body_done;
                    let mut left = n;
                    if left <= head_rest.len() {
                        head_done += left;
                    } else {
                        left -= head_rest.len();
                        head_done = head_len;
                        body_done += left;
                    }
                    self.out = Out::Chunk { head_done, body_done };
                    if head_done >= head_len && body_done >= body_len {
                        self.out = Out::Idle;
                        // 落线完成 → 暂存区复位（池化块复用，零新分配）。
                        self.stage.clear();
                        self.staged = 0;
                        match self.poll_flush_inner(cx) {
                            Poll::Ready(Ok(())) => {},
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                },
            }
        }
    }

    /// 顺序写若干段（首段写完才写次段，wire 字节序不变）。
    ///
    /// 返回本次实际写出的字节数（部分写由调用方推进偏移量）；**一个字节都没写出且
    /// 底层未就绪 → `Pending`**（否则调用方会空转）。
    fn poll_write_bytes(
        inner: &mut Box<dyn Connection>,
        cx: &mut Context<'_>,
        segs: &[&[u8]],
    ) -> Poll<io::Result<usize>> {
        let mut written = 0usize;
        for seg in segs {
            if seg.is_empty() {
                continue;
            }
            match Pin::new(&mut *inner).poll_write(cx, seg) {
                Poll::Ready(Ok(n)) => {
                    written += n;
                    if n < seg.len() {
                        return Poll::Ready(Ok(written));
                    }
                },
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending if written == 0 => return Poll::Pending,
                Poll::Pending => return Poll::Ready(Ok(written)),
            }
        }
        Poll::Ready(Ok(written))
    }

    /// flush 底层连接（TLS 记录上线；裸 TCP 为空操作）。
    fn poll_flush_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.ss.get_mut()).poll_flush(cx)
    }

    /// SS-2022 请求头空闲兜底：上游 200ms 无数据也必须发出（padding-only 请求，
    /// 否则 server-speaks-first 目标（FTP/SMTP banner）双向等死锁）。
    fn poll_idle_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(timer) = self.idle.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        if timer.as_mut().poll(cx).is_pending() {
            return Poll::Ready(Ok(()));
        }
        self.idle = None;
        if !self.ss.has_pending_client_2022() {
            return Poll::Ready(Ok(()));
        }
        let (wire, _used) =
            self.ss.build_client_2022_header(&[]).map_err(|e| io::Error::other(e.to_string()))?;
        self.head.clear();
        self.head.extend_from_slice(&wire);
        self.out = Out::Header { done: 0 };
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SsStreamConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            // ① 已解出的明文交付（chunk 大于调用方缓冲时保留余量）。
            if !me.plain.is_empty() {
                let n = me.plain.len().min(buf.remaining());
                buf.put_slice(&me.plain[..n]);
                me.plain.advance(n);
                return Poll::Ready(Ok(()));
            }
            // ② SS-2022 请求头空闲兜底 + 推进待落线内容（写半由下行任务顺带驱动）。
            match me.poll_idle_header(cx) {
                Poll::Ready(Ok(())) => {},
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            match me.poll_out(cx) {
                Poll::Ready(Ok(())) => {},
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {},
            }
            // ③ 解帧：整帧解出才推进 nonce（半帧不推进，与旧泵同）。
            match me.ss.try_open_chunk(&mut me.pending) {
                Ok(ChunkOut::Message(plain)) => {
                    me.plain = plain;
                    continue;
                },
                Ok(ChunkOut::NeedMore) => {
                    // 需要更多 wire 字节：直读进 pending 的 spare 区（零中转拷贝）。
                    me.pending.reserve(DOWN_RESERVE);
                    let n = {
                        let spare = me.pending.spare_capacity_mut();
                        let mut rb = ReadBuf::uninit(spare);
                        let inner = me.ss.get_mut();
                        match Pin::new(inner).poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) => rb.filled().len(),
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    };
                    if n == 0 {
                        // wire EOF：关写向（旧泵同语义），下一次 poll 继续报 EOF。
                        let _ = Pin::new(me.ss.get_mut()).poll_shutdown(cx);
                        return Poll::Ready(Ok(()));
                    }
                    // SAFETY: 刚由底层读入 `n` 个已初始化字节到 pending 的 spare 区，
                    // `n ≤ spare.len()`，写入范围与已初始化范围严格一致。
                    unsafe { me.pending.advance_mut(n) };
                },
                Ok(ChunkOut::End) => {
                    // 0 长度 chunk = 流结束标记。
                    let _ = Pin::new(me.ss.get_mut()).poll_shutdown(cx);
                    return Poll::Ready(Ok(()));
                },
                Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
            }
        }
    }
}

impl AsyncWrite for SsStreamConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // ① 待落线内容先冲刷（wire 未就绪 → 背压，未消费任何明文）。
        match me.poll_out(cx) {
            Poll::Ready(Ok(())) => {},
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        // ② 明文进暂存区（一次 memcpy；密文 seal 原地覆写，载荷零拷贝）。
        let room = me.up_cap() - me.staged;
        let n = buf.len().min(room);
        if n > 0 {
            let dst = me.stage.writable_bytes();
            dst[..n].copy_from_slice(&buf[..n]);
            me.stage.advance_write(n);
            me.staged += n;
        }
        // ③ 满块 → 原地 seal（落线由后续 poll 推进）。
        if me.staged >= me.up_cap() {
            if let Err(e) = me.seal_stage() {
                return Poll::Ready(Err(io::Error::other(e.to_string())));
            }
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // ① 待落线内容先冲刷。
        match me.poll_out(cx) {
            Poll::Ready(Ok(())) => {},
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        // ② 暂存明文封块并落线（尾块 = 应用侧批次边界，与旧泵「读到多少封多少」同）。
        if me.staged > 0 {
            if let Err(e) = me.seal_stage() {
                return Poll::Ready(Err(io::Error::other(e.to_string())));
            }
            match me.poll_out(cx) {
                Poll::Ready(Ok(())) => {},
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        // ③ flush 底层。
        me.poll_flush_inner(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // ① 未发客户端请求头时兜底发出（Go requestDone 恒写请求头，payload 可为空）。
        if me.ss.has_pending_client_2022() {
            let (wire, _used) =
                me.ss.build_client_2022_header(&[]).map_err(|e| io::Error::other(e.to_string()))?;
            me.head.clear();
            me.head.extend_from_slice(&wire);
            me.out = Out::Header { done: 0 };
        }
        // ② 暂存明文封块落线。
        if me.staged > 0 {
            if let Err(e) = me.seal_stage() {
                return Poll::Ready(Err(io::Error::other(e.to_string())));
            }
        }
        // ③ 冲刷待落线内容 + 关底层写向（FIN）。
        match me.poll_out(cx) {
            Poll::Ready(Ok(())) => {},
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(me.ss.get_mut()).poll_shutdown(cx)
    }
}

impl Connection for SsStreamConn {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

    use super::*;
    use crate::config::{CipherType, MemoryAccount};

    /// 测试用底层连接（duplex 半）。
    struct TestConn(DuplexStream);

    impl AsyncRead for TestConn {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestConn {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl Connection for TestConn {
        fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
            Ok(None)
        }

        fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
            Ok(None)
        }
    }

    fn make_account() -> MemoryAccount {
        let p = ProtoAccount {
            password: "test-password".to_string(),
            cipher_type: CipherType::Aes256Gcm.as_i32(),
            iv_check: false,
        };
        MemoryAccount::from_proto(&p).expect("account")
    }

    /// SS 首帧明文（ATYP=IPv4 + 1.2.3.4:80）。
    const FIRST_FRAME: [u8; 7] = [0x01, 0x01, 0x02, 0x03, 0x04, 0x00, 0x50];

    /// 建一对共享 key/IV 的 SS 流：返回 (客户端直挂连接, 服务端解密读端)。
    ///
    /// 客户端先写 SS 首帧（addr+port，与 `Client::dial_target` 同），再包成直挂连接；
    /// 服务端 nonce 与客户端同起 `[0xFF;n]`，首帧后自然对齐到 body nonce。
    async fn pair() -> (SsStreamConn, SSStream<TestConn>) {
        let account = make_account();
        let iv: Vec<u8> = (0..account.cipher.iv_size()).map(|_| rand::random()).collect();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let mut client = SSStream::new_client(
            Box::new(TestConn(client_io)) as Box<dyn Connection>,
            &account,
            &iv,
        )
        .expect("client stream");
        // SS 首帧：ATYP=IPv4 + 1.2.3.4:80。
        client.write_chunk(&FIRST_FRAME).await.expect("首帧");
        client.flush().await.expect("flush 首帧");

        let server = SSStream::new_client(TestConn(server_io), &account, &iv).expect("server");
        (SsStreamConn::new(client), server)
    }

    /// 帧粒度不回退：1 MiB 负载经直挂连接落线后，帧数仍与改前 duplex 环泵同档。
    ///
    /// 每批 8×8KB = 65536B，而单帧载荷上限 65520B（64KiB 暂存 − 16B tag）⇒ 每批封
    /// 1 整帧 + 1 尾块 = 32 帧/MiB。改前泵同式（抓包实测 33 帧/MiB，见
    /// `reports/audit-2026-11-02/ss-frame-granularity.md` §2），故不回退。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn frames_per_mib_stays_batched() {
        let (mut conn, mut server) = pair().await;

        let writer = tokio::spawn(async move {
            // 模拟 bridge `write_all_mb`：8×8KB 一批，每批一次 flush。
            let batch = vec![0x5Au8; 8 * 1024];
            for _ in 0..16 {
                for _ in 0..8 {
                    conn.write_all(&batch).await.expect("write 8KB");
                }
                conn.flush().await.expect("flush batch");
            }
            conn.shutdown().await.expect("shutdown");
        });

        // 服务端逐帧解密：首帧是 addr+port，其余是负载。
        let mut frames = 0usize;
        let mut total = 0usize;
        while let Some(plain) = server.read_chunk().await.expect("read chunk") {
            if plain.as_slice() != FIRST_FRAME {
                frames += 1;
                total += plain.len();
            }
        }
        writer.await.expect("writer task");

        assert_eq!(total, 1024 * 1024, "1 MiB 负载逐字节送达");
        // 32 帧/MiB = 16 整帧(65520B) + 16 尾块；改前抓包实测 33 帧/MiB 同档。
        // 上限 40 吸收调度抖动，下限 16 = 纯理论满帧帧数（1 MiB / 65520）。
        assert!(frames <= 40, "帧粒度回退：{frames} 帧/MiB（改前 33，上限 40）");
        assert!(frames >= 16, "帧数异常偏少：{frames} 帧/MiB（1 MiB / 65520 = 16）");
    }

    /// 直挂连接读半：一个大 chunk 分多次 `poll_read` 交付，字节与顺序不变。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_splits_large_chunk_without_loss() {
        let (mut conn, mut server) = pair().await;
        let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let expect = payload.clone();
        let writer = tokio::spawn(async move {
            server.write_chunk(&payload).await.expect("写大 chunk");
            server.flush().await.expect("flush");
        });

        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while got.len() < expect.len() {
            let n = conn.read(&mut buf).await.expect("read");
            assert!(n > 0, "未到预期长度即 EOF");
            got.extend_from_slice(&buf[..n]);
        }
        writer.await.expect("writer task");
        assert_eq!(got, expect);
    }
}
