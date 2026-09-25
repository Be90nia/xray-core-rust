//! 加密连接包装（对应 Go `encryption.CommonConn`）。
//!
//! 在底层连接上提供透明的加解密：
//! - [`CommonConn::poll_write`]：明文分段（≤8192）→ TLS record header + AEAD 加密 → 写底层
//! - [`CommonConn::poll_read`]：从底层读 → 按 TLS record 切片 → AEAD 解密 → 返回明文
//!
//! nonce 达到 MaxNonce 时按 Go 语义重建 AEAD（用当前 header 作 context）。
//! 0-RTT：上行 AEAD 构造时给定（context=加密后 ticket）；下行 AEAD 延迟到首次
//! 读，用 server 首发的 16B 随机数建立（[`CommonConn::new_zero_rtt`]）。

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    encryption::{
        aead::{Aead, MAX_NONCE, NONCE_LEN, TAG_LEN},
        common::{
            TLS_PAYLOAD_MAX, TLS_RECORD_HEADER_LEN, decode_tls_record_header,
            write_tls_record_header,
        },
    },
    error::{Result, VlessError},
};

/// 单段明文上限（对齐 Go `CommonConn` 的 8192）。
const MAX_SEGMENT: usize = 8192;

/// 加密连接：包装底层 `C`，实现 [`EncryptionConn`]。
///
/// 对应 Go 的 `*CommonConn`。构造时传入握手后的 AEAD 对（`aead` 发送 / `peer_aead` 接收）。
pub struct CommonConn<C> {
    conn: C,
    aead: Aead,
    /// 下行 AEAD。0-RTT 时为 `None`：延迟到首次读，用 server 首发的 16B 随机数
    /// 建立（Go common.go:84-93）。
    peer_aead: Option<Aead>,
    /// 重建 AEAD 所需：UnitedKey + use_aes（对齐 Go 轮换语义）。
    united_key: Vec<u8>,
    use_aes: bool,
    /// 从底层读到但尚未切分成 record 的原始字节；`raw_pos` 为已消费游标。
    /// 游标追平长度即整体清空——整 record 消费路径零 memmove（替代 drain 搬移）。
    raw_buf: Vec<u8>,
    raw_pos: usize,
    /// 已解密待读的明文（复用缓冲，原地解密，Go 池化等价物）。
    decrypted: Vec<u8>,
    /// 已解密待读的明文偏移。
    decrypted_pos: usize,
    /// 常驻写缓冲（Go 池化等价物）：[pre_write] || header || ciphertext || tag。
    /// pending 发送期间保持不动，发送完毕后下一段复用——写路径零堆分配。
    write_buf: Vec<u8>,
    /// 待发送：(write_buf 已发送偏移, 对应明文长度)。
    write_pending: Option<(usize, usize)>,
    /// 0-RTT 缓存 handle（仅 0-RTT 构造注入）：票据失效时清空三缓存。
    cache: Option<std::sync::Arc<super::ZeroRttCache>>,
    /// 首写前缀（Go `CommonConn.PreWrite`）：server 0-RTT 握手后的首个下行
    /// record 前附加的 16B 明文随机数，client 以其派生下行 AEAD（Go common.go:69-72，
    /// 首写时取出拼接后清空）。
    pre_write: Option<Vec<u8>>,
    closed: bool,
}

impl<C> CommonConn<C> {
    /// 内层连接访问（vision splice 的 `InnerRawClone` 穿透与测试裸读用）。
    pub(crate) fn inner_conn(&self) -> &C {
        &self.conn
    }

    pub(crate) fn inner_conn_mut(&mut self) -> &mut C {
        &mut self.conn
    }
}

impl<C> CommonConn<C>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// 创建加密连接（handshake 后调用，AEAD 对已协商完成）。
    #[must_use]
    pub fn new(conn: C, aead: Aead, peer_aead: Aead, use_aes: bool, united_key: Vec<u8>) -> Self {
        Self {
            conn,
            aead,
            peer_aead: Some(peer_aead),
            use_aes,
            united_key,
            cache: None,
            pre_write: None,
            raw_buf: Vec::with_capacity(16_384),
            raw_pos: 0,
            decrypted: Vec::with_capacity(TLS_PAYLOAD_MAX as usize),
            decrypted_pos: 0,
            write_buf: Vec::with_capacity(16 + TLS_RECORD_HEADER_LEN + MAX_SEGMENT + TAG_LEN),
            write_pending: None,
            closed: false,
        }
    }

    /// 0-RTT 构造（Go client.go:122-126）：上行 AEAD 已就绪（context=加密后
    /// ticket 32B），下行 `peer_aead` 延迟到首次读时用 server 随机数建立。
    pub fn new_zero_rtt(
        conn: C,
        aead: Aead,
        united_key: Vec<u8>,
        use_aes: bool,
        cache: Option<std::sync::Arc<super::ZeroRttCache>>,
    ) -> Self {
        Self {
            conn,
            aead,
            peer_aead: None,
            use_aes,
            united_key,
            cache,
            pre_write: None,
            raw_buf: Vec::with_capacity(16_384),
            raw_pos: 0,
            decrypted: Vec::with_capacity(TLS_PAYLOAD_MAX as usize),
            decrypted_pos: 0,
            write_buf: Vec::with_capacity(16 + TLS_RECORD_HEADER_LEN + MAX_SEGMENT + TAG_LEN),
            write_pending: None,
            closed: false,
        }
    }

    /// server 0-RTT 构造（Go server.go:227-230）：下行 AEAD 已就绪
    /// （context=PreWrite 16B 随机数），上行 `peer_aead` context=客户端加密 ticket
    /// 32B；`pre_write` 在首个下行 record 前明文写出（Go common.go:69-72）。
    pub fn new_server_zero_rtt(
        conn: C,
        aead: Aead,
        peer_aead: Aead,
        pre_write: Vec<u8>,
        united_key: Vec<u8>,
        use_aes: bool,
    ) -> Self {
        Self {
            conn,
            aead,
            peer_aead: Some(peer_aead),
            use_aes,
            united_key,
            cache: None,
            pre_write: Some(pre_write),
            raw_buf: Vec::with_capacity(16_384),
            raw_pos: 0,
            decrypted: Vec::with_capacity(TLS_PAYLOAD_MAX as usize),
            decrypted_pos: 0,
            write_buf: Vec::with_capacity(16 + TLS_RECORD_HEADER_LEN + MAX_SEGMENT + TAG_LEN),
            write_pending: None,
            closed: false,
        }
    }
}

impl<C> AsyncRead for CommonConn<C>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 0-RTT（Go common.go:84-93）：下行 AEAD 未建立时先读 server 首发的
            // 16B 随机数，以其为 context 建立（恰好 16B，不属于任何 record）。
            if this.peer_aead.is_none() {
                while this.raw_buf.len() - this.raw_pos < 16 {
                    let mut tmp = [0u8; 4096];
                    let mut rb = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut this.conn).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "EOF before 0-RTT server random",
                                )));
                            }
                            this.raw_buf.extend_from_slice(&tmp[..n]);
                        },
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                let server_random: [u8; 16] = this.raw_buf[this.raw_pos..this.raw_pos + 16]
                    .try_into()
                    .expect("16B server random");
                this.peer_aead = Some(Aead::new(&server_random, &this.united_key, this.use_aes));
                this.raw_pos += 16;
                if this.raw_pos == this.raw_buf.len() {
                    this.raw_buf.clear();
                    this.raw_pos = 0;
                }
            }
            // 1. 已解密明文优先返回
            if this.decrypted_pos < this.decrypted.len() {
                let avail = &this.decrypted[this.decrypted_pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                this.decrypted_pos += n;
                if this.decrypted_pos >= this.decrypted.len() {
                    this.decrypted.clear();
                    this.decrypted_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // 2. 尝试从 raw_buf 窗口提取完整 record
            let avail = this.raw_buf.len() - this.raw_pos;
            if avail >= TLS_RECORD_HEADER_LEN {
                let base = this.raw_pos;
                let header: [u8; TLS_RECORD_HEADER_LEN] = this.raw_buf
                    [base..base + TLS_RECORD_HEADER_LEN]
                    .try_into()
                    .expect("header slice len");
                let len = match decode_tls_record_header(&header) {
                    Ok(l) => l,
                    Err(e) => {
                        // 0-RTT 票据失效（Go server.go:210-222 session miss → 回噪声）：
                        // 噪声的 [16..21] 不是合法 record header。比对 united_key 前缀
                        // 64B 与缓存 pfs_key 确认本连接确用缓存票据建立，清空三缓存让
                        // 下条连接回到 1-RTT 慢路径，并返回专用错误供 dispatcher 自动重试。
                        if this.united_key.len() >= 64 {
                            if let Some(cache) = &this.cache {
                                if cache.matches_pfs_key(&this.united_key[..64]) {
                                    cache.clear();
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::ConnectionReset,
                                        super::TICKET_REJECTED_MSG,
                                    )));
                                }
                            }
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    },
                };
                let total = TLS_RECORD_HEADER_LEN + len as usize;
                if avail >= total {
                    // 完整 record：密文||tag 拷入复用的 decrypted 原地解密（零分配），
                    // 消费游标推进替代 drain memmove。
                    this.decrypted.clear();
                    this.decrypted.extend_from_slice(
                        &this.raw_buf[base + TLS_RECORD_HEADER_LEN..base + total],
                    );
                    let peer_aead =
                        this.peer_aead.as_mut().expect("peer_aead established at loop top");
                    if let Err(e) = peer_aead.open_in_place(None, &mut this.decrypted, &header) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }
                    this.raw_pos = base + total;
                    if this.raw_pos == this.raw_buf.len() {
                        this.raw_buf.clear();
                        this.raw_pos = 0;
                    }
                    this.decrypted_pos = 0;
                    continue; // 回到步骤 1 返回明文
                }
            }
            // 3. raw_buf 不足，从底层读
            let mut tmp = [0u8; 16_384];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.conn).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        // EOF：raw_buf 残留 = 不完整 record
                        if this.raw_pos == this.raw_buf.len() {
                            return Poll::Ready(Ok(())); // 干净 EOF
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated record at EOF",
                        )));
                    }
                    this.raw_buf.extend_from_slice(&tmp[..n]);
                },
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<C> AsyncWrite for CommonConn<C>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            if this.closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "write on closed CommonConn",
                )));
            }

            // 1. 先发完 pending（发送窗口 = 常驻 write_buf 的已发送偏移起）
            if let Some((sent, plain_len)) = this.write_pending.take() {
                match Pin::new(&mut this.conn).poll_write(cx, &this.write_buf[sent..]) {
                    // AsyncWrite 协议：非空 buf 的 Ok(0) = 写入器无法再接受数据。
                    // 裸 Pending 此处没有 waker 注册（底层返回的是 Ready），
                    // 返回它会丢唤醒——部分写入 + 跨缓冲窗口时即死锁。
                    Poll::Ready(Ok(0)) => {
                        this.write_pending = Some((sent, plain_len));
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "inner conn accepted 0 bytes",
                        )));
                    },
                    Poll::Ready(Ok(n)) => {
                        let new_sent = sent + n;
                        if new_sent >= this.write_buf.len() {
                            return Poll::Ready(Ok(plain_len));
                        }
                        this.write_pending = Some((new_sent, plain_len));
                        // 底层刚返回 Ready（部分写入）：立即重试剩余字节。
                        // 若在此返回 Pending，没有任何 poll 注册过 waker，
                        // 上层不再被唤醒 → 剩余字节滞留 → 对端凑不齐 record
                        // → 跨缓冲窗口流式死锁。
                        continue;
                    },
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    // 唯一合法的 Pending 出口：底层本次确实 Pending，
                    // 已用当前 cx 注册 waker。
                    Poll::Pending => {
                        this.write_pending = Some((sent, plain_len));
                        return Poll::Pending;
                    },
                }
            }

            // 2. 构造新段（全部写入常驻 write_buf 复用，零堆分配——Go 池化等价物）
            let n = buf.len().min(MAX_SEGMENT);
            if n == 0 {
                return Poll::Ready(Ok(0));
            }
            let data = &buf[..n];
            let mut header = [0u8; TLS_RECORD_HEADER_LEN];
            let payload_len = u16::try_from(n + TAG_LEN).expect("segment + tag fits in u16");
            write_tls_record_header(&mut header, payload_len);

            // nonce 达 MaxNonce → 重建 AEAD（对齐 Go：context=当前 header, key=UnitedKey）
            if this.aead.is_max() {
                this.aead = Aead::new(&header, &this.united_key, this.use_aes);
            }

            this.write_buf.clear();
            // 首写前缀（Go common.go:69-72）：server 0-RTT 的 16B 明文随机数
            // 与首个 record 同次写出，随后清空（后续写不含前缀）。
            if let Some(pre) = this.pre_write.take() {
                this.write_buf.extend_from_slice(&pre);
            }
            this.write_buf.extend_from_slice(&header);
            let hdr_end = this.write_buf.len();
            this.write_buf.extend_from_slice(data);
            let tag = this
                .aead
                .seal_in_place(None, &mut this.write_buf[hdr_end..], &header)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            this.write_buf.extend_from_slice(&tag);
            this.write_pending = Some((0, n));
            // continue → 下次迭代进入“发 pending”分支
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}

impl<C> super::EncryptionConn for CommonConn<C>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn close(&mut self) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            use tokio::io::AsyncWriteExt;
            self.closed = true;
            self.conn.shutdown().await.map_err(VlessError::from)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// round-trip：A 写 → 底层 → B 读。
    /// A.aead 与 B.peer_aead 同配置，seal(None)/open(None) nonce 同步递增，互通。
    #[tokio::test]
    async fn round_trip_basic() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let mut conn_a = CommonConn::new(
            client_io,
            Aead::new(b"ctx", b"united-key", true),
            Aead::new(b"ctx", b"united-key", true),
            true,
            b"united-key".to_vec(),
        );
        let mut conn_b = CommonConn::new(
            server_io,
            Aead::new(b"ctx", b"united-key", true),
            Aead::new(b"ctx", b"united-key", true),
            true,
            b"united-key".to_vec(),
        );

        conn_a.write_all(b"hello world").await.unwrap();
        conn_a.flush().await.unwrap();

        let mut buf = [0u8; 11];
        conn_b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello world");
    }

    /// 多段写 + 读（验证分段 8192 不破坏流）。
    #[tokio::test]
    async fn round_trip_multi_segment() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let payload = vec![0xABu8; 20_000]; // > 8192，触发分段

        let mut conn_a = CommonConn::new(
            client_io,
            Aead::new(b"ctx", b"k", true),
            Aead::new(b"ctx", b"k", true),
            true,
            b"k".to_vec(),
        );
        let mut conn_b = CommonConn::new(
            server_io,
            Aead::new(b"ctx", b"k", true),
            Aead::new(b"ctx", b"k", true),
            true,
            b"k".to_vec(),
        );

        conn_a.write_all(&payload).await.unwrap();
        conn_a.flush().await.unwrap();

        let mut got = vec![0u8; payload.len()];
        conn_b.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
    }

    /// ChaCha20 路径 round-trip（验证非 AES 分支）。
    #[tokio::test]
    async fn round_trip_chacha() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let mut conn_a = CommonConn::new(
            client_io,
            Aead::new(b"ctx", b"k", false),
            Aead::new(b"ctx", b"k", false),
            false,
            b"k".to_vec(),
        );
        let mut conn_b = CommonConn::new(
            server_io,
            Aead::new(b"ctx", b"k", false),
            Aead::new(b"ctx", b"k", false),
            false,
            b"k".to_vec(),
        );

        conn_a.write_all(b"chacha test").await.unwrap();
        conn_a.flush().await.unwrap();

        let mut buf = [0u8; 11];
        conn_b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"chacha test");
    }

    /// 双向通信：A↔B 互发互收。
    #[tokio::test]
    async fn bidirectional() {
        let (a_io, b_io) = tokio::io::duplex(64 * 1024);

        let mut conn_a = CommonConn::new(
            a_io,
            Aead::new(b"ctx", b"k", true),
            Aead::new(b"ctx-r", b"k", true),
            true,
            b"k".to_vec(),
        );
        let mut conn_b = CommonConn::new(
            b_io,
            Aead::new(b"ctx-r", b"k", true), // B 发用 ctx-r（对应 A 收）
            Aead::new(b"ctx", b"k", true),   // B 收用 ctx（对应 A 发）
            true,
            b"k".to_vec(),
        );

        // A → B
        conn_a.write_all(b"a-to-b").await.unwrap();
        conn_a.flush().await.unwrap();
        let mut buf1 = [0u8; 6];
        conn_b.read_exact(&mut buf1).await.unwrap();
        assert_eq!(&buf1, b"a-to-b");

        // B → A
        conn_b.write_all(b"b-to-a").await.unwrap();
        conn_b.flush().await.unwrap();
        let mut buf2 = [0u8; 6];
        conn_a.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"b-to-a");
    }
}
