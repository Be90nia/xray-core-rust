//! 加密连接包装（对应 Go `encryption.CommonConn`）。
//!
//! 在底层连接上提供透明的加解密：
//! - [`CommonConn::poll_write`]：明文分段（≤8192）→ TLS record header + AEAD 加密 → 写底层
//! - [`CommonConn::poll_read`]：从底层读 → 按 TLS record 切片 → AEAD 解密 → 返回明文
//!
//! nonce 达到 MaxNonce 时按 Go 语义重建 AEAD（用当前 header 作 context）。
//! 0-RTT：上行 AEAD 构造时给定（context=加密后 ticket）；下行 AEAD 延迟到首次
//! 读，用 server 首发的 16B 随机数建立（[`CommonConn::new_zero_rtt`]）。

use crate::encryption::aead::{Aead, MAX_NONCE, NONCE_LEN};
use crate::encryption::common::{
    decode_tls_record_header, write_tls_record_header, TLS_PAYLOAD_MIN, TLS_RECORD_HEADER_LEN,
};
use crate::error::{Result, VlessError};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 单段明文上限（对齐 Go `CommonConn` 的 8192）。
const MAX_SEGMENT: usize = 8192;

/// GCM/Poly1305 认证标签长度。
const TAG_LEN: usize = 16;

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
    /// 从底层读到但尚未切分成 record 的原始字节。
    raw_buf: Vec<u8>,
    /// 已解密待读的明文。
    decrypted: Vec<u8>,
    decrypted_pos: usize,
    /// 待发送的密文 + 已发送偏移 + 对应明文长度。
    write_pending: Option<(Vec<u8>, usize, usize)>,
    /// 首写前缀（Go `CommonConn.PreWrite`）：server 0-RTT 握手后的首个下行
    /// record 前附加的 16B 明文随机数，client 以其派生下行 AEAD（Go common.go:69-72，
    /// 首写时取出拼接后清空）。
    pre_write: Option<Vec<u8>>,
    closed: bool,
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
            pre_write: None,
            raw_buf: Vec::new(),
            decrypted: Vec::new(),
            decrypted_pos: 0,
            write_pending: None,
            closed: false,
        }
    }

    /// 0-RTT 构造（Go client.go:122-126）：上行 AEAD 已就绪（context=加密后
    /// ticket 32B），下行 `peer_aead` 延迟到首次读时用 server 随机数建立。
    pub fn new_zero_rtt(conn: C, aead: Aead, united_key: Vec<u8>, use_aes: bool) -> Self {
        Self {
            conn,
            aead,
            peer_aead: None,
            use_aes,
            united_key,
            pre_write: None,
            raw_buf: Vec::new(),
            decrypted: Vec::new(),
            decrypted_pos: 0,
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
            pre_write: Some(pre_write),
            raw_buf: Vec::new(),
            decrypted: Vec::new(),
            decrypted_pos: 0,
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
                while this.raw_buf.len() < 16 {
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
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                let server_random: [u8; 16] =
                    this.raw_buf[..16].try_into().expect("16B server random");
                this.peer_aead =
                    Some(Aead::new(&server_random, &this.united_key, this.use_aes));
                this.raw_buf.drain(..16);
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

            // 2. 尝试从 raw_buf 提取完整 record
            if this.raw_buf.len() >= TLS_RECORD_HEADER_LEN {
                let header: [u8; TLS_RECORD_HEADER_LEN] =
                    this.raw_buf[..TLS_RECORD_HEADER_LEN].try_into().unwrap();
                let len = match decode_tls_record_header(&header) {
                    Ok(l) => l,
                    Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))),
                };
                let total = TLS_RECORD_HEADER_LEN + len as usize;
                if this.raw_buf.len() >= total {
                    // 完整 record：解密
                    let data: Vec<u8> = this.raw_buf[TLS_RECORD_HEADER_LEN..total].to_vec();
                    let mut plaintext = Vec::with_capacity(data.len().saturating_sub(TAG_LEN));
                    let peer_aead = this
                        .peer_aead
                        .as_mut()
                        .expect("peer_aead established at loop top");
                    if let Err(e) = peer_aead.open(&mut plaintext, None, &data, &header) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }
                    this.raw_buf.drain(..total);
                    this.decrypted = plaintext;
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
                        if this.raw_buf.is_empty() {
                            return Poll::Ready(Ok(())); // 干净 EOF
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated record at EOF",
                        )));
                    }
                    this.raw_buf.extend_from_slice(&tmp[..n]);
                }
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

            // 1. 先发完 pending
            if let Some((ct, sent, plain_len)) = this.write_pending.take() {
                match Pin::new(&mut this.conn).poll_write(cx, &ct[sent..]) {
                    Poll::Ready(Ok(0)) => {
                        this.write_pending = Some((ct, sent, plain_len));
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(n)) => {
                        let new_sent = sent + n;
                        if new_sent >= ct.len() {
                            return Poll::Ready(Ok(plain_len));
                        }
                        this.write_pending = Some((ct, new_sent, plain_len));
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        this.write_pending = Some((ct, sent, plain_len));
                        return Poll::Pending;
                    }
                }
            }

            // 2. 构造新段
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

            let mut ct = Vec::with_capacity(TLS_RECORD_HEADER_LEN + n + TAG_LEN + 16);
            // 首写前缀（Go common.go:69-72）：server 0-RTT 的 16B 明文随机数
            // 与首个 record 同次写出，随后清空（后续写不含前缀）。
            if let Some(pre) = this.pre_write.take() {
                ct.extend_from_slice(&pre);
            }
            ct.extend_from_slice(&header);
            if let Err(e) = this.aead.seal(&mut ct, None, data, &header) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())));
            }
            this.write_pending = Some((ct, 0, n));
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
    fn close(
        &mut self,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
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
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
