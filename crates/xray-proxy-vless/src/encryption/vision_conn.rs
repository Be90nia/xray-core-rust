//! XTLS-Vision 连接包装（对应 Go `proxy/proxy.go` 的 VisionReader/VisionWriter）。
//!
//! 在 [`CommonConn`]（AEAD 加密层）之上提供 Vision padding：
//! - [`VisionConn::poll_write`]：明文 padding 包装 → CommonConn AEAD 加密 → 底层
//! - [`VisionConn::poll_read`]：CommonConn AEAD 解密 → unpadding → 返回明文
//!
//! 切片 2a：padding 模式完整（Continue/End），Direct(splice) 返回 Unsupported。
//! 切片 2b（待办）：splice 切换底层 rawConn 绕过 AEAD。

use crate::encryption::aead::Aead;
use crate::encryption::common_conn::CommonConn;
use crate::encryption::vision::{
    xtls_padding, xtls_unpadding, DirectionState, COMMAND_PADDING_CONTINUE,
    COMMAND_PADDING_DIRECT, COMMAND_PADDING_END, DEFAULT_PADDING_SEED,
};
use rand::rngs::ThreadRng;
use rand::Rng;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// padding 块 content 上限（BUF_SIZE - header(5) - uuid(16) = 8171）。
const MAX_PADDING_CONTENT: usize = 8171;
/// Vision 连接：包装 [`CommonConn`]，提供 XTLS-Vision padding。
///
/// 对应 Go 的 VisionReader/VisionWriter。padding 模式下每个读写都包装/解包
/// Vision padding 块，直到 command=End（关闭 padding）或 command=Direct（splice，待办）。
pub struct VisionConn<C> {
    inner: CommonConn<C>,
    /// user_uuid（始终保留，downlink unpadding 匹配首块用）。
    user_uuid: Vec<u8>,
    /// uplink 首次 padding 附带的 uuid（take 后 None）。
    uplink_uuid_pending: Option<Vec<u8>>,
    /// uplink（writer）方向状态。
    uplink_state: DirectionState,
    /// downlink（reader）方向状态。
    downlink_state: DirectionState,
    /// unpadding 后待返回的 content。
    downlink_pending: Vec<u8>,
    downlink_pending_pos: usize,
    /// padding 块待写入底层（padded, sent_in_padded, original_buf_len）。
    uplink_write_pending: Option<(Vec<u8>, usize, usize)>,
    /// padding 模式标志（command=End 后关闭）。
    uplink_padding: bool,
    downlink_padding: bool,
    rng: ThreadRng,
}

impl<C> VisionConn<C>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// 创建 Vision 连接（handshake 后调用，AEAD 对已协商完成）。
    #[must_use]
    pub fn new(
        conn: C,
        aead: Aead,
        peer_aead: Aead,
        use_aes: bool,
        united_key: Vec<u8>,
        user_uuid: Vec<u8>,
    ) -> Self {
        let uplink_uuid_pending = Some(user_uuid.clone());
        Self {
            inner: CommonConn::new(conn, aead, peer_aead, use_aes, united_key),
            user_uuid,
            uplink_uuid_pending,
            uplink_state: DirectionState::default(),
            downlink_state: DirectionState::default(),
            downlink_pending: Vec::new(),
            downlink_pending_pos: 0,
            uplink_write_pending: None,
            uplink_padding: true,
            downlink_padding: true,
            rng: rand::rng(),
        }
    }
}

impl<C> AsyncRead for VisionConn<C>
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
            // 1. pending 优先返回
            if this.downlink_pending_pos < this.downlink_pending.len() {
                let avail = &this.downlink_pending[this.downlink_pending_pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                this.downlink_pending_pos += n;
                if this.downlink_pending_pos >= this.downlink_pending.len() {
                    this.downlink_pending.clear();
                    this.downlink_pending_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // 2. padding 关闭 → 直接 CommonConn read（无 unpadding）
            if !this.downlink_padding {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            // 3. padding 模式 → CommonConn read + unpadding
            let mut tmp = [0u8; 16_384];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    let content =
                        xtls_unpadding(&tmp[..n], &mut this.downlink_state, &this.user_uuid);
                    let cmd = this.downlink_state.current_command;
                    if cmd == COMMAND_PADDING_END as i32 {
                        this.downlink_padding = false;
                    } else if cmd == COMMAND_PADDING_DIRECT as i32 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "Vision splice (Direct) not implemented in this slice",
                        )));
                    }
                    if !content.is_empty() {
                        this.downlink_pending = content;
                        this.downlink_pending_pos = 0;
                    }
                    // content 空（纯 padding 块）或已存 pending → continue
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<C> AsyncWrite for VisionConn<C>
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
            // 1. 先写完 pending padded
            if let Some((padded, sent, orig_len)) = this.uplink_write_pending.take() {
                if sent >= padded.len() {
                    return Poll::Ready(Ok(orig_len));
                }
                match Pin::new(&mut this.inner).poll_write(cx, &padded[sent..]) {
                    Poll::Ready(Ok(0)) => {
                        this.uplink_write_pending = Some((padded, sent, orig_len));
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(n)) => {
                        let new_sent = sent + n;
                        if new_sent >= padded.len() {
                            return Poll::Ready(Ok(orig_len));
                        }
                        this.uplink_write_pending = Some((padded, new_sent, orig_len));
                        // 底层 Ready，continue 循环继续写剩余 padded（避免无 wakeup 的 Pending）
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        this.uplink_write_pending = Some((padded, sent, orig_len));
                        return Poll::Pending;
                    }
                }
            }

            // 2. padding 关闭 → 直接 CommonConn write
            if !this.uplink_padding {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }

            // 3. padding 模式 → padding 包装
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            // 3. padding 模式 → 分段 padding（每段 content ≤ MAX_PADDING_CONTENT，
            //    确保一个 padding 块 = 一个 CommonConn record）
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let n = buf.len().min(MAX_PADDING_CONTENT);
            let padded = xtls_padding(
                Some(&buf[..n]),
                COMMAND_PADDING_CONTINUE,
                &mut this.uplink_uuid_pending,
                false,
                &DEFAULT_PADDING_SEED,
                &mut this.rng,
            );
            this.uplink_write_pending = Some((padded, 0, n));
            // continue → 步骤 1 写 pending
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 构造一对互连的 VisionConn（共享相同 AEAD key，模拟 handshake 后状态）。
    fn make_pair() -> (
        VisionConn<tokio::io::DuplexStream>,
        VisionConn<tokio::io::DuplexStream>,
    ) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let uuid = vec![0xABu8; 16];
        let key = b"united-key".to_vec();
        let ctx = b"ctx";
        (
            VisionConn::new(
                a,
                Aead::new(ctx, &key, true),
                Aead::new(ctx, &key, true),
                true,
                key.clone(),
                uuid.clone(),
            ),
            VisionConn::new(
                b,
                Aead::new(ctx, &key, true),
                Aead::new(ctx, &key, true),
                true,
                key.clone(),
                uuid.clone(),
            ),
        )
    }

    #[tokio::test]
    async fn round_trip_basic() {
        let (mut a, mut b) = make_pair();
        a.write_all(b"hello vision").await.unwrap();
        a.flush().await.unwrap();

        let mut buf = [0u8; 12];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello vision");
    }

    #[tokio::test]
    async fn round_trip_bidirectional() {
        let (mut a, mut b) = make_pair();
        a.write_all(b"c2s-hello").await.unwrap();
        a.flush().await.unwrap();
        b.write_all(b"s2c-world").await.unwrap();
        b.flush().await.unwrap();

        let mut buf = [0u8; 9];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"c2s-hello");
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"s2c-world");
    }

    #[tokio::test]
    async fn multiple_writes() {
        let (mut a, mut b) = make_pair();
        a.write_all(b"msg1-").await.unwrap();
        a.write_all(b"msg2-").await.unwrap();
        a.write_all(b"msg3").await.unwrap();
        a.flush().await.unwrap();

        let mut buf = [0u8; 14];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"msg1-msg2-msg3");
    }

    #[tokio::test]
    async fn medium_write() {
        // 100 字节（一个 CommonConn record），验证基本 padding/unpadding。
        let (mut a, mut b) = make_pair();
        let payload: Vec<u8> = (0u8..=255).cycle().take(100).collect();
        a.write_all(&payload).await.unwrap();
        a.flush().await.unwrap();

        let mut buf = vec![0u8; 100];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, payload);
    }
    #[tokio::test]
    async fn large_write() {
        // 跨多个 CommonConn record（每段 ≤8192）验证 unpadding 跨 record 累积。
        // 用 join! 并发 write+read，避免顺序死锁（write 缓冲满时需 read 消费）。
        let (mut a, mut b) = make_pair();
        let payload: Vec<u8> = (0u8..=255).cycle().take(16_384).collect();
        let payload_clone = payload.clone();

        tokio::join!(
            async {
                a.write_all(&payload).await.unwrap();
                a.flush().await.unwrap();
            },
            async {
                let mut buf = vec![0u8; 16_384];
                b.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, payload_clone);
            }
        );
    }
}
