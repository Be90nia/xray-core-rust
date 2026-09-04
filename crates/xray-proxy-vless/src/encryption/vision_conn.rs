//! XTLS-Vision 连接包装（对应 Go `proxy/proxy.go` 的 VisionReader/VisionWriter）。
//!
//! 在 [`CommonConn`]（AEAD 加密层）之上提供 Vision padding：
//! - [`VisionConn::poll_write`]: 明文 padding 包装 → 底层 conn（CommonConn AEAD 或 TLS 直传）
//! - [`VisionConn::poll_read`]: 底层 conn 读取 → unpadding → 返回明文
//!
//! 切片 2a：padding 模式完整（Continue/End）。
//! 切片 2b：splice（command=Direct 触发，绕过 Vision padding，仍走底层 conn）。

use crate::encryption::aead::Aead;
use crate::encryption::common_conn::CommonConn;
use crate::encryption::vision::{
    is_complete_record, xtls_filter_tls, xtls_padding, xtls_unpadding, DirectionState,
    TrafficState, COMMAND_PADDING_CONTINUE, COMMAND_PADDING_DIRECT, COMMAND_PADDING_END,
    DEFAULT_PADDING_SEED,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use xray_transport::connection::Connection;

/// padding 块 content 上限（BUF_SIZE - header(5) - uuid(16) = 8171）。
const MAX_PADDING_CONTENT: usize = 8171;
/// 内层裸 TCP 克隆入口（vision splice 用）。
///
/// 生产链内层是 `Box<dyn Connection>`（实现 [`Connection`]，穿透到最底层
/// `TcpConnection::raw_tcp_clone`）；tests/inbound 的内层（`CommonConn<DuplexStream>`、
/// `tokio::io::Join`）无裸 TCP 可克隆，走默认 `None`。
pub(crate) trait InnerRawClone {
    fn inner_raw_tcp_clone(&self) -> Option<TcpStream> {
        None
    }
}

impl InnerRawClone for Box<dyn Connection> {
    fn inner_raw_tcp_clone(&self) -> Option<TcpStream> {
        (**self).raw_tcp_clone()
    }
}

impl<A: AsyncRead, B: AsyncWrite> InnerRawClone for tokio::io::Join<A, B> {}

impl InnerRawClone for CommonConn<tokio::io::DuplexStream> {}
/// Vision 连接：包装 [`CommonConn`]，提供 XTLS-Vision padding。
///
/// 对应 Go 的 VisionReader/VisionWriter。padding 模式下每个读写都包装/解包
/// Vision padding 块，直到 command=End（关闭 padding）或 command=Direct（splice，待办）。
pub struct VisionConn<C> {
    inner: C,
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
    rng: StdRng,
    /// uplink TLS 过滤状态（检测 TLS 1.3 → enable_xtls → splice）。
    uplink_traffic: TrafficState,
    /// downlink TLS 过滤状态（检测服务器 TLS 1.3 → enable_xtls → splice）。
    downlink_traffic: TrafficState,
    /// splice 后的裸 TCP 读直通道（server 发 DIRECT 帧后克隆内层 socket）。
    raw_fallback: Option<TcpStream>,
}

impl<C> VisionConn<C>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// 创建 Vision 连接，包装一个已建立的底层连接。
    ///
    /// `conn` 可以是 `CommonConn`（encryption=mlkem768 场景）或 TLS conn
    /// （encryption=none + flow=xtls-rprx-vision 场景）。
    /// `user_uuid` 为首块 padding 附带的 UUID（Vision 协议要求）。
    #[must_use]
    pub fn new(conn: C, user_uuid: Vec<u8>) -> Self {
        let uplink_uuid_pending = Some(user_uuid.clone());
        Self {
            inner: conn,
            user_uuid: user_uuid.clone(),
            uplink_uuid_pending,
            uplink_state: DirectionState::default(),
            downlink_state: DirectionState::default(),
            downlink_pending: Vec::new(),
            downlink_pending_pos: 0,
            uplink_write_pending: None,
            uplink_padding: true,
            downlink_padding: true,
            rng: StdRng::from_os_rng(),
            uplink_traffic: TrafficState::new(user_uuid.clone()),
            downlink_traffic: TrafficState::new(user_uuid.clone()),
            raw_fallback: None,
        }
    }
    /// dial 同步阶段主动发 uuid-only padding 块,后续 chunk 进 vision content。
    /// 对齐 Go outbound VisionWriter mb[0]=nil → XtlsPadding(None, CommandPaddingContinue)。
    pub async fn write_uuid_only_padding(&mut self) -> io::Result<()> {
        use crate::encryption::vision::{xtls_padding, COMMAND_PADDING_CONTINUE};
        use tokio::io::AsyncWriteExt;
        let padded = xtls_padding(
            None,
            COMMAND_PADDING_CONTINUE,
            &mut self.uplink_uuid_pending,
            true,
            &DEFAULT_PADDING_SEED,
            &mut self.rng,
        );
        self.inner.write_all(&padded).await?;
        Ok(())
    }
}

impl<C> AsyncRead for VisionConn<C>
where
    C: AsyncRead + AsyncWrite + Unpin + InnerRawClone,
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

            // 2. padding 关闭 → 优先裸 TCP 直读；raw 通道不可用（无 TLS 或
            //    非生产链内层）才退 inner。splice 后读 inner 会把对端在裸 TCP
            //    上发的明文 TLS records 当外层密文解密 → 永远解不开。
            if !this.downlink_padding {
                if let Some(raw) = this.raw_fallback.as_mut() {
                    return Pin::new(raw).poll_read(cx, buf);
                }
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
                    // server 关闭下行 padding：END=只关 padding（继续读 TLS 层），
                    // DIRECT=splice——server 已 UnwrapRawConn，此后在裸 TCP 上
                    // 收发端到端 TLS records。本帧 content 先入 pending 返回给
                    // caller，再克隆裸 socket 切换读通道（对齐 Go XtlsRead）。
                    // 对齐 Go VisionReader（proxy.go L244-253）：仅当当前帧
                    // 完成（content/padding 无残留）时 END/DIRECT 才生效；
                    // End/Direct 帧可能跨块，帧未完成就切 raw 会跳过帧尾字节
                    // 并把外层 TLS 密文当裸流转发 → curl 解密失败。
                    let frames_done = this.downlink_state.remaining_content <= 0
                        && this.downlink_state.remaining_padding <= 0
                        && cmd != 0;
                    if frames_done {
                        if cmd == COMMAND_PADDING_END as i32 {
                            this.downlink_padding = false;
                        } else if cmd == COMMAND_PADDING_DIRECT as i32 {
                            this.downlink_padding = false;
                            this.raw_fallback = this.inner.inner_raw_tcp_clone();
                        }
                    }
                    if !content.is_empty() {
                        // downlink TLS 过滤：检测下行 TLS 1.3 → enable_xtls
                        // 对齐 Go VisionReader 的 xtls_filter_tls 调用
                        if this.downlink_traffic.number_of_packet_to_filter > 0 {
                            xtls_filter_tls(&[&content], &mut this.downlink_traffic);
                        }
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
    C: AsyncRead + AsyncWrite + Unpin + InnerRawClone,
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

            // 2. padding 关闭 → 优先裸 TCP 直写（splice 后对端已拆外层 TLS，
            //    写 inner 会把 caller 的 TLS records 当明文再加密一层）。
            if !this.uplink_padding {
                if let Some(raw) = this.raw_fallback.as_mut() {
                    return Pin::new(raw).poll_write(cx, buf);
                }
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }

            // 3. padding 模式 → TLS 检测 + 分段 padding
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let n = buf.len().min(MAX_PADDING_CONTENT);
            // TLS filter：检测 TLS 1.3 ServerHello → enable_xtls（仅过滤窗口内）
            if this.uplink_traffic.number_of_packet_to_filter > 0 {
                xtls_filter_tls(&[&buf[..n]], &mut this.uplink_traffic);
            }
            // splice trigger（对齐 Go VisionWriter.WriteMultiBuffer L356-393）：
            // Go 的 TrafficState.EnableXtls 是共享字段——由下行 ServerHello
            // 检测置位，上行 writer 直接读它（Rust 侧两个实例，等价于读
            // downlink_traffic）。触发还需 caller 写入是完整的 TLS app-data
            // record（0x17 0x03 0x03 前缀 = curl 的端到端 TLS records）。
            let is_app_data = buf.len() >= 3 && buf[0] == 0x17 && buf[1] == 0x03 && buf[2] == 0x03;
            let command = if this.downlink_traffic.enable_xtls
                && is_app_data
                && is_complete_record(buf)
                && n == buf.len()
            {
                COMMAND_PADDING_DIRECT
            } else {
                COMMAND_PADDING_CONTINUE
            };
            let padded = xtls_padding(
                Some(&buf[..n]),
                command,
                &mut this.uplink_uuid_pending,
                false,
                &DEFAULT_PADDING_SEED,
                &mut this.rng,
            );
            this.uplink_write_pending = Some((padded, 0, n));
            if command == COMMAND_PADDING_DIRECT {
                this.uplink_padding = false;
                this.raw_fallback = this.inner.inner_raw_tcp_clone();
            }
            // continue → 步骤 1 写 pending
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(raw) = this.raw_fallback.as_mut() {
            return Pin::new(raw).poll_flush(cx);
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(raw) = this.raw_fallback.as_mut() {
            // splice 后对端已拆外层 TLS：半关闭通知必须走裸 TCP（inner 的
            // TLS close_notify 会被对端当 raw bytes 转发污染下游流）。
            return Pin::new(raw).poll_shutdown(cx);
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// `Connection` 转发（地址信息透传内层，padding 层不改变连接属性），
/// 让 `VisionConn<Box<dyn Connection>>` 可作为 `Box<dyn Connection>` 返回生产路径。
impl<C> xray_transport::connection::Connection for VisionConn<C>
where
    C: xray_transport::connection::Connection + InnerRawClone,
{
    fn remote_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.remote_addr()
    }
    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 构造一对互连的 VisionConn（共享相同 AEAD key，模拟 handshake 后状态）。
    fn make_pair() -> (
        VisionConn<CommonConn<tokio::io::DuplexStream>>,
        VisionConn<CommonConn<tokio::io::DuplexStream>>,
    ) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let uuid = vec![0xABu8; 16];
        let key = b"united-key".to_vec();
        let ctx = b"ctx";
        let common_a = CommonConn::new(
            a,
            Aead::new(ctx, &key, true),
            Aead::new(ctx, &key, true),
            true,
            key.clone(),
        );
        let common_b = CommonConn::new(
            b,
            Aead::new(ctx, &key, true),
            Aead::new(ctx, &key, true),
            true,
            key.clone(),
        );
        (
            VisionConn::new(common_a, uuid.clone()),
            VisionConn::new(common_b, uuid.clone()),
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

    /// 构造 TLS 1.3 ServerHello record（触发 xtls_filter_tls enable_xtls）。
    fn build_tls13_server_hello_record() -> Vec<u8> {
        let mut buf = Vec::new();
        // record header placeholder (len 填后补)
        buf.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]);
        let hs_start = buf.len();
        buf.push(0x02); // ServerHello
        buf.extend_from_slice(&[0x00, 0x00, 0x00]); // handshake len placeholder
        let hs_body_start = buf.len();
        buf.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        buf.extend_from_slice(&[0xAB; 32]); // random
        buf.push(32); // session_id_len
        buf.extend_from_slice(&[0xCD; 32]); // session_id
        buf.extend_from_slice(&[0x13, 0x01]); // cipher TLS_AES_128_GCM_SHA256
        buf.push(0x00); // compression null
        let ext_start = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]); // ext len placeholder
        // supported_versions: type=0x002b + len=2 + 0x0304 (TLS 1.3)
        buf.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        let ext_len = buf.len() - ext_start - 2;
        buf[ext_start..ext_start + 2].copy_from_slice(&(ext_len as u16).to_be_bytes());
        let hs_len = buf.len() - hs_body_start;
        buf[hs_start + 1..hs_start + 4].copy_from_slice(&(hs_len as u32).to_be_bytes()[1..]);
        let rec_len = buf.len() - 5;
        buf[3..5].copy_from_slice(&(rec_len as u16).to_be_bytes());
        buf
    }

    /// 构造 TLS ApplicationData record。
    fn build_tls_app_data(payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x17, 0x03, 0x03]);
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[tokio::test]
    async fn splice_uplink_on_tls13() {
        let (mut a, mut b) = make_pair();
        // 1. TLS 1.3 ServerHello → xtls_filter_tls enable_xtls
        let sh = build_tls13_server_hello_record();
        a.write_all(&sh).await.unwrap();
        a.flush().await.unwrap();
        // 2. TLS ApplicationData → enable_xtls + is_complete_record → Direct + splice
        let app = build_tls_app_data(b"GET / HTTP/1.1\r\n\r\n");
        a.write_all(&app).await.unwrap();
        a.flush().await.unwrap();
        // 3. splice 后明文直写（绕过 padding）
        a.write_all(b"post-splice").await.unwrap();
        a.flush().await.unwrap();
        // reader b: sh（Continue padding）+ app（Direct padding content）+ post-splice（splice 后直读）
        let mut buf = vec![0u8; sh.len() + app.len() + 11];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..sh.len()], &sh);
        assert_eq!(&buf[sh.len()..sh.len() + app.len()], &app);
        assert_eq!(&buf[sh.len() + app.len()..], b"post-splice");
    }

    #[tokio::test]
    async fn splice_bidirectional() {
        // 双向独立 splice：a uplink + b uplink 各自触发
        let (mut a, mut b) = make_pair();
        let sh = build_tls13_server_hello_record();
        let app = build_tls_app_data(b"data");
        // a → b: sh + app（触发 a uplink splice）
        a.write_all(&sh).await.unwrap();
        a.write_all(&app).await.unwrap();
        a.flush().await.unwrap();
        // b → a: sh + app（触发 b uplink splice）
        b.write_all(&sh).await.unwrap();
        b.write_all(&app).await.unwrap();
        b.flush().await.unwrap();
        // 并发读验证双向
        let total = sh.len() + app.len();
        let mut buf_a = vec![0u8; total];
        let mut buf_b = vec![0u8; total];
        tokio::join!(
            async { a.read_exact(&mut buf_a).await.unwrap(); },
            async { b.read_exact(&mut buf_b).await.unwrap(); }
        );
        let mut expected = sh.clone();
        expected.extend_from_slice(&app);
        assert_eq!(buf_a, expected);
        assert_eq!(buf_b, expected);
    }
}
