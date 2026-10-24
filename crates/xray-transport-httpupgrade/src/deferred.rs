//! 延迟响应读取器——ed (0-RTT / Early Data) 支持。
//!
//! 对应 Go `dialer.go::ConnRF`：`First bool` 控制首次 Read 时解析 101 响应。
//!
//! 当 `config.ed > 0` 时，客户端写完 HTTP Upgrade 请求后不立即读 101 响应，
//! 让上层协议先写 early data（0-RTT），首次 `AsyncRead::poll_read` 时才解析响应。

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::dialer::parse_upgrade_response;

/// 延迟响应读取状态。
#[derive(Debug)]
enum State {
    /// 尚未读取 101 响应。
    Pending,
    /// 正在读取 101 响应。
    ReadingResponse(Vec<u8>),
    /// 101 已解析，余留 payload 缓存。
    Ready { leftover: Vec<u8> },
}

/// poll_read 内部动作。
enum Action {
    StartReading,
    ContinueReading,
    DrainLeftover,
}

/// 延迟响应读取器。
///
/// 包装底层 IO，在首次 `AsyncRead::poll_read` 时才解析 HTTP 101 响应。
/// `AsyncWrite` 始终透传到 inner（允许上层在握手完成前写 early data）。
pub struct DeferredResponseReader<IO> {
    inner: IO,
    state: State,
}

impl<IO> DeferredResponseReader<IO> {
    /// 构造延迟读取器。`inner` 已写完 HTTP Upgrade 请求但未读响应。
    pub fn new(inner: IO) -> Self {
        Self { inner, state: State::Pending }
    }

    /// 拆出内层 IO。
    pub fn into_inner(self) -> IO {
        self.inner
    }
}

/// 响应头读取缓冲上限。
const MAX_RESPONSE_SIZE: usize = 64 * 1024;

impl<IO: AsyncRead + Unpin> AsyncRead for DeferredResponseReader<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // 先检查状态，决定动作（避免同时 &mut state 和 &mut inner）
            let action = match &self.state {
                State::Pending => Action::StartReading,
                State::ReadingResponse(rb) => {
                    if rb.len() >= MAX_RESPONSE_SIZE {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "HTTPUpgrade response header too large",
                        )));
                    }
                    Action::ContinueReading
                },
                State::Ready { leftover } => {
                    if !leftover.is_empty() {
                        Action::DrainLeftover
                    } else {
                        // leftover 空，透传到 inner
                        return Pin::new(&mut self.inner).poll_read(cx, buf);
                    }
                },
            };

            match action {
                Action::StartReading => {
                    self.state = State::ReadingResponse(Vec::with_capacity(1024));
                },
                Action::ContinueReading => {
                    // 取出 response_buf，读 inner，再放回
                    let rb = match std::mem::replace(&mut self.state, State::Pending) {
                        State::ReadingResponse(rb) => rb,
                        _ => unreachable!(),
                    };
                    let mut chunk = [0u8; 1024];
                    let mut read_buf = ReadBuf::new(&mut chunk);
                    let result = Pin::new(&mut self.inner).poll_read(cx, &mut read_buf);
                    match result {
                        Poll::Pending => {
                            self.state = State::ReadingResponse(rb);
                            return Poll::Pending;
                        },
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                "EOF before HTTP response header complete",
                            )));
                        },
                        Poll::Ready(Ok(())) => {
                            let mut rb = rb;
                            rb.extend_from_slice(read_buf.filled());
                            if find_header_end(&rb).is_some() {
                                let payload_offset = match parse_upgrade_response(&rb) {
                                    Ok(offset) => offset,
                                    Err(e) => {
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::ConnectionRefused,
                                            format!("HTTPUpgrade response validation failed: {e}"),
                                        )));
                                    },
                                };
                                let leftover = if payload_offset < rb.len() {
                                    rb[payload_offset..].to_vec()
                                } else {
                                    Vec::new()
                                };
                                self.state = State::Ready { leftover };
                            } else {
                                self.state = State::ReadingResponse(rb);
                            }
                        },
                    }
                },
                Action::DrainLeftover => {
                    let leftover = match std::mem::replace(
                        &mut self.state,
                        State::Ready { leftover: Vec::new() },
                    ) {
                        State::Ready { leftover } => leftover,
                        _ => unreachable!(),
                    };
                    let n = leftover.len().min(buf.remaining());
                    buf.put_slice(&leftover[..n]);
                    if n < leftover.len() {
                        self.state = State::Ready { leftover: leftover[n..].to_vec() };
                    }
                    return Poll::Ready(Ok(()));
                },
            }
        }
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for DeferredResponseReader<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<IO: xray_transport::connection::Connection + Unpin> xray_transport::connection::Connection
    for DeferredResponseReader<IO>
{
    fn remote_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.remote_addr()
    }

    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.local_addr()
    }
}

/// 在字节流中查找 `\r\n\r\n` 位置。
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn deferred_read_parses_101_on_first_read() {
        let (mut client_io, mut server_io) = duplex(8192);

        // 客户端先写请求（模拟 dial_over_io 已写完）
        client_io
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            )
            .await
            .unwrap();
        client_io.flush().await.unwrap();

        let mut reader = DeferredResponseReader::new(client_io);

        // 服务端回 101 + payload
        let mut buf = vec![0u8; 4096];
        let _ = server_io.read(&mut buf).await.unwrap();
        server_io.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nhello").await.unwrap();
        server_io.flush().await.unwrap();

        // 首次 read 应解析 101 并返回 payload
        let mut out = vec![0u8; 64];
        let n = reader.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"hello");
    }

    #[tokio::test]
    async fn deferred_write_works_before_read() {
        let (client_io, mut server_io) = duplex(8192);

        let mut reader = DeferredResponseReader::new(client_io);

        // 在读 101 之前先写 early data
        reader.write_all(b"early").await.unwrap();

        // 服务端读 early data
        let mut buf = vec![0u8; 4096];
        let n = server_io.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"early");

        // 服务端回 101（无后续 payload）后关闭，客户端读到 EOF
        server_io.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
        server_io.flush().await.unwrap();
        drop(server_io);

        // 现在读：先解析 101（leftover 空），再透传 inner 得到 EOF
        let mut out = vec![0u8; 64];
        let n = reader.read(&mut out).await.unwrap();
        assert_eq!(n, 0); // EOF
    }

    #[tokio::test]
    async fn deferred_rejects_non_101() {
        let (client_io, mut server_io) = duplex(8192);

        let mut reader = DeferredResponseReader::new(client_io);

        // 服务端回 200（非 101）
        server_io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        server_io.flush().await.unwrap();

        let mut out = vec![0u8; 64];
        let result = reader.read(&mut out).await;
        assert!(result.is_err());
    }
}
