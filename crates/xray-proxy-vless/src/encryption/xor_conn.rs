//! XorConn (XTLS direct mode Phase A) — 双 CTR XOR 连接包装。
//!
//! 对应 Go `proxy/vless/outbound/outbound.go` 的 XorConn（xor_mode==2）。
//!
//! Phase A: 所有流量 XOR 加密（无 TLS header skip）。
//! Phase B: TLS header skip 状态机（后续实现）。

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::encryption::xor::CtrXor;
use crate::encryption::{EncryptionConn, Result};


/// XorConn：双 CTR XOR 连接包装。
///
/// - 读方向：`read_ctr` 解密
/// - 写方向：`write_ctr` 加密
///
/// Phase A：全部流量 XOR。Phase B 会加 TLS header skip。
pub struct XorConn<IO> {
    inner: IO,
    read_ctr: CtrXor,
    write_ctr: CtrXor,
}

impl<IO> XorConn<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// 创建 XorConn。
    ///
    /// # Arguments
    /// - `inner` — 底层连接（如 TLS stream）
    /// - `read_ctr` — 读方向（解密）CTR
    /// - `write_ctr` — 写方向（加密）CTR
    pub fn new(inner: IO, read_ctr: CtrXor, write_ctr: CtrXor) -> Self {
        Self { inner, read_ctr, write_ctr }
    }

    /// 获取底层连接引用。
    pub fn inner(&self) -> &IO {
        &self.inner
    }
}

impl<IO> AsyncRead for XorConn<IO>
where
    IO: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled_before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled_after = buf.filled().len();
                if filled_after > filled_before {
                    let newly_read = &mut buf.filled_mut()[filled_before..filled_after];
                    this.read_ctr.apply(newly_read);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<IO> AsyncWrite for XorConn<IO>
where
    IO: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // ponytail: alloc per write. Phase B 可能 buffer 化以做 TLS header skip.
        let mut encrypted = data.to_vec();
        this.write_ctr.apply(&mut encrypted);
        match Pin::new(&mut this.inner).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<IO> EncryptionConn for XorConn<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn close(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            use tokio::io::AsyncWriteExt;
            self.inner.shutdown().await?;
            Ok(())
        })
    }
}

 #[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn xor_roundtrip() {
        // 创建两个 CtrXor（客户端写 + 服务端读 = 相同 key/iv）
        let key = b"test-key-for-xor";
        let iv = &[0xAA; 16];

        let client_write = CtrXor::new(key, iv).unwrap();
        let client_read = CtrXor::new(key, iv).unwrap();
        let server_write = CtrXor::new(key, iv).unwrap();
        let server_read = CtrXor::new(key, iv).unwrap();

        let (client_io, server_io) = duplex(4096);

        let mut client = XorConn::new(client_io, client_read, client_write);
        let mut server = XorConn::new(server_io, server_read, server_write);

        // 客户端写 → 服务端读
        let msg = b"hello xor conn phase a!";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut buf = [0u8; 32];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg);
    }

    #[tokio::test]
    async fn xor_bidirectional() {
        let key = b"bidir-key";
        let iv_a = &[0x11; 16];
        let iv_b = &[0x22; 16];

        // 客户端：写用 iv_a，读用 iv_b
        // 服务端：写用 iv_b，读用 iv_a
        let (client_io, server_io) = duplex(4096);
        let mut client = XorConn::new(
            client_io,
            CtrXor::new(key, iv_b).unwrap(), // read
            CtrXor::new(key, iv_a).unwrap(), // write
        );
        let mut server = XorConn::new(
            server_io,
            CtrXor::new(key, iv_a).unwrap(), // read (matches client write)
            CtrXor::new(key, iv_b).unwrap(), // write (matches client read)
        );

        // 双向
        client.write_all(b"client->server").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0u8; 32];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"client->server");

        server.write_all(b"server->client").await.unwrap();
        server.flush().await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"server->client");
    }

    #[tokio::test]
    async fn xor_empty_read() {
        let key = b"key";
        let iv = &[0; 16];
        let (client_io, _server_io) = duplex(4096);
        let mut client = XorConn::new(client_io, CtrXor::new(key, iv).unwrap(), CtrXor::new(key, iv).unwrap());

        // 不写数据直接读 — 应该 pending（但 duplex 会 EOF）
        drop(_server_io); // 关闭服务端
        let mut buf = [0u8; 16];
        let result = client.read(&mut buf).await;
        // duplex 关闭另一端后，read 返回 0 (EOF)
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }
}
