//! 监听器抽象：服务端 IO 边界。
//!
//! 对应 Go `transport/internet/system_listener.go` 的 `DefaultListener`。
//! 仅翻译 IO 边界 trait，平台特定细节（TCP keepalive、Unix socket + FileLocker、
//! proxyproto、socket2 syscall.RawConn）留待具体传输实现 crate 处理。

use std::{future::Future, io, net::SocketAddr, pin::Pin};

use tokio::net::TcpListener as TokioTcpListener;

use crate::connection::{Connection, TcpConnection};

/// 服务端监听器 trait。`accept` 返回 `Box<dyn Connection>`，沿用项目手写
/// `Pin<Box<dyn Future>>` 风格（避免 `#[async_trait]`，符合翻译约定 §3）。
pub trait Listener: Send + Sync {
    /// 接受一个入站连接。返回的连接对象以 trait object 形式交由上层多态使用。
    fn accept<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Connection>>> + Send + 'a>>;

    /// 监听器本地地址。
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// 基于 `tokio::net::TcpListener` 的 `Listener` 参考实现。
///
/// 命名 `TcpListenerConn` 避免与 `tokio::net::TcpListener` 直接重名，
/// 同时表达「产出 Connection 的 Listener」语义。
#[derive(Debug)]
pub struct TcpListenerConn {
    inner: TokioTcpListener,
}

impl TcpListenerConn {
    /// 用已绑定的 tokio 监听器构造。
    pub fn new(inner: TokioTcpListener) -> Self {
        Self { inner }
    }

    /// 绑定到指定地址。封装 `TokioTcpListener::bind` 以让构造路径与 Go
    /// `DefaultListener::Listen(ctx, addr, sockopt)` 对齐（sockopt 暂未实现）。
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let inner = TokioTcpListener::bind(addr).await?;
        Ok(Self { inner })
    }

    /// 取回内部 tokio 监听器。
    pub fn into_inner(self) -> TokioTcpListener {
        self.inner
    }
}

impl Listener for TcpListenerConn {
    fn accept<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Connection>>> + Send + 'a>> {
        Box::pin(async move {
            let (stream, _peer) = self.inner.accept().await?;
            // ponytail: 暂不处理 keepalive/sockopt，留给具体传输实现 crate
            Ok(Box::new(TcpConnection::new(stream)) as Box<dyn Connection>)
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    use super::*;

    #[tokio::test]
    async fn tcp_listener_bind_and_accept() {
        let listener =
            TcpListenerConn::bind("127.0.0.1:0".parse().unwrap()).await.expect("bind 失败");
        let bound = listener.local_addr().expect("local_addr 失败");

        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.expect("accept 失败");
            // pong 回客户端
            conn.write_all(b"pong").await.expect("write 失败");
        });

        let mut client = TcpStream::connect(bound).await.expect("connect 失败");
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.expect("客户端读取失败");
        assert_eq!(&buf, b"pong");

        server.await.expect("server task panic");
    }

    #[tokio::test]
    async fn local_addr_returns_bound_port() {
        let listener =
            TcpListenerConn::bind("127.0.0.1:0".parse().unwrap()).await.expect("bind 失败");
        let addr = listener.local_addr().expect("local_addr 失败");
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        // 端口由 OS 分配，必须非 0（bind(:0) 后会被填入实际端口）
        assert_ne!(addr.port(), 0);
    }

    #[tokio::test]
    async fn accept_returns_dyn_connection_usable_as_async_io() {
        // 验证 accept 产出的 Box<dyn Connection> 可被当作 AsyncRead+AsyncWrite 使用，
        // 证明 tokio blanket impl 经 Connection supertrait 自动可用。
        let listener =
            TcpListenerConn::bind("127.0.0.1:0".parse().unwrap()).await.expect("bind 失败");
        let bound = listener.local_addr().expect("local_addr 失败");

        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.expect("accept 失败");
            // 读取客户端发来的字节后原样回写
            let mut byte = [0u8; 1];
            conn.read_exact(&mut byte).await.expect("read 失败");
            conn.write_all(&byte).await.expect("write 失败");
        });

        let mut client = TcpStream::connect(bound).await.expect("connect 失败");
        client.write_all(b"X").await.expect("客户端写入失败");
        let mut buf = [0u8; 1];
        client.read_exact(&mut buf).await.expect("客户端读取失败");
        assert_eq!(buf, [b'X']);

        server.await.expect("server task panic");
    }
}
