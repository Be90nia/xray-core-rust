//! 反向代理数据流（TCP 直连模式）。
//!
//! Bridge（客户端）：为每个入站连接直接连接 portal。
//! Portal（服务端）：接受 bridge 连接 → 路由到 outbound。
//!
//! ## 数据流
//!
//! ```text
//! [用户连接] → [Bridge] → TCP → [Portal] → [Outbound handler] → [目标]
//! ```
//!
//! 注：Go xray-core 使用 yamux 多路复用。yamux 0.14 使用 futures 生态，
//! tokio 适配需要 compat 层。当前用 TCP 直连替代，每流一连接。
//! yamux 集成待 futures/tokio compat 方案确定后接入。

use std::io;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

/// Bridge 客户端：连接 portal 并提供 stream 开启能力。
pub struct YamuxBridge {
    portal_addr: String,
}

impl YamuxBridge {
    /// 创建 Bridge，记录 portal 地址。
    pub fn new(portal_addr: String) -> Self {
        Self { portal_addr }
    }

    /// 打开一个新的 TCP 连接到 portal（每个入站连接一个 TCP）。
    pub async fn open_stream(&self) -> io::Result<TcpStream> {
        let stream = TcpStream::connect(&self.portal_addr).await?;
        stream.set_nodelay(true).ok();
        Ok(stream)
    }
}

/// Portal 服务端：接受 bridge 连接，为每个连接创建路由。
///
/// `on_stream` 回调用于路由连接到目标 outbound。
pub async fn serve_portal<F, Fut>(
    listener: TcpListener,
    on_stream: F,
) -> io::Result<()>
where
    F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let on_stream = Arc::new(on_stream);
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "portal accept error");
                continue;
            }
        };
        socket.set_nodelay(true).ok();

        let cb = Arc::clone(&on_stream);
        tokio::spawn(async move {
            tracing::debug!(peer = %peer, "portal stream connected");
            cb(socket).await;
            tracing::debug!(peer = %peer, "portal stream done");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_type_exists() {
        fn _assert_bridge(_b: YamuxBridge) {}
    }

    #[tokio::test]
    async fn portal_accept_and_forward() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // spawn portal
        tokio::spawn(async move {
            serve_portal(listener, |sock| async move {
                // Echo: write back what we read
                let (mut rd, mut wr) = sock.into_split();
                tokio::io::copy(&mut rd, &mut wr).await.ok();
            })
            .await
            .ok();
        });

        // connect via bridge
        let bridge = YamuxBridge::new(addr.to_string());
        let mut sock = bridge.open_stream().await.unwrap();
        use tokio::io::AsyncWriteExt;
        sock.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        use tokio::io::AsyncReadExt;
        sock.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }
}
