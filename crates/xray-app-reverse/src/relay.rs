//! yamux 多路复用反向代理数据流。
//!
//! Bridge（客户端）：连接 portal，为每个入站连接打开 yamux stream。
//! Portal（服务端）：接受 bridge 连接，接受 yamux stream → 路由到 outbound。
//!
//! ## 数据流
//!
//! ```text
//! [用户连接] → [Bridge] → yamux stream → [Portal] → [Outbound handler] → [目标]
//! ```

use std::io;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::{FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};

use yamux::{Connection as YamuxConn, Config, Mode, Stream as YamuxStream};

/// Bridge 客户端：连接 portal 并提供 stream 开启能力。
pub struct YamuxBridge {
    control: yamux::Control,
}

impl YamuxBridge {
    /// 连接到 portal 服务器。
    ///
    /// 内部在后台 task 驱动 yamux 连接。
    pub async fn connect(portal_addr: &str) -> io::Result<Self> {
        let socket = TcpStream::connect(portal_addr).await?;
        socket.set_nodelay(true).ok();

        let conn = YamuxConn::new(socket.compat(), Config::default(), Mode::Client);
        let control = conn.control();

        // 后台驱动 yamux 连接（处理 incoming stream + keepalive）
        tokio::spawn(async move {
            use futures::stream::StreamExt;
            let mut conn = conn;
            // Bridge 端不应收到 incoming stream（只有 Portal 端收到）
            while conn.next().await.is_some() {}
        });

        tracing::info!(addr = portal_addr, "yamux bridge connected");
        Ok(Self { control })
    }

    /// 打开一个新的 yamux stream（用于中继入站连接）。
    pub async fn open_stream(&mut self) -> io::Result<YamuxStream> {
        self.control
            .open_stream()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))
    }
}

/// Portal 服务端：接受 bridge 连接，为每个 yamux stream 创建 Link。
///
/// `on_stream` 回调用于路由 stream 到目标 outbound。
pub async fn serve_portal<F, Fut>(
    listener: TcpListener,
    on_stream: F,
) -> io::Result<()>
where
    F: Fn(YamuxStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "portal accept error");
                continue;
            }
        };
        socket.set_nodelay(true).ok();

        let on_stream = Arc::new(on_stream);
        tokio::spawn(async move {
            let conn = YamuxConn::new(socket.compat(), Config::default(), Mode::Server);
            tracing::info!(peer = %peer, "yamux portal bridge connected");

            use futures::stream::StreamExt;
            let mut conn = conn;
            while let Some(result) = conn.next().await {
                match result {
                    Ok(stream) => {
                        let on_stream = Arc::clone(&on_stream);
                        tokio::spawn(async move {
                            on_stream(stream).await;
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "yamux portal stream error");
                        break;
                    }
                }
            }
            tracing::info!(peer = %peer, "yamux portal bridge disconnected");
        });
    }
}

/// 将 yamux Stream（futures trait）适配为 tokio compat 包装。
///
/// 返回的 reader/writer 实现 `tokio::io::AsyncRead + AsyncWrite`。
pub fn compat_stream(stream: YamuxStream) -> (impl tokio::io::AsyncRead, impl tokio::io::AsyncWrite) {
    let stream = stream.compat();
    let reader = stream;
    let writer = reader.clone(); // ponytail: yamux Stream is bi-directional, clone gives same stream
    (reader, writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_type_exists() {
        // 编译时类型检查
        fn _assert_bridge(_b: YamuxBridge) {}
    }
}
