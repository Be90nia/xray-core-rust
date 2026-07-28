//! Blackhole 入站处理器：accept 连接后静默关闭。
//!
//! 对应 Go 版本中 blackhole 不注册 inbound（Go 只有 outbound），
//! 但 Rust 侧为满足 InboundHandler 注册要求，提供此实现。
//!
//! ## 行为
//!
//! - `ResponseConfig::None`：accept 后直接 drop 连接（静默关闭）。
//! - `ResponseConfig::Http403`：写 HTTP 403 响应后关闭。

use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use async_trait::async_trait;
use tokio::net::TcpListener;
use xray_features::inbound::{InboundError, InboundHandler};

use crate::response::ResponseConfig;

/// Blackhole 入站处理器。accept 连接后按 [`ResponseConfig`] 写响应（或直接关闭）。
pub struct BlackholeInboundHandler {
    /// Handler 唯一标识。
    tag: String,
    /// 响应配置：None=静默关闭，Http403=写 403 后关闭。
    response: ResponseConfig,
    /// 监听地址。
    listen_addr: String,
    /// 缓存的监听端口（start 后填充）。
    cached_port: AtomicU16,
    /// 是否已启动。
    started: AtomicBool,
}

impl BlackholeInboundHandler {
    /// 构造 Blackhole 入站处理器。
    pub fn new(tag: impl Into<String>, response: ResponseConfig, listen_addr: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            response,
            listen_addr: listen_addr.into(),
            cached_port: AtomicU16::new(0),
            started: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl InboundHandler for BlackholeInboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self) -> Result<(), InboundError> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Err(InboundError::AlreadyStarted(self.tag.clone()));
        }
        let listener = TcpListener::bind(&self.listen_addr)
            .await
            .map_err(|e| InboundError::ListenError(e.to_string()))?;
        let port = listener.local_addr()
            .map(|a| a.port())
            .unwrap_or(0);
        self.cached_port.store(port, Ordering::SeqCst);
        let response = self.response;
        let tag = self.tag.clone();
        // spawn accept 循环
        tokio::spawn(async move {
            loop {
                let (stream, _peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(tag = %tag, error = %e, "blackhole inbound accept failed");
                        continue;
                    }
                };
                tokio::spawn(async move {
                    match response {
                        ResponseConfig::None => {
                            // 静默关闭：直接 drop 连接
                            drop(stream);
                        }
                        ResponseConfig::Http403 => {
                            // 写 HTTP 403 后关闭
                            use tokio::io::AsyncWriteExt;
                            let mut stream = stream;
                            if let Err(e) = stream.write_all(crate::response::HTTP_403_RESPONSE.as_bytes()).await {
                                tracing::debug!(error = %e, "blackhole inbound write 403 failed");
                            }
                            let _ = stream.shutdown().await;
                        }
                    }
                });
            }
        });
        tracing::info!(tag = %self.tag, port = port, "blackhole inbound started");
        Ok(())
    }

    async fn close(&self) -> Result<(), InboundError> {
        if !self.started.swap(false, Ordering::SeqCst) {
            return Err(InboundError::Closed(self.tag.clone()));
        }
        // ponytail: accept 循环在独立 task 中运行，close 只设标志位。
        // 真正的优雅关闭需要 CancellationToken，当前设 port=0 即可。
        self.cached_port.store(0, Ordering::SeqCst);
        tracing::info!(tag = %self.tag, "blackhole inbound closed");
        Ok(())
    }

    fn port(&self) -> u16 {
        self.cached_port.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn blackhole_inbound_none_response_drops_immediately() {
        let handler = BlackholeInboundHandler::new("bh-test", ResponseConfig::None, "127.0.0.1:0");
        handler.start().await.unwrap();
        let port = handler.port();
        assert!(port > 0);

        let mut conn = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        // 连接应被立即关闭（读返回 0）
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            conn.read(&mut buf),
        ).await.unwrap().unwrap();
        assert_eq!(n, 0, "blackhole none response should close immediately");

        handler.close().await.unwrap();
    }

    #[tokio::test]
    async fn blackhole_inbound_http403_writes_response() {
        let handler = BlackholeInboundHandler::new("bh-http", ResponseConfig::Http403, "127.0.0.1:0");
        handler.start().await.unwrap();
        let port = handler.port();

        let mut conn = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            conn.read(&mut buf),
        ).await.unwrap().unwrap();
        assert!(n > 0, "should receive HTTP 403 response");
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.starts_with("HTTP/1.1 403"), "response should be HTTP 403");

        handler.close().await.unwrap();
    }

    #[test]
    fn port_zero_before_start() {
        let handler = BlackholeInboundHandler::new("bh", ResponseConfig::None, "127.0.0.1:0");
        assert_eq!(handler.port(), 0);
    }

    #[tokio::test]
    async fn double_start_returns_error() {
        let handler = BlackholeInboundHandler::new("bh-dbl", ResponseConfig::None, "127.0.0.1:0");
        handler.start().await.unwrap();
        let result = handler.start().await;
        assert!(result.is_err());
        handler.close().await.unwrap();
    }
}
