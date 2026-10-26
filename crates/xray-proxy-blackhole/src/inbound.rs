//! Blackhole 入站处理器：accept 连接后静默关闭。
//!
//! 对应 Go 版本中 blackhole 不注册 inbound（Go 只有 outbound），
//! 但 Rust 侧为满足 InboundHandler 注册要求，提供此实现。
//!
//! ## 行为
//!
//! - `ResponseConfig::None`：accept 后直接 drop 连接（静默关闭）。
//! - `ResponseConfig::Http403`：写 HTTP 403 响应后关闭。

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU16, Ordering},
};

use async_trait::async_trait;
use tokio::net::TcpListener;
use xray_features::inbound::{InboundError, InboundHandler};
use xray_frame::PluginContext;

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
    /// L2 能力句柄（nn8os 2b：spawn/log 只经 ctx——坑约束 5/10；原自持
    /// `Arc<FxScope>` 收编进 ctx）。Arc 形态：accept 循环内层 per-conn spawn
    /// 需在 'static 任务里再取 ctx.spawn。scope 随 handler drop 兜底 abort
    /// 在途任务（生命周期与原自持面等价）。
    ctx: Arc<PluginContext>,
}

impl BlackholeInboundHandler {
    /// 构造 Blackhole 入站处理器。
    pub fn new(
        ctx: Arc<PluginContext>,
        tag: impl Into<String>,
        response: ResponseConfig,
        listen_addr: impl Into<String>,
    ) -> Self {
        Self {
            tag: tag.into(),
            response,
            listen_addr: listen_addr.into(),
            cached_port: AtomicU16::new(0),
            started: AtomicBool::new(false),
            ctx,
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
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        self.cached_port.store(port, Ordering::SeqCst);
        let response = self.response.clone();
        let tag = self.tag.clone();
        // 任务内日志只持克隆门面（spawn 的 future 不得借用 ctx）。
        let log = self.ctx.log().clone();
        // spawn accept 循环（ctx.spawn 托管，坑约束 5）。
        // 预制克隆源：避免 async move 块自捕获 ctx 与 spawn 接收者借用冲突（E0505）。
        let ctx_conns = Arc::clone(&self.ctx);
        self.ctx
            .spawn(async move {
                loop {
                    let (stream, _peer) = match listener.accept().await {
                        Ok(v) => v,
                        Err(e) => {
                            log.warn(format!(
                                "blackhole inbound accept failed tag={tag} error={e}"
                            ));
                            continue;
                        },
                    };
                    let response = response.clone();
                    let ctx = Arc::clone(&ctx_conns);
                    // future 专持克隆：async move 捕获的绑定不得与 spawn
                    // 接收者同源（E0505：&self 借用期间不可 move out）。
                    let fut_ctx = Arc::clone(&ctx);
                    ctx.spawn(async move {
                        match &response {
                            ResponseConfig::None => {
                                // 静默关闭：直接 drop 连接
                                drop(stream);
                            },
                            ResponseConfig::Http403 => {
                                // 写 HTTP 403 后关闭
                                use tokio::io::AsyncWriteExt;
                                let mut stream = stream;
                                if let Err(e) = stream
                                    .write_all(crate::response::HTTP_403_RESPONSE.as_bytes())
                                    .await
                                {
                                    fut_ctx.log().debug(format!(
                                        "blackhole inbound write 403 failed error={e}"
                                    ));
                                }
                                let _ = stream.shutdown().await;
                            },
                            ResponseConfig::Custom(data) => {
                                // Go 01a034be：custom 原样回写后关闭
                                use tokio::io::AsyncWriteExt;
                                let mut stream = stream;
                                if !data.is_empty() {
                                    if let Err(e) = stream.write_all(data).await {
                                        fut_ctx.log().debug(format!(
                                            "blackhole inbound write custom failed error={e}"
                                        ));
                                    }
                                }
                                let _ = stream.shutdown().await;
                            },
                        }
                    })
                    .expect("plugin ctx FxScope is never closed (assembly-owned)");
                }
            })
            .expect("plugin ctx FxScope is never closed (assembly-owned)");
        self.ctx.log().info(format!("blackhole inbound started tag={} port={port}", self.tag));
        Ok(())
    }

    async fn close(&self) -> Result<(), InboundError> {
        if !self.started.swap(false, Ordering::SeqCst) {
            return Err(InboundError::Closed(self.tag.clone()));
        }
        // ponytail: accept 循环在独立 task 中运行，close 只设标志位。
        // 真正的优雅关闭需要 CancellationToken，当前设 port=0 即可。
        self.cached_port.store(0, Ordering::SeqCst);
        self.ctx.log().info(format!("blackhole inbound closed tag={}", self.tag));
        Ok(())
    }

    fn port(&self) -> u16 {
        self.cached_port.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::{io::AsyncReadExt, net::TcpStream};
    use xray_frame::PluginContext;

    use super::*;

    /// 测试用 L2 句柄：for_plugin 配方（自持 scope + 独享审计环）。
    fn test_ctx() -> Arc<PluginContext> {
        Arc::new(PluginContext::for_plugin("blackhole"))
    }

    #[tokio::test]
    async fn blackhole_inbound_none_response_drops_immediately() {
        let handler = BlackholeInboundHandler::new(
            test_ctx(),
            "bh-test",
            ResponseConfig::None,
            "127.0.0.1:0",
        );
        handler.start().await.unwrap();
        let port = handler.port();
        assert!(port > 0);

        let mut conn = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        // 连接应被立即关闭（读返回 0）
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), conn.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0, "blackhole none response should close immediately");

        handler.close().await.unwrap();
    }

    #[tokio::test]
    async fn blackhole_inbound_http403_writes_response() {
        let handler = BlackholeInboundHandler::new(
            test_ctx(),
            "bh-http",
            ResponseConfig::Http403,
            "127.0.0.1:0",
        );
        handler.start().await.unwrap();
        let port = handler.port();

        let mut conn = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), conn.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0, "should receive HTTP 403 response");
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.starts_with("HTTP/1.1 403"), "response should be HTTP 403");

        handler.close().await.unwrap();
    }

    #[test]
    fn port_zero_before_start() {
        let handler =
            BlackholeInboundHandler::new(test_ctx(), "bh", ResponseConfig::None, "127.0.0.1:0");
        assert_eq!(handler.port(), 0);
    }

    #[tokio::test]
    async fn double_start_returns_error() {
        let handler =
            BlackholeInboundHandler::new(test_ctx(), "bh-dbl", ResponseConfig::None, "127.0.0.1:0");
        handler.start().await.unwrap();
        let result = handler.start().await;
        assert!(result.is_err());
        handler.close().await.unwrap();
    }
}
