//! # TCP hub
//!
//! 对应 Go `transport/internet/tcp/hub.go`。TCP listener 实现 + accept 循环。
//!
//! ## 架构
//!
//! - `TcpHubListener` — 持有 `DefaultListener` + `ConnHandler`，spawn accept 循环
//! - `listen_tcp_impl` — `TransportListenFn` 实现，注册到全局 listener 注册表
//! - `keep_accepting` — accept 循环：accept → TLS/REALITY/auth wrap → `add_conn`
//!
//! TLS/REALITY/auth wrapping 当前为 stub（对应 crate 未集成），直接传原始连接。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Notify;

use crate::connection::Connection;
use crate::listener_registry::{ConnHandler, TransportListener};
use crate::system_listener::SystemListener;
use crate::sockopt::SocketOptions;
use crate::system_listener::DefaultListener;

/// TCP hub listener。对应 Go `tcp/hub.go::Listener` struct。
///
/// 持有 `DefaultListener`（底层 TCP bind + accept + sockopt）+ `ConnHandler`（新连接回调）。
/// `keep_accepting` 在独立 tokio task 中运行，accept 后调用 `add_conn`。
pub struct TcpHubListener {
    inner: DefaultListener,
    add_conn: ConnHandler,
    close_notify: Arc<Notify>,
}

impl TcpHubListener {
    /// 创建 TCP hub listener 并 spawn accept 循环。
    ///
    /// 对应 Go `ListenTCP()`：bind → spawn `keepAccepting` → return。
    ///
    /// # 参数
    ///
    /// - `addr`：监听地址
    /// - `sockopt`：socket 选项
    /// - `add_conn`：新连接回调
    ///
    /// # 错误
    ///
    /// bind 失败时返回 `io::Error`。
    pub async fn listen(
        addr: SocketAddr,
        sockopt: &SocketOptions,
        add_conn: ConnHandler,
    ) -> io::Result<Self> {
        let inner = DefaultListener::bind(addr, sockopt.clone()).await?;
        let close_notify = Arc::new(Notify::new());

        let listener = Self {
            inner,
            add_conn,
            close_notify,
        };

        // ponytail: 暂不 spawn accept 循环——由调用方显式调用 `keep_accepting`
        // 或通过 `spawn_accept_loop` 启动。这避免在构造函数中隐式 spawn，
        // 让测试可以控制 accept 时机。
        Ok(listener)
    }

    /// Spawn accept 循环到独立 tokio task。
    ///
    /// 对应 Go `go l.keepAccepting()`。
    /// 返回 `JoinHandle`，调用方可 await 等待循环结束。
    pub fn spawn_accept_loop(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            this.keep_accepting().await;
        })
    }

    /// Accept 循环。对应 Go `keepAccepting()`。
    ///
    /// 循环调用 `inner.accept()`，对每个新连接：
    /// 1. TLS wrapping（stub — 等对应 crate 集成）
    /// 2. REALITY wrapping（stub）
    /// 3. auth wrapping（stub）
    /// 4. 调用 `add_conn(conn)`
    ///
    /// accept 错误处理与 Go 一致：
    /// - "closed" 错误 → break（监听器关闭）
    /// - "too many" 错误 → sleep 500ms 后 continue
    /// - 其他错误 → log + continue
    async fn keep_accepting(&self) {
        loop {
            let accept_fut = self.inner.accept();
            tokio::pin!(accept_fut);

            tokio::select! {
                result = &mut accept_fut => {
                    match result {
                        Ok(conn) => {
                            // ponytail: TLS/REALITY/auth wrapping 留待对应 crate 集成。
                            // 当前直接传原始连接给 add_conn。
                            (self.add_conn)(conn);
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("closed") {
                                break;
                            }
                            tracing::warn!(error = %e, "failed to accept raw connection");
                            if err_str.contains("too many") {
                                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            }
                            continue;
                        }
                    }
                }
                _ = self.close_notify.notified() => {
                    // 收到关闭信号，退出循环。
                    break;
                }
            }
        }
    }

    /// Accept 单个连接（不进入循环）。用于测试或自定义 accept 逻辑。
    pub async fn accept_one(&self) -> io::Result<Box<dyn Connection>> {
        self.inner.accept().await
    }
}

impl TransportListener for TcpHubListener {
    fn close(&self) -> io::Result<()> {
        // 通知 accept 循环退出（打断 select! 中的 accept 等待）。
        self.close_notify.notify_waiters();
        // ponytail: 底层 TcpListener 在 Arc drop 时关闭。
        // 如果需要立即释放端口，需在 DefaultListener 上加 close() 方法。
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

// ===== TransportListenFn 实现 =====

/// TCP 协议的 `TransportListenFn` 实现。
///
/// 注册到全局 listener 注册表，让 `listen_tcp("tcp", ...)` 可找到。
pub async fn listen_tcp_impl(
    addr: SocketAddr,
    _settings: crate::dialer::StreamSettings,
    sockopt: SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let listener = TcpHubListener::listen(addr, &sockopt, handler).await?;
    Ok(Box::new(listener) as Box<dyn TransportListener>)
}

/// 创建 TCP `TransportListenFn`（用于注册到全局注册表）。
#[must_use]
pub fn tcp_listen_fn() -> crate::listener_registry::TransportListenFn {
    Arc::new(
        |addr: SocketAddr,
         settings: crate::dialer::StreamSettings,
         sockopt: SocketOptions,
         handler: ConnHandler| {
            Box::pin(async move { listen_tcp_impl(addr, settings, sockopt, handler).await })
        },
    )
}

// ===== 旧 API 兼容 =====
//
// 保留 `register_tcp_listener` / `take_tcp_listener` 向后兼容，
// 但标记为 deprecated——新代码应使用 `listener_registry::register_transport_listener`。

use std::collections::HashMap;
use std::sync::Mutex;
use tokio::net::TcpListener as TokioTcpListener;

static TCP_HUB: std::sync::OnceLock<Mutex<HashMap<SocketAddr, TokioTcpListener>>> = std::sync::OnceLock::new();
fn tcp_hub() -> &'static Mutex<HashMap<SocketAddr, TokioTcpListener>> {
    TCP_HUB.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 注册 TCP listener。锁中毒时静默忽略。
#[deprecated(note = "use listener_registry::register_transport_listener instead")]
pub fn register_tcp_listener(addr: SocketAddr, listener: TokioTcpListener) {
    if let Ok(mut hub) = tcp_hub().lock() {
        hub.insert(addr, listener);
    }
}

/// 取出已注册的 TCP listener（从注册表中移除）。
#[deprecated(note = "use listener_registry::get_transport_listener instead")]
pub fn take_tcp_listener(addr: SocketAddr) -> Option<TokioTcpListener> {
    tcp_hub().lock().ok().and_then(|mut hub| hub.remove(&addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn tcp_hub_listener_bind_and_accept() {
        let handler: ConnHandler = Arc::new(|_| {});
        let listener =
            TcpHubListener::listen("127.0.0.1:0".parse().unwrap(), &SocketOptions::default(), handler)
                .await
                .expect("listen 失败");
        let addr = listener.local_addr().expect("local_addr 失败");

        let server = tokio::spawn(async move {
            let mut conn = listener.accept_one().await.expect("accept 失败");
            conn.write_all(b"pong").await.expect("write 失败");
        });

        let mut client = TcpStream::connect(addr).await.expect("connect 失败");
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.expect("read 失败");
        assert_eq!(&buf, b"pong");

        server.await.expect("server task panic");
    }

    #[tokio::test]
    async fn tcp_hub_listener_local_addr() {
        let handler: ConnHandler = Arc::new(|_| {});
        let listener =
            TcpHubListener::listen("127.0.0.1:0".parse().unwrap(), &SocketOptions::default(), handler)
                .await
                .expect("listen 失败");
        let addr = listener.local_addr().expect("local_addr 失败");
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_ne!(addr.port(), 0);
    }

    #[tokio::test]
    async fn keep_accepting_calls_handler() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&count);
        let handler: ConnHandler = Arc::new(move |_conn| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        });

        let listener = Arc::new(
            TcpHubListener::listen("127.0.0.1:0".parse().unwrap(), &SocketOptions::default(), handler)
                .await
                .expect("listen 失败"),
        );
        let addr = listener.local_addr().expect("local_addr 失败");

        let accept_handle = listener.spawn_accept_loop();

        // 连接 3 个客户端。
        for _ in 0..3 {
            let _ = TcpStream::connect(addr).await.expect("connect 失败");
        }

        // 等待 accept 循环处理。
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert_eq!(count.load(Ordering::SeqCst), 3);

        // 关闭 listener 让 accept 循环退出。
        listener.close().ok();
        // drop listener 触发 closed 错误退出循环。
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let _ = accept_handle.await;
    }

    #[tokio::test]
    async fn tcp_listen_fn_registers_and_works() {
        use crate::tcp::register_tcp_transport;

        // 注册 TCP transport（忽略 AlreadyExists，可能之前测试已注册）。
        let _ = register_tcp_transport();

        let handler: ConnHandler = Arc::new(|_| {});
        let listener = crate::listener_registry::listen_tcp(
            "127.0.0.1:0".parse().unwrap(),
            crate::dialer::StreamSettings::tcp(),
            SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen_tcp 失败");
        let addr = listener.local_addr().expect("local_addr 失败");
        assert_ne!(addr.port(), 0);
    }

    #[tokio::test]
    async fn transport_listener_trait_close_and_local_addr() {
        let handler: ConnHandler = Arc::new(|_| {});
        let listener: Box<dyn TransportListener> = Box::new(
            TcpHubListener::listen("127.0.0.1:0".parse().unwrap(), &SocketOptions::default(), handler)
                .await
                .expect("listen 失败"),
        );
        let addr = listener.local_addr().expect("local_addr 失败");
        assert_ne!(addr.port(), 0);
        listener.close().expect("close 失败");
    }
}
