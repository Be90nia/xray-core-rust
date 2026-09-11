//! # TCP hub
//!
//! 对应 Go `transport/internet/tcp/hub.go`。TCP listener 实现 + accept 循环。
//!
//! ## 架构
//!
//! - `TcpHubListener` — 持有 `DefaultListener` + `ConnHandler`，spawn accept 循环
//! - `listen_tcp_impl` — `TransportListenFn` 实现，注册到全局 listener 注册表
//! - `keep_accepting` — accept 循环：accept → header auth wrap → `add_conn`
//!   （Go hub.go:125-127）
//!
//! TLS/REALITY wrapping 不在 hub（生产 TLS 由 xray-core inbound 各协议层包装）。

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
    /// header 伪装 authenticator（Go hub.go:24 `authConfig internet.ConnectionAuthenticator`）。
    /// `None` = 未配置（type none/缺失）→ accept 后不包装。
    auth: Option<Arc<crate::headers::http::HttpAuthenticator>>,
    /// Tcpmask 伪装管理器（Go hub.go:68 `WrapListener`），accept 后对每条连接做
    /// `WrapConnServer` 链式包装；`None` 或 `tcpmasks` 为空 → 跳过。
    tcpmask_manager: Option<crate::finalmask::TcpmaskManager>,
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
    pub async fn listen(
        addr: SocketAddr,
        sockopt: &SocketOptions,
        add_conn: ConnHandler,
        auth: Option<Arc<crate::headers::http::HttpAuthenticator>>,
        tcpmask_manager: Option<crate::finalmask::TcpmaskManager>,
    ) -> io::Result<Self> {
        let inner = DefaultListener::bind(addr, sockopt.clone()).await?;
        let close_notify = Arc::new(Notify::new());

        let listener = Self {
            inner,
            add_conn,
            close_notify,
            auth,
            tcpmask_manager,
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
                            // ponytail: TLS/REALITY wrapping 留待对应 crate 集成
                            //（生产 TLS 在 xray-core inbound 各协议层包装）。
                            // header 伪装包装（Go hub.go:125-127 authConfig.Server）：
                            let conn = match &self.auth {
                                Some(a) => crate::headers::conn::wrap_server(conn, a),
                                None => conn,
                            };
                            // Tcpmask 包装（Go hub.go:67-69 WrapListener → WrapConnServer）：
                            // 优先于 add_conn；manager 为空 → 跳过。
                            let conn = match self.tcpmask_manager.as_ref() {
                                Some(mgr) => match crate::finalmask::wrap_conn_server_into_connection(
                                    mgr, conn,
                                ) {
                                    Ok(c) => c,
                                    Err(e) => {
                                        tracing::warn!(error = %e, "tcpmask wrap failed");
                                        // auth-wrapped conn 已丢失原始 conn——此处吞错
                                        unreachable!("tcpmask wrap failed but conn was moved by auth wrap")
                                    }
                                },
                                None => conn,
                            };
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
        // notify_one 存一个 permit：close 与 accept 循环重新注册 notified() 之间的
        // 窗口内到达的 close 不会丢失（notify_waiters 只唤醒已注册 waiter）。
        self.close_notify.notify_one();
        // ponytail: 底层 TcpListener 在 Arc drop 时关闭。
        // 如果需要立即释放端口，需在 DefaultListener 上加 close() 方法。
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

impl TransportListener for Arc<TcpHubListener> {
    fn close(&self) -> io::Result<()> {
        (**self).close()
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        (**self).local_addr()
    }
}

// ===== TransportListenFn 实现 =====

/// 提取 `tcpSettings.acceptProxyProtocol`（Go transport_method.go:234 TCPConfig JSON
/// 键；Go tcp/hub.go:37-40 监听时把 `l.config.AcceptProxyProtocol` OR 进
/// `SocketSettings.AcceptProxyProtocol`）。缺省/非 bool → false。
fn accept_proxy_protocol_from_tcp_settings(settings: &crate::dialer::StreamSettings) -> bool {
    settings
        .transport_json
        .as_ref()
        .and_then(|v| v.get("acceptProxyProtocol"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// TCP 协议的 `TransportListenFn` 实现。
///
/// 注册到全局 listener 注册表，让 `listen_tcp("tcp", ...)` 可找到。
pub async fn listen_tcp_impl(
    addr: SocketAddr,
    settings: crate::dialer::StreamSettings,
    mut sockopt: SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    // tcpSettings.acceptProxyProtocol OR 进 sockopt（Go hub.go:40：
    // `streamSettings.SocketSettings.AcceptProxyProtocol = l.config.AcceptProxyProtocol
    //  || streamSettings.SocketSettings.AcceptProxyProtocol`——后者已由
    //  StreamSettings::socket_options 从 sockopt JSON 解析）。
    sockopt.accept_proxy_protocol |= accept_proxy_protocol_from_tcp_settings(&settings);
    // header 伪装构建（Go hub.go:85-95：HeaderSettings → ConnectionAuthenticator，
    // 失败报错；none/缺失 → None 不包装）。
    let auth = crate::headers::conn::auth_from_json(settings.transport_json.as_ref())?;
    // Tcpmask 解析（Go hub.go:67-68 WrapListener）：finalmask_json.tcp[] 链
    let mgr = crate::finalmask::build_tcpmask_manager_from_json(settings.finalmask_json.as_ref())?;
    let mgr = if mgr.tcpmasks.is_empty() { None } else { Some(mgr) };
    let listener = TcpHubListener::listen(addr, &sockopt, handler, auth, mgr).await?;
    // Go hub.go ListenTCP：bind 后 `go l.keepAccepting()`——registry 契约要求
    // TransportListenFn 内部 spawn accept 循环（listener_registry.rs:34；对齐
    // ws/httpupgrade/kcp 同层实现）。listener 升 Arc 与循环共享；返回的 Box
    // 经上方 Arc 转发 impl 仍可 close/local_addr（close → notify → 循环退出）。
    let listener = Arc::new(listener);
    let _accept_loop = listener.spawn_accept_loop();
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

/// TCP hub 注册表最大条目数。
const MAX_TCP_HUB_ENTRIES: usize = 4096;

/// 注册 TCP listener。锁中毒时静默忽略。
#[deprecated(note = "use listener_registry::register_transport_listener instead")]
pub fn register_tcp_listener(addr: SocketAddr, listener: TokioTcpListener) -> io::Result<()> {
    if let Ok(mut hub) = tcp_hub().lock() {
        if hub.len() >= MAX_TCP_HUB_ENTRIES {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                format!("TCP hub registry full ({MAX_TCP_HUB_ENTRIES})")));
        }
        hub.insert(addr, listener);
    }
    Ok(())
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
            TcpHubListener::listen("127.0.0.1:0".parse().unwrap(), &SocketOptions::default(), handler, None, None)
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
            TcpHubListener::listen("127.0.0.1:0".parse().unwrap(), &SocketOptions::default(), handler, None, None)
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
            TcpHubListener::listen("127.0.0.1:0".parse().unwrap(), &SocketOptions::default(), handler, None, None)
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
            TcpHubListener::listen("127.0.0.1:0".parse().unwrap(), &SocketOptions::default(), handler, None, None)
                .await
                .expect("listen 失败"),
        );
        let addr = listener.local_addr().expect("local_addr 失败");
        assert_ne!(addr.port(), 0);
        listener.close().expect("close 失败");
    }

    /// tcpSettings.acceptProxyProtocol → sockopt 装配（Go tcp/hub.go:37-40）：
    /// tcpSettings 携带该键时经 listen_tcp_impl OR 进 sockopt，listener 开关打开。
    #[tokio::test]
    async fn tcp_settings_accept_proxy_protocol_reaches_listener_switch() {
        let mut settings = crate::dialer::StreamSettings::tcp();
        settings.transport_json = Some(serde_json::json!({ "acceptProxyProtocol": true }));
        // 解析半边：transport JSON → bool。
        assert!(accept_proxy_protocol_from_tcp_settings(&settings));
        // 装配半边：listen_tcp_impl 用该 settings 绑定成功（开关在内部生效）。
        let handler: ConnHandler = Arc::new(|_| {});
        let listener = listen_tcp_impl(
            "127.0.0.1:0".parse().unwrap(),
            settings,
            SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen_tcp_impl 失败");
        assert_ne!(listener.local_addr().expect("local_addr 失败").port(), 0);

        // 缺省/非 bool → false（Go TCPConfig 缺省 false）。
        assert!(!accept_proxy_protocol_from_tcp_settings(
            &crate::dialer::StreamSettings::tcp()
        ));
        let mut settings = crate::dialer::StreamSettings::tcp();
        settings.transport_json = Some(serde_json::json!({ "acceptProxyProtocol": "yes" }));
        assert!(!accept_proxy_protocol_from_tcp_settings(&settings));

    }
    /// 竞态窗回归锚（票 n8k8）：close 发生在 accept 循环注册 notified() 之前。
    /// notify_one 存 permit，循环首次注册即被唤醒退出；旧 notify_waiters 语义下
    /// 通知蒸发，循环 parked 在 accept() 永不退出——本测试必挂。
    #[tokio::test]
    async fn close_before_spawn_loop_exits_immediately() {
        let handler: ConnHandler = Arc::new(|_| {});
        let listener = Arc::new(
            TcpHubListener::listen(
                "127.0.0.1:0".parse().unwrap(),
                &SocketOptions::default(),
                handler,
                None,
                None,
            )
            .await
            .expect("listen 失败"),
        );
        // 先 close 再 spawn：循环首次注册 notified() 时 close 已发生。
        listener.close().expect("close 失败");
        let handle = listener.spawn_accept_loop();
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("accept 循环必须在 pre-spawn close 后退出（permit 语义）")
            .expect("循环 task panic");
    }

    /// close + drop 后端口释放，新连接被拒（票 n8k8 端口滞留修复的行为面）。
    #[tokio::test]
    async fn close_then_drop_rejects_new_connections() {
        let handler: ConnHandler = Arc::new(|_| {});
        let listener: Box<dyn TransportListener> = Box::new(
            TcpHubListener::listen(
                "127.0.0.1:0".parse().unwrap(),
                &SocketOptions::default(),
                handler,
                None,
                None,
            )
            .await
            .expect("listen 失败"),
        );
        let addr = listener.local_addr().expect("local_addr 失败");
        listener.close().expect("close 失败");
        drop(listener); // socket 随最后一个 Arc 释放

        // 循环 task 退出是异步的：轮询直至 connect 被拒。
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match tokio::net::TcpStream::connect(addr).await {
                Err(_) => break,
                Ok(_) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "close+drop 后端口仍接受连接"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod header_wrap_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// inbound header 装配（Go tcp/hub.go:85-95 构建 + 125-127 accept 后包装）：
    /// `header.type=http` → add_conn 收到的连接已被 server 包装——
    /// 原始 client 手发 request header + payload，包装连接直接读出 payload；
    /// 包装连接写回应时自动注入 response header。
    #[tokio::test]
    async fn tcp_hub_wraps_inbound_with_header_authenticator() {
        use tokio::sync::mpsc;

        let (tx, mut rx) = mpsc::channel::<Box<dyn Connection>>(1);
        let handler: ConnHandler = Arc::new(move |conn| {
            tx.try_send(conn).ok();
        });

        // settings JSON → auth（Go hub.go:85-95 装配路径）。
        let auth = crate::headers::conn::auth_from_json(Some(&serde_json::json!({
            "header": {"type": "http"}
        })))
        .expect("json 构建")
        .expect("type http → Some");

        let listener = Arc::new(
            TcpHubListener::listen(
                "127.0.0.1:0".parse().unwrap(),
                &SocketOptions::default(),
                handler,
                Some(auth),
                None,
            )
            .await
            .expect("listen 失败"),
        );
        let addr = listener.local_addr().expect("local_addr 失败");
        let _loop = listener.spawn_accept_loop();

        // 原始 client：手发 request header + payload。
        let mut client = TcpStream::connect(addr).await.expect("connect 失败");
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\ninbound-payload")
            .await
            .expect("raw write");

        // handler 收到的 conn 已被 server 包装（header 被吞，payload 透传）。
        let mut wrapped = rx.recv().await.expect("应收到包装连接");
        let mut buf = [0u8; 15];
        wrapped
            .read_exact(&mut buf)
            .await
            .expect("wrapped read");
        assert_eq!(&buf, b"inbound-payload", "header 应被吞，payload 透传");

        wrapped.write_all(b"resp").await.expect("wrapped write");
        let mut got = [0u8; 512];
        let n = client.read(&mut got).await.expect("client read");
        let text = String::from_utf8_lossy(&got[..n]).to_string();
        assert!(
            text.starts_with("HTTP/1.1 200"),
            "应注入 response header，实际 {text:?}"
        );
        assert!(text.ends_with("resp"), "payload 应跟随 header，实际 {text:?}");
    }
}
