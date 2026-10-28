//! # TCP hub
//!
//! 对应 Go `transport/internet/tcp/hub.go`。TCP listener 实现 + accept 循环。
//!
//! ## 架构
//!
//! - `TcpHubListener` — bind 后 spawn accept 循环（socket 归循环所有，Go `go
//!   l.keepAccepting()`）；close/Drop → 循环 break → 端口释放
//! - `listen_tcp_impl` — `TransportListenFn` 实现，注册到全局 listener 注册表
//! - `keep_accepting` — accept 循环：accept → header auth wrap → `add_conn` （Go hub.go:125-127）
//!
//! TLS/REALITY wrapping 不在 hub（生产 TLS 由 xray-core inbound 各协议层包装）。

use std::{io, net::SocketAddr, sync::Arc};

use skeleton_infra::fx::FxScope;
use tokio::sync::Notify;

use crate::{
    accept_policy::{AcceptErrorKind, backoff_if_resource, classify, supervise_accept_loop},
    listener_registry::{ConnHandler, TransportListener},
    sockopt::SocketOptions,
    system_listener::{DefaultListener, SystemListener},
};

/// TCP hub listener。对应 Go `tcp/hub.go::Listener` struct。
///
/// socket 所有权已在 [`TcpHubListener::listen`] 内移入 accept 循环（Go
/// `go l.keepAccepting()` 同形，hub.go:86）：本结构只持 `local` + close 通知。
/// `close()`/`Drop` → 循环 break → socket drop → 端口即时释放（Go `Close()` =
/// `listener.Close()`，hub.go:128-130；`Accept` 返回错误退出，hub.go:90-97）。
pub struct TcpHubListener {
    /// bind 结果（Go `Listener.Addr()`——socket 已归循环，无法再向内核查询）。
    local: SocketAddr,
    close_notify: Arc<Notify>,
    /// B6（bd 39hko 切片1）：accept 循环 + 退出监控任务唯一托管口（坑约束 5）。
    /// 协作停机仍走 close_notify（close/Drop 触发）；scope 随句柄 drop 兜底 abort
    /// ——socket 归循环所有，任一路径端口都即时释放（Go `Close()` 同形）。
    /// 只持不读：存活锚（drop=abort 兜底），读回面待需（salamander_gecko 同形）。
    #[allow(dead_code)]
    fx: Arc<FxScope>,
}

impl TcpHubListener {
    /// 绑定 `addr` 并 spawn accept 循环（对应 Go `ListenTCP()`：bind →
    /// `go l.keepAccepting()` → return）。
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
        auth: Option<Arc<crate::headers::http::HttpAuthenticator>>,
        tcpmask_manager: Option<crate::finalmask::TcpmaskManager>,
    ) -> io::Result<Self> {
        let inner = DefaultListener::bind(addr, sockopt.clone()).await?;
        let local = inner.local_addr()?;
        let close_notify = Arc::new(Notify::new());
        // B6（bd 39hko 切片1）：任务托管收口（坑约束 5）；闸关不可达，expect 只防
        // 编程错误（realm/conn.rs 同形）。
        let fx = Arc::new(FxScope::new());
        let loop_task = fx
            .spawn_tracked(keep_accepting(
                inner,
                local,
                add_conn,
                auth,
                tcpmask_manager,
                Arc::clone(&close_notify),
            ))
            .expect("internal FxScope is never closed");
        // 意外退出监控：循环只应经 close_notify 分支退出；panic 会静默杀掉
        // 监听（端口不再 listen 而进程存活），error! 兜底发声。
        fx.spawn_tracked(supervise_accept_loop("tcp", local.to_string(), loop_task.join()))
            .expect("internal FxScope is never closed");
        Ok(Self { local, close_notify, fx })
    }
}

/// Accept 循环。对应 Go `keepAccepting()`（hub.go:90-121）。
///
/// `inner` 按值传入 = socket 归循环所有（v7nqa）：close/drop 触发 break →
/// `inner` drop → 端口释放。
///
/// 对每个新连接：header 伪装包装（Go hub.go:125-127）→ tcpmask 包装（Go
/// hub.go:67-69）→ `add_conn`。TLS/REALITY wrapping 不在 hub（生产 TLS 由
/// xray-core inbound 各协议层包装）。
///
/// accept 错误处置走 [`crate::accept_policy`]：资源类 warn + 退避 500ms + 继续；
/// 单连接级 debug + 继续；未知 warn + 继续。错误永不退出——循环唯一出口是
/// close_notify 分支（单连接级错误文本常含 "closed"，旧 `contains("closed") =>
/// break` 曾静默杀死监听）。
async fn keep_accepting(
    inner: DefaultListener,
    local: SocketAddr,
    add_conn: ConnHandler,
    auth: Option<Arc<crate::headers::http::HttpAuthenticator>>,
    tcpmask_manager: Option<crate::finalmask::TcpmaskManager>,
    close_notify: Arc<Notify>,
) {
    loop {
        let accept_fut = inner.accept();
        tokio::pin!(accept_fut);

        tokio::select! {
            result = &mut accept_fut => {
                match result {
                    Ok(conn) => {
                        let conn = match auth.as_ref() {
                            Some(a) => crate::headers::conn::wrap_server(conn, a),
                            None => conn,
                        };
                        let conn = match tcpmask_manager.as_ref() {
                            Some(mgr) => match crate::finalmask::wrap_conn_server_into_connection(
                                mgr, conn,
                            ) {
                                Ok(c) => c,
                                Err(e) => {
                                    crate::LOG.warn(format!("error={e} tcpmask wrap failed"));
                                    // auth-wrapped conn 已丢弃原始 conn，无法重试。
                                    continue;
                                }
                            },
                            None => conn,
                        };
                        (add_conn)(conn);
                    }
                    Err(e) => {
                        match classify(&e) {
                            AcceptErrorKind::Resource => {
                                crate::LOG.warn(format!("tag=tcp local={local} error={e} tcp inbound: 资源/瞬时类 accept 错误，退避 500ms 后继续"));
                                backoff_if_resource(&e).await;
                            }
                            AcceptErrorKind::Connection => {
                                crate::LOG.debug(format!("tag=tcp error={e} tcp inbound: 单连接级 accept 错误，继续监听"));
                            }
                            AcceptErrorKind::Unknown => {
                                crate::LOG.warn(format!("tag=tcp error={e} tcp inbound: accept 错误（未知类别），继续监听"));
                            }
                        }
                    }
                }
            }
            _ = close_notify.notified() => {
                // 收到关闭信号，退出循环（唯一出口）→ inner（socket）随 drop 释放。
                break;
            }
        }
    }
}

impl TransportListener for TcpHubListener {
    fn close(&self) -> io::Result<()> {
        // notify_one 存一个 permit：close 与 accept 循环重新注册 notified() 之间的
        // 窗口内到达的 close 不会丢失（notify_waiters 只唤醒已注册 waiter）。
        self.close_notify.notify_one();
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

impl Drop for TcpHubListener {
    fn drop(&mut self) {
        // v7nqa：inbound 停机只 drop 监听句柄、不显式调 close——不通知则循环
        // 继续持有 socket，端口在进程内继续 accept（Go worker.close 显式
        // hub.Close()，proxyman/inbound/worker.go:151-158）。
        let _ = TransportListener::close(self);
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
    // Go hub.go:86：bind 后 `go l.keepAccepting()`——循环已在 listen 内 spawn，
    // socket 归循环所有（close/drop → 循环 break → 端口释放）。
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

// ===== Unix 监听（Go tcp/hub.go:44 `port == net.Port(0)` 分支）=====

/// TCP hub unix listener。socket 与 accept 循环同 [`TcpHubListener`]：bind 在
/// [`TcpUnixHubListener::listen`] 内完成并随循环所有权移动，本结构只持 close
/// 通知。对应 Go tcp Listener 在 `port==0` 时 `net.UnixAddr` +
/// `internet.ListenSystem` 路径。
#[cfg(unix)]
pub struct TcpUnixHubListener {
    close_notify: Arc<Notify>,
    /// B6（bd 39hko 切片1）：accept 循环 + 退出监控唯一托管口（坑约束 5），
    /// 同 `TcpHubListener` 的 `fx` 字段口径（只持不读存活锚，drop=abort 兜底）。
    #[allow(dead_code)]
    fx: Arc<FxScope>,
}

#[cfg(unix)]
impl TcpUnixHubListener {
    /// 绑定 unix domain socket 并 spawn accept 循环（socket 所有权随循环移动，
    /// 同 [`TcpHubListener::listen`]）。
    pub async fn listen(
        path: &str,
        sockopt: &SocketOptions,
        add_conn: ConnHandler,
    ) -> io::Result<Self> {
        let inner = crate::system_listener::UnixListener::bind(path, sockopt.clone()).await?;
        let close_notify = Arc::new(Notify::new());
        let fx = Arc::new(FxScope::new());
        let loop_task = fx
            .spawn(keep_accepting_unix(
                inner,
                path.to_string(),
                add_conn,
                Arc::clone(&close_notify),
            ))
            .expect("internal FxScope is never closed");
        // 意外退出监控（同 tcp 循环）：panic 静默杀监听——error! 兜底发声。
        fx.spawn(supervise_accept_loop("tcp-unix", path.to_string(), loop_task.join()))
            .expect("internal FxScope is never closed");
        Ok(Self { close_notify, fx })
    }
}

/// Accept 循环：accept → `add_conn`（Go keepAccepting 的 unix 载体，无
/// header/finalmask 包装——Go unix 分支同样不走 WrapListener 的 tcp 语义）。
/// 错误处置与 [`keep_accepting`] 一致（accept_policy：错误永不退出，唯一出口是
/// close 分支）。`inner` 归循环所有 → 退出即释放 socket。
#[cfg(unix)]
async fn keep_accepting_unix(
    inner: crate::system_listener::UnixListener,
    path: String,
    add_conn: ConnHandler,
    close_notify: Arc<Notify>,
) {
    loop {
        let accept_fut = inner.accept();
        tokio::pin!(accept_fut);
        tokio::select! {
            result = &mut accept_fut => {
                match result {
                    Ok(conn) => (add_conn)(conn),
                    Err(e) => {
                        match classify(&e) {
                            AcceptErrorKind::Resource => {
                                crate::LOG.warn(format!("tag=tcp-unix path={path} error={e} unix inbound: 资源/瞬时类 accept 错误，退避 500ms 后继续"));
                                backoff_if_resource(&e).await;
                            }
                            AcceptErrorKind::Connection => {
                                crate::LOG.debug(format!("tag=tcp-unix path={path} error={e} unix inbound: 单连接级 accept 错误，继续监听"));
                            }
                            AcceptErrorKind::Unknown => {
                                crate::LOG.warn(format!("tag=tcp-unix path={path} error={e} unix inbound: accept 错误（未知类别），继续监听"));
                            }
                        }
                    }
                }
            }
            _ = close_notify.notified() => break,
        }
    }
}

#[cfg(unix)]
impl TransportListener for TcpUnixHubListener {
    fn close(&self) -> io::Result<()> {
        self.close_notify.notify_one();
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // unix socket 无 SocketAddr，返回 unspecified（对齐 UnixConnection / Go UnixConnWrapper）
        Ok(SocketAddr::from(([0, 0, 0, 0], 0)))
    }
}

#[cfg(unix)]
impl Drop for TcpUnixHubListener {
    fn drop(&mut self) {
        // v7nqa：停机只 drop 监听句柄 → 不通知则 UDS 继续 accept。
        let _ = TransportListener::close(self);
    }
}

/// TCP 协议的 unix 监听实现（对应 Go `ListenTCP` 的 `port==0` unix 分支）。
///
/// Go 该分支支持 `FinalMask.Listen(ctx, unixAddr)`；Rust tcpmask 为 TCP 语义
/// 载体，unix 上无对应能力——非空显式拒绝而非静默忽略（对齐本模块 finalmask
/// 拒绝惯例）。
#[cfg(unix)]
pub async fn listen_unix_impl(
    path: String,
    settings: crate::dialer::StreamSettings,
    sockopt: SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    if settings.finalmask_json.as_ref().is_some_and(|v| !v.is_null()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "finalmask is not supported on unix listeners; remove the finalmask key",
        ));
    }
    let listener = TcpUnixHubListener::listen(&path, &sockopt, handler).await?;
    // 同 tcp：accept 循环已在 listen 内 spawn，socket 归循环所有。
    Ok(Box::new(listener) as Box<dyn TransportListener>)
}

/// 创建 TCP 协议的 unix `UnixTransportListenFn`（注册到 unix 注册表）。
#[cfg(unix)]
#[must_use]
pub fn tcp_unix_listen_fn() -> crate::listener_registry::UnixTransportListenFn {
    Arc::new(
        |path: String,
         settings: crate::dialer::StreamSettings,
         sockopt: SocketOptions,
         handler: ConnHandler| {
            Box::pin(async move { listen_unix_impl(path, settings, sockopt, handler).await })
        },
    )
}

// ===== 旧 API 兼容 =====
//
// 保留 `register_tcp_listener` / `take_tcp_listener` 向后兼容，
// 但标记为 deprecated——新代码应使用 `listener_registry::register_transport_listener`。

use std::{collections::HashMap, sync::Mutex};

use tokio::net::TcpListener as TokioTcpListener;

static TCP_HUB: std::sync::OnceLock<Mutex<HashMap<SocketAddr, TokioTcpListener>>> =
    std::sync::OnceLock::new();
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
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("TCP hub registry full ({MAX_TCP_HUB_ENTRIES})"),
            ));
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
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    use super::*;

    #[tokio::test]
    async fn tcp_hub_listener_bind_and_accept() {
        let handler: ConnHandler = Arc::new(|mut conn| {
            #[allow(clippy::disallowed_methods, reason = "测试：pong handler 任务")]
            tokio::spawn(async move {
                conn.write_all(b"pong").await.expect("write 失败");
            });
        });
        let listener = TcpHubListener::listen(
            "127.0.0.1:0".parse().unwrap(),
            &SocketOptions::default(),
            handler,
            None,
            None,
        )
        .await
        .expect("listen 失败");
        let addr = listener.local_addr().expect("local_addr 失败");

        let mut client = TcpStream::connect(addr).await.expect("connect 失败");
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.expect("read 失败");
        assert_eq!(&buf, b"pong");
    }

    #[tokio::test]
    async fn tcp_hub_listener_local_addr() {
        let handler: ConnHandler = Arc::new(|_| {});
        let listener = TcpHubListener::listen(
            "127.0.0.1:0".parse().unwrap(),
            &SocketOptions::default(),
            handler,
            None,
            None,
        )
        .await
        .expect("listen 失败");
        let addr = listener.local_addr().expect("local_addr 失败");
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_ne!(addr.port(), 0);
    }

    /// 停机 → 端口释放（bd 39hko 切片1 验收④）：listen → 建连 → drop listener
    /// （Drop → close_notify → 循环 break；托管 scope 随句柄 drop abort 兜底）→
    /// 端口不再接受连接。socket 归循环任务所有，任一收口路径都释放。
    #[tokio::test]
    async fn tcp_hub_listener_stop_releases_port() {
        let handler: ConnHandler = Arc::new(|_| {});
        let listener = TcpHubListener::listen(
            "127.0.0.1:0".parse().unwrap(),
            &SocketOptions::default(),
            handler,
            None,
            None,
        )
        .await
        .expect("listen 失败");
        let addr = listener.local_addr().expect("local_addr 失败");

        // 建连：监听活跃态（连接由 handler 立即 drop，客户端读到 EOF）。
        let client = TcpStream::connect(addr).await.expect("connect 失败");
        drop(client);

        // 停机：drop listener。
        drop(listener);

        // 端口释放证据：connect 由「成功」翻转为「拒绝」。关闭经 runtime 异步
        // 生效（close_notify 唤醒 / abort 处理），5s 墙钟上限轮询。
        let wait_release = async {
            loop {
                if TcpStream::connect(addr).await.is_err() {
                    return; // 连接被拒 = 端口已释放
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), wait_release)
            .await
            .expect("port still accepting after listener stop");
    }

    #[tokio::test]
    async fn keep_accepting_calls_handler() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&count);
        let handler: ConnHandler = Arc::new(move |_conn| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        });

        let listener = TcpHubListener::listen(
            "127.0.0.1:0".parse().unwrap(),
            &SocketOptions::default(),
            handler,
            None,
            None,
        )
        .await
        .expect("listen 失败");
        let addr = listener.local_addr().expect("local_addr 失败");

        // 连接 3 个客户端。
        for _ in 0..3 {
            let _ = TcpStream::connect(addr).await.expect("connect 失败");
        }

        // 等待 accept 循环处理。
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert_eq!(count.load(Ordering::SeqCst), 3);

        // close → accept 循环退出（tcp_hub_listener_bind_and_accept 反向锚：
        // 停机后不再接新连）。
        listener.close().ok();
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

    /// ③ transport 级 ListenUnix：注册 → listen_unix 真监听 → UnixStream 连入
    /// 回环（Go tcp_hub.go ListenUnix + tcp/hub.go port==0 分支）。unix-only。
    #[cfg(unix)]
    #[tokio::test]
    async fn listen_unix_tcp_hub_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        use crate::connection::Connection;

        // 注册（同进程其他测试可能已注册，容忍 AlreadyExists）。
        let _ = crate::tcp::register_tcp_unix_transport();

        let path = std::env::temp_dir().join(format!(
            "xray-transport-unix-hub-{}-{}",
            std::process::id(),
            xray_frame::compat::clock()
                .now_system()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path_str = path.to_str().expect("temp path utf8");

        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel::<Box<dyn Connection>>(4);
        let handler: ConnHandler = Arc::new(move |mut conn| {
            let conn_tx = conn_tx.clone();
            #[allow(clippy::disallowed_methods, reason = "测试：echo handler 任务")]
            tokio::spawn(async move {
                let mut buf = [0u8; 4];
                if conn.read_exact(&mut buf).await.is_ok() {
                    let _ = conn.write_all(&buf).await;
                    let _ = conn_tx.send(conn).await;
                }
            });
        });

        let listener = crate::listener_registry::listen_unix(
            path_str,
            crate::dialer::StreamSettings::tcp(),
            SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen_unix 失败");
        // unix listener 无 SocketAddr（Go UnixConnWrapper 同理）：local_addr 按契约返回
        // unspecified，不能像 TCP 那样断言 port != 0。
        assert_eq!(
            listener.local_addr().expect("local_addr 失败"),
            std::net::SocketAddr::from(([0, 0, 0, 0], 0))
        );

        let mut client = tokio::net::UnixStream::connect(&path).await.expect("connect 失败");
        client.write_all(b"ping").await.expect("write 失败");
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.expect("read 失败");
        assert_eq!(&buf, b"ping");
        assert!(conn_rx.recv().await.is_some(), "handler must receive the connection");

        listener.close().expect("close 失败");
        // UDS 同 TCP：close → 循环 break → UnixListener drop → 新连接被拒
        // （v7nqa：循环持有 socket 时 .sock 持续 accept）。
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if tokio::net::UnixStream::connect(&path).await.is_err() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "close 后 unix socket 仍接受连接（循环未退出/socket 未释放）"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path_str}.lock"));
    }

    #[tokio::test]
    async fn transport_listener_trait_close_and_local_addr() {
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
        assert!(!accept_proxy_protocol_from_tcp_settings(&crate::dialer::StreamSettings::tcp()));
        let mut settings = crate::dialer::StreamSettings::tcp();
        settings.transport_json = Some(serde_json::json!({ "acceptProxyProtocol": "yes" }));
        assert!(!accept_proxy_protocol_from_tcp_settings(&settings));
    }
    /// 轮询直至 `addr` 不再接受新连接（close/drop → 循环 break → socket drop
    /// 是异步的，Go 侧 `Accept` 返回错误也非瞬时）。
    async fn assert_tcp_port_closed(addr: SocketAddr) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if tokio::net::TcpStream::connect(addr).await.is_err() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "listener 关闭后端口仍接受连接（close 通知丢失/循环未退出）"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// close() 即释放端口（Go hub.go:128-130 `Close()` = `listener.Close()`，
    /// hub.go:90-97 `Accept` 报错退出），不需要等 drop。
    #[tokio::test]
    async fn close_rejects_new_connections() {
        let handler: ConnHandler = Arc::new(|_| {});
        let listener = TcpHubListener::listen(
            "127.0.0.1:0".parse().unwrap(),
            &SocketOptions::default(),
            handler,
            None,
            None,
        )
        .await
        .expect("listen 失败");
        let addr = listener.local_addr().expect("local_addr 失败");
        // 前置：关闭前端口在听（否则下面断言恒真）。
        TcpStream::connect(addr).await.expect("close 前应可连接");

        listener.close().expect("close 失败");
        assert_tcp_port_closed(addr).await;
    }

    /// v7nqa 回归锚：inbound 停机只 drop 监听句柄、不显式 close()。
    /// 无 `Drop → close` 兜底时 accept 循环继续持有 socket，端口在进程内继续
    /// accept（改前本测试必挂）。
    #[tokio::test]
    async fn drop_without_close_rejects_new_connections() {
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
        TcpStream::connect(addr).await.expect("drop 前应可连接");

        drop(listener); // 只 drop，不调 close——走 Drop 兜底
        assert_tcp_port_closed(addr).await;
    }
}

#[cfg(test)]
mod header_wrap_tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    use super::*;
    use crate::connection::Connection;

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

        let listener = TcpHubListener::listen(
            "127.0.0.1:0".parse().unwrap(),
            &SocketOptions::default(),
            handler,
            Some(auth),
            None,
        )
        .await
        .expect("listen 失败");
        let addr = listener.local_addr().expect("local_addr 失败");

        // 原始 client：手发 request header + payload。
        let mut client = TcpStream::connect(addr).await.expect("connect 失败");
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\ninbound-payload")
            .await
            .expect("raw write");

        // handler 收到的 conn 已被 server 包装（header 被吞，payload 透传）。
        let mut wrapped = rx.recv().await.expect("应收到包装连接");
        let mut buf = [0u8; 15];
        wrapped.read_exact(&mut buf).await.expect("wrapped read");
        assert_eq!(&buf, b"inbound-payload", "header 应被吞，payload 透传");

        wrapped.write_all(b"resp").await.expect("wrapped write");
        let mut got = [0u8; 512];
        let n = client.read(&mut got).await.expect("client read");
        let text = String::from_utf8_lossy(&got[..n]).to_string();
        assert!(text.starts_with("HTTP/1.1 200"), "应注入 response header，实际 {text:?}");
        assert!(text.ends_with("resp"), "payload 应跟随 header，实际 {text:?}");
    }
}

#[cfg(test)]
mod accept_error_tests {
    use super::*;

    // tcp / unix 两个 accept 循环共用 `crate::accept_policy::classify`。这里锁定
    // accept 场景的关键分类决策（"退出"不在 AcceptErrorKind 表示域内——任何错误
    // 分类都不产生退出动作，循环唯一出口是 close_notify 分支）。

    #[test]
    fn accept_queue_abort_is_connection_class() {
        // Linux：连接在 accept 完成前被客户端中止（ECONNABORTED）——单连接级
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::ConnectionAborted)),
            AcceptErrorKind::Connection
        );
        // Windows：客户端握手前重置（WSAECONNRESET）
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::ConnectionReset)),
            AcceptErrorKind::Connection
        );
    }

    #[test]
    fn emfile_enfile_backs_off_regardless_of_text_case() {
        // glibc 文本 "Too many open files" 大写 T——旧 `contains("too many")` 大小写
        // 敏感永不命中的静默失效，由 kind 分级 + 大小写不敏感兜底消除
        assert_eq!(classify(&io::Error::other("Too many open files")), AcceptErrorKind::Resource);
        assert_eq!(classify(&io::Error::other("too many open files")), AcceptErrorKind::Resource);
    }

    #[test]
    fn closed_text_still_never_maps_to_exit() {
        // 回归锁：单连接级 "closed" 文本（生产杀手）不再触发退出——分类为
        // Connection / Unknown 都只是记录 + 继续
        assert_eq!(
            classify(&io::Error::other("Connection closed normally")),
            AcceptErrorKind::Unknown
        );
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::ConnectionAborted)),
            AcceptErrorKind::Connection
        );
    }
}
