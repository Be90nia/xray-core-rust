//! # TCP hub
//!
//! 对应 Go `transport/internet/tcp/hub.go`。TCP listener 注册表。
//!
//! TODO tgg-future: 实现 ListenAndServe + port 复用。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use tokio::net::TcpListener;

static TCP_HUB: std::sync::OnceLock<Mutex<HashMap<SocketAddr, TcpListener>>> = std::sync::OnceLock::new();
fn tcp_hub() -> &'static Mutex<HashMap<SocketAddr, TcpListener>> {
    TCP_HUB.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 注册 TCP listener。锁中毒时静默忽略。
pub fn register_tcp_listener(addr: SocketAddr, listener: TcpListener) {
    if let Ok(mut hub) = tcp_hub().lock() {
        hub.insert(addr, listener);
    }
}

/// 取出已注册的 TCP listener（从注册表中移除）。
///
/// `TcpListener` 不可 `Clone`，因此取出操作会从 hub 中移除。
pub fn take_tcp_listener(addr: SocketAddr) -> Option<TcpListener> {
    tcp_hub().lock().ok().and_then(|mut hub| hub.remove(&addr))
}
