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

pub fn register_tcp_listener(addr: SocketAddr, listener: TcpListener) {
    tcp_hub().lock().unwrap().insert(addr, listener);
}

pub fn get_tcp_listener(addr: SocketAddr) -> Option<TcpListener> {
    None
}
