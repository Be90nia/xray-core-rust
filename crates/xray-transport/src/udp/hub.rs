//! # UDP hub
//!
//! 对应 Go `transport/internet/udp/hub.go`。UDP listener 注册表。
//!
//! TODO tgg-future: 实现 UDP listener 生命周期 + NAT 保持。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

static UDP_HUB: std::sync::OnceLock<Mutex<HashMap<SocketAddr, ()>>> = std::sync::OnceLock::new();
fn udp_hub() -> &'static Mutex<HashMap<SocketAddr, ()>> {
    UDP_HUB.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn register_udp_listener(addr: SocketAddr) {
    udp_hub().lock().unwrap().insert(addr, ());
}

pub fn unregister_udp_listener(addr: SocketAddr) {
    udp_hub().lock().unwrap().remove(&addr);
}
