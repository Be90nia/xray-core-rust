//! UDP (Classic) DNS nameserver。对应 Go `app/dns/nameserver_udp.go`。
//!
//! **状态**：占位。等 `tokio::net::UdpSocket` + DNS wire format（hickory-proto 或自研）
//! 就位后实现 `ClassicNameServer` 与工厂函数。

use crate::error::DnsError;
use crate::nameserver::Server;

/// 构造 UDP nameserver。对应 Go `NewClassicNameServer`。
///
/// 入参：服务端地址、缓存控制策略、客户端 IP（EDNS0 subnet）。
///
/// TODO: 实现 `ClassicNameServer` struct + `Server` impl + UDP socket dial。
pub fn new_classic_name_server() -> Result<Box<dyn Server>, DnsError> {
    Err(DnsError::NotImplemented("udp::new_classic_name_server"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_returns_not_implemented() {
        match new_classic_name_server() {
            Err(DnsError::NotImplemented(_)) => {}
            Err(e) => panic!("expected NotImplemented, got error: {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }
}
