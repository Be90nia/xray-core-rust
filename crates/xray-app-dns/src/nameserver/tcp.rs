//! TCP DNS nameserver。对应 Go `app/dns/nameserver_tcp.go`。
//!
//! **状态**：占位。

use crate::error::DnsError;
use crate::nameserver::Server;

/// 构造 TCP nameserver。对应 Go `NewTCPNameServer`。
///
/// TODO: 实现 TCPNameServer + TCPLocalNameServer。
pub fn new_tcp_name_server() -> Result<Box<dyn Server>, DnsError> {
    Err(DnsError::NotImplemented("tcp::new_tcp_name_server"))
}

/// 构造 TCP 本地 nameserver。对应 Go `NewTCPLocalNameServer`。
pub fn new_tcp_local_name_server() -> Result<Box<dyn Server>, DnsError> {
    Err(DnsError::NotImplemented("tcp::new_tcp_local_name_server"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factories_return_not_implemented() {
        for f in [new_tcp_name_server(), new_tcp_local_name_server()] {
            match f {
                Err(DnsError::NotImplemented(_)) => {}
                Err(e) => panic!("expected NotImplemented, got error: {e:?}"),
                Ok(_) => panic!("expected error, got Ok"),
            }
        }
    }
}
