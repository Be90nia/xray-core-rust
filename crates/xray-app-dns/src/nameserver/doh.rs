//! DNS-over-HTTPS (DoH) nameserver。对应 Go `app/dns/nameserver_doh.go`。
//!
//! **状态**：占位。
//!
//! 实现 DoH 需依赖：
//! - TLS 客户端（`xray-tls::ConnInterface`）
//! - HTTP/2 客户端（`hyper` 或 `wreq`）
//! - DNS wire format
//! 等这些就位后接入。

use crate::error::DnsError;
use crate::nameserver::Server;

/// 构造 DoH nameserver。对应 Go `NewDoHNameServer`。
///
/// TODO: 实现 DoHNameServer + HTTP/2 client + TLS handshake。
pub fn new_doh_name_server() -> Result<Box<dyn Server>, DnsError> {
    Err(DnsError::NotImplemented("doh::new_doh_name_server"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_returns_not_implemented() {
        match new_doh_name_server() {
            Err(DnsError::NotImplemented(_)) => {}
            Err(e) => panic!("expected NotImplemented, got error: {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }
}
