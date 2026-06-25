//! 本地系统 DNS nameserver。对应 Go `app/dns/nameserver_local.go`。
//!
//! **状态**：占位。依赖系统 DNS resolver（`trust-dns-resolver` 或 `tokio::net::lookup_host`）。

use crate::error::DnsError;
use crate::nameserver::Server;

/// 构造本地 nameserver。对应 Go `NewLocalNameServer`。
///
/// TODO: 实现 LocalNameServer + 系统 resolver 调用。
pub fn new_local_name_server() -> Result<Box<dyn Server>, DnsError> {
    Err(DnsError::NotImplemented("local::new_local_name_server"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_returns_not_implemented() {
        match new_local_name_server() {
            Err(DnsError::NotImplemented(_)) => {}
            Err(e) => panic!("expected NotImplemented, got error: {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }
}
