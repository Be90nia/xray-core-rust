//! DNS-over-QUIC (DoQ) nameserver。对应 Go `app/dns/nameserver_quic.go`。
//!
//! **状态**：占位。依赖 `quinn` crate 与 QUIC-specific TLS 配置。

use crate::error::DnsError;
use crate::nameserver::Server;

/// 构造 QUIC nameserver。对应 Go `NewQUICNameServer`。
///
/// TODO: 实现 QUICNameServer + quinn endpoint。
pub fn new_quic_name_server() -> Result<Box<dyn Server>, DnsError> {
    Err(DnsError::NotImplemented("quic::new_quic_name_server"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_returns_not_implemented() {
        match new_quic_name_server() {
            Err(DnsError::NotImplemented(_)) => {}
            Err(e) => panic!("expected NotImplemented, got error: {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }
}
