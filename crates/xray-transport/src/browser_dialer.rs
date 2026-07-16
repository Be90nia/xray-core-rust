//! # Browser dialer
//!
//! 对应 Go `transport/internet/browser_dialer.go`。
//!
//! TODO tgg-future: 内嵌 HTML/JS 资源 + HTTP task 派发 + WebSocket 回传。

use std::net::SocketAddr;

#[derive(Debug, Clone, Default)]
pub struct BrowserDialerConfig {
    pub listen: Option<SocketAddr>,
}

pub struct BrowserDialer {
    config: BrowserDialerConfig,
}

impl BrowserDialer {
    #[must_use]
    pub fn new(config: BrowserDialerConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.config.listen
    }
}
