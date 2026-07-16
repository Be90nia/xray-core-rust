//! # Linux socket options
//!
//! 对应 Go `transport/internet/sockopt_linux.go`。
//!
//! TODO tgg-future: TCP_FASTOPEN/SO_REUSEPORT/IP_TRANSPARENT/TCP_CONGESTION。

#[derive(Debug, Clone, Default)]
pub struct LinuxSockOpt {
    pub tcp_fast_open: u32,
    pub reuse_port: bool,
    pub tproxy: bool,
    pub tcp_congestion: Option<String>,
}

impl LinuxSockOpt {
    pub fn apply(&self, _fd: i32) -> std::io::Result<()> {
        Ok(())
    }
}
