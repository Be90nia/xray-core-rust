//! # FreeBSD socket options
//!
//! 对应 Go `transport/internet/sockopt_freebsd.go`。

#[derive(Debug, Clone, Default)]
pub struct FreebsdSockOpt {
    pub tcp_fast_open: u32,
    pub reuse_port: bool,
}

impl FreebsdSockOpt {
    pub fn apply(&self, _fd: i32) -> std::io::Result<()> {
        Ok(())
    }
}
