//! # Darwin socket options
//!
//! 对应 Go `transport/internet/sockopt_darwin.go`。
//!
//! TODO tgg-future: 实现 macOS 特定 sockopt。

#[derive(Debug, Clone, Default)]
pub struct DarwinSockOpt {
    pub tcp_fast_open: u32,
    pub reuse_port: bool,
}

impl DarwinSockOpt {
    pub fn apply(&self, _fd: i32) -> std::io::Result<()> {
        Ok(())
    }
}
