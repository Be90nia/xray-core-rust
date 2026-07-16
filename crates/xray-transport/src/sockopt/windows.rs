//! # Windows socket options
//!
//! 对应 Go `transport/internet/sockopt_windows.go`。

#[derive(Debug, Clone, Default)]
pub struct WindowsSockOpt {
    pub tcp_fast_open: u32,
}

impl WindowsSockOpt {
    pub fn apply(&self, _fd: i32) -> std::io::Result<()> {
        Ok(())
    }
}
