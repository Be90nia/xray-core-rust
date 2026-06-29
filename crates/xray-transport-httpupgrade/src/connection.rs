//! HTTPUpgrade 连接包装——覆盖 `remote_addr`，对应 Go `connection.go`。
//!
//! 切片1 仅声明类型 + 注释说明用途。实际 `Connection` trait impl 需要
//! 包装一个 `Box<dyn xray_transport::Connection>`，留切片2 与真实 IO 接通后实现。
//!
//! 设计：HTTPUpgrade 握手后底层字节流就是 raw TCP/TLS，无需任何额外封装。
//! 仅在地址上需要覆盖（X-Forwarded-For 注入），所以 wrapper 只是简单持有
//! 内层连接 + 一个替代的 `remote_addr`。

use std::net::SocketAddr;

/// 占位 wrapper 类型。切片2 接入 `xray_transport::Connection` impl。
///
/// `inner` 是握手完成后的底层字节流（TCP/TLS），`remote_addr` 是从
/// `X-Forwarded-For` 解析得到的源 IP（端口为 0，与 Go `connection.go` 一致）。
pub struct HttpUpgradeConnection<C> {
    /// 内层连接（TCP / TLS / 其他）。切片2 由调用方注入。
    pub inner: C,
    /// 替换后的对端地址。`Ok(Some(addr))` 时 Connection::remote_addr 返回此值。
    pub remote_addr_override: Option<SocketAddr>,
}

impl<C> HttpUpgradeConnection<C> {
    /// 构造 wrapper。
    #[must_use]
    pub fn new(inner: C, remote_addr: Option<SocketAddr>) -> Self {
        Self {
            inner,
            remote_addr_override: remote_addr,
        }
    }

    /// 拆出内层连接。
    #[must_use]
    pub fn into_inner(self) -> C {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn construction_preserves_inner() {
        let inner = vec![1u8, 2, 3];
        let addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 0).into();
        let conn = HttpUpgradeConnection::new(inner.clone(), Some(addr));
        assert_eq!(conn.remote_addr_override, Some(addr));
        assert_eq!(conn.into_inner(), inner);
    }

    #[test]
    fn none_override_preserved() {
        let conn = HttpUpgradeConnection::new(42u8, None);
        assert!(conn.remote_addr_override.is_none());
    }
}
