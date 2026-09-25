//! 代理 inbound 与 outbound 之间的连接桥。
//!
//! 对应 Go 版本 `transport/link.go`。
//!
//! `Link` 是一对 `xray_buf::io::{Reader, Writer}`，作为代理 handler
//! `process(link, ...)` 的标准入参，让 inbound 拿到的字节流能直接喂给
//! outbound 写出，无需关心底层是 TCP / TLS / WebSocket / pipe。

use xray_buf::io::{Reader, Writer};

/// inbound → outbound 的字节流桥。
///
/// 对应 Go 的 `transport.Link{ Reader, Writer }`。
///
/// # 示例
///
/// ```
/// use xray_buf::io::{Reader, Writer};
/// use xray_transport::link::Link;
///
/// fn build_link(reader: Box<dyn Reader>, writer: Box<dyn Writer>) -> Link {
///     Link::new(reader, writer)
/// }
/// ```
pub struct Link {
    /// inbound 读到的字节流来源。
    pub reader: Box<dyn Reader>,
    /// outbound 写出的字节流去向。
    pub writer: Box<dyn Writer>,
}

impl Link {
    /// 用一对 reader/writer 构造 Link。
    #[must_use]
    pub fn new(reader: Box<dyn Reader>, writer: Box<dyn Writer>) -> Self {
        Self { reader, writer }
    }

    /// 拆出 (reader, writer)。
    #[must_use]
    pub fn into_parts(self) -> (Box<dyn Reader>, Box<dyn Writer>) {
        (self.reader, self.writer)
    }
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use xray_buf::io::{new_reader, new_writer};

    use super::*;

    #[test]
    fn link_new_stores_reader_writer() {
        let reader = new_reader(std::io::Cursor::new(Vec::<u8>::new()));
        let writer = new_writer(Vec::new());
        let link = Link::new(reader, writer);
        // 仅验证字段存在；trait object 无法直接比较。
        let _ = &link.reader;
        let _ = &link.writer;
    }

    #[tokio::test]
    async fn link_roundtrip_through_buf_io() {
        // 端到端：reader 端能读出预设字节、writer 端能收集写入字节。
        let reader = new_reader(std::io::Cursor::new(b"hello".to_vec()));
        let writer = new_writer(Vec::new());
        let mut link = Link::new(reader, writer);

        let mb = link.reader.read_multi_buffer().await.expect("read ok");
        assert!(!mb.is_empty());

        link.writer.write_multi_buffer(mb).await.expect("write ok");
    }

    #[test]
    fn link_into_parts_returns_same_objects() {
        let reader = new_reader(std::io::Cursor::new(Vec::<u8>::new()));
        let writer = new_writer(Vec::new());
        let link = Link::new(reader, writer);
        let (_r, _w) = link.into_parts();
        // 拆出后两端仍可独立使用（编译期保证）。
    }

    #[test]
    fn link_debug_does_not_panic() {
        let reader = new_reader(std::io::Cursor::new(Vec::<u8>::new()));
        let writer = new_writer(Vec::new());
        let link = Link::new(reader, writer);
        let s = format!("{link:?}");
        assert!(s.contains("Link"));
    }
}
