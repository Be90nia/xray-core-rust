//! VLESS 客户端编解码（出站方向）。
//!
//! 对应 Go 版本 `proxy/vless/encoding/encoding.go` 中的 `EncodeRequestHeader`
//! 和 `DecodeResponseHeader`。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_common::net::address::Address;
use xray_common::uuid::UUID;
use xray_proto::xray::proxy::vless::encoding::Addons;

use crate::encoding::{encode_header_addons, write_address_port, VlessCommand};
use crate::error::{Result, VlessError};

/// 编码并发送请求头到 `writer`。
///
/// 对应 Go 的 `EncodeRequestHeader`。布局见 [`crate::encoding`] 模块文档。
///
/// - `user_uuid`：用户 UUID 引用（16 字节原始表示）。
/// - `command`：TCP/UDP/Mux/Rvs。
/// - `address` / `port`：仅 TCP/UDP 必填，Mux/Rvs 必填 `None`。
pub async fn encode_request_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    version: u8,
    user_uuid: &UUID,
    command: VlessCommand,
    address: Option<&Address>,
    port: Option<u16>,
    addons: &Addons,
) -> Result<()> {
    // 校验：TCP/UDP 必须传 address+port；Mux/Rvs 必须不传
    if command.needs_address() {
        if address.is_none() || port.is_none() {
            return Err(VlessError::InvalidRequestAddress);
        }
    } else if address.is_some() || port.is_some() {
        // Mux/Rvs 携带固定域名，调用方不应传 address+port
        return Err(VlessError::Other(
            "Mux/Rvs command should not carry address/port".into(),
        ));
    }

    let mut buf = Vec::with_capacity(64);

    // 1B version
    buf.push(version);

    // 16B user id（UUID 原始字节）
    buf.extend_from_slice(user_uuid.as_bytes());

    // addons
    encode_header_addons(&mut buf, addons)?;

    // 1B command
    buf.push(command.as_u8());

    // TCP/UDP: port + addr
    if let (Some(addr), Some(p)) = (address, port) {
        write_address_port(&mut buf, addr, p);
    }

    writer.write_all(&buf).await.map_err(VlessError::Io)?;
    Ok(())
}

/// 解码响应头：薄包装 [`crate::encoding::decode_response_header`]。
///
/// 对应 Go 的 `DecodeResponseHeader`。返回响应 addons，版本不匹配返回错误。
pub async fn decode_response_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected_version: u8,
) -> Result<Addons> {
    crate::encoding::decode_response_header(reader, expected_version).await
}

/// 惰性消费 VLESS 响应头的连接包装。
///
/// 对齐 Go outbound 的并发时序：Go 客户端 `postRequest`（发请求头 + 首块业务
/// 数据）与 `getResponse`（读响应头）经 `task.Run` 并发执行；Go 服务端响应头经
/// `BufferedWriter` + `SetFlushNext` 缓冲到**首个下行数据**才 flush。若在 dial
/// 阶段同步读响应头，上行首包（vision 首块 padding 尤甚——服务端 VisionReader
/// 等待 uuid 前缀块）发不出去，服务端永远没有下行数据 → 双向互等 → 服务端超时
/// 断开（#9/#15/#32 "early eof" 根因）。此包装把响应头消费推迟到首次读。
pub struct ResponseHeaderReader<C> {
    inner: C,
    expected_version: u8,
    /// 首读阶段累积字节：响应头 + 可能超读的后续数据。
    head: Vec<u8>,
    head_pos: usize,
    /// 响应头已完整消费。
    done: bool,
}

impl<C> ResponseHeaderReader<C> {
    /// 包装 `inner`，在首次读时消费并校验 `[version][addon_len][addons]`。
    #[must_use]
    pub fn new(inner: C, expected_version: u8) -> Self {
        Self {
            inner,
            expected_version,
            head: Vec::with_capacity(8),
            head_pos: 0,
            done: false,
        }
    }

    /// 从 `inner` 读到 `head` 至少 `want` 字节。EOF/错误透传。
    fn fill_head(
        inner: &mut C,
        cx: &mut Context<'_>,
        head: &mut Vec<u8>,
        want: usize,
    ) -> Poll<io::Result<()>>
    where
        C: AsyncRead + Unpin,
    {
        while head.len() < want {
            let mut tmp = [0u8; 128];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut *inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "vless response header: early eof",
                        )));
                    }
                    head.extend_from_slice(&rb.filled()[..n]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<C> AsyncRead for ResponseHeaderReader<C>
where
    C: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.done {
            // 头部至少 2 字节（version + addon_len）
            if let Poll::Ready(Err(e)) =
                Self::fill_head(&mut this.inner, cx, &mut this.head, 2)
            {
                return Poll::Ready(Err(e));
            }
            if this.head.len() < 2 {
                // fill_head returned Ready(Ok) but head is incomplete — treat as Pending
                // (next poll will retry). Avoid head[..1] OOB on EOF/partial read.
                return Poll::Pending;
            }
            let addon_len = this.head[1] as usize;
            if addon_len > 0 {
                match Self::fill_head(
                    &mut this.inner,
                    cx,
                    &mut this.head,
                    2 + addon_len,
                ) {
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => {}
                }
            }
            if this.head[0] != this.expected_version {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "vless response version mismatch: expected {} got {}",
                        this.expected_version, this.head[0]
                    ),
                )));
            }
            this.head_pos = 2 + addon_len; // 头部字节已消费，仅超读部分返回
            this.done = true; // 关键修复：mark 响应头 done,否则下次 poll_read 永远等 head
        }
        if this.head_pos < this.head.len() {
            let avail = &this.head[this.head_pos..];
            let n = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..n]);
            this.head_pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<C> AsyncWrite for ResponseHeaderReader<C>
where
    C: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<C> xray_transport::connection::Connection for ResponseHeaderReader<C>
where
    C: xray_transport::connection::Connection,
{
    fn remote_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.remote_addr()
    }
    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.local_addr()
    }
    fn raw_tcp_clone(&self) -> Option<tokio::net::TcpStream> {
        // vision splice：穿透响应头缓冲层克隆裸 TCP（装箱后经 dyn 分发到达这里）。
        self.inner.raw_tcp_clone()
    }
}

impl<C> crate::encryption::vision_conn::InnerRawClone for ResponseHeaderReader<C>
where
    C: xray_transport::connection::Connection + crate::encryption::vision_conn::InnerRawClone,
{
    fn inner_raw_tcp_clone(&self) -> Option<tokio::net::TcpStream> {
        // vision splice：穿透响应头缓冲层克隆裸 TCP（响应头消费完后由
        // VisionConn 切换读通道，本层不再参与）。
        self.inner.inner_raw_tcp_clone()
    }
}

// ---------------------------------------------------------------------------
// 单元测试（对应 Go 的 encoding_test.go）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::server::decode_request_header;
    use crate::encoding::VERSION;
    use crate::encoding::empty_addons;
    use crate::validator::{MemoryUser, MemoryValidator, Validator};
    use crate::MemoryAccount;
    use std::io::Cursor;
    use xray_common::net::address::Address;
    use xray_common::uuid::UUID;

    fn make_user_and_validator() -> (UUID, MemoryValidator) {
        let uuid = UUID::new();
        let user = MemoryUser {
            level: 0,
            email: "test@example.com".to_string(),
            account: MemoryAccount::from_proto_account(&xray_proto::xray::proxy::vless::Account {
                    id: uuid.to_string(),
                    ..Default::default()
                },
            )
            .unwrap(),
        };
        let v = MemoryValidator::new();
        v.add(user).unwrap();
        (uuid, v)
    }

    #[tokio::test]
    async fn test_request_serialization_tcp_domain() {
        // 对照 Go TestRequestSerialization: TCP + Domain
        let (uuid, validator) = make_user_and_validator();

        let mut buf = Vec::new();
        let addons = empty_addons();
        let addr = Address::Domain("www.example.com".to_string());
        encode_request_header(
            &mut buf,
            VERSION,
            &uuid,
            VlessCommand::Tcp,
            Some(&addr),
            Some(443),
            &addons,
        )
        .await
        .unwrap();

        let mut cursor = Cursor::new(buf);
        let mut first: Option<Vec<u8>> = None;
        let decoded = decode_request_header(false, &mut first, &mut cursor, &validator)
            .await
            .unwrap();

        assert_eq!(decoded.version, VERSION);
        assert_eq!(decoded.command, VlessCommand::Tcp);
        assert_eq!(decoded.port, Some(443));
        let got_addr = decoded.address.expect("address should be present");
        assert!(got_addr.is_domain());
        assert_eq!(got_addr.as_domain(), Some("www.example.com"));
    }

    #[tokio::test]
    async fn test_request_serialization_mux() {
        // 对照 Go TestMuxRequest: Mux command 不写 addr/port
        let (uuid, validator) = make_user_and_validator();

        let mut buf = Vec::new();
        let addons = empty_addons();
        encode_request_header(
            &mut buf,
            VERSION,
            &uuid,
            VlessCommand::Mux,
            None,
            None,
            &addons,
        )
        .await
        .unwrap();

        let mut cursor = Cursor::new(buf);
        let mut first: Option<Vec<u8>> = None;
        let decoded = decode_request_header(false, &mut first, &mut cursor, &validator)
            .await
            .unwrap();

        assert_eq!(decoded.command, VlessCommand::Mux);
        let got_addr = decoded.address.expect("mux address should be set");
        assert_eq!(got_addr.as_domain(), Some("v1.mux.cool"));
        assert_eq!(decoded.port, None);
    }

    #[tokio::test]
    async fn test_request_invalid_command() {
        // 对照 Go TestInvalidRequest: command=100 在 decode 时拒绝
        let (uuid, validator) = make_user_and_validator();

        let mut buf = Vec::new();
        buf.push(VERSION);
        buf.extend_from_slice(uuid.as_bytes());
        buf.push(0); // addons len = 0
        buf.push(100); // 非法 command

        let mut cursor = Cursor::new(buf);
        let mut first: Option<Vec<u8>> = None;
        let err = decode_request_header(false, &mut first, &mut cursor, &validator)
            .await
            .unwrap_err();
        match err {
            VlessError::InvalidRequestCommand(_) => {}
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_request_unknown_user_rejected() {
        let uuid_unknown = UUID::new();

        let mut buf = Vec::new();
        let addons = empty_addons();
        let addr = Address::Domain("www.example.com".to_string());
        encode_request_header(
            &mut buf,
            VERSION,
            &uuid_unknown,
            VlessCommand::Tcp,
            Some(&addr),
            Some(443),
            &addons,
        )
        .await
        .unwrap();

        let validator = MemoryValidator::new(); // 空
        let mut cursor = Cursor::new(buf);
        let mut first: Option<Vec<u8>> = None;
        let err = decode_request_header(false, &mut first, &mut cursor, &validator)
            .await
            .unwrap_err();
        match err {
            VlessError::UserNotFound(_) => {}
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_encode_response_header_round_trip() {
        let mut buf = Vec::new();
        let addons = empty_addons();
        crate::encoding::encode_response_header(&mut buf, VERSION, &addons)
            .await
            .unwrap();

        let mut cursor = Cursor::new(buf);
        let got = decode_response_header(&mut cursor, VERSION).await.unwrap();
        assert_eq!(got.flow, addons.flow);
    }
}
