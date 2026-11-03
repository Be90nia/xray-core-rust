//! UDP-over-TCP（UoT v2）帧 —— anytls 生态的 UDP 承载约定。
//!
//! 规范来源 `github.com/SagerNet/sing/common/uot`（anytls / sing-box / mihomo 共用）：
//!
//! 1. 客户端以 **magic 目标** `sp.v2.udp-over-tcp.arpa` 建 TCP 会话（端口 0）；
//! 2. 会话首帧 = `Request`：`[1B isConnect][SOCKS5 addr]`（标准 ATYP 1/3/4）；
//! 3. 之后每个数据报：`isConnect=true` 时 `[2B BE len][payload]`（目标固定为 Request
//!    里的目标）；`isConnect=false` 时每包前再带 `[1B atyp{0=IPv4,1=IPv6,2=Fqdn}][addr][2B
//!    len][payload]`。
//!
//! 本仓实现 **isConnect=true** 单目标形态（与 Xray 的「一线程一目标」UDP 模型
//! 一致）；`isConnect=false`（每包自带目标，cone 语义）在服务端显式拒绝并记日志
//! —— 静默按单目标处理会错投到首包目标。

use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use xray_buf::{
    buffer::Buffer,
    io::{Error as BufError, Reader, Writer},
    multi::MultiBuffer,
};

use crate::{
    error::{AnytlsError, Result},
    socks::SocksAddr,
};

/// UoT v2 magic 目标域名。
pub const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
/// UoT v1 兼容 magic 目标域名（同一 framing，仅探测用）。
pub const LEGACY_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";

/// 目标域名是否是 UoT magic（任一版本）。
#[must_use]
pub fn is_magic(host: &str) -> bool {
    host == MAGIC_ADDRESS || host == LEGACY_MAGIC_ADDRESS
}

/// 编码 `Request`：`[1B isConnect][SOCKS5 addr]`。
pub fn encode_request(is_connect: bool, dest: &SocksAddr) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(32);
    out.push(u8::from(is_connect));
    out.extend_from_slice(&dest.encode()?);
    Ok(out)
}

/// 解析 `Request`。`Ok(None)` = 字节不足（调用方继续读）。
pub fn decode_request(buf: &[u8]) -> Result<Option<(bool, SocksAddr, usize)>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    // [1B isConnect][1B atyp]...
    let need = match buf[1] {
        // atyp IPv4：1 + 4 + 2
        0x01 => 1 + 1 + 4 + 2,
        // atyp IPv6：1 + 1 + 16 + 2
        0x04 => 1 + 1 + 16 + 2,
        // atyp 域名：1 + 1 + 1(len) + len + 2
        0x03 => {
            if buf.len() < 3 {
                return Ok(None);
            }
            1 + 1 + 1 + usize::from(buf[2]) + 2
        },
        other => {
            return Err(AnytlsError::InvalidSocksAddr(format!("uot: unknown atyp {other}")));
        },
    };
    if buf.len() < need {
        return Ok(None);
    }
    let (dest, used) = SocksAddr::decode(&buf[1..])?;
    let is_connect = buf[0] != 0;
    Ok(Some((is_connect, dest, 1 + used)))
}

/// `[2B BE len][payload]` 帧读端：每次交付恰好一个数据报（单个 Buffer）。
///
/// 一包一 Buffer 是 mux / `XudpUnframingReader` 组合的硬前提。
pub struct LengthFramedReader {
    inner: Box<dyn AsyncRead + Unpin + Send>,
}

impl LengthFramedReader {
    /// 包装内层字节流。
    #[must_use]
    pub fn new(inner: impl AsyncRead + Unpin + Send + 'static) -> Self {
        Self { inner: Box::new(inner) }
    }
}

impl Reader for LengthFramedReader {
    fn read_multi_buffer(
        &mut self,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = std::result::Result<MultiBuffer, BufError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let mut len_buf = [0u8; 2];
            match self.inner.read_exact(&mut len_buf).await {
                Ok(_) => {},
                // 干净 EOF：交付空 MultiBuffer（上层据此收流）
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(MultiBuffer::new());
                },
                Err(e) => return Err(BufError::ReadError(format!("uot frame len: {e}"))),
            }
            let len = usize::from(u16::from_be_bytes(len_buf));
            let mut payload = Buffer::with_capacity(len.max(1));
            if len > 0 {
                payload
                    .read_exact_from(&mut *self.inner, len)
                    .await
                    .map_err(|e| BufError::ReadError(format!("uot frame body: {e}")))?;
            }
            Ok(MultiBuffer::from_buffer(payload))
        })
    }
}

/// `[2B BE len][payload]` 帧写端：每次 `write_multi_buffer` = 一个数据报。
///
/// 帧头进池化 Buffer，载荷 Buffer 原样挂上（零拷贝）。
pub struct LengthFramedWriter {
    inner: Box<dyn AsyncWrite + Unpin + Send>,
}

impl LengthFramedWriter {
    /// 包装内层字节流。
    #[must_use]
    pub fn new(inner: impl AsyncWrite + Unpin + Send + 'static) -> Self {
        Self { inner: Box::new(inner) }
    }
}

impl Writer for LengthFramedWriter {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn std::future::Future<Output = std::result::Result<(), BufError>> + Send + '_>>
    {
        Box::pin(async move {
            // 零长载荷也要写出 `0x0000` 帧头：uot wire = `[2B BE len][payload]`，
            // 长度前缀**无条件先写**（对齐 Go/sing uot）。早先的 `mb.is_empty() →
            // return Ok(())` 把空 datagram 变成「对端等帧头、本端不发」的永久挂起
            // （wave1 yfcnr 遗留；`tests` 的 length_framed_roundtrip 空载荷分支即
            // 因此挂死），且等于空 datagram 静默丢包。
            if mb.len() > usize::from(u16::MAX) {
                return Err(BufError::WriteError(format!(
                    "uot frame payload {} exceeds u16 length",
                    mb.len()
                )));
            }
            let mut header = Buffer::new();
            header.write_from(&(mb.len() as u16).to_be_bytes());
            let mut out = MultiBuffer::with_capacity(mb.buffer_count() + 1);
            out.push(header);
            for buf in mb.into_buffers() {
                out.push(buf);
            }
            for buf in out.into_buffers() {
                if buf.is_empty() {
                    continue;
                }
                self.inner
                    .write_all(buf.bytes())
                    .await
                    .map_err(|e| BufError::WriteError(format!("uot frame write: {e}")))?;
            }
            Ok(())
        })
    }

    fn shutdown(&self) {
        // AsyncWrite 的 shutdown 需要 &mut；Writer::shutdown 是 &self。
        // 会话层收尾由 anytls session 自身的 finish 承担（server.rs
        // finish_session），这里不重复半关闭。
    }

    fn shutdown_flush(
        &mut self,
    ) -> Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + '_>> {
        Box::pin(async move {
            self.inner.flush().await?;
            self.inner.shutdown().await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip_ipv4() {
        let dest = SocksAddr::ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8), 53);
        let bytes = encode_request(true, &dest).unwrap();
        assert_eq!(bytes[0], 1, "isConnect 前缀");
        assert_eq!(bytes[1], 0x01, "atyp IPv4");
        let (is_connect, got, used) = decode_request(&bytes).unwrap().expect("complete");
        assert!(is_connect);
        assert_eq!(got, dest);
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn request_roundtrip_domain() {
        let dest = SocksAddr::domain("example.com", 443);
        let bytes = encode_request(false, &dest).unwrap();
        let (is_connect, got, used) = decode_request(&bytes).unwrap().expect("complete");
        assert!(!is_connect);
        assert_eq!(got, dest);
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn request_incomplete_returns_none() {
        let dest = SocksAddr::domain("abcd.example", 53);
        let bytes = encode_request(true, &dest).unwrap();
        for cut in 0..bytes.len() {
            assert!(decode_request(&bytes[..cut]).unwrap().is_none(), "cut={cut} must be None");
        }
        assert!(decode_request(&bytes).unwrap().is_some());
    }

    #[test]
    fn magic_address_detection() {
        assert!(is_magic("sp.v2.udp-over-tcp.arpa"));
        assert!(is_magic("sp.udp-over-tcp.arpa"));
        assert!(!is_magic("example.com"));
    }

    #[tokio::test]
    async fn length_framed_roundtrip() {
        let (a, b) = tokio::io::duplex(4096);
        let mut w = LengthFramedWriter::new(a);
        let mut r = LengthFramedReader::new(b);
        for payload in [b"hello".as_slice(), b"".as_slice(), &[7u8; 3000][..]] {
            let mut mb = MultiBuffer::new();
            if !payload.is_empty() {
                let mut buf = Buffer::from_vec(payload.to_vec());
                buf.advance(0);
                mb.push(std::mem::replace(&mut buf, Buffer::with_capacity(1)));
            }
            // 本仓无 per-test 超时：写端一旦吞帧（历史形态 `mb.is_empty() → Ok(())`），
            // 读端 read_exact 永久等 2B 帧头，整个 `--lib` 跑到 1200s 被 kill 都不出新
            // 结果（bd 33ll3 现场）。墙钟把「挂死」变成 5s 内的红。
            let got = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                w.write_multi_buffer(mb).await.unwrap();
                r.read_multi_buffer().await.unwrap()
            })
            .await
            .expect("uot 帧往返超过 5s：写端吞帧或读端永等帧头（挂死形态）");
            let mut out = Vec::new();
            for buf in got.iter() {
                out.extend_from_slice(buf.bytes());
            }
            assert_eq!(out, payload, "帧边界与载荷逐字节一致");
        }
    }

    /// 空 datagram 的 wire 证据（回归门）：`write_multi_buffer(空)` 必须**真的写出**
    /// 2 字节 `0x0000` 帧头，而不是「本端不发、对端等帧头」的永久挂起
    /// （旧 `mb.is_empty() → return Ok(())` 的挂死形态；对齐 Go uot 无条件写长度前缀）。
    #[tokio::test]
    async fn empty_datagram_emits_zero_length_frame_on_wire() {
        let (a, mut peer) = tokio::io::duplex(64);
        let mut w = LengthFramedWriter::new(a);
        w.write_multi_buffer(MultiBuffer::new()).await.expect("空载荷必须写出 0x0000 帧");

        let mut hdr = [0u8; 2];
        tokio::time::timeout(std::time::Duration::from_secs(5), peer.read_exact(&mut hdr))
            .await
            .expect("对端必须在期限内收到帧头（写端吞帧 = 本用例红）")
            .expect("read hdr");
        assert_eq!(hdr, [0u8, 0], "零长载荷的 wire 形态 = 2 字节 0x0000 帧头");
    }
}
