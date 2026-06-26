//! VLESS 协议编解码。
//!
//! 对应 Go 版本 `proxy/vless/encoding/`。VLESS 是非常紧凑的二进制协议：
//!
//! # 请求头布局
//! ```text
//! +-----+----------+--------+---------+-----------------------------+
//! | Ver | User ID  | Addons | Command | Address + Port (可选)        |
//! | 1B  |   16B    | 变长   |   1B    | 2B Port BE + 1B Type + Data |
//! +-----+----------+--------+---------+-----------------------------+
//! ```
//! - `Ver`：协议版本，目前固定为 0。
//! - `User ID`：用户 UUID 的 16 字节原始表示（**注意**是 ProcessUUID 处理后的）。
//! - `Addons`：见 [`encode_header_addons`]。
//! - `Command`：1=TCP、2=UDP、3=Mux（特殊地址 `v1.mux.cool`）、4=Rvs（`v1.rvs.cool`）。
//! - 当 `Command` 为 TCP/UDP 时才写 `Address + Port`。
//!
//! # 响应头布局
//! ```text
//! +-----+--------+
//! | Ver | Addons |
//! | 1B  |  变长  |
//! +-----+--------+
//! ```
//!
//! # Address 编码
//! 2B Port（大端）+ 1B 类型 + 数据：
//! - Type=1 IPv4：4 字节
//! - Type=2 Domain：1 字节长度 + N 字节域名
//! - Type=3 IPv6：16 字节

pub mod client;
pub mod server;

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use xray_common::net::{address::Address, port::Port};
use xray_proto::xray::proxy::vless::encoding::Addons;

use crate::error::{Result, VlessError};

/// VLESS 请求命令（含 Rvs）。
///
/// 对应 Go 端 `protocol.RequestCommand` + VLESS 反向代理独有的 `RequestCommandRvs`(4)。
/// `xray_common::protocol::Command` 不包含 Rvs，所以在 vless crate 内部定义。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VlessCommand {
    /// TCP 代理
    Tcp = 1,
    /// UDP 代理
    Udp = 2,
    /// 多路复用，地址固定为 `v1.mux.cool`
    Mux = 3,
    /// VLESS 反向代理，地址固定为 `v1.rvs.cool`
    Rvs = 4,
}

impl VlessCommand {
    /// 从 u8 数值转换，未知值返回 `None`。
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Tcp),
            2 => Some(Self::Udp),
            3 => Some(Self::Mux),
            4 => Some(Self::Rvs),
            _ => None,
        }
    }

    /// 转为 u8 数值。
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// 该命令是否需要携带 `Address + Port`（Mux/Rvs 用固定地址）。
    #[must_use]
    pub fn needs_address(self) -> bool {
        matches!(self, Self::Tcp | Self::Udp)
    }

    /// 该命令对应的固定域名（用于 Mux/Rvs）。
    #[must_use]
    pub fn fixed_domain(self) -> Option<&'static str> {
        match self {
            Self::Mux => Some("v1.mux.cool"),
            Self::Rvs => Some("v1.rvs.cool"),
            _ => None,
        }
    }
}

impl From<xray_common::protocol::Command> for VlessCommand {
    fn from(cmd: xray_common::protocol::Command) -> Self {
        match cmd {
            xray_common::protocol::Command::Tcp => Self::Tcp,
            xray_common::protocol::Command::Udp => Self::Udp,
            xray_common::protocol::Command::Mux => Self::Mux,
        }
    }
}
/// VLESS 协议版本（目前固定为 0）。
pub const VERSION: u8 = 0;

/// 地址类型字节。
pub mod addr_type {
    /// IPv4 = 4 字节地址。
    pub const IPV4: u8 = 1;
    /// Domain = 1 字节长度 + N 字节域名。
    pub const DOMAIN: u8 = 2;
    /// IPv6 = 16 字节地址。
    pub const IPV6: u8 = 3;
}

/// 重新导出 proto 生成的 [`Addons`]，避免上层重复路径。
pub type EncAddons = Addons;

/**
 * 工厂函数：返回一个空的 [`Addons`]（`flow=""`, `seed=[]`）。
 *
 * 因为 `Addons` 是 proto 生成的外部类型，不能在 vless crate 内部 impl `Default`
 * （orphan rule），所以提供工厂函数作为替代。
 */
#[must_use]
pub fn empty_addons() -> Addons {
    Addons {
        flow: String::new(),
        seed: Vec::new(),
    }
}

/// 把地址 + 端口按 VLESS 格式写入 `out`（2B BE port + 1B type + data）。
///
/// 对应 Go 的 `addrParser.WriteAddressPort`（采用 `PortThenAddress` 顺序）。
pub fn write_address_port(out: &mut Vec<u8>, address: &Address, port: u16) {
    out.extend_from_slice(&port.to_be_bytes());
    match address {
        Address::IPv4(v4) => {
            out.push(addr_type::IPV4);
            out.extend_from_slice(&v4.octets());
        }
        Address::Domain(domain) => {
            out.push(addr_type::DOMAIN);
            let bytes = domain.as_bytes();
            // 域名长度上限是 255，超过应在上层拒绝
            let len = u8::try_from(bytes.len()).unwrap_or(255);
            out.push(len);
            out.extend_from_slice(&bytes[..len as usize]);
        }
        Address::IPv6(v6) => {
            out.push(addr_type::IPV6);
            out.extend_from_slice(&v6.octets());
        }
    }
}

/// 从 `reader` 读取地址 + 端口。
pub async fn read_address_port<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(Address, Port)> {
    let mut port_buf = [0u8; 2];
    reader
        .read_exact(&mut port_buf)
        .await
        .map_err(|e| VlessError::Io(e))?;
    let port = u16::from_be_bytes(port_buf);

    let mut type_buf = [0u8; 1];
    reader
        .read_exact(&mut type_buf)
        .await
        .map_err(VlessError::Io)?;
    let addr = match type_buf[0] {
        addr_type::IPV4 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).await.map_err(VlessError::Io)?;
            Address::IPv4(std::net::Ipv4Addr::from(buf))
        }
        addr_type::DOMAIN => {
            let mut len_buf = [0u8; 1];
            reader
                .read_exact(&mut len_buf)
                .await
                .map_err(VlessError::Io)?;
            let mut buf = vec![0u8; len_buf[0] as usize];
            reader.read_exact(&mut buf).await.map_err(VlessError::Io)?;
            let domain = String::from_utf8(buf)
                .map_err(|_| VlessError::InvalidRequestAddress)?;
            Address::Domain(domain)
        }
        addr_type::IPV6 => {
            let mut buf = [0u8; 16];
            reader.read_exact(&mut buf).await.map_err(VlessError::Io)?;
            Address::IPv6(std::net::Ipv6Addr::from(buf))
        }
        _ => return Err(VlessError::InvalidRequestAddress),
    };
    Ok((addr, Port::new(port)))
}

/// 编码 `Addons` 到 `out`。
///
/// 对应 Go 的 `EncodeHeaderAddons`：当 `Flow == XRV` 时写 `[1B len][len B proto]`，
/// 其他情况只写一个 `0x00` 字节。
pub fn encode_header_addons(out: &mut Vec<u8>, addons: &Addons) -> Result<()> {
    if addons.flow == crate::FLOW_XRV {
        let bytes = addons.encode_to_vec();
        let len = u8::try_from(bytes.len())
            .map_err(|_| VlessError::Other("addons too long".into()))?;
        out.push(len);
        out.extend_from_slice(&bytes);
    } else {
        out.push(0);
    }
    Ok(())
}

/// 从 `reader` 解码 `Addons`。
pub async fn decode_header_addons<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Addons> {
    let mut len_buf = [0u8; 1];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(VlessError::Io)?;
    if len_buf[0] == 0 {
        return Ok(empty_addons());
    }
    let mut buf = vec![0u8; len_buf[0] as usize];
    reader.read_exact(&mut buf).await.map_err(VlessError::Io)?;
    let addons = Addons::decode(&*buf)
        .map_err(|e| VlessError::Other(format!("unmarshal addons: {e}")))?;
    Ok(addons)
}

/// 编码响应头：`[1B version][addons]`，写入 `writer`。
pub async fn encode_response_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    version: u8,
    response_addons: &Addons,
) -> Result<()> {
    let mut buf = Vec::with_capacity(16);
    buf.push(version);
    encode_header_addons(&mut buf, response_addons)?;
    writer
        .write_all(&buf)
        .await
        .map_err(VlessError::Io)?;
    Ok(())
}

/// 从 `reader` 解码响应头，返回 `Addons`。版本不匹配返回错误。
pub async fn decode_response_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected_version: u8,
) -> Result<Addons> {
    let mut ver_buf = [0u8; 1];
    reader
        .read_exact(&mut ver_buf)
        .await
        .map_err(VlessError::Io)?;
    if ver_buf[0] != expected_version {
        return Err(VlessError::UnexpectedResponseVersion {
            expected: expected_version,
            actual: ver_buf[0],
        });
    }
    decode_header_addons(reader).await
}

// ---------------------------------------------------------------------------
// LengthPacket 系列（UDP 长度前缀包）
// ---------------------------------------------------------------------------

/// 写一个带 2B BE 长度前缀的 UDP 包。返回写入字节数（不含内部缓冲开销）。
///
/// 对应 Go 的 `LengthPacketWriter.WriteMultiBuffer`。
pub async fn write_length_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<()> {
    let len = u16::try_from(payload.len())
        .map_err(|_| VlessError::Other("packet too long for u16 length prefix".into()))?;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(VlessError::Io)?;
    writer
        .write_all(payload)
        .await
        .map_err(VlessError::Io)?;
    Ok(())
}

/// 读一个带 2B BE 长度前缀的 UDP 包。
///
/// 对应 Go 的 `LengthPacketReader.ReadMultiBuffer`。底层 reader EOF 时返回
/// `Err(VlessError::Io(UnexpectedEof))`，由调用方决定是否吞掉。
pub async fn read_length_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(VlessError::Io)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(VlessError::Io)?;
    Ok(payload)
}

/// 把多个 UDP 包逐个加 2B 长度前缀后写出去。
///
/// 对应 Go 的 `MultiLengthPacketWriter.WriteMultiBuffer`。Go 端对超过 `buf.Size`
/// 的包会跳过；Rust 端语义保留——超过 `max_packet_size` 的包跳过（默认 64KiB-2）。
pub async fn write_multi_length_packets<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packets: &[&[u8]],
    max_packet_size: usize,
) -> Result<()> {
    for &p in packets {
        if p.is_empty() || p.len() + 2 > max_packet_size {
            continue;
        }
        write_length_packet(writer, p).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 单元测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_address_ipv4() -> Address {
        Address::IPv4(std::net::Ipv4Addr::new(192, 168, 1, 1))
    }

    fn sample_address_domain() -> Address {
        Address::Domain("www.example.com".to_string())
    }

    fn sample_address_ipv6() -> Address {
        Address::IPv6(std::net::Ipv6Addr::LOCALHOST)
    }

    #[test]
    fn test_write_then_read_address_ipv4() {
        let addr = sample_address_ipv4();
        let mut buf = Vec::new();
        write_address_port(&mut buf, &addr, 443);
        // 2 port + 1 type + 4 = 7
        assert_eq!(buf.len(), 7);
        assert_eq!(&buf[0..2], &[0x01, 0xBB]); // port 443 BE
        assert_eq!(buf[2], addr_type::IPV4);

        let mut cursor = Cursor::new(buf);
        // 这里用同步 helper 测，避免 tokio runtime
        // read_address_port 是 async，借助 block_on
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (got_addr, got_port) = rt.block_on(async move {
            read_address_port(&mut cursor).await.unwrap()
        });
        assert_eq!(got_port.value(), 443);
        assert!(got_addr.is_ipv4());
        assert_eq!(got_addr.ipv4_bytes(), Some([192, 168, 1, 1]));
    }

    #[test]
    fn test_write_then_read_address_domain() {
        let addr = sample_address_domain();
        let mut buf = Vec::new();
        write_address_port(&mut buf, &addr, 8080);
        let expected_len = 2 + 1 + 1 + "www.example.com".len();
        assert_eq!(buf.len(), expected_len);

        let mut cursor = Cursor::new(buf);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (got_addr, got_port) = rt.block_on(async move {
            read_address_port(&mut cursor).await.unwrap()
        });
        assert_eq!(got_port.value(), 8080);
        assert!(got_addr.is_domain());
        assert_eq!(got_addr.as_domain(), Some("www.example.com"));
    }

    #[test]
    fn test_write_then_read_address_ipv6() {
        let addr = sample_address_ipv6();
        let mut buf = Vec::new();
        write_address_port(&mut buf, &addr, 443);
        // 2 + 1 + 16 = 19
        assert_eq!(buf.len(), 19);

        let mut cursor = Cursor::new(buf);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (got_addr, got_port) = rt.block_on(async move {
            read_address_port(&mut cursor).await.unwrap()
        });
        assert_eq!(got_port.value(), 443);
        assert!(got_addr.is_ipv6());
        assert_eq!(got_addr.ipv6_bytes(), Some([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]));
    }

    #[test]
    fn test_encode_header_addons_default() {
        // 非 XRV flow：写 1 个 0 字节
        let mut buf = Vec::new();
        let addons = empty_addons();
        encode_header_addons(&mut buf, &addons).unwrap();
        assert_eq!(buf, vec![0]);
    }

    #[test]
    fn test_encode_header_addons_xrv() {
        // XRV flow：写 [1B len][proto bytes]
        let mut buf = Vec::new();
        let addons = Addons {
            flow: crate::FLOW_XRV.to_string(),
            seed: Vec::new(),
        };
        encode_header_addons(&mut buf, &addons).unwrap();
        assert!(!buf.is_empty());
        // buf[0] = len of marshaled Addons
        let proto_len = buf[0] as usize;
        assert_eq!(buf.len(), 1 + proto_len);
    }

    #[tokio::test]
    async fn test_decode_header_addons_default() {
        let mut cursor = Cursor::new(vec![0u8]);
        let addons = decode_header_addons(&mut cursor).await.unwrap();
        assert_eq!(addons.flow, "");
        assert!(addons.seed.is_empty());
    }

    #[tokio::test]
    async fn test_decode_header_addons_xrv_round_trip() {
        let mut encoded = Vec::new();
        let original = Addons {
            flow: crate::FLOW_XRV.to_string(),
            seed: b"seed-data".to_vec(),
        };
        encode_header_addons(&mut encoded, &original).unwrap();

        let mut cursor = Cursor::new(encoded);
        let got = decode_header_addons(&mut cursor).await.unwrap();
        assert_eq!(got.flow, crate::FLOW_XRV);
        assert_eq!(got.seed, original.seed);
    }

    #[tokio::test]
    async fn test_encode_then_decode_response_header() {
        let mut buf = Vec::new();
        let addons = empty_addons();
        encode_response_header(&mut buf, VERSION, &addons).await.unwrap();
        // 1B version + 1B addons(0)
        assert_eq!(buf, vec![VERSION, 0]);

        let mut cursor = Cursor::new(buf);
        let got = decode_response_header(&mut cursor, VERSION).await.unwrap();
        assert_eq!(got.flow, "");
    }

    #[tokio::test]
    async fn test_decode_response_header_version_mismatch() {
        let mut buf = Vec::new();
        encode_response_header(&mut buf, 1u8, &empty_addons())
            .await
            .unwrap();
        let mut cursor = Cursor::new(buf);
        let err = decode_response_header(&mut cursor, 0u8).await.unwrap_err();
        match err {
            VlessError::UnexpectedResponseVersion { expected, actual } => {
                assert_eq!(expected, 0);
                assert_eq!(actual, 1);
            }
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_length_packet_round_trip() {
        let mut buf = Vec::new();
        let payload = b"hello world";
        write_length_packet(&mut buf, payload).await.unwrap();
        // 2B len + payload
        assert_eq!(buf.len(), 2 + payload.len());
        assert_eq!(&buf[0..2], &[0x00, payload.len() as u8]);

        let mut cursor = Cursor::new(buf);
        let got = read_length_packet(&mut cursor).await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn test_multi_length_packets() {
        let mut buf = Vec::new();
        let packets: Vec<&[u8]> = vec![b"aaa", b"bbbb", b""];
        write_multi_length_packets(&mut buf, &packets, 8192)
            .await
            .unwrap();
        let mut cursor = Cursor::new(buf);
        // 空包应被跳过
        let p1 = read_length_packet(&mut cursor).await.unwrap();
        let p2 = read_length_packet(&mut cursor).await.unwrap();
        assert_eq!(p1, b"aaa");
        assert_eq!(p2, b"bbbb");
    }

    #[tokio::test]
    async fn test_multi_length_packets_skip_oversized() {
        let mut buf = Vec::new();
        let big = vec![0u8; 10];
        let small = b"ok";
        let packets: Vec<&[u8]> = vec![&big, small];
        // max_packet_size = 5 → big(10+2=12) 被跳过，small(2+2=4) 通过
        write_multi_length_packets(&mut buf, &packets, 5)
            .await
            .unwrap();
        let mut cursor = Cursor::new(buf);
        let got = read_length_packet(&mut cursor).await.unwrap();
        assert_eq!(got, small);
    }
}
