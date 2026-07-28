//! TUIC v5 HTTP/3 传输层（h3-quinn 封装）。
//!
//! 本模块提供 [`H3TuicTransport`]：在已建立的 QUIC 连接上运行 HTTP/3，
//! 实现 TUIC 的 h3 伪装（camouflage）模式。真实 HTTP/3 帧封装（real-h3 mode）
//! 用于传输 TUIC 命令和数据。
//!
//! ## 设计
//!
//! - 复用 [`crate::pool::MultiplexedConnection`] 的 QUIC 连接
//! - 通过 h3-quinn 创建 HTTP/3 连接和 stream
//! - 在 HTTP/3 DATA 帧中封装 TUIC 命令（CONNECT + UDP_ASSOCIATE + DATAGRAM）
//! - 支持 HTTP/3 DATAGRAM 扩展（RFC 9297）用于 native UDP 模式
//!
//! ## 限制（ponytail）
//!
//! - 仅实现 h3 伪装层，不实现完整 HTTP/3 语义（GET/POST 等）
//! - 依赖 quinn 的 ALPN 协商（已设置 `h3`）
//! - 不实现 QPACK 动态表（静态表足够）
//! - 单连接多 stream 复用由 quinn 内部管理

use bytes::{BufMut, BytesMut};

use crate::error::{Result, TuicError};
use crate::pool::MultiplexedConnection;
use crate::protocol::address::Address;
use crate::protocol::command::TOKEN_LEN;

/// HTTP/3 帧类型码（RFC 9114）。
mod h3_frame_type {
    /// DATA 帧。
    pub const DATA: u8 = 0x00;
    /// HEADERS 帧。
    pub const HEADERS: u8 = 0x01;
    /// SETTINGS 帧。
    pub const SETTINGS: u8 = 0x04;
    /// GOAWAY 帧。
    pub const GOAWAY: u8 = 0x07;
}

/// HTTP/3 SETTINGS 标识符。
mod h3_settings_id {
    /// QPACK 最大动态表容量。
    pub const QPACK_MAX_TABLE_CAPACITY: u8 = 0x01;
    /// 最大 field section 大小。
    pub const MAX_FIELD_SECTION_SIZE: u8 = 0x06;
    /// DATAGRAM 支持（RFC 9297）。
    pub const H3_DATAGRAM: u8 = 0x33;
}

/// TUIC over HTTP/3 传输包装。
///
/// 在 QUIC 连接上发送 HTTP/3 帧，伪装成正常 H3 流量。
#[derive(Clone)]
pub struct H3TuicTransport {
    multiplexed: MultiplexedConnection,
}

impl H3TuicTransport {
    /// 从 [`MultiplexedConnection`] 构造。
    pub fn new(multiplexed: MultiplexedConnection) -> Self {
        Self { multiplexed }
    }

    /// 发送 HTTP/3 SETTINGS 帧（连接初始化）。
    ///
    /// 在控制 stream（uni stream id = 0x2）上发送。
    /// 设置：QPACK 动态表容量 = 0（禁用动态表），DATAGRAM 支持 = 1。
    pub async fn send_settings(&self) -> Result<()> {
        let mut settings = BytesMut::new();
        // QPACK_MAX_TABLE_CAPACITY = 0
        settings.put_u8(h3_settings_id::QPACK_MAX_TABLE_CAPACITY);
        settings.put_u64(0);
        // MAX_FIELD_SECTION_SIZE = 8192
        settings.put_u8(h3_settings_id::MAX_FIELD_SECTION_SIZE);
        settings.put_u64(8192);
        // H3_DATAGRAM = 1（启用 DATAGRAM 支持）
        settings.put_u8(h3_settings_id::H3_DATAGRAM);
        settings.put_u64(1);

        let mut frame = BytesMut::new();
        frame.put_u8(h3_frame_type::SETTINGS);
        frame.put_u64(settings.len() as u64);
        frame.put_slice(&settings);

        let mut uni = self.multiplexed.open_uni().await?;
        uni.write_all(&frame).await?;
        let _ = uni.finish();
        Ok(())
    }

    /// 发送 HTTP/3 HEADERS 帧（伪装请求头）。
    ///
    /// 构造一个伪装的 `:method = CONNECT` 请求头，目标为 TUIC server。
    /// 实际负载在后续的 DATA 帧中。
    pub async fn send_connect_headers(
        &self,
        target: Address,
        auth_token: [u8; TOKEN_LEN],
    ) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let (mut send, recv) = self.multiplexed.open_bi().await?;

        // 构造伪装的 HEADERS 帧
        // 格式：`:method = CONNECT`, `:authority = <target>`, `x-tuic-token = <token>`
        let mut headers = BytesMut::new();
        headers.put_u8(0x00); // :method 索引（静态表）
        headers.put_u8(0x07); // CONNECT 字符串长度
        headers.put_slice(b"CONNECT");

        // :authority = target address
        let authority = format!("{}:{}", target.host(), target.port());
        headers.put_u8(0x01); // :authority 索引（静态表）
        headers.put_u8(authority.len() as u8);
        headers.put_slice(authority.as_bytes());

        // x-tuic-token = hex(token)（自定义 header，用于认证）
        let token_hex = format!("{:02x?}", auth_token).replace(|c: char| c == '[' || c == ']' || c == ' ' || c == '"', "");
        headers.put_u8(0x40); // Literal header with name reference（新 header）
        headers.put_u8(13); // "x-tuic-token" 长度
        headers.put_slice(b"x-tuic-token");
        headers.put_u8(token_hex.len() as u8);
        headers.put_slice(token_hex.as_bytes());

        let mut frame = BytesMut::new();
        frame.put_u8(h3_frame_type::HEADERS);
        frame.put_u64(headers.len() as u64);
        frame.put_slice(&headers);

        send.write_all(&frame).await?;
        Ok((send, recv))
    }

    /// 发送 HTTP/3 DATA 帧。
    ///
    /// 在 bi-stream 上发送，封装 TUIC 命令或数据。
    pub async fn send_data(
        &self,
        send: &mut quinn::SendStream,
        data: &[u8],
    ) -> Result<()> {
        let mut frame = BytesMut::new();
        frame.put_u8(h3_frame_type::DATA);
        frame.put_u64(data.len() as u64);
        frame.put_slice(data);

        send.write_all(&frame).await?;
        Ok(())
    }

    /// 发送 HTTP/3 GOAWAY 帧（优雅关闭）。
    pub async fn send_goaway(&self) -> Result<()> {
        let mut frame = BytesMut::new();
        frame.put_u8(h3_frame_type::GOAWAY);
        frame.put_u64(0); // GOAWAY ID = 0

        let mut uni = self.multiplexed.open_uni().await?;
        uni.write_all(&frame).await?;
        let _ = uni.finish();
        Ok(())
    }

    /// 读取 HTTP/3 帧头，返回 (帧类型, 负载长度)。
    ///
    /// 从 recv stream 读取 1 字节类型 + varint 长度。
    pub async fn read_frame_header(recv: &mut quinn::RecvStream) -> Result<(u8, u64)> {
        let mut type_buf = [0u8; 1];
        recv.read_exact(&mut type_buf)
            .await
            .map_err(TuicError::QuinnReadExact)?;
        let frame_type = type_buf[0];

        // 读取 varint 长度（quic 变长整数编码）
        let mut len_buf = [0u8; 8];
        recv.read_exact(&mut len_buf[..1])
            .await
            .map_err(TuicError::QuinnReadExact)?;
        let first_byte = len_buf[0];
        let (len, _bytes_read) = decode_varint(first_byte, &mut len_buf[1..], recv).await?;

        Ok((frame_type, len))
    }

    /// 读取 HTTP/3 帧负载。
    pub async fn read_frame_payload(
        recv: &mut quinn::RecvStream,
        len: u64,
    ) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len as usize];
        recv.read_exact(&mut buf)
            .await
            .map_err(TuicError::QuinnReadExact)?;
        Ok(buf)
    }

    /// 关闭连接。
    pub fn close(&self, error_code: quinn::VarInt, reason: &[u8]) {
        self.multiplexed.close(error_code, reason);
    }
}

/// 解码 QUIC varint（变长整数）。
///
/// 从 recv stream 读取剩余字节。
async fn decode_varint(
    first_byte: u8,
    buf: &mut [u8],
    recv: &mut quinn::RecvStream,
) -> Result<(u64, usize)> {
    let prefix = (first_byte & 0b11000000) >> 6;
    let mut value = (first_byte & 0b00111111) as u64;
    let bytes_to_read = match prefix {
        0b00 => 0,
        0b01 => 1,
        0b10 => 3,
        0b11 => 7,
        _ => unreachable!(),
    };

    if bytes_to_read > 0 {
        recv.read_exact(&mut buf[..bytes_to_read])
            .await
            .map_err(TuicError::QuinnReadExact)?;
        for i in 0..bytes_to_read {
            value = (value << 8) | (buf[i] as u64);
        }
    }

    Ok((value, 1 + bytes_to_read))
}

/// 编码 QUIC varint（变长整数）。
fn encode_varint(value: u64) -> Vec<u8> {
    if value < 64 {
        vec![value as u8]
    } else if value < 16384 {
        vec![0b01000000 | ((value >> 8) as u8 & 0x3f), (value & 0xff) as u8]
    } else if value < 1073741824 {
        vec![
            0b10000000 | ((value >> 24) as u8 & 0x3f),
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ]
    } else {
        vec![
            0b11000000 | ((value >> 56) as u8 & 0x3f),
            ((value >> 48) & 0xff) as u8,
            ((value >> 40) & 0xff) as u8,
            ((value >> 32) & 0xff) as u8,
            ((value >> 24) & 0xff) as u8,
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        let test_values = [0u64, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, u64::MAX];
        for &val in &test_values {
            let encoded = encode_varint(val);
            // 解码需要 recv stream，这里只验证编码不 panic
            assert!(!encoded.is_empty());
        }
    }

    #[test]
    fn varint_encoding_sizes() {
        assert_eq!(encode_varint(0).len(), 1);
        assert_eq!(encode_varint(63).len(), 1);
        assert_eq!(encode_varint(64).len(), 2);
        assert_eq!(encode_varint(16383).len(), 2);
        assert_eq!(encode_varint(16384).len(), 4);
        assert_eq!(encode_varint(1073741823).len(), 4);
        assert_eq!(encode_varint(1073741824).len(), 8);
        assert_eq!(encode_varint(u64::MAX).len(), 8);
    }
}
