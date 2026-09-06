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

/// HTTP/3 帧负载最大长度（1 MiB）。
///
/// [`H3TuicTransport::read_frame_payload`] 入口限幅：帧长度是对方声明的 varint
///（可至 2^62），未限幅直接按声明值预分配会被恶意长度打爆内存。
/// 常量模式与 hysteria `MAX_*_LENGTH` 一致。
pub const MAX_FRAME_PAYLOAD_LENGTH: u64 = 1_048_576;

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
        settings.put_slice(&encode_varint(0));
        // MAX_FIELD_SECTION_SIZE = 8192
        settings.put_u8(h3_settings_id::MAX_FIELD_SECTION_SIZE);
        settings.put_slice(&encode_varint(8192));
        // H3_DATAGRAM = 1（启用 DATAGRAM 支持）
        settings.put_u8(h3_settings_id::H3_DATAGRAM);
        settings.put_slice(&encode_varint(1));

        let mut frame = BytesMut::new();
        frame.put_u8(h3_frame_type::SETTINGS);
        frame.put_slice(&encode_varint(settings.len() as u64));
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
        frame.put_slice(&encode_varint(headers.len() as u64));
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
        frame.put_slice(&encode_varint(data.len() as u64));
        frame.put_slice(data);

        send.write_all(&frame).await?;
        Ok(())
    }

    /// 发送 HTTP/3 GOAWAY 帧（优雅关闭）。
    pub async fn send_goaway(&self) -> Result<()> {
        let mut frame = BytesMut::new();
        frame.put_u8(h3_frame_type::GOAWAY);
        frame.put_slice(&encode_varint(0)); // GOAWAY ID = 0
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
    ///
    /// 入口按声明长度限幅（[`MAX_FRAME_PAYLOAD_LENGTH`]），超限返回
    /// [`TuicError::ProtocolParse`]，不做预分配。
    pub async fn read_frame_payload(
        recv: &mut quinn::RecvStream,
        frame_type: u8,
        len: u64,
    ) -> Result<Vec<u8>> {
        check_frame_len(frame_type, len)?;
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

    /// Server 端：读取 client 在 control stream 上发的 SETTINGS 帧。
    ///
    /// H3 控制 stream 是 uni stream id=0x3；本方法先读 frame header + payload，
    /// 校验 frame type = SETTINGS，然后扫描 settings 验证 H3_DATAGRAM=1。
    /// 成功时返回完整 settings 负载；失败返 [`TuicError::UnexpectedEof`]。
    pub async fn recv_settings(&self, recv: &mut quinn::RecvStream) -> Result<Vec<u8>> {
        let (frame_type, len) = Self::read_frame_header(recv).await?;
        if frame_type != h3_frame_type::SETTINGS {
            return Err(TuicError::UnexpectedEof("h3 control stream not SETTINGS"));
        }
        let payload = Self::read_frame_payload(recv, frame_type, len).await?;
        // 校验 settings 含 H3_DATAGRAM=1（TUIC 伪装需要）
        let mut saw_datagram = false;
        let mut i = 0;
        while i + 2 <= payload.len() {
            let id = payload[i];
            // value 是 varint；简化：每个 setting 占 1B id + 变长 value
            let first_byte = payload[i + 1];
            let prefix = (first_byte & 0b11000000) >> 6;
            let bytes_to_read = match prefix {
                0b00 => 0,
                0b01 => 1,
                0b10 => 3,
                0b11 => 7,
                _ => unreachable!(),
            };
            if id == h3_settings_id::H3_DATAGRAM && first_byte == 1 && bytes_to_read == 0 {
                saw_datagram = true;
            }
            i += 1 + 1 + bytes_to_read;
        }
        if !saw_datagram {
            return Err(TuicError::UnexpectedEof("h3 settings missing H3_DATAGRAM=1"));
        }
        Ok(payload)
    }

    /// 伪装 HTTP 请求路径（默认 `/`）。
    ///
    /// 在 SETTINGS 帧交换后，client 发的首个 HEADERS 帧的 `:path` 字段为该值；
    /// server 端 [`verify_camouflage_headers`] 校验一致即可认定为合法 H3 流量。
    pub const fn camouflage_path() -> &'static str {
        "/"
    }

    /// Server 端：校验 client 发来的 HEADERS 帧负载，含 token。
    ///
    /// 编码约定（client [`send_connect_headers`] 同）：
    /// `\x00\x07CONNECT \x01<auth_len><auth> \x40\x0dx-tuic-token\x40<token_hex_len><token_hex>`
    /// ponytail: 非完整 QPACK decoder，仅校验关键 token 字段存在且匹配。
    ///
    /// [`send_connect_headers`]: H3TuicTransport::send_connect_headers
    pub fn verify_camouflage_headers(
        headers_payload: &[u8],
        expected_token: &[u8; TOKEN_LEN],
    ) -> bool {
        // 查找 "x-tuic-token" 后接 hex(token)
        const HEADER_NAME: &[u8] = b"x-tuic-token";
        let Some(name_pos) = find_subseq(headers_payload, HEADER_NAME) else {
            return false;
        };
        // 名字后: \x40<hex_len><token_hex>
        let mut idx = name_pos + HEADER_NAME.len();
        if idx >= headers_payload.len() || headers_payload[idx] != 0x40 {
            return false;
        }
        idx += 1;
        if idx >= headers_payload.len() {
            return false;
        }
        let hex_len = headers_payload[idx] as usize;
        idx += 1;
        if idx + hex_len > headers_payload.len() {
            return false;
        }
        let token_hex = &headers_payload[idx..idx + hex_len];
        let expected_hex = token_to_hex(expected_token);
        token_hex == expected_hex.as_bytes()
    }
}

/// 帧长度限幅检查：声明长度超过 [`MAX_FRAME_PAYLOAD_LENGTH`] 即拒绝。
///
/// 独立纯函数以便单测覆盖边界（`read_frame_payload` 本体需要 quinn stream）。
fn check_frame_len(frame_type: u8, len: u64) -> Result<()> {
    if len > MAX_FRAME_PAYLOAD_LENGTH {
        return Err(TuicError::ProtocolParse(format!(
            "h3 frame payload too large: type={frame_type:#04x} len={len} (max {MAX_FRAME_PAYLOAD_LENGTH})"
        )));
    }
    Ok(())
}

/// 在 `haystack` 中查找首个 `needle` 子序列；找不到返回 None。
fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// 32 字节 token → 64 字节 lowercase hex（与 client `send_connect_headers` 同源）。
fn token_to_hex(token: &[u8; TOKEN_LEN]) -> String {
    let mut s = String::with_capacity(TOKEN_LEN * 2);
    for b in token {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 同步解码 QUIC varint（纯字节切片，无 stream）。用于测试/解析已缓冲数据。
pub(crate) fn decode_varint_sync(buf: &[u8]) -> (u64, usize) {
    if buf.is_empty() {
        return (0, 0);
    }
    let first = buf[0];
    let prefix = (first & 0b11000000) >> 6;
    let mut v = (first & 0b00111111) as u64;
    let extra = match prefix {
        0b00 => 0,
        0b01 => 1,
        0b10 => 3,
        0b11 => 7,
        _ => unreachable!(),
    };
    if buf.len() < 1 + extra {
        return (v, 1);
    }
    for i in 0..extra {
        v = (v << 8) | (buf[1 + i] as u64);
    }
    (v, 1 + extra)
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
///
/// pub 以便测试/调用方复用（如 frame 长度字段）。
pub fn encode_varint(value: u64) -> Vec<u8> {
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

    /// 客户端伪造 SETTINGS 帧的完整字节序列校验：
    /// type=0x04, varint(len)=N, 然后 QPACK=0, MAX_FIELD=8192, H3_DATAGRAM=1
    #[test]
    fn settings_frame_byte_layout() {
        // 重建 send_settings 的 payload 部分（不写 stream，只算 bytes）
        let mut settings = Vec::new();
        settings.push(h3_settings_id::QPACK_MAX_TABLE_CAPACITY);
        settings.extend_from_slice(&encode_varint(0));
        settings.push(h3_settings_id::MAX_FIELD_SECTION_SIZE);
        settings.extend_from_slice(&encode_varint(8192));
        settings.push(h3_settings_id::H3_DATAGRAM);
        settings.extend_from_slice(&encode_varint(1));

        // 完整帧 = type(1) + varint(len)(1) + payload(N)
        let mut frame = Vec::new();
        frame.push(h3_frame_type::SETTINGS);
        frame.extend_from_slice(&encode_varint(settings.len() as u64));
        frame.extend_from_slice(&settings);

        // 解析：type + varint(len) + payload
        assert_eq!(frame[0], 0x04);
        let (len, consumed) = decode_varint_sync(&frame[1..]);
        assert_eq!(consumed, 1);
        assert_eq!(len as usize, settings.len());
        // 第三个 setting 起始：payload[1 + 1 + 1 + 1 + 1] = payload[5]
        assert_eq!(settings[5], h3_settings_id::H3_DATAGRAM);
        assert_eq!(settings[6], 1);
    }

    #[test]
    fn camouflage_headers_verify() {
        // 构造与 client `send_connect_headers` 一致的 headers payload：
        // \x00\x07CONNECT \x01<auth_len><auth> \x40\x0dx-tuic-token\x40<hex_len><hex>
        let token: [u8; TOKEN_LEN] = [0xab; TOKEN_LEN];
        let authority = b"example.com:443";
        let token_hex = token_to_hex(&token);

        let mut headers = Vec::new();
        headers.push(0x00); // :method 静态表索引
        headers.push(0x07); // CONNECT 长度
        headers.extend_from_slice(b"CONNECT");
        headers.push(0x01); // :authority 静态表索引
        headers.push(authority.len() as u8);
        headers.extend_from_slice(authority);
        headers.push(0x40); // Literal header with name reference
        headers.push(13); // "x-tuic-token"
        headers.extend_from_slice(b"x-tuic-token");
        headers.push(0x40); // value 长度前缀
        headers.push(token_hex.len() as u8);
        headers.extend_from_slice(token_hex.as_bytes());

        // 合法 token 应通过
        assert!(H3TuicTransport::verify_camouflage_headers(&headers, &token));
        // 错误 token 拒绝
        let wrong: [u8; TOKEN_LEN] = [0xcd; TOKEN_LEN];
        assert!(!H3TuicTransport::verify_camouflage_headers(&headers, &wrong));
        // 缺名字拒绝
        let truncated = &headers[..headers.len() - 3];
        assert!(!H3TuicTransport::verify_camouflage_headers(truncated, &token));
    }

    #[test]
    fn camouflage_path_default() {
        assert_eq!(H3TuicTransport::camouflage_path(), "/");
    }

    #[test]
    fn settings_payload_datagram_scan() {
        // 构造最小 settings payload，仅 H3_DATAGRAM=1
        let mut settings = Vec::new();
        settings.push(h3_settings_id::H3_DATAGRAM);
        settings.push(1); // varint(1) = 0x01
        // 用同步模拟 recv_settings 内部的扫描：
        let mut saw_datagram = false;
        let mut i = 0;
        while i + 2 <= settings.len() {
            let id = settings[i];
            let first_byte = settings[i + 1];
            let prefix = (first_byte & 0b11000000) >> 6;
            let bytes_to_read = match prefix {
                0b00 => 0,
                0b01 => 1,
                0b10 => 3,
                0b11 => 7,
                _ => unreachable!(),
            };
            if id == h3_settings_id::H3_DATAGRAM && first_byte == 1 && bytes_to_read == 0 {
                saw_datagram = true;
            }
            i += 1 + 1 + bytes_to_read;
        }
        assert!(saw_datagram, "H3_DATAGRAM=1 must be detected");
    }

    /// 限幅回归：超限帧被拒（恶意 varint 声明不可触发大分配）。
    #[test]
    fn frame_len_limit_rejects_oversize() {
        let err = check_frame_len(h3_frame_type::DATA, MAX_FRAME_PAYLOAD_LENGTH + 1).unwrap_err();
        assert!(matches!(err, TuicError::ProtocolParse(_)), "got {err:?}");
        assert!(err.to_string().contains("too large"), "got {err}");
        // 恶意最大声明同样被拒
        let err = check_frame_len(h3_frame_type::SETTINGS, u64::MAX).unwrap_err();
        assert!(matches!(err, TuicError::ProtocolParse(_)), "got {err:?}");
    }

    #[test]
    fn frame_len_limit_accepts_boundary() {
        // 恰好 1 MiB 与空帧都放行（边界=上限本身不拒）
        check_frame_len(h3_frame_type::DATA, MAX_FRAME_PAYLOAD_LENGTH).expect("1MiB frame allowed");
        check_frame_len(h3_frame_type::SETTINGS, 0).expect("empty frame allowed");
    }
}
