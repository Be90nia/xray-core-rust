//! naive padding 协议（naiveproxy `NaivePaddingFramer`/`NaivePaddingSocket` 移植）。
//!
//! 帧格式（kVariant1，`naive_protocol.h`）：
//!
//! ```text
//! [payload_size_hi: u8][payload_size_lo: u8][padding_size: u8]
//! [payload: payload_size][zeros: padding_size]
//! ```
//!
//! 双向首 8 帧（`kFirstPaddings`）应用 padding，之后直通。
//! 请求头 `padding: <16-32 字节 non-index 字符>` 协商能力；响应含
//! `padding` 头则双向启用帧化，否则完全直通（kNone）。

use rand::Rng;

/// HPACK Huffman 表中前 17 个长度 ≥8 bit 的可打印符号
/// （naiveproxy `g_nonindex_codes`：前 16 个按 4 bit 随机选取，第 17 个作填充）。
const NONINDEX_CODES: &[u8; 17] = b"!\"#$&'()*+,;<>?@X";

/// 双向应用 padding 帧化的帧数（naiveproxy `kFirstPaddings`）。
pub const FIRST_PADDINGS: u32 = 8;

/// 单帧缓冲上限（对齐 naiveproxy `kMaxBufferSize` = 64 KiB）。
const MAX_BUFFER_SIZE: usize = 64 * 1024;

/// 生成 padding 头值（naiveproxy `FillNonindexHeaderValue`）。
///
/// 前 `min(len, 16)` 字节按 seed 每 4 bit 取一个符号，其余填第 17 个符号。
/// 这些符号的 Huffman 编码 ≥8 bit，HPACK 不会压缩/索引，对齐真实流量。
#[must_use]
pub fn padding_header(len: usize, seed: u64) -> String {
    let mut bits = seed;
    let mut out = String::with_capacity(len);
    let first = len.min(16);
    for _ in 0..first {
        out.push(NONINDEX_CODES[(bits & 0b1111) as usize] as char);
        bits >>= 4;
    }
    for _ in first..len {
        out.push(NONINDEX_CODES[16] as char);
    }
    out
}

/// 随机 padding 请求头（naiveproxy 发送 16-32 字节，不依赖服务端支持）。
#[must_use]
pub fn random_padding_header() -> String {
    let len = rand::rng().random_range(16..=32usize);
    padding_header(len, rand::rng().random())
}

/// 客户端→服务端方向的帧 padding 长度（naiveproxy `WritePaddingV1` kServer 分支：
/// 小包补满到 255 隐藏真实长度，大包均匀随机）。
#[must_use]
pub fn random_padding_size(payload_len: usize) -> usize {
    if payload_len < 100 {
        rand::rng().random_range((u8::MAX as usize - payload_len)..=u8::MAX as usize)
    } else {
        rand::rng().random_range(0..=u8::MAX as usize)
    }
}

/// 编码一帧。返回 `(帧字节, 消费的 payload 字节数)`。
///
/// payload 超出 [`MAX_BUFFER_SIZE`] 预算时截断（naiveproxy `NaivePaddingFramer::Write`
/// 同语义：截断量作为本次写入的用户字节数，余量留给下一次调用）。
#[must_use]
pub fn encode_frame(payload: &[u8], padding_size: usize) -> (Vec<u8>, usize) {
    debug_assert!(padding_size <= u8::MAX as usize);
    let consumed = payload.len().min(MAX_BUFFER_SIZE - 3 - padding_size);
    let mut out = Vec::with_capacity(3 + consumed + padding_size);
    out.push((consumed / 256) as u8);
    out.push((consumed % 256) as u8);
    out.push(padding_size as u8);
    out.extend_from_slice(&payload[..consumed]);
    out.resize(3 + consumed + padding_size, 0);
    (out, consumed)
}

/// 帧解码状态机（naiveproxy `NaivePaddingFramer::Read` 移植）。
#[derive(Debug, Default)]
pub struct PaddingDecoder {
    state: ReadState,
    payload_remaining: usize,
    padding_remaining: usize,
    frames_read: u32,
}

#[derive(Debug, Default)]
enum ReadState {
    #[default]
    Len1,
    Len2,
    Pad1,
    Payload,
    Padding,
}

impl PaddingDecoder {
    /// 解码 `buf` 前缀中的完整帧，payload 追加到 `out`，消费的字节从 `buf` 移除。
    ///
    /// 返回 `true` 表示已解满 [`FIRST_PADDINGS`] 帧——此后 `buf` 中剩余字节为
    /// 直通数据（不再帧化），调用方应切换透传模式。
    pub fn decode(&mut self, buf: &mut Vec<u8>, out: &mut Vec<u8>) -> bool {
        let mut pos = 0;
        while pos < buf.len() {
            match self.state {
                ReadState::Len1 => {
                    self.payload_remaining = usize::from(buf[pos]);
                    pos += 1;
                    self.state = ReadState::Len2;
                }
                ReadState::Len2 => {
                    self.payload_remaining = self.payload_remaining * 256 + usize::from(buf[pos]);
                    pos += 1;
                    self.state = ReadState::Pad1;
                }
                ReadState::Pad1 => {
                    self.padding_remaining = usize::from(buf[pos]);
                    pos += 1;
                    self.state = ReadState::Payload;
                }
                ReadState::Payload => {
                    let take = self.payload_remaining.min(buf.len() - pos);
                    out.extend_from_slice(&buf[pos..pos + take]);
                    pos += take;
                    self.payload_remaining -= take;
                    if self.payload_remaining == 0 {
                        self.state = ReadState::Padding;
                    }
                }
                ReadState::Padding => {
                    let take = self.padding_remaining.min(buf.len() - pos);
                    pos += take;
                    self.padding_remaining -= take;
                    if self.padding_remaining == 0 {
                        self.frames_read += 1;
                        self.state = ReadState::Len1;
                        if self.frames_read >= FIRST_PADDINGS {
                            break;
                        }
                    }
                }
            }
        }
        buf.drain(..pos);
        self.frames_read >= FIRST_PADDINGS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_header_charset_and_layout() {
        // naiveproxy g_nonindex_codes：前 16 随机符号 + 'X' 填充
        assert_eq!(
            std::str::from_utf8(&NONINDEX_CODES[..16]).unwrap(),
            r##"!"#$&'()*+,;<>?@"##
        );
        // seed 0x0003_0201 逐 nibble（LSB 先）：1,0,2,0 → codes[1],[0],[2],[0]
        assert_eq!(padding_header(4, 0x0003_0201), "\"!#!");
        // seed = 1：首字节 codes[1]，其余 codes[0]；第 17 字节起填 'X'
        assert_eq!(padding_header(20, 1), format!("\"{}", "!".repeat(15)) + &"X".repeat(4));
        // seed = u64::MAX：前 16 字节 codes[15]='@'
        assert_eq!(padding_header(16, u64::MAX), "@".repeat(16));
    }

    #[test]
    fn encode_frame_layout() {
        let (frame, consumed) = encode_frame(b"hello", 2);
        assert_eq!(consumed, 5);
        assert_eq!(frame, vec![0, 5, 2, b'h', b'e', b'l', b'l', b'o', 0, 0]);
        // 大于 256 的 payload：长度字段两字节 BE
        let payload = vec![7u8; 300];
        let (frame, consumed) = encode_frame(&payload, 0);
        assert_eq!(consumed, 300);
        assert_eq!(&frame[..3], &[1, 44, 0]);
        assert_eq!(frame.len(), 303);
    }

    #[test]
    fn decode_roundtrip_multi_frames() {
        let mut decoder = PaddingDecoder::default();
        let mut wire = Vec::new();
        let mut expected = Vec::new();
        for i in 0..3u16 {
            let payload = vec![b'a' + i as u8; 100 + i as usize];
            let (frame, _) = encode_frame(&payload, (i as usize) * 7);
            wire.extend_from_slice(&frame);
            expected.extend_from_slice(&payload);
        }
        let mut buf = wire;
        let mut out = Vec::new();
        assert!(!decoder.decode(&mut buf, &mut out));
        assert_eq!(out, expected);
        assert!(buf.is_empty());
        assert_eq!(decoder.frames_read, 3);
    }

    #[test]
    fn decode_byte_by_byte() {
        let mut decoder = PaddingDecoder::default();
        let mut wire = Vec::new();
        let (f1, _) = encode_frame(b"AB", 1);
        let (f2, _) = encode_frame(b"CDE", 0);
        wire.extend_from_slice(&f1);
        wire.extend_from_slice(&f2);
        let mut out = Vec::new();
        for b in wire {
            let mut buf = vec![b];
            decoder.decode(&mut buf, &mut out);
        }
        assert_eq!(out, b"ABCDE");
    }

    #[test]
    fn pure_padding_frame_counts_but_yields_nothing() {
        let mut decoder = PaddingDecoder::default();
        let (frame, _) = encode_frame(b"", 5);
        assert_eq!(frame.len(), 8);
        let mut buf = frame;
        let mut out = Vec::new();
        assert!(!decoder.decode(&mut buf, &mut out));
        assert!(out.is_empty());
        assert!(buf.is_empty());
        assert_eq!(decoder.frames_read, 1);
    }

    #[test]
    fn decode_switches_to_passthrough_after_eight_frames() {
        let mut decoder = PaddingDecoder::default();
        let mut buf = Vec::new();
        for _ in 0..8 {
            let (frame, _) = encode_frame(b"x", 3);
            buf.extend_from_slice(&frame);
        }
        buf.extend_from_slice(b"RAW-TAIL");
        let mut out = Vec::new();
        assert!(decoder.decode(&mut buf, &mut out));
        assert_eq!(out, vec![b'x'; 8]);
        // 第 8 帧之后的字节原样保留
        assert_eq!(buf, b"RAW-TAIL");
    }

    #[test]
    fn random_padding_size_bounds() {
        for _ in 0..100 {
            let small = random_padding_size(50);
            assert!((205..=255).contains(&small), "small payload padding {small}");
            let large = random_padding_size(500);
            assert!(large <= 255);
        }
    }
}
