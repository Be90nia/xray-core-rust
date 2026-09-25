//! # Minecraft 协议原语（对应 Go `xmc/protocol.go`）
//!
//! 提供 VarInt / String / Bytes / UnsignedShort / Long / UUID 读写函数 + packet IO。
//! 不用 trait 抽象，直接函数对 `io::Read`/`io::Write` 操作。

use std::io::{self, Read, Write};

/// VarInt 上限 5 字节（int32, 7-bit 编码）。
const VARINT_MAX_BYTES: usize = 5;
/// String 长度上限（MC 协议约束）。
const STRING_MAX: i32 = 4096;
/// Bytes 长度上限。
const BYTES_MAX: i32 = 1024;
/// 单包 payload 上限（32 KiB，对应 Go `1024*32`）。
const PACKET_DATA_MAX: i32 = 32 * 1024;

#[inline]
fn read_byte<R: Read>(r: &mut R) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0])
}

/// 读 Minecraft VarInt（带符号 int32，7-bit 编码，最多 5 字节）。
pub fn read_varint<R: Read>(r: &mut R) -> io::Result<i32> {
    const SEGMENT_BITS: u8 = 0x7F;
    const CONTINUE_BIT: u8 = 0x80;

    let mut value: i32 = 0;
    let mut position: i32 = 0;
    for _ in 0..VARINT_MAX_BYTES {
        let b = read_byte(r)?;
        value |= i32::from(b & SEGMENT_BITS) << position;
        if b & CONTINUE_BIT == 0 {
            return Ok(value);
        }
        position += 7;
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "xmc varint too large"))
}

/// 写 Minecraft VarInt。
pub fn write_varint<W: Write>(w: &mut W, mut value: i32) -> io::Result<()> {
    const SEGMENT_BITS: u8 = 0x7F;
    const CONTINUE_BIT: u8 = 0x80;
    loop {
        let mut b = (value & i32::from(SEGMENT_BITS)) as u8;
        value >>= 7;
        if value != 0 {
            b |= CONTINUE_BIT;
        }
        w.write_all(&[b])?;
        if value == 0 {
            return Ok(());
        }
    }
}

/// VarInt 编码后字节数。
pub fn varint_size(mut value: i32) -> usize {
    let mut size = 0;
    loop {
        size += 1;
        value >>= 7;
        if value == 0 {
            return size;
        }
    }
}

/// 读 MC String（VarInt 长度前缀 + UTF-8 字节）。
pub fn read_string<R: Read>(r: &mut R) -> io::Result<String> {
    let len = read_varint(r)?;
    if !(0..=STRING_MAX).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("xmc string bad length: {len}"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// 写 MC String。
pub fn write_string<W: Write>(w: &mut W, s: &str) -> io::Result<()> {
    let bytes = s.as_bytes();
    write_varint(w, bytes.len() as i32)?;
    w.write_all(bytes)
}

/// 读 MC Bytes（VarInt 长度前缀）。
pub fn read_bytes<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let len = read_varint(r)?;
    if !(0..=BYTES_MAX).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("xmc bytes bad length: {len}"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// 写 MC Bytes。
pub fn write_bytes<W: Write>(w: &mut W, b: &[u8]) -> io::Result<()> {
    write_varint(w, b.len() as i32)?;
    w.write_all(b)
}

/// 读 MC UnsignedShort（2 字节大端）。
pub fn read_u16_be<R: Read>(r: &mut R) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

/// 写 MC UnsignedShort。
pub fn write_u16_be<W: Write>(w: &mut W, v: u16) -> io::Result<()> {
    w.write_all(&v.to_be_bytes())
}

/// 读 MC Long（8 字节大端 i64）。
pub fn read_i64_be<R: Read>(r: &mut R) -> io::Result<i64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(i64::from_be_bytes(buf))
}

/// 写 MC Long。
pub fn write_i64_be<W: Write>(w: &mut W, v: i64) -> io::Result<()> {
    w.write_all(&v.to_be_bytes())
}

/// 读 MC UUID（16 字节固定长度）。
pub fn read_uuid<R: Read>(r: &mut R) -> io::Result<[u8; 16]> {
    let mut buf = [0u8; 16];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// 写 MC UUID。
pub fn write_uuid<W: Write>(w: &mut W, u: &[u8; 16]) -> io::Result<()> {
    w.write_all(u)
}

/// 读 MC packet（VarInt 总长 + VarInt ID + payload）。
///
/// 返回 `(packet_id, payload)`，payload 长度已校验 ≤ 32 KiB。
pub fn read_packet<R: Read>(r: &mut R) -> io::Result<(i32, Vec<u8>)> {
    let packet_length = read_varint(r)?;
    let packet_id = read_varint(r)?;
    let id_size = varint_size(packet_id) as i32;
    let data_length = packet_length - id_size;
    if !(0..=PACKET_DATA_MAX).contains(&data_length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("xmc packet bad data length: {data_length}"),
        ));
    }
    let mut data = vec![0u8; data_length as usize];
    r.read_exact(&mut data)?;
    Ok((packet_id, data))
}

/// 写 MC packet（先序列化 fields 到 payload，再写 VarInt 总长 + VarInt ID + payload）。
///
/// `payload` 是已序列化好的字段内容。
pub fn write_packet<W: Write>(w: &mut W, packet_id: i32, payload: &[u8]) -> io::Result<()> {
    let id_size = varint_size(packet_id);
    let total_len = id_size + payload.len();
    write_varint(w, total_len as i32)?;
    write_varint(w, packet_id)?;
    w.write_all(payload)
}

/// 写 Disconnect packet（packet_id=0x00，单 String 字段）。
pub fn write_disconnect<W: Write>(w: &mut W, reason: &str) -> io::Result<()> {
    let mut payload = Vec::with_capacity(reason.len() + 5);
    write_string(&mut payload, reason)?;
    write_packet(w, 0x00, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0i32, 1, 127, 128, 255, 16384, 2147483647] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v).unwrap();
            let mut reader = &buf[..];
            let got = read_varint(&mut reader).unwrap();
            assert_eq!(got, v, "varint roundtrip {v}");
        }
    }

    #[test]
    fn varint_size_matches_encoding() {
        for v in [0i32, 1, 127, 128, 16384, 2097151, 268435455] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v).unwrap();
            assert_eq!(buf.len(), varint_size(v));
        }
    }

    #[test]
    fn string_roundtrip() {
        let mut buf = Vec::new();
        write_string(&mut buf, "hello, 世界").unwrap();
        let mut reader = &buf[..];
        let got = read_string(&mut reader).unwrap();
        assert_eq!(got, "hello, 世界");
    }

    #[test]
    fn packet_roundtrip() {
        let mut buf = Vec::new();
        let payload = b"\x2a\xfe\xed";
        write_packet(&mut buf, 0x42, payload).unwrap();
        let mut reader = &buf[..];
        let (id, data) = read_packet(&mut reader).unwrap();
        assert_eq!(id, 0x42);
        assert_eq!(data, payload);
    }

    #[test]
    fn too_long_string_rejected() {
        // 长度声明 5000（> 4096）
        let mut buf = Vec::new();
        write_varint(&mut buf, 5000).unwrap();
        buf.extend_from_slice(&[0u8; 10]);
        let mut reader = &buf[..];
        let err = read_string(&mut reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn u16_be_roundtrip() {
        let mut buf = Vec::new();
        write_u16_be(&mut buf, 0x1234).unwrap();
        let mut reader = &buf[..];
        assert_eq!(read_u16_be(&mut reader).unwrap(), 0x1234);
        assert_eq!(buf, vec![0x12, 0x34]);
    }

    #[test]
    fn i64_be_roundtrip() {
        let v = 0x0123_4567_89ab_cdefi64;
        let mut buf = Vec::new();
        write_i64_be(&mut buf, v).unwrap();
        let mut reader = &buf[..];
        assert_eq!(read_i64_be(&mut reader).unwrap(), v);
    }
}
