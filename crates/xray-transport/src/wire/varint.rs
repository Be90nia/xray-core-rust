//! RFC 9000 §16 QUIC varint 编解码。
//!
//! **udf-promotion-candidate**（规划 §4.1 / §5 B1.5）：本件零 xray 语义（纯 RFC 9000
//! varint），终态应上浮 udf（`std_ext::wire` 族）；本票不动 udf 仓，暂驻
//! `xray-transport::wire`，由 `xray-proxy-hysteria`（hysteria 协议帧）与
//! `xray-transport-masque`（CONNECT-IP 胶囊）两处消费。
//!
//! 移动来源：`xray-proxy-hysteria/src/protocol.rs`（B1.5 纯移动，函数体字节不变；
//! hysteria 侧 `pub use` 保持 `crate::protocol::read_varint` 等路径不变）。

use std::io::{self, Read};

/// 读取 QUIC varint（对应 Go `quicvarint.Read`）。
///
/// 从 reader 逐字节读取，解析 1/2/4/8 字节 varint。
pub fn read_varint<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut first = [0u8; 1];
    r.read_exact(&mut first)?;
    let prefix = first[0] >> 6;
    match prefix {
        0 => Ok(u64::from(first[0])),
        _ => {
            let mask: u8 = 0x3F;
            let len = 1usize << prefix;
            let mut buf = vec![0u8; len - 1];
            r.read_exact(&mut buf)?;
            let mut val = u64::from(first[0] & mask);
            for &b in &buf {
                val = (val << 8) | u64::from(b);
            }
            Ok(val)
        },
    }
}

/// 写入 QUIC varint 到 buf（对应 Go `varintPut`）。
///
/// 返回写入字节数。
pub fn write_varint(buf: &mut [u8], v: u64) -> usize {
    if v < (1 << 6) {
        buf[0] = v as u8;
        1
    } else if v < (1 << 14) {
        buf[0] = (v >> 8) as u8 | 0x40;
        buf[1] = v as u8;
        2
    } else if v < (1 << 30) {
        buf[0] = (v >> 24) as u8 | 0x80;
        buf[1] = (v >> 16) as u8;
        buf[2] = (v >> 8) as u8;
        buf[3] = v as u8;
        4
    } else {
        buf[0] = (v >> 56) as u8 | 0xC0;
        buf[1] = (v >> 48) as u8;
        buf[2] = (v >> 40) as u8;
        buf[3] = (v >> 32) as u8;
        buf[4] = (v >> 24) as u8;
        buf[5] = (v >> 16) as u8;
        buf[6] = (v >> 8) as u8;
        buf[7] = v as u8;
        8
    }
}

/// 计算 varint 编码后字节数。
#[must_use]
pub fn varint_len(v: u64) -> usize {
    if v < (1 << 6) {
        1
    } else if v < (1 << 14) {
        2
    } else if v < (1 << 30) {
        4
    } else {
        8
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    // 移动自 xray-proxy-hysteria/src/protocol.rs（B1.5 纯移动，断言不变）。

    #[test]
    fn varint_roundtrip() {
        let cases = [0u64, 63, 64, 16383, 16384, 1_073_741_823, 0x401];
        for &v in &cases {
            let mut buf = vec![0u8; 8];
            let n = write_varint(&mut buf, v);
            let mut cursor = Cursor::new(&buf[..n]);
            let decoded = read_varint(&mut cursor).expect("varint decode should succeed");
            assert_eq!(decoded, v, "varint roundtrip failed for {v}");
        }
    }

    #[test]
    fn varint_len_matches_write() {
        let cases = [0u64, 63, 64, 16383, 16384];
        for &v in &cases {
            let mut buf = vec![0u8; 8];
            let n = write_varint(&mut buf, v);
            assert_eq!(varint_len(v), n, "varint_len mismatch for {v}");
        }
    }
}
