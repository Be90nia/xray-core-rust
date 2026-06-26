//! 加密层共享常量与纯算法（无 IO 依赖）。
//!
//! 对应 Go 版本 `encryption/common.go` 中可独立测试的部分：
//! - TLS 1.3 record header 伪装常量（5B header `[23,3,3,len_hi,len_lo]`）
//! - AEAD Nonce 自增与 `MaxNonce` 上限
//! - 长度字段（2B BE）编解码
//!
//! 这些算法不涉及密钥派生、AEAD、TLS 状态机，所以可以独立单元测试。

/// TLS 1.3 Application Data record type byte (0x17 = 23)。
pub const TLS_RECORD_TYPE_APP_DATA: u8 = 23;

/// TLS 1.3 legacy_version 高字节 (0x03)。
pub const TLS_LEGACY_VERSION_HIGH: u8 = 3;

/// TLS 1.3 legacy_version 低字节 (0x03)。
pub const TLS_LEGACY_VERSION_LOW: u8 = 3;

/// TLS record header 总长度（5 字节：type + version_hi + version_lo + len_hi + len_lo）。
pub const TLS_RECORD_HEADER_LEN: usize = 5;

/// AEAD Nonce 达到此值后必须重新派生密钥（防 nonce 复用）。
///
/// 对应 Go 端 `MaxNonce = math.MaxUint64`。本实现使用 u64 上限。
pub const MAX_NONCE: u64 = u64::MAX;

/// AEAD Nonce 字节长度（标准 12 字节，AES-GCM/ChaCha20-Poly1305 都用）。
pub const NONCE_LEN: usize = 12;

/// 把 5 字节 TLS 1.3 record header 写入 `out`。
///
/// - `payload_len`：实际加密载荷长度（不含 header 本身）。
///
/// 对应 Go 端构造 `[23,3,3,len_hi,len_lo]` 的逻辑。
///
/// # Panics
/// 如果 `out.len() < 5` 会 panic（debug 断言）。
pub fn write_tls_record_header(out: &mut [u8], payload_len: u16) {
    assert!(out.len() >= TLS_RECORD_HEADER_LEN, "tls header buffer too short");
    out[0] = TLS_RECORD_TYPE_APP_DATA;
    out[1] = TLS_LEGACY_VERSION_HIGH;
    out[2] = TLS_LEGACY_VERSION_LOW;
    let bytes = payload_len.to_be_bytes();
    out[3] = bytes[0];
    out[4] = bytes[1];
}

/// 把 12 字节 Nonce 视为 BE u64 计数器（高 8 字节）+ 固定（低 4 字节），
/// 自增 1。溢出（达到 `MAX_NONCE`）返回 false，调用方应触发密钥轮换。
///
/// 对应 Go 端 `IncreaseNonce(nonce *[12]byte)`。
///
/// # Returns
/// - `true`：自增成功。
/// - `false`：已达到 `MAX_NONCE`，调用方必须重新派生密钥。
pub fn increase_nonce(nonce: &mut [u8; NONCE_LEN]) -> bool {
    // 把前 8 字节作为 BE u64 计数器
    let mut counter = u64::from_be_bytes([
        nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7],
    ]);
    if counter == MAX_NONCE {
        return false;
    }
    counter += 1;
    nonce[0..8].copy_from_slice(&counter.to_be_bytes());
    let _ = &mut nonce[8..]; // 低 4 字节保持不变
    true
}

/// 把 2B BE 长度编码到 `out`（用于加密包长度前缀）。
pub fn encode_length_be(out: &mut Vec<u8>, len: u16) {
    out.extend_from_slice(&len.to_be_bytes());
}

/// 从 `bytes` 解码 2B BE 长度，返回 (剩余字节, 长度)。
///
/// # Errors
/// 字节不足 2 字节时返回 [`crate::VlessError::Other`]。
pub fn decode_length_be(bytes: &[u8]) -> crate::error::Result<(&[u8], u16)> {
    if bytes.len() < 2 {
        return Err(crate::VlessError::Other(
            "decode_length_be: buffer too short".into(),
        ));
    }
    let len = u16::from_be_bytes([bytes[0], bytes[1]]);
    Ok((&bytes[2..], len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_record_header_layout() {
        let mut buf = [0u8; 5];
        write_tls_record_header(&mut buf, 0x1234);
        assert_eq!(buf, [23, 3, 3, 0x12, 0x34]);
    }

    #[test]
    fn tls_record_header_max_len() {
        let mut buf = [0u8; 5];
        write_tls_record_header(&mut buf, u16::MAX);
        assert_eq!(buf, [23, 3, 3, 0xFF, 0xFF]);
    }

    #[test]
    fn increase_nonce_increments_high_8_bytes() {
        let mut nonce = [0u8; NONCE_LEN];
        assert!(increase_nonce(&mut nonce));
        assert_eq!(&nonce[0..8], &[0, 0, 0, 0, 0, 0, 0, 1]);
        // 低 4 字节不变
        assert_eq!(&nonce[8..12], &[0, 0, 0, 0]);
    }

    #[test]
    fn increase_nonce_max_returns_false() {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[0..8].copy_from_slice(&MAX_NONCE.to_be_bytes());
        assert!(!increase_nonce(&mut nonce));
    }

    #[test]
    fn increase_nonce_multiple_times() {
        let mut nonce = [0u8; NONCE_LEN];
        for _ in 0..1000 {
            assert!(increase_nonce(&mut nonce));
        }
        let counter = u64::from_be_bytes([
            nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7],
        ]);
        assert_eq!(counter, 1000);
    }

    #[test]
    fn encode_decode_length_be_round_trip() {
        let mut buf = Vec::new();
        encode_length_be(&mut buf, 0xABCD);
        assert_eq!(buf, vec![0xAB, 0xCD]);

        let (rest, len) = decode_length_be(&buf).unwrap();
        assert_eq!(len, 0xABCD);
        assert!(rest.is_empty());
    }

    #[test]
    fn decode_length_be_too_short_rejected() {
        let one_byte = [0u8; 1];
        let err = decode_length_be(&one_byte).unwrap_err();
        match err {
            crate::VlessError::Other(msg) => assert!(msg.contains("too short")),
            _ => panic!("unexpected error: {err:?}"),
        }
    }
}
