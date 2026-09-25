//! 序列化类型工具
//!
//! 对应 Go 版本 `common/serial` 包，提供 TypedMessage 类型和 uint16/64 读写工具。

/// 带类型 URL 的消息，用于多态消息传递。
///
/// 对应 Go 版本 `common/serial.TypedMessage`，类似 protobuf Any 的包装器。
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TypedMessage {
    /// 类型标识 URL
    pub type_url: String,
    /// 消息体字节
    pub value: Vec<u8>,
}

impl TypedMessage {
    /// 创建新的 TypedMessage。
    pub fn new(type_url: impl Into<String>, value: Vec<u8>) -> Self {
        Self { type_url: type_url.into(), value }
    }

    /// 返回类型 URL。
    pub fn type_url(&self) -> &str {
        &self.type_url
    }

    /// 返回消息体字节切片。
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// 从字节切片读取大端序 uint16。
///
/// 数据不足 2 字节时返回 None。
pub fn read_uint16(data: &[u8]) -> Option<u16> {
    if data.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([data[0], data[1]]))
}

/// 将 uint16 写入大端序字节数组。
pub fn write_uint16(value: u16) -> [u8; 2] {
    value.to_be_bytes()
}

/// 从字节切片读取大端序 uint64。
///
/// 数据不足 8 字节时返回 None。
pub fn read_uint64(data: &[u8]) -> Option<u64> {
    if data.len() < 8 {
        return None;
    }
    let bytes: [u8; 8] = data[..8].try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// 将 uint64 写入大端序字节数组。
pub fn write_uint64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_typed_message_new() {
        let msg = TypedMessage::new("type.googleapis.com/xray.Test", vec![1, 2, 3]);
        assert_eq!(msg.type_url(), "type.googleapis.com/xray.Test");
        assert_eq!(msg.value(), &[1, 2, 3]);
    }

    #[test]
    fn test_typed_message_clone_eq() {
        let msg = TypedMessage::new("test", vec![4, 5]);
        let cloned = msg.clone();
        assert_eq!(msg, cloned);
    }

    #[test]
    fn test_read_write_uint16_roundtrip() {
        let values = [0, 1, 255, 256, 65535, 12345];
        for &v in &values {
            let bytes = write_uint16(v);
            assert_eq!(read_uint16(&bytes), Some(v));
        }
    }

    #[test]
    fn test_read_uint16_big_endian() {
        // 0x0102 = 258
        assert_eq!(read_uint16(&[0x01, 0x02]), Some(258));
    }

    #[test]
    fn test_read_uint16_insufficient_data() {
        assert_eq!(read_uint16(&[0x01]), None);
        assert_eq!(read_uint16(&[]), None);
    }

    #[test]
    fn test_read_write_uint64_roundtrip() {
        let values = [0, 1, 255, 65536, u64::MAX, 123456789012345];
        for &v in &values {
            let bytes = write_uint64(v);
            assert_eq!(read_uint64(&bytes), Some(v));
        }
    }

    #[test]
    fn test_read_uint64_big_endian() {
        // 0x0102030405060708 = 72623859790382856
        assert_eq!(
            read_uint64(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            Some(0x0102_0304_0506_0708)
        );
    }

    #[test]
    fn test_read_uint64_insufficient_data() {
        assert_eq!(read_uint64(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]), None);
        assert_eq!(read_uint64(&[]), None);
    }
}
