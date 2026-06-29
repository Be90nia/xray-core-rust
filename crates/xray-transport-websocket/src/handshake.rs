//! WebSocket 握手辅助 + 协议常量。
//!
//! 对应 RFC 6455 与 Go `gorilla/websocket` 握手部分。Xray 自身不做帧编解码
//! （由 `gorilla/websocket` 处理），所以 Rust 切片1 只覆盖握手 key 计算与
//! 协议常量；实际帧编解码与 IO 在切片2 由 `tokio-tungstenite` 接入。
//!
//! ## Sec-WebSocket-Accept 计算
//!
//! 服务端在 101 响应中必须返回 `Sec-WebSocket-Accept` header，值由客户端
//! `Sec-WebSocket-Key` 加全局 GUID 经 SHA-1 + base64 编码得到：
//!
//! ```text
//! accept = base64(sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
//! ```

use base64::Engine;
use sha1::{Digest, Sha1};

/// RFC 6455 全局 GUID，用于 `Sec-WebSocket-Accept` 计算。
pub const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// WebSocket 帧 opcode（RFC 6455 §5.2）。
///
/// 对应 `gorilla/websocket` 的常量：`TextMessage`/`BinaryMessage`/`CloseMessage`/
/// `PingMessage`/`PongMessage`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    /// 0x0：延续帧（fragmentation 后续分片）。
    Continuation = 0x0,
    /// 0x1：文本帧。Xray 不使用（数据是二进制）。
    Text = 0x1,
    /// 0x2：二进制帧。Xray 客户端默认用此类型承载 payload。
    Binary = 0x2,
    /// 0x8：关闭帧。
    Close = 0x8,
    /// 0x9：Ping 帧（心跳）。
    Ping = 0x9,
    /// 0xA：Pong 帧（心跳响应）。
    Pong = 0xA,
}

impl Opcode {
    /// 从原始 4-bit 值构造。返回 `None` 表示非法 opcode（3..=7 / B..=F 保留或非法）。
    #[must_use]
    pub fn from_raw(low_nibble: u8) -> Option<Self> {
        match low_nibble & 0x0F {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }

    /// 是否为控制帧（Close / Ping / Pong）。控制帧不可分片、payload ≤ 125 字节。
    #[must_use]
    pub fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// 计算 `Sec-WebSocket-Accept` header 值。
///
/// 入参 `client_key` 是客户端 `Sec-WebSocket-Key` 的 base64 字符串（24 字节）。
/// 返回 28 字节 base64 字符串。
///
/// 对应 RFC 6455 §1.3 与 `gorilla/websocket` 的 `ComputeAcceptKey`。
#[must_use]
pub fn compute_accept_key(client_key: &str) -> String {
    let mut sha = Sha1::new();
    sha.update(client_key.as_bytes());
    sha.update(WS_GUID.as_bytes());
    let digest = sha.finalize();
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// 生成随机 `Sec-WebSocket-Key`（16 字节随机 + base64 编码 = 24 字符）。
///
/// 切片1 仅声明函数签名——实际随机数由切片2 接入 `ring::rand` 或
/// `tokio-tungstenite` 内置握手时自动生成。当前返回固定测试值用于 roundtrip 验证。
///
/// 切片2 切换为真随机实现。
#[must_use]
pub fn generate_client_key_for_testing() -> String {
    // RFC 6455 §1.3 示例 key（16 字节 base64 编码）。
    "dGhlIHNhbXBsZSBub25jZQ==".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_rfc_example() {
        // RFC 6455 §4.2.2 示例：client_key -> accept
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = compute_accept_key(key);
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn accept_key_known_vector() {
        // RFC 6455 §4.1.7 / §4.2.2 唯一官方向量（其他常见 key 可用 rfc 示例验证）
        // 同 accept_key_rfc_example，但保留独立测试便于回归诊断
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        assert_eq!(compute_accept_key(key), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn accept_key_deterministic() {
        // 同一 key 两次计算结果一致
        let k = "test-key-12345678==";
        assert_eq!(compute_accept_key(k), compute_accept_key(k));
    }

    #[test]
    fn accept_key_length_is_28() {
        // base64(SHA-1 20 字节) = 28 字符（含末尾 '='）
        let accept = compute_accept_key("any-key");
        assert_eq!(accept.len(), 28);
    }

    #[test]
    fn opcode_from_raw_known_values() {
        assert_eq!(Opcode::from_raw(0x0), Some(Opcode::Continuation));
        assert_eq!(Opcode::from_raw(0x1), Some(Opcode::Text));
        assert_eq!(Opcode::from_raw(0x2), Some(Opcode::Binary));
        assert_eq!(Opcode::from_raw(0x8), Some(Opcode::Close));
        assert_eq!(Opcode::from_raw(0x9), Some(Opcode::Ping));
        assert_eq!(Opcode::from_raw(0xA), Some(Opcode::Pong));
    }

    #[test]
    fn opcode_from_raw_rejects_reserved() {
        // 3..=7 / B..=F 是保留值
        for v in [0x3, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF] {
            assert_eq!(Opcode::from_raw(v), None, "value={v:#x}");
        }
    }

    #[test]
    fn opcode_from_raw_masks_high_bits() {
        // 传入完整 byte，只看低 4 位
        assert_eq!(Opcode::from_raw(0x82), Some(Opcode::Binary)); // FIN=1, opcode=2
        assert_eq!(Opcode::from_raw(0x89), Some(Opcode::Ping));
    }

    #[test]
    fn opcode_is_control_classification() {
        assert!(!Opcode::Continuation.is_control());
        assert!(!Opcode::Text.is_control());
        assert!(!Opcode::Binary.is_control());
        assert!(Opcode::Close.is_control());
        assert!(Opcode::Ping.is_control());
        assert!(Opcode::Pong.is_control());
    }

    #[test]
    fn generate_client_key_for_testing_is_rfc_vector() {
        // 占位实现返回 RFC 示例 key，便于 roundtrip 测试
        let key = generate_client_key_for_testing();
        assert_eq!(key, "dGhlIHNhbXBsZSBub25jZQ==");
        // 与 accept key 形成 roundtrip
        let accept = compute_accept_key(&key);
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn ws_guid_constant_matches_rfc() {
        assert_eq!(WS_GUID, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    }
}
