//! wire 声明 padding 长度的上界校验（跨协议 DoS 通用防御）。
//!
//! 背景（bd p67v / 8tfh）：padding 长度字段是攻击者可控的 wire 输入，
//! 解码端若不设上界，会按声明值预分配缓冲或长时间逐块丢弃字节。凡从
//! wire 读出 padding 长度的解码点，消费（分配/丢弃）padding 字节前必须
//! 经 [`validate_padding_len`] 拒绝超界值。
//!
//! 上界按协议各自对齐 Go / 参考实现（禁自发明统一值），由调用方以常量
//! 传入；错误信息也由调用方按各协议既有语义映射（测试断言的字符串保持
//! 不变）。仓内现有收敛点：
//!
//! | 协议 | 上界 | Rust 调用点 | Go 参考 |
//! |---|---|---|---|
//! | anytls 认证帧 padding0 | `16 KiB − 34` | `xray-proxy-anytls/src/server.rs` | anytls-go inbound 首包缓冲有效上界 |
//! | hysteria TCP req/resp padding | `64 KiB`（有意放宽） | `xray-proxy-hysteria/src/protocol.rs` | `proxy/hysteria/protocol.go` `MaxPaddingLength`（4096，Rust 侧文档化放宽） |
//! | hysteria transport resp pad | `4096` | `xray-transport-hysteria/src/conn.rs` | 同上（对齐 Go 值） |
//! | xmc padding turn record | `8 MiB` | `xray-transport/src/finalmask/xmc/padding.rs` | `transport/internet/finalmask/xmc/padding.go` `maxPaddingTurnLength` |

use std::fmt;

/// padding 长度超界错误：携带 wire 声明值与协议上界，供调用方记录/包装。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaddingLenError {
    /// wire 声明的 padding 长度。
    pub len: u64,
    /// 协议合法上界。
    pub max: u64,
}

impl fmt::Display for PaddingLenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "padding length {} exceeds maximum {}", self.len, self.max)
    }
}

impl std::error::Error for PaddingLenError {}

/// 校验 wire 声明的 padding 长度不超过协议上界。
///
/// `len > max` 返回 [`Err`]；在按声明值分配缓冲或逐块丢弃之前调用。
/// 上界随协议不同（anytls 认证帧 `16 KiB − 34`、hysteria TCP req/resp
/// `64 KiB` 与 transport 侧 `4 KiB`、xmc padding turn `8 MiB`），禁止
/// 统一值；调用方保留各自错误信息映射。
pub fn validate_padding_len(len: u64, max: u64) -> Result<(), PaddingLenError> {
    if len > max { Err(PaddingLenError { len, max }) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_up_to_bound() {
        assert!(validate_padding_len(0, 0).is_ok());
        assert!(validate_padding_len(16350, 16 * 1024 - 34).is_ok());
        assert!(validate_padding_len(u64::MAX, u64::MAX).is_ok());
    }

    #[test]
    fn rejects_over_bound_with_payload() {
        assert_eq!(
            validate_padding_len(16351, 16 * 1024 - 34),
            Err(PaddingLenError { len: 16351, max: 16350 })
        );
    }

    #[test]
    fn display_carries_len_and_max() {
        let err = validate_padding_len(65537, 65536).unwrap_err();
        assert_eq!(err.to_string(), "padding length 65537 exceeds maximum 65536");
    }
}
