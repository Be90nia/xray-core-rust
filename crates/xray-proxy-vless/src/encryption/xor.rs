//! XTLS Vision 的 XOR/CTR 加密连接。
//!
//! 对应 Go 版本 `encryption/xor.go`。Go 实现用 BLAKE3 派生密钥 + AES-CTR，
//! 再用 `XorConn` 包装底层 `net.Conn` 做双 CTR 流加密（上行/下行）+ skip/header 状态机。
//!
//! # 当前状态
//!
//! 完整实现需要 `blake3` + `aes` crate（workspace 尚未引入），且涉及 splice copy
//! 状态机复杂，因此本文件留 trait + 占位函数。等加密依赖就绪后注入实现。

use crate::error::{Result, VlessError};

/// XOR 模式标记（Go 端 `XorMode = 2`）。
pub const XOR_MODE: u32 = 2;

/// BLAKE3 派生密钥的上下文字符串（Go 端硬编码 `"VLESS"`）。
pub const BLAKE3_CONTEXT: &str = "VLESS";

/// AES-CTR 流式加密的占位工厂。
///
/// 对应 Go 的 `NewCTR(key, iv []byte) cipher.Stream`：BLAKE3 DeriveKey + AES-CTR。
///
/// 实际实现需 `blake3` + `aes` crate；当前返回 `NotImplemented`。
pub fn new_ctr(_key: &[u8], _iv: &[u8]) -> Result<Box<dyn std::io::Read + Send>> {
    Err(VlessError::NotImplemented(
        "new_ctr requires blake3 + aes crates".into(),
    ))
}
