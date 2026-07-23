//! SS-2022 TCP client (SIP022)
//!
//! 对应 Go `proxy/shadowsocks_2022/outbound.go` + sing-shadowsocks `clientConn.writeRequest`。
//!
//! # Client TCP 流程
//!
//! 1. TCP connect to server
//! 2. 生成随机 salt（len = key_size）
//! 3. blake3 derive session subkey: "shadowsocks 2022 session subkey", PSK || salt
//! 4. AEAD::new(subkey)
//! 5. 写 salt（明文）到连接
//! 6. SSStream::new_with_aead(conn, aead, 12) — nonce [0xFF;12], 第一次 increment → [0;12]
//! 7. write_chunk(fixed-header: type=0 + timestamp_BE_u64) — nonce [0;12]+[1,0,...]
//! 8. write_chunk(variable-header: ATYP + addr + port) — nonce [2,0,...]+[3,0,...]
//! 9. write_chunk(body) — nonce [4,0,...]+
//! 10. read_chunk 循环读响应

use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use xray_crypto::aead::{AeadCipher, Aes128Gcm, Aes256Gcm};

use crate::error::{Result, SsError};
use crate::ss2022::key::{derive_session_subkey, psk_from_base64, CipherKind2022};
use crate::stream::SSStream;

/// SS-2022 TCP client。
pub struct Client2022 {
    psk: Vec<u8>,
    kind: CipherKind2022,
    server_host: String,
    server_port: u16,
}

impl Client2022 {
    /// 构造 client。
    ///
    /// # Errors
    /// - [`SsError::InvalidCipherName`]：cipher 名称不支持。
    /// - [`SsError::InvalidPassword`]：PSK base64 解码失败或长度不匹配。
    #[inline]
    pub fn new(cipher: &str, psk_b64: &str, host: &str, port: u16) -> Result<Self> {
        let kind = CipherKind2022::from_name(cipher)?;
        let psk = psk_from_base64(psk_b64)?;
        if psk.len() != kind.key_size() {
            return Err(SsError::InvalidPassword(format!(
                "PSK length {} != key_size {}",
                psk.len(),
                kind.key_size()
            )));
        }
        Ok(Self {
            psk,
            kind,
            server_host: host.to_string(),
            server_port: port,
        })
    }

    /// 从 subkey 构造 AEAD。
    fn build_aead(&self, subkey: &[u8]) -> Result<Box<dyn AeadCipher + Send + Sync>> {
        match self.kind {
            CipherKind2022::Aes128Gcm => Ok(Box::new(Aes128Gcm::new(subkey)?)),
            CipherKind2022::Aes256Gcm => Ok(Box::new(Aes256Gcm::new(subkey)?)),
            // ponytail: ChaCha20 SS-2022 留后续（VPS 用 aes-256-gcm）
            CipherKind2022::ChaCha20Poly1305 => Err(SsError::InvalidCipherName(
                "2022-blake3-chacha20-poly1305 not yet implemented".into(),
            )),
        }
    }

    /// 生成随机 salt。
    fn random_salt(&self) -> Vec<u8> {
        let len = self.kind.salt_size();
        (0..len).map(|_| rand::random::<u8>()).collect()
    }

    /// 连接到 SS-2022 server，发送 salt + header（fixed + variable），拨号到 target。
    ///
    /// 返回 `SSStream<TcpStream>`，调用方继续 `write_chunk` 发送 body + `read_chunk` 读响应。
    ///
    /// # Errors
    /// - [`SsError::Io`]：TCP 连接 / 写失败。
    /// - [`SsError::AeadSeal`]：AEAD 加密失败。
    /// - 透传 AEAD 初始化错误。
    pub async fn dial_target(
        &self,
        target_addr: &str,
        target_port: u16,
    ) -> Result<SSStream<TcpStream>> {
        // 1. TCP connect
        let mut conn = TcpStream::connect((self.server_host.as_str(), self.server_port)).await?;

        // 2-4. 随机 salt + derive subkey + build AEAD
        let salt = self.random_salt();
        let subkey = derive_session_subkey(&self.psk, &salt, self.kind);
        let aead = self.build_aead(&subkey)?;

        // nonce 从 [0;12] 开始（SS-2022 规范）
        let mut nonce = vec![0u8; 12];

        // timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| SsError::GetCipher(e.to_string()))?
            .as_secs();

        // padding: 1~900 随机（SIP022 要求 request 有 payload 或 padding）
        let padding_len: u16 = rand::random::<u16>() % 900 + 1;

        // addr+port 长度 (SOCKS5 domain: ATYP + 1B len + domain + 2B port)
        let addr_port_len = 1 + 1 + target_addr.len() + 2;

        // variable-header-chunk 明文长度 = addr_port + 2(paddingLen field) + padding
        let variable_len = addr_port_len + 2 + padding_len as usize;

        // 5. 手动 seal fixed-header-chunk (11B): headerType=0 + timestamp_BE_u64 + variableLen_BE_u16
        //    SS-2022 header 用直接 seal（无 size prefix），对应 Go shadowaead.Writer.WriteChunk
        let mut fixed = Vec::with_capacity(11);
        fixed.push(0u8); // headerType=0 client
        fixed.extend_from_slice(&timestamp.to_be_bytes());
        fixed.extend_from_slice(&(variable_len as u16).to_be_bytes());
        let sealed_fixed = aead
            .seal(&nonce, &[], &fixed)
            .map_err(|e| SsError::AeadSeal(e.to_string()))?;
        increment_nonce(&mut nonce); // [0;12] → [1,0,...]

        // 6. 手动 seal variable-header-chunk: addr+port + paddingLen_BE_u16 + padding
        let mut var = Vec::with_capacity(variable_len);
        var.push(3u8); // ATYP=3 domain
        var.push(u8::try_from(target_addr.len()).map_err(|_| SsError::InvalidRemoteAddress)?);
        var.extend_from_slice(target_addr.as_bytes());
        var.extend_from_slice(&target_port.to_be_bytes());
        var.extend_from_slice(&padding_len.to_be_bytes());
        for _ in 0..padding_len {
            var.push(rand::random::<u8>());
        }
        let sealed_var = aead
            .seal(&nonce, &[], &var)
            .map_err(|e| SsError::AeadSeal(e.to_string()))?;
        increment_nonce(&mut nonce); // [1,0,...] → [2,0,...]

        // 7. 合并发送 salt + sealed_fixed + sealed_var（一次性，避免分次 TCP 包导致 server 超时）
        let mut header_buf = Vec::with_capacity(salt.len() + sealed_fixed.len() + sealed_var.len());
        header_buf.extend_from_slice(&salt);
        header_buf.extend_from_slice(&sealed_fixed);
        header_buf.extend_from_slice(&sealed_var);
        conn.write_all(&header_buf).await?;
        conn.flush().await?;

        // 8. nonce 回退到 [1,0,...]，SSStream write_chunk increment → [2,0,...]（body size nonce）
        nonce[0] = 1;
        let stream = SSStream::new_with_aead_and_nonce(conn, aead, nonce);

        Ok(stream)
    }
}

/// LE increment（byte[0]++，进位），对应 Go `increaseNonce`。
fn increment_nonce(nonce: &mut [u8]) {
    for b in nonce.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_new_aes256() {
        let c = Client2022::new(
            "2022-blake3-aes-256-gcm",
            "swzPBNUUnCN6/Ply/V90cKtGbQdNf/UK6v1UjIRAsdQ=",
            "example.com",
            8388,
        );
        assert!(c.is_ok());
        let c = c.unwrap();
        assert_eq!(c.psk.len(), 32);
        assert_eq!(c.kind, CipherKind2022::Aes256Gcm);
    }

    #[test]
    fn client_new_wrong_psk_len() {
        // aes-256 需要 32B PSK，给 16B → 错误
        let c = Client2022::new(
            "2022-blake3-aes-256-gcm",
            "AAAAAAAAAAAAAAAAAAAAAA==", // 16B base64
            "example.com",
            8388,
        );
        assert!(c.is_err());
    }

    #[test]
    fn client_new_chacha_not_yet() {
        // chacha20 SS-2022 暂未实现
        let c = Client2022::new(
            "2022-blake3-chacha20-poly1305",
            "swzPBNUUnCN6/Ply/V90cKtGbQdNf/UK6v1UjIRAsdQ=",
            "example.com",
            8388,
        );
        // new() 成功（只是 cipher kind），但 build_aead 会失败
        assert!(c.is_ok());
    }
}
