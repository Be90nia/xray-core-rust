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
use tokio::net::TcpStream;
use xray_crypto::aead::{AeadCipher, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305Aead};

use crate::error::{Result, SsError};
use crate::ss2022::key::{
    derive_psk, derive_session_subkey, psk_from_base64, CipherKind2022,
};
use crate::stream::SSStream;

/// SS-2022 TCP client。
#[derive(Debug)]
pub struct Client2022 {
    psk: Vec<u8>,
    /// 多用户模式：server 主 PSK（iPSK）。Some 时在 salt 后写 1 层 EIH（SIP023）。
    identity_psk: Option<Vec<u8>>,
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
    pub fn new(cipher: &str, psk_b64: &str, host: &str, port: u16) -> Result<Self> {
        let kind = CipherKind2022::from_name(cipher)?;
        let psk = derive_psk(&psk_from_base64(psk_b64)?, kind)?;
        Ok(Self {
            psk,
            identity_psk: None,
            kind,
            server_host: host.to_string(),
            server_port: port,
        })
    }

    /// 设置 server 主 PSK（iPSK）启用多用户 EIH（SIP023）。
    /// 单端口多用户服务器配置 "server_psk:user_psk" 时：psk=user_psk，此处传 server_psk。
    pub fn with_identity(mut self, server_psk_b64: &str) -> Result<Self> {
        let ipsk = derive_psk(&psk_from_base64(server_psk_b64)?, self.kind)?;
        self.identity_psk = Some(ipsk);
        Ok(self)
    }

    /// 从 subkey 构造 AEAD。
    fn build_aead(&self, subkey: &[u8]) -> Result<Box<dyn AeadCipher + Send + Sync>> {
        match self.kind {
            CipherKind2022::Aes128Gcm => Ok(Box::new(Aes128Gcm::new(subkey)?)),
            CipherKind2022::Aes256Gcm => Ok(Box::new(Aes256Gcm::new(subkey)?)),
            CipherKind2022::ChaCha20Poly1305 => {
                Ok(Box::new(ChaCha20Poly1305Aead::new(subkey)?))
            }
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
        let conn = TcpStream::connect((self.server_host.as_str(), self.server_port)).await?;
        self.dial_target_on(conn, target_addr, target_port).await
    }

    /// 在**已建立**的连接上发送 salt + header（fixed + variable），拨号到 target。
    ///
    /// 生产路径（dispatcher）经 transport 层（ws+tls 等 streamSettings 包装）拿到
    /// 连接后调用本方法完成 SS-2022 握手；[`Self::dial_target`] 是裸 TCP 便捷版。
    ///
    /// 返回 `SSStream<C>`，调用方继续 `write_chunk` 发送 body + `read_chunk` 读响应。
    ///
    /// # Errors
    /// - [`SsError::Io`]：写失败。
    /// - [`SsError::AeadSeal`]：AEAD 加密失败。
    /// - 透传 AEAD 初始化错误。
    pub async fn dial_target_on<C>(
        &self,
        mut conn: C,
        target_addr: &str,
        target_port: u16,
    ) -> Result<SSStream<C>>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        // 随机 salt + derive subkey + build AEAD
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

        // 手动 seal fixed-header-chunk (11B): headerType=0 + timestamp_BE_u64 + variableLen_BE_u16
        //    SS-2022 header 用直接 seal（无 size prefix），对应 Go shadowaead.Writer.WriteChunk
        let mut fixed = Vec::with_capacity(11);
        fixed.push(0u8); // headerType=0 client
        fixed.extend_from_slice(&timestamp.to_be_bytes());
        fixed.extend_from_slice(&(variable_len as u16).to_be_bytes());
        let sealed_fixed = aead
            .seal(&nonce, &[], &fixed)
            .map_err(|e| SsError::AeadSeal(e.to_string()))?;
        increment_nonce(&mut nonce); // [0;12] → [1,0,...]

        // 手动 seal variable-header-chunk: addr+port + paddingLen_BE_u16 + padding
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

        // 合并发送 salt [+ EIH] + sealed_fixed + sealed_var（一次性，避免分次写导致 DPI 识别）
        let mut header_buf =
            Vec::with_capacity(salt.len() + sealed_fixed.len() + sealed_var.len() + 16);
        header_buf.extend_from_slice(&salt);
        // SIP023：identity PSK 存在时写 1 层 EIH（server iPSK 派生 subkey 加密 uPSK hash）
        if let Some(ipsk) = &self.identity_psk {
            let eih =
                crate::ss2022::key::encrypt_identity_header(ipsk, &self.psk, &salt, self.kind)?;
            header_buf.extend_from_slice(&eih);
        }
        header_buf.extend_from_slice(&sealed_fixed);
        header_buf.extend_from_slice(&sealed_var);
        use tokio::io::AsyncWriteExt;
        conn.write_all(&header_buf).await?;
        conn.flush().await?;

        nonce[0] = 1;
        let mut stream = SSStream::new_with_aead_and_nonce(conn, aead, nonce);
        // SS-2022 响应头分阶段 rekey：sing `clientConn.readResponse`
        //（salt → blake3 重派生 subkey → fixed header chunk → variable header chunk）。
        stream.mark_response_rekey_2022(self.psk.clone(), self.kind, salt);

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
    fn client_build_aead_chacha20_roundtrip() {
        // 2022-blake3-chacha20-poly1305：TCP 直接用 ChaCha20-Poly1305 替换 AES-GCM（SIP022 §4），
        // KDF 与 AES-256-GCM 完全一致（blake3 derive_key 32B subkey）。
        // 验证 build_aead 不再返回 not-implemented，且 seal/open 往返一致。
        let c = Client2022::new(
            "2022-blake3-chacha20-poly1305",
            "swzPBNUUnCN6/Ply/V90cKtGbQdNf/UK6v1UjIRAsdQ=",
            "example.com",
            8388,
        )
        .expect("Client2022::new chacha20");
        assert_eq!(c.psk.len(), 32);
        assert_eq!(c.kind, CipherKind2022::ChaCha20Poly1305);

        let salt = vec![0xABu8; c.kind.salt_size()];
        let subkey = derive_session_subkey(&c.psk, &salt, c.kind);
        assert_eq!(subkey.len(), 32);

        let aead = c.build_aead(&subkey).expect("build_aead chacha20");
        let nonce = vec![0u8; aead.nonce_size()];
        let plaintext = b"hello ss2022 chacha20-ietf-poly1305";
        let sealed = aead.seal(&nonce, b"", plaintext).expect("seal");
        assert_eq!(sealed.len(), plaintext.len() + aead.tag_size());
        let opened = aead.open(&nonce, b"", &sealed).expect("open");
        assert_eq!(opened.as_slice(), &plaintext[..]);

        // nonce 参与认证：错 nonce 必须解密失败
        let mut bad_nonce = nonce.clone();
        bad_nonce[0] = 1;
        assert!(aead.open(&bad_nonce, b"", &sealed).is_err());
    }
}
