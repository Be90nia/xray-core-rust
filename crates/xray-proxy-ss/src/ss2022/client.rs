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
//! 6. SSStream::new_with_aead(conn, aead, 12) — nonce `[0xFF;12]`, 第一次 increment → `[0;12]`
//! 7. write_chunk(fixed-header: type=0 + timestamp_BE_u64) — nonce `[0;12]+`[1,0,...]
//! 8. write_chunk(variable-header: ATYP + addr + port) — nonce [2,0,...]+[3,0,...]
//! 9. write_chunk(body) — nonce [4,0,...]+
//! 10. read_chunk 循环读响应

use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::TcpStream;
use xray_crypto::aead::{AeadCipher, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305Aead};

use crate::{
    error::{Result, SsError},
    ss2022::key::{
        CipherKind2022, derive_psk, derive_session_subkey, encrypt_identity_header, psk_from_base64,
    },
    stream::SSStream,
};

/// SS-2022 TCP client。
///
/// PSK 链（Go `ParsePSKList`，密码 "iPSK:...:uPSK" 冒号分段）：末段为实际
/// 用户 PSK，前面各段逐层写 EIH（TCP EIH 用 salt 派生的 identity subkey）。
/// chacha + 多 PSK 在构造即硬错（Go outbound.go:48-50）。
#[derive(Debug)]
pub struct Client2022 {
    psk_list: Vec<Vec<u8>>,
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
    /// - [`SsError::Ss2022UnsupportedMethod`]：chacha + 多 PSK（Go 硬错对齐）。
    pub fn new(cipher: &str, psk_b64_list: &[String], host: &str, port: u16) -> Result<Self> {
        let kind = CipherKind2022::from_name(cipher)?;
        if psk_b64_list.is_empty() {
            return Err(SsError::Ss2022MissingKey);
        }
        let psk_list = psk_b64_list
            .iter()
            .map(|b| derive_psk(&psk_from_base64(b)?, kind))
            .collect::<Result<Vec<_>>>()?;
        if kind == CipherKind2022::ChaCha20Poly1305 && psk_list.len() > 1 {
            return Err(SsError::Ss2022UnsupportedMethod(
                "multi-key is not supported for chacha20-poly1305".to_string(),
            ));
        }
        Ok(Self { psk_list, kind, server_host: host.to_string(), server_port: port })
    }

    /// 最终 PSK（PSK 链末段，session key 派生材料）。
    fn final_psk(&self) -> &[u8] {
        &self.psk_list[self.psk_list.len() - 1]
    }

    /// 从 subkey 构造 AEAD。
    fn build_aead(&self, subkey: &[u8]) -> Result<Box<dyn AeadCipher + Send + Sync>> {
        match self.kind {
            CipherKind2022::Aes128Gcm => Ok(Box::new(Aes128Gcm::new(subkey)?)),
            CipherKind2022::Aes256Gcm => Ok(Box::new(Aes256Gcm::new(subkey)?)),
            CipherKind2022::ChaCha20Poly1305 => Ok(Box::new(ChaCha20Poly1305Aead::new(subkey)?)),
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
    /// 请求头**不在此处落线**（Go WriteTCPRequest(payload) 语义）：salt+EIH+fixed
    /// 明文与 variable chunk 的 addr_port 材料登记为 [`SSStream`] 首写待发状态，
    /// 首段 body 数据与 variable chunk 合并封装后**单次写出**（TCP 初始载荷并入
    /// 请求首写）；无首段数据时由调用方 `flush_pending_client_2022` 兜底发出
    /// （padding 1..900 满足 SIP022 §3.1.4）。
    ///
    /// 返回 `SSStream<C>`，调用方继续 `write_chunk` 发送 body + `read_chunk` 读响应。
    ///
    /// # Errors
    /// - [`SsError::Io`]：写失败。
    /// - [`SsError::AeadSeal`]：AEAD 加密失败。
    /// - 透传 AEAD 初始化错误。
    pub async fn dial_target_on<C>(
        &self,
        conn: C,
        target_addr: &str,
        target_port: u16,
    ) -> Result<SSStream<C>>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        // 随机 salt + derive subkey + build AEAD
        let psk = self.final_psk();
        let salt = self.random_salt();
        let subkey = derive_session_subkey(psk, &salt, self.kind);
        let aead = self.build_aead(&subkey)?;

        // nonce 从 [0;12] 开始（SS-2022 规范）；两个 header chunk 的 seal
        // 推迟到首写 emit 时进行（stream.rs emit_pending_client_2022）
        let nonce = vec![0u8; 12];

        // timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| SsError::GetCipher(e.to_string()))?
            .as_secs();

        // fixed-header-chunk 明文（11B）：variable 长度在首写时才定，先按 0 占位
        let mut fixed_plain = [0u8; 11];
        fixed_plain[0] = 0u8; // headerType=0 client
        fixed_plain[1..9].copy_from_slice(&timestamp.to_be_bytes());
        // variable_len 字段在 emit 时随实际长度回填，此处不写

        // addr+port 段（SOCKS5 domain: ATYP + 1B len + domain + 2B port）
        let mut addr_port = Vec::with_capacity(1 + 1 + target_addr.len() + 2);
        addr_port.push(3u8); // ATYP=3 domain
        addr_port.push(u8::try_from(target_addr.len()).map_err(|_| SsError::InvalidRemoteAddress)?);
        addr_port.extend_from_slice(target_addr.as_bytes());
        addr_port.extend_from_slice(&target_port.to_be_bytes());

        // 合并 wire 前缀：salt + EIH 层（SIP023：TCP EIH 用 salt 派生 identity
        // subkey 加密下一层 PSK hash，Go WriteTCPRequest pskList[:-1] 循环）
        let mut prefix = Vec::with_capacity(salt.len() + (self.psk_list.len() - 1) * 16);
        prefix.extend_from_slice(&salt);
        for i in 0..self.psk_list.len() - 1 {
            let eih = encrypt_identity_header(
                &self.psk_list[i],
                &self.psk_list[i + 1],
                &salt,
                self.kind,
            )?;
            prefix.extend_from_slice(&eih);
        }

        // 写 nonce 语义：emit 时 fixed 用 [0]、variable 用 [1]；body chunk 由
        // write_single_chunk 先 increment，size chunk 落在 [2]（服务端读序一致）
        let mut stream = SSStream::new_with_aead_and_nonce(conn, aead, nonce);
        stream.set_pending_client_2022(prefix, fixed_plain, addr_port);
        // SS-2022 响应头分阶段 rekey：sing `clientConn.readResponse`
        //（salt → blake3 重派生 subkey → fixed header chunk → variable header chunk）。
        stream.mark_response_rekey_2022(psk.to_vec(), self.kind, salt);

        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psk256_b64() -> String {
        "swzPBNUUnCN6/Ply/V90cKtGbQdNf/UK6v1UjIRAsdQ=".to_string()
    }

    #[test]
    fn client_new_aes256() {
        let c = Client2022::new("2022-blake3-aes-256-gcm", &[psk256_b64()], "example.com", 8388);
        assert!(c.is_ok());
        let c = c.unwrap();
        assert_eq!(c.psk_list.len(), 1);
        assert_eq!(c.final_psk().len(), 32);
        assert_eq!(c.kind, CipherKind2022::Aes256Gcm);
    }

    #[test]
    fn client_new_wrong_psk_len() {
        // aes-256 需要 32B PSK，给 16B → 错误
        let c = Client2022::new(
            "2022-blake3-aes-256-gcm",
            &["AAAAAAAAAAAAAAAAAAAAAA==".to_string()], // 16B base64
            "example.com",
            8388,
        );
        assert!(c.is_err());
    }

    /// chacha + 多 PSK 出站硬错（Go outbound.go:48-50）。
    #[test]
    fn client_new_chacha_multi_psk_rejected() {
        let c = Client2022::new(
            "2022-blake3-chacha20-poly1305",
            &[psk256_b64(), psk256_b64()],
            "example.com",
            8388,
        );
        let err = c.unwrap_err();
        assert!(matches!(err, SsError::Ss2022UnsupportedMethod(_)));
        assert!(err.to_string().contains("multi-key is not supported"));
    }

    #[test]
    fn client_build_aead_chacha20_roundtrip() {
        // 2022-blake3-chacha20-poly1305：TCP 直接用 ChaCha20-Poly1305 替换 AES-GCM（SIP022 §4），
        // KDF 与 AES-256-GCM 完全一致（blake3 derive_key 32B subkey）。
        // 验证 build_aead 不再返回 not-implemented，且 seal/open 往返一致。
        let c =
            Client2022::new("2022-blake3-chacha20-poly1305", &[psk256_b64()], "example.com", 8388)
                .expect("Client2022::new chacha20");
        assert_eq!(c.final_psk().len(), 32);
        assert_eq!(c.kind, CipherKind2022::ChaCha20Poly1305);

        let salt = vec![0xABu8; c.kind.salt_size()];
        let subkey = derive_session_subkey(c.final_psk(), &salt, c.kind);
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

    /// Go 2776ea6d 对照：dial 建连后早退（此处目标域名超长触发
    /// InvalidRemoteAddress）时，到服务器的连接必须被关闭——Rust 以所有权
    /// RAII 等价 Go `defer connection.Close()`。server accept 后应读到 EOF。
    #[tokio::test]
    async fn dial_target_on_early_return_closes_server_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let conn = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (mut server_sock, _) = listener.accept().await.expect("accept");

        let client =
            Client2022::new("2022-blake3-aes-256-gcm", &[psk256_b64()], "example.com", 8388)
                .expect("client");

        // 256+ 字节域名 → u8 长度装不下 → 早退（写 header 之前）。
        let oversize_domain = "a".repeat(300);
        let result = client.dial_target_on(conn, &oversize_domain, 443).await;
        assert!(result.is_err(), "oversize domain must fail handshake");

        // 连接已被关闭：server 读到 EOF（Go defer connection.Close() 语义）。
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 16];
        let n = server_sock.read(&mut buf).await.expect("read after early return");
        assert_eq!(n, 0, "server must observe EOF (conn closed) after early return");
    }

    /// TCP 初始载荷并入请求首写（Go WriteTCPRequest(payload)，v26.9.30）：
    /// 首段 body 数据必须 riding 在 variable chunk 尾部——对端
    /// [`crate::ss2022::Ss2022Inbound`] 解出的 first_payload 即首写数据，
    /// 且 TCP wire 上首写是一个 write_all（server 单次 read 即收到完整请求头+载荷）。
    #[tokio::test]
    async fn dial_target_on_merges_initial_payload_into_first_write() {
        use base64::Engine as _;

        let psk = [0x55u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(psk);
        let inbound = std::sync::Arc::new(
            crate::ss2022::Ss2022Inbound::new("2022-blake3-aes-256-gcm", &b64, "u1").unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let result = inbound.handle_conn(conn).await.unwrap();
            // 首个 chunk = variable chunk 尾部首段 payload，第二个 chunk = 常规 body
            let mut stream = result.stream;
            let head = stream.read_chunk().await.unwrap().expect("early payload chunk");
            assert_eq!(head, b"GET / HTTP early", "initial payload must ride the var chunk");
            let got = stream.read_chunk().await.unwrap().expect("body chunk");
            assert_eq!(got, b"second");
        });

        let client = Client2022::new(
            "2022-blake3-aes-256-gcm",
            std::slice::from_ref(&b64),
            "127.0.0.1",
            addr.port(),
        )
        .unwrap();
        let conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut stream = client.dial_target_on(conn, "example.com", 80).await.unwrap();
        // 首写 → salt+fixed+var(含本段) 一次落线；次写 → 常规 body chunk
        stream.write_chunk(b"GET / HTTP early").await.unwrap();
        stream.write_chunk(b"second").await.unwrap();
        stream.flush().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("initial-payload roundtrip timed out")
            .unwrap();
    }

    /// 无首段数据（dial 后直接 flush + 关闭）：兜底 flush 必须发出请求头
    /// （padding 1..900 满足 SIP022 §3.1.4），对端正常解出目标地址。
    #[tokio::test]
    async fn dial_target_on_flush_pending_sends_header_without_payload() {
        use base64::Engine as _;

        let psk = [0x66u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(psk);
        let inbound = std::sync::Arc::new(
            crate::ss2022::Ss2022Inbound::new("2022-blake3-aes-256-gcm", &b64, "u1").unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let result = inbound.handle_conn(conn).await.unwrap();
            assert_eq!(
                result.address,
                xray_common::net::address::Address::Domain("empty.example".into())
            );
        });

        let client = Client2022::new(
            "2022-blake3-aes-256-gcm",
            std::slice::from_ref(&b64),
            "127.0.0.1",
            addr.port(),
        )
        .unwrap();
        let conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut stream = client.dial_target_on(conn, "empty.example", 443).await.unwrap();
        stream.flush_pending_client_2022().await.unwrap();
        stream.flush().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("flush-only roundtrip timed out")
            .unwrap();
    }
}
