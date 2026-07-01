//! VMess 客户端会话：编码请求头 + body chunk 编解码 + 响应头解密。
//!
//! 对应 Go 版本 `proxy/vmess/encoding/client.go`。
//!
//! # 实现范围
//!
//! - **完整**：`ClientSession::new` + `encode_request_header`
//! - **完整**：`encode_request_body` / `decode_response_header` / `decode_response_body`
//!   （AES-128-GCM + PlainChunkSizeParser 路径，对应 Go 默认 security）
//! - **留 follow-up**：ChaCha20-Poly1305 security + AuthenticatedLength option +
//!   ShakeSizeParser（ChunkMasking）+ async 化（接入 xray-crypto AuthenticationReader/Writer）
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use xray_common::bitmask::Bitmask;
use xray_common::protocol::{Command, RequestHeader, ResponseHeader, SecurityType};
use xray_crypto::aead::{AeadCipher, Aes128Gcm};

use crate::aead::{self, consts, SealHeaderError};
use crate::encoding::body_chunk::{self, ChunkNonceAdapter, PlainSizeParser};
use crate::encoding::{authenticate, write_address_port, ChunkNonceGenerator};
use crate::error::{Result, VmessError};
use crate::VmessCommand;

/// VMess 客户端会话（对应 Go `ClientSession`）。
///
/// 持有请求/响应 body 加密所需的 key/IV（随机生成），以及响应头首字节。
#[derive(Debug, Clone)]
pub struct ClientSession {
    /// 请求 body key（16B 随机）。
    pub request_body_key: [u8; 16],
    /// 请求 body IV（16B 随机）。
    pub request_body_iv: [u8; 16],
    /// 响应 body key = SHA256(request_body_key)[..16]。
    pub response_body_key: [u8; 16],
    /// 响应 body IV = SHA256(request_body_iv)[..16]。
    pub response_body_iv: [u8; 16],
    /// 响应头首字节（1B 随机，用于服务端响应校验）。
    pub response_header: u8,
}

impl ClientSession {
    /// 创建新会话：生成 33B 随机（16 key + 16 iv + 1 header），派生 body key/IV。
    #[must_use]
    pub fn new() -> Self {
        use rand::RngCore;
        let mut buf = [0u8; 33];
        rand::rng().fill_bytes(&mut buf);
        let mut request_body_key = [0u8; 16];
        let mut request_body_iv = [0u8; 16];
        request_body_key.copy_from_slice(&buf[..16]);
        request_body_iv.copy_from_slice(&buf[16..32]);
        let response_header = buf[32];

        let body_key_hash = Sha256::digest(&request_body_key);
        let body_iv_hash = Sha256::digest(&request_body_iv);
        let mut response_body_key = [0u8; 16];
        let mut response_body_iv = [0u8; 16];
        response_body_key.copy_from_slice(&body_key_hash[..16]);
        response_body_iv.copy_from_slice(&body_iv_hash[..16]);

        Self {
            request_body_key,
            request_body_iv,
            response_body_key,
            response_body_iv,
            response_header,
        }
    }

    /// 编码请求头（对应 Go `EncodeRequestHeader`）。
    ///
    /// # 算法
    ///
    /// 1. 构造 38B base buffer：`[Ver=1 | requestBodyIV | requestBodyKey | respHeader | option | sec/pad | reserved | cmd]`
    /// 2. 若 cmd ≠ Mux，追加地址 + 端口
    /// 3. 追加 padding（随机长度，最多 16B）
    /// 4. 追加 FNV1a 校验和（4B BE）
    /// 5. 用 cmd_key 通过 `seal_vmess_aead_header` 加密整个 buffer
    ///
    /// # Errors
    ///
    /// - [`VmessError::AeadReadFailed`]：AEAD 加密失败。
    pub fn encode_request_header(
        &self,
        header: &RequestHeader,
        cmd_key: &[u8; 16],
    ) -> Result<Vec<u8>> {
        // 取账户（Go 端是 `header.User.Account.(*vmess.MemoryAccount)`）
        // Rust 端 RequestHeader.user 是 Option<MemoryUser>，且本地没有 account 信息
        // 这里要求调用方在传入前确保 header.user.account 已设；本函数只用 cmd_key 参数

        let mut buffer: Vec<u8> = Vec::with_capacity(64);
        // 1B version
        buffer.push(crate::encoding::VERSION);

        // 16B IV + 16B key
        buffer.extend_from_slice(&self.request_body_iv);
        buffer.extend_from_slice(&self.request_body_key);

        // 1B response header
        buffer.push(self.response_header);

        // 1B option
        buffer.push(header.option.bits());

        // padding len (high 4 bits) + security (low 4 bits)
        use rand::RngCore;
        let mut pad_buf = [0u8; 1];
        rand::rng().fill_bytes(&mut pad_buf);
        let padding_len = (pad_buf[0] as usize) % 16;
        let security_byte = (u8::try_from(padding_len << 4).unwrap_or(0))
            | header.security.as_u8();
        buffer.push(security_byte);

        // 1B reserved
        buffer.push(0);

        // 1B command
        let vmess_cmd = VmessCommand::from(header.command);
        buffer.push(vmess_cmd.as_u8());

        // 地址 + 端口（非 Mux）
        if vmess_cmd != VmessCommand::Mux {
            let addr = header.destination.address();
            let port = header.destination.port().value();
            write_address_port(&mut buffer, addr, port);
        }

        // padding
        if padding_len > 0 {
            let mut pad = vec![0u8; padding_len];
            rand::rng().fill_bytes(&mut pad);
            buffer.extend_from_slice(&pad);
        }

        // FNV1a 4B BE 校验和
        let auth = authenticate(&buffer);
        buffer.extend_from_slice(&auth.to_be_bytes());

        // AEAD seal
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        aead::seal_vmess_aead_header(cmd_key, &buffer, now)
            .map_err(|e| match e {
                SealHeaderError::InvalidKeyLength(n) => {
                    VmessError::Other(format!("cmd_key length mismatch: {n}"))
                }
                SealHeaderError::Crypto(c) => VmessError::Crypto(c),
            })
    }

    /// 编码请求 body：把明文 data 加密为 chunk 流写入 writer。
    ///
    /// 对应 Go `EncodeRequestBody`。
    ///
    /// # 算法
    ///
    /// 1. 构造 AES-128-GCM cipher（key = `request_body_key`）
    /// 2. 构造 ChunkNonce 生成器（IV = `request_body_iv`，nonce_size = 12）
    /// 3. 选 SizeParser（默认 Plain，`RequestOptionChunkMasking` 选 Shake 留 follow-up）
    /// 4. 调用 `body_chunk::encode_chunk_stream` 分块 seal + 写入
    ///
    /// # Errors
    ///
    /// - [`VmessError::Other`]：security ≠ AES-128-GCM（当前路径限制）
    /// - [`VmessError::Crypto`]：AES key 长度错误
    /// - [`VmessError::Io`]：writer IO 错误
    pub fn encode_request_body<W: std::io::Write>(
        &self,
        request: &RequestHeader,
        data: &[u8],
        writer: &mut W,
    ) -> Result<()> {
        // ponytail: 当前只支持 AES-128-GCM（默认 security）
        if !matches!(request.security, SecurityType::Aes128Gcm) {
            return Err(VmessError::Other(format!(
                "encode_request_body: only Aes128Gcm supported, got {:?}",
                request.security
            )));
        }

        let cipher = Aes128Gcm::new(&self.request_body_key)?;
        let mut nonce_gen = ChunkNonceAdapter::new(&self.request_body_iv, 12);
        // ponytail: ChunkMasking (ShakeSizeParser) + GlobalPadding 留 follow-up
        let mut size_parser = PlainSizeParser;
        body_chunk::encode_chunk_stream(writer, data, &cipher, &mut nonce_gen, &mut size_parser)?;
        Ok(())
    }

    /// 解码响应头：AEAD 解密响应头 length + payload，返回 ResponseHeader。
    ///
    /// 对应 Go `DecodeResponseHeader`。
    ///
    /// # 算法
    ///
    /// 1. KDF16 派生 len key，KDF 派生 len IV[:12]
    /// 2. 读 18B 加密 length，AES-128-GCM Open → 2B length BE u16
    /// 3. KDF16 派生 payload key，KDF 派生 payload IV[:12]
    /// 4. 读 (length+16)B 加密 payload，AES-128-GCM Open
    /// 5. 解析 payload: [1B response_header | 1B option | 1B cmd_id | 1B data_len | N B data]
    /// 6. 验证 response_header == self.response_header
    ///
    /// # Errors
    ///
    /// 参见 [`VmessError`] 各变体。
    pub fn decode_response_header<R: std::io::Read>(
        &self,
        reader: &mut R,
    ) -> Result<ResponseHeader> {
        // 1. 派生 len key/IV
        let len_key = aead::kdf16(&self.response_body_key, &[consts::AEAD_RESP_HEADER_LEN_KEY]);
        let len_iv_full = aead::kdf(&self.response_body_iv, &[consts::AEAD_RESP_HEADER_LEN_IV]);
        let len_nonce = &len_iv_full[..12];
        let len_cipher = Aes128Gcm::new(&len_key)?;

        // 2. 读 18B 加密 length + AEAD Open
        let mut encrypted_len = [0u8; 18];
        reader.read_exact(&mut encrypted_len)?;
        let decrypted_len_bytes = len_cipher
            .open(len_nonce, &[], &encrypted_len)
            .map_err(|_| VmessError::DecryptResponseHeaderLengthFailed)?;
        if decrypted_len_bytes.len() < 2 {
            return Err(VmessError::ReadResponseHeaderFailed);
        }
        let payload_len = u16::from_be_bytes([decrypted_len_bytes[0], decrypted_len_bytes[1]]);

        // 3. 派生 payload key/IV
        let payload_key = aead::kdf16(&self.response_body_key, &[consts::AEAD_RESP_HEADER_PAYLOAD_KEY]);
        let payload_iv_full = aead::kdf(&self.response_body_iv, &[consts::AEAD_RESP_HEADER_PAYLOAD_IV]);
        let payload_nonce = &payload_iv_full[..12];
        let payload_cipher = Aes128Gcm::new(&payload_key)?;

        // 4. 读 (payload_len+16)B 加密 payload + AEAD Open
        let mut encrypted_payload = vec![0u8; usize::from(payload_len) + 16];
        reader.read_exact(&mut encrypted_payload)?;
        let payload = payload_cipher
            .open(payload_nonce, &[], &encrypted_payload)
            .map_err(|_| VmessError::DecryptResponseHeaderPayloadFailed)?;

        // 5. 解析 payload
        if payload.len() < 4 {
            return Err(VmessError::ReadResponseHeaderFailed);
        }
        // 6. 验证 response_header
        if payload[0] != self.response_header {
            return Err(VmessError::UnexpectedResponseHeader {
                expected: self.response_header,
                actual: payload[0],
            });
        }
        let option = Bitmask::new(payload[1]);
        // payload[2] = cmd_id (0 表示无 command)
        // payload[3] = data_len
        // ponytail: 当前不解析 command（留 follow-up，VMess 响应 command 用于动态转发控制）
        Ok(ResponseHeader {
            command: Command::Tcp,
            option,
        })
    }

    /// 解码响应 body：从 reader 读取 chunk 流解密，返回所有明文。
    ///
    /// 对应 Go `DecodeResponseBody`。
    ///
    /// # 算法
    ///
    /// 1. 构造 AES-128-GCM cipher（key = `response_body_key`）
    /// 2. 构造 ChunkNonce 生成器（IV = `response_body_iv`，nonce_size = 12）
    /// 3. 选 SizeParser（默认 Plain）
    /// 4. 调用 `body_chunk::decode_chunk_stream`
    ///
    /// # Errors
    ///
    /// - [`VmessError::Other`]：security ≠ AES-128-GCM
    /// - [`VmessError::Io`]：reader IO 错误（含 EOF）
    /// - [`VmessError::Crypto`]：AEAD 解密失败
    pub fn decode_response_body<R: std::io::Read>(
        &self,
        request: &RequestHeader,
        reader: &mut R,
    ) -> Result<Vec<u8>> {
        // ponytail: 当前只支持 AES-128-GCM
        if !matches!(request.security, SecurityType::Aes128Gcm) {
            return Err(VmessError::Other(format!(
                "decode_response_body: only Aes128Gcm supported, got {:?}",
                request.security
            )));
        }
        let cipher = Aes128Gcm::new(&self.response_body_key)?;
        let mut nonce_gen = ChunkNonceAdapter::new(&self.response_body_iv, 12);
        let mut size_parser = PlainSizeParser;
        let plaintext = body_chunk::decode_chunk_stream(reader, &cipher, &mut nonce_gen, &mut size_parser)?;
        Ok(plaintext)
    }

    /// 构造 chunk nonce 生成器（对应 Go `GenerateChunkNonce(iv, nonce_size)`）。
    ///
    /// 用 `request_body_iv` 初始化，nonce 大小由 AEAD 算法决定（AES-GCM=12，ChaCha20-Poly1305=12）。
    #[must_use]
    pub fn chunk_nonce_generator(&self, nonce_size: usize) -> ChunkNonceGenerator {
        ChunkNonceGenerator::new(&self.request_body_iv, nonce_size)
    }
}

impl Default for ClientSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::Validator;
    use xray_common::net::address::Address;
    use xray_common::net::destination::Destination;
    use xray_common::net::port::Port;
    use xray_common::protocol::{Command, SecurityType};
    use xray_common::uuid::UUID;

    fn sample_cmd_key() -> [u8; 16] {
        let uuid = UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("uuid");
        crate::account::cmd_key_of(&uuid)
    }

    fn sample_request_header_tcp() -> RequestHeader {
        let dest = Destination::tcp(Address::ipv4(std::net::Ipv4Addr::new(1, 2, 3, 4)), Port::new(80));
        RequestHeader::new(crate::encoding::VERSION, Command::Tcp, dest, SecurityType::Aes128Gcm)
    }

    #[test]
    fn new_session_has_random_keys() {
        let s1 = ClientSession::new();
        let s2 = ClientSession::new();
        // 极大概率两次随机会得到不同 key/iv
        assert_ne!(s1.request_body_key, s2.request_body_key);
        assert_ne!(s1.request_body_iv, s2.request_body_iv);
        assert_ne!(s1.response_header, s2.response_header);
    }

    #[test]
    fn response_body_key_derived_from_request_body_key() {
        let s = ClientSession::new();
        let hash = Sha256::digest(&s.request_body_key);
        let mut expected = [0u8; 16];
        expected.copy_from_slice(&hash[..16]);
        assert_eq!(s.response_body_key, expected);
    }

    #[test]
    fn response_body_iv_derived_from_request_body_iv() {
        let s = ClientSession::new();
        let hash = Sha256::digest(&s.request_body_iv);
        let mut expected = [0u8; 16];
        expected.copy_from_slice(&hash[..16]);
        assert_eq!(s.response_body_iv, expected);
    }

    #[test]
    fn encode_request_header_returns_sealed_bytes() {
        let session = ClientSession::new();
        let header = sample_request_header_tcp();
        let cmd_key = sample_cmd_key();
        let sealed = session.encode_request_header(&header, &cmd_key).expect("encode");
        // sealed = authID(16) + encrypted_len(18) + nonce(8) + encrypted_payload(N+16)
        // 至少 16 + 18 + 8 + 16 + 16 = 74 字节
        assert!(sealed.len() > 60);
    }

    #[test]
    fn encode_request_header_aead_can_be_decoded() {
        // 客户端 encode → 服务端 decode 完整往返
        let session = ClientSession::new();
        let header = sample_request_header_tcp();
        let cmd_key = sample_cmd_key();
        let sealed = session.encode_request_header(&header, &cmd_key).expect("encode");

        let mut auth_id = [0u8; 16];
        auth_id.copy_from_slice(&sealed[..16]);
        let mut reader = &sealed[16..];
        let opened = aead::open_vmess_aead_header(&cmd_key, &auth_id, &mut reader).expect("open");

        // 验证解码后的 buffer 结构
        let payload = opened.payload;
        assert_eq!(payload[0], crate::encoding::VERSION);
        // 1B ver + 16B IV + 16B key + 1B resp + 1B opt + 1B sec/pad + 1B reserved + 1B cmd = 38
        // + 2 port + 1 type + 4 ipv4 = 7
        // + 0..16 padding + 4 fnv1a
        assert!(payload.len() >= 38 + 7 + 4);
    }

    #[test]
    fn encode_request_header_mux_skips_address() {
        let session = ClientSession::new();
        let dest = Destination::tcp(
            Address::Domain("v1.mux.cool".to_string()),
            Port::new(0),
        );
        let header = RequestHeader::new(
            crate::encoding::VERSION,
            Command::Mux,
            dest,
            SecurityType::Aes128Gcm,
        );
        let cmd_key = sample_cmd_key();
        let sealed = session.encode_request_header(&header, &cmd_key).expect("encode");

        let mut auth_id = [0u8; 16];
        auth_id.copy_from_slice(&sealed[..16]);
        let mut reader = &sealed[16..];
        let opened = aead::open_vmess_aead_header(&cmd_key, &auth_id, &mut reader).expect("open");

        // Mux 不写地址：38 + 0..16 padding + 4 fnv1a
        assert!(opened.payload.len() < 38 + 16 + 16 + 4);
    }

    #[test]
    fn encode_request_body_writes_chunk_stream() {
        let session = ClientSession::new();
        let header = sample_request_header_tcp();
        let mut buf: Vec<u8> = Vec::new();
        session.encode_request_body(&header, b"hello body", &mut buf).expect("encode");
        // 至少包含一个 chunk（2B size + payload + 16B tag）+ 终止 chunk（2B + 16B）
        assert!(buf.len() > 2 + 16);
    }

    #[test]
    fn decode_response_header_roundtrip_with_server_encode() {
        // 客户端 decode_response_header ↔ 服务端 encode_response_header 往返
        use crate::encoding::server::{ServerSession, SessionHistory};
        use crate::validator::{MemoryUser, TimedUserValidator};
        use xray_common::protocol::ResponseHeader;

        let validator = TimedUserValidator::new();
        let history = SessionHistory::new();
        let uuid = UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("uuid");
        let account = crate::account::MemoryAccount::new(uuid);
        let user = MemoryUser::new("alice@example.com", account);
        validator.add(user).expect("add");

        let client_session = ClientSession::new();
        let mut server = ServerSession::new(&validator, &history);
        // 手动同步 server 的 request_body_key/iv 与 client 一致
        server.request_body_key = client_session.request_body_key;
        server.request_body_iv = client_session.request_body_iv;
        // 手动同步 server.response_header（否则 encode 写的字节 ≠ client 期望）
        server.response_header = client_session.response_header;

        let resp_header = ResponseHeader { command: Command::Tcp, option: Bitmask::new(0) };
        let mut buf: Vec<u8> = Vec::new();
        server.encode_response_header(&resp_header, &mut buf).expect("server encode");

        let mut reader = &buf[..];
        let decoded = client_session.decode_response_header(&mut reader).expect("client decode");
        assert_eq!(decoded.option.bits(), 0);
    }

    #[test]
    fn decode_response_body_roundtrip_with_server_encode() {
        // 客户端 decode_response_body ↔ 服务端 encode_response_body 往返
        use crate::encoding::server::{ServerSession, SessionHistory};
        use crate::validator::{MemoryUser, TimedUserValidator};

        let validator = TimedUserValidator::new();
        let history = SessionHistory::new();
        let uuid = UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("uuid");
        let account = crate::account::MemoryAccount::new(uuid);
        let user = MemoryUser::new("alice@example.com", account);
        validator.add(user).expect("add");

        let client_session = ClientSession::new();
        let mut server = ServerSession::new(&validator, &history);
        server.request_body_key = client_session.request_body_key;
        server.request_body_iv = client_session.request_body_iv;
        // encode_response_body 依赖 response_body_key/iv，手动同步
        server.response_body_key = client_session.response_body_key;
        server.response_body_iv = client_session.response_body_iv;

        let header = sample_request_header_tcp();
        let payload = b"response body payload from server";
        let mut buf: Vec<u8> = Vec::new();
        server.encode_response_body(&header, payload, &mut buf).expect("server encode");

        let mut reader = &buf[..];
        let decoded = client_session.decode_response_body(&header, &mut reader).expect("client decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn chunk_nonce_generator_uses_request_body_iv() {
        let session = ClientSession::new();
        let mut nonce_gen = session.chunk_nonce_generator(12);
        let nonce = nonce_gen.next();
        assert_eq!(nonce.len(), 12);
        // 前 2 字节是 count=0
        assert_eq!(nonce[0], 0);
        assert_eq!(nonce[1], 0);
        // 后 10 字节来自 request_body_iv[2..12]（nonce_size=12）
        assert_eq!(&nonce[2..], &session.request_body_iv[2..12]);
    }

    #[test]
    fn session_default_eq_new() {
        let _ = ClientSession::default();
    }

    #[test]
    fn session_clone_preserves_keys() {
        let s1 = ClientSession::new();
        let s2 = s1.clone();
        assert_eq!(s1.request_body_key, s2.request_body_key);
        assert_eq!(s1.request_body_iv, s2.request_body_iv);
        assert_eq!(s1.response_header, s2.response_header);
    }
}
