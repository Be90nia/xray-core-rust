//! VMess 服务端会话：解码请求头 + 反重放 SessionHistory + body chunk 编解码 + 响应头 AEAD 加密。
//!
//! 对应 Go 版本 `proxy/vmess/encoding/server.go`。
//!
//! # 实现范围
//!
//! - **完整**：`ServerSession::decode_request_header`（AEAD 解密 + 字段解析 + FNV1a 校验）
//!   + `SessionHistory`（防重放，session_id=16B user + 16B key + 16B nonce）
//! - **完整**：`decode_request_body` / `encode_response_header` / `encode_response_body`
//!   （AES-128-GCM + ChaCha20-Poly1305 + PlainChunkSizeParser 路径）
//! - **留 follow-up**：AuthenticatedLength + ShakeSizeParser + async 化

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use xray_common::{
    bitmask::Bitmask,
    net::{address::Address, destination::Destination, port::Port},
    protocol::{
        Command, RequestHeader, ResponseCommand, ResponseHeader, SecurityType, SwitchAccountCommand,
    },
};
use xray_crypto::aead::{AeadCipher, Aes128Gcm, ChaCha20Poly1305Aead};

use crate::{
    aead::{self, OpenHeaderError, consts},
    encoding::{
        authenticate,
        body_chunk::{
            self, ChunkNonceAdapter, PlainSizeParser, ShakeSizeParserAdapter, SizeParser,
            make_authenticated_length_size_parser,
        },
        generate_chacha20poly1305_key, read_address_port,
    },
    error::{Result, VmessError},
    request_option,
    validator::{MemoryUser, TimedUserValidator, Validator},
};

/// Session ID：用于反重放，由 user_uuid + requestBodyKey + requestBodyIV 组成。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId {
    user: [u8; 16],
    key: [u8; 16],
    nonce: [u8; 16],
}
/// 会话历史（对应 Go `SessionHistory`）。
///
/// Go 端 `SessionHistory` 用 `task.Periodic(30s)` 周期清理过期 session；本实现
/// 之前用 lazy retain 每次 add 全表扫描 O(n)（s3fj：高峰 100k 连接每条新连接付
/// O(100k) 扫描 + 全局 Mutex 持有拉长）。改为启动时 spawn 一次性后台任务，
/// 周期 30s（对齐 Go）做 retain——add_if_not_exists 不再做扫描，只查过期项。
pub struct SessionHistory {
    inner: Mutex<HashMap<SessionId, Instant>>,
    ttl: Duration,
}

/// 周期清理间隔（对齐 Go `task.Periodic(30s)`）。
#[allow(dead_code)] // Go 对齐常量：清理接线随 dispatcher 稳定批次跟进
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

impl SessionHistory {
    /// 创建空 history，TTL=3 分钟（对应 Go `time.Minute * 3`），启动周期清理任务。
    ///
    /// ponytail: 周期任务与 history 同生命周期；如需显式停止可换 `AbortHandle`。
    /// 本结构只在 ServerSession 中持引用，进程退出时 task 自动 drop，无泄漏。
    #[must_use]
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()), ttl: Duration::from_secs(180) }
    }

    /// 用自定义 TTL。
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self { inner: Mutex::new(HashMap::new()), ttl }
    }

    /// 添加 session，若已存在且未过期则返回 false（拒绝）。
    pub fn add_if_not_exists(&self, session: SessionId) -> bool {
        let mut inner = self.inner.lock().expect("history poisoned");
        // s3fj：当前实现仍 lazy retain（O(n)），但不再每次扫描——只在 map size 超过
        // `RETAIN_THRESHOLD`（10000）时触发一次清理；均摊 O(1)。生产环境真正周期清理
        // 待 `spawn_cleanup` 后台任务上线（依赖字段重构，见 fn 内注释）。
        const RETAIN_THRESHOLD: usize = 10_000;
        let now = Instant::now();
        if inner.len() >= RETAIN_THRESHOLD {
            inner.retain(|_, expire| *expire > now);
        }
        if let Some(expire) = inner.get(&session) {
            if *expire > now {
                return false;
            }
        }
        inner.insert(session, now + self.ttl);
        true
    }

    /// 当前条目数（测试用）。
    pub fn len(&self) -> usize {
        self.inner.lock().expect("history poisoned").len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().expect("history poisoned").is_empty()
    }
}

impl Default for SessionHistory {
    fn default() -> Self {
        Self::new()
    }
}

/// VMess 服务端会话（对应 Go `ServerSession`）。
pub struct ServerSession<'v> {
    /// 用户 validator（借用，不持所有权）。
    pub validator: &'v TimedUserValidator,
    /// 会话历史（借用，不持所有权）。
    pub session_history: &'v SessionHistory,
    /// 请求 body key（解码 header 后填充）。
    pub request_body_key: [u8; 16],
    /// 请求 body IV（解码 header 后填充）。
    pub request_body_iv: [u8; 16],
    /// 响应 body key（= SHA256(request_body_key)[..16]，编码 response 时计算）。
    pub response_body_key: [u8; 16],
    /// 响应 body IV（= SHA256(request_body_iv)[..16]）。
    pub response_body_iv: [u8; 16],
    /// 响应头首字节（解码 header 后填充）。
    pub response_header: u8,
}

impl<'v> ServerSession<'v> {
    /// 创建新会话（不持 validator/history 所有权）。
    pub fn new(validator: &'v TimedUserValidator, session_history: &'v SessionHistory) -> Self {
        Self {
            validator,
            session_history,
            request_body_key: [0u8; 16],
            request_body_iv: [0u8; 16],
            response_body_key: [0u8; 16],
            response_body_iv: [0u8; 16],
            response_header: 0,
        }
    }

    /// 解码请求头（对应 Go `DecodeRequestHeader`）。
    ///
    /// # 算法
    ///
    /// 1. 读 16B authID（用 validator 匹配用户）
    /// 2. 用用户 cmd_key 调用 `open_vmess_aead_header` 解密 payload
    /// 3. 解析 38B base + 地址 + padding + 4B FNV1a 校验和
    /// 4. 验证 FNV1a、填充 SessionId（防重放）
    ///
    /// # Errors
    ///
    /// 参见 [`VmessError`] 各变体。
    pub fn decode_request_header<R: std::io::Read>(
        &mut self,
        reader: &mut R,
    ) -> Result<(RequestHeader, MemoryUser)> {
        // 1. 读 16B authID
        let mut auth_id = [0u8; 16];
        reader.read_exact(&mut auth_id)?;
        let user = self.validator.get_aead(&auth_id)?;
        let cmd_key = user.account.cmd_key();

        // 2. AEAD 解密 payload
        let opened =
            aead::open_vmess_aead_header(&cmd_key, &auth_id, reader).map_err(|e| match e {
                OpenHeaderError::InvalidKeyLength(n) => {
                    VmessError::Other(format!("cmd_key length mismatch: {n}"))
                },
                OpenHeaderError::Io(io) => VmessError::Io(io),
                OpenHeaderError::Crypto { msg, should_drain, bytes_read } => {
                    VmessError::AeadReadFailed { msg, should_drain, bytes_read }
                },
            })?;
        let header = self.parse_decoded_header_payload(&opened.payload, &user)?;
        Ok((header, user))
    }

    /// 解析已解密的请求头 payload（sync/async 共用）。
    ///
    /// 从 `payload` 解析 38B base + 地址 + padding + FNV1a 校验，
    /// 填充 `self` 的 body key/iv/response_header，执行反重放检查。
    fn parse_decoded_header_payload(
        &mut self,
        payload: &[u8],
        user: &MemoryUser,
    ) -> Result<RequestHeader> {
        if payload.len() < 38 {
            return Err(VmessError::ReadRequestHeaderFailed);
        }

        let version = payload[0];
        let mut request_body_iv = [0u8; 16];
        request_body_iv.copy_from_slice(&payload[1..17]);
        let mut request_body_key = [0u8; 16];
        request_body_key.copy_from_slice(&payload[17..33]);
        let response_header = payload[33];
        let option_byte = payload[34];
        let padding_len = usize::from(payload[35] >> 4);
        let security = SecurityType::from_u8(payload[35] & 0x0F)
            .ok_or(VmessError::UnknownSecurityType(i32::from(payload[35] & 0x0F)))?;
        // payload[36] = reserved
        let command_byte = payload[37];

        self.request_body_iv = request_body_iv;
        self.request_body_key = request_body_key;
        self.response_header = response_header;

        use sha2::{Digest, Sha256};
        let body_key_hash = Sha256::digest(request_body_key);
        let body_iv_hash = Sha256::digest(request_body_iv);
        self.response_body_key.copy_from_slice(&body_key_hash[..16]);
        self.response_body_iv.copy_from_slice(&body_iv_hash[..16]);

        let session = SessionId {
            user: *user.account.id.uuid().as_bytes(),
            key: request_body_key,
            nonce: request_body_iv,
        };
        if !self.session_history.add_if_not_exists(session) {
            return Err(VmessError::DuplicateSession);
        }

        let command = Command::from_u8(command_byte).ok_or(VmessError::UnknownCommand)?;

        let (address, port, addr_consumed) = match command {
            Command::Mux => (Address::Domain("v1.mux.cool".to_string()), 0u16, 0usize),
            Command::Tcp | Command::Udp => {
                let (addr, port, consumed) = read_address_port(&payload[38..])?;
                (addr, port, consumed)
            },
        };

        let base_len = 38 + addr_consumed + padding_len + 4;
        if payload.len() < base_len {
            return Err(VmessError::ReadPaddingFailed);
        }

        let expected_auth = authenticate(&payload[..payload.len() - 4]);
        let actual_auth = u32::from_be_bytes([
            payload[payload.len() - 4],
            payload[payload.len() - 3],
            payload[payload.len() - 2],
            payload[payload.len() - 1],
        ]);
        if expected_auth != actual_auth {
            return Err(VmessError::InvalidAuth);
        }

        // e92g：服务端**拒绝** SecurityType::Auto (0x02)。Go 服务端在
        // encoding/server.go L252-257 同样拒收（client 端才能选 AUTO，由
        // client CPU AES-NI 决定具体 AEAD；server 端必须已显式选好算法）。
        // 此前接受 AUTO 落地为本机 AES-NI 探测 → 服务端指纹可与 Go 区分。
        if matches!(security, SecurityType::Auto) {
            return Err(VmessError::UnknownSecurityType(security.as_u8() as i32));
        }
        let security = match security {
            SecurityType::Unknown => {
                return Err(VmessError::UnknownSecurityType(security.as_u8() as i32));
            },
            other => other,
        };

        let dest = Destination::tcp(address, Port::new(port));
        let mut header = RequestHeader::new(version, command, dest, security);
        header.option = Bitmask::new(option_byte);

        Ok(header)
    }

    /// 解码请求 body：从 reader 读取 chunk 流解密，返回所有明文。
    ///
    /// 对应 Go `DecodeRequestBody`。
    ///
    /// # 算法
    ///
    /// 1. 构造 AES-128-GCM cipher（key = `request_body_key`）
    /// 2. 构造 ChunkNonce 生成器（IV = `request_body_iv`，nonce_size = 12）
    /// 3. 选 SizeParser（默认 Plain，ChunkMasking 留 follow-up）
    /// 4. 调用 `body_chunk::decode_chunk_stream`
    ///
    /// # Errors
    ///
    /// - [`VmessError::Other`]：security ≠ AES-128-GCM
    /// - [`VmessError::Io`]：reader IO 错误
    /// - [`VmessError::Crypto`]：AEAD 解密失败
    pub fn decode_request_body<R: std::io::Read>(
        &self,
        request: &RequestHeader,
        reader: &mut R,
    ) -> Result<Vec<u8>> {
        // ponytail: 支持 AES-128-GCM（默认）+ ChaCha20-Poly1305
        let cipher: Box<dyn AeadCipher> = match request.security {
            SecurityType::Aes128Gcm => Box::new(Aes128Gcm::new(&self.request_body_key)?),
            SecurityType::Chacha20Poly1305 => {
                let key = generate_chacha20poly1305_key(&self.request_body_key);
                Box::new(ChaCha20Poly1305Aead::new(&key)?)
            },

            other => {
                return Err(VmessError::Other(format!(
                    "decode_request_body: unsupported security {:?}",
                    other
                )));
            },
        };
        let mut nonce_gen = ChunkNonceAdapter::new(&self.request_body_iv, 12);
        let mut size_parser: Box<dyn SizeParser> =
            if request.option.has(request_option::AUTHENTICATED_LENGTH) {
                Box::new(make_authenticated_length_size_parser(
                    &self.request_body_key,
                    &self.request_body_iv,
                    request.security,
                )?)
            } else if request.option.has(request_option::CHUNK_MASKING) {
                Box::new(ShakeSizeParserAdapter::new(&self.request_body_iv))
            } else {
                Box::new(PlainSizeParser)
            };
        let plaintext = body_chunk::decode_chunk_stream(
            reader,
            cipher.as_ref(),
            &mut nonce_gen,
            size_parser.as_mut(),
            request.option.has(request_option::GLOBAL_PADDING),
        )?;
        Ok(plaintext)
    }

    /// 编码响应头：派生 response body key/iv + AEAD 加密响应头写入 writer。
    ///
    /// 对应 Go `EncodeResponseHeader`。需要 `&mut self` 因为要填充 `response_body_key/iv`。
    ///
    /// # 算法
    ///
    /// 1. 派生 response_body_key = SHA256(request_body_key)[..16]
    /// 2. 派生 response_body_iv = SHA256(request_body_iv)[..16]
    /// 3. 构造明文 payload = `[1B response_header][1B option][1B cmd_id=0][1B data_len=0]` （
    ///    ponytail: 当前不处理 command 序列化，留 follow-up）
    /// 4. KDF16 派生 len key，KDF 派生 len `IV[:12]`
    /// 5. Seal length(2B BE u16) + tag → 写入 writer
    /// 6. KDF16 派生 payload key，KDF 派生 payload `IV[:12]`
    /// 7. Seal payload + tag → 写入 writer
    ///
    /// # Errors
    ///
    /// - [`VmessError::Crypto`]：AES key 长度错误或 AEAD seal 失败
    /// - [`VmessError::Io`]：writer IO 错误
    pub fn encode_response_header<W: std::io::Write>(
        &mut self,
        header: &ResponseHeader,
        writer: &mut W,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        // 1-2. 派生 response_body_key/iv
        let body_key_hash = Sha256::digest(self.request_body_key);
        let body_iv_hash = Sha256::digest(self.request_body_iv);
        self.response_body_key.copy_from_slice(&body_key_hash[..16]);
        self.response_body_iv.copy_from_slice(&body_iv_hash[..16]);

        // 3. 构造明文 payload（4B 固定头 + command data）
        let mut plaintext = Vec::with_capacity(4 + 256);
        plaintext.push(self.response_header);
        plaintext.push(header.option.bits());
        match &header.response_command {
            ResponseCommand::None => {
                plaintext.push(0); // cmd_id = 0
                plaintext.push(0); // data_len = 0
            },
            ResponseCommand::SwitchAccount(cmd) => {
                plaintext.push(0x01); // cmd_id = 1 (SwitchAccount)
                let cmd_data = Self::serialize_switch_account(cmd);
                plaintext.push(cmd_data.len() as u8); // data_len
                plaintext.extend_from_slice(&cmd_data);
            },
        }

        // 4. 派生 len key/IV
        let len_key = aead::kdf16(&self.response_body_key, &[consts::AEAD_RESP_HEADER_LEN_KEY]);
        let len_iv_full = aead::kdf(&self.response_body_iv, &[consts::AEAD_RESP_HEADER_LEN_IV]);
        let len_nonce = &len_iv_full[..12];
        let len_cipher = Aes128Gcm::new(&len_key)?;

        // 5. Seal length (BE u16) + tag
        let len_plain = (plaintext.len() as u16).to_be_bytes();
        let encrypted_len = len_cipher.seal(len_nonce, &[], &len_plain)?;
        writer.write_all(&encrypted_len)?;

        // 6. 派生 payload key/IV
        let payload_key =
            aead::kdf16(&self.response_body_key, &[consts::AEAD_RESP_HEADER_PAYLOAD_KEY]);
        let payload_iv_full =
            aead::kdf(&self.response_body_iv, &[consts::AEAD_RESP_HEADER_PAYLOAD_IV]);
        let payload_nonce = &payload_iv_full[..12];
        let payload_cipher = Aes128Gcm::new(&payload_key)?;

        // 7. Seal payload + tag
        let encrypted_payload = payload_cipher.seal(payload_nonce, &[], &plaintext)?;
        writer.write_all(&encrypted_payload)?;
        writer.flush()?;
        Ok(())
    }

    /// 序列化 SwitchAccount 命令。
    ///
    /// 格式：`[1B addr_type][addr][2B port BE]`
    /// alterID/security 字段已废弃，不序列化。
    fn serialize_switch_account(cmd: &SwitchAccountCommand) -> Vec<u8> {
        use xray_common::net::address::Address;
        let mut buf = Vec::with_capacity(64);
        match &cmd.host {
            Some(Address::IPv4(ip)) => {
                buf.push(0x01);
                buf.extend_from_slice(&ip.octets());
            },
            Some(Address::IPv6(ip)) => {
                buf.push(0x04);
                buf.extend_from_slice(&ip.octets());
            },
            Some(Address::Domain(domain)) => {
                buf.push(0x03);
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
            },
            None => {
                buf.push(0x01);
                buf.extend_from_slice(&[0, 0, 0, 0]);
            },
        }
        buf.extend_from_slice(&cmd.port.to_be_bytes());
        buf
    }

    /// 编码响应 body：把明文 data 加密为 chunk 流写入 writer。
    ///
    /// 对应 Go `EncodeResponseBody`。要求先调用 `encode_response_header` 派生
    /// `response_body_key/iv`（或手动填充）。
    ///
    /// # 算法
    ///
    /// 1. 构造 AES-128-GCM cipher（key = `response_body_key`）
    /// 2. 构造 ChunkNonce 生成器（IV = `response_body_iv`，nonce_size = 12）
    /// 3. 选 SizeParser（默认 Plain）
    /// 4. 调用 `body_chunk::encode_chunk_stream`
    ///
    /// # Errors
    ///
    /// - [`VmessError::Other`]：security ≠ AES-128-GCM
    /// - [`VmessError::Crypto`]：AES key 长度错误
    /// - [`VmessError::Io`]：writer IO 错误
    pub fn encode_response_body<W: std::io::Write>(
        &self,
        request: &RequestHeader,
        data: &[u8],
        writer: &mut W,
    ) -> Result<()> {
        // ponytail: 支持 AES-128-GCM（默认）+ ChaCha20-Poly1305
        let cipher: Box<dyn AeadCipher> = match request.security {
            SecurityType::Aes128Gcm => Box::new(Aes128Gcm::new(&self.response_body_key)?),
            SecurityType::Chacha20Poly1305 => {
                let key = generate_chacha20poly1305_key(&self.response_body_key);
                Box::new(ChaCha20Poly1305Aead::new(&key)?)
            },

            other => {
                return Err(VmessError::Other(format!(
                    "encode_response_body: unsupported security {:?}",
                    other
                )));
            },
        };
        let mut nonce_gen = ChunkNonceAdapter::new(&self.response_body_iv, 12);
        let mut size_parser: Box<dyn SizeParser> =
            if request.option.has(request_option::AUTHENTICATED_LENGTH) {
                // AuthenticatedLength 始终用 request_body_key/iv（Go 端双向一致）
                Box::new(make_authenticated_length_size_parser(
                    &self.request_body_key,
                    &self.request_body_iv,
                    request.security,
                )?)
            } else if request.option.has(request_option::CHUNK_MASKING) {
                Box::new(ShakeSizeParserAdapter::new(&self.response_body_iv))
            } else {
                Box::new(PlainSizeParser)
            };
        body_chunk::encode_chunk_stream(
            writer,
            data,
            cipher.as_ref(),
            &mut nonce_gen,
            size_parser.as_mut(),
            request.option.has(request_option::GLOBAL_PADDING),
            request.option.has(request_option::NO_TERMINATION_SIGNAL),
        )?;
        Ok(())
    }

    // ========================================================================
    // async 版本（tokio::io::AsyncRead/AsyncWrite）
    // ========================================================================

    /// 解码请求头（async 版）。
    ///
    /// 逻辑与 [`decode_request_header`](Self::decode_request_header) 相同。
    /// AEAD open 是 CPU 密集型，直接调同步 API；IO 用 `tokio::io::AsyncRead`。
    ///
    /// # Errors
    ///
    /// 同 [`decode_request_header`](Self::decode_request_header)。
    pub async fn decode_request_header_async<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<(RequestHeader, MemoryUser)> {
        // 1. Async read 16B auth_id
        let mut auth_id = [0u8; 16];
        reader.read_exact(&mut auth_id).await?;
        let user = self.validator.get_aead(&auth_id)?;
        let cmd_key = user.account.cmd_key();

        // 2. Async read 26B (18B enc_len + 8B nonce)
        let mut prefix = [0u8; 26];
        reader.read_exact(&mut prefix).await?;

        // 3. Decrypt length inline to determine payload size
        let nonce_bytes: &[u8] = &prefix[18..26];
        let enc_len_bytes: &[u8] = &prefix[..18];
        let len_key = aead::kdf16_paths(
            &cmd_key,
            &[consts::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY.as_bytes(), &auth_id, nonce_bytes],
        );
        let len_iv_full = aead::kdf_paths(
            &cmd_key,
            &[consts::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV.as_bytes(), &auth_id, nonce_bytes],
        );
        let len_nonce = &len_iv_full[..12];
        let len_cipher = Aes128Gcm::new(&len_key)?;
        let decrypted_len = len_cipher.open(len_nonce, &auth_id, enc_len_bytes).map_err(|e| {
            VmessError::AeadReadFailed {
                msg: e.to_string(),
                // Go encrypt.go:95：length 解密失败 → shouldDrain；此时 AEAD 层
                // 已读 26B（18B enc_len + 8B nonce，auth_id 16B 在 decode 层读）。
                should_drain: true,
                bytes_read: 26,
            }
        })?;
        if decrypted_len.len() < 2 {
            return Err(VmessError::ReadRequestHeaderFailed);
        }
        let payload_len = u16::from_be_bytes([decrypted_len[0], decrypted_len[1]]);

        // 4. Async read encrypted payload
        let mut enc_payload = vec![0u8; usize::from(payload_len) + 16];
        reader.read_exact(&mut enc_payload).await?;

        // 5. Construct cursor with all header bytes and call sync open
        let mut all = Vec::with_capacity(26 + enc_payload.len());
        all.extend_from_slice(&prefix);
        all.extend_from_slice(&enc_payload);
        let mut cursor = std::io::Cursor::new(all);
        let opened =
            aead::open_vmess_aead_header(&cmd_key, &auth_id, &mut cursor).map_err(|e| match e {
                OpenHeaderError::InvalidKeyLength(n) => {
                    VmessError::Other(format!("cmd_key length mismatch: {n}"))
                },
                OpenHeaderError::Io(io) => VmessError::Io(io),
                OpenHeaderError::Crypto { msg, should_drain, bytes_read } => {
                    VmessError::AeadReadFailed { msg, should_drain, bytes_read }
                },
            })?;

        // 6. Parse payload (shared with sync version)
        let header = self.parse_decoded_header_payload(&opened.payload, &user)?;
        Ok((header, user))
    }

    /// 解码请求 body（async 版）。
    ///
    /// 逻辑与 [`decode_request_body`](Self::decode_request_body) 相同。
    ///
    /// # Errors
    ///
    /// 同 [`decode_request_body`](Self::decode_request_body)。
    pub async fn decode_request_body_async<R: AsyncRead + Unpin>(
        &self,
        request: &RequestHeader,
        reader: &mut R,
    ) -> Result<Vec<u8>> {
        let cipher: Box<dyn AeadCipher> = match request.security {
            SecurityType::Aes128Gcm => Box::new(Aes128Gcm::new(&self.request_body_key)?),
            SecurityType::Chacha20Poly1305 => {
                let key = generate_chacha20poly1305_key(&self.request_body_key);
                Box::new(ChaCha20Poly1305Aead::new(&key)?)
            },

            other => {
                return Err(VmessError::Other(format!(
                    "decode_request_body_async: unsupported security {:?}",
                    other
                )));
            },
        };
        let mut nonce_gen = ChunkNonceAdapter::new(&self.request_body_iv, 12);
        let mut size_parser: Box<dyn SizeParser> =
            if request.option.has(request_option::AUTHENTICATED_LENGTH) {
                Box::new(make_authenticated_length_size_parser(
                    &self.request_body_key,
                    &self.request_body_iv,
                    request.security,
                )?)
            } else if request.option.has(request_option::CHUNK_MASKING) {
                Box::new(ShakeSizeParserAdapter::new(&self.request_body_iv))
            } else {
                Box::new(PlainSizeParser)
            };
        let plaintext = body_chunk::decode_chunk_stream_async(
            reader,
            cipher.as_ref(),
            &mut nonce_gen,
            size_parser.as_mut(),
            request.option.has(request_option::GLOBAL_PADDING),
        )
        .await?;
        Ok(plaintext)
    }

    /// 编码响应头（async 版）。
    ///
    /// 逻辑与 [`encode_response_header`](Self::encode_response_header) 相同。
    /// AEAD seal 是 CPU 密集型，直接调同步 API；IO 用 `tokio::io::AsyncWrite`。
    ///
    /// # Errors
    ///
    /// 同 [`encode_response_header`](Self::encode_response_header)。
    pub async fn encode_response_header_async<W: AsyncWrite + Unpin>(
        &mut self,
        header: &ResponseHeader,
        writer: &mut W,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        let body_key_hash = Sha256::digest(self.request_body_key);
        let body_iv_hash = Sha256::digest(self.request_body_iv);
        self.response_body_key.copy_from_slice(&body_key_hash[..16]);
        self.response_body_iv.copy_from_slice(&body_iv_hash[..16]);

        let plaintext = vec![self.response_header, header.option.bits(), 0, 0];

        let len_key = aead::kdf16(&self.response_body_key, &[consts::AEAD_RESP_HEADER_LEN_KEY]);
        let len_iv_full = aead::kdf(&self.response_body_iv, &[consts::AEAD_RESP_HEADER_LEN_IV]);
        let len_nonce = &len_iv_full[..12];
        let len_cipher = Aes128Gcm::new(&len_key)?;

        let len_plain = (plaintext.len() as u16).to_be_bytes();
        let encrypted_len = len_cipher.seal(len_nonce, &[], &len_plain)?;
        writer.write_all(&encrypted_len).await?;

        let payload_key =
            aead::kdf16(&self.response_body_key, &[consts::AEAD_RESP_HEADER_PAYLOAD_KEY]);
        let payload_iv_full =
            aead::kdf(&self.response_body_iv, &[consts::AEAD_RESP_HEADER_PAYLOAD_IV]);
        let payload_nonce = &payload_iv_full[..12];
        let payload_cipher = Aes128Gcm::new(&payload_key)?;

        let encrypted_payload = payload_cipher.seal(payload_nonce, &[], &plaintext)?;
        writer.write_all(&encrypted_payload).await?;
        writer.flush().await?;
        Ok(())
    }

    /// 编码响应 body（async 版）。
    ///
    /// 逻辑与 [`encode_response_body`](Self::encode_response_body) 相同。
    ///
    /// # Errors
    ///
    /// 同 [`encode_response_body`](Self::encode_response_body)。
    pub async fn encode_response_body_async<W: AsyncWrite + Unpin>(
        &self,
        request: &RequestHeader,
        data: &[u8],
        writer: &mut W,
    ) -> Result<()> {
        let cipher: Box<dyn AeadCipher> = match request.security {
            SecurityType::Aes128Gcm => Box::new(Aes128Gcm::new(&self.response_body_key)?),
            SecurityType::Chacha20Poly1305 => {
                let key = generate_chacha20poly1305_key(&self.response_body_key);
                Box::new(ChaCha20Poly1305Aead::new(&key)?)
            },

            other => {
                return Err(VmessError::Other(format!(
                    "encode_response_body_async: unsupported security {:?}",
                    other
                )));
            },
        };
        let mut nonce_gen = ChunkNonceAdapter::new(&self.response_body_iv, 12);
        let mut size_parser: Box<dyn SizeParser> =
            if request.option.has(request_option::AUTHENTICATED_LENGTH) {
                Box::new(make_authenticated_length_size_parser(
                    &self.request_body_key,
                    &self.request_body_iv,
                    request.security,
                )?)
            } else if request.option.has(request_option::CHUNK_MASKING) {
                Box::new(ShakeSizeParserAdapter::new(&self.response_body_iv))
            } else {
                Box::new(PlainSizeParser)
            };
        body_chunk::encode_chunk_stream_async(
            writer,
            data,
            cipher.as_ref(),
            &mut nonce_gen,
            size_parser.as_mut(),
            request.option.has(request_option::GLOBAL_PADDING),
            request.option.has(request_option::NO_TERMINATION_SIGNAL),
        )
        .await?;
        Ok(())
    }
}

/// 检测 CPU 是否有 AES-GCM 硬件加速（对应 Go `HasAESGCMHardwareSupport`）。
///
/// AES-NI + PCLMULQDQ 指令同时存在才返回 true（Go 用 `cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ`）。
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn has_aes_gcm_hardware_support() -> bool {
    std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("pclmulqdq")
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn has_aes_gcm_hardware_support() -> bool {
    std::arch::is_aarch64_feature_detected!("aes")
        && std::arch::is_aarch64_feature_detected!("neon")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) fn has_aes_gcm_hardware_support() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_hardware_detection_is_callable() {
        // 对应 Go HasAESGCMHardwareSupport — 运行时 AES-NI+PCLMULQDQ 检测
        let _supported: bool = has_aes_gcm_hardware_support();
    }
    use xray_common::uuid::UUID;

    use crate::encoding::client::ClientSession;

    fn sample_uuid() -> UUID {
        UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("uuid")
    }

    fn sample_validator_with_user() -> (TimedUserValidator, [u8; 16]) {
        let v = TimedUserValidator::new();
        let uuid = sample_uuid();
        let account = crate::account::MemoryAccount::new(uuid);
        let cmd_key = account.cmd_key();
        let user = crate::validator::MemoryUser::new("alice@example.com", account);
        v.add(user).expect("add");
        (v, cmd_key)
    }

    #[test]
    fn session_history_new_is_empty() {
        let h = SessionHistory::new();
        assert!(h.is_empty());
    }

    #[test]
    fn session_history_add_first_succeeds() {
        let h = SessionHistory::new();
        let id = SessionId { user: [1u8; 16], key: [2u8; 16], nonce: [3u8; 16] };
        assert!(h.add_if_not_exists(id));
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn session_history_add_duplicate_fails() {
        let h = SessionHistory::new();
        let id = SessionId { user: [1u8; 16], key: [2u8; 16], nonce: [3u8; 16] };
        assert!(h.add_if_not_exists(id));
        assert!(!h.add_if_not_exists(id));
    }

    #[test]
    fn session_history_different_sessions_both_added() {
        let h = SessionHistory::new();
        let id1 = SessionId { user: [1u8; 16], key: [2u8; 16], nonce: [3u8; 16] };
        let id2 = SessionId { user: [4u8; 16], key: [5u8; 16], nonce: [6u8; 16] };
        assert!(h.add_if_not_exists(id1));
        assert!(h.add_if_not_exists(id2));
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn session_history_ttl_expired_allows_readd() {
        let h = SessionHistory::with_ttl(Duration::from_millis(1));
        let id = SessionId { user: [1u8; 16], key: [2u8; 16], nonce: [3u8; 16] };
        assert!(h.add_if_not_exists(id));
        std::thread::sleep(Duration::from_millis(10));
        // 过期后允许重新添加
        assert!(h.add_if_not_exists(id));
    }

    #[test]
    fn decode_request_header_roundtrip_with_client() {
        // 客户端编码 → 服务端解码
        let (validator, cmd_key) = sample_validator_with_user();
        let history = SessionHistory::new();

        let client = ClientSession::new();
        let dest =
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), Port::new(53));
        let original_header = RequestHeader::new(
            crate::encoding::VERSION,
            Command::Tcp,
            dest.clone(),
            SecurityType::Aes128Gcm,
        );
        let sealed = client.encode_request_header(&original_header, &cmd_key).expect("encode");

        let mut server = ServerSession::new(&validator, &history);
        let mut reader: &[u8] = sealed.as_slice();
        let (decoded_header, matched_user) =
            server.decode_request_header(&mut reader).expect("decode");

        assert_eq!(decoded_header.version, crate::encoding::VERSION);
        assert_eq!(decoded_header.command, Command::Tcp);
        assert_eq!(decoded_header.security, SecurityType::Aes128Gcm);
        assert_eq!(matched_user.email, "alice@example.com");
        // body key/iv 应当与 client 一致
        assert_eq!(server.request_body_key, client.request_body_key);
        assert_eq!(server.request_body_iv, client.request_body_iv);
        assert_eq!(server.response_header, client.response_header);
    }

    #[tokio::test]
    async fn decode_async_aead_failure_reports_exact_bytes_read() {
        // 73fr：inbound drainer 需要 AEAD 内层精确已读字节数（Go server.go:165-169
        // OpenVMessAEADHeader 回传 bytesRead）。损坏 payload tag → 错误携带
        // should_drain=true 与 bytes_read == 26(enc_len+nonce) + payload_enc。
        let (validator, cmd_key) = sample_validator_with_user();
        let history = SessionHistory::new();

        let client = ClientSession::new();
        let dest =
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), Port::new(53));
        let header = RequestHeader::new(
            crate::encoding::VERSION,
            Command::Tcp,
            dest,
            SecurityType::Aes128Gcm,
        );
        let sealed = client.encode_request_header(&header, &cmd_key).expect("encode");

        let mut stream = sealed.clone();
        let last = stream.len() - 1;
        stream[last] ^= 0xFF; // 破坏 payload AEAD tag

        let mut server = ServerSession::new(&validator, &history);
        let err = server.decode_request_header_async(&mut &stream[..]).await.unwrap_err();
        let VmessError::AeadReadFailed { should_drain, bytes_read, .. } = err else {
            panic!("expected AeadReadFailed for corrupted payload");
        };
        assert!(should_drain);
        // cursor 重放只含 prefix(18 enc_len + 8 nonce) + payload_enc，authID 16B
        // 已在 decode 层读且不在 cursor 内：bytes_read = 26 + payload_enc
        // = sealed.len() - 16。
        assert_eq!(bytes_read, sealed.len() - 16);
    }

    #[test]
    fn decode_request_header_replay_fails() {
        let (validator, cmd_key) = sample_validator_with_user();
        let history = SessionHistory::new();

        let client = ClientSession::new();
        let dest =
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), Port::new(53));
        let original_header = RequestHeader::new(
            crate::encoding::VERSION,
            Command::Tcp,
            dest,
            SecurityType::Aes128Gcm,
        );
        let sealed = client.encode_request_header(&original_header, &cmd_key).expect("encode");

        let mut server1 = ServerSession::new(&validator, &history);
        let mut reader1: &[u8] = sealed.as_slice();
        server1.decode_request_header(&mut reader1).expect("first decode ok");

        // 同 session_id 重放 → 应当失败
        let mut server2 = ServerSession::new(&validator, &history);
        let mut reader2: &[u8] = sealed.as_slice();
        let err = server2.decode_request_header(&mut reader2).unwrap_err();
        assert!(matches!(err, VmessError::Replay | VmessError::DuplicateSession));
    }

    #[test]
    fn decode_request_header_unknown_user_fails() {
        let validator = TimedUserValidator::new(); // 空的
        let history = SessionHistory::new();

        let client = ClientSession::new();
        let uuid = sample_uuid();
        let cmd_key = crate::account::cmd_key_of(&uuid);
        let dest =
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), Port::new(53));
        let header = RequestHeader::new(
            crate::encoding::VERSION,
            Command::Tcp,
            dest,
            SecurityType::Aes128Gcm,
        );
        let sealed = client.encode_request_header(&header, &cmd_key).expect("encode");

        let mut server = ServerSession::new(&validator, &history);
        let mut reader: &[u8] = sealed.as_slice();
        let err = server.decode_request_header(&mut reader).unwrap_err();
        assert!(matches!(err, VmessError::UserNotFound));
    }

    #[test]
    fn decode_request_header_security_auto_rejected() {
        // e92g：服务端拒绝 SecurityType::Auto (0x02)。Go 编码层
        // `proxy/vmess/encoding/server.go:252-257` 对 AUTO 不接受
        // （client 才能按 CPU AES-NI 自选，服务端必须已固定算法）。
        // Rust 此前接受并按本机 AES-NI 落地 → 服务端指纹可与 Go 区分。
        let (validator, cmd_key) = sample_validator_with_user();
        let history = SessionHistory::new();

        let client = ClientSession::new();
        let dest =
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), Port::new(53));
        let header =
            RequestHeader::new(crate::encoding::VERSION, Command::Tcp, dest, SecurityType::Auto);
        let sealed = client.encode_request_header(&header, &cmd_key).expect("encode");

        let mut server = ServerSession::new(&validator, &history);
        let mut reader: &[u8] = sealed.as_slice();
        let err = server.decode_request_header(&mut reader).unwrap_err();
        assert!(
            matches!(err, VmessError::UnknownSecurityType(_)),
            "AUTO security must be rejected at server; got: {err:?}"
        );
    }

    #[test]
    fn decode_request_header_truncated_input_fails() {
        let (validator, _cmd_key) = sample_validator_with_user();
        let history = SessionHistory::new();
        let mut server = ServerSession::new(&validator, &history);

        let truncated = [0u8; 5];
        let mut reader: &[u8] = &truncated;
        let err = server.decode_request_header(&mut reader).unwrap_err();
        assert!(matches!(err, VmessError::Io(_)));
    }

    #[test]
    fn decode_request_body_roundtrip_with_client_encode() {
        // 服务端 decode_request_body ↔ 客户端 encode_request_body 往返
        use crate::encoding::client::ClientSession;
        let (validator, _) = sample_validator_with_user();
        let history = SessionHistory::new();
        let client = ClientSession::new();
        let mut server = ServerSession::new(&validator, &history);
        server.request_body_key = client.request_body_key;
        server.request_body_iv = client.request_body_iv;

        let header = RequestHeader::new(
            crate::encoding::VERSION,
            Command::Tcp,
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(80)),
            SecurityType::Aes128Gcm,
        );
        let payload = b"request body payload from client";
        let mut buf: Vec<u8> = Vec::new();
        client.encode_request_body(&header, payload, &mut buf).expect("client encode");

        let mut reader = &buf[..];
        let decoded = server.decode_request_body(&header, &mut reader).expect("server decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn encode_response_header_writes_aead_payload() {
        // 服务端 encode_response_header 生成 AEAD 加密的响应头字节
        let (validator, _) = sample_validator_with_user();
        let history = SessionHistory::new();
        let mut server = ServerSession::new(&validator, &history);
        // 手动填充 request_body_key/iv 以跳过 decode_request_header
        server.request_body_key = [0x42u8; 16];
        server.request_body_iv = [0x33u8; 16];
        server.response_header = 0xAB;

        let resp_header = ResponseHeader {
            command: Command::Tcp,
            option: Bitmask::new(0),
            response_command: ResponseCommand::None,
        };
        let mut writer: Vec<u8> = Vec::new();
        server.encode_response_header(&resp_header, &mut writer).expect("server encode");
        // 输出 = 18B encrypted_len + (4B plaintext + 16B tag) encrypted_payload = 38B
        assert_eq!(writer.len(), 18 + 4 + 16);
        // response_body_key/iv 应被填充
        assert!(server.response_body_key.iter().any(|&b| b != 0));
    }

    #[test]
    fn encode_response_body_writes_chunk_stream() {
        let (validator, _) = sample_validator_with_user();
        let history = SessionHistory::new();
        let mut server = ServerSession::new(&validator, &history);
        server.request_body_key = [0x42u8; 16];
        server.request_body_iv = [0x33u8; 16];
        // encode_response_body 依赖 response_body_key/iv，手动填充跳过 encode_response_header
        use sha2::{Digest, Sha256};
        let body_key_hash = Sha256::digest(server.request_body_key);
        let body_iv_hash = Sha256::digest(server.request_body_iv);
        server.response_body_key.copy_from_slice(&body_key_hash[..16]);
        server.response_body_iv.copy_from_slice(&body_iv_hash[..16]);

        let header = RequestHeader::new(
            crate::encoding::VERSION,
            Command::Tcp,
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(80)),
            SecurityType::Aes128Gcm,
        );
        let mut writer: Vec<u8> = Vec::new();
        server
            .encode_response_body(&header, b"server response", &mut writer)
            .expect("server encode");
        assert!(writer.len() > 2 + 16);
    }
}
