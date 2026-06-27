//! VMess 服务端会话：解码请求头 + 反重放 SessionHistory + body 包装 trait stub。
//!
//! 对应 Go 版本 `proxy/vmess/encoding/server.go`。
//!
//! # 实现范围
//!
//! - **完整**：`ServerSession::decode_request_header`（AEAD 解密 + 字段解析 + FNV1a 校验）
//!   + `SessionHistory`（防重放，session_id=16B user + 16B key + 16B nonce）
//! - **trait stub**：`decode_request_body` / `encode_response_header` / `encode_response_body`
//!   依赖 `xray-crypto` 的 chunk reader/writer + AES-CFB 流包装链（待接入）。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use xray_common::bitmask::Bitmask;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_common::protocol::{Command, RequestHeader, SecurityType};

use crate::aead::{self, OpenHeaderError};
use crate::encoding::{authenticate, read_address_port};
use crate::error::{Result, VmessError};
use crate::validator::{MemoryUser, TimedUserValidator, Validator};

/// Session ID：用于反重放，由 user_uuid + requestBodyKey + requestBodyIV 组成。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId {
    user: [u8; 16],
    key: [u8; 16],
    nonce: [u8; 16],
}

/// 会话历史（对应 Go `SessionHistory`）。
///
/// ponytail: Go 端用 `task.Periodic` 周期清理过期 session（30s）。
/// 本实现简化为：每次 `add` 时检查过期（lazy 清理），过期阈值 3 分钟。
pub struct SessionHistory {
    inner: Mutex<HashMap<SessionId, Instant>>,
    ttl: Duration,
}

impl SessionHistory {
    /// 创建空 history，TTL=3 分钟（对应 Go `time.Minute * 3`）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(180),
        }
    }

    /// 用自定义 TTL。
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// 添加 session，若已存在且未过期则返回 false（拒绝）。
    pub fn add_if_not_exists(&self, session: SessionId) -> bool {
        let mut inner = self.inner.lock().expect("history poisoned");
        let now = Instant::now();
        // lazy 清理过期项
        inner.retain(|_, expire| *expire > now);
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
        let opened = aead::open_vmess_aead_header(&cmd_key, &auth_id, reader)
            .map_err(|e| match e {
                OpenHeaderError::InvalidKeyLength(n) => {
                    VmessError::Other(format!("cmd_key length mismatch: {n}"))
                }
                OpenHeaderError::Io(io) => VmessError::Io(io),
                OpenHeaderError::Crypto { msg, should_drain, bytes_read } => {
                    VmessError::AeadReadFailed(format!(
                        "msg={msg}, should_drain={should_drain}, bytes_read={bytes_read}"
                    ))
                }
            })?;
        let payload = opened.payload;

        // 3. 解析 38B base
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

        // 派生 response body key/IV
        use sha2::{Digest, Sha256};
        let body_key_hash = Sha256::digest(&request_body_key);
        let body_iv_hash = Sha256::digest(&request_body_iv);
        self.response_body_key.copy_from_slice(&body_key_hash[..16]);
        self.response_body_iv.copy_from_slice(&body_iv_hash[..16]);

        // 4. SessionHistory 反重放
        let session = SessionId {
            user: *user.account.id.uuid().as_bytes(),
            key: request_body_key,
            nonce: request_body_iv,
        };
        if !self.session_history.add_if_not_exists(session) {
            return Err(VmessError::DuplicateSession);
        }

        // 5. 解析地址 + 端口（非 Mux）
        let command = Command::from_u8(command_byte).ok_or_else(|| {
            VmessError::UnknownCommand
        })?;

        let (address, port, addr_consumed) = match command {
            Command::Mux => (
                Address::Domain("v1.mux.cool".to_string()),
                0u16,
                0usize,
            ),
            Command::Tcp | Command::Udp => {
                let (addr, port, consumed) = read_address_port(&payload[38..])?;
                (addr, port, consumed)
            }
        };

        // 6. 验证 padding 长度（payload 长度校验）
        let base_len = 38 + addr_consumed + padding_len + 4;
        if payload.len() < base_len {
            return Err(VmessError::ReadPaddingFailed);
        }

        // 7. FNV1a 校验
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

        // 8. 安全类型检查
        if matches!(security, SecurityType::Unknown | SecurityType::Auto) {
            return Err(VmessError::UnknownSecurityType(security.as_u8() as i32));
        }

        // 构造 RequestHeader
        let dest = Destination::tcp(address, Port::new(port));
        let mut header = RequestHeader::new(version, command, dest, security);
        header.option = Bitmask::new(option_byte);

        Ok((header, user))
    }

    /// 解码请求 body（对应 Go `DecodeRequestBody`）。
    ///
    /// 当前 stub：依赖 `xray-crypto` 的 chunk reader + AES-CFB/CTR 流包装链。
    ///
    /// # Errors
    ///
    /// 始终返回 [`VmessError::NotImplemented`]。
    pub fn decode_request_body<R: std::io::Read>(
        &self,
        _request: &RequestHeader,
        _reader: &mut R,
    ) -> Result<()> {
        Err(VmessError::NotImplemented("decode_request_body: requires xray-crypto AuthenticationReader chain"))
    }

    /// 编码响应头（对应 Go `EncodeResponseHeader`）。
    ///
    /// 当前 stub：依赖 AES-CFB 流写入 + AEAD 加密响应头。
    ///
    /// # Errors
    ///
    /// 始终返回 [`VmessError::NotImplemented`]。
    pub fn encode_response_header<W: std::io::Write>(
        &self,
        _option: u8,
        _writer: &mut W,
    ) -> Result<()> {
        Err(VmessError::NotImplemented("encode_response_header: requires AES-CFB writer + AEAD response header encrypt"))
    }

    /// 编码响应 body（对应 Go `EncodeResponseBody`）。
    ///
    /// 当前 stub：依赖 `xray-crypto` 的 AuthenticationWriter + ChunkSizeParser 链。
    ///
    /// # Errors
    ///
    /// 始终返回 [`VmessError::NotImplemented`]。
    pub fn encode_response_body<W: std::io::Write>(
        &self,
        _request: &RequestHeader,
        _writer: &mut W,
    ) -> Result<()> {
        Err(VmessError::NotImplemented("encode_response_body: requires xray-crypto AuthenticationWriter chain"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::client::ClientSession;
    use xray_common::uuid::UUID;

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
        let id = SessionId {
            user: [1u8; 16],
            key: [2u8; 16],
            nonce: [3u8; 16],
        };
        assert!(h.add_if_not_exists(id));
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn session_history_add_duplicate_fails() {
        let h = SessionHistory::new();
        let id = SessionId {
            user: [1u8; 16],
            key: [2u8; 16],
            nonce: [3u8; 16],
        };
        assert!(h.add_if_not_exists(id));
        assert!(!h.add_if_not_exists(id));
    }

    #[test]
    fn session_history_different_sessions_both_added() {
        let h = SessionHistory::new();
        let id1 = SessionId {
            user: [1u8; 16],
            key: [2u8; 16],
            nonce: [3u8; 16],
        };
        let id2 = SessionId {
            user: [4u8; 16],
            key: [5u8; 16],
            nonce: [6u8; 16],
        };
        assert!(h.add_if_not_exists(id1));
        assert!(h.add_if_not_exists(id2));
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn session_history_ttl_expired_allows_readd() {
        let h = SessionHistory::with_ttl(Duration::from_millis(1));
        let id = SessionId {
            user: [1u8; 16],
            key: [2u8; 16],
            nonce: [3u8; 16],
        };
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
        let dest = Destination::tcp(
            Address::ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            Port::new(53),
        );
        let original_header = RequestHeader::new(
            crate::encoding::VERSION,
            Command::Tcp,
            dest.clone(),
            SecurityType::Aes128Gcm,
        );
        let sealed = client.encode_request_header(&original_header, &cmd_key).expect("encode");

        let mut server = ServerSession::new(&validator, &history);
        let mut reader: &[u8] = sealed.as_slice();
        let (decoded_header, matched_user) = server.decode_request_header(&mut reader).expect("decode");

        assert_eq!(decoded_header.version, crate::encoding::VERSION);
        assert_eq!(decoded_header.command, Command::Tcp);
        assert_eq!(decoded_header.security, SecurityType::Aes128Gcm);
        assert_eq!(matched_user.email, "alice@example.com");
        // body key/iv 应当与 client 一致
        assert_eq!(server.request_body_key, client.request_body_key);
        assert_eq!(server.request_body_iv, client.request_body_iv);
        assert_eq!(server.response_header, client.response_header);
    }

    #[test]
    fn decode_request_header_replay_fails() {
        let (validator, cmd_key) = sample_validator_with_user();
        let history = SessionHistory::new();

        let client = ClientSession::new();
        let dest = Destination::tcp(
            Address::ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            Port::new(53),
        );
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
        let dest = Destination::tcp(
            Address::ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            Port::new(53),
        );
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
    fn decode_request_body_stub_returns_not_implemented() {
        let (validator, _) = sample_validator_with_user();
        let history = SessionHistory::new();
        let server = ServerSession::new(&validator, &history);
        let header = RequestHeader::new(
            crate::encoding::VERSION,
            Command::Tcp,
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(80)),
            SecurityType::Aes128Gcm,
        );
        let mut reader = &b""[..];
        let err = server.decode_request_body(&header, &mut reader).unwrap_err();
        assert!(matches!(err, VmessError::NotImplemented(_)));
    }

    #[test]
    fn encode_response_header_stub_returns_not_implemented() {
        let (validator, _) = sample_validator_with_user();
        let history = SessionHistory::new();
        let server = ServerSession::new(&validator, &history);
        let mut writer: Vec<u8> = Vec::new();
        let err = server.encode_response_header(0, &mut writer).unwrap_err();
        assert!(matches!(err, VmessError::NotImplemented(_)));
    }

    #[test]
    fn encode_response_body_stub_returns_not_implemented() {
        let (validator, _) = sample_validator_with_user();
        let history = SessionHistory::new();
        let server = ServerSession::new(&validator, &history);
        let header = RequestHeader::new(
            crate::encoding::VERSION,
            Command::Tcp,
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(80)),
            SecurityType::Aes128Gcm,
        );
        let mut writer: Vec<u8> = Vec::new();
        let err = server.encode_response_body(&header, &mut writer).unwrap_err();
        assert!(matches!(err, VmessError::NotImplemented(_)));
    }
}
