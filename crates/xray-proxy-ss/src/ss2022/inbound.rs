//! SS-2022 入站处理器（单用户、多用户、中继模式）。
//!
//! 对应 Go `proxy/shadowsocks_2022/inbound.go` + `inbound_multi.go` + `inbound_relay.go`。
//!
//! # 模式
//!
//! - [`Ss2022Inbound`]：单用户模式（ServerConfig）
//! - [`MultiUserInbound`]：多用户模式（MultiUserServerConfig）
//! - [`RelayInbound`]：中继模式（RelayServerConfig）
//!
//! # SS-2022 TCP 入站流程
//!
//! 1. 读 salt（len = key_size）
//! 2. 用 server PSK + salt 派生 session subkey（blake3）
//! 3. 构造 AEAD，nonce `[0;12]`
//! 4. open fixed-header-chunk：headerType + timestamp_BE_u64 + variableLen_BE_u16
//! 5. 验证 headerType（0=client）+ timestamp（防重放）
//! 6. open variable-header-chunk：addr+port + paddingLen + padding（尾部含客户端首段 payload，先于
//!    body 交付）
//! 7. 构造 SSStream 继续读写 body（下行首写自动发 sing writeResponse 响应头）

use std::{
    io,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use parking_lot::Mutex;
use tokio::{io::AsyncReadExt, net::TcpStream};
use xray_common::net::address::Address;
use xray_crypto::aead::{AeadCipher, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305Aead};

use crate::{
    error::{Result, SsError},
    protocol::addr_type,
    ss2022::{
        key::{
            CipherKind2022, decrypt_identity_header, derive_psk, derive_session_subkey,
            psk_from_base64, psk_identity,
        },
        replay::{REPLAY_WINDOW, SaltReplayFilter},
    },
    stream::SSStream,
};

// ============================================================================
// 公共类型
// ============================================================================

/// SS-2022 入站请求结果：目标地址 + 加密流 + 匹配的用户标识。
pub struct InboundResult {
    /// 目标地址。
    pub address: Address,
    /// 目标端口。
    pub port: u16,
    /// 加密流（可继续读写 body）。
    pub stream: SSStream<TcpStream>,
    /// 匹配的用户标识（email），单用户模式为配置的 email。
    pub user_email: String,
}

/// SS-2022 用户条目（PSK + email）。
#[derive(Debug, Clone)]
pub struct Ss2022User {
    /// 用户标识。
    pub email: String,
    /// 用户等级。
    pub level: u32,
    /// PSK（原始字节）。
    pub psk: Vec<u8>,
}

// ============================================================================
// 单用户入站
// ============================================================================

/// SS-2022 单用户入站处理器。
///
/// 对应 Go `Inbound` struct（`proxy/shadowsocks_2022/inbound.go`）。
pub struct Ss2022Inbound {
    psk: Vec<u8>,
    kind: CipherKind2022,
    email: String,
    /// 时间戳容忍窗口（秒），默认 30。
    timestamp_tolerance: u64,
    /// 明文 salt 重放过滤器（sing `replay.NewSimple(60s)` 语义，check 即注册）。
    replay: SaltReplayFilter,
}

impl Ss2022Inbound {
    /// 创建单用户入站。
    ///
    /// # Errors
    /// - [`SsError::InvalidCipherName`]：cipher 不支持。
    /// - [`SsError::InvalidPassword`]：PSK base64 解码失败或长度不匹配。
    /// - [`SsError::Ss2022MissingKey`]：PSK 为空。
    pub fn new(cipher: &str, psk_b64: &str, email: impl Into<String>) -> Result<Self> {
        let kind = CipherKind2022::from_name(cipher)?;
        let psk = derive_psk(&psk_from_base64(psk_b64)?, kind)?;
        Ok(Self {
            psk,
            kind,
            email: email.into(),
            timestamp_tolerance: 30,
            replay: SaltReplayFilter::new(REPLAY_WINDOW),
        })
    }

    /// 处理入站 TCP 连接：读 salt → 派生 subkey → 解密 header → 解析目标。
    ///
    /// # Errors
    /// - 透传 AEAD、IO、协议解析错误。
    pub async fn handle_conn(&self, conn: TcpStream) -> io::Result<InboundResult> {
        let result =
            read_ss2022_request(conn, &self.psk, self.kind, self.timestamp_tolerance, &self.replay)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(InboundResult {
            address: result.0,
            port: result.1,
            stream: result.2,
            user_email: self.email.clone(),
        })
    }

    /// 返回 cipher kind。
    #[must_use]
    pub fn kind(&self) -> CipherKind2022 {
        self.kind
    }

    /// 返回 server PSK（UDP relay 用）。
    #[must_use]
    pub fn psk(&self) -> &[u8] {
        &self.psk
    }
}

// ============================================================================
// 多用户入站
// ============================================================================

/// SS-2022 多用户入站处理器。
///
/// 对应 Go `MultiUserInbound` struct（`proxy/shadowsocks_2022/inbound_multi.go`）。
///
/// TCP 多用户识别：EIH（identity header）= AES-ECB(identitySubkey(iPSK, salt))，
/// 解密得 `psk_identity(uPSK)` 查用户表；session key 由命中的 uPSK 派生。
pub struct MultiUserInbound {
    /// 服务端主 PSK。
    psk: Vec<u8>,
    kind: CipherKind2022,
    /// 用户列表（`Arc<Mutex>` 支持动态增删）。
    ///
    /// 每项 = (user, psk_identity(user.psk))：identity 在用户装载/添加时
    /// 预计算一次（blake3），EIH 匹配退化为 16B memcmp，消除每连接 ×
    /// 用户数的哈希放大（对齐 Go `identityMap` 语义）。
    users: Arc<Mutex<Vec<(Ss2022User, [u8; 16])>>>,
    /// 时间戳容忍窗口（秒）。
    #[allow(dead_code)] // 时间戳校验由 header 时间戳直接比较承担；字段为配置面 Go 对齐保留
    timestamp_tolerance: u64,
    /// 明文 salt 重放过滤器（sing `replay.NewSimple(60s)` 语义，check 即注册）。
    replay: SaltReplayFilter,
}
impl MultiUserInbound {
    /// 创建多用户入站。
    ///
    /// # Errors
    /// - [`SsError::InvalidCipherName`]：cipher 不支持。
    /// - [`SsError::InvalidPassword`]：PSK base64 解码失败或长度不匹配。
    /// - [`SsError::Ss2022MissingKey`]：server PSK 为空。
    pub fn new(cipher: &str, server_psk_b64: &str, users: Vec<Ss2022User>) -> Result<Self> {
        let kind = CipherKind2022::from_name(cipher)?;
        let psk = derive_psk(&psk_from_base64(server_psk_b64)?, kind)?;
        let users = users
            .into_iter()
            .map(|u| {
                let psk = derive_psk(&u.psk, kind)?;
                let identity = psk_identity(&psk);
                Ok::<_, SsError>((Ss2022User { email: u.email, level: u.level, psk }, identity))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            psk,
            kind,
            users: Arc::new(Mutex::new(users)),
            timestamp_tolerance: 30,
            replay: SaltReplayFilter::new(REPLAY_WINDOW),
        })
    }

    /// 处理入站 TCP 连接：逐用户尝试解密，匹配成功返回结果。
    ///
    /// # Errors
    /// - [`SsError::Ss2022NoUserMatched`]：无用户匹配。
    /// - 透传其他错误。
    pub async fn handle_conn(&self, conn: TcpStream) -> io::Result<InboundResult> {
        let users = self.users.lock().clone();
        read_ss2022_request_multi(
            conn,
            &self.psk,
            self.kind,
            &users,
            self.timestamp_tolerance,
            &self.replay,
        )
        .await
        .map_err(|e| io::Error::other(e.to_string()))
    }

    /// 添加用户（对应 Go `AddUser`）。
    ///
    /// # Errors
    /// - [`SsError::EmptyEmail`]：email 为空。
    /// - [`SsError::InvalidPassword`]：PSK 长度不匹配。
    pub fn add_user(&self, user: Ss2022User) -> Result<()> {
        if user.email.is_empty() {
            return Err(SsError::EmptyEmail);
        }
        let psk = derive_psk(&user.psk, self.kind)?;
        let identity = psk_identity(&psk);
        let mut users = self.users.lock();
        if users.iter().any(|(u, _)| u.email == user.email) {
            return Err(SsError::UserNotFoundByEmail(format!(
                "User {} already exists",
                user.email
            )));
        }
        users.push((Ss2022User { email: user.email, level: user.level, psk }, identity));
        Ok(())
    }

    /// 删除用户（对应 Go `RemoveUser`）。
    ///
    /// # Errors
    /// - [`SsError::UserNotFoundByEmail`]：email 不存在。
    pub fn remove_user(&self, email: &str) -> Result<()> {
        let mut users = self.users.lock();
        let len_before = users.len();
        users.retain(|(u, _)| u.email != email);
        if users.len() == len_before {
            return Err(SsError::UserNotFoundByEmail(email.to_string()));
        }
        Ok(())
    }

    /// 返回 cipher kind（UDP relay 用）。
    #[must_use]
    pub fn kind(&self) -> CipherKind2022 {
        self.kind
    }

    /// 返回 server 主 PSK（UDP relay 的 EIH 解密 key）。
    #[must_use]
    pub fn server_psk(&self) -> &[u8] {
        &self.psk
    }

    /// 返回用户 (identity, psk) 表快照（UDP relay 的 EIH 用户识别）。
    #[must_use]
    pub fn udp_user_table(&self) -> Vec<([u8; 16], Vec<u8>)> {
        self.users.lock().iter().map(|(u, identity)| (*identity, u.psk.clone())).collect()
    }

    /// 当前用户数。
    #[must_use]
    pub fn users_count(&self) -> usize {
        self.users.lock().len()
    }
}

// ============================================================================
// 中继入站
// ============================================================================

/// SS-2022 中继目标。
#[derive(Debug, Clone)]
pub struct RelayDestination {
    /// 目标 PSK。
    pub key: Vec<u8>,
    /// 目标地址。
    pub address: Address,
    /// 目标端口。
    pub port: u16,
    /// 目标标识。
    pub email: String,
    /// 目标等级。
    pub level: u32,
}

/// SS-2022 中继入站处理器。
///
/// 对应 Go `RelayInbound` struct（`proxy/shadowsocks_2022/inbound_relay.go`）。
///
/// 中继模式：按用户匹配确定目标 destination，dispatcher 将流量转发到该目标。
pub struct RelayInbound {
    /// 服务端主 PSK。
    psk: Vec<u8>,
    kind: CipherKind2022,
    /// 中继目标列表。
    destinations: Vec<RelayDestination>,
    /// 时间戳容忍窗口（秒）。
    #[allow(dead_code)] // 时间戳校验由 header 时间戳直接比较承担；字段为配置面 Go 对齐保留
    timestamp_tolerance: u64,
}

impl RelayInbound {
    /// 创建中继入站。
    ///
    /// # Errors
    /// - [`SsError::InvalidCipherName`]：cipher 不支持。
    /// - [`SsError::InvalidPassword`]：PSK 解码/长度错误。
    /// - [`SsError::Ss2022MissingKey`]：server PSK 为空。
    /// - [`SsError::Ss2022UnsupportedMethod`]：非 AES cipher（中继规范限制）。
    pub fn new(
        cipher: &str,
        server_psk_b64: &str,
        destinations: Vec<RelayDestination>,
    ) -> Result<Self> {
        let kind = CipherKind2022::from_name(cipher)?;
        // 中继模式规范仅支持 AES（SIP022）
        if !matches!(kind, CipherKind2022::Aes128Gcm | CipherKind2022::Aes256Gcm) {
            return Err(SsError::Ss2022UnsupportedMethod(cipher.to_string()));
        }
        let psk = derive_psk(&psk_from_base64(server_psk_b64)?, kind)?;
        Ok(Self { psk, kind, destinations, timestamp_tolerance: 30 })
    }

    /// 处理中继入站 TCP 连接（SIP022 relay，对齐 sing-shadowsocks relay.go）：
    ///
    /// wire：`[salt][identity_header(16B)][发往 destination 的 EISS 流...]`
    /// - identity_header = AES(identitySubkey) 加密的 `blake3(dest_key)[..16]`
    /// - identitySubkey = blake3::derive_key("shadowsocks 2022 identity subkey", serverPSK||salt)
    ///
    /// 匹配 destination 后**剥掉 16B identity_header**，返回
    /// `(dest地址, dest端口, salt前缀, 剩余连接)`——转发字节 = `[salt] ++ 剩余原始字节`，
    /// 内层是端到端 EISS 加密，中继不解不改（回程同样原样）。
    ///
    /// # Errors
    /// - [`SsError::Ss2022NoUserMatched`]：无 destination 身份匹配。
    /// - 透传 IO 错误。
    pub async fn handle_conn_relay(
        &self,
        mut conn: TcpStream,
    ) -> io::Result<(Address, u16, Vec<u8>, TcpStream)> {
        let salt_len = self.kind.key_size();
        let mut salt = vec![0u8; salt_len];
        conn.read_exact(&mut salt).await?;
        let mut id_header = [0u8; crate::ss2022::key::IDENTITY_HEADER_LEN];
        conn.read_exact(&mut id_header).await?;

        // identity subkey → AES 单块解密
        let subkey = crate::ss2022::key::derive_identity_subkey(&self.psk, &salt, self.kind);
        let decrypted = crate::ss2022::key::ecb_block(self.kind, &subkey, &id_header, false)
            .map_err(|e| io::Error::other(e.to_string()))?;

        // 匹配 destination（blake3(dest.key)[..16]）
        let dest = self
            .destinations
            .iter()
            .find(|d| crate::ss2022::key::psk_identity(&d.key) == decrypted[..])
            .ok_or_else(|| io::Error::other(SsError::Ss2022NoUserMatched.to_string()))?;
        Ok((dest.address.clone(), dest.port, salt, conn))
    }

    /// 目标数量。
    #[must_use]
    pub fn destinations_count(&self) -> usize {
        self.destinations.len()
    }
}
// ============================================================================
// 协议层：SS-2022 请求读取
// ============================================================================

/// 从 subkey 构造 AEAD（与 client.rs 中 build_aead 一致）。
fn build_aead(kind: CipherKind2022, subkey: &[u8]) -> Result<Box<dyn AeadCipher + Send + Sync>> {
    match kind {
        CipherKind2022::Aes128Gcm => Ok(Box::new(Aes128Gcm::new(subkey)?)),
        CipherKind2022::Aes256Gcm => Ok(Box::new(Aes256Gcm::new(subkey)?)),
        CipherKind2022::ChaCha20Poly1305 => Ok(Box::new(ChaCha20Poly1305Aead::new(subkey)?)),
    }
}

/// LE nonce increment（与 client.rs 一致）。
fn increment_nonce(nonce: &mut [u8]) {
    for b in nonce.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

/// 单用户请求读取：salt -> subkey -> open fixed/variable header -> SSStream。
///
/// 返回 (address, port, SSStream)。
async fn read_ss2022_request(
    mut conn: TcpStream,
    server_psk: &[u8],
    kind: CipherKind2022,
    timestamp_tolerance: u64,
    replay: &SaltReplayFilter,
) -> Result<(Address, u16, SSStream<TcpStream>)> {
    // 1. 读 salt
    let salt_size = kind.salt_size();
    let mut salt = vec![0u8; salt_size];
    conn.read_exact(&mut salt).await?;

    // 重放检查（Go sing：解密前 Check，check 即注册，重放 = ErrSaltNotUnique）
    if !replay.check(&salt) {
        return Err(SsError::Ss2022SaltNotUnique);
    }

    // 2. 派生 session subkey
    let subkey = derive_session_subkey(server_psk, &salt, kind);
    let aead = build_aead(kind, &subkey)?;

    // 3. 读 fixed-header-chunk（11B plaintext + tag）
    let fixed_plain_len = 11; // type(1) + timestamp(8) + variableLen(2)
    let tag_size = aead.tag_size();
    let fixed_wire_len = fixed_plain_len + tag_size;
    let mut fixed_wire = vec![0u8; fixed_wire_len];
    conn.read_exact(&mut fixed_wire).await?;

    // nonce [0;12]
    let mut nonce = vec![0u8; aead.nonce_size()];

    // open fixed-header
    let fixed_plain =
        aead.open(&nonce, &[], &fixed_wire).map_err(|e| SsError::AeadOpen(e.to_string()))?;
    increment_nonce(&mut nonce);

    if fixed_plain.len() < fixed_plain_len {
        return Err(SsError::InsufficientData(fixed_plain.len()));
    }

    // 4. 解析 fixed-header
    let header_type = fixed_plain[0];
    if header_type != 0 {
        return Err(SsError::Ss2022InvalidHeaderType(header_type));
    }

    let timestamp = u64::from_be_bytes([
        fixed_plain[1],
        fixed_plain[2],
        fixed_plain[3],
        fixed_plain[4],
        fixed_plain[5],
        fixed_plain[6],
        fixed_plain[7],
        fixed_plain[8],
    ]);

    check_timestamp(timestamp, timestamp_tolerance)?;

    let variable_len = u16::from_be_bytes([fixed_plain[9], fixed_plain[10]]) as usize;

    // 5. 读 variable-header-chunk（sing 无额外上限，u16 即 wire 上限；
    // variable chunk 内含 padding + 客户端首段 payload——Go DialEarlyConn 首写）
    let variable_wire_len = variable_len + tag_size;
    let mut variable_wire = vec![0u8; variable_wire_len];
    conn.read_exact(&mut variable_wire).await?;

    let variable_plain =
        aead.open(&nonce, &[], &variable_wire).map_err(|e| SsError::AeadOpen(e.to_string()))?;
    increment_nonce(&mut nonce);

    // 6. 解析 variable-header：addr+port + paddingLen + padding [+ 首段 payload]
    let (address, port, hdr_end) = parse_variable_header(&variable_plain)?;
    if variable_plain.len() < hdr_end + 2 {
        return Err(SsError::InsufficientData(variable_plain.len()));
    }
    let padding_len = u16::from_be_bytes([variable_plain[hdr_end], variable_plain[hdr_end + 1]]);
    let payload_start = hdr_end + 2 + padding_len as usize;
    if payload_start > variable_plain.len() {
        return Err(SsError::InsufficientData(variable_plain.len()));
    }
    let first_payload = variable_plain[payload_start..].to_vec();

    // 7. 构造 SSStream
    nonce[0] = 1;
    let mut stream = SSStream::new_with_aead_and_nonce(conn, aead, nonce);
    // server 读侧续接请求 nonce 序列（body 首帧 [2,0..]）
    stream.continue_read_nonce();
    // variable chunk 尾部首段 payload 先于 body chunk 交付（sing reader.cached 语义）
    stream.push_plain_prefix(&first_payload);
    // 下行首写时发 sing writeResponse 响应头（新 salt + echo request salt）
    stream.mark_server_response_2022(server_psk.to_vec(), kind, salt);

    Ok((address, port, stream))
}

/// 多用户请求读取：salt || EIH(16B) || fixed-chunk wire，EIH 识别用户。
///
/// SS-2022 多用户匹配：identitySubkey = blake3::derive_key(iPSK||salt)，
/// EIH 解密得 `psk_identity(uPSK)` 查表；session key 用命中用户的 uPSK 派生。
async fn read_ss2022_request_multi(
    mut conn: TcpStream,
    server_psk: &[u8],
    kind: CipherKind2022,
    users: &[(Ss2022User, [u8; 16])],
    timestamp_tolerance: u64,
    replay: &SaltReplayFilter,
) -> Result<InboundResult> {
    // 1. 读 salt
    let salt_size = kind.salt_size();
    let mut salt = vec![0u8; salt_size];
    conn.read_exact(&mut salt).await?;

    // 重放检查（Go sing：解密前 Check，check 即注册，重放 = ErrSaltNotUnique）
    if !replay.check(&salt) {
        return Err(SsError::Ss2022SaltNotUnique);
    }

    // 2. SIP023 EIH：wire 顺序 salt || EIH || AEAD chunks（先读 16B identity header）
    let tag_size: usize = match kind {
        CipherKind2022::Aes128Gcm | CipherKind2022::Aes256Gcm => 16,
        CipherKind2022::ChaCha20Poly1305 => 16,
    };
    let fixed_plain_len = 11;
    let fixed_wire_len = fixed_plain_len + tag_size;

    let mut identity_wire = vec![0u8; crate::ss2022::key::IDENTITY_HEADER_LEN];
    conn.read_exact(&mut identity_wire).await?;

    let plaintext = match decrypt_identity_header(server_psk, &identity_wire, &salt, kind) {
        Ok(p) => p,
        Err(_) => return Err(SsError::Ss2022NoUserMatched),
    };

    let matched = users.iter().find(|(_, identity)| identity == &plaintext);

    let Some(user) = matched else {
        return Err(SsError::Ss2022NoUserMatched);
    };

    // 3. 读 fixed-header-chunk wire bytes（EIH 之后）
    let mut fixed_wire = vec![0u8; fixed_wire_len];
    conn.read_exact(&mut fixed_wire).await?;

    // 4. 命中用户：uPSK 派生 session subkey，解 fixed/variable header
    let user = &user.0;
    let subkey = derive_session_subkey(&user.psk, &salt, kind);
    let aead = build_aead(kind, &subkey)?;
    let nonce = vec![0u8; aead.nonce_size()];

    let fixed_plain =
        aead.open(&nonce, &[], &fixed_wire).map_err(|e| SsError::AeadOpen(e.to_string()))?;
    if fixed_plain.len() < fixed_plain_len {
        return Err(SsError::InsufficientData(fixed_plain.len()));
    }
    if fixed_plain[0] != 0 {
        return Err(SsError::Ss2022InvalidHeaderType(fixed_plain[0]));
    }
    let timestamp = u64::from_be_bytes([
        fixed_plain[1],
        fixed_plain[2],
        fixed_plain[3],
        fixed_plain[4],
        fixed_plain[5],
        fixed_plain[6],
        fixed_plain[7],
        fixed_plain[8],
    ]);
    check_timestamp(timestamp, timestamp_tolerance)?;

    let variable_len = u16::from_be_bytes([fixed_plain[9], fixed_plain[10]]) as usize;

    let mut nonce = nonce;
    increment_nonce(&mut nonce);
    let variable_wire_len = variable_len + tag_size;
    let mut variable_wire = vec![0u8; variable_wire_len];
    conn.read_exact(&mut variable_wire).await?;

    let variable_plain =
        aead.open(&nonce, &[], &variable_wire).map_err(|e| SsError::AeadOpen(e.to_string()))?;
    increment_nonce(&mut nonce);

    // 6. 解析 variable-header：addr+port + paddingLen + padding [+ 首段 payload]
    let (address, port, hdr_end) = parse_variable_header(&variable_plain)?;
    if variable_plain.len() < hdr_end + 2 {
        return Err(SsError::InsufficientData(variable_plain.len()));
    }
    let padding_len = u16::from_be_bytes([variable_plain[hdr_end], variable_plain[hdr_end + 1]]);
    let payload_start = hdr_end + 2 + padding_len as usize;
    if payload_start > variable_plain.len() {
        return Err(SsError::InsufficientData(variable_plain.len()));
    }
    let first_payload = variable_plain[payload_start..].to_vec();

    nonce[0] = 1;
    let mut stream = SSStream::new_with_aead_and_nonce(conn, aead, nonce);
    // server 读侧续接请求 nonce 序列（body 首帧 [2,0..]）
    stream.continue_read_nonce();
    // variable chunk 尾部首段 payload 先于 body chunk 交付（sing reader.cached 语义）
    stream.push_plain_prefix(&first_payload);
    // 下行首写时发 sing writeResponse 响应头（新 salt + echo request salt）
    stream.mark_server_response_2022(user.psk.clone(), kind, salt);

    Ok(InboundResult { address, port, stream, user_email: user.email.clone() })
}

/// 验证时间戳：与当前时间差在 tolerance 内。
fn check_timestamp(timestamp: u64, tolerance: u64) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| SsError::Ss2022TimestampCheck(e.to_string()))?
        .as_secs();
    if timestamp > now + tolerance || timestamp < now.saturating_sub(tolerance) {
        return Err(SsError::Ss2022TimestampCheck(format!(
            "timestamp {} out of range (now={}, tol={})",
            timestamp, now, tolerance
        )));
    }
    Ok(())
}

/// 解析 variable-header：addr+port + paddingLen_BE_u16 + padding。
/// 返回 `(address, port, 端口字段之后的偏移)`（供调用方剥离 padding/取首段 payload）。
fn parse_variable_header(buf: &[u8]) -> Result<(Address, u16, usize)> {
    if buf.is_empty() {
        return Err(SsError::InsufficientData(0));
    }

    let addr_type_byte = buf[0];
    let at = addr_type_byte & 0x0F;
    let mut offset = 1;

    let address = match at {
        addr_type::IPV4 => {
            if buf.len() < offset + 4 {
                return Err(SsError::InsufficientData(buf.len()));
            }
            let ip = std::net::Ipv4Addr::new(
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            );
            offset += 4;
            Address::IPv4(ip)
        },
        addr_type::DOMAIN => {
            if buf.len() < offset + 1 {
                return Err(SsError::InsufficientData(buf.len()));
            }
            let domain_len = buf[offset] as usize;
            offset += 1;
            if buf.len() < offset + domain_len {
                return Err(SsError::InsufficientData(buf.len()));
            }
            let domain = String::from_utf8(buf[offset..offset + domain_len].to_vec())
                .map_err(|_| SsError::InvalidRemoteAddress)?;
            offset += domain_len;
            Address::Domain(domain)
        },
        addr_type::IPV6 => {
            if buf.len() < offset + 16 {
                return Err(SsError::InsufficientData(buf.len()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[offset..offset + 16]);
            offset += 16;
            Address::IPv6(std::net::Ipv6Addr::from(octets))
        },
        _ => return Err(SsError::InvalidRemoteAddress),
    };

    if buf.len() < offset + 2 {
        return Err(SsError::InsufficientData(buf.len()));
    }
    let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);

    Ok((address, port, offset + 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造固定 salt 的 SS-2022 请求 wire：salt || [EIH] || sealed_fixed || sealed_var。
    ///
    /// 镜像 [`crate::ss2022::client::Client2022::dial_target_on`] 的 header 构造，
    /// salt 由调用方固定以供重放测试；`first_payload` 走 variable chunk 尾部
    /// （Go DialEarlyConn 首写 / sing writeRequest(payload) 语义）。
    fn build_request_wire(
        kind: CipherKind2022,
        salt: &[u8],
        ipsk: Option<&[u8]>,
        upsk: &[u8],
        first_payload: &[u8],
    ) -> Vec<u8> {
        use crate::ss2022::key::encrypt_identity_header;
        let subkey = derive_session_subkey(upsk, salt, kind);
        let aead = build_aead(kind, &subkey).unwrap();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let padding_len: u16 = 16;
        let addr_port_len = 1 + 1 + 11 + 2; // ATYP + len + "example.com" + port
        let variable_len = addr_port_len + 2 + padding_len as usize + first_payload.len();

        let mut fixed = Vec::with_capacity(11);
        fixed.push(0u8); // headerType = 0 client
        fixed.extend_from_slice(&timestamp.to_be_bytes());
        fixed.extend_from_slice(&(variable_len as u16).to_be_bytes());
        let mut nonce = vec![0u8; 12];
        let sealed_fixed = aead.seal(&nonce, &[], &fixed).unwrap();
        increment_nonce(&mut nonce);

        let mut var = Vec::with_capacity(variable_len);
        var.push(3u8); // ATYP domain
        var.push(11u8);
        var.extend_from_slice(b"example.com");
        var.extend_from_slice(&443u16.to_be_bytes());
        var.extend_from_slice(&padding_len.to_be_bytes());
        var.extend(std::iter::repeat_n(0u8, padding_len as usize));
        var.extend_from_slice(first_payload);
        let sealed_var = aead.seal(&nonce, &[], &var).unwrap();

        let mut out = Vec::with_capacity(salt.len() + 16 + sealed_fixed.len() + sealed_var.len());
        out.extend_from_slice(salt);
        if let Some(ik) = ipsk {
            out.extend_from_slice(&encrypt_identity_header(ik, upsk, salt, kind).unwrap());
        }
        out.extend_from_slice(&sealed_fixed);
        out.extend_from_slice(&sealed_var);
        out
    }

    /// 多 PSK roundtrip（对齐 Go `MultiService.UpdateUsersWithPasswords`）：
    /// server 配 2+ PSK 用户池，两个 client 各用其中一 PSK 连通，
    /// 各自 body 用各自 uPSK 派生的 AEAD 上下文独立解密。
    #[tokio::test]
    async fn multi_user_two_clients_roundtrip() {
        use base64::Engine as _;

        use crate::ss2022::client::Client2022;

        let server_psk = [0x11u8; 32];
        let alice_psk = [0x22u8; 32];
        let bob_psk = [0x33u8; 32];
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);

        let inbound = std::sync::Arc::new(
            MultiUserInbound::new(
                "2022-blake3-aes-256-gcm",
                &b64(&server_psk),
                vec![
                    Ss2022User { email: "alice".into(), level: 0, psk: alice_psk.to_vec() },
                    Ss2022User { email: "bob".into(), level: 0, psk: bob_psk.to_vec() },
                ],
            )
            .unwrap(),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for (email, fill) in [("alice", 0x77u8), ("bob", 0x88u8)] {
                let (conn, _) = listener.accept().await.unwrap();
                let mut result = inbound.handle_conn(conn).await.unwrap();
                assert_eq!(result.user_email, email, "EIH must identify the right user");
                let payload = vec![fill; 64];
                let got = result.stream.read_chunk().await.unwrap().expect("body chunk");
                assert_eq!(got, payload, "{email} body must decrypt with its own PSK context");
            }
        });

        for (psk, fill) in [(&alice_psk, 0x77u8), (&bob_psk, 0x88u8)] {
            let client =
                Client2022::new("2022-blake3-aes-256-gcm", &b64(psk), "127.0.0.1", addr.port())
                    .unwrap()
                    .with_identity(&b64(&server_psk))
                    .unwrap();
            let mut stream = client.dial_target("example.com", 443).await.unwrap();
            stream.write_chunk(&[fill; 64]).await.unwrap();
            stream.flush().await.unwrap();
        }

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("multi-user roundtrip timed out")
            .unwrap();
    }

    /// TCP salt 重放防护（对齐 Go sing `replay.NewSimple(60s)`，解密前 Check）：
    /// 单用户 inbound 同 salt 二次握手必须拒绝，异 salt 连接不受影响。
    #[tokio::test]
    async fn salt_replay_rejected_single_user() {
        use base64::Engine as _;
        use tokio::io::AsyncWriteExt;

        let psk = [0x11u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(psk);
        let inbound =
            std::sync::Arc::new(Ss2022Inbound::new("2022-blake3-aes-256-gcm", &b64, "u1").unwrap());
        let listener =
            std::sync::Arc::new(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
        let addr = listener.local_addr().unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let ib = std::sync::Arc::clone(&inbound);
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (conn, _) = listener.accept().await.unwrap();
                let _ = tx.send(ib.handle_conn(conn).await);
            }
        });

        let wire = build_request_wire(CipherKind2022::Aes256Gcm, &[0xAAu8; 32], None, &psk, &[]);
        let mut c1 = tokio::net::TcpStream::connect(addr).await.unwrap();
        c1.write_all(&wire).await.unwrap();
        let mut c2 = tokio::net::TcpStream::connect(addr).await.unwrap();
        c2.write_all(&wire).await.unwrap();

        let r1 = rx.recv().await.unwrap().expect("first use of salt must pass");
        assert_eq!(r1.address, Address::Domain("example.com".to_string()));
        let err = rx.recv().await.unwrap().err().expect("replayed salt must be rejected");
        assert!(
            err.to_string().contains("salt not unique"),
            "expected salt-not-unique, got: {err}"
        );
        server.await.unwrap();
    }

    /// TCP salt 重放防护（多用户路径）：同 salt 二次握手必须拒绝。
    #[tokio::test]
    async fn salt_replay_rejected_multi_user() {
        use base64::Engine as _;
        use tokio::io::AsyncWriteExt;

        let server_psk = [0x11u8; 32];
        let user_psk = [0x22u8; 32];
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let inbound = std::sync::Arc::new(
            MultiUserInbound::new(
                "2022-blake3-aes-256-gcm",
                &b64(&server_psk),
                vec![Ss2022User { email: "alice".into(), level: 0, psk: user_psk.to_vec() }],
            )
            .unwrap(),
        );
        let listener =
            std::sync::Arc::new(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
        let addr = listener.local_addr().unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let ib = std::sync::Arc::clone(&inbound);
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (conn, _) = listener.accept().await.unwrap();
                let _ = tx.send(ib.handle_conn(conn).await);
            }
        });

        let wire = build_request_wire(
            CipherKind2022::Aes256Gcm,
            &[0xBBu8; 32],
            Some(&server_psk),
            &user_psk,
            &[],
        );
        let mut c1 = tokio::net::TcpStream::connect(addr).await.unwrap();
        c1.write_all(&wire).await.unwrap();
        let mut c2 = tokio::net::TcpStream::connect(addr).await.unwrap();
        c2.write_all(&wire).await.unwrap();

        let r1 = rx.recv().await.unwrap().expect("first use of salt must pass");
        assert_eq!(r1.user_email, "alice");
        let err = rx.recv().await.unwrap().err().expect("replayed salt must be rejected");
        assert!(
            err.to_string().contains("salt not unique"),
            "expected salt-not-unique, got: {err}"
        );
        server.await.unwrap();
    }
    /// SIP023 EIH 端到端：Client2022(with_identity) 写 EIH → MultiUserInbound 匹配对应用户。
    #[tokio::test]
    async fn multi_user_eih_roundtrip() {
        use base64::Engine as _;

        use crate::ss2022::client::Client2022;

        let server_psk = [0x11u8; 32];
        let user_psk = [0x22u8; 32];
        let server_psk_b64 = base64::engine::general_purpose::STANDARD.encode(server_psk);
        let user_psk_b64 = base64::engine::general_purpose::STANDARD.encode(user_psk);

        let inbound = MultiUserInbound::new(
            "2022-blake3-aes-256-gcm",
            &server_psk_b64,
            vec![Ss2022User { email: "alice".into(), level: 0, psk: user_psk.to_vec() }],
        )
        .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            inbound.handle_conn(conn).await
        });

        let client =
            Client2022::new("2022-blake3-aes-256-gcm", &user_psk_b64, "127.0.0.1", addr.port())
                .unwrap()
                .with_identity(&server_psk_b64)
                .unwrap();
        let _stream = client.dial_target("example.com", 443).await.unwrap();

        let result = server.await.unwrap().unwrap();
        assert_eq!(result.address, Address::Domain("example.com".to_string()));
        assert_eq!(result.port, 443);
        assert_eq!(result.user_email, "alice");
    }

    /// EIH 错误用户：user PSK 不在白名单 → NoUserMatched。
    #[tokio::test]
    async fn multi_user_eih_rejects_unknown_user() {
        use base64::Engine as _;

        use crate::ss2022::client::Client2022;

        let server_psk = [0x11u8; 32];
        let other_psk = [0x33u8; 32];
        let server_psk_b64 = base64::engine::general_purpose::STANDARD.encode(server_psk);
        let other_psk_b64 = base64::engine::general_purpose::STANDARD.encode(other_psk);

        let inbound = MultiUserInbound::new(
            "2022-blake3-aes-256-gcm",
            &server_psk_b64,
            vec![Ss2022User { email: "alice".into(), level: 0, psk: [0x22u8; 32].to_vec() }],
        )
        .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            inbound.handle_conn(conn).await
        });

        let client =
            Client2022::new("2022-blake3-aes-256-gcm", &other_psk_b64, "127.0.0.1", addr.port())
                .unwrap()
                .with_identity(&server_psk_b64)
                .unwrap();
        let _ = client.dial_target("example.com", 443).await;

        let result = server.await.unwrap();
        assert!(result.is_err(), "unknown user PSK must be rejected");
    }

    /// SS-2022 relay e2e（对齐 sing-shadowsocks relay.go）：
    /// Client(with_identity) → [salt][EIH][EISS] → RelayInbound 剥 EIH →
    /// destination Ss2022Inbound 用 dest PSK 解密 → echo（sing writeResponse 响应头）→ 原路回包。
    #[tokio::test]
    async fn relay_tunnel_roundtrip() {
        use base64::Engine as _;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        use crate::ss2022::client::Client2022;

        // 0. 真实 echo 目标
        let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = echo_listener.accept().await else { break };
                tokio::spawn(async move {
                    let (mut r, mut w) = c.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        // 1. destination SS-2022 server（端到端密文的真正终结点）
        let dest_psk = [0x44u8; 32];
        let dest_psk_b64 = base64::engine::general_purpose::STANDARD.encode(dest_psk);
        let dest_inbound = std::sync::Arc::new(
            Ss2022Inbound::new("2022-blake3-aes-256-gcm", &dest_psk_b64, "u@dest").unwrap(),
        );
        let dest_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_port = dest_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((conn, _)) = dest_listener.accept().await else { break };
                let ib = std::sync::Arc::clone(&dest_inbound);
                tokio::spawn(async move {
                    let Ok(result) = ib.handle_conn(conn).await else { return };
                    // 读一个 body chunk（请求 AEAD 续接 header nonce 序列，
                    // continue_read_nonce 后 body 首帧在 [2,0..] 解）。
                    let mut ss = result.stream;
                    let Ok(Some(p)) = ss.read_chunk().await else { return };
                    // sing server writeResponse 响应 wire：resp_salt ||
                    // AEAD(fixed：type=1+epoch+echo_salt+var_len) || AEAD(var=first body)。
                    // dest_psk 32B 恰为 key_size，derive_psk 恒等；echo_salt 全零
                    // （client 只校验 echo ≤ 请求盐 lexicographic）。
                    let kind = CipherKind2022::from_name("2022-blake3-aes-256-gcm").unwrap();
                    let resp_subkey = derive_session_subkey(&dest_psk, &[0u8; 32], kind);
                    let resp_aead = build_aead(kind, &resp_subkey).unwrap();
                    let epoch = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let mut fixed = Vec::with_capacity(43);
                    fixed.push(1u8);
                    fixed.extend_from_slice(&epoch.to_be_bytes());
                    fixed.extend_from_slice(&[0u8; 32]);
                    fixed.extend_from_slice(&(p.len() as u16).to_be_bytes());
                    let mut nonce = vec![0u8; 12];
                    let sealed_fixed = resp_aead.seal(&nonce, &[], &fixed).unwrap();
                    increment_nonce(&mut nonce);
                    let sealed_var = resp_aead.seal(&nonce, &[], &p).unwrap();
                    let mut out = Vec::with_capacity(32 + sealed_fixed.len() + sealed_var.len());
                    out.extend_from_slice(&[0u8; 32]); // resp_salt
                    out.extend_from_slice(&sealed_fixed);
                    out.extend_from_slice(&sealed_var);
                    ss.get_mut().write_all(&out).await.unwrap();
                    ss.flush().await.unwrap();
                });
            }
        });

        // 2. relay server（剥 EIH，原样转发到 destination）
        let server_psk = [0x11u8; 32];
        let server_psk_b64 = base64::engine::general_purpose::STANDARD.encode(server_psk);
        let relay = std::sync::Arc::new(
            RelayInbound::new(
                "2022-blake3-aes-256-gcm",
                &server_psk_b64,
                vec![RelayDestination {
                    key: dest_psk.to_vec(),
                    address: Address::IPv4(std::net::Ipv4Addr::LOCALHOST),
                    port: dest_port,
                    email: "dest-1".into(),
                    level: 0,
                }],
            )
            .unwrap(),
        );
        let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((conn, _)) = relay_listener.accept().await else { break };
                let relay = std::sync::Arc::clone(&relay);
                tokio::spawn(async move {
                    let Ok((_addr, _port, salt, client)) = relay.handle_conn_relay(conn).await
                    else {
                        return;
                    };
                    // 原样桥：salt 回灌 + 双向 copy
                    let Ok(mut upstream) =
                        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, dest_port))
                            .await
                    else {
                        return;
                    };
                    if upstream.write_all(&salt).await.is_err() {
                        return;
                    }
                    let (mut cr, mut cw) = client.into_split();
                    let (mut ur, mut uw) = upstream.into_split();
                    let up = tokio::io::copy(&mut cr, &mut uw);
                    let down = tokio::io::copy(&mut ur, &mut cw);
                    let _ = tokio::join!(up, down);
                });
            }
        });

        // 3. client：dest PSK 加密 + relay server PSK 的 EIH
        let client =
            Client2022::new("2022-blake3-aes-256-gcm", &dest_psk_b64, "127.0.0.1", relay_port)
                .unwrap()
                .with_identity(&server_psk_b64)
                .unwrap();
        // 看门狗：wire 任一侧失配时快速失败而非无限挂起（挂起测试回归防护）
        let roundtrip = async {
            let mut stream = client.dial_target("127.0.0.1", echo_port).await.unwrap();

            let payload = b"ss2022-relay-e2e";
            stream.write_chunk(payload).await.unwrap();
            stream.flush().await.unwrap();
            // SS-2022 响应必须走 try_open_chunk（read_chunk 是 legacy 路径，
            // 不跑 drive_2022_rekey 响应头状态机）
            let mut pending: Vec<u8> = Vec::new();
            let mut down_buf = vec![0u8; 16 * 1024];
            loop {
                match stream.try_open_chunk(&mut pending) {
                    Ok(crate::stream::ChunkOut::Message(p)) => {
                        assert_eq!(p, payload, "relay e2e roundtrip");
                        return;
                    },
                    Ok(crate::stream::ChunkOut::End) => {
                        panic!("stream ended before echo response");
                    },
                    Ok(crate::stream::ChunkOut::NeedMore) => {
                        let n = stream.get_mut().read(&mut down_buf).await.unwrap();
                        assert!(n > 0, "EOF before echo response");
                        pending.extend_from_slice(&down_buf[..n]);
                    },
                    Err(e) => panic!("try_open_chunk: {e}"),
                }
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), roundtrip)
            .await
            .expect("relay roundtrip timed out (wire mismatch)");
    }

    #[test]
    fn inbound_build_aead_chacha20_roundtrip() {
        // 入站 build_aead 与 client.rs 对称：chacha20 用 blake3 派生的 32B subkey 直接构造。
        let psk = [0x11u8; 32];
        let salt = [0x22u8; 32];
        let subkey = derive_session_subkey(&psk, &salt, CipherKind2022::ChaCha20Poly1305);
        assert_eq!(subkey.len(), 32);

        let aead =
            build_aead(CipherKind2022::ChaCha20Poly1305, &subkey).expect("build_aead chacha20");
        let nonce = vec![0u8; aead.nonce_size()];
        let plaintext = b"inbound chacha20 round trip";
        let sealed = aead.seal(&nonce, b"", plaintext).expect("seal");
        let opened = aead.open(&nonce, b"", &sealed).expect("open");
        assert_eq!(opened.as_slice(), &plaintext[..]);
    }

    #[test]
    fn inbound_build_aead_all_methods() {
        // 三种 cipher kind 都能成功构造 AEAD（回归：chacha20 不再 not-implemented）。
        let sub32 = [0x55u8; 32];
        let sub16 = [0x55u8; 16];
        assert!(build_aead(CipherKind2022::Aes128Gcm, &sub16).is_ok());
        assert!(build_aead(CipherKind2022::Aes256Gcm, &sub32).is_ok());
        assert!(build_aead(CipherKind2022::ChaCha20Poly1305, &sub32).is_ok());
    }

    /// Go 26.7.28 (sing v0.2.7) 互操作语义回归：
    /// ① 客户端首段 payload 塞在 variable chunk 尾部（Go DialEarlyConn 首写），
    ///    server 必须先于 body chunk 交付（此前被静默丢弃 → 目标收不到请求）；
    /// ② server 下行首写必须发 sing writeResponse 响应头（resp_salt +
    ///    fixed(type=1|epoch|echo_salt|payload_len) + var chunk），用响应 subkey
    ///    加密、nonce 重新计数（此前用请求 subkey 写裸 body chunk → Go client
    ///    readResponse 卡死/解密失败）。
    #[tokio::test]
    async fn sing_semantics_first_payload_and_response_header() {
        use base64::Engine as _;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let psk = [0x66u8; 16];
        let b64 = base64::engine::general_purpose::STANDARD.encode(psk);
        let salt = [0x77u8; 16];
        let inbound =
            std::sync::Arc::new(Ss2022Inbound::new("2022-blake3-aes-128-gcm", &b64, "u1").unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let mut r = inbound.handle_conn(conn).await.unwrap();
            assert_eq!(r.address, Address::Domain("example.com".to_string()));
            // ① 首段 payload 先于 body chunk 交付
            let first = r.stream.read_chunk().await.unwrap().expect("first payload");
            assert_eq!(first, b"GET / one".to_vec(), "variable chunk 尾部首段 payload");
            let second = r.stream.read_chunk().await.unwrap().expect("body chunk");
            assert_eq!(second, b"BODY".to_vec(), "后续 body chunk nonce 续接");
            // ② 下行首写触发 writeResponse 响应头
            r.stream.write_chunk(b"RESP").await.unwrap();
            r.stream.flush().await.unwrap();
        });

        let wire = build_request_wire(CipherKind2022::Aes128Gcm, &salt, None, &psk, b"GET / one");
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(&wire).await.unwrap();

        // 请求 body：常规 chunk（nonce [2,0..] size / [3,0..] payload），镜像 sing Writer
        let subkey = derive_session_subkey(&psk, &salt, CipherKind2022::Aes128Gcm);
        let req_aead = build_aead(CipherKind2022::Aes128Gcm, &subkey).unwrap();
        let mut nonce = vec![2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut body_wire = Vec::new();
        body_wire.extend_from_slice(&req_aead.seal(&nonce, &[], &4u16.to_be_bytes()).unwrap());
        increment_nonce(&mut nonce);
        body_wire.extend_from_slice(&req_aead.seal(&nonce, &[], b"BODY").unwrap());
        c.write_all(&body_wire).await.unwrap();
        c.flush().await.unwrap();

        // ③ 手工解 server 响应：resp_salt || AEAD(fixed) || AEAD(var=RESP)。
        // 响应握手 chunk 无 size 前缀（sing WriteChunk 直 seal / ReadWithLength
        // 定长读），fixed 用 nonce [0]、var（首段响应数据）用 nonce [1]。
        let mut resp_salt = vec![0u8; 16];
        c.read_exact(&mut resp_salt).await.unwrap();
        let resp_subkey = derive_session_subkey(&psk, &resp_salt, CipherKind2022::Aes128Gcm);
        let resp_aead = build_aead(CipherKind2022::Aes128Gcm, &resp_subkey).unwrap();
        let zero = [0u8; 12];
        let one = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut fixed_wire = vec![0u8; (1 + 8 + 16 + 2) + 16];
        c.read_exact(&mut fixed_wire).await.unwrap();
        let fixed = resp_aead.open(&zero, &[], &fixed_wire).unwrap();
        assert_eq!(fixed.len(), 1 + 8 + 16 + 2, "响应 fixed chunk 明文长度");
        assert_eq!(fixed[0], 1, "HeaderTypeServer");
        let epoch = u64::from_be_bytes(fixed[1..9].try_into().unwrap());
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert!(now.abs_diff(epoch) <= 30, "epoch within ±30s");
        assert_eq!(&fixed[9..25], &salt, "echo 必须回显请求 salt");
        let payload_len = u16::from_be_bytes([fixed[25], fixed[26]]) as usize;
        assert_eq!(payload_len, 4, "payload_len = 首段响应数据长度");
        let mut var_wire = vec![0u8; payload_len + 16];
        c.read_exact(&mut var_wire).await.unwrap();
        let var = resp_aead.open(&one, &[], &var_wire).unwrap();
        assert_eq!(var, b"RESP".to_vec(), "var chunk = 首段响应 payload（无 size 前缀）");

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("sing semantics roundtrip timed out")
            .unwrap();
    }
}
