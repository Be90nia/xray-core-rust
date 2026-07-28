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
//! 3. 构造 AEAD，nonce [0;12]
//! 4. open fixed-header-chunk：headerType + timestamp_BE_u64 + variableLen_BE_u16
//! 5. 验证 headerType（0=client）+ timestamp（防重放）
//! 6. open variable-header-chunk：addr+port + paddingLen + padding
//! 7. 构造 SSStream 继续读写 body
//!
//! 多用户/中继：用每个 user PSK 尝试 open fixed-header，成功即匹配该用户。

use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use xray_common::net::address::Address;
use xray_crypto::aead::{AeadCipher, Aes128Gcm, Aes256Gcm};

use crate::error::{Result, SsError};
use crate::protocol::addr_type;
use crate::ss2022::key::{derive_session_subkey, psk_from_base64, CipherKind2022};
use crate::stream::SSStream;

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
        let psk = psk_from_base64(psk_b64)?;
        if psk.is_empty() {
            return Err(SsError::Ss2022MissingKey);
        }
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
            email: email.into(),
            timestamp_tolerance: 30,
        })
    }

    /// 处理入站 TCP 连接：读 salt → 派生 subkey → 解密 header → 解析目标。
    ///
    /// # Errors
    /// - 透传 AEAD、IO、协议解析错误。
    pub async fn handle_conn(&self, conn: TcpStream) -> io::Result<InboundResult> {
        let result = read_ss2022_request(conn, &self.psk, self.kind, self.timestamp_tolerance)
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
}

// ============================================================================
// 多用户入站
// ============================================================================

/// SS-2022 多用户入站处理器。
///
/// 对应 Go `MultiUserInbound` struct（`proxy/shadowsocks_2022/inbound_multi.go`）。
///
/// 用 server PSK 派生 subkey 后，逐个 user PSK 尝试 open fixed-header。
/// 匹配成功则用该 user 的 PSK 继续解密 variable-header。
pub struct MultiUserInbound {
    /// 服务端主 PSK。
    psk: Vec<u8>,
    kind: CipherKind2022,
    /// 用户列表（Arc<Mutex> 支持动态增删）。
    users: Arc<Mutex<Vec<Ss2022User>>>,
    /// 时间戳容忍窗口（秒）。
    timestamp_tolerance: u64,
}

impl MultiUserInbound {
    /// 创建多用户入站。
    ///
    /// # Errors
    /// - [`SsError::InvalidCipherName`]：cipher 不支持。
    /// - [`SsError::InvalidPassword`]：PSK base64 解码失败或长度不匹配。
    /// - [`SsError::Ss2022MissingKey`]：server PSK 为空。
    pub fn new(
        cipher: &str,
        server_psk_b64: &str,
        users: Vec<Ss2022User>,
    ) -> Result<Self> {
        let kind = CipherKind2022::from_name(cipher)?;
        let psk = psk_from_base64(server_psk_b64)?;
        if psk.is_empty() {
            return Err(SsError::Ss2022MissingKey);
        }
        if psk.len() != kind.key_size() {
            return Err(SsError::InvalidPassword(format!(
                "Server PSK length {} != key_size {}",
                psk.len(),
                kind.key_size()
            )));
        }
        for user in &users {
            if user.psk.len() != kind.key_size() {
                return Err(SsError::InvalidPassword(format!(
                    "User '{}' PSK length {} != key_size {}",
                    user.email,
                    user.psk.len(),
                    kind.key_size()
                )));
            }
        }
        Ok(Self {
            psk,
            kind,
            users: Arc::new(Mutex::new(users)),
            timestamp_tolerance: 30,
        })
    }

    /// 处理入站 TCP 连接：逐用户尝试解密，匹配成功返回结果。
    ///
    /// # Errors
    /// - [`SsError::Ss2022NoUserMatched`]：无用户匹配。
    /// - 透传其他错误。
    pub async fn handle_conn(&self, conn: TcpStream) -> io::Result<InboundResult> {
        let users = self.users.lock();
        read_ss2022_request_multi(conn, &self.psk, self.kind, &users, self.timestamp_tolerance)
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
        if user.psk.len() != self.kind.key_size() {
            return Err(SsError::InvalidPassword(format!(
                "User '{}' PSK length {} != key_size {}",
                user.email,
                user.psk.len(),
                self.kind.key_size()
            )));
        }
        let mut users = self.users.lock();
        if users.iter().any(|u| u.email == user.email) {
            return Err(SsError::UserNotFoundByEmail(format!(
                "User {} already exists",
                user.email
            )));
        }
        users.push(user);
        Ok(())
    }

    /// 删除用户（对应 Go `RemoveUser`）。
    ///
    /// # Errors
    /// - [`SsError::UserNotFoundByEmail`]：email 不存在。
    pub fn remove_user(&self, email: &str) -> Result<()> {
        let mut users = self.users.lock();
        let len_before = users.len();
        users.retain(|u| u.email != email);
        if users.len() == len_before {
            return Err(SsError::UserNotFoundByEmail(email.to_string()));
        }
        Ok(())
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
        let psk = psk_from_base64(server_psk_b64)?;
        if psk.is_empty() {
            return Err(SsError::Ss2022MissingKey);
        }
        if psk.len() != kind.key_size() {
            return Err(SsError::InvalidPassword(format!(
                "Server PSK length {} != key_size {}",
                psk.len(),
                kind.key_size()
            )));
        }
        Ok(Self {
            psk,
            kind,
            destinations,
            timestamp_tolerance: 30,
        })
    }

    /// 处理入站 TCP 连接：按 destination 匹配用户。
    ///
    /// # Errors
    /// - [`SsError::Ss2022NoUserMatched`]：无 destination 匹配。
    /// - 透传其他错误。
    pub async fn handle_conn(&self, conn: TcpStream) -> io::Result<InboundResult> {
        let users: Vec<Ss2022User> = self
            .destinations
            .iter()
            .map(|d| Ss2022User {
                email: d.email.clone(),
                level: d.level,
                psk: d.key.clone(),
            })
            .collect();
        read_ss2022_request_multi(conn, &self.psk, self.kind, &users, self.timestamp_tolerance)
            .await
            .map_err(|e| io::Error::other(e.to_string()))
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
        // ponytail: ChaCha20 SS-2022 入站留后续
        CipherKind2022::ChaCha20Poly1305 => Err(SsError::InvalidCipherName(
            "2022-blake3-chacha20-poly1305 not yet implemented".into(),
        )),
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
) -> Result<(Address, u16, SSStream<TcpStream>)> {
    // 1. 读 salt
    let salt_size = kind.salt_size();
    let mut salt = vec![0u8; salt_size];
    conn.read_exact(&mut salt).await?;

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
    let fixed_plain = aead
        .open(&nonce, &[], &fixed_wire)
        .map_err(|e| SsError::AeadOpen(e.to_string()))?;
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
        fixed_plain[1], fixed_plain[2], fixed_plain[3], fixed_plain[4],
        fixed_plain[5], fixed_plain[6], fixed_plain[7], fixed_plain[8],
    ]);

    check_timestamp(timestamp, timestamp_tolerance)?;

    let variable_len = u16::from_be_bytes([fixed_plain[9], fixed_plain[10]]) as usize;

    // 5. 读 variable-header-chunk
    if variable_len > 900 + 260 {
        return Err(SsError::Ss2022PaddingTooLarge(variable_len));
    }
    let variable_wire_len = variable_len + tag_size;
    let mut variable_wire = vec![0u8; variable_wire_len];
    conn.read_exact(&mut variable_wire).await?;

    let variable_plain = aead
        .open(&nonce, &[], &variable_wire)
        .map_err(|e| SsError::AeadOpen(e.to_string()))?;
    increment_nonce(&mut nonce);

    // 6. 解析 variable-header
    let (address, port) = parse_variable_header(&variable_plain)?;

    // 7. 构造 SSStream
    nonce[0] = 1;
    let stream = SSStream::new_with_aead_and_nonce(conn, aead, nonce);

    Ok((address, port, stream))
}

/// 多用户请求读取：先读 salt + fixed-header wire bytes，逐用户尝试 open。
///
/// SS-2022 多用户匹配：用 server_psk||user_psk 作为 PSK 派生 subkey，
/// 尝试 open fixed-header，成功即匹配该用户。
async fn read_ss2022_request_multi(
    mut conn: TcpStream,
    server_psk: &[u8],
    kind: CipherKind2022,
    users: &[Ss2022User],
    timestamp_tolerance: u64,
) -> Result<InboundResult> {
    // 1. 读 salt
    let salt_size = kind.salt_size();
    let mut salt = vec![0u8; salt_size];
    conn.read_exact(&mut salt).await?;

    // 2. 读 fixed-header-chunk wire bytes（先读到 buffer，后续逐用户尝试）
    let tag_size: usize = match kind {
        CipherKind2022::Aes128Gcm | CipherKind2022::Aes256Gcm => 16,
        CipherKind2022::ChaCha20Poly1305 => 16,
    };
    let fixed_plain_len = 11;
    let fixed_wire_len = fixed_plain_len + tag_size;
    let mut fixed_wire = vec![0u8; fixed_wire_len];
    conn.read_exact(&mut fixed_wire).await?;

    // 3. 逐用户尝试 open fixed-header
    // 多用户场景：subkey = blake3(psk=server_psk||user_psk, material=server_psk||user_psk||salt)
    // 简化实现：用 server_psk + user_psk 拼接后与 salt 一起派生
    for user in users {
        // 多用户 subkey 派生：PSK = server_psk XOR user_psk（SIP022 规范）
        let combined_psk: Vec<u8> = server_psk
            .iter()
            .zip(user.psk.iter())
            .map(|(s, u)| s ^ u)
            .collect();
        let subkey = derive_session_subkey(&combined_psk, &salt, kind);

        if let Ok(aead) = build_aead(kind, &subkey) {
            let nonce = vec![0u8; aead.nonce_size()];
            if let Ok(fixed_plain) = aead.open(&nonce, &[], &fixed_wire) {
                if fixed_plain.len() >= fixed_plain_len && fixed_plain[0] == 0 {
                    let timestamp = u64::from_be_bytes([
                        fixed_plain[1], fixed_plain[2], fixed_plain[3], fixed_plain[4],
                        fixed_plain[5], fixed_plain[6], fixed_plain[7], fixed_plain[8],
                    ]);

                    if check_timestamp(timestamp, timestamp_tolerance).is_err() {
                        continue;
                    }

                    let variable_len =
                        u16::from_be_bytes([fixed_plain[9], fixed_plain[10]]) as usize;
                    if variable_len > 900 + 260 {
                        continue;
                    }

                    // 匹配成功：继续读 variable-header
                    let mut nonce = nonce;
                    increment_nonce(&mut nonce);
                    let variable_wire_len = variable_len + tag_size;
                    let mut variable_wire = vec![0u8; variable_wire_len];
                    conn.read_exact(&mut variable_wire).await?;

                    let variable_plain = match aead.open(&nonce, &[], &variable_wire) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    increment_nonce(&mut nonce);

                    let (address, port) = match parse_variable_header(&variable_plain) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };

                    nonce[0] = 1;
                    let stream = SSStream::new_with_aead_and_nonce(conn, aead, nonce);

                    return Ok(InboundResult {
                        address,
                        port,
                        stream,
                        user_email: user.email.clone(),
                    });
                }
            }
        }
    }

    Err(SsError::Ss2022NoUserMatched)
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
fn parse_variable_header(buf: &[u8]) -> Result<(Address, u16)> {
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
        }
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
        }
        addr_type::IPV6 => {
            if buf.len() < offset + 16 {
                return Err(SsError::InsufficientData(buf.len()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[offset..offset + 16]);
            offset += 16;
            Address::IPv6(std::net::Ipv6Addr::from(octets))
        }
        _ => return Err(SsError::InvalidRemoteAddress),
    };

    if buf.len() < offset + 2 {
        return Err(SsError::InsufficientData(buf.len()));
    }
    let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);

    Ok((address, port))
}
