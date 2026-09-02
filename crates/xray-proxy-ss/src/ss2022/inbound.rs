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
use xray_crypto::aead::{AeadCipher, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305Aead};
use xray_common::net::address::Address;

use crate::error::{Result, SsError};
use crate::protocol::addr_type;
use crate::ss2022::key::{
    derive_psk, derive_session_subkey, psk_from_base64, CipherKind2022,
};
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
        let psk = derive_psk(&psk_from_base64(psk_b64)?, kind)?;
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
        let psk = derive_psk(&psk_from_base64(server_psk_b64)?, kind)?;
        let users = users
            .into_iter()
            .map(|u| {
                Ok::<_, SsError>(Ss2022User {
                    email: u.email,
                    level: u.level,
                    psk: derive_psk(&u.psk, kind)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
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
        let users = self.users.lock().clone();
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
        let psk = derive_psk(&user.psk, self.kind)?;
        let mut users = self.users.lock();
        if users.iter().any(|u| u.email == user.email) {
            return Err(SsError::UserNotFoundByEmail(format!(
                "User {} already exists",
                user.email
            )));
        }
        users.push(Ss2022User {
            email: user.email,
            level: user.level,
            psk,
        });
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
        use crate::ss2022::key::psk_identity;
        self.users
            .lock()
            .iter()
            .map(|u| (psk_identity(&u.psk), u.psk.clone()))
            .collect()
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
        let psk = derive_psk(&psk_from_base64(server_psk_b64)?, kind)?;
        Ok(Self {
            psk,
            kind,
            destinations,
            timestamp_tolerance: 30,
        })
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
        CipherKind2022::ChaCha20Poly1305 => {
            Ok(Box::new(ChaCha20Poly1305Aead::new(subkey)?))
        }
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

    // 2. SIP023 EIH：wire 顺序 salt || EIH || AEAD chunks（先读 16B identity header）
    let tag_size: usize = match kind {
        CipherKind2022::Aes128Gcm | CipherKind2022::Aes256Gcm => 16,
        CipherKind2022::ChaCha20Poly1305 => 16,
    };
    let fixed_plain_len = 11;
    let fixed_wire_len = fixed_plain_len + tag_size;

    use crate::ss2022::key::{decrypt_identity_header, psk_identity};

    let mut identity_wire = vec![0u8; crate::ss2022::key::IDENTITY_HEADER_LEN];
    conn.read_exact(&mut identity_wire).await?;

    let plaintext = match decrypt_identity_header(server_psk, &identity_wire, &salt, kind) {
        Ok(p) => p,
        Err(_) => return Err(SsError::Ss2022NoUserMatched),
    };

    let matched = users
        .iter()
        .find(|u| psk_identity(&u.psk) == plaintext);

    let Some(user) = matched else {
        return Err(SsError::Ss2022NoUserMatched);
    };

    // 3. 读 fixed-header-chunk wire bytes（EIH 之后）
    let mut fixed_wire = vec![0u8; fixed_wire_len];
    conn.read_exact(&mut fixed_wire).await?;


    // 4. 命中用户：uPSK 派生 session subkey，解 fixed/variable header
    let subkey = derive_session_subkey(&user.psk, &salt, kind);
    let aead = build_aead(kind, &subkey)?;
    let nonce = vec![0u8; aead.nonce_size()];

    let fixed_plain = aead
        .open(&nonce, &[], &fixed_wire)
        .map_err(|e| SsError::AeadOpen(e.to_string()))?;
    if fixed_plain.len() < fixed_plain_len {
        return Err(SsError::InsufficientData(fixed_plain.len()));
    }
    if fixed_plain[0] != 0 {
        return Err(SsError::Ss2022InvalidHeaderType(fixed_plain[0]));
    }
    let timestamp = u64::from_be_bytes([
        fixed_plain[1], fixed_plain[2], fixed_plain[3], fixed_plain[4],
        fixed_plain[5], fixed_plain[6], fixed_plain[7], fixed_plain[8],
    ]);
    check_timestamp(timestamp, timestamp_tolerance)?;

    let variable_len = u16::from_be_bytes([fixed_plain[9], fixed_plain[10]]) as usize;
    if variable_len > 900 + 260 {
        return Err(SsError::Ss2022PaddingTooLarge(variable_len));
    }

    let mut nonce = nonce;
    increment_nonce(&mut nonce);
    let variable_wire_len = variable_len + tag_size;
    let mut variable_wire = vec![0u8; variable_wire_len];
    conn.read_exact(&mut variable_wire).await?;

    let variable_plain = aead
        .open(&nonce, &[], &variable_wire)
        .map_err(|e| SsError::AeadOpen(e.to_string()))?;
    increment_nonce(&mut nonce);

    let (address, port) = parse_variable_header(&variable_plain)?;

    nonce[0] = 1;
    let stream = SSStream::new_with_aead_and_nonce(conn, aead, nonce);

    Ok(InboundResult {
        address,
        port,
        stream,
        user_email: user.email.clone(),
    })
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


#[cfg(test)]
mod tests {
    use super::*;

    /// SIP023 EIH 端到端：Client2022(with_identity) 写 EIH → MultiUserInbound 匹配对应用户。
    #[tokio::test]
    async fn multi_user_eih_roundtrip() {
        use crate::ss2022::client::Client2022;
        use base64::Engine as _;

        let server_psk = [0x11u8; 32];
        let user_psk = [0x22u8; 32];
        let server_psk_b64 = base64::engine::general_purpose::STANDARD.encode(server_psk);
        let user_psk_b64 = base64::engine::general_purpose::STANDARD.encode(user_psk);

        let inbound = MultiUserInbound::new(
            "2022-blake3-aes-256-gcm",
            &server_psk_b64,
            vec![Ss2022User {
                email: "alice".into(),
                level: 0,
                psk: user_psk.to_vec(),
            }],
        )
        .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            inbound.handle_conn(conn).await
        });

        let client = Client2022::new(
            "2022-blake3-aes-256-gcm",
            &user_psk_b64,
            "127.0.0.1",
            addr.port(),
        )
        .unwrap()
        .with_identity(&server_psk_b64)
        .unwrap();
        let mut stream = client.dial_target("example.com", 443).await.unwrap();

        let result = server.await.unwrap().unwrap();
        assert_eq!(result.address, Address::Domain("example.com".to_string()));
        assert_eq!(result.port, 443);
        assert_eq!(result.user_email, "alice");
    }

    /// EIH 错误用户：user PSK 不在白名单 → NoUserMatched。
    #[tokio::test]
    async fn multi_user_eih_rejects_unknown_user() {
        use crate::ss2022::client::Client2022;
        use base64::Engine as _;

        let server_psk = [0x11u8; 32];
        let other_psk = [0x33u8; 32];
        let server_psk_b64 = base64::engine::general_purpose::STANDARD.encode(server_psk);
        let other_psk_b64 = base64::engine::general_purpose::STANDARD.encode(other_psk);

        let inbound = MultiUserInbound::new(
            "2022-blake3-aes-256-gcm",
            &server_psk_b64,
            vec![Ss2022User {
                email: "alice".into(),
                level: 0,
                psk: [0x22u8; 32].to_vec(),
            }],
        )
        .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            inbound.handle_conn(conn).await
        });

        let client = Client2022::new(
            "2022-blake3-aes-256-gcm",
            &other_psk_b64,
            "127.0.0.1",
            addr.port(),
        )
        .unwrap()
        .with_identity(&server_psk_b64)
        .unwrap();
        let _ = client.dial_target("example.com", 443).await;

        let result = server.await.unwrap();
        assert!(result.is_err(), "unknown user PSK must be rejected");
    }

    /// SS-2022 relay e2e（对齐 sing-shadowsocks relay.go）：
    /// Client(with_identity) → [salt][EIH][EISS] → RelayInbound 剥 EIH →
    /// destination Ss2022Inbound 用 dest PSK 解密 → echo → 原路回包。
    #[tokio::test]
    async fn relay_tunnel_roundtrip() {
        use crate::ss2022::client::Client2022;
        use base64::Engine as _;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
                    // 解密 body → echo；echo 回包 → 加密回写
                    let mut ss = result.stream;
                    let _ = tokio::spawn(async move {
                        loop {
                            match ss.read_chunk().await {
                                Ok(Some(p)) => {
                                    // 简化：不真正连 echo（已在 client 侧验证往返），
                                    // 直接回写相同 payload 模拟 echo
                                    if ss.write_chunk(&p).await.is_err() { break; }
                                    if ss.flush().await.is_err() { break; }
                                }
                                _ => break,
                            }
                        }
                    })
                    .await;
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
                    else { return };
                    // 原样桥：salt 回灌 + 双向 copy
                    let Ok(mut upstream) = tokio::net::TcpStream::connect(
                        (std::net::Ipv4Addr::LOCALHOST, dest_port),
                    ).await else { return };
                    if upstream.write_all(&salt).await.is_err() { return; }
                    let (mut cr, mut cw) = client.into_split();
                    let (mut ur, mut uw) = upstream.into_split();
                    let up = tokio::io::copy(&mut cr, &mut uw);
                    let down = tokio::io::copy(&mut ur, &mut cw);
                    let _ = tokio::join!(up, down);
                });
            }
        });

        // 3. client：dest PSK 加密 + relay server PSK 的 EIH
        let client = Client2022::new(
            "2022-blake3-aes-256-gcm",
            &dest_psk_b64,
            "127.0.0.1",
            relay_port,
        )
        .unwrap()
        .with_identity(&server_psk_b64)
        .unwrap();
        let mut stream = client.dial_target("127.0.0.1", echo_port).await.unwrap();

        let payload = b"ss2022-relay-e2e";
        stream.write_chunk(payload).await.unwrap();
        stream.flush().await.unwrap();
        let resp = stream.read_chunk().await.unwrap().expect("echo resp");
        assert_eq!(resp, payload);
    }

    #[test]
    fn inbound_build_aead_chacha20_roundtrip() {
        // 入站 build_aead 与 client.rs 对称：chacha20 用 blake3 派生的 32B subkey 直接构造。
        let psk = [0x11u8; 32];
        let salt = [0x22u8; 32];
        let subkey =
            derive_session_subkey(&psk, &salt, CipherKind2022::ChaCha20Poly1305);
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
}