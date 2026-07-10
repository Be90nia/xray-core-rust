//! VMess AEAD 加密原语。
//!
//! 对应 Go 版本 `proxy/vmess/aead/` 包。包含：
//! - **常量**：9 个 KDF salt 字符串
//! - **KDF**：嵌套 HMAC-SHA256 密钥派生（VMess 自有结构）
//! - **CreateAuthID**：AES-128 单块加密生成 16B 认证 ID
//! - **SealVMessAEADHeader**：客户端封装 AEAD 加密请求头
//! - **OpenVMessAEADHeader**：服务端解密 AEAD 请求头
//! - **AuthIDDecoderHolder**：服务端多用户认证 + 反重放

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use xray_crypto::aead::{AeadCipher, Aes128Gcm};

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// 常量（对应 Go `proxy/vmess/aead/consts.go`）
// ============================================================================

/// KDF salt 常量（与 Go 端字符串字节级一致）。
pub mod consts {
    /// AuthID 加密密钥派生 salt。
    pub const AUTH_ID_ENCRYPTION_KEY: &str = "AES Auth ID Encryption";
    /// 响应头长度密钥 salt。
    pub const AEAD_RESP_HEADER_LEN_KEY: &str = "AEAD Resp Header Len Key";
    /// 响应头长度 IV salt。
    pub const AEAD_RESP_HEADER_LEN_IV: &str = "AEAD Resp Header Len IV";
    /// 响应头 payload 密钥 salt。
    pub const AEAD_RESP_HEADER_PAYLOAD_KEY: &str = "AEAD Resp Header Key";
    /// 响应头 payload IV salt。
    pub const AEAD_RESP_HEADER_PAYLOAD_IV: &str = "AEAD Resp Header IV";
    /// VMess AEAD KDF 主 salt。
    pub const VMESS_AEAD_KDF: &str = "VMess AEAD KDF";
    /// VMess header payload AEAD 密钥 salt。
    pub const VMESS_HEADER_PAYLOAD_AEAD_KEY: &str = "VMess Header AEAD Key";
    /// VMess header payload AEAD nonce salt。
    pub const VMESS_HEADER_PAYLOAD_AEAD_IV: &str = "VMess Header AEAD Nonce";
    /// VMess header payload 长度 AEAD 密钥 salt。
    pub const VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &str = "VMess Header AEAD Key_Length";
    /// VMess header payload 长度 AEAD nonce salt。
    pub const VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV: &str = "VMess Header AEAD Nonce_Length";
}

// ============================================================================
// KDF（对应 Go `proxy/vmess/aead/kdf.go`）
// ============================================================================

/// VMess KDF：基于 HMAC-SHA256 的嵌套密钥派生。
///
/// 对应 Go `KDF(key, path...)`。Go 端通过 `hash2` 包装 HMAC 实例，
/// 使内层 HMAC 成为外层 HMAC 的哈希函数（而非 key）。
///
/// 正确的嵌套结构：
/// ```text
/// L0(data) = HMAC-SHA256("VMess AEAD KDF", data)
/// L1(salt, data) = L0(salt⊕opad || L0(salt⊕ipad || data))
/// L2(s1,s2,data) = L1(s1, s2⊕opad || L1(s1, s2⊕ipad || data))
/// L3(s1,s2,s3,data) = L2(s1,s2, s3⊕opad || L2(s1,s2, s3⊕ipad || data))
/// ```

const HMAC_BLOCK_LEN: usize = 64;

/// L0: 基础哈希 = HMAC-SHA256(key="VMess AEAD KDF")
fn l0(data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(consts::VMESS_AEAD_KDF.as_bytes())
        .expect("HMAC key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// 计算 HMAC ipad/opad（key 零填充到 64 字节后 XOR）
fn compute_pads(key: &[u8]) -> ([u8; HMAC_BLOCK_LEN], [u8; HMAC_BLOCK_LEN]) {
    let mut ikey = [0u8; HMAC_BLOCK_LEN];
    let mut okey = [0u8; HMAC_BLOCK_LEN];
    let k = if key.len() > HMAC_BLOCK_LEN {
        // 超长 key 先用 l0 哈希（VMess 实际不会触发）
        let h = l0(key);
        ikey[..32].copy_from_slice(&h);
        okey[..32].copy_from_slice(&h);
        return {
            for i in 0..HMAC_BLOCK_LEN { ikey[i] ^= 0x36; okey[i] ^= 0x5c; }
            (ikey, okey)
        };
    } else {
        key
    };
    ikey[..k.len()].copy_from_slice(k);
    okey[..k.len()].copy_from_slice(k);
    for i in 0..HMAC_BLOCK_LEN { ikey[i] ^= 0x36; okey[i] ^= 0x5c; }
    (ikey, okey)
}

/// L1: HMAC(hash=L0, key=salt)(data) = L0(okey || L0(ikey || data))
fn l1(salt: &[u8], data: &[u8]) -> [u8; 32] {
    let (ikey, okey) = compute_pads(salt);
    let mut inner = Vec::with_capacity(HMAC_BLOCK_LEN + data.len());
    inner.extend_from_slice(&ikey);
    inner.extend_from_slice(data);
    let inner_hash = l0(&inner);
    let mut outer = Vec::with_capacity(HMAC_BLOCK_LEN + 32);
    outer.extend_from_slice(&okey);
    outer.extend_from_slice(&inner_hash);
    l0(&outer)
}

/// L2: HMAC(hash=L1(s1), key=s2)(data)
fn l2(s1: &[u8], s2: &[u8], data: &[u8]) -> [u8; 32] {
    let (ikey, okey) = compute_pads(s2);
    let mut inner = Vec::with_capacity(HMAC_BLOCK_LEN + data.len());
    inner.extend_from_slice(&ikey);
    inner.extend_from_slice(data);
    let inner_hash = l1(s1, &inner);
    let mut outer = Vec::with_capacity(HMAC_BLOCK_LEN + 32);
    outer.extend_from_slice(&okey);
    outer.extend_from_slice(&inner_hash);
    l1(s1, &outer)
}

/// L3: HMAC(hash=L2(s1,s2), key=s3)(data)
fn l3(s1: &[u8], s2: &[u8], s3: &[u8], data: &[u8]) -> [u8; 32] {
    let (ikey, okey) = compute_pads(s3);
    let mut inner = Vec::with_capacity(HMAC_BLOCK_LEN + data.len());
    inner.extend_from_slice(&ikey);
    inner.extend_from_slice(data);
    let inner_hash = l2(s1, s2, &inner);
    let mut outer = Vec::with_capacity(HMAC_BLOCK_LEN + 32);
    outer.extend_from_slice(&okey);
    outer.extend_from_slice(&inner_hash);
    l2(s1, s2, &outer)
}

/// KDF：Go `KDF(key, path...)` 的正确实现。
///
/// # Panics
///
/// 超过 3 个路径段时 panic（VMess 协议不需要）。
pub fn kdf(key: &[u8], path: &[&str]) -> Vec<u8> {
    let path_bytes: Vec<&[u8]> = path.iter().map(|s| s.as_bytes()).collect();
    kdf_paths(key, &path_bytes)
}

/// KDF 的字节切片版本（用于 AuthID/nonce 等非 UTF-8 路径段）。
pub fn kdf_paths(key: &[u8], paths: &[&[u8]]) -> Vec<u8> {
    match paths.len() {
        0 => l0(key).to_vec(),
        1 => l1(paths[0], key).to_vec(),
        2 => l2(paths[0], paths[1], key).to_vec(),
        3 => l3(paths[0], paths[1], paths[2], key).to_vec(),
        n => panic!("VMess KDF supports at most 3 path segments, got {n}"),
    }
}

/// 取 KDF 前 16 字节（对应 Go `KDF16`）。
pub fn kdf16(key: &[u8], path: &[&str]) -> [u8; 16] {
    let full = kdf(key, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// KDF16 字节切片版本。
pub fn kdf16_paths(key: &[u8], paths: &[&[u8]]) -> [u8; 16] {
    let full = kdf_paths(key, paths);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

// ============================================================================
// CreateAuthID（对应 Go `proxy/vmess/aead/authid.go::CreateAuthID`）
// ============================================================================

/// `CreateAuthID` 错误（cmdKey 长度必须为 16）。
#[derive(Debug, thiserror::Error)]
pub enum CreateAuthIDError {
    /// cmdKey 长度必须为 16 字节。
    #[error("cmdKey must be 16 bytes, got {0}")]
    InvalidKeyLength(usize),
}

/// 生成 16 字节 AuthID：AES-128-ECB 加密 `[8B time BE | 4B random | 4B crc32 BE]`。
///
/// 对应 Go `CreateAuthID(cmdKey, time)`：
/// - `time`：Unix 秒（BE）
/// - `random`：4 字节随机
/// - `crc32`：IEEE 多项式，对前 12 字节计算
/// - AES key = `KDF16(cmdKey, AUTH_ID_ENCRYPTION_KEY)`
pub fn create_auth_id(cmd_key: &[u8], time: i64) -> Result<[u8; 16], CreateAuthIDError> {
    if cmd_key.len() != 16 {
        return Err(CreateAuthIDError::InvalidKeyLength(cmd_key.len()));
    }
    use rand::RngCore;
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&time.to_be_bytes());
    rand::rng().fill_bytes(&mut buf[8..12]);
    let crc = crc32fast::hash(&buf[..12]);
    buf[12..].copy_from_slice(&crc.to_be_bytes());

    let derived_key = kdf16(cmd_key, &[consts::AUTH_ID_ENCRYPTION_KEY]);
    let cipher = Aes128::new(GenericArray::from_slice(&derived_key));
    let mut block = GenericArray::clone_from_slice(&buf);
    cipher.encrypt_block(&mut block);
    Ok(block.into())
}

// ============================================================================
// SealVMessAEADHeader / OpenVMessAEADHeader（对应 Go `aead/encrypt.go`）
// ============================================================================

/// `SealVMessAEADHeader` 错误。
#[derive(Debug, thiserror::Error)]
pub enum SealHeaderError {
    /// cmdKey 长度必须为 16 字节。
    #[error("cmdKey must be 16 bytes, got {0}")]
    InvalidKeyLength(usize),

    /// AEAD 加密失败。
    #[error("crypto error: {0}")]
    Crypto(#[from] xray_crypto::aead::CryptoError),
}

impl From<CreateAuthIDError> for SealHeaderError {
    fn from(e: CreateAuthIDError) -> Self {
        match e {
            CreateAuthIDError::InvalidKeyLength(n) => Self::InvalidKeyLength(n),
        }
    }
}

/// 客户端：封装 AEAD 加密请求头。
///
/// 对应 Go `SealVMessAEADHeader(key, data)`。
///
/// # 输出格式
///
/// ```text
/// [authID:16B]
/// [encrypted length: 2B + 16B tag]   (aad=authID)
/// [nonce: 8B]
/// [encrypted payload: N B + 16B tag] (aad=authID)
/// ```
///
/// # Errors
///
/// - [`SealHeaderError::InvalidKeyLength`]：cmdKey 长度不是 16。
/// - [`SealHeaderError::Crypto`]：AEAD 加密失败（极少）。
pub fn seal_vmess_aead_header(
    cmd_key: &[u8],
    data: &[u8],
    now_unix: i64,
) -> Result<Vec<u8>, SealHeaderError> {
    if cmd_key.len() != 16 {
        return Err(SealHeaderError::InvalidKeyLength(cmd_key.len()));
    }

    let auth_id = create_auth_id(cmd_key, now_unix)?;
    let mut connection_nonce = [0u8; 8];
    use rand::RngCore;
    rand::rng().fill_bytes(&mut connection_nonce);

    let header_payload_data_len = u16::try_from(data.len()).unwrap_or(u16::MAX);
    let len_plain = header_payload_data_len.to_be_bytes();

    // KDF path 用字节切片（Go 端用 string(byte_slice)，非 UTF-8 也合法）
    let path_segments: [Vec<u8>; 3] = [
        auth_id.to_vec(),
        connection_nonce.to_vec(),
        Vec::new(), // 占位，下面按需填充
    ];

    // 加密 length
    let len_key = kdf16_paths(
        cmd_key,
        &[
            consts::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY.as_bytes(),
            &path_segments[0],
            &path_segments[1],
        ],
    );
    let len_iv_full = kdf_paths(
        cmd_key,
        &[
            consts::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV.as_bytes(),
            &path_segments[0],
            &path_segments[1],
        ],
    );
    let len_nonce = &len_iv_full[..12];
    let len_cipher = Aes128Gcm::new(&len_key)?;
    let encrypted_len = len_cipher.seal(len_nonce, &auth_id, &len_plain)?;

    // 加密 payload
    let payload_key = kdf16_paths(
        cmd_key,
        &[
            consts::VMESS_HEADER_PAYLOAD_AEAD_KEY.as_bytes(),
            &path_segments[0],
            &path_segments[1],
        ],
    );
    let payload_iv_full = kdf_paths(
        cmd_key,
        &[
            consts::VMESS_HEADER_PAYLOAD_AEAD_IV.as_bytes(),
            &path_segments[0],
            &path_segments[1],
        ],
    );
    let payload_nonce = &payload_iv_full[..12];
    let payload_cipher = Aes128Gcm::new(&payload_key)?;
    let encrypted_payload = payload_cipher.seal(payload_nonce, &auth_id, data)?;

    let mut out = Vec::with_capacity(16 + encrypted_len.len() + 8 + encrypted_payload.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&encrypted_len);
    out.extend_from_slice(&connection_nonce);
    out.extend_from_slice(&encrypted_payload);
    Ok(out)
}

/// `OpenVMessAEADHeader` 返回结构。
#[derive(Debug)]
pub struct OpenHeaderResult {
    /// 解密后的 payload。
    pub payload: Vec<u8>,
    /// 是否应当 drain（length 解密失败时为 true，payload 解密失败时为 false）。
    pub should_drain: bool,
    /// 已读取字节数（用于 drain 决策）。
    pub bytes_read: usize,
}

/// `OpenVMessAEADHeader` 错误。
#[derive(Debug, thiserror::Error)]
pub enum OpenHeaderError {
    /// cmdKey 长度必须为 16 字节。
    #[error("cmdKey must be 16 bytes, got {0}")]
    InvalidKeyLength(usize),

    /// 读取流数据不足。
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// AEAD 解密失败（含 should_drain 标记）。
    #[error("AEAD open failed: {msg}")]
    Crypto {
        /// 错误消息。
        msg: String,
        /// 是否应当 drain：length 解密失败 true，payload 失败 false。
        should_drain: bool,
        /// 已读字节数（drain 用）。
        bytes_read: usize,
    },
}

/// 服务端：解密 AEAD 加密请求头。
///
/// 对应 Go `OpenVMessAEADHeader(key, authid, reader)`。
///
/// # Errors
///
/// - [`OpenHeaderError::InvalidKeyLength`]：cmdKey 长度不是 16。
/// - [`OpenHeaderError::Io`]：读取流数据不足。
/// - [`OpenHeaderError::Crypto`]：AEAD 解密失败（含 should_drain + bytes_read）。
pub fn open_vmess_aead_header<R: std::io::Read>(
    cmd_key: &[u8],
    auth_id: &[u8; 16],
    reader: &mut R,
) -> Result<OpenHeaderResult, OpenHeaderError> {
    if cmd_key.len() != 16 {
        return Err(OpenHeaderError::InvalidKeyLength(cmd_key.len()));
    }

    let mut bytes_read = 0usize;

    // 读 18B 加密 length
    let mut encrypted_len = [0u8; 18];
    reader.read_exact(&mut encrypted_len)?;
    bytes_read += 18;

    // 读 8B nonce
    let mut nonce = [0u8; 8];
    reader.read_exact(&mut nonce)?;
    bytes_read += 8;

    // 解密 length（aad = authID）
    let len_key = kdf16_paths(
        cmd_key,
        &[
            consts::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY.as_bytes(),
            auth_id,
            &nonce,
        ],
    );
    let len_iv_full = kdf_paths(
        cmd_key,
        &[
            consts::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV.as_bytes(),
            auth_id,
            &nonce,
        ],
    );
    let len_nonce = &len_iv_full[..12];
    let len_cipher = Aes128Gcm::new(&len_key).map_err(|e| OpenHeaderError::Crypto { msg: e.to_string(), should_drain: true, bytes_read: 0 })?;
    let decrypted_len_bytes = match len_cipher.open(len_nonce, auth_id, &encrypted_len) {
        Ok(v) => v,
        Err(e) => {
            return Err(OpenHeaderError::Crypto {
                msg: e.to_string(),
                should_drain: true,
                bytes_read,
            });
        }
    };
    let length = u16::from_be_bytes([decrypted_len_bytes[0], decrypted_len_bytes[1]]);

    // 读 encrypted payload（length + 16B tag）
    let mut encrypted_payload = vec![0u8; usize::from(length) + 16];
    reader.read_exact(&mut encrypted_payload)?;
    bytes_read += encrypted_payload.len();

    // 解密 payload（aad = authID）
    let payload_key = kdf16_paths(
        cmd_key,
        &[
            consts::VMESS_HEADER_PAYLOAD_AEAD_KEY.as_bytes(),
            auth_id,
            &nonce,
        ],
    );
    let payload_iv_full = kdf_paths(
        cmd_key,
        &[
            consts::VMESS_HEADER_PAYLOAD_AEAD_IV.as_bytes(),
            auth_id,
            &nonce,
        ],
    );
    let payload_nonce = &payload_iv_full[..12];
    let payload_cipher = Aes128Gcm::new(&payload_key).map_err(|e| OpenHeaderError::Crypto { msg: e.to_string(), should_drain: false, bytes_read: 0 })?;
    let payload = match payload_cipher.open(payload_nonce, auth_id, &encrypted_payload) {
        Ok(v) => v,
        Err(e) => {
            return Err(OpenHeaderError::Crypto {
                msg: e.to_string(),
                should_drain: false,
                bytes_read,
            });
        }
    };

    Ok(OpenHeaderResult {
        payload,
        should_drain: false,
        bytes_read,
    })
}

// ============================================================================

// ============================================================================
// AuthIDDecoderHolder（对应 Go `aead/authid.go::AuthIDDecoderHolder`）
// ============================================================================

/// 单个用户的 AuthID 解码器项。
pub struct AuthIDDecoderItem {
    decoder_key: [u8; 16],
    aes: Aes128,
}

impl AuthIDDecoderItem {
    /// 创建解码器项。`decoder_key` 是用户的 cmd_key。
    pub fn new(decoder_key: [u8; 16]) -> Self {
        let derived = kdf16(&decoder_key, &[consts::AUTH_ID_ENCRYPTION_KEY]);
        let aes = Aes128::new(GenericArray::from_slice(&derived));
        Self { decoder_key, aes }
    }

    /// 解码 16B AuthID，返回 (time, crc32_expected, rand, decrypted_bytes)。
    ///
    /// 对应 Go `AuthIDDecoder.Decode`。调用方应检查前 12 字节的 CRC32 是否等于后 4 字节。
    pub fn decode(&self, auth_id: &[u8; 16]) -> (i64, u32, i32, [u8; 16]) {
        let mut block = GenericArray::clone_from_slice(auth_id);
        self.aes.decrypt_block(&mut block);
        let data: [u8; 16] = block.into();
        let t = i64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let rand_val = i32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let crc = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        (t, crc, rand_val, data)
    }

    /// 返回 decoder_key（用户 cmd_key）。
    #[must_use]
    pub fn decoder_key(&self) -> &[u8; 16] {
        &self.decoder_key
    }
}

/// AuthID 反重放 + 多用户解码器（对应 Go `AuthIDDecoderHolder`）。
///
/// ponytail: Go 端是 LRU-120 反重放 filter，本实现用容量满后整体清空（1024 阈值）。
/// 回放窗口在满容量瞬间放宽到 0，但实际攻击者要在 1024 个不同用户请求内重放才受益。
pub struct AuthIDDecoderHolder {
    items: Mutex<HashMap<[u8; 16], AuthIDDecoderItem>>,
    replay_filter: Mutex<std::collections::HashSet<[u8; 16]>>,
}

/// AuthID 匹配结果。
#[derive(Debug)]
pub enum AuthIDMatchError {
    /// 时间戳为负。
    NegativeTime,
    /// 时间戳与本地相差超过 120 秒。
    InvalidTime,
    /// 重放（authID 在近期已见过）。
    Replay,
    /// 无任何用户匹配（含所有用户 CRC 校验失败）。
    NotFound,
}

impl AuthIDDecoderHolder {
    /// 创建空 holder。
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: Mutex::new(HashMap::new()),
            replay_filter: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// 添加用户（key = cmdKey）。
    pub fn add_user(&self, key: [u8; 16]) {
        self.items
            .lock()
            .expect("items poisoned")
            .insert(key, AuthIDDecoderItem::new(key));
    }

    /// 移除用户。
    pub fn remove_user(&self, key: &[u8; 16]) {
        self.items.lock().expect("items poisoned").remove(key);
    }

    /// 用户数量。
    #[must_use]
    pub fn user_count(&self) -> usize {
        self.items.lock().expect("items poisoned").len()
    }

    /// 尝试匹配 16B AuthID，返回匹配到的用户 cmdKey。
    ///
    /// 对应 Go `AuthIDDecoderHolder.Match`。Go 端返回 ticket（interface{}），
    /// 这里返回 cmdKey，调用方可通过外部 HashMap 进一步查到 MemoryUser。
    ///
    /// # Errors
    ///
    /// - [`AuthIDMatchError::NegativeTime`]：时间戳为负。
    /// - [`AuthIDMatchError::InvalidTime`]：时间戳与本地相差超过 120 秒。
    /// - [`AuthIDMatchError::Replay`]：authID 已见过（反重放）。
    /// - [`AuthIDMatchError::NotFound`]：无用户匹配。
    pub fn match_auth_id(&self, auth_id: &[u8; 16]) -> Result<[u8; 16], AuthIDMatchError> {
        let items = self.items.lock().expect("items poisoned");
        for (key, item) in items.iter() {
            let (t, crc, _, decrypted) = item.decode(auth_id);
            if crc32fast::hash(&decrypted[..12]) != crc {
                continue;
            }

            if t < 0 {
                return Err(AuthIDMatchError::NegativeTime);
            }

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if (t - now).abs() > 120 {
                return Err(AuthIDMatchError::InvalidTime);
            }

            let mut filter = self.replay_filter.lock().expect("replay poisoned");
            if filter.len() > 1024 {
                filter.clear();
            }
            if !filter.insert(*auth_id) {
                return Err(AuthIDMatchError::Replay);
            }

            return Ok(*key);
        }
        Err(AuthIDMatchError::NotFound)
    }
}

impl Default for AuthIDDecoderHolder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_common::uuid::UUID;

    fn sample_cmd_key() -> [u8; 16] {
        let uuid = UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("uuid");
        crate::account::cmd_key_of(&uuid)
    }

    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    // === KDF 测试 ===

    #[test]
    fn kdf_returns_32_bytes() {
        let out = kdf(b"key", &["path1", "path2"]);
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn kdf_deterministic_for_same_inputs() {
        let a = kdf(b"key", &["a", "b"]);
        let b = kdf(b"key", &["a", "b"]);
        assert_eq!(a, b);
    }

    #[test]
    fn kdf_changes_with_key() {
        let a = kdf(b"key1", &["path"]);
        let b = kdf(b"key2", &["path"]);
        assert_ne!(a, b);
    }

    #[test]
    fn kdf_changes_with_path() {
        let a = kdf(b"key", &["a"]);
        let b = kdf(b"key", &["b"]);
        assert_ne!(a, b);
    }

    #[test]
    fn kdf_changes_with_path_count() {
        let a = kdf(b"key", &["a"]);
        let b = kdf(b"key", &["a", "b"]);
        assert_ne!(a, b);
    }

    #[test]
    fn kdf16_is_prefix_of_kdf() {
        let full = kdf(b"key", &["p"]);
        let sixteen = kdf16(b"key", &["p"]);
        assert_eq!(&full[..16], &sixteen[..]);
    }

    #[test]
    fn kdf_empty_path() {
        let out = kdf(b"key", &[]);
        assert_eq!(out.len(), 32);
    }


    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
    }

    #[test]
    fn kdf_go_compat_known_vectors() {
        // Go 参考值: KDF16("Demo Key for Auth ID Test", "Demo Path for Auth ID Test")
        let go_vec1 = kdf16(b"Demo Key for Auth ID Test", &["Demo Path for Auth ID Test"]);
        assert_eq!(&go_vec1[..], hex_to_bytes("66e41ad47fa745fbfd1e97325e93dbf4"),
            "KDF16 mismatch with Go reference (simple path)");

        // Go 参考值: KDF16(0x00*16, "AES Auth ID Encryption")
        let go_vec2 = kdf16(&[0u8; 16], &["AES Auth ID Encryption"]);
        assert_eq!(&go_vec2[..], hex_to_bytes("2114985832a5bad7b65a0f72c3c73329"),
            "KDF16 mismatch with Go reference (zero key)");

        // Go L3 参考值: KDF16(key, "VMess Header AEAD Key_Length", authID_0*16, nonce_0*8)
        let l3_key = kdf16_paths(
            b"Demo Key for Auth ID Test",
            &[b"VMess Header AEAD Key_Length", &[0u8; 16][..], &[0u8; 8][..]],
        );
        assert_eq!(&l3_key[..], hex_to_bytes("4f78a9bb23d8386f79ca39db0dccf0db"),
            "L3 KDF16 mismatch: {:02x?}", l3_key);

        // Go L3 with non-zero authID/nonce
        let l3_key2 = kdf16_paths(
            b"Demo Key for Auth ID Test",
            &[b"VMess Header AEAD Key_Length", &[0x01u8,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10][..], &[0xAAu8,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11][..]],
        );
        assert_eq!(&l3_key2[..], hex_to_bytes("b31ccb5a152bcc9759e76d0ced86fe4d"),
            "L3 KDF16 mismatch (nonzero): {:02x?}", l3_key2);
    }

    // === CreateAuthID 测试 ===
    // === CreateAuthID 测试 ===

    #[test]
    fn create_auth_id_returns_16_bytes() {
        let id = create_auth_id(&sample_cmd_key(), 1_700_000_000).expect("ok");
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn create_auth_id_invalid_key_length() {
        let err = create_auth_id(&[0u8; 15], 0).unwrap_err();
        assert!(matches!(err, CreateAuthIDError::InvalidKeyLength(15)));
    }

    #[test]
    fn create_auth_id_time_byte_reflected() {
        let cmd = sample_cmd_key();
        let item = AuthIDDecoderItem::new(cmd);
        let time = 1_700_000_000i64;
        let auth_id = create_auth_id(&cmd, time).expect("create");
        let (decoded_time, _, _, _) = item.decode(&auth_id);
        assert_eq!(decoded_time, time);
    }

    // === AuthIDDecoderItem 测试 ===

    #[test]
    fn decoder_decode_roundtrip() {
        let cmd_key = sample_cmd_key();
        let item = AuthIDDecoderItem::new(cmd_key);
        let time = 1_700_000_000i64;
        let auth_id = create_auth_id(&cmd_key, time).expect("create");
        let (decoded_time, decoded_crc, _, decoded_bytes) = item.decode(&auth_id);
        assert_eq!(decoded_time, time);
        assert_eq!(crc32fast::hash(&decoded_bytes[..12]), decoded_crc);
    }

    #[test]
    fn decoder_decode_wrong_key_gives_garbage() {
        let cmd_key = sample_cmd_key();
        let item = AuthIDDecoderItem::new(cmd_key);
        let other_key = [0xAAu8; 16];
        let auth_id = create_auth_id(&other_key, 1_700_000_000).expect("create");
        let (_, crc, _, decoded_bytes) = item.decode(&auth_id);
        assert_ne!(crc32fast::hash(&decoded_bytes[..12]), crc);
    }

    // === AuthIDDecoderHolder 测试 ===

    #[test]
    fn holder_match_known_user() {
        let cmd_key = sample_cmd_key();
        let holder = AuthIDDecoderHolder::new();
        holder.add_user(cmd_key);

        let auth_id = create_auth_id(&cmd_key, now_unix()).expect("create");
        let matched = holder.match_auth_id(&auth_id).expect("match");
        assert_eq!(matched, cmd_key);
    }

    #[test]
    fn holder_match_unknown_user_returns_not_found() {
        let holder = AuthIDDecoderHolder::new();
        let auth_id = create_auth_id(&sample_cmd_key(), 1_700_000_000).expect("create");
        let err = holder.match_auth_id(&auth_id).unwrap_err();
        assert!(matches!(err, AuthIDMatchError::NotFound));
    }

    #[test]
    fn holder_match_replay_returns_replay() {
        let cmd_key = sample_cmd_key();
        let holder = AuthIDDecoderHolder::new();
        holder.add_user(cmd_key);

        let auth_id = create_auth_id(&cmd_key, now_unix()).expect("create");

        holder.match_auth_id(&auth_id).expect("first match");
        let err = holder.match_auth_id(&auth_id).unwrap_err();
        assert!(matches!(err, AuthIDMatchError::Replay));
    }

    #[test]
    fn holder_match_invalid_time() {
        let cmd_key = sample_cmd_key();
        let holder = AuthIDDecoderHolder::new();
        holder.add_user(cmd_key);

        let auth_id = create_auth_id(&cmd_key, 1).expect("create"); // 1970-01-01
        let err = holder.match_auth_id(&auth_id).unwrap_err();
        assert!(matches!(err, AuthIDMatchError::InvalidTime));
    }

    #[test]
    fn holder_remove_user() {
        let cmd_key = sample_cmd_key();
        let holder = AuthIDDecoderHolder::new();
        holder.add_user(cmd_key);
        assert_eq!(holder.user_count(), 1);
        holder.remove_user(&cmd_key);
        assert_eq!(holder.user_count(), 0);
    }

    // === Seal/Open Header 完整往返测试 ===

    #[test]
    fn seal_open_header_roundtrip() {
        let cmd_key = sample_cmd_key();
        let data = b"hello vmess header payload";

        let sealed = seal_vmess_aead_header(&cmd_key, data, now_unix()).expect("seal");
        assert!(sealed.len() > 16 + 18 + 8 + data.len());

        let mut auth_id = [0u8; 16];
        auth_id.copy_from_slice(&sealed[..16]);
        let mut reader = &sealed[16..];
        let opened = open_vmess_aead_header(&cmd_key, &auth_id, &mut reader).expect("open");
        assert_eq!(opened.payload.as_slice(), data);
        assert!(!opened.should_drain);
    }

    #[test]
    fn seal_header_invalid_key_length() {
        let err = seal_vmess_aead_header(&[0u8; 15], b"data", 0).unwrap_err();
        assert!(matches!(err, SealHeaderError::InvalidKeyLength(15)));
    }

    #[test]
    fn open_header_invalid_key_length() {
        let auth_id = [0u8; 16];
        let mut reader = &b""[..];
        let err = open_vmess_aead_header(&[0u8; 15], &auth_id, &mut reader).unwrap_err();
        assert!(matches!(err, OpenHeaderError::InvalidKeyLength(15)));
    }

    #[test]
    fn open_header_truncated_length() {
        let cmd_key = sample_cmd_key();
        let auth_id = [0u8; 16];
        let truncated = [0u8; 5];
        let mut reader = &truncated[..];
        let err = open_vmess_aead_header(&cmd_key, &auth_id, &mut reader).unwrap_err();
        assert!(matches!(err, OpenHeaderError::Io(_)));
    }

    #[test]
    fn open_header_wrong_key_fails() {
        let cmd_key = sample_cmd_key();
        let wrong_key = [0xBBu8; 16];

        let sealed = seal_vmess_aead_header(&cmd_key, b"data", now_unix()).expect("seal");
        let mut auth_id = [0u8; 16];
        auth_id.copy_from_slice(&sealed[..16]);
        let mut reader = &sealed[16..];
        let err = open_vmess_aead_header(&wrong_key, &auth_id, &mut reader).unwrap_err();
        assert!(matches!(
            err,
            OpenHeaderError::Crypto {
                should_drain: true,
                ..
            }
        ));
    }

    #[test]
    fn open_header_truncated_payload_after_length() {
        // 构造一个部分 sealed：authID(16) + encrypted_len(18) + nonce(8) + 不完整 payload
        let cmd_key = sample_cmd_key();
        let sealed = seal_vmess_aead_header(&cmd_key, b"payload_data", now_unix()).expect("seal");
        // 截掉末尾
        let truncated = &sealed[..sealed.len() - 5];
        let mut auth_id = [0u8; 16];
        auth_id.copy_from_slice(&truncated[..16]);
        let mut reader = &truncated[16..];
        let err = open_vmess_aead_header(&cmd_key, &auth_id, &mut reader).unwrap_err();
        assert!(matches!(err, OpenHeaderError::Io(_)));
    }
}
