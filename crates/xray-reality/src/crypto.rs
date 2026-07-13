//! REALITY 纯密码学组件（独立于 uTLS 的协议算法）。
//!
//! 翻译自 Go `transport/internet/reality/reality.go` 中 5 个不依赖 uTLS
//! 内部 API 的纯算法函数。这些函数可在标准 rustls 下独立单元测试，
//! 握手层（ClientHello session_id 注入、HandshakeState 访问）等接入
//! watfaq-rustls 后再接。
//!
//! # 协议算法对应关系
//!
//! | Go 源（reality.go UClient） | Rust 函数 |
//! |---|---|
//! | session_id 字段编码（version+timestamp+short_id） | [`encode_session_id`] |
//! | ECDH + HKDF-SHA256 派生 auth_key | [`derive_auth_key`] |
//! | AES-256-GCM 加密 session_id[:16] | [`encrypt_session_id`] |
//! | Ed25519 + HMAC-SHA512 证书验证 | [`verify_reality_certificate`] |
//!
//! # 为什么是纯函数
//!
//! Go 端这些算法的输入（ECDH 私钥、ClientHello.Random、hello.Raw 字节）
//! 来自 uTLS 的 `HandshakeState.State13.KeyShareKeys.Ecdhe` 和
//! `HandshakeState.Hello.Raw`——标准 rustls 不暴露这些。但算法本身
//! 是纯密码学运算，可独立提取并测试。

use crate::config::{SHORT_ID_LEN, X25519_KEY_LEN};
use crate::error::RealityError;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

/// SessionId 总长度（TLS 1.3 ClientHello 固定 32 字节）。
pub const SESSION_ID_LEN: usize = 32;

/// auth_key 长度（HKDF-SHA256 收紧后 32 字节，对应 AES-256 key 长度）。
pub const AUTH_KEY_LEN: usize = 32;

/// ClientHello.Random 前 20 字节作为 HKDF salt。
pub const HKDF_SALT_LEN: usize = 20;

/// ClientHello.Random 后 12 字节作为 AES-GCM nonce。
pub const AEAD_NONCE_LEN: usize = 12;

/// HKDF info label（对应 Go `[]byte("REALITY")`）。
pub const HKDF_INFO: &[u8] = b"REALITY";

type HmacSha512 = Hmac<Sha512>;

/// 构造明文 session_id（加密前）。
///
/// 对应 Go：
/// ```go
/// hello.SessionId[0] = core.Version_x
/// hello.SessionId[1] = core.Version_y
/// hello.SessionId[2] = core.Version_z
/// hello.SessionId[3] = 0 // reserved
/// binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
/// copy(hello.SessionId[8:], config.ShortId)
/// ```
///
/// 布局：`[version_x, version_y, version_z, reserved=0, timestamp_be(4), short_id(≤8), zeros(余下)]`
///
/// `short_id` 超过 8 字节返回 [`RealityError::InvalidShortIdLen`]。
pub fn encode_session_id(
    version: [u8; 3],
    timestamp: u32,
    short_id: &[u8],
) -> Result<[u8; SESSION_ID_LEN], RealityError> {
    if short_id.len() > SHORT_ID_LEN {
        return Err(RealityError::InvalidShortIdLen {
            actual: short_id.len(),
        });
    }
    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id[0] = version[0];
    session_id[1] = version[1];
    session_id[2] = version[2];
    // session_id[3] = 0 reserved（默认 0）
    session_id[4..8].copy_from_slice(&timestamp.to_be_bytes());
    session_id[8..8 + short_id.len()].copy_from_slice(short_id);
    Ok(session_id)
}

/// ECDH(X25519) 派生共享密钥 + HKDF-SHA256 收紧到 32 字节 auth_key。
///
/// 对应 Go：
/// ```go
/// uConn.AuthKey, _ = ecdhe.ECDH(publicKey)
/// hkdf.New(sha256.New, uConn.AuthKey, hello.Random[:20], []byte("REALITY")).Read(uConn.AuthKey)
/// ```
///
/// # 参数
/// - `ecdhe_private_key`：客户端 TLS 1.3 key_share 的 X25519 私钥（32 字节）
/// - `server_public_key`：服务端配置的 X25519 公钥（32 字节）
/// - `hello_random_first_20`：ClientHello.Random 的前 20 字节（HKDF salt）
///
/// # 返回
/// 32 字节 auth_key（同时用于 AES-256-GCM 和 HMAC-SHA512）。
pub fn derive_auth_key(
    ecdhe_private_key: &[u8],
    server_public_key: &[u8],
    hello_random_first_20: &[u8],
) -> Result<[u8; AUTH_KEY_LEN], RealityError> {
    if ecdhe_private_key.len() != X25519_KEY_LEN {
        return Err(RealityError::InvalidPrivateKeyLen {
            actual: ecdhe_private_key.len(),
        });
    }
    if server_public_key.len() != X25519_KEY_LEN {
        return Err(RealityError::InvalidPublicKeyLen {
            actual: server_public_key.len(),
        });
    }
    if hello_random_first_20.len() != HKDF_SALT_LEN {
        return Err(RealityError::AuthKeyDeriveFailed);
    }

    // ECDH(X25519)
    let secret = x25519_dalek::StaticSecret::from(try_array32(ecdhe_private_key));
    let public = x25519_dalek::PublicKey::from(try_array32(server_public_key));
    let shared = secret.diffie_hellman(&public);
    if shared.as_bytes().iter().all(|&b| b == 0) {
        return Err(RealityError::EmptySharedKey);
    }

    // HKDF-SHA256: new(salt=hello_random[:20], ikm=shared).expand("REALITY", 32)
    let hk = Hkdf::<Sha256>::new(Some(hello_random_first_20), shared.as_bytes());
    let mut auth_key = [0u8; AUTH_KEY_LEN];
    hk.expand(HKDF_INFO, &mut auth_key)
        .map_err(|_| RealityError::AuthKeyDeriveFailed)?;
    Ok(auth_key)
}

/// AES-256-GCM 加密 session_id[:16]，密文+tag 覆盖整个 32 字节 session_id。
///
/// 对应 Go：
/// ```go
/// aead := crypto.NewAesGcm(uConn.AuthKey)  // AES-256-GCM
/// aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
/// ```
///
/// Go `Seal(dst[:0], nonce, plaintext, additional_data)` 原地写：密文(16B) + tag(16B)
/// = 32 字节，正好覆盖整个 session_id。
///
/// # 参数
/// - `auth_key`：32 字节 AES-256 key（来自 [`derive_auth_key`]）
/// - `nonce_12`：ClientHello.Random 的后 12 字节（`hello.Random[20:32]`）
/// - `session_id`：可变的 32 字节 session_id，前 16 字节作为明文加密，结果覆盖全部
/// - `hello_raw`：ClientHello 原始字节（AES-GCM additional data）
///
/// # 返回
/// `session_id` 被原地修改：`[ciphertext(16), tag(16)]`。
pub fn encrypt_session_id(
    auth_key: &[u8],
    nonce_12: &[u8],
    session_id: &mut [u8; SESSION_ID_LEN],
    hello_raw: &[u8],
) -> Result<(), RealityError> {
    if auth_key.len() != AUTH_KEY_LEN {
        return Err(RealityError::SessionIdEncryptFailed);
    }
    if nonce_12.len() != AEAD_NONCE_LEN {
        return Err(RealityError::SessionIdEncryptFailed);
    }

    let cipher = Aes256Gcm::new_from_slice(auth_key)
        .map_err(|_| RealityError::SessionIdEncryptFailed)?;
    let mut nonce_arr = [0u8; AEAD_NONCE_LEN];
    nonce_arr.copy_from_slice(nonce_12);
    let nonce = Nonce::from(nonce_arr);

    // plaintext = session_id[:16], aad = hello_raw
    let sealed = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &session_id[..16],
                aad: hello_raw,
            },
        )
        .map_err(|_| RealityError::SessionIdEncryptFailed)?;

    // sealed = ciphertext(16) + tag(16) = 32 bytes，覆盖整个 session_id
    if sealed.len() != SESSION_ID_LEN {
        return Err(RealityError::SessionIdEncryptFailed);
    }
    session_id.copy_from_slice(&sealed);
    Ok(())
}

/// 解密 session_id（[`encrypt_session_id`] 的逆操作）。
///
/// 服务端 REALITY 验证用：用 ECDH 派生的 auth_key 解密客户端发来的 32 字节
/// session_id（= ciphertext(16) + tag(16)），还原 16 字节明文 payload。
///
/// # 参数
/// - `auth_key`：ECDH+HKDF 派生的 32 字节 key
/// - `nonce_12`：AES-GCM nonce（watfaq 协议固定为 `ClientHello.Random[20..32]`）
/// - `sealed_session_id`：客户端发来的 32 字节 session_id（密文+tag）
/// - `hello_raw`：完整 ClientHello handshake message 字节（AAD，须与加密时一致）
///
/// # 返回
/// 16 字节明文（`[version(3) | reserved(1) | timestamp(4 BE) | short_id(8 零填充)]`）.
pub fn decrypt_session_id(
    auth_key: &[u8],
    nonce_12: &[u8],
    sealed_session_id: &[u8],
    hello_raw: &[u8],
) -> Result<[u8; 16], RealityError> {
    if auth_key.len() != AUTH_KEY_LEN
        || nonce_12.len() != AEAD_NONCE_LEN
        || sealed_session_id.len() != SESSION_ID_LEN
    {
        return Err(RealityError::SessionIdDecryptFailed);
    }
    let cipher = Aes256Gcm::new_from_slice(auth_key)
        .map_err(|_| RealityError::SessionIdDecryptFailed)?;
    let mut nonce_arr = [0u8; AEAD_NONCE_LEN];
    nonce_arr.copy_from_slice(nonce_12);
    let plaintext = cipher
        .decrypt(
            &Nonce::from(nonce_arr),
            Payload {
                msg: sealed_session_id,
                aad: hello_raw,
            },
        )
        .map_err(|_| RealityError::SessionIdDecryptFailed)?;
    if plaintext.len() != 16 {
        return Err(RealityError::SessionIdDecryptFailed);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&plaintext);
    Ok(out)
}

/// 解析后的 session_id 明文负载。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPayload {
    /// 协议版本（3 字节，watfaq 默认 `[1, 8, 1]`）。
    pub version: [u8; 3],
    /// session_id 内嵌的 Unix timestamp（秒，big-endian u32）。
    pub timestamp: u32,
    /// 客户端 short_id（固定 8 字节，不足零填充）。
    pub short_id: [u8; 8],
}

/// 校验解密后的 session_id 明文负载。
///
/// 服务端 REALITY 验证用：检查 timestamp 在窗口内、short_id 在白名单。
///
/// # 参数
/// - `plaintext_16`：[`decrypt_session_id`] 返回的 16 字节明文
/// - `now_unix`：当前 Unix 时间戳（秒）
/// - `max_diff`：允许的时间偏差（秒）
/// - `short_ids`：服务端 short_id 白名单（每个 8 字节）
pub fn verify_session_payload(
    plaintext_16: &[u8; 16],
    now_unix: u32,
    max_diff: u32,
    short_ids: &[[u8; 8]],
) -> Result<SessionPayload, RealityError> {
    let mut version = [0u8; 3];
    version.copy_from_slice(&plaintext_16[0..3]);
    let timestamp = u32::from_be_bytes([
        plaintext_16[4],
        plaintext_16[5],
        plaintext_16[6],
        plaintext_16[7],
    ]);
    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&plaintext_16[8..16]);

    // timestamp 窗口校验（双向：防重放 + 防过期）
    let diff = if now_unix >= timestamp {
        now_unix - timestamp
    } else {
        timestamp - now_unix
    };
    if diff > max_diff {
        return Err(RealityError::TimestampOutOfWindow {
            actual: timestamp,
            expected: now_unix,
            max_diff,
        });
    }

    // short_id 白名单校验
    if !short_ids.contains(&short_id) {
        return Err(RealityError::ShortIdNotAllowed);
    }

    Ok(SessionPayload {
        version,
        timestamp,
        short_id,
    })
}

/// HMAC-SHA512 证书验证（REALITY 服务端自签证书的快速验证路径）。
///
/// 对应 Go `VerifyPeerCertificate`：
/// ```go
/// if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
///     h := hmac.New(sha512.New, c.AuthKey)
///     h.Write(pub)
///     if bytes.Equal(h.Sum(nil), certs[0].Signature) {
///         c.Verified = true
///         return nil
///     }
/// }
/// ```
///
/// REALITY 服务端生成 Ed25519 自签证书时，签名值 = HMAC-SHA512(auth_key, public_key)，
/// 而非真正的 Ed25519 签名。客户端用 auth_key 重算 HMAC 比对即可验证。
///
/// # 参数
/// - `auth_key`：ECDH 派生的 32 字节 auth_key
/// - `cert_pub_key_ed25519`：证书公钥的原始字节（Ed25519 公钥 = 32 字节）
/// - `cert_signature`：证书签名值（应 = HMAC-SHA512 输出 = 64 字节）
///
/// # 返回
/// `true` = 验证通过（是 REALITY 证书）；`false` = 不是 REALITY 证书（走标准 x509 验证）。
///
/// # 恒定时间比较
/// 使用 `crypto_mac::Mac::verify_slice` 内部的恒定时间比较，防时序攻击。
pub fn verify_reality_certificate(
    auth_key: &[u8],
    cert_pub_key_ed25519: &[u8],
    cert_signature: &[u8],
) -> Result<bool, RealityError> {
    let mut mac = HmacSha512::new_from_slice(auth_key)
        .map_err(|_| RealityError::EmptySharedKey)?;
    mac.update(cert_pub_key_ed25519);
    // verify_slice 内部用恒定时间比较，长度/内容不匹配都返 Err
    Ok(mac.verify_slice(cert_signature).is_ok())
}

/// 服务端签名 REALITY 证书（HMAC-SHA512）。
///
/// [`verify_reality_certificate`] 的逆运算：
/// HMAC-SHA512(auth_key, ed25519_pub_key) → 64 字节签名。
///
/// 服务端用此签名覆盖 cert 末尾 64 字节（rcgen Ed25519 self-signed cert 的
/// signature 字段）。客户端校验时同样计算 HMAC 比对。
///
/// # 参数
///
/// - `auth_key`：HKDF-SHA256 派生的认证密钥（ECDH 输出）
/// - `cert_pub_key_ed25519`：Ed25519 公钥原始字节（32 字节）
///
/// # 返回
///
/// 64 字节 HMAC-SHA512 签名。
///
/// # Errors
///
/// - [`RealityError::EmptySharedKey`]：auth_key 为空
pub fn sign_reality_certificate(
    auth_key: &[u8],
    cert_pub_key_ed25519: &[u8],
) -> Result<[u8; 64], RealityError> {
    let mut mac = HmacSha512::new_from_slice(auth_key)
        .map_err(|_| RealityError::EmptySharedKey)?;
    mac.update(cert_pub_key_ed25519);
    let result = mac.finalize().into_bytes();
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&result);
    Ok(sig)
}

/// 将 32 字节切片转为数组（失败返 [`RealityError::InvalidPrivateKeyLen`]）。
fn try_array32(b: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(b);
    arr
}


#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    /// 从固定种子确定性生成 X25519 密钥对（测试用，无需 RNG）。
    fn make_keypair(seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret);
        (secret.to_bytes(), public.to_bytes())
    }

    // ===== encode_session_id 测试 =====

    #[test]
    fn encode_session_id_basic_layout() {
        let short_id = [0xaa; 8];
        let sid = encode_session_id([1, 2, 3], 0x12345678, &short_id).unwrap();
        assert_eq!(sid[0], 1); // version_x
        assert_eq!(sid[1], 2); // version_y
        assert_eq!(sid[2], 3); // version_z
        assert_eq!(sid[3], 0); // reserved
        assert_eq!(&sid[4..8], &[0x12, 0x34, 0x56, 0x78]); // timestamp BE
        assert_eq!(&sid[8..16], &short_id); // short_id
        assert_eq!(&sid[16..], &[0u8; 16]); // 余下 0
    }

    #[test]
    fn encode_session_id_short_id_partial() {
        let short_id = [0xff; 4];
        let sid = encode_session_id([0, 0, 0], 0, &short_id).unwrap();
        assert_eq!(&sid[8..12], &short_id);
        assert_eq!(&sid[12..], &[0u8; 20]); // 余下 0
    }

    #[test]
    fn encode_session_id_short_id_too_long_errors() {
        let short_id = [0u8; 9];
        let err = encode_session_id([0; 3], 0, &short_id).unwrap_err();
        assert!(matches!(
            err,
            RealityError::InvalidShortIdLen { actual: 9 }
        ));
    }

    #[test]
    fn encode_session_id_full_8_byte_short_id_fills_exactly() {
        let short_id = [0x42; 8];
        let sid = encode_session_id([0; 3], 0, &short_id).unwrap();
        assert_eq!(&sid[8..16], &short_id);
        // [16..32] 全 0
        assert_eq!(&sid[16..], &[0u8; 16]);
    }

    // ===== derive_auth_key 测试 =====

    #[test]
    fn derive_auth_key_e2e_x25519() {
        let (client_priv, _) = make_keypair([0x42; 32]);
        let (_, server_pub) = make_keypair([0x99; 32]);
        let hello_random = [0x55u8; 20];

        let auth_key = derive_auth_key(&client_priv, &server_pub, &hello_random);
        assert!(auth_key.is_ok(), "ECDH 应成功");
        let auth_key = auth_key.unwrap();
        assert_eq!(auth_key.len(), AUTH_KEY_LEN);
        assert_ne!(auth_key, [0u8; 32]); // 非全 0
    }

    #[test]
    fn derive_auth_key_symmetric_consistency() {
        // 同一对密钥协商，从两端派生的 shared secret 应相同
        // （但 auth_key 还依赖 hello_random + HKDF，两端用相同 salt 应一致）
        let (client_priv, client_pub) = make_keypair([0x42; 32]);
        let (server_priv, server_pub) = make_keypair([0x99; 32]);
        let hello_random = [0x33u8; 20];

        let ak_client = derive_auth_key(&client_priv, &server_pub, &hello_random).unwrap();
        let ak_server = derive_auth_key(&server_priv, &client_pub, &hello_random).unwrap();
        // ECDH 对称性：两端 shared secret 相同 → HKDF 输出相同
        assert_eq!(ak_client, ak_server);
    }

    #[test]
    fn derive_auth_key_wrong_private_key_len() {
        let server_pub = [0u8; 32];
        let hello_random = [0u8; 20];
        let err = derive_auth_key(&[0u8; 16], &server_pub, &hello_random).unwrap_err();
        assert!(matches!(
            err,
            RealityError::InvalidPrivateKeyLen { actual: 16 }
        ));
    }

    #[test]
    fn derive_auth_key_wrong_public_key_len() {
        let client_priv = [0u8; 32];
        let hello_random = [0u8; 20];
        let err = derive_auth_key(&client_priv, &[0u8; 16], &hello_random).unwrap_err();
        assert!(matches!(
            err,
            RealityError::InvalidPublicKeyLen { actual: 16 }
        ));
    }

    #[test]
    fn derive_auth_key_wrong_random_len() {
        let client_priv = [0u8; 32];
        let server_pub = [0u8; 32];
        let err = derive_auth_key(&client_priv, &server_pub, &[0u8; 16]).unwrap_err();
        assert!(matches!(err, RealityError::AuthKeyDeriveFailed));
    }

    #[test]
    fn derive_auth_key_deterministic() {
        let (client_priv, _) = make_keypair([0x42; 32]);
        let (_, server_pub) = make_keypair([0x99; 32]);
        let hello_random = [0x77u8; 20];
        let ak1 = derive_auth_key(&client_priv, &server_pub, &hello_random).unwrap();
        let ak2 = derive_auth_key(&client_priv, &server_pub, &hello_random).unwrap();
        assert_eq!(ak1, ak2, "相同输入应派生相同 auth_key");
    }

    // ===== encrypt_session_id 测试 =====

    #[test]
    fn encrypt_session_id_e2e_roundtrip() {
        let auth_key = [0x42u8; 32];
        let nonce_12 = [0x11u8; 12];
        let mut session_id = [0u8; 32];
        session_id[0] = 1; // version
        session_id[8] = 0xff; // some short_id byte
        let original_first_16: [u8; 16] = session_id[..16].try_into().unwrap();
        let hello_raw = b"fake ClientHello raw bytes";

        encrypt_session_id(&auth_key, &nonce_12, &mut session_id, hello_raw).unwrap();
        // 加密后 session_id 应全非 0（极大概率）
        assert_ne!(&session_id[..16], &original_first_16[..]);
        assert_ne!(session_id, [0u8; 32]);

        // 解密验证（用相同 key/nonce/aad 解密 session_id[:16]）
        let cipher = Aes256Gcm::new_from_slice(&auth_key).unwrap();
        let nonce = Nonce::from(nonce_12);
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &session_id, // 整个 32B = ciphertext(16) + tag(16)
                    aad: hello_raw,
                },
            )
            .unwrap();
        assert_eq!(plaintext.len(), 16);
        assert_eq!(&plaintext[..], &original_first_16[..]);
    }

    #[test]
    fn encrypt_session_id_wrong_key_len() {
        let mut session_id = [0u8; 32];
        let err = encrypt_session_id(&[0u8; 16], &[0u8; 12], &mut session_id, &[]).unwrap_err();
        assert!(matches!(err, RealityError::SessionIdEncryptFailed));
    }

    #[test]
    fn encrypt_session_id_wrong_nonce_len() {
        let mut session_id = [0u8; 32];
        let err = encrypt_session_id(&[0u8; 32], &[0u8; 8], &mut session_id, &[]).unwrap_err();
        assert!(matches!(err, RealityError::SessionIdEncryptFailed));
    }

    #[test]
    fn encrypt_session_id_different_aad_produces_different_ciphertext() {
        let auth_key = [0x42u8; 32];
        let nonce_12 = [0x11u8; 12];
        let mut sid1 = [0u8; 32];
        let mut sid2 = [0u8; 32];
        sid1[0] = 1;
        sid2[0] = 1;
        encrypt_session_id(&auth_key, &nonce_12, &mut sid1, b"aad1").unwrap();
        encrypt_session_id(&auth_key, &nonce_12, &mut sid2, b"aad2").unwrap();
        assert_ne!(sid1, sid2, "不同 AAD 应产生不同密文");
    }

    // ===== verify_reality_certificate 测试 =====

    #[test]
    fn verify_reality_certificate_valid() {
        let auth_key = [0x42u8; 32];
        let cert_pub_key = [0xabu8; 32];

        // 服务端构造签名 = HMAC-SHA512(auth_key, cert_pub_key)
        let mut mac = HmacSha512::new_from_slice(&auth_key).unwrap();
        mac.update(&cert_pub_key);
        let signature = mac.finalize().into_bytes();

        let verified =
            verify_reality_certificate(&auth_key, &cert_pub_key, &signature).unwrap();
        assert!(verified);
    }

    #[test]
    fn verify_reality_certificate_wrong_signature() {
        let auth_key = [0x42u8; 32];
        let cert_pub_key = [0xabu8; 32];
        let wrong_sig = [0u8; 64]; // 全 0 签名

        let verified =
            verify_reality_certificate(&auth_key, &cert_pub_key, &wrong_sig).unwrap();
        assert!(!verified);
    }

    #[test]
    fn verify_reality_certificate_wrong_key_fails() {
        // 用 auth_key_A 签名，用 auth_key_B 验证 → 失败
        let auth_key_a = [0x42u8; 32];
        let auth_key_b = [0x99u8; 32];
        let cert_pub_key = [0xabu8; 32];

        let mut mac = HmacSha512::new_from_slice(&auth_key_a).unwrap();
        mac.update(&cert_pub_key);
        let signature = mac.finalize().into_bytes();

        let verified =
            verify_reality_certificate(&auth_key_b, &cert_pub_key, &signature).unwrap();
        assert!(!verified);
    }

    #[test]
    fn verify_reality_certificate_length_mismatch_returns_false() {
        // 签名长度不匹配（HMAC-SHA512 = 64 字节，传入短签名）
        let auth_key = [0x42u8; 32];
        let cert_pub_key = [0xabu8; 32];
        let short_sig = [0u8; 16];

        let verified =
            verify_reality_certificate(&auth_key, &cert_pub_key, &short_sig).unwrap();
        assert!(!verified);
    }

    // ===== 完整协议链路 E2E =====

    #[test]
    fn full_reality_crypto_pipeline_e2e() {
        // 客户端密钥对 + 服务端密钥对
        let (client_priv, client_pub) = make_keypair([0x42; 32]);
        let (server_priv, server_pub) = make_keypair([0x99; 32]);
        let hello_random_20 = [0x55u8; 20];
        let nonce_12 = [0x66u8; 12];
        let hello_raw = b"mock ClientHello raw bytes for AAD";
        let short_id = [0xaa; 8];

        // 客户端：encode session_id
        let mut session_id = encode_session_id([1, 8, 16], 1_700_000_000, &short_id).unwrap();

        // 两端独立派生 auth_key（ECDH 对称性 → 结果相同）
        let client_auth_key =
            derive_auth_key(&client_priv, &server_pub, &hello_random_20).unwrap();
        let server_auth_key =
            derive_auth_key(&server_priv, &client_pub, &hello_random_20).unwrap();
        assert_eq!(client_auth_key, server_auth_key);

        // 客户端：encrypt session_id
        encrypt_session_id(&client_auth_key, &nonce_12, &mut session_id, hello_raw).unwrap();

        // 服务端：解密 session_id 验证（解密是 encrypt 的逆操作）
        let cipher = Aes256Gcm::new_from_slice(&server_auth_key).unwrap();
        let nonce = Nonce::from(nonce_12);
        let decrypted = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &session_id,
                    aad: hello_raw,
                },
            )
            .unwrap();
        assert_eq!(decrypted.len(), 16);
        // decrypted 应对应 encode_session_id 的前 16 字节
        let expected_sid =
            encode_session_id([1, 8, 16], 1_700_000_000, &short_id).unwrap();
        assert_eq!(&decrypted[..], &expected_sid[..16]);

        // 服务端：构造 REALITY 证书并验证
        let cert_pub_key = [0xcdu8; 32];
        let mut mac = HmacSha512::new_from_slice(&server_auth_key).unwrap();
        mac.update(&cert_pub_key);
        let cert_sig = mac.finalize().into_bytes();

        let verified = verify_reality_certificate(
            &client_auth_key,
            &cert_pub_key,
            &cert_sig,
        )
        .unwrap();
        assert!(verified, "客户端应能验证服务端的 REALITY 证书");
    }

    // ===== decrypt_session_id 测试 =====

    #[test]
    fn decrypt_session_id_roundtrip() {
        let auth_key = [0x42u8; 32];
        let nonce_12 = [0x11u8; 12];
        let hello_raw = b"mock ClientHello AAD";
        let short_id = [0xaa; 8];
        let mut session_id = encode_session_id([1, 8, 16], 1_700_000_000, &short_id).unwrap();
        encrypt_session_id(&auth_key, &nonce_12, &mut session_id, hello_raw).unwrap();

        let plaintext = decrypt_session_id(&auth_key, &nonce_12, &session_id, hello_raw).unwrap();
        let expected = encode_session_id([1, 8, 16], 1_700_000_000, &short_id).unwrap();
        assert_eq!(&plaintext[..], &expected[..16]);
    }

    #[test]
    fn decrypt_session_id_wrong_key_fails() {
        let auth_key = [0x42u8; 32];
        let wrong_key = [0x99u8; 32];
        let nonce_12 = [0x11u8; 12];
        let mut session_id = [0u8; 32];
        encrypt_session_id(&auth_key, &nonce_12, &mut session_id, b"AAD").unwrap();

        let err = decrypt_session_id(&wrong_key, &nonce_12, &session_id, b"AAD").unwrap_err();
        assert!(matches!(err, RealityError::SessionIdDecryptFailed));
    }

    #[test]
    fn decrypt_session_id_wrong_aad_fails() {
        let auth_key = [0x42u8; 32];
        let nonce_12 = [0x11u8; 12];
        let mut session_id = [0u8; 32];
        encrypt_session_id(&auth_key, &nonce_12, &mut session_id, b"AAD1").unwrap();

        let err = decrypt_session_id(&auth_key, &nonce_12, &session_id, b"AAD2").unwrap_err();
        assert!(matches!(err, RealityError::SessionIdDecryptFailed));
    }

    #[test]
    fn decrypt_session_id_wrong_length_fails() {
        let auth_key = [0x42u8; 32];
        let nonce_12 = [0x11u8; 12];
        assert!(matches!(
            decrypt_session_id(&auth_key, &nonce_12, &[0u8; 16], b"AAD").unwrap_err(),
            RealityError::SessionIdDecryptFailed
        ));
    }

    // ===== verify_session_payload 测试 =====

    #[test]
    fn verify_session_payload_ok() {
        let mut plaintext = [0u8; 16];
        plaintext[0..3].copy_from_slice(&[1, 8, 1]);
        plaintext[4..8].copy_from_slice(&1_700_000_000u32.to_be_bytes());
        plaintext[8..16].copy_from_slice(&[0xaa; 8]);
        let short_ids = vec![[0xaa; 8], [0xbb; 8]];
        let payload = verify_session_payload(&plaintext, 1_700_000_010, 120, &short_ids).unwrap();
        assert_eq!(payload.version, [1, 8, 1]);
        assert_eq!(payload.timestamp, 1_700_000_000);
        assert_eq!(payload.short_id, [0xaa; 8]);
    }

    #[test]
    fn verify_session_payload_timestamp_out_of_window() {
        let mut plaintext = [0u8; 16];
        plaintext[4..8].copy_from_slice(&1_700_000_000u32.to_be_bytes());
        plaintext[8..16].copy_from_slice(&[0xaa; 8]);
        let short_ids = vec![[0xaa; 8]];
        let err = verify_session_payload(&plaintext, 1_700_000_300, 120, &short_ids).unwrap_err();
        assert!(matches!(err, RealityError::TimestampOutOfWindow { .. }));
    }

    #[test]
    fn verify_session_payload_short_id_not_allowed() {
        let mut plaintext = [0u8; 16];
        plaintext[8..16].copy_from_slice(&[0xaa; 8]);
        let short_ids = vec![[0xbb; 8]];
        let err = verify_session_payload(&plaintext, 0, 120, &short_ids).unwrap_err();
        assert!(matches!(err, RealityError::ShortIdNotAllowed));
    }

    #[test]
    fn verify_session_payload_e2e_with_decrypt() {
        // 完整链路：encode → encrypt → decrypt → verify
        let (client_priv, client_pub) = make_keypair([0x42; 32]);
        let (server_priv, server_pub) = make_keypair([0x99; 32]);
        let hello_random = [0x55u8; 32];
        let hello_raw = b"mock ClientHello";
        let short_id = [0xaa; 8];
        let timestamp = 1_700_000_000u32;

        let mut session_id = encode_session_id([1, 8, 1], timestamp, &short_id).unwrap();
        let client_auth_key =
            derive_auth_key(&client_priv, &server_pub, &hello_random[..20]).unwrap();
        encrypt_session_id(&client_auth_key, &hello_random[20..32], &mut session_id, hello_raw)
            .unwrap();

        // 服务端视角
        let server_auth_key =
            derive_auth_key(&server_priv, &client_pub, &hello_random[..20]).unwrap();
        let plaintext =
            decrypt_session_id(&server_auth_key, &hello_random[20..32], &session_id, hello_raw)
                .unwrap();
        let short_ids = vec![[0xaa; 8]];
        let payload =
            verify_session_payload(&plaintext, timestamp, 120, &short_ids).unwrap();
        assert_eq!(payload.short_id, short_id);
    }
}
