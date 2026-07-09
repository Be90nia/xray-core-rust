//! REALITY 服务端。
//!
//! 翻译自 Go `transport/internet/reality/reality.go` 的 `Server`/`Conn` 部分。
//!
//! # 切片进度
//! - **切片1**（已完成）：client.rs 接入 watfaq-rustls RealityConfig。
//! - **切片2**（本切片）：纯逻辑验证层——[`parse_client_hello`] 字节解析 +
//!   [`crate::crypto::decrypt_session_id`] + [`crate::crypto::verify_session_payload`]。
//! - **切片3a**（本切片）：[`verify_reality_client_hello`] 组合（ECDH+HKDF+AES-GCM 解密+校验）。
//! - **切片3b**（待办）：IO 层（peek record + fallback pipe + rustls 服务端伪造证书）。
//!
//! # 为什么 ClientHello 手动解析
//! Go 借助 `tls.Server` 读 ClientHello。Rust rustls 的 `server::Acceptor` 不直接暴露
//! session_id / Random / key_share（TLS 内部字段）。本实现手动解析 TLS record 字节，
//! 仅提取 REALITY 验证需要的字段，参考 Go `common/protocol/tls/sniff.go::ReadClientHello`。

use crate::config::RealityConfig;
use crate::error::RealityError;

/// 解析后的 TLS 1.3 ClientHello（仅提取 REALITY 验证需要的字段）。
#[derive(Debug, Clone)]
pub struct ParsedClientHello<'a> {
    /// 完整 ClientHello handshake message 字节（record payload，作为 AES-GCM AAD）。
    pub handshake_message: &'a [u8],
    /// ClientHello.Random（32 字节）。前 20 字节是 HKDF salt，后 12 字节是 AES-GCM nonce。
    pub random: [u8; 32],
    /// ClientHello.SessionId（32 字节，REALITY 加密载荷 = ciphertext(16) + tag(16)）。
    pub session_id: [u8; 32],
    /// key_share extension 中的 X25519 公钥（32 字节）；无则 `None`。
    pub key_share_x25519: Option<[u8; 32]>,
    /// server_name extension 中的 SNI；无则 `None`（用于 server_names 白名单匹配）。
    pub server_name: Option<String>,
}

/// 解析 TLS record，提取 REALITY 验证需要的 ClientHello 字段。
///
/// 输入 = 完整 TLS record 字节（含 5 字节 record header）。
/// 对应 Go `crypto/tls` 的 ClientHello 解析 + `sniff.ReadClientHello` 的 SNI 提取。
///
/// REALITY 要求 ClientHello.SessionId 恰好 32 字节（承载加密载荷）；
/// 非标准长度（0 或其他）返回 [`RealityError::InvalidConnection`]。
pub fn parse_client_hello(record: &[u8]) -> Result<ParsedClientHello<'_>, RealityError> {
    // TLS record header: type(1) + version(2) + length(2) = 5
    if record.len() < 5 || record[0] != 0x16 {
        return Err(RealityError::InvalidConnection);
    }
    let rec_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record.len() < 5 + rec_len {
        return Err(RealityError::InvalidConnection);
    }
    parse_handshake(&record[5..5 + rec_len])
}

fn parse_handshake(msg: &[u8]) -> Result<ParsedClientHello<'_>, RealityError> {
    // handshake header: type(1) + length(3)
    if msg.len() < 4 || msg[0] != 0x01 {
        return Err(RealityError::InvalidConnection);
    }
    let hs_len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | (msg[3] as usize);
    if msg.len() < 4 + hs_len {
        return Err(RealityError::InvalidConnection);
    }
    // handshake_message = 整个 handshake（含 type+length header），作为 AES-GCM AAD
    let handshake_message = &msg[..4 + hs_len];
    let body = &msg[4..4 + hs_len];
    // body: legacy_version(2) + random(32) + session_id(1+n)
    if body.len() < 2 + 32 + 1 {
        return Err(RealityError::InvalidConnection);
    }
    let mut off = 2; // skip legacy_version
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[off..off + 32]);
    off += 32;
    let sid_len = body[off] as usize;
    off += 1;
    if sid_len != 32 || body.len() < off + 32 {
        return Err(RealityError::InvalidConnection);
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&body[off..off + 32]);
    off += 32;
    // cipher_suites(2+n)
    if body.len() < off + 2 {
        return Err(RealityError::InvalidConnection);
    }
    let cs_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2 + cs_len;
    // compression_methods(1+n)
    if body.len() < off + 1 {
        return Err(RealityError::InvalidConnection);
    }
    let cm_len = body[off] as usize;
    off += 1 + cm_len;
    // extensions(2+n)
    if body.len() < off + 2 {
        return Err(RealityError::InvalidConnection);
    }
    let ext_total = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + ext_total {
        return Err(RealityError::InvalidConnection);
    }
    let exts = &body[off..off + ext_total];

    let mut key_share_x25519 = None;
    let mut server_name = None;
    let mut e_off = 0;
    while e_off + 4 <= exts.len() {
        let etype = u16::from_be_bytes([exts[e_off], exts[e_off + 1]]);
        let elen = u16::from_be_bytes([exts[e_off + 2], exts[e_off + 3]]) as usize;
        e_off += 4;
        if e_off + elen > exts.len() {
            break;
        }
        let edata = &exts[e_off..e_off + elen];
        e_off += elen;
        match etype {
            0x0000 if server_name.is_none() => server_name = parse_sni(edata),
            0x0033 if key_share_x25519.is_none() => {
                key_share_x25519 = parse_key_share_x25519(edata);
            }
            _ => {}
        }
    }

    Ok(ParsedClientHello {
        handshake_message,
        random,
        session_id,
        key_share_x25519,
        server_name,
    })
}

/// 解析 server_name extension (0x0000)，返回第一个 host_name 类型的 SNI。
fn parse_sni(edata: &[u8]) -> Option<String> {
    if edata.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
    if edata.len() < 2 + list_len {
        return None;
    }
    let mut d = &edata[2..2 + list_len];
    while d.len() >= 3 {
        let name_type = d[0];
        let name_len = u16::from_be_bytes([d[1], d[2]]) as usize;
        if d.len() < 3 + name_len {
            return None;
        }
        if name_type == 0 {
            return std::str::from_utf8(&d[3..3 + name_len])
                .ok()
                .map(String::from);
        }
        d = &d[3 + name_len..];
    }
    None
}

/// 解析 key_share extension (0x0033)，返回 X25519 (group 0x001d) 的 32 字节公钥。
fn parse_key_share_x25519(edata: &[u8]) -> Option<[u8; 32]> {
    if edata.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
    if edata.len() < 2 + list_len {
        return None;
    }
    let mut d = &edata[2..2 + list_len];
    while d.len() >= 4 {
        let group = u16::from_be_bytes([d[0], d[1]]);
        let key_len = u16::from_be_bytes([d[2], d[3]]) as usize;
        if d.len() < 4 + key_len {
            return None;
        }
        if group == 0x001d && key_len == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&d[4..4 + 32]);
            return Some(k);
        }
        d = &d[4 + key_len..];
    }
    None
}

/// `session_id` 在 handshake_message 中的字节偏移。
///
/// handshake_message 布局：
/// `[type(1)][length(3)][legacy_version(2)][random(32)][sid_len(1)=32][session_id(32)][...]`
/// session_id 起始 = 1 + 3 + 2 + 32 + 1 = 39。
const SESSION_ID_OFFSET_IN_HANDSHAKE: usize = 39;

/// 服务端 REALITY 验证：组合 ECDH + HKDF + AES-GCM 解密 + timestamp/short_id 校验。
///
/// 对应 Go `transport/internet/reality/reality.go::Server` 的 session_id 校验。
/// watfaq-rustls 仅暴露 client 端 REALITY（`compute_session_id`），服务端验证需自行实现。
///
/// # AAD 协议（关键，来自 watfaq `hs.rs` line 770-779）
///
/// client 端 `compute_session_id` 编码时先把 session_id 置全 0，再编码整个 handshake message，
/// 用此 zero-session-id 版本作为 AES-GCM AAD。因此服务端验证时必须取 handshake_message，
/// 把 session_id 字段（偏移 [`SESSION_ID_OFFSET_IN_HANDSHAKE`]，32 字节）替换为全 0 再解密。
///
/// # 参数
///
/// - `parsed`: [`parse_client_hello`] 的输出。
/// - `server_static_private`: 服务端静态 X25519 私钥（对应 client 配置的 `public_key`）。
/// - `now_unix`: 当前 Unix 时间戳（秒）。
/// - `max_diff`: 允许的 timestamp 偏差秒数（Go 默认 ±12h = 43200）。
/// - `allowed_short_ids`: 允许的 short_id 白名单（每个 8 字节）。
pub fn verify_reality_client_hello(
    parsed: &ParsedClientHello<'_>,
    server_static_private: &[u8; 32],
    now_unix: u32,
    max_diff: u32,
    allowed_short_ids: &[[u8; 8]],
) -> Result<crate::crypto::SessionPayload, RealityError> {
    // 1. 提取 client X25519 公钥（来自 key_share extension）
    let client_pub = parsed
        .key_share_x25519
        .ok_or(RealityError::NoKeyShareX25519)?;

    // 2. 构造 zero-session-id handshake message（AES-GCM AAD）
    //    复用 parsed.handshake_message（record payload，含 handshake type+length header），
    //    把 session_id 字段替换为全 0，对齐 watfaq client 端编码行为。
    let mut aad = parsed.handshake_message.to_vec();
    let sid_end = SESSION_ID_OFFSET_IN_HANDSHAKE + crate::crypto::SESSION_ID_LEN;
    if aad.len() < sid_end {
        return Err(RealityError::InvalidConnection);
    }
    // 防御性校验：sid_len 字段（偏移 38）必须 == 32
    if aad[SESSION_ID_OFFSET_IN_HANDSHAKE - 1] != crate::crypto::SESSION_ID_LEN as u8 {
        return Err(RealityError::InvalidConnection);
    }
    aad[SESSION_ID_OFFSET_IN_HANDSHAKE..sid_end].fill(0);

    // 3. ECDH(server_priv, client_pub) → auth_key
    //    X25519 ECDH 对称：ECDH(server_priv, client_pub) == ECDH(client_priv, server_pub)，
    //    与 client 端 derive_auth_key(client_priv, server_pub, ...) 产出相同 auth_key。
    let auth_key = crate::crypto::derive_auth_key(
        server_static_private,
        &client_pub,
        &parsed.random[..crate::crypto::HKDF_SALT_LEN],
    )?;

    // 4. AES-256-GCM 解密 session_id（nonce = random[20..32]）
    let plaintext = crate::crypto::decrypt_session_id(
        &auth_key,
        &parsed.random[crate::crypto::HKDF_SALT_LEN..],
        &parsed.session_id,
        &aad,
    )?;

    // 5. 校验 timestamp 窗口 + short_id 白名单
    crate::crypto::verify_session_payload(&plaintext, now_unix, max_diff, allowed_short_ids)
}

/// 创建 REALITY 服务端连接（IO 层，切片3 待实现）。
///
/// 当前返回 [`RealityError::UtlsRequired`]。完整实现需：peek ClientHello record →
/// [`parse_client_hello`] → 验证 → 成功走 rustls 服务端伪造证书 + VLESS；失败 fallback 到 dest。
pub fn server<C>(_inner: C, _config: RealityConfig) -> Result<(), RealityError> {
    Err(RealityError::UtlsRequired)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造最小 TLS 1.3 ClientHello record（测试用，含 session_id + key_share + 可选 SNI）。
    fn build_test_client_hello(
        random: &[u8; 32],
        session_id: &[u8; 32],
        key_share_x25519: &[u8; 32],
        sni: Option<&str>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(random);
        body.push(32); // session_id_len
        body.extend_from_slice(session_id);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: TLS_AES_128_GCM_SHA256
        body.extend_from_slice(&[1, 0]); // compression_methods: null

        let mut exts = Vec::new();
        if let Some(name) = sni {
            let nb = name.as_bytes();
            let list_len = 1 + 2 + nb.len();
            let mut sni_ext = Vec::new();
            sni_ext.extend_from_slice(&(list_len as u16).to_be_bytes());
            sni_ext.push(0); // host_name type
            sni_ext.extend_from_slice(&(nb.len() as u16).to_be_bytes());
            sni_ext.extend_from_slice(nb);
            exts.extend_from_slice(&[0x00, 0x00]); // server_name
            exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
            exts.extend_from_slice(&sni_ext);
        }
        let mut ks_ext = Vec::new();
        ks_ext.extend_from_slice(&((2 + 2 + 32) as u16).to_be_bytes());
        ks_ext.extend_from_slice(&[0x00, 0x1d]); // x25519
        ks_ext.extend_from_slice(&[0x00, 0x20]); // key_len=32
        ks_ext.extend_from_slice(key_share_x25519);
        exts.extend_from_slice(&[0x00, 0x33]); // key_share
        exts.extend_from_slice(&(ks_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ks_ext);

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        // handshake header
        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let blen = body.len();
        hs.push((blen >> 16) as u8);
        hs.push((blen >> 8) as u8);
        hs.push(blen as u8);
        hs.extend_from_slice(&body);

        // record header
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // legacy record version
        let hl = hs.len();
        record.push((hl >> 8) as u8);
        record.push(hl as u8);
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn parse_client_hello_valid_full() {
        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32];
        let key_share = [0x88u8; 32];
        let record =
            build_test_client_hello(&random, &session_id, &key_share, Some("example.com"));
        let parsed = parse_client_hello(&record).unwrap();
        assert_eq!(parsed.random, random);
        assert_eq!(parsed.session_id, session_id);
        assert_eq!(parsed.key_share_x25519, Some(key_share));
        assert_eq!(parsed.server_name.as_deref(), Some("example.com"));
        // handshake_message 应非空且指向 record 内部
        assert!(!parsed.handshake_message.is_empty());
    }

    #[test]
    fn parse_client_hello_no_sni() {
        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32];
        let key_share = [0x88u8; 32];
        let record = build_test_client_hello(&random, &session_id, &key_share, None);
        let parsed = parse_client_hello(&record).unwrap();
        assert!(parsed.server_name.is_none());
        assert_eq!(parsed.key_share_x25519, Some(key_share));
    }

    #[test]
    fn parse_client_hello_too_short() {
        assert!(matches!(
            parse_client_hello(&[0u8; 3]).unwrap_err(),
            RealityError::InvalidConnection
        ));
    }

    #[test]
    fn parse_client_hello_not_handshake_record() {
        let mut record = vec![0u8; 10];
        record[0] = 0x17; // ApplicationData
        assert!(parse_client_hello(&record).is_err());
    }

    #[test]
    fn parse_client_hello_wrong_handshake_type() {
        let random = [0u8; 32];
        let session_id = [0u8; 32];
        let key_share = [0u8; 32];
        let mut record = build_test_client_hello(&random, &session_id, &key_share, None);
        record[5] = 0x02; // 改 handshake type 为 ServerHello
        assert!(parse_client_hello(&record).is_err());
    }

    #[test]
    fn parse_client_hello_session_id_not_32() {
        // 构造 session_id_len=0 的 ClientHello（非 REALITY 客户端）
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id_len=0
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        body.extend_from_slice(&[1, 0]); // compression
        body.extend_from_slice(&[0x00, 0x00]); // extensions_len=0

        let mut hs = vec![0x01];
        let blen = body.len();
        hs.push((blen >> 16) as u8);
        hs.push((blen >> 8) as u8);
        hs.push(blen as u8);
        hs.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        let hl = hs.len();
        record.push((hl >> 8) as u8);
        record.push(hl as u8);
        record.extend_from_slice(&hs);

        assert!(matches!(
            parse_client_hello(&record).unwrap_err(),
            RealityError::InvalidConnection
        ));
    }

    #[test]
    fn server_stub_returns_utls_required() {
        let cfg = RealityConfig::default();
        let err = server::<()>((), cfg).unwrap_err();
        assert!(matches!(err, RealityError::UtlsRequired));
    }

    /// 构造完整 REALITY ClientHello record（含真实加密 session_id），测试 verify 用。
    ///
    /// 流程对齐 watfaq client `compute_session_id`：session_id=0 编码拿 AAD →
    /// derive_auth_key → encrypt_session_id → 用密文 session_id 重新编码。
    fn build_reality_client_hello(
        random: &[u8; 32],
        server_static_private: &[u8; 32],
        client_private: &[u8; 32],
        timestamp: u32,
        short_id: &[u8; 8],
        sni: Option<&str>,
    ) -> Vec<u8> {
        use crate::crypto::{derive_auth_key, encrypt_session_id};
        use x25519_dalek::{PublicKey, StaticSecret};

        let client_secret = StaticSecret::from(*client_private);
        let client_pub = PublicKey::from(&client_secret);
        let server_pub = PublicKey::from(&StaticSecret::from(*server_static_private));

        // 1. 构造 session_id=0 的 ClientHello（拿 AAD = handshake_message）
        let zero_sid = [0u8; 32];
        let record_zero = build_test_client_hello(random, &zero_sid, client_pub.as_bytes(), sni);
        let parsed_zero = parse_client_hello(&record_zero).unwrap();

        // 2. derive auth_key（client 视角：client_priv + server_pub）
        let auth_key =
            derive_auth_key(client_private, server_pub.as_bytes(), &random[..20]).unwrap();

        // 3. 构造 plaintext[16] = [version(3)|reserved(1)|timestamp(4 BE)|short_id(8)]
        let mut plaintext = [0u8; 16];
        plaintext[0..3].copy_from_slice(&[1, 8, 1]); // version（对齐 watfaq 默认）
        plaintext[3] = 0; // reserved
        plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
        plaintext[8..16].copy_from_slice(short_id);

        // 4. encrypt session_id[:16] → 密文 32 字节
        let mut sid = [0u8; 32];
        sid[..16].copy_from_slice(&plaintext);
        encrypt_session_id(&auth_key, &random[20..32], &mut sid, parsed_zero.handshake_message)
            .unwrap();

        // 5. 构造最终 ClientHello（session_id = 密文）
        build_test_client_hello(random, &sid, client_pub.as_bytes(), sni)
    }

    #[test]
    fn verify_reality_client_hello_ok() {
        let random = [0x55u8; 32];
        let server_priv = [0x11u8; 32];
        let client_priv = [0x22u8; 32];
        let now = 1_700_000_000u32;
        let short_id = [0xaa; 8];

        let record = build_reality_client_hello(
            &random,
            &server_priv,
            &client_priv,
            now,
            &short_id,
            Some("example.com"),
        );
        let parsed = parse_client_hello(&record).unwrap();
        let payload =
            verify_reality_client_hello(&parsed, &server_priv, now, 43200, &[short_id]).unwrap();
        assert_eq!(payload.timestamp, now);
        assert_eq!(payload.short_id, short_id);
        assert_eq!(payload.version, [1, 8, 1]);
    }

    #[test]
    fn verify_reality_client_hello_no_key_share() {
        // 构造无 key_share 的 ClientHello（extensions_len=0）
        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32];
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&random);
        body.push(32);
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&[0x00, 0x00]);

        let mut hs = vec![0x01];
        let blen = body.len();
        hs.push((blen >> 16) as u8);
        hs.push((blen >> 8) as u8);
        hs.push(blen as u8);
        hs.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        let hl = hs.len();
        record.push((hl >> 8) as u8);
        record.push(hl as u8);
        record.extend_from_slice(&hs);

        let parsed = parse_client_hello(&record).unwrap();
        assert!(parsed.key_share_x25519.is_none());
        let err = verify_reality_client_hello(&parsed, &[0u8; 32], 0, 0, &[]).unwrap_err();
        assert!(matches!(err, RealityError::NoKeyShareX25519));
    }

    #[test]
    fn verify_reality_client_hello_wrong_server_key() {
        let random = [0x55u8; 32];
        let server_priv = [0x11u8; 32];
        let client_priv = [0x22u8; 32];
        let now = 1_700_000_000u32;
        let short_id = [0xaa; 8];

        let record =
            build_reality_client_hello(&random, &server_priv, &client_priv, now, &short_id, None);
        let parsed = parse_client_hello(&record).unwrap();
        // 用错误的 server key 验证 → AES-GCM 解密失败
        let wrong_priv = [0x99u8; 32];
        let err =
            verify_reality_client_hello(&parsed, &wrong_priv, now, 43200, &[short_id]).unwrap_err();
        assert!(matches!(err, RealityError::SessionIdDecryptFailed));
    }

    #[test]
    fn verify_reality_client_hello_timestamp_out_of_window() {
        let random = [0x55u8; 32];
        let server_priv = [0x11u8; 32];
        let client_priv = [0x22u8; 32];
        let client_time = 1_700_000_000u32;
        let short_id = [0xaa; 8];

        let record = build_reality_client_hello(
            &random,
            &server_priv,
            &client_priv,
            client_time,
            &short_id,
            None,
        );
        let parsed = parse_client_hello(&record).unwrap();
        // server 时间偏离 100000s，max_diff=43200 → 超窗
        let server_now = client_time + 100_000;
        let err = verify_reality_client_hello(&parsed, &server_priv, server_now, 43200, &[
            short_id,
        ])
        .unwrap_err();
        assert!(matches!(err, RealityError::TimestampOutOfWindow { .. }));
    }

    #[test]
    fn verify_reality_client_hello_short_id_not_allowed() {
        let random = [0x55u8; 32];
        let server_priv = [0x11u8; 32];
        let client_priv = [0x22u8; 32];
        let now = 1_700_000_000u32;
        let client_short_id = [0xaa; 8];
        let server_allowed = [[0xbb; 8]]; // 不含 client_short_id

        let record = build_reality_client_hello(
            &random,
            &server_priv,
            &client_priv,
            now,
            &client_short_id,
            None,
        );
        let parsed = parse_client_hello(&record).unwrap();
        let err =
            verify_reality_client_hello(&parsed, &server_priv, now, 43200, &server_allowed)
                .unwrap_err();
        assert!(matches!(err, RealityError::ShortIdNotAllowed));
    }
}
