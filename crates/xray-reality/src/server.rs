//! REALITY 服务端。
//!
//! 翻译自 Go `transport/internet/reality/reality.go` 的 `Server`/`Conn` 部分。
//!
//! # 切片进度
//! - **切片1**（已完成）：client.rs 接入 watfaq-rustls RealityConfig。
//! - **切片2**（本切片）：纯逻辑验证层——[`parse_client_hello`] 字节解析 +
//!   [`crate::crypto::decrypt_session_id`] + [`crate::crypto::verify_session_payload`]。
//! - **切片3**（待办）：`verify_reality_client_hello` 组合（需确认 watfaq AAD 协议细节）+
//!   IO 层（peek record + fallback pipe + rustls 服务端伪造证书）。
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
}
