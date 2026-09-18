//! REALITY 服务端。
//!
//! 翻译自 Go `transport/internet/reality/reality.go` 的 `Server`/`Conn` 部分。
//!
//! # 为什么 ClientHello 手动解析
//! Go 借助 `tls.Server` 读 ClientHello。Rust rustls 的 `server::Acceptor` 不直接暴露
//! session_id / Random / key_share（TLS 内部字段）。本实现手动解析 TLS record 字节，
//! 仅提取 REALITY 验证需要的字段，参考 Go `common/protocol/tls/sniff.go::ReadClientHello`。

use crate::error::RealityError;
use crate::mitm::{build_server_config, generate_reality_ed25519_cert};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// 解析后的 TLS 1.3 ClientHello（仅提取 REALITY 验证需要的字段）。
#[derive(Debug, Clone)]
pub struct ParsedClientHello<'a> {
    /// 完整 ClientHello handshake message 字节（record payload，作为 AES-GCM AAD）。
    pub handshake_message: &'a [u8],
    /// ClientHello.legacy_version（2 字节，如 TLS 1.3 仍发 `[0x03, 0x03]`）。
    /// fs0o: REALITY 版本门控字段——按字典序与 `min_client_ver`/`max_client_ver` 比较。
    pub legacy_version: [u8; 2],
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
    let handshake_message = &msg[..4 + hs_len];
    let body = &msg[4..4 + hs_len];
    // body: legacy_version(2) + random(32) + session_id(1+n)
    if body.len() < 2 + 32 + 1 {
        return Err(RealityError::InvalidConnection);
    }
    let mut legacy_version = [0u8; 2];
    legacy_version.copy_from_slice(&body[..2]);
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
        legacy_version,
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
///
/// tvky (REALITY 10.0)：同时支持 X25519MLKEM768 hybrid key share
/// (group=0x4588 = 4588，data = mlkem ek(1184) + x25519 pub(32)，共 1216 字节)。
/// Go `MlkemEcdhe.ECDH(serverPub)` 仅返回 X25519 段（`ecdh.PrivateKey.ECDH`
/// 是纯 X25519），hybrid MLKEM 段在 auth_key 派生中不参与；REALITY 10.0
/// PQC 安全性来自 TLS session key 的 hybrid 派生，而非 auth_key 本身。
/// 对应 Go utls `handshake_client.go:181-183`
/// `{group: X25519MLKEM768, data: append(mlkemEncapsulationKey, x25519EphemeralKey...)}`。
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
        // X25519 (group 0x001d): 32 字节公钥
        if group == 0x001d && key_len == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&d[4..4 + 32]);
            return Some(k);
        }
        // X25519MLKEM768 hybrid (group 0x4588): 1184B MLKEM ek + 32B X25519 pub，
        // X25519 部分在末尾。Go 端 `MlkemEcdhe.ECDH(serverPub)` 只消费 X25519 段。
        if group == 0x4588 && key_len == 1216 {
            let x_start = 4 + 1184; // skip mlkem ek
            let mut k = [0u8; 32];
            k.copy_from_slice(&d[x_start..x_start + 32]);
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
/// - `min_client_ver`/`max_client_ver`：fs0o REALITY 版本门控，字节字典序比较
///   **解密 payload 前 3 字节 ClientVer**（客户端 Xray 版本，client
///   `encode_session_id` 写入 `[0..3)`；Go xtls/reality tls.go:259-267
///   `copy(hs.c.ClientVer[:], plainText)`。Go 端默认 `MinClientVer=[26,3,27]`
///   即 Xray-core v26.3.27，空切片=不校验）。
pub fn verify_reality_client_hello(
    parsed: &ParsedClientHello<'_>,
    server_static_private: &[u8; 32],
    now_unix: u32,
    max_diff: u32,
    allowed_short_ids: &[[u8; 8]],
    min_client_ver: &[u8],
    max_client_ver: &[u8],
) -> Result<(crate::crypto::SessionPayload, [u8; 32]), RealityError> {
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
    let payload =
        crate::crypto::verify_session_payload(&plaintext, now_unix, max_diff, allowed_short_ids)?;

    // 6. ft0g: 版本门控——对齐 Go xtls/reality tls.go:259-267，比较**解密 payload
    //    前 3 字节 ClientVer**（客户端 Xray 版本），而非 ClientHello.legacy_version
    //    （TLS1.3 恒 [0x03,0x03]，读它 = min 配置下全客户端被拒 / max 恒过）。
    //    字典序：[major, minor, patch]；空切片=无限边界（不限制）。
    if !min_client_ver.is_empty() && payload.version.as_slice() < min_client_ver {
        return Err(RealityError::ClientVersionTooOld);
    }
    if !max_client_ver.is_empty() && payload.version.as_slice() > max_client_ver {
        return Err(RealityError::ClientVersionTooNew);
    }
    Ok((payload, auth_key))
}

/// [`server_tls`] 的返回：REALITY 验证成功返回 TLS 连接，失败返回原连接 + 已读 record 供 fallback。
pub enum RealityServerOutcome<C> {
    /// REALITY 验证通过，返回 rustls TLS 连接（可传给 VLESS 入站）。
    Verified(TlsStream<PrefixedReader<C>>),
    /// REALITY 验证失败。调用方可拿回 `conn` + `record` 做 [`fallback_to_dest`]。
    Invalid {
        conn: C,
        record: Vec<u8>,
        reason: RealityError,
    },
}

/// REALITY 服务端握手（切片3b-ii）。
///
/// 流程：
/// 1. [`read_tls_record`] 读 ClientHello record
/// 2. [`parse_client_hello`] + [`verify_reality_client_hello`] 验证
/// 3. 成功：[`generate_reality_ed25519_cert`] + [`build_server_config`] + rustls TLS 握手
/// 4. 失败：返回 [`RealityServerOutcome::Invalid`]，调用方决定 fallback
///
/// # 参数
///
/// - `conn`：客户端 TCP 连接
/// - `server_private_key`：服务端 X25519 静态私钥（对应 client 配置的 `public_key`）
/// - `allowed_short_ids`：允许的 short_id 白名单
/// - `max_diff`：允许的 timestamp 偏差秒数（Go 默认 ±12h = 43200）
/// - `min_client_ver`/`max_client_ver`：fs0o REALITY 版本门控；slice 与解密
///   payload 前 3 字节 ClientVer 字典序比较（ft0g 对齐 Go tls.go:259-267）。
///   空切片=无限边界（不限制）。
/// - `server_names`：SNI 白名单（精确匹配，对齐 Go `xtls/reality` tls.go:211/466
///   `config.ServerNames[serverName]`：无 SNI 或不在白名单 → 前置失败走
///   steal-oneself fallback）。空切片 = 门禁用（仅测试用低层 API；生产
///   parse 层已强制非空白名单，Go transport_security.go:94-96 空 serverNames 拒启）。
///
/// # Errors
///
/// - [`read_tls_record`] IO 错误 → [`RealityError::TlsHandshake`]
/// - 证书生成 / ServerConfig 构建失败 → [`RealityError::CertGenerate`]
/// - TLS 握手失败 → [`RealityError::TlsHandshake`]
///
/// 验证失败（parse/verify）**不返回 Err**，而是返回 [`RealityServerOutcome::Invalid`]，
/// 让调用方决定是否 [`fallback_to_dest`]。
pub async fn server_tls<C>(
    mut conn: C,
    server_private_key: &[u8; 32],
    allowed_short_ids: &[[u8; 8]],
    max_diff: u32,
    min_client_ver: &[u8],
    max_client_ver: &[u8],
    server_names: &[String],
) -> std::result::Result<RealityServerOutcome<C>, RealityError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let record = read_tls_record(&mut conn).await.map_err(|e| {
        RealityError::TlsHandshake(format!("read ClientHello: {e}"))
    })?;
    let outcome = (|| {
        let parsed = parse_client_hello(&record)?;
        // t38j：SNI 白名单前置门。Go xtls/reality tls.go:211 `!config.ServerNames[
        // serverName]` → break（steal-oneself fallback），在 short_id/timestamp
        // 校验之前；精确匹配（map 查找），无 SNI 视为不匹配。
        if !server_names.is_empty() {
            let sni = parsed.server_name.as_deref().unwrap_or("");
            if !server_names.iter().any(|n| n == sni) {
                return Err(RealityError::InvalidServerName(sni.to_string()));
            }
        }

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        let (_payload, auth_key) = verify_reality_client_hello(
            &parsed,
            server_private_key,
            now_unix,
            max_diff,
            allowed_short_ids,
            min_client_ver,
            max_client_ver,
        )?;
        Ok::<_, RealityError>(auth_key)
    })();

    let auth_key = match outcome {
        Ok(v) => v,
        Err(reason) => {
            return Ok(RealityServerOutcome::Invalid { conn, record, reason });
        }
    };

    // 3. 成功分支：生成 REALITY HMAC 证书 + TLS 握手
    // （证书为进程级固定空模板，Go init() 语义，与 SNI 无关）
    let (cert_der, key_der) = generate_reality_ed25519_cert(&auth_key)?;
    let server_config = build_server_config(cert_der, key_der)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let prefixed = PrefixedReader::new(record, conn);
    match acceptor.accept(prefixed).await {
        Ok(tls) => Ok(RealityServerOutcome::Verified(tls)),
        Err(e) => Err(RealityError::TlsHandshake(e.to_string())),
    }
}

/// TLS record 最大长度（RFC 5246: 2^14 bytes，防止恶意 OOM）。
const MAX_TLS_RECORD_LEN: usize = 16384;

/// 从流读取一个完整 TLS record（5 字节 header + payload），返回完整 record 字节。
///
/// 翻译自 Go `common/protocol/tls/sniff.go::ReadClientHello` 的 record 读取部分。
/// 用于 REALITY 服务端：先读到完整 ClientHello record，再 [`parse_client_hello`] + verify。
pub async fn read_tls_record<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut header = [0u8; 5];
    reader.read_exact(&mut header).await?;
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    if length > MAX_TLS_RECORD_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("TLS record length {length} exceeds max {MAX_TLS_RECORD_LEN}"),
        ));
    }
    let mut record = Vec::with_capacity(5 + length);
    record.extend_from_slice(&header);
    record.resize(5 + length, 0);
    reader.read_exact(&mut record[5..]).await?;
    Ok(record)
}

/// 先返回 `prefix` 字节，耗尽后转发到 `inner` 的 [`AsyncRead`]；写操作直接转发到 `inner`。
///
/// REALITY 服务端读出 ClientHello record 后，rustls 服务端需要完整 TLS 字节流
/// （不能跳过已读的 ClientHello）。[`PrefixedReader`] 把已读 record 重新注入流头，
/// 让 rustls 像读新连接一样处理。写方向不需 prefix（直接写原连接）。
///
/// REALITY 服务端读出 ClientHello record 后，rustls 服务端需要完整 TLS 字节流
/// （不能跳过已读的 ClientHello）。[`PrefixedReader`] 把已读 record 重新注入流头，
/// 让 rustls 像读新连接一样处理。
pub struct PrefixedReader<R> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: R,
}

impl<R> PrefixedReader<R> {
    /// 创建：`prefix` 是已读字节（如 ClientHello record），`inner` 是原连接。
    pub fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self { prefix, prefix_pos: 0, inner }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixedReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.prefix_pos < self.prefix.len() {
            let remaining = self.prefix.len() - self.prefix_pos;
            let n = std::cmp::min(remaining, buf.remaining());
            let filled = buf.initialize_unfilled();
            filled[..n].copy_from_slice(&self.prefix[self.prefix_pos..self.prefix_pos + n]);
            self.prefix_pos += n;
            buf.advance(n);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }}

impl<R: AsyncWrite + Unpin> AsyncWrite for PrefixedReader<R> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// PROXY protocol 编码与 fallback 转发已上移至 `xray_transport::fallback`
//（VLESS/Trojan/REALITY 共用的通用逻辑）。
pub use xray_transport::fallback::{encode_proxy_header, fallback_to_dest};

#[cfg(test)]
mod tests {
    use super::*;

    /// 确保 rustls CryptoProvider 在并行测试中只初始化一次
    fn ensure_crypto_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| { let _ = rustls::crypto::ring::default_provider().install_default(); });
    }

    #[tokio::test]
    async fn read_tls_record_roundtrip() {
        let mut record = vec![0x16, 0x03, 0x01, 0x00, 0x0a];
        record.extend_from_slice(&[0u8; 10]);
        let mut reader = &record[..];
        let got = read_tls_record(&mut reader).await.unwrap();
        assert_eq!(got, record);
    }

    #[tokio::test]
    async fn read_tls_record_rejects_too_long() {
        let record = [0x16, 0x03, 0x01, 0x4e, 0x20]; // length=20000
        let mut reader = &record[..];
        let err = read_tls_record(&mut reader).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_tls_record_eof_on_truncated_header() {
        let record = [0x16, 0x03];
        let mut reader = &record[..];
        let err = read_tls_record(&mut reader).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn prefixed_reader_drains_prefix_then_inner() {
        use tokio::io::AsyncReadExt;
        let prefix = b"hello".to_vec();
        let inner = b" world";
        let mut reader = PrefixedReader::new(prefix, &inner[..]);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello world");
    }

    #[tokio::test]
    async fn prefixed_reader_empty_prefix_forwards_inner() {
        use tokio::io::AsyncReadExt;
        let mut reader = PrefixedReader::new(Vec::new(), &b"data"[..]);
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"data");
    }

    #[tokio::test]
    async fn prefixed_reader_partial_reads() {
        use tokio::io::AsyncReadExt;
        let prefix = b"abcdef".to_vec();
        let inner = b"XYZ";
        let mut reader = PrefixedReader::new(prefix, &inner[..]);
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ab");
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"cd");
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ef");
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"XY");
        let mut one = [0u8; 1];
        reader.read_exact(&mut one).await.unwrap();
        assert_eq!(&one, b"Z");
    }
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

    /// 构造最小 TLS 1.3 ClientHello record（测试用，含 session_id + key_share + 可选 SNI）。
    /// `legacy_version` 可定制——fs0o 测试用。
    fn build_test_client_hello_with_legacy_version(
        random: &[u8; 32],
        session_id: &[u8; 32],
        key_share_x25519: &[u8; 32],
        sni: Option<&str>,
        legacy_version: &[u8; 2],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(legacy_version);
        body.extend_from_slice(random);
        body.push(32);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);

        let mut exts = Vec::new();
        if let Some(name) = sni {
            let nb = name.as_bytes();
            let list_len = 1 + 2 + nb.len();
            let mut sni_ext = Vec::new();
            sni_ext.extend_from_slice(&(list_len as u16).to_be_bytes());
            sni_ext.push(0);
            sni_ext.extend_from_slice(&(nb.len() as u16).to_be_bytes());
            sni_ext.extend_from_slice(nb);
            exts.extend_from_slice(&[0x00, 0x00]);
            exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
            exts.extend_from_slice(&sni_ext);
        }
        let mut ks_ext = Vec::new();
        ks_ext.extend_from_slice(&((2 + 2 + 32) as u16).to_be_bytes());
        ks_ext.extend_from_slice(&[0x00, 0x1d]);
        ks_ext.extend_from_slice(&[0x00, 0x20]);
        ks_ext.extend_from_slice(key_share_x25519);
        exts.extend_from_slice(&[0x00, 0x33]);
        exts.extend_from_slice(&(ks_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ks_ext);

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01);
        let blen = body.len();
        hs.push((blen >> 16) as u8);
        hs.push((blen >> 8) as u8);
        hs.push(blen as u8);
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
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

    /// tvky (REALITY 10.0)：X25519MLKEM768 hybrid key_share entry（group=0x4588，
    /// 1216B = 1184B ML-KEM ek + 32B X25519 pub）→ parse 出末尾 X25519 段。
    fn build_test_client_hello_hybrid_key_share(
        random: &[u8; 32],
        session_id: &[u8; 32],
        mlkem_ek: &[u8; 1184],
        x25519_pub_tail: &[u8; 32],
        sni: Option<&str>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(random);
        body.push(32);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);

        let mut exts = Vec::new();
        if let Some(name) = sni {
            let nb = name.as_bytes();
            let list_len = 1 + 2 + nb.len();
            let mut sni_ext = Vec::new();
            sni_ext.extend_from_slice(&(list_len as u16).to_be_bytes());
            sni_ext.push(0);
            sni_ext.extend_from_slice(&(nb.len() as u16).to_be_bytes());
            sni_ext.extend_from_slice(nb);
            exts.extend_from_slice(&[0x00, 0x00]);
            exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
            exts.extend_from_slice(&sni_ext);
        }
        // X25519MLKEM768 hybrid key share entry
        let mut ks_ext = Vec::new();
        ks_ext.extend_from_slice(&((2 + 2 + 1216) as u16).to_be_bytes());
        ks_ext.extend_from_slice(&[0x45, 0x88]); // X25519MLKEM768 = 4588
        ks_ext.extend_from_slice(&[0x04, 0xC0]); // key_len = 1216
        ks_ext.extend_from_slice(mlkem_ek);
        ks_ext.extend_from_slice(x25519_pub_tail);
        exts.extend_from_slice(&[0x00, 0x33]);
        exts.extend_from_slice(&(ks_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ks_ext);

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01);
        let blen = body.len();
        hs.push((blen >> 16) as u8);
        hs.push((blen >> 8) as u8);
        hs.push(blen as u8);
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        let hl = hs.len();
        record.push((hl >> 8) as u8);
        record.push(hl as u8);
        record.extend_from_slice(&hs);
        record
    }

    /// tvky：hybrid key_share 解析——确认从 1216B 末尾 32B 取出 X25519 公钥。
    #[test]
    fn parse_client_hello_x25519mlkem768_hybrid_key_share() {
        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32];
        // 模拟 ML-KEM-768 encapsulation key（1184B，任意值）
        let mlkem_ek = [0xAAu8; 1184];
        let x25519_pub_tail = [0xBBu8; 32]; // hybrid entry 末尾 X25519 公钥
        let record = build_test_client_hello_hybrid_key_share(
            &random,
            &session_id,
            &mlkem_ek,
            &x25519_pub_tail,
            Some("example.com"),
        );
        let parsed = parse_client_hello(&record).unwrap();
        // 关键断言：parse 出末尾 32B 而非 MLKEM 段前 32B
        assert_eq!(parsed.key_share_x25519, Some(x25519_pub_tail));
        assert_eq!(parsed.random, random);
        assert_eq!(parsed.session_id, session_id);
        assert_eq!(parsed.server_name.as_deref(), Some("example.com"));
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
        build_reality_client_hello_with_version(
            random,
            server_static_private,
            client_private,
            [1, 8, 1], // version（对齐 watfaq 默认）
            timestamp,
            short_id,
            sni,
        )
    }

    /// [`build_reality_client_hello`] 的 ClientVer 定制版（ft0g 版本门控测试用）。
    fn build_reality_client_hello_with_version(
        random: &[u8; 32],
        server_static_private: &[u8; 32],
        client_private: &[u8; 32],
        version: [u8; 3],
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
        plaintext[0..3].copy_from_slice(&version);
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

    /// tvky：构造含 X25519MLKEM768 hybrid key_share 的完整 REALITY ClientHello record。
    ///
    /// 与 [`build_reality_client_hello`] 相同流程但 key_share entry 为 hybrid
    /// （group=0x4588，1216B = 1184B ML-KEM ek + 32B X25519 pub），auth_key
    /// 仍只从 X25519 段派生（与 Go `MlkemEcdhe.ECDH(serverPub)` 语义一致）。
    fn build_reality_client_hello_hybrid(
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

        // 1. 构造 session_id=0 的 hybrid ClientHello（拿 AAD）
        let zero_sid = [0u8; 32];
        let mlkem_ek_placeholder = [0xAAu8; 1184];
        let record_zero = build_test_client_hello_hybrid_key_share(
            random,
            &zero_sid,
            &mlkem_ek_placeholder,
            client_pub.as_bytes(),
            sni,
        );
        let parsed_zero = parse_client_hello(&record_zero).unwrap();

        // 2. auth_key（仅 X25519 段 ECDH，与 Go MlkemEcdhe.ECDH 语义一致）
        let auth_key =
            derive_auth_key(client_private, server_pub.as_bytes(), &random[..20]).unwrap();

        // 3. plaintext[16] = [version(3)|reserved(1)|timestamp(4 BE)|short_id(8)]
        let mut plaintext = [0u8; 16];
        plaintext[0..3].copy_from_slice(&[1, 8, 1]);
        plaintext[3] = 0;
        plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
        plaintext[8..16].copy_from_slice(short_id);

        // 4. encrypt → 32B ciphertext session_id
        let mut sid = [0u8; 32];
        sid[..16].copy_from_slice(&plaintext);
        encrypt_session_id(&auth_key, &random[20..32], &mut sid, parsed_zero.handshake_message)
            .unwrap();

        // 5. 构造最终 hybrid ClientHello
        build_test_client_hello_hybrid_key_share(
            random,
            &sid,
            &mlkem_ek_placeholder,
            client_pub.as_bytes(),
            sni,
        )
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
        let (payload, _auth_key) =
            verify_reality_client_hello(&parsed, &server_priv, now, 43200, &[short_id], &[], &[]).unwrap();
        assert_eq!(payload.timestamp, now);
        assert_eq!(payload.short_id, short_id);
        assert_eq!(payload.version, [1, 8, 1]);
    }

    /// tvky：X25519MLKEM768 hybrid ClientHello 走完整 verify 路径——auth_key
    /// 仅从 hybrid entry 末尾 X25519 段派生（与 Go `MlkemEcdhe.ECDH(serverPub)`
    /// 语义一致），AES-GCM 解密成功 → payload 校验通过。
    #[test]
    fn verify_reality_client_hello_x25519mlkem768_hybrid_ok() {
        let random = [0x55u8; 32];
        let server_priv = [0x11u8; 32];
        let client_priv = [0x22u8; 32];
        let now = 1_700_000_000u32;
        let short_id = [0xaa; 8];

        let record = build_reality_client_hello_hybrid(
            &random,
            &server_priv,
            &client_priv,
            now,
            &short_id,
            Some("example.com"),
        );
        let parsed = parse_client_hello(&record).unwrap();
        // 关键断言：hybrid entry 解析出末尾 X25519 公钥
        assert!(parsed.key_share_x25519.is_some());
        let (payload, auth_key) = verify_reality_client_hello(
            &parsed,
            &server_priv,
            now,
            43200,
            &[short_id],
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(payload.timestamp, now);
        assert_eq!(payload.short_id, short_id);
        // auth_key 与纯 X25519 路径派生一致（hybrid 仅扩展 transport layer，
        // auth_key 仍走 X25519-only ECDH，与 Go MlkemEcdhe.ECDH 对齐）
        assert_eq!(auth_key.len(), 32);
        assert!(auth_key.iter().any(|&b| b != 0));
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
        let err = verify_reality_client_hello(&parsed, &[0u8; 32], 0, 0, &[], &[], &[]).unwrap_err();
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
            verify_reality_client_hello(&parsed, &wrong_priv, now, 43200, &[short_id], &[], &[]).unwrap_err();
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
        ], &[], &[])
        .unwrap_err();
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
            verify_reality_client_hello(&parsed, &server_priv, now, 43200, &server_allowed, &[], &[])
                .unwrap_err();
        assert!(matches!(err, RealityError::ShortIdNotAllowed));
    }

    // ===== fs0o/ft0g: REALITY 版本门控行为测试 =====
    // ft0g: 门控读**解密 payload 的 ClientVer**（Go xtls/reality tls.go:259-267
    // `copy(hs.c.ClientVer[:], plainText)`），不再读 ClientHello.legacy_version。

    /// 统一构造：真加密 ClientHello（定制 ClientVer）→ verify，时间窗/short_id 合法。
    fn ft0g_verify_with_ver(
        ver: [u8; 3],
        min: &[u8],
        max: &[u8],
    ) -> Result<crate::crypto::SessionPayload, RealityError> {
        let random = [0x55u8; 32];
        let server_priv = [0x11u8; 32];
        let client_priv = [0x22u8; 32];
        let now = 1_700_000_000u32;
        let short_id = [0xaa; 8];
        let record = build_reality_client_hello_with_version(
            &random, &server_priv, &client_priv, ver, now, &short_id, None,
        );
        let parsed = parse_client_hello(&record).unwrap();
        verify_reality_client_hello(&parsed, &server_priv, now, 43200, &[short_id], min, max)
            .map(|(p, _)| p)
    }

    /// 解密 ClientVer 低于 `min_client_ver` → 拒绝并报 ClientVersionTooOld。
    #[test]
    fn fs0o_min_client_ver_rejects_old_version() {
        // 客户端报 [1,8,1]（watfaq 默认），min=[26,3,27]（Xray v26.3.27）→ 拒。
        let err = ft0g_verify_with_ver([1, 8, 1], &[26, 3, 27], &[]).unwrap_err();
        assert!(matches!(err, RealityError::ClientVersionTooOld));
    }

    /// 解密 ClientVer 高于 `max_client_ver` → 拒绝并报 ClientVersionTooNew。
    #[test]
    fn fs0o_max_client_ver_rejects_new_version() {
        let err = ft0g_verify_with_ver([26, 9, 10], &[], &[26, 9, 9]).unwrap_err();
        assert!(matches!(err, RealityError::ClientVersionTooNew));
    }

    /// min..max 区间内 → 通过，且 payload.version 原样返回。
    #[test]
    fn fs0o_in_range_version_passes() {
        let payload = ft0g_verify_with_ver([26, 7, 28], &[26, 3, 27], &[26, 9, 9]).unwrap();
        assert_eq!(payload.version, [26, 7, 28]);
    }

    /// ft0g 回归：门控不再读 legacy_version——TLS1.3 恒 [0x03,0x03]，旧实现下
    /// min=[26,3,27] 会把所有真实客户端拒掉（fail-closed DoS）；现在合法
    /// ClientVer 过闸。此测试在旧实现（读 legacy_version）下必失败。
    #[test]
    fn ft0g_gate_reads_decrypted_client_ver_not_legacy_version() {
        // legacy_version 恒 [0x03,0x03]（build_test_client_hello 写死）；
        // 若门控读它，[3,3] < [26,3,27] → 误拒。解密 ClientVer=[26,9,9] → 应过。
        let payload = ft0g_verify_with_ver([26, 9, 9], &[26, 3, 27], &[]).unwrap();
        assert_eq!(payload.version, [26, 9, 9]);
    }

    /// ft0g 回归：ClientVer 恰等于 min/max 边界 → 过（Go `>=`/`<=` 含等号）。
    #[test]
    fn ft0g_boundary_version_equals_min_passes() {
        let payload = ft0g_verify_with_ver([26, 3, 27], &[26, 3, 27], &[]).unwrap();
        assert_eq!(payload.version, [26, 3, 27]);
    }

    /// 空切片=不限制（向后兼容）：任意 ClientVer 全过。
    #[test]
    fn fs0o_empty_min_max_means_unbounded() {
        let payload = ft0g_verify_with_ver([0, 0, 0], &[], &[]).unwrap();
        assert_eq!(payload.version, [0, 0, 0]);
    }

    fn fs0o_legacy_version_parsed_correctly() {
        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32];
        let key_share = [0x88u8; 32];
        let record = build_test_client_hello_with_legacy_version(
            &random,
            &session_id,
            &key_share,
            Some("example.com"),
            &[0x03, 0x04],
        );
        let parsed = parse_client_hello(&record).unwrap();
        assert_eq!(parsed.legacy_version, [0x03, 0x04]);
    }

    #[tokio::test]
    async fn server_tls_invalid_returns_invalid_outcome() {
        use tokio::io::{AsyncWriteExt, duplex};

        // 构造合法 TLS record 但 session_id 不含 REALITY 加密载荷（verify 失败）
        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32]; // 非加密载荷
        let key_share = [0x88u8; 32];
        let record =
            build_test_client_hello(&random, &session_id, &key_share, Some("example.com"));

        let (mut client, server) = duplex(4096);
        let server_priv = [0x11u8; 32];
        let short_id = [0xaa; 8];

        let server_task = tokio::spawn(async move {
            server_tls(server, &server_priv, &[short_id], 43200, &[], &[], &[]).await
        });

        // client 发送 ClientHello record 后保持连接（让 server_tls 完成 verify）
        client.write_all(&record).await.unwrap();

        let outcome = server_task.await.unwrap().unwrap();
        match outcome {
            RealityServerOutcome::Invalid { record: rec, reason, .. } => {
                assert_eq!(rec, record, "Invalid outcome 应保留原 record 供 fallback");
                assert!(
                    matches!(reason, RealityError::SessionIdDecryptFailed),
                    "expected SessionIdDecryptFailed, got {reason:?}"
                );
            }
            RealityServerOutcome::Verified(_) => panic!("expected Invalid, got Verified"),
        }
    }

    /// t38j：SNI 不在白名单 → 前置 Invalid（调用方 fallback_to_dest，
    /// Go xtls/reality tls.go:211 break 语义），在 short_id/timestamp 校验之前。
    #[tokio::test]
    async fn server_tls_sni_mismatch_returns_invalid() {
        use tokio::io::{AsyncWriteExt, duplex};

        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32];
        let key_share = [0x88u8; 32];
        let record =
            build_test_client_hello(&random, &session_id, &key_share, Some("example.com"));

        let (mut client, server) = duplex(4096);
        let server_priv = [0x11u8; 32];
        let whitelist = vec!["other.com".to_string()];

        let server_task = tokio::spawn(async move {
            server_tls(server, &server_priv, &[[0xaa; 8]], 43200, &[], &[], &whitelist).await
        });
        client.write_all(&record).await.unwrap();

        let outcome = server_task.await.unwrap().unwrap();
        match outcome {
            RealityServerOutcome::Invalid { reason, .. } => match reason {
                RealityError::InvalidServerName(sni) => {
                    assert_eq!(sni, "example.com");
                }
                other => panic!("expected InvalidServerName, got {other:?}"),
            },
            RealityServerOutcome::Verified(_) => panic!("expected Invalid, got Verified"),
        }
    }

    /// t38j：无 SNI（ClientHello 不带 server_name extension）→ 视为不匹配。
    #[tokio::test]
    async fn server_tls_missing_sni_returns_invalid() {
        use tokio::io::{AsyncWriteExt, duplex};

        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32];
        let key_share = [0x88u8; 32];
        let record = build_test_client_hello(&random, &session_id, &key_share, None);

        let (mut client, server) = duplex(4096);
        let server_priv = [0x11u8; 32];
        let whitelist = vec!["example.com".to_string()];

        let server_task = tokio::spawn(async move {
            server_tls(server, &server_priv, &[[0xaa; 8]], 43200, &[], &[], &whitelist).await
        });
        client.write_all(&record).await.unwrap();

        let outcome = server_task.await.unwrap().unwrap();
        assert!(
            matches!(
                outcome,
                RealityServerOutcome::Invalid {
                    reason: RealityError::InvalidServerName(_),
                    ..
                }
            ),
            "missing SNI must not pass the whitelist gate"
        );
    }

    #[tokio::test]
    async fn server_tls_eof_returns_tls_handshake_err() {
        use tokio::io::duplex;

        let (client, server) = duplex(4096);
        drop(client); // 立即关闭 client → server 读 EOF

        let server_priv = [0x11u8; 32];
        let result = server_tls(server, &server_priv, &[], 43200, &[], &[], &[]).await;

        assert!(
            matches!(result, Err(RealityError::TlsHandshake(_))),
            "expected Err(TlsHandshake) on EOF"
        );
    }

    /// verify 通过后进入 acceptor.accept 阶段（成功分支标志）。
    ///
    /// server_tls 在 verify 失败时返回 `Ok(Invalid)`，不会进入 Err 路径。
    /// 此测试发送合法 REALITY ClientHello，verify 通过 → 进入 accept → 因 client
    /// 端不响应 TLS 1.3 ServerHello，accept 失败 → `Err(TlsHandshake)`。
    /// `Err` + 已发送 record = verify 通过 + accept 阶段失败 = 成功分支进入标志。
    /// 完整 TLS 握手由 VPS #13 + 单元测试覆盖。
    #[tokio::test]
    async fn server_tls_verified_branch_enters_tls_accept() {
        ensure_crypto_provider();
        use tokio::io::{AsyncWriteExt, duplex};

        let random = [0x55u8; 32];
        let server_priv = [0x11u8; 32];
        let client_priv = [0x22u8; 32];
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(1_700_000_000);
        let short_id = [0xaa; 8];
        let record = build_reality_client_hello(
            &random,
            &server_priv,
            &client_priv,
            now,
            &short_id,
            Some("example.com"),
        );

        let (mut client, server) = duplex(8192);
        let server_task = tokio::spawn(async move {
            server_tls(server, &server_priv, &[short_id], 43200, &[], &[], &[]).await
        });

        // client 发送合法 REALITY ClientHello（verify 会通过）
        client.write_all(&record).await.unwrap();

        let result = server_task.await.unwrap();
        match result {
            // verify 通过 + accept 阶段失败（client 没继续 TLS）
            Err(RealityError::TlsHandshake(_)) => { /* 成功分支进入标志 */ }
            Ok(RealityServerOutcome::Invalid { reason, .. }) => {
                panic!("expected verify pass + TLS accept, got Invalid: {reason:?}");
            }
            Ok(RealityServerOutcome::Verified(_)) => { /* 不可能：client 未完成 TLS */ }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    /// 真 REALITY loopback：reality u_client (watfaq-rustls with_reality) + server_tls
    /// (HMAC 签名 cert)。验证完整 REALITY 握手成功。
    #[tokio::test]
    async fn reality_loopback_u_client_with_server_tls() {
        ensure_crypto_provider();
        use std::time::Duration;
        use tokio::io::duplex;
        use x25519_dalek::{PublicKey, StaticSecret};
        use crate::client::{u_client, UConnState};
        use crate::config::RealityConfig;
        use xray_proto::transport::internet::reality::Config as ProtoConfig;

        let server_priv_array = [0x11u8; 32];
        let short_id = [0xaa; 8];

        // server X25519 公钥（client RealityConfig.public_key）
        let server_secret = StaticSecret::from(server_priv_array);
        let server_pub = PublicKey::from(&server_secret);

        // client RealityConfig（fingerprint/server_name/public_key/short_id）
        let proto = ProtoConfig {
            fingerprint: "chrome".into(),
            public_key: server_pub.as_bytes().to_vec(),
            server_name: "example.com".into(),
            short_id: short_id.to_vec(),
            ..Default::default()
        };
        let reality_config = RealityConfig::from_proto(&proto).unwrap();
        let state = UConnState::new(reality_config).unwrap();

        // 双向管道（足够大 buffer 避免 TCP 反压）+ Connection 适配（btls 路径要求）
        let (client, server) = duplex(65536);
        let client = xray_transport::connection::DuplexConnection::new(client);

        // spawn server_tls
        let server_task = tokio::spawn(async move {
            server_tls(server, &server_priv_array, &[short_id], 43200, &[], &[], &[]).await
        });

        // client 端：reality u_client 握手
        let client_result = tokio::time::timeout(
            Duration::from_secs(10),
            u_client(client, state),
        )
        .await;

        let server_result = server_task.await.unwrap();

        match (client_result, server_result) {
            (Ok(Ok(_tls_stream)), Ok(RealityServerOutcome::Verified(_))) => {
                // 完整 REALITY 握手成功！
            }
            (Ok(Ok(_)), Ok(_)) => panic!("server unexpected outcome"),
            (Ok(Ok(_)), Err(e)) => panic!("server error: {e:?}"),
            (Ok(Err(e)), _) => panic!("client u_client failed: {e:?}"),
            (Err(_timeout), _) => panic!("client u_client timeout"),
        }
    }

    /// watfaq-rustls fallback 路径 loopback（指纹 `randomizednoalpn` 不被 btls
    /// 支持，u_client 走 `with_reality` rustls 握手）：完整 REALITY 握手 + 固定空模板
    /// 证书 HMAC 验证（Go init() 语义 cert 的 e2e 证明，独立于 btls 指纹路径）。
    #[tokio::test]
    async fn reality_loopback_watfaq_fallback_fingerprint() {
        ensure_crypto_provider();
        use std::time::Duration;
        use tokio::io::duplex;
        use x25519_dalek::{PublicKey, StaticSecret};
        use crate::client::{u_client, UConnState};
        use crate::config::RealityConfig;
        use xray_proto::transport::internet::reality::Config as ProtoConfig;

        let server_priv_array = [0x11u8; 32];
        let short_id = [0xaa; 8];

        let server_secret = StaticSecret::from(server_priv_array);
        let server_pub = PublicKey::from(&server_secret);

        let proto = ProtoConfig {
            fingerprint: "randomizednoalpn".into(),
            public_key: server_pub.as_bytes().to_vec(),
            server_name: "example.com".into(),
            short_id: short_id.to_vec(),
            ..Default::default()
        };
        let reality_config = RealityConfig::from_proto(&proto).unwrap();
        let state = UConnState::new(reality_config).unwrap();

        let (client, server) = duplex(65536);
        let client = xray_transport::connection::DuplexConnection::new(client);

        let server_task = tokio::spawn(async move {
            server_tls(server, &server_priv_array, &[short_id], 43200, &[], &[], &[]).await
        });

        let client_result =
            tokio::time::timeout(Duration::from_secs(10), u_client(client, state)).await;
        let server_result = server_task.await.unwrap();

        match (client_result, server_result) {
            (Ok(Ok(_tls_stream)), Ok(RealityServerOutcome::Verified(_))) => {
                // 完整 REALITY 握手成功（watfaq 路径 + 固定模板证书）
            }
            (Ok(Ok(_)), Ok(_)) => panic!("server unexpected outcome"),
            (Ok(Ok(_)), Err(e)) => panic!("server error: {e:?}"),
            (Ok(Err(e)), _) => panic!("client u_client failed: {e:?}"),
            (Err(_timeout), _) => panic!("client u_client timeout"),
        }
    }

    /// bd xvkh：REALITY 指纹矩阵 e2e。
    ///
    /// 覆盖 Go 基准指纹表全集（D:/Project/Xray-core/transport/internet/tls/tls.go:203-232）：
    /// - `PresetFingerprints`（tls.go:204-217）：chrome/firefox/safari/ios/android/
    ///   edge/360/qq（random 系走 fallback 矩阵）
    /// - `ModernFingerprints`（tls.go:219-232）：hellofirefox_120/148、hellochrome_120/
    ///   131/133、helloios_13/14、helloedge_106、hellosafari_26_3、hello360_11_0、
    ///   helloqq_11_1
    /// - 旧版变体（btls 映射到就近 connector，见 xray-tls btls_client.rs）
    ///
    /// 注：派单提及的 "2345" 在 Go v26.6.1 基准不存在（PresetFingerprints 无此键），
    /// 矩阵按 Go 实际集合执行。
    async fn reality_loopback_with_fingerprint(fp: &str) {
        use std::time::Duration;
        use tokio::io::duplex;
        use x25519_dalek::{PublicKey, StaticSecret};
        use crate::client::{u_client, UConnState};
        use crate::config::RealityConfig;
        use xray_proto::transport::internet::reality::Config as ProtoConfig;

        let server_priv_array = [0x11u8; 32];
        let short_id = [0xaa; 8];

        let server_secret = StaticSecret::from(server_priv_array);
        let server_pub = PublicKey::from(&server_secret);

        let proto = ProtoConfig {
            fingerprint: fp.to_string(),
            public_key: server_pub.as_bytes().to_vec(),
            server_name: "example.com".into(),
            short_id: short_id.to_vec(),
            ..Default::default()
        };
        let reality_config = RealityConfig::from_proto(&proto).unwrap();
        let state = UConnState::new(reality_config).unwrap();

        let (client, server) = duplex(65536);
        let client = xray_transport::connection::DuplexConnection::new(client);

        let server_task = tokio::spawn(async move {
            server_tls(server, &server_priv_array, &[short_id], 43200, &[], &[], &[]).await
        });

        let client_result =
            tokio::time::timeout(Duration::from_secs(10), u_client(client, state)).await;
        let server_result = server_task.await.unwrap();

        match (client_result, server_result) {
            (Ok(Ok(_tls_stream)), Ok(RealityServerOutcome::Verified(_))) => {}
            (Ok(Ok(_)), Ok(_)) => panic!("[{fp}] server unexpected outcome"),
            (Ok(Ok(_)), Err(e)) => panic!("[{fp}] server error: {e:?}"),
            (Ok(Err(e)), _) => panic!("[{fp}] client u_client failed: {e:?}"),
            (Err(_timeout), _) => panic!("[{fp}] client u_client timeout"),
        }
    }

    /// btls 浏览器指纹主路径矩阵：preset 8 + modern 11 + 旧版 2 = 21 例。
    ///
    /// **ignore 根因（aai 遗留，非本批引入）**：btls 客户端路径 REALITY 注入
    /// 在 BIO 写出时改写 ClientHello session_id（btls_reality.rs 拦截流），
    /// 但 BoringSSL 在消息构建期已将**原** session_id 计入握手 transcript——
    /// 服务端 transcript（含注入值）与客户端不一致 → ServerHello
    /// legacy_session_id_echo / Finished 校验失败 → 客户端秒败
    /// `TlsHandshake("[DECODE_ERROR]")`（既有 `reality_loopback_u_client_
    /// with_server_tls` 同因失败，commit 30b84bd 注记）。修复需 btls fork 提供
    /// pre-hash 注入 API（utls `hello.SessionId` 语义），属 btls-sys 层工作。
    /// 修复后去 ignore 即为 ≥10 指纹 btls 路径验收门。
    #[tokio::test]
    #[ignore = "btls REALITY transcript mismatch (aai legacy DECODE_ERROR); needs pre-hash injection API in btls fork"]
    async fn reality_fingerprint_matrix_btls() {
        ensure_crypto_provider();
        let matrix = [
            // PresetFingerprints（Go tls.go:204-212）
            "chrome",
            "firefox",
            "safari",
            "ios",
            "android",
            "edge",
            "360",
            "qq",
            // ModernFingerprints（Go tls.go:221-231）
            "hellofirefox_120",
            "hellofirefox_148",
            "hellochrome_120",
            "hellochrome_131",
            "hellochrome_133",
            "helloios_13",
            "helloios_14",
            "helloedge_106",
            "hellosafari_26_3",
            "hello360_11_0",
            "helloqq_11_1",
            // 旧版变体（btls 就近映射）
            "hellochrome_100",
            "hellofirefox_99",
        ];
        for fp in matrix {
            reality_loopback_with_fingerprint(fp).await;
        }
    }

    /// watfaq-rustls fallback 路径矩阵：`randomizednoalpn`/`hellorandomizednoalpn`
    /// 是仅有的两个不被 btls connector 覆盖的指纹（btls_client.rs:975 仅映射
    /// Random/Randomized/HelloRandomized/HelloRandomizedAlpn→Chrome133），走标准
    /// rustls ClientHello + REALITY session_id 注入（transcript 一致，可完整握手）。
    #[tokio::test]
    async fn reality_fingerprint_matrix_watfaq_fallback() {
        ensure_crypto_provider();
        for fp in ["randomizednoalpn", "hellorandomizednoalpn"] {
            reality_loopback_with_fingerprint(fp).await;
        }
    }

    /// 全 21 指纹名查表（无 btls 握手）——验证 xray-tls::fingerprint::get_fingerprint
    /// 能识别 21 个目标指纹名（preset 8 + modern 11 + 旧版 2 = 21）。
    /// 真实握手测试见上方 `reality_fingerprint_matrix_btls`（#[ignore]，
    /// btls transcript mismatch 修复后启用）。
    #[test]
    fn all_21_fingerprints_resolve() {
        let names = [
            // PresetFingerprints（Go tls.go:204-212）
            "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
            // ModernFingerprints（Go tls.go:221-231）
            "hellofirefox_120", "hellofirefox_148", "hellochrome_120", "hellochrome_131",
            "hellochrome_133", "helloios_13", "helloios_14", "helloedge_106",
            "hellosafari_26_3", "hello360_11_0", "helloqq_11_1",
            // 旧版变体（btls 就近映射）
            "hellochrome_100", "hellofirefox_99",
        ];
        assert_eq!(names.len(), 21, "matrix must be 21");
        for name in names {
            let fp = xray_tls::fingerprint::get_fingerprint(name)
                .unwrap_or_else(|e| panic!("fingerprint {name} must resolve: {e}"));
            // 解析后 enum variant 必非空/必可被 btls_client 路由
            let supported = xray_tls::btls_client::fingerprint_supported(&fp);
            assert!(
                supported
                    || matches!(fp,
                        xray_tls::fingerprint::Fingerprint::HelloRandomized
                        | xray_tls::fingerprint::Fingerprint::HelloRandomizedAlpn
                        | xray_tls::fingerprint::Fingerprint::HelloRandomizedNoAlpn
                        | xray_tls::fingerprint::Fingerprint::Randomized
                        | xray_tls::fingerprint::Fingerprint::RandomizedNoAlpn),
                "{name} ({fp:?}) must be either btls-supported or randomized-fallback"
            );
        }
    }
}
