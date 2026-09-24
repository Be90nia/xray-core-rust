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

/// bd tce2：REALITY 握手成功后的 TLS 流（rustls 默认 / btls opt-in）。
///
/// 两路在「ClientHello 判定 / dest fallback / probe 喂值」三处共享同一前置
/// （[`verify_and_probe`]），仅 TLS 握手执行者不同；调用方按 AsyncRead +
/// AsyncWrite 消费，无感知具体实现。
pub enum RealityTlsStream<C> {
    /// 默认：rustls（tokio-rustls）TLS 1.3 握手。
    Rustls(TlsStream<PrefixedReader<C>>),
    /// bd tce2 opt-in：BoringSSL（btls）服务端握手。
    /// iOS 无注入 FFI（bd mygg 教训），整体 cfg 门控，opt-in 配置双保险。
    #[cfg(not(target_os = "ios"))]
    Btls(xray_tls::btls_server::BtlsServerStream<PrefixedReader<C>>),
}

impl<C: AsyncRead + AsyncWrite + Unpin> AsyncRead for RealityTlsStream<C> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Rustls(tls) => std::pin::Pin::new(tls).poll_read(cx, buf),
            #[cfg(not(target_os = "ios"))]
            Self::Btls(tls) => std::pin::Pin::new(tls).poll_read(cx, buf),
        }
    }
}

impl<C: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RealityTlsStream<C> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Rustls(tls) => std::pin::Pin::new(tls).poll_write(cx, buf),
            #[cfg(not(target_os = "ios"))]
            Self::Btls(tls) => std::pin::Pin::new(tls).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Rustls(tls) => std::pin::Pin::new(tls).poll_flush(cx),
            #[cfg(not(target_os = "ios"))]
            Self::Btls(tls) => std::pin::Pin::new(tls).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Rustls(tls) => std::pin::Pin::new(tls).poll_shutdown(cx),
            #[cfg(not(target_os = "ios"))]
            Self::Btls(tls) => std::pin::Pin::new(tls).poll_shutdown(cx),
        }
    }
}

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
    /// sb6g：key_share 中存在合格 X25519MLKEM768 entry（Go `peerPub2 != nil`：
    /// 位于可选 X25519 之前且不重复）。`false` = outdated/strange ClientHello，
    /// Go tls.go:233-235 reject→forward。
    pub key_share_mlkem768: bool,
    /// server_name extension 中的 SNI；无则 `None`（用于 server_names 白名单匹配）。
    pub server_name: Option<String>,
    /// bd frxi：alpn extension 中的协议名列表（按 ClientHello 顺序；无 extension 则空）。
    /// Go `tls.go:411-417` 用 `alpn_protocols[0]` 推导探测 key 的 alpn 段。
    pub alpn_protocols: Vec<String>,
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
    let mut key_share_mlkem768 = false;
    let mut server_name = None;
    let mut alpn_protocols = Vec::new();
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
                let (pub_key, mlkem_ok) = parse_key_shares(edata);
                key_share_x25519 = pub_key;
                key_share_mlkem768 = mlkem_ok;
            }
            // bd frxi：alpn extension（RFC 7301）。畸形项跳过——REALITY 验证
            // 不依赖 alpn，此处只服务探测 key 推导，不必硬错。
            0x0010 if alpn_protocols.is_empty() => alpn_protocols = parse_alpn(edata),
            _ => {}
        }
    }
    Ok(ParsedClientHello {
        handshake_message,
        legacy_version,
        random,
        session_id,
        key_share_x25519,
        key_share_mlkem768,
        server_name,
        alpn_protocols,
    })
}

/// 解析 alpn extension data（RFC 7301：`alpn_list(2) + [len(1)+name]*`）。
///
/// 畸形（长度越界）按截断处理返回已解析项——调用方仅用于探测 key 推导。
fn parse_alpn(edata: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if edata.len() < 2 {
        return out;
    }
    let list_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
    let end = std::cmp::min(2 + list_len, edata.len());
    let mut off = 2;
    while off < end {
        let name_len = edata[off] as usize;
        off += 1;
        if off + name_len > end {
            break;
        }
        if let Ok(name) = std::str::from_utf8(&edata[off..off + name_len]) {
            out.push(name.to_string());
        }
        off += name_len;
    }
    out
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
/// (group=0x11EC，data = mlkem ek(1184) + x25519 pub(32)，共 1216 字节)。
/// Go `MlkemEcdhe.ECDH(serverPub)` 仅返回 X25519 段（`ecdh.PrivateKey.ECDH`
/// 是纯 X25519），hybrid MLKEM 段在 auth_key 派生中不参与；REALITY 10.0
/// PQC 安全性来自 TLS session key 的 hybrid 派生，而非 auth_key 本身。
/// 对应 Go utls `handshake_client.go:181-183`
/// `{group: X25519MLKEM768, data: append(mlkemEncapsulationKey, x25519EphemeralKey...)}`。
///
/// sb6g：选择逻辑精确对齐 Go xtls/reality tls.go:233-244——返回
/// `(选中的 client X25519 公钥, 是否存在合格 MLKEM768 entry)`：
/// - X25519MLKEM768（group **0x11EC** = 十进制 4588；历史实现误写 0x4588
///   ——把十进制当十六进制，导致真实 hybrid entry 永不匹配）必须存在，
///   且位于可选独立 X25519 entry 之前、不重复；
/// - 独立 X25519（group 0x001D, 32B）首遇即停（Go `break // ensure order`），
///   其后 entry 不再消费；
/// - 无合格 MLKEM entry → `mlkem768_ok = false`，Go `peerPub2 == nil → break`
///   reject outdated/strange ClientHello → forward fallback。
fn parse_key_shares(edata: &[u8]) -> (Option<[u8; 32]>, bool) {
    if edata.len() < 2 {
        return (None, false);
    }
    let list_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
    if edata.len() < 2 + list_len {
        return (None, false);
    }
    let mut d = &edata[2..2 + list_len];
    let mut mlkem_pub: Option<[u8; 32]> = None;
    while d.len() >= 4 {
        let group = u16::from_be_bytes([d[0], d[1]]);
        let key_len = u16::from_be_bytes([d[2], d[3]]) as usize;
        if d.len() < 4 + key_len {
            return (None, false);
        }
        // X25519MLKEM768 hybrid (group 0x11EC): 1184B MLKEM ek + 32B X25519 pub，
        // X25519 部分在末尾。Go 端 `MlkemEcdhe.ECDH(serverPub)` 只消费 X25519 段。
        if group == 0x11ec && key_len == 1216 {
            if mlkem_pub.is_some() {
                // Go: 重复 MLKEM entry → `peerPub2 = nil // ensure once` → reject
                return (None, false);
            }
            let x_start = 4 + 1184; // skip mlkem ek
            let mut k = [0u8; 32];
            k.copy_from_slice(&d[x_start..x_start + 32]);
            mlkem_pub = Some(k);
        } else if group == 0x001d && key_len == 32 {
            // X25519 (group 0x001D): 32 字节公钥，Go peerPub 优先；
            // 首遇即 break——其后（顺序颠倒的 MLKEM）不消费 = reject。
            let mut k = [0u8; 32];
            k.copy_from_slice(&d[4..4 + 32]);
            return (Some(k), mlkem_pub.is_some());
        }
        d = &d[4 + key_len..];
    }
    // MLKEM-only：Go `if peerPub == nil { peerPub = peerPub2 }`（次选）
    (mlkem_pub, mlkem_pub.is_some())
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
    // sb6g：Go tls.go:233-235 `peerPub2 == nil → break`——缺合格
    // X25519MLKEM768 key share 的 outdated ClientHello（纯 X25519 单 share、
    // MLKEM 顺序颠倒、重复 MLKEM entry）一律 reject → 调用方 forward
    // fallback，不做 REALITY 验证。
    if !parsed.key_share_mlkem768 {
        return Err(RealityError::NoKeyShareX25519);
    }

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
    /// REALITY 验证通过，返回 TLS 连接（rustls 或 btls，见
    /// [`RealityTlsStream`]；可传给 VLESS 入站）。
    ///
    /// `max_useless_records`（bd frxi）：本连接的"连续未推进 record"上限——
    /// 启动期探测值（[`crate::probe::probe_for_key`]），miss 时按配置 fallback
    /// （缺省 Go 默认 32，`reality/common.go:70`）。Go 侧由定制 BoringSSL 在
    /// record 循环消费（`reality/conn.go:830-836`，超限 alert）；btls 路径
    /// 另消费为后握手记录模仿触发条件（bd 26zn，见 [`server_tls_btls`]）。
    Verified {
        tls: RealityTlsStream<C>,
        max_useless_records: u32,
    },
    /// REALITY 验证失败。调用方可拿回 `conn` + `record` 做 [`fallback_to_dest`]。
    Invalid {
        conn: C,
        record: Vec<u8>,
        reason: RealityError,
    },
}

/// bd frxi：server_tls 的启动期探测消费上下文。
///
/// listener 启动时若配置启用探测（[`crate::config::MaxUselessRecordsSetting::Probe`]），
/// 创建 [`crate::probe::ProbeTable`] 并 spawn [`crate::probe::detect_max_useless_records`]，
/// 再把表 + dest + fallback 打包为本结构传给 [`server_tls`]；未启用传 `None`
/// （行为与改动前一致：不查表，喂 Go 默认 32）。
#[derive(Clone)]
pub struct ProbeContext {
    pub table: crate::probe::ProbeTable,
    /// 探测 dest（即 fallback_dest，Go `config.Dest`）。
    pub dest: String,
    /// 查表 miss 时的 fallback 值（Disabled→32 / Probe(n)→n）。
    pub fallback: crate::config::MaxUselessRecordsSetting,
}

impl ProbeContext {
    /// Go `tls.go:411-417` key 推导的 Rust 等价：dest + " " + sni + " " + alpn_id。
    /// alpn_id：无 ALPN → None；首个协议为 "h2" → H2；否则 → Http11。
    fn key_for(&self, server_name: &str, alpn_protocols: &[String]) -> crate::probe::ProbeKey {
        let alpn = match alpn_protocols.first().map(String::as_str) {
            None => crate::probe::AlpnId::None,
            Some("h2") => crate::probe::AlpnId::H2,
            Some(_) => crate::probe::AlpnId::Http11,
        };
        crate::probe::ProbeKey {
            dest: self.dest.clone(),
            server_name: server_name.to_string(),
            alpn,
        }
    }
}

/// 前置验证结果（rustls/btls 两路共享，bd tce2）。
struct VerifiedHandshake {
    /// REALITY auth_key（派生 HMAC 证书用）。
    auth_key: [u8; 32],
    /// 本连接的 maxUselessRecords 消费值（探测命中值或配置 fallback）。
    max_useless_records: u32,
    /// dest 主动发的后握手 type23 记录长度列表（bd 26zn：Go `tls.go:414-416`
    /// `GlobalPostHandshakeRecordsLens.Load(key)` 等价；空 = dest 未主动发
    /// type23 / 未启用探测 / 查表 miss）。gate 判定保留为未来接线点；发送体
    /// 已删（方案 B，见 [`server_tls_btls`] 处置记录），gate 命中现仅记日志。
    mirror_record_lens: Vec<u32>,
}

/// REALITY 前置验证（rustls/btls 两路共享语义，bd tce2）：
/// parse → SNI 前置门 → session_id verify → probe 查表。
///
/// Err = REALITY 验证失败（调用方转 [`RealityServerOutcome::Invalid`] 走
/// fallback）；不返回 Err 的约定由各 server_tls* 函数保持。
fn verify_and_probe(
    record: &[u8],
    server_private_key: &[u8; 32],
    allowed_short_ids: &[[u8; 8]],
    max_diff: u32,
    min_client_ver: &[u8],
    max_client_ver: &[u8],
    server_names: &[String],
    probe: Option<&ProbeContext>,
) -> Result<VerifiedHandshake, RealityError> {
    let parsed = parse_client_hello(record)?;
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

    // bd frxi：Go tls.go:435-437 Load(GlobalMaxCSSMsgCount) 等价——查表喂值，
    // miss 用配置 fallback（缺省 32）。Go 在握手完成前 sleep(5s) 轮询等探测
    // 结果；Rust 不阻塞握手（探测为启动期后台任务，miss 只损失该连接的
    // 精确值），偏差登记在案。
    let (max_useless_records, mirror_record_lens) = match probe {
        Some(ctx) => {
            let sni = parsed.server_name.as_deref().unwrap_or("");
            let key = ctx.key_for(sni, &parsed.alpn_protocols);
            let tier = crate::probe::probe_for_key(&ctx.table, &key);
            // bd 26zn：Go tls.go:414-416 Load(GlobalPostHandshakeRecordsLens)
            // 等价——miss（探测中/未启用）与空列表同判"不发"。
            let lens = ctx.table.record_lens_for_key(&key).unwrap_or_default();
            (tier.unwrap_or_else(|| ctx.fallback.fallback()), lens)
        }
        None => (
            crate::config::MaxUselessRecordsSetting::Disabled.fallback(),
            Vec::new(),
        ),
    };
    Ok(VerifiedHandshake {
        auth_key,
        max_useless_records,
        mirror_record_lens,
    })
}

/// REALITY 服务端握手（rustls 默认路径）。
///
/// 流程：
/// 1. [`read_tls_record`] 读 ClientHello record
/// 2. [`verify_and_probe`] 验证（parse/SNI 门/verify/查表）
/// 3. 成功：[`generate_reality_ed25519_cert`] + [`build_server_config`] + rustls TLS 握手
/// 4. 失败：返回 [`RealityServerOutcome::Invalid`]，调用方决定 fallback
///
/// btls（BoringSSL）opt-in 路径见 [`server_tls_btls`]；两路前置语义共享
/// （[`verify_and_probe`]），dest fallback / probe 喂值行为一致。
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
/// - `probe`：bd frxi 启动期探测消费上下文；`None` = 未启用探测（不查表，
///   `Verified.max_useless_records` 恒为配置 fallback / Go 默认 32）。
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
    probe: Option<&ProbeContext>,
) -> std::result::Result<RealityServerOutcome<C>, RealityError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let record = read_tls_record(&mut conn).await.map_err(|e| {
        RealityError::TlsHandshake(format!("read ClientHello: {e}"))
    })?;
    // bd frxi：探测 key 需 sni + alpn，verify 失败路径（Invalid）不查表——
    // Go 侧消费点在 REALITY 握手成功分支内（tls.go:410-437），fallback 连接
    // 走原样转发，无消费。
    let verified = match verify_and_probe(
        &record,
        server_private_key,
        allowed_short_ids,
        max_diff,
        min_client_ver,
        max_client_ver,
        server_names,
        probe,
    ) {
        Ok(v) => v,
        Err(reason) => {
            return Ok(RealityServerOutcome::Invalid { conn, record, reason });
        }
    };

    // 3. 成功分支：生成 REALITY HMAC 证书 + TLS 握手
    // （证书为进程级固定空模板，Go init() 语义，与 SNI 无关）
    let (cert_der, key_der) = generate_reality_ed25519_cert(&verified.auth_key)?;
    let server_config = build_server_config(cert_der, key_der)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let prefixed = PrefixedReader::new(record, conn);
    match acceptor.accept(prefixed).await {
        Ok(tls) => Ok(RealityServerOutcome::Verified {
            tls: RealityTlsStream::Rustls(tls),
            max_useless_records: verified.max_useless_records,
        }),
        Err(e) => Err(RealityError::TlsHandshake(e.to_string())),
    }
}

/// dest 后握手记录长度列表探测可用性（Go `GlobalPostHandshakeRecordsLens`
/// 等价物，表在 [`crate::probe::ProbeTable`]，探测入口
/// [`crate::probe::detect_post_handshake_record_lens`]）。
///
/// Go 只在探测到 **dest 主动发的 type 23 记录长度列表非空**时才发 mirror
/// （`record_detect.go:124-139`：列表 = 真实 TLS 连 dest 后 `io.ReadAll`
/// 收到的记录；列表为空则服务端不发，客户端无丢弃逻辑也不受影响）。Rust
/// probe（frxi）早期只有 CCS tier——tier<MaxInt 只证明 dest 对 CCS 有
/// alert 行为，**不是** dest 握手后主动发记录的证据。VPS 生产实测
/// （2026-09-20）：按 tier<MaxInt 即发的保守做法 mirror 会泄漏进客户端
/// VLESS 数据流（REALITY 客户端 TLS 栈把 mirror 当 app data 交付上层，
/// curl 3/3 失败）。现 gate = 记录长度列表非空（`tls.go:414-416` 语义），
/// tier 与 mirror gate 解耦（tier 只喂 `maxUselessRecords` 上限消费）。
/// Rust 侧 gate 命中亦**不发**（bd 26zn 方案 B，见下方处置记录）。

/// REALITY 服务端握手（btls/BoringSSL opt-in 路径，bd tce2）。
///
/// 前置与 [`server_tls`] 完全共享（[`verify_and_probe`]：ClientHello 预读
/// 判定 / SNI 门 / session_id verify / probe 查表），dest fallback 语义一致
/// （Invalid → 调用方 [`fallback_to_dest`]）；差异仅在握手执行者：
/// BoringSSL server SSL（[`xray_tls::btls_server::accept`]）。
///
/// # bd 26zn：后握手记录模仿（方案 B 处置记录）
///
/// Go reality tls.go:414-424 在探测确认 dest 主动发 type23 记录后，把 dest
/// 的后握手记录逐条重放给 REALITY 客户端（使 REALITY 连接与 dest 直连的
/// 记录序列不可区分）。
///
/// **Rust 侧发送体已删（bd 26zn 方案 B）**：gate 命中（`mirror_record_lens`
/// 非空，判定结构保留，见 [`verify_and_probe`]）现在只记 debug 日志，不发
/// 任何记录。原因：标准 `SSL_write` 语义是「明文 + 自动追加 inner
/// content-type + AEAD tag」，无法构造「剥掉尾部 tag 的空记录」实现字节级
/// 等价；逐条重放真实 dest 记录需要新的 btls 原语（bd z32z）。此前保守
/// 实现发 48B 零 padding（wire 70B 单记录），被 REALITY 客户端 TLS 栈当
/// app data 交付上层泄漏进 VLESS 数据流（VPS 生产实测 curl 3/3 失败）——
/// 等价原语落地前，静默污染比不发更糟。gate 判定保留为未来接线点 +
/// 可观测性（本函数内 `tracing::debug!`）。
///
/// # Errors
///
/// - [`read_tls_record`] IO 错误 → [`RealityError::TlsHandshake`]
/// - 证书生成失败 → [`RealityError::CertGenerate`]
/// - btls 握手失败 → [`RealityError::TlsHandshake`]
///
/// 验证失败不返回 Err，返回 [`RealityServerOutcome::Invalid`]（同 [`server_tls`]）。
#[cfg(not(target_os = "ios"))]
pub async fn server_tls_btls<C>(
    mut conn: C,
    server_private_key: &[u8; 32],
    allowed_short_ids: &[[u8; 8]],
    max_diff: u32,
    min_client_ver: &[u8],
    max_client_ver: &[u8],
    server_names: &[String],
    probe: Option<&ProbeContext>,
) -> std::result::Result<RealityServerOutcome<C>, RealityError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let record = read_tls_record(&mut conn).await.map_err(|e| {
        RealityError::TlsHandshake(format!("read ClientHello: {e}"))
    })?;
    let verified = match verify_and_probe(
        &record,
        server_private_key,
        allowed_short_ids,
        max_diff,
        min_client_ver,
        max_client_ver,
        server_names,
        probe,
    ) {
        Ok(v) => v,
        Err(reason) => {
            return Ok(RealityServerOutcome::Invalid { conn, record, reason });
        }
    };

    let (cert_der, key_der) = generate_reality_ed25519_cert(&verified.auth_key)?;
    let prefixed = PrefixedReader::new(record, conn);
    let tls = xray_tls::btls_server::accept(prefixed, &cert_der, &key_der)
        .await
        .map_err(|e| RealityError::TlsHandshake(format!("btls accept: {e}")))?;

    // bd 26zn（方案 B）：发送 gate 判定保留（未来接线点 + 可观测性），
    // 发送体已删——见函数文档处置记录。
    if !verified.mirror_record_lens.is_empty() {
        tracing::debug!(
            lens = verified.mirror_record_lens.len(),
            "reality btls: post-handshake mirror suppressed (send path removed, bd 26zn; \
             byte-level equivalence pending new btls primitive, bd z32z)"
        );
    }

    Ok(RealityServerOutcome::Verified {
        tls: RealityTlsStream::Btls(tls),
        max_useless_records: verified.max_useless_records,
    })
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
        // X25519MLKEM768 hybrid key share entry（group 0x11EC = 十进制 4588）
        let mut ks_ext = Vec::new();
        ks_ext.extend_from_slice(&((2 + 2 + 1216) as u16).to_be_bytes());
        ks_ext.extend_from_slice(&[0x11, 0xEC]); // X25519MLKEM768 = 0x11EC
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
    ///
    /// sb6g：key_share 用 X25519MLKEM768 hybrid entry（真实 Chrome/btls 形态，
    /// Go tls.go:233-235 要求 MLKEM768 存在才进 REALITY 验证）——纯 X25519
    /// 单 share 的 ClientHello 会被服务端 reject→forward。
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
        let mlkem_ek_placeholder = [0xAAu8; 1184];

        // 1. 构造 session_id=0 的 hybrid ClientHello（拿 AAD = handshake_message）
        let zero_sid = [0u8; 32];
        let record_zero = build_test_client_hello_hybrid_key_share(
            random,
            &zero_sid,
            &mlkem_ek_placeholder,
            client_pub.as_bytes(),
            sni,
        );
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

        // sb6g 后 build_reality_client_hello 产 hybrid（0x11EC）key_share CH
        let record = build_reality_client_hello(
            &random,
            &server_priv,
            &client_priv,
            now,
            &short_id,
            Some("example.com"),
        );
        let parsed = parse_client_hello(&record).unwrap();
        // 关键断言：hybrid entry 解析出末尾 X25519 公钥 + MLKEM768 检测命中
        assert!(parsed.key_share_x25519.is_some());
        assert!(parsed.key_share_mlkem768, "hybrid entry must set key_share_mlkem768");
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

    // ===== sb6g：服务端 MLKEM768 key share 门禁（Go tls.go:233-235 reject→forward）=====

    /// 构造任意 key_share entries 的 ClientHello record（sb6g 测试专用）。
    /// entries 按 wire 顺序编码进单一 key_share extension。
    fn build_test_client_hello_with_key_share_entries(
        random: &[u8; 32],
        session_id: &[u8; 32],
        entries: &[(u16, Vec<u8>)],
        sni: Option<&str>,
    ) -> Vec<u8> {
        let mut ks_list = Vec::new();
        for (group, key) in entries {
            ks_list.extend_from_slice(&group.to_be_bytes());
            ks_list.extend_from_slice(&(key.len() as u16).to_be_bytes());
            ks_list.extend_from_slice(key);
        }
        let mut ks_ext = Vec::with_capacity(2 + ks_list.len());
        ks_ext.extend_from_slice(&(ks_list.len() as u16).to_be_bytes());
        ks_ext.extend_from_slice(&ks_list);

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
        exts.extend_from_slice(&[0x00, 0x33]);
        exts.extend_from_slice(&(ks_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ks_ext);

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x01];
        let blen = body.len();
        hs.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
        hs.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        let hl = hs.len();
        record.extend_from_slice(&[(hl >> 8) as u8, hl as u8]);
        record.extend_from_slice(&hs);
        record
    }

    /// 票面核心：纯 X25519 单 share（无 MLKEM768）→ Go `peerPub2 == nil` reject，
    /// verify 返回 NoKeyShareX25519 → server_tls 转 Invalid 走 forward fallback。
    #[test]
    fn verify_reality_client_hello_pure_x25519_only_rejected() {
        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32];
        let record = build_test_client_hello_with_key_share_entries(
            &random,
            &session_id,
            &[(0x001d, vec![0x88u8; 32])],
            Some("example.com"),
        );
        let parsed = parse_client_hello(&record).unwrap();
        assert!(parsed.key_share_x25519.is_some());
        assert!(!parsed.key_share_mlkem768);
        let err = verify_reality_client_hello(&parsed, &[0u8; 32], 0, 0, &[], &[], &[]).unwrap_err();
        assert!(matches!(err, RealityError::NoKeyShareX25519));
    }

    /// Chrome 双 share 形态 [X25519MLKEM768, X25519]（MLKEM 在前）：独立
    /// X25519 entry 优先（Go peerPub），MLKEM 检测命中。
    #[test]
    fn parse_client_hello_dual_share_mlkem_then_x25519() {
        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32];
        let x_pub = [0xBBu8; 32];
        let mut hybrid = vec![0xAAu8; 1216];
        hybrid[1184..].copy_from_slice(&x_pub);
        let record = build_test_client_hello_with_key_share_entries(
            &random,
            &session_id,
            &[(0x11ec, hybrid), (0x001d, vec![0xCCu8; 32])],
            None,
        );
        let parsed = parse_client_hello(&record).unwrap();
        // 独立 X25519 entry 优先（Go `peerPub = keyShare.data; break`）
        assert_eq!(parsed.key_share_x25519, Some([0xCCu8; 32]));
        assert!(parsed.key_share_mlkem768);
    }

    /// MLKEM-only 单 entry（无独立 X25519）：取 hybrid 末段
    /// （Go `if peerPub == nil { peerPub = peerPub2 }` 次选）。
    #[test]
    fn parse_client_hello_hybrid_only_uses_mlkem_tail() {
        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32];
        let x_pub = [0xBBu8; 32];
        let mut hybrid = vec![0xAAu8; 1216];
        hybrid[1184..].copy_from_slice(&x_pub);
        let record = build_test_client_hello_with_key_share_entries(
            &random,
            &session_id,
            &[(0x11ec, hybrid)],
            None,
        );
        let parsed = parse_client_hello(&record).unwrap();
        assert_eq!(parsed.key_share_x25519, Some(x_pub));
        assert!(parsed.key_share_mlkem768);
    }

    /// 顺序颠倒 [X25519, X25519MLKEM768]：Go 首遇 X25519 即 break，其后
    /// MLKEM 不消费 → `peerPub2 == nil` reject。
    #[test]
    fn parse_client_hello_x25519_before_mlkem_rejected() {
        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32];
        let record = build_test_client_hello_with_key_share_entries(
            &random,
            &session_id,
            &[(0x001d, vec![0xCCu8; 32]), (0x11ec, vec![0xAAu8; 1216])],
            None,
        );
        let parsed = parse_client_hello(&record).unwrap();
        assert_eq!(parsed.key_share_x25519, Some([0xCCu8; 32]));
        assert!(!parsed.key_share_mlkem768);
        let err = verify_reality_client_hello(&parsed, &[0u8; 32], 0, 0, &[], &[], &[]).unwrap_err();
        assert!(matches!(err, RealityError::NoKeyShareX25519));
    }

    /// 重复 MLKEM entry：Go `peerPub2 = nil // ensure once` → reject。
    #[test]
    fn parse_client_hello_duplicate_mlkem_rejected() {
        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32];
        let record = build_test_client_hello_with_key_share_entries(
            &random,
            &session_id,
            &[(0x11ec, vec![0xAAu8; 1216]), (0x11ec, vec![0xABu8; 1216])],
            None,
        );
        let parsed = parse_client_hello(&record).unwrap();
        assert!(parsed.key_share_x25519.is_none());
        assert!(!parsed.key_share_mlkem768);
    }

    /// server_tls e2e：纯 X25519 单 share CH → `Invalid`（调用方拿回
    /// conn+record 走 `fallback_to_dest`），reason = NoKeyShareX25519。
    #[tokio::test]
    async fn server_tls_pure_x25519_ch_invalid_for_fallback() {
        use tokio::io::{AsyncWriteExt, duplex};

        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32];
        let record = build_test_client_hello_with_key_share_entries(
            &random,
            &session_id,
            &[(0x001d, vec![0x88u8; 32])],
            Some("example.com"),
        );

        let (client, server) = duplex(65536);
        let server_task = tokio::spawn(async move {
            server_tls(server, &[0x11u8; 32], &[[0xaa; 8]], 43200, &[], &[], &[], None).await
        });

        let mut client = client;
        client.write_all(&record).await.unwrap();
        drop(client); // 半关闭：让 server 侧读完 record 后完成 verify

        match server_task.await.unwrap() {
            Ok(RealityServerOutcome::Invalid { reason, .. }) => {
                assert!(
                    matches!(reason, RealityError::NoKeyShareX25519),
                    "expected NoKeyShareX25519, got {reason:?}"
                );
            }
            Ok(RealityServerOutcome::Verified { .. }) => {
                panic!("expected Invalid outcome, got Verified")
            }
            Err(e) => panic!("expected Invalid outcome, got server error: {e:?}"),
        }
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

        // 构造合法 hybrid CH 但 session_id 不含 REALITY 加密载荷（verify 失败）。
        // sb6g 后 key_share 需带 MLKEM768 才过门禁，故用 hybrid entry——
        // 失败点落在 session_id 解密（而非 key share 门禁）。
        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32]; // 非加密载荷
        let record = build_test_client_hello_with_key_share_entries(
            &random,
            &session_id,
            &[(0x11ec, vec![0xAAu8; 1216])],
            Some("example.com"),
        );

        let (mut client, server) = duplex(4096);
        let server_priv = [0x11u8; 32];
        let short_id = [0xaa; 8];

        let server_task = tokio::spawn(async move {
            server_tls(server, &server_priv, &[short_id], 43200, &[], &[], &[], None).await
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
            RealityServerOutcome::Verified { .. } => panic!("expected Invalid, got Verified"),
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
            server_tls(server, &server_priv, &[[0xaa; 8]], 43200, &[], &[], &whitelist, None).await
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
            RealityServerOutcome::Verified { .. } => panic!("expected Invalid, got Verified"),
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
            server_tls(server, &server_priv, &[[0xaa; 8]], 43200, &[], &[], &whitelist, None).await
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
        let result = server_tls(server, &server_priv, &[], 43200, &[], &[], &[], None).await;

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
            server_tls(server, &server_priv, &[short_id], 43200, &[], &[], &[], None).await
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
            Ok(RealityServerOutcome::Verified { .. }) => { /* 不可能：client 未完成 TLS */ }
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
            server_tls(server, &server_priv_array, &[short_id], 43200, &[], &[], &[], None).await
        });

        // client 端：reality u_client 握手
        let client_result = tokio::time::timeout(
            Duration::from_secs(10),
            u_client(client, state),
        )
        .await;

        let server_result = server_task.await.unwrap();

        match (client_result, server_result) {
            (Ok(Ok(_tls_stream)), Ok(RealityServerOutcome::Verified { .. })) => {
                // 完整 REALITY 握手成功！
            }
            (Ok(Ok(_)), Ok(_)) => panic!("server unexpected outcome"),
            (Ok(Ok(_)), Err(e)) => panic!("server error: {e:?}"),
            (Ok(Err(e)), _) => panic!("client u_client failed: {e:?}"),
            (Err(_timeout), _) => panic!("client u_client timeout"),
        }
    }

    /// `randomizednoalpn` 指纹 loopback。
    ///
    /// 566y 注释修正：randomizednoalpn **并非** watfaq-rustls fallback——
    /// btls_client.rs 已将其就近映射为 Chrome 133 no-ALPN connector
    /// （key_shares = CHROME_133_KEY_SHARES 双 share，含 MLKEM768），本测试
    /// 实际锁 btls no-ALPN 变体全链。真正走 watfaq fallback 的唯一预设是
    /// `unsafe`（btls 清单外）；fallback CH 为纯 X25519 单 share，在 sb6g 的
    /// Go MLKEM 门禁下会被服务端 reject→forward（Go 一致），其行为由
    /// [`server_tls_pure_x25519_ch_invalid_for_fallback`] 锁定。
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
            server_tls(server, &server_priv_array, &[short_id], 43200, &[], &[], &[], None).await
        });

        let client_result =
            tokio::time::timeout(Duration::from_secs(10), u_client(client, state)).await;
        let server_result = server_task.await.unwrap();

        match (client_result, server_result) {
            (Ok(Ok(_tls_stream)), Ok(RealityServerOutcome::Verified { .. })) => {
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
            server_tls(server, &server_priv_array, &[short_id], 43200, &[], &[], &[], None).await
        });

        let client_result =
            tokio::time::timeout(Duration::from_secs(10), u_client(client, state)).await;
        let server_result = server_task.await.unwrap();

        match (client_result, server_result) {
            (Ok(Ok(_tls_stream)), Ok(RealityServerOutcome::Verified { .. })) => {}
            (Ok(Ok(_)), Ok(_)) => panic!("[{fp}] server unexpected outcome"),
            (Ok(Ok(_)), Err(e)) => panic!("[{fp}] server error: {e:?}"),
            (Ok(Err(e)), _) => panic!("[{fp}] client u_client failed: {e:?}"),
            (Err(_timeout), _) => panic!("[{fp}] client u_client timeout"),
        }
    }

    /// 566y：btls 主路径 **MLKEM-capable 指纹 active 矩阵**（实测 2026-09-19）。
    ///
    /// 从原 21 指纹大矩阵中摘出**当前 btls 栈上真实可完成 REALITY 全链**的
    /// 子集：仅 Chrome 133/131 系模板（`CHROME_133_KEY_SHARES` /
    /// `CHROME_131_KEY_SHARES` = `[X25519MLKEM768, X25519]` 双 share）满足
    /// sb6g 的 Go MLKEM768 门禁（xtls/reality tls.go:233-235）。android 就近
    /// 映射 Chrome 133（btls_client.rs），同样双 share。
    ///
    /// 非失败语义：其余 17 指纹模板（firefox/ios/safari/edge/360/qq/120/100/99
    /// 系）key share 无 MLKEM768，被服务端 reject→forward——与 Go 上游对
    /// outdated ClientHello 的行为**一致**（Go REALITY 10.0 同样只接受
    /// MLKEM-capable 客户端），非本仓缺口；行为由
    /// [`server_tls_pure_x25519_ch_invalid_for_fallback`] 单测锁定。
    /// 单指纹 timeout/EOF 细节见下方 ignored 大矩阵注释。
    #[tokio::test]
    async fn reality_fingerprint_matrix_btls_mlkem() {
        ensure_crypto_provider();
        for fp in ["chrome", "android", "hellochrome_131", "hellochrome_133"] {
            reality_loopback_with_fingerprint(fp).await;
        }
    }

    /// btls 浏览器指纹主路径矩阵：preset 8 + modern 11 + 旧版 2 = 21 例。
    ///
    /// **566y 实测分类（2026-09-19，对 21 指纹逐个 loopback 探针）**：
    /// - PASS（4）：chrome / android / hellochrome_131 / hellochrome_133
    ///   —— 已摘为上方 active 矩阵 [`reality_fingerprint_matrix_btls_mlkem`]；
    /// - FAIL（17）：非 MLKEM 模板。服务端按 Go 语义 reject→forward（正确行为），
    ///   客户端等不到 ServerHello → 10s timeout（edge/360/qq/safari/100/99 系）
    ///   或 EOF（firefox 系——rustls 服务端对 firefox CH 另有兼容性问题，EOF
    ///   先于门禁发生，属既有独立问题）。
    ///
    /// **ignore 根因更新**：旧注释声称的"btls transcript mismatch → DECODE_ERROR"
    /// 已不复现（chrome 全链实测通过）；当前保留 ignore 是因为矩阵混合
    /// PASS/FAIL 形态，单测无法断言统一结果。治本方向（二选一）：
    /// ① btls 指纹模板为 firefox/edge 等现代变体补 X25519MLKEM768 key share
    /// entry（对齐真实浏览器 131+ 形态，随后可摘入 active 矩阵）；
    /// ② btls fork 提供 pre-hash 注入 API 修 transcript（已非 chrome 路径阻塞）。
    /// 修复后按门禁语义逐指纹归类，不做单一全矩阵断言。
    #[tokio::test]
    #[ignore = "mixed PASS(4 MLKEM-capable, extracted as active matrix)/FAIL(17 non-MLKEM templates, Go-consistent reject); see doc above"]
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

    /// `randomizednoalpn` / `hellorandomizednoalpn` 矩阵。
    ///
    /// 566y 注释修正：两者均被 btls_client.rs 就近映射为 Chrome 133 no-ALPN
    /// connector（key_shares = CHROME_133_KEY_SHARES，含 MLKEM768 双 share），
    /// 走 **btls 路径**而非 watfaq-rustls fallback（旧注释已过时）；本测试锁
    /// 该 no-ALPN 映射的全链可用性。真正走 fallback 的唯一预设是 `unsafe`
    /// （btls 清单外），其 CH 纯 X25519 单 share 在 Go MLKEM 门禁下被
    /// reject→forward，行为由 [`server_tls_pure_x25519_ch_invalid_for_fallback`]
    /// 锁定。
    #[tokio::test]
    async fn reality_fingerprint_matrix_watfaq_fallback() {
        ensure_crypto_provider();
        for fp in ["randomizednoalpn", "hellorandomizednoalpn"] {
            reality_loopback_with_fingerprint(fp).await;
        }
    }

    /// 全 21 指纹名查表（无 btls 握手）——验证 xray-tls::fingerprint::get_fingerprint
    /// 能识别 21 个目标指纹名（preset 8 + modern 11 + 旧版 2 = 21）。
    /// 真实握手测试见 `reality_fingerprint_matrix_btls_mlkem`（active，
    /// MLKEM-capable 子集）与 `reality_fingerprint_matrix_btls`（#[ignore]，
    /// 全矩阵实测分类见其注释）。
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

    // ===== bd frxi：alpn 解析 + ProbeTable 喂值联动 =====

    /// 向已构造的 ClientHello record extensions 尾部追加 alpn extension
    /// 并修正三层长度字段（record/handshake/ext_total）。
    fn append_alpn_ext(mut record: Vec<u8>, protos: &[&str]) -> Vec<u8> {
        let mut names = Vec::new();
        for p in protos {
            names.push(p.len() as u8);
            names.extend_from_slice(p.as_bytes());
        }
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x10]); // extension_type: alpn
        ext.extend_from_slice(&((2 + names.len()) as u16).to_be_bytes());
        ext.extend_from_slice(&(names.len() as u16).to_be_bytes());
        ext.extend_from_slice(&names);

        let hs_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        let body_end = 5 + hs_len; // record payload = 4B hs header + body
        let body = record[9..body_end].to_vec();
        // 按结构偏移找 ext_total 字段（对齐 parse_handshake）：
        // legacy_version(2) + random(32) + session_id(1+32) + cipher_suites(2+n)
        // + compression(1+n) → ext_total(2) + exts...
        let mut off = 2 + 32 + 1 + 32;
        let cs_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
        off += 2 + cs_len;
        let cm_len = body[off] as usize;
        off += 1 + cm_len;
        let old_total = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
        assert_eq!(
            off + 2 + old_total,
            body.len(),
            "fixture ext_total must be self-consistent"
        );

        let mut new_body = body[..off].to_vec();
        new_body.extend_from_slice(&((old_total + ext.len()) as u16).to_be_bytes());
        new_body.extend_from_slice(&body[off + 2..]);
        new_body.extend_from_slice(&ext);

        // fixture 惯例：handshake length 字段只含 body（不含 4B header）
        let new_hs_len = new_body.len();
        record.truncate(5);
        // record 层长度（2B）= handshake 整长（4B header + body）
        record[3..5].copy_from_slice(&((4 + new_hs_len) as u16).to_be_bytes());
        // 重建 handshake header（type 1B + length 3B）
        record.push(0x01);
        record.push((new_hs_len >> 16) as u8);
        record.push((new_hs_len >> 8) as u8);
        record.push(new_hs_len as u8);
        record.extend_from_slice(&new_body);
        record
    }

    #[test]
    fn parse_client_hello_alpn_protocols() {
        let base = build_test_client_hello(&[0x55; 32], &[0x77; 32], &[0x88; 32], Some("example.com"));
        // 无 alpn extension → 空
        assert!(parse_client_hello(&base).unwrap().alpn_protocols.is_empty());
        // 带 alpn → 按序解析
        let record = append_alpn_ext(base, &["h2", "http/1.1"]);
        let parsed = parse_client_hello(&record).unwrap();
        assert_eq!(parsed.alpn_protocols, vec!["h2", "http/1.1"]);
        // 其余字段不受追加影响
        assert_eq!(parsed.server_name.as_deref(), Some("example.com"));
        assert_eq!(parsed.session_id, [0x77; 32]);
    }

    /// Go `tls.go:411-417` key 推导等价：无 ALPN→0 / 首个 h2→2 / 其他→1。
    #[test]
    fn probe_context_key_for_matches_go_derivation() {
        use crate::probe::AlpnId;
        let ctx = ProbeContext {
            table: crate::probe::ProbeTable::new(),
            dest: "dest:443".into(),
            fallback: crate::config::MaxUselessRecordsSetting::Disabled,
        };
        assert_eq!(ctx.key_for("s", &[]).alpn, AlpnId::None);
        assert_eq!(
            ctx.key_for("s", &["h2".into(), "http/1.1".into()]).alpn,
            AlpnId::H2
        );
        assert_eq!(ctx.key_for("s", &["http/1.1".into()]).alpn, AlpnId::Http11);
    }

    /// ProbeTable 喂值联动（Go tls.go:435-437 等价）：真 u_client loopback 握手，
    /// ProbeTable 插入 (dest, sni, alpn) key → Verified.max_useless_records 携带
    /// 插值；miss 的 key → 配置 fallback；probe=None → Go 默认 32。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_tls_feeds_probe_result_into_verified() {
        ensure_crypto_provider();
        use std::time::Duration;
        use tokio::io::duplex;
        use x25519_dalek::{PublicKey, StaticSecret};
        use crate::client::{u_client, UConnState};
        use crate::config::RealityConfig;
        use crate::probe::{AlpnId, ProbeKey};
        use xray_proto::transport::internet::reality::Config as ProtoConfig;

        let server_priv_array = [0x11u8; 32];
        let short_id = [0xaa; 8];
        let server_secret = StaticSecret::from(server_priv_array);
        let server_pub = PublicKey::from(&server_secret);

        let proto = ProtoConfig {
            fingerprint: "chrome".into(),
            public_key: server_pub.as_bytes().to_vec(),
            server_name: "example.com".into(),
            short_id: short_id.to_vec(),
            ..Default::default()
        };
        let state = UConnState::new(RealityConfig::from_proto(&proto).unwrap()).unwrap();

        // 插 H2=16 / None=8 两档 key（u_client chrome 指纹的 CH 实际 alpn 由
        // btls 模板决定，双插消除对模板细节的依赖，miss 则暴露模板回归）。
        let table = crate::probe::ProbeTable::new();
        for (alpn, v) in [(AlpnId::H2, 16u32), (AlpnId::None, 8u32)] {
            table.insert(
                ProbeKey {
                    dest: "dest.example:443".into(),
                    server_name: "example.com".into(),
                    alpn,
                },
                v,
            );
        }
        let ctx = ProbeContext {
            table,
            dest: "dest.example:443".into(),
            fallback: crate::config::MaxUselessRecordsSetting::Probe(20),
        };

        let (client, server) = duplex(65536);
        let client = xray_transport::connection::DuplexConnection::new(client);
        let server_task = tokio::spawn(async move {
            server_tls(
                server,
                &server_priv_array,
                &[short_id],
                43200,
                &[],
                &[],
                &[],
                Some(&ctx),
            )
            .await
        });
        let client_result =
            tokio::time::timeout(Duration::from_secs(10), u_client(client, state)).await;
        let server_result = server_task.await.unwrap();

        match (client_result, server_result) {
            (
                Ok(Ok(_)),
                Ok(RealityServerOutcome::Verified {
                    max_useless_records, ..
                }),
            ) => {
                assert!(
                    max_useless_records == 16 || max_useless_records == 8,
                    "probe value must come from the table (got {max_useless_records})"
                );
            }
            (Ok(Ok(_)), other) => panic!("server unexpected outcome (see outcome variant)"),
            (Ok(Err(e)), _) => panic!("client u_client failed: {e:?}"),
            (Err(_timeout), _) => panic!("client u_client timeout"),
        }
    }

    /// probe=None（未启用探测）时 Verified.max_useless_records 恒为 Go 默认 32。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_tls_without_probe_defaults_to_go_max_useless_records() {
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
            fingerprint: "chrome".into(),
            public_key: server_pub.as_bytes().to_vec(),
            server_name: "example.com".into(),
            short_id: short_id.to_vec(),
            ..Default::default()
        };
        let state = UConnState::new(RealityConfig::from_proto(&proto).unwrap()).unwrap();

        let (client, server) = duplex(65536);
        let client = xray_transport::connection::DuplexConnection::new(client);
        let server_task = tokio::spawn(async move {
            server_tls(server, &server_priv_array, &[short_id], 43200, &[], &[], &[], None).await
        });
        let client_result =
            tokio::time::timeout(Duration::from_secs(10), u_client(client, state)).await;
        let server_result = server_task.await.unwrap();

        match (client_result, server_result) {
            (
                Ok(Ok(_)),
                Ok(RealityServerOutcome::Verified {
                    max_useless_records, ..
                }),
            ) => assert_eq!(max_useless_records, 32),
            (Ok(Ok(_)), other) => panic!("server unexpected outcome (see outcome variant)"),
            (Ok(Err(e)), _) => panic!("client u_client failed: {e:?}"),
            (Err(_timeout), _) => panic!("client u_client timeout"),
        }
    }

    // ===== bd tce2：btls server acceptor =====

    /// wire tap：包装服务端连接，记录全部写出字节（bd 26zn 反向断言用：
    /// gate 命中也不得有 mirror 记录上 wire）。
    struct WireTap<S> {
        inner: S,
        written: std::sync::Arc<parking_lot::Mutex<Vec<u8>>>,
    }

    impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for WireTap<S> {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for WireTap<S> {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            match std::pin::Pin::new(&mut this.inner).poll_write(cx, buf) {
                std::task::Poll::Ready(Ok(n)) => {
                    this.written.lock().extend_from_slice(&buf[..n]);
                    std::task::Poll::Ready(Ok(n))
                }
                other => other,
            }
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// btls 路径 loopback 共享装配：REALITY 客户端（u_client chrome btls 指纹）
    /// ↔ [`server_tls_btls`]。
    ///
    /// `probe_tier`：`Some(tier)` = 三档 alpn key 全插表（命中）并配非空记录
    /// 长度列表（mirror gate 就绪态）；`None` = 不启用探测（gate miss）。
    /// 返回（客户端握手结果, 服务端 outcome, 服务端 wire 写出字节 tap）。
    async fn btls_reality_loopback(
        probe_tier: Option<u32>,
    ) -> (
        Result<
            Result<
                crate::client::RealityTlsStream<xray_transport::connection::DuplexConnection>,
                RealityError,
            >,
            tokio::time::error::Elapsed,
        >,
        Result<RealityServerOutcome<WireTap<tokio::io::DuplexStream>>, RealityError>,
        std::sync::Arc<parking_lot::Mutex<Vec<u8>>>,
    ) {
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
            fingerprint: "chrome".into(),
            public_key: server_pub.as_bytes().to_vec(),
            server_name: "example.com".into(),
            short_id: short_id.to_vec(),
            ..Default::default()
        };
        let reality_config = RealityConfig::from_proto(&proto).unwrap();
        let state = UConnState::new(reality_config).unwrap();

        let (client, server) = duplex(65536);
        let client = xray_transport::connection::DuplexConnection::new(client);
        let wire = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let server = WireTap {
            inner: server,
            written: std::sync::Arc::clone(&wire),
        };

        let probe_ctx = probe_tier.map(|tier| {
            let table = crate::probe::ProbeTable::new();
            // chrome 模板 ALPN 档不硬编码——三档全插保证 key 命中。
            for alpn in [
                crate::probe::AlpnId::None,
                crate::probe::AlpnId::Http11,
                crate::probe::AlpnId::H2,
            ] {
                let key = crate::probe::ProbeKey {
                    dest: "fallback.example:443".to_string(),
                    server_name: "example.com".to_string(),
                    alpn,
                };
                table.insert(key.clone(), tier);
                // mirror gate 输入：非空列表 = 模拟探测确认 dest 主动发 type23
                //（发送体已删 bd 26zn，此输入现仅驱动 gate 命中日志与反向断言）。
                table.insert_record_lens(key, vec![70]);
            }
            ProbeContext {
                table,
                dest: "fallback.example:443".to_string(),
                fallback: crate::config::MaxUselessRecordsSetting::Disabled,
            }
        });

        let server_task = tokio::spawn(async move {
            server_tls_btls(
                server,
                &server_priv_array,
                &[short_id],
                43200,
                &[],
                &[],
                &["example.com".to_string()],
                probe_ctx.as_ref(),
            )
            .await
        });

        let client_result =
            tokio::time::timeout(Duration::from_secs(10), u_client(client, state)).await;
        let server_result = server_task.await.unwrap();
        (client_result, server_result, wire)
    }

    /// btls 路径 REALITY 全链：Verified（Btls 变体）+ 双向数据 roundtrip。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_tls_btls_loopback_verified_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client_result, server_result, _wire) = btls_reality_loopback(None).await;
        // 服务端 outcome 解构（Verified 且 btls 变体）
        let RealityServerOutcome::Verified {
            tls: mut server_tls, ..
        } = server_result.unwrap()
        else {
            panic!("server outcome not Verified");
        };
        assert!(matches!(server_tls, RealityTlsStream::Btls(_)));
        let Ok(Ok(mut client)) = client_result else {
            panic!("client u_client failed or timeout");
        };
        // 双向数据 roundtrip（enum AsyncRead/AsyncWrite 语义）
        client.write_all(b"hello btls").await.unwrap();
        let mut buf = [0u8; 10];
        server_tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello btls");
        server_tls.write_all(&buf).await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello btls");
    }

    /// bd 26zn 方案 B：mirror 发送体已删（标准 SSL_write 无法构造剥尾空记录，
    /// 字节级等价待新 btls 原语，见 bd z32z）。gate 就绪（探测确认 dest 主动
    /// 发 type23，列表非空）也**不发** mirror。双断言：
    /// 1. wire 无 mirror——gate 就绪与 gate miss 两次握手在服务端交付（accept
    ///    返回）时刻的 wire 字节数相等（旧实现 gate 就绪会多一条 70B type23）；
    /// 2. 客户端首读 = 真实响应（旧实现首读 = 48B 零 padding mirror）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_tls_btls_suppresses_post_handshake_mirror() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client_result, server_result, wire_gate_hit) = btls_reality_loopback(Some(16)).await;
        let RealityServerOutcome::Verified {
            tls: mut server_tls, ..
        } = server_result.unwrap()
        else {
            panic!("server outcome not Verified");
        };
        let Ok(Ok(mut client)) = client_result else {
            panic!("client u_client failed or timeout");
        };

        // 断言 1（快照在写任何 app data 之前）：gate 命中交付时 wire 上无
        // mirror 附加字节。
        let gate_hit_wire_len = wire_gate_hit.lock().len();

        // 断言 2：服务端发真实响应，客户端首读必须就是它。
        server_tls.write_all(b"real response").await.unwrap();
        server_tls.flush().await.unwrap();
        let mut buf = [0u8; 13];
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut buf))
            .await
            .expect("real response should arrive within 5s")
            .expect("read real response");
        assert_eq!(
            &buf, b"real response",
            "client first read must be the real response, not mirror padding"
        );

        // gate miss 对照：两次握手 wire 字节数必须一致（mirror 若存在 =
        // gate 命中侧多出 70B 单记录）。
        let (_, _, wire_gate_miss) = btls_reality_loopback(None).await;
        assert_eq!(
            gate_hit_wire_len,
            wire_gate_miss.lock().len(),
            "gate hit wire must carry no mirror bytes vs gate miss"
        );
    }

    /// 未启用探测（probe=None）→ 记录列表表 miss → 不发模仿记录（gate
    /// 输入 = dest 记录长度列表，Go tls.go:414-424；与 CCS tier 无关——
    /// 原「MaxInt tier 不发」断言随 tier-gate 契约废除移除，三态判定见
    /// probe.rs parse/gate 单测）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_tls_btls_no_mirror_without_probe_optin() {
        use tokio::io::AsyncReadExt;

        let (client_result, server_result, _wire) = btls_reality_loopback(None).await;
        match (client_result, server_result) {
            (Ok(Ok(mut client)), Ok(RealityServerOutcome::Verified { .. })) => {
                let mut buf = [0u8; 48];
                let r = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf))
                    .await;
                assert!(r.is_err(), "no mirror record must be sent without probe opt-in");
            }
            (Ok(Ok(_)), _) => panic!("server outcome not Verified"),
            (Ok(Err(e)), _) => panic!("client u_client failed: {e:?}"),
            (Err(_), _) => panic!("client u_client timeout"),
        }
    }

    /// btls 路径非 REALITY ClientHello → Invalid（dest fallback 语义与 rustls
    /// 路径一致，共享 [`verify_and_probe`]）。
    #[tokio::test]
    async fn server_tls_btls_invalid_returns_invalid_outcome() {
        use tokio::io::{AsyncWriteExt, duplex};

        // 合法 hybrid CH 但 session_id 非加密载荷（verify 失败点在解密，
        // 与 rustls 版 server_tls_invalid_returns_invalid_outcome 同构）。
        let random = [0x55u8; 32];
        let session_id = [0x77u8; 32];
        let record = build_test_client_hello_with_key_share_entries(
            &random,
            &session_id,
            &[(0x11ec, vec![0xAAu8; 1216])],
            Some("example.com"),
        );

        let (mut client, server) = duplex(4096);
        let server_priv = [0x11u8; 32];
        let short_id = [0xaa; 8];

        let server_task = tokio::spawn(async move {
            server_tls_btls(server, &server_priv, &[short_id], 43200, &[], &[], &[], None).await
        });
        client.write_all(&record).await.unwrap();

        let outcome = server_task.await.unwrap().unwrap();
        match outcome {
            RealityServerOutcome::Invalid { record: rec, reason, .. } => {
                assert_eq!(rec, record, "Invalid outcome 应保留原 record 供 fallback");
                assert!(matches!(reason, RealityError::SessionIdDecryptFailed));
            }
            RealityServerOutcome::Verified { .. } => panic!("expected Invalid, got Verified"),
        }
    }
}
