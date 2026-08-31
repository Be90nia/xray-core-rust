//! VMess outbound → DialBridge 适配器。
//!
//! 把 VMess 协议接入 dispatcher 的 [`DialBridge`]：提供
//! [`make_vmess_dial_fn`] 闭包，内部拨号到 VMess 服务器 →
//! 写 AEAD 加密请求头 → 返回连接。
//!
//! ## 范围
//!
//! VMess over **raw TCP**：请求头 AEAD 加密 + body chunk AEAD 加密（duplex pump）。
//! [`make_vmess_dial_fn`] 闭包拨号到 VMess 服务器 → 写 AEAD 请求头 → 读响应头 →
//! 返回 [`VmessConn`]（内部 spawn 双向 pump：明文↔chunk 密文）。transport 层补全后
//! 可注入 TLS-wrapped 拨号闭包。仅支持 PlainSizeParser（默认 body 选项）。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf, WriteHalf,
};
use xray_app_dispatcher::default::DialFn;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_common::protocol::{request_option, Command, RequestHeader, SecurityType};
use xray_common::bitmask::Bitmask;
use crate::encoding::body_chunk::{PlainSizeParser, ShakeSizeParserAdapter, SizeParser};
use xray_common::uuid::UUID;
use xray_crypto::aead::{AeadCipher, Aes128Gcm, ChaCha20Poly1305Aead, NoOpAeadCipher};
use xray_transport::connection::Connection;
use xray_transport::sockopt::SocketOptions;

use crate::account::MemoryAccount;
use crate::encoding::client::ClientSession;
use crate::encoding::server::has_aes_gcm_hardware_support;
use crate::encoding::{generate_chacha20poly1305_key, ChunkNonceGenerator};
use crate::encoding::VERSION;
use crate::error::VmessError;


/// VMess outbound 配置。
#[derive(Debug, Clone)]
pub struct VmessOutboundConfig {
    /// 用户 UUID。
    pub user_uuid: UUID,
    /// VMess 服务器地址。
    pub server_address: Address,
    /// VMess 服务器端口。
    pub server_port: Port,
    /// 安全类型（决定 body 加密方式）。
    pub security: SecurityType,
    /// 可选 streamSettings（TLS/WS/gRPC/...）。None 走 raw TCP。
    pub stream_settings: Option<xray_transport::dialer::StreamSettings>,
    /// 用户 level（policy/stats 系统用）。
    pub level: u32,
    /// 用户 email（stats 系统标识用）。
    pub email: String,
}


impl VmessOutboundConfig {
    /// 构造配置（默认 security=Auto）。
    #[must_use]
    pub fn new(user_uuid: UUID, server_address: Address, server_port: Port) -> Self {
        Self {
            user_uuid,
            server_address,
            server_port,
            security: SecurityType::Auto,
            stream_settings: None,
            level: 0,
            email: String::new(),
        }
    }
    /// 设置安全类型（builder 风格）。
    #[must_use]
    pub fn with_security(mut self, security: SecurityType) -> Self {
        self.security = security;
        self
    }

    /// 指定 streamSettings（builder 风格）。
    #[must_use]
    pub fn with_stream_settings(mut self, settings: Option<xray_transport::dialer::StreamSettings>) -> Self {
        self.stream_settings = settings;
        self
    }

    /// 设置用户 level（builder 风格）。
    #[must_use]
    pub fn with_level(mut self, level: u32) -> Self {
        self.level = level;
        self
    }

    /// 设置用户 email（builder 风格）。
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = email.into();
        self
    }

    /// 服务器 Destination（TCP）。
    fn server_destination(&self) -> Destination {
        Destination::new(
            self.server_address.clone(),
            self.server_port,
            Network::TCP,
        )
    }
}

/// 从 JSON 字符串解析 security 类型。
///
/// Go 端 `security` 字段值：`"aes-128-gcm"` / `"chacha20-poly1305"` / `"auto"`。
/// `"none"` / `"zero"` 已被 Go 上游移除（v26.7.28）。
fn parse_security(s: &str) -> SecurityType {
    match s {
        "aes-128-gcm" | "aes-128-gcm@shadowsocks.org" => SecurityType::Aes128Gcm,
        "chacha20-poly1305" | "chacha20-poly1305@shadowsocks.org" => SecurityType::Chacha20Poly1305,
        "auto" => SecurityType::Auto,
        _ => SecurityType::Auto,
    }
}

/// 解析 VMess outbound settings JSON → VmessOutboundConfig。
///
/// JSON 格式：`{ "vnext": [{ "address": "...", "port": 443, "users": [{ "id": "uuid", "security": "aes-128-gcm" }] }] }`
pub fn parse_vmess_config(data: &[u8]) -> Result<VmessOutboundConfig, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let vnext = v
        .get("vnext")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing vnext array".to_string())?;
    // Go infra/conf/vmess.go：vnext/users 必须恰好 1 个，多端点应配多个 outbound + balancer。
    if vnext.len() != 1 {
        return Err(r#"vmess "vnext" should have one and only one member. Multiple endpoints should use multiple VMess outbounds and routing balancer instead"#.into());
    }
    let first = vnext
        .first()
        .ok_or_else(|| "vnext array is empty".to_string())?;
    let address = first
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing vnext[0].address".to_string())?;
    let port = first
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing vnext[0].port".to_string())?;
    let users = first
        .get("users")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing vnext[0].users".to_string())?;
    if users.len() != 1 {
        return Err(r#"vmess "users" should have one and only one member. Multiple members should use multiple VMess outbounds and routing balancer instead"#.into());
    }
    let user = users.first().unwrap();
    let user_id = user
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing vnext[0].users[0].id".to_string())?;
    let uuid = UUID::from_str(user_id)?;
    let security_str = user
        .get("security")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");
    let level = user.get("level").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let email = user.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // alterId≠0 的 legacy VMess 不支持（AEAD-only）；数字/字符串形式都认
    // （老配置生成器输出过字符串 alterId）。
    let alter_id = user
        .get("alterId")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok())))
        .unwrap_or(0);
    if alter_id != 0 {
        tracing::warn!(alter_id, "vmess outbound: legacy VMess is not supported");
        return Err(VmessError::UnsupportedLegacyAlterId(alter_id).to_string());
    }
    Ok(VmessOutboundConfig::new(
        uuid,
        Address::Domain(address.to_string()),
        Port::new(u16::try_from(port).map_err(|_| "port out of range")?),
    )
    .with_security(parse_security(security_str))
    .with_level(level)
    .with_email(email))
}

use std::str::FromStr;

/// 构造 VMess 的 DialFn 闭包。
///
/// 闭包捕获 `Arc<VmessOutboundConfig>`，每次调用：
/// 1. `dial` 到 VMess 服务器 → `Box<dyn Connection>`
/// 2. 解析 security（Auto → 具体算法）+ `encode_request_header` 写 AEAD 加密请求头
/// 3. `decode_response_header_async` 读服务端响应头（消费字节）
/// 4. 返回 [`VmessConn`]（内部 spawn 双向 chunk AEAD pump）
///
/// # Panics
///
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_vmess_dial_fn(config: Arc<VmessOutboundConfig>) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let config = Arc::clone(&config);
        let target_addr = dest.address().clone();
        let target_port = dest.port();
        Box::pin(async move {
            let server_dest = config.server_destination();
            let sockopt = config.stream_settings.as_ref().map(|s| s.socket_options()).unwrap_or_default();
            let mut conn: Box<dyn Connection> = match &config.stream_settings {
                Some(s) => xray_transport::dialer::dial(&server_dest, s, &sockopt)
                    .await
                    .map_err(|e| format!("vmess dial server ({}): {e}", s.protocol))?,
                None => xray_transport::system_dialer::dial_system(&server_dest, &sockopt)
                    .await
                    .map_err(|e| format!("vmess dial server (tcp): {e}"))?,
            };

            // 2. 解析 security：Auto → 具体算法（与 server 端 has_aes_gcm_hardware_support 同语义）。
            //    客户端发送具体 security 字节，服务端直接使用 → 两端 body 算法必一致。
            let security = resolve_security(config.security)
                .map_err(|e| format!("vmess resolve security: {e}"))?;
            // 3. 构造请求头（resolved security）+ body option bits
            let mut option = Bitmask::new(request_option::CHUNK_STREAM);
            let use_masking = matches!(
                config.security,
                SecurityType::Aes128Gcm | SecurityType::Chacha20Poly1305
            );
            if use_masking {
                option.set(request_option::CHUNK_MASKING);
                if matches!(
                    config.security,
                    SecurityType::Aes128Gcm
                        | SecurityType::Chacha20Poly1305
                        | SecurityType::Auto
                ) {
                    option.set(request_option::GLOBAL_PADDING);
                }
            }
            let account = MemoryAccount::new(config.user_uuid.clone())
                .with_security(security.clone());
            let session = ClientSession::new();
            let header = RequestHeader::new(
                VERSION,
                Command::Tcp,
                Destination::new(target_addr, target_port, Network::TCP),
                security.clone(),
            )
            .with_option(option);
            let sealed = session
                .encode_request_header(&header, &account.cmd_key())
                .map_err(|e| format!("vmess encode header: {e}"))?;
            conn.write_all(&sealed)
                .await
                .map_err(|e| format!("vmess write header: {e}"))?;
            conn.flush()
                .await
                .map_err(|e| format!("vmess flush header: {e}"))?;

            // 4. 读服务端响应头（服务端解码请求头后立即发送），消费掉响应头字节
            session
                .decode_response_header_async(&mut conn)
                .await
                .map_err(|e| format!("vmess decode response header: {e}"))?;

            // 5. 构造 body 加密状态（request_body_key/iv 加密上行，response_body_key/iv 解密下行）
            let (req_cipher, resp_cipher) = build_body_ciphers(security, &session)
                .map_err(|e| format!("vmess build body cipher: {e}"))?;
            let req_iv = session.request_body_iv;
            let resp_iv = session.response_body_iv;
            let use_padding = option.has(request_option::GLOBAL_PADDING);

            // 6. size parser：CHUNK_MASKING → Shake（req/resp 各自 IV 播种），否则 Plain
            let req_size_parser: Box<dyn SizeParser + Send> = if use_masking {
                Box::new(ShakeSizeParserAdapter::new(&req_iv))
            } else {
                Box::new(PlainSizeParser)
            };
            let resp_size_parser: Box<dyn SizeParser + Send> = if use_masking {
                Box::new(ShakeSizeParserAdapter::new(&resp_iv))
            } else {
                Box::new(PlainSizeParser)
            };

            // 7. 返回 VmessConn（内部 spawn 双向 chunk pump）
            Ok(Box::new(VmessConn::from_conn(
                conn,
                req_cipher,
                req_iv,
                req_size_parser,
                use_padding,
                resp_cipher,
                resp_iv,
                resp_size_parser,
                use_padding,
            )) as Box<dyn Connection>)
        })
    })
}

/// Duplex 缓冲（与 chunk payload 上限 8 KiB 对齐，留足一个 chunk 余量）。
const DUPLEX_BUF: usize = 16_384;

/// Pump 单次 read 缓冲（与 body_chunk `DEFAULT_PAYLOAD_SIZE` 对齐）。
const PUMP_BUF: usize = 8192;

/// VMess outbound 连接包装：内部用 `tokio::io::duplex` 桥接底层连接的 chunk AEAD 加密。
///
/// `_pump` 字段保证桥接 task 生命周期与连接一致——drop 时自动 abort。
pub struct VmessConn {
    inner: DuplexStream,
    _pump: tokio::task::JoinHandle<()>,
}

impl VmessConn {
    /// 从底层连接构造：spawn 双向 pump（明文 duplex ↔ chunk 密文 wire），返回 duplex 客户端包装。
    fn from_conn(
        conn: Box<dyn Connection>,
        req_cipher: BodyCipher,
        req_iv: [u8; 16],
        req_size_parser: Box<dyn SizeParser + Send>,
        req_padding: bool,
        resp_cipher: BodyCipher,
        resp_iv: [u8; 16],
        resp_size_parser: Box<dyn SizeParser + Send>,
        resp_padding: bool,
    ) -> Self {
        let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF);
        let (stream_r, stream_w) = tokio::io::split(conn);
        let pump = tokio::spawn(async move {
            let (server_r, server_w) = tokio::io::split(server_io);
            // up: 明文 duplex → chunk 加密 → wire（请求 body）
            let up = pump_up(server_r, stream_w, req_cipher, req_iv, req_size_parser, req_padding);
            // down: wire → chunk 解密 → 明文 duplex（响应 body）
            let down = pump_down(stream_r, server_w, resp_cipher, resp_iv, resp_size_parser, resp_padding);
            tokio::join!(up, down);
        });
        Self {
            inner: client_io,
            _pump: pump,
        }
    }
}

impl AsyncRead for VmessConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VmessConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Connection for VmessConn {
    fn remote_addr(&self) -> std::io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    fn local_addr(&self) -> std::io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

/// 解析 security：Auto → 具体算法（与 server 端 `has_aes_gcm_hardware_support` 同语义）。
fn resolve_security(s: SecurityType) -> Result<SecurityType, VmessError> {
    match s {
        SecurityType::Auto => {
            if has_aes_gcm_hardware_support() {
                Ok(SecurityType::Aes128Gcm)
            } else {
                Ok(SecurityType::Chacha20Poly1305)
            }
        }
        SecurityType::Unknown => Err(VmessError::Other("unknown security type".into())),
        other => Ok(other),
    }
}

/// VMess body 加密枚举：统一 Aes128Gcm / ChaCha20-Poly1305 / NoOp 为同一类型，
/// 供 pump 函数泛型使用（`Box<dyn AeadCipher>` 不实现 `AeadCipher`，故用枚举统一）。
enum BodyCipher {
    Aes(Aes128Gcm),
    Chacha(ChaCha20Poly1305Aead),
    NoOp(NoOpAeadCipher),
}

impl AeadCipher for BodyCipher {
    fn nonce_size(&self) -> usize {
        match self {
            BodyCipher::Aes(c) => c.nonce_size(),
            BodyCipher::Chacha(c) => c.nonce_size(),
            BodyCipher::NoOp(c) => c.nonce_size(),
        }
    }
    fn tag_size(&self) -> usize {
        match self {
            BodyCipher::Aes(c) => c.tag_size(),
            BodyCipher::Chacha(c) => c.tag_size(),
            BodyCipher::NoOp(c) => c.tag_size(),
        }
    }
    fn key_size(&self) -> usize {
        match self {
            BodyCipher::Aes(c) => c.key_size(),
            BodyCipher::Chacha(c) => c.key_size(),
            BodyCipher::NoOp(c) => c.key_size(),
        }
    }
    fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, xray_crypto::aead::CryptoError> {
        match self {
            BodyCipher::Aes(c) => c.seal(nonce, aad, plaintext),
            BodyCipher::Chacha(c) => c.seal(nonce, aad, plaintext),
            BodyCipher::NoOp(c) => c.seal(nonce, aad, plaintext),
        }
    }
    fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, xray_crypto::aead::CryptoError> {
        match self {
            BodyCipher::Aes(c) => c.open(nonce, aad, ciphertext),
            BodyCipher::Chacha(c) => c.open(nonce, aad, ciphertext),
            BodyCipher::NoOp(c) => c.open(nonce, aad, ciphertext),
        }
    }
}

/// 按 resolved security 构造请求/响应 body cipher（同一算法，不同 key）。
fn build_body_ciphers(
    security: SecurityType,
    session: &ClientSession,
) -> Result<(BodyCipher, BodyCipher), VmessError> {
    match security {
        SecurityType::Aes128Gcm => {
            let r = BodyCipher::Aes(Aes128Gcm::new(&session.request_body_key)?);
            let s = BodyCipher::Aes(Aes128Gcm::new(&session.response_body_key)?);
            Ok((r, s))
        }
        SecurityType::Chacha20Poly1305 => {
            let rk = generate_chacha20poly1305_key(&session.request_body_key);
            let r = BodyCipher::Chacha(ChaCha20Poly1305Aead::new(&rk)?);
            let sk = generate_chacha20poly1305_key(&session.response_body_key);
            let s = BodyCipher::Chacha(ChaCha20Poly1305Aead::new(&sk)?);
            Ok((r, s))
        }
        other => Err(VmessError::Other(format!(
            "unsupported body security: {other:?}"
        ))),
    }
}
/// size_field 由 SizeParser 编码——CHUNK_MASKING 时 SHAKE128 掩码）。nonce 跨块自增。
/// 流结束（EOF/错误）时写终止 chunk `seal([])`。
async fn pump_up<C, R, W>(
    mut server_r: R,
    mut stream_w: W,
    cipher: C,
    iv: [u8; 16],
    mut size_parser: Box<dyn SizeParser + Send>,
    global_padding: bool,
)
where
    C: AeadCipher + Send,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut nonce_gen = ChunkNonceGenerator::new(&iv, 12);
    let mut buf = [0u8; PUMP_BUF];
    loop {
        match server_r.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if write_one_chunk(
                    &mut stream_w,
                    &buf[..n],
                    &cipher,
                    &mut nonce_gen,
                    size_parser.as_mut(),
                    global_padding,
                )
                .await
                .is_err()
                {
                    break;
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "vmess up body plaintext read failed");
                break;
            }
        }
    }
    // 写终止 chunk：seal([]) → 仅 tag 字节，服务端 decode 看到 plaintext 为空即请求 body 结束
    let _ = write_one_chunk(
        &mut stream_w,
        &[],
        &cipher,
        &mut nonce_gen,
        size_parser.as_mut(),
        global_padding,
    )
    .await;
    let _ = stream_w.flush().await;
    let _ = stream_w.shutdown().await;
}

/// 写单个 chunk `[size_field][sealed][padding]`（对齐 body_chunk::write_one_chunk 的
/// SHAKE128 流消费顺序：next_padding_len → encode，与 decode 侧对称）。
async fn write_one_chunk<W, C>(
    writer: &mut W,
    data: &[u8],
    cipher: &C,
    nonce_gen: &mut ChunkNonceGenerator,
    size_parser: &mut (dyn SizeParser + Send),
    global_padding: bool,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    C: AeadCipher,
{
    let nonce = nonce_gen.next();
    let sealed = cipher
        .seal(&nonce, &[], data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let padding_size = if global_padding {
        usize::from(size_parser.next_padding_len())
    } else {
        0
    };
    let size_value = u16::try_from(sealed.len() + padding_size).unwrap_or(u16::MAX);
    let sb = size_parser.size_bytes();
    let mut size_field = vec![0u8; sb];
    size_parser.encode(size_value, &mut size_field);
    writer.write_all(&size_field).await?;
    writer.write_all(&sealed).await?;
    if padding_size > 0 {
        use rand::RngCore;
        let mut pad = vec![0u8; padding_size];
        rand::rng().fill_bytes(&mut pad);
        writer.write_all(&pad).await?;
    }
    Ok(())
}

/// 下行 pump：从 wire 读 VMess 响应 body chunk 流 → 解密为明文写入 duplex。
///
/// nonce 跨块自增。终止 chunk（解密后 plaintext 为空）/ EOF / 解密失败时 break，
/// 然后 shutdown duplex 写半边，让上层 reader 看到 EOF。
async fn pump_down<C, R, W>(
    mut stream_r: R,
    mut server_w: W,
    cipher: C,
    iv: [u8; 16],
    mut size_parser: Box<dyn SizeParser + Send>,
    global_padding: bool,
)
where
    C: AeadCipher + Send,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut nonce_gen = ChunkNonceGenerator::new(&iv, 12);
    loop {
        // SHAKE128 流消费顺序：next_padding_len → decode（与 encode 侧对称）
        let padding_size = if global_padding {
            usize::from(size_parser.next_padding_len())
        } else {
            0
        };
        let sb = size_parser.size_bytes();
        let mut size_field = vec![0u8; sb];
        if stream_r.read_exact(&mut size_field).await.is_err() {
            break;
        }
        let total_size = size_parser.decode(&size_field);
        if total_size == 0 {
            break; // 兼容 Go AuthenticationReader 的 size==0 → EOF 语义
        }
        let mut ciphertext = vec![0u8; usize::from(total_size)];
        if stream_r.read_exact(&mut ciphertext).await.is_err() {
            break;
        }
        let ciphertext_only = &ciphertext[..ciphertext.len().saturating_sub(padding_size)];
        let nonce = nonce_gen.next();
        match cipher.open(&nonce, &[], ciphertext_only) {
            Ok(pt) if pt.is_empty() => break, // 终止 chunk
            Ok(pt) => {
                if server_w.write_all(&pt).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                tracing::debug!(error = %e.to_string(), "vmess down body chunk open failed");
                break;
            }
        }
    }
    let _ = server_w.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_server_destination_roundtrip() {
        let uuid = UUID::new();
        let cfg = VmessOutboundConfig::new(
            uuid,
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(443),
        );
        let dest = cfg.server_destination();
        assert!(dest.is_tcp());
        assert_eq!(dest.port(), Port::new(443));
    }
    #[test]
    fn parse_security_mapping() {
        assert!(matches!(super::parse_security("aes-128-gcm"), SecurityType::Aes128Gcm));
        assert!(matches!(super::parse_security("chacha20-poly1305"), SecurityType::Chacha20Poly1305));
        assert!(matches!(super::parse_security("auto"), SecurityType::Auto));
        assert!(matches!(super::parse_security("unknown"), SecurityType::Auto));
    }

    #[test]
    fn make_dial_fn_returns_arc_closure() {
        let uuid = UUID::new();
        let cfg = Arc::new(VmessOutboundConfig::new(
            uuid,
            Address::new_domain("example.com"),
            Port::new(443),
        ));
        let _dial = make_vmess_dial_fn(Arc::clone(&cfg));
        assert_eq!(Arc::strong_count(&cfg), 2);
    }
    fn parse_vmess_config_extracts_fields() {
        let data = r#"{
            "vnext": [{
                "address": "server.example.com",
                "port": 8443,
                "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "security": "aes-128-gcm" }]
            }]
        }"#;
        let config = parse_vmess_config(data.as_bytes()).unwrap();
        assert_eq!(config.server_port.value(), 8443);
        assert!(matches!(config.security, SecurityType::Aes128Gcm));
        match &config.server_address {
            Address::Domain(d) => assert_eq!(d, "server.example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn parse_vmess_config_missing_vnext_fails() {
        let result = parse_vmess_config(b"{}");
        assert!(result.is_err());
    }

    /// Go infra/conf/vmess.go：vnext/users 恰好 1 个，多个直接拒绝。
    #[test]
    fn parse_vmess_config_multiple_vnext_fails() {
        let data = r#"{
            "vnext": [
                { "address": "a.example.com", "port": 443, "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }] },
                { "address": "b.example.com", "port": 443, "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }] }
            ]
        }"#;
        assert!(parse_vmess_config(data.as_bytes()).is_err());
    }

    /// alterId>0 的 legacy VMess 不支持（AEAD-only，对齐 Go v26 已删 alterId）。
    #[test]
    fn parse_vmess_config_alter_id_nonzero_fails() {
        let data = r#"{
            "vnext": [{
                "address": "server.example.com",
                "port": 8443,
                "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "alterId": 64 }]
            }]
        }"#;
        let err = parse_vmess_config(data.as_bytes()).unwrap_err();
        assert!(err.contains("alterId"), "unexpected error: {err}");
    }

    /// 老配置生成器（v2rayN 等）会输出字符串形式 alterId，同样拒绝。
    #[test]
    fn parse_vmess_config_alter_id_string_fails() {
        let data = r#"{
            "vnext": [{
                "address": "server.example.com",
                "port": 8443,
                "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "alterId": "64" }]
            }]
        }"#;
        assert!(parse_vmess_config(data.as_bytes()).is_err());
    }

    /// alterId==0（或缺失）走现有 AEAD 路径。
    #[test]
    fn parse_vmess_config_alter_id_zero_ok() {
        let data = r#"{
            "vnext": [{
                "address": "server.example.com",
                "port": 8443,
                "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "alterId": 0 }]
            }]
        }"#;
        assert!(parse_vmess_config(data.as_bytes()).is_ok());
    }
}
