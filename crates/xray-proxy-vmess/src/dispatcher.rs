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

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use xray_app_dispatcher::default::DialFn;
use xray_common::{
    bitmask::Bitmask,
    net::{address::Address, destination::Destination, network::Network, port::Port},
    protocol::{Command, RequestHeader, SecurityType, request_option},
    uuid::UUID,
};
use xray_crypto::aead::{AeadCipher, Aes128Gcm, ChaCha20Poly1305Aead};
use xray_transport::connection::Connection;

use crate::{
    account::MemoryAccount,
    encoding::{
        ChunkNonceGenerator, VERSION,
        body_chunk::{ChunkNonceAdapter, PlainSizeParser, ShakeSizeParserAdapter, SizeParser},
        client::ClientSession,
        generate_chacha20poly1305_key,
        server::has_aes_gcm_hardware_support,
    },
    error::VmessError,
};

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
    pub fn with_stream_settings(
        mut self,
        settings: Option<xray_transport::dialer::StreamSettings>,
    ) -> Self {
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
        Destination::new(self.server_address.clone(), self.server_port, Network::TCP)
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
/// JSON 格式：`{ "vnext": [{ "address": "...", "port": 443, "users": [{ "id": "uuid", "security":
/// "aes-128-gcm" }] }] }`
pub fn parse_vmess_config(data: &[u8]) -> Result<VmessOutboundConfig, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    // Go infra/conf/vmess.go:112-134 扁平形式：顶层 address 非空 → 以顶层
    // id/security/level/email 构造 vnext[0]（覆盖显式 vnext；Go Build 里
    // flat 时 user 只取顶层 Level/Email/ID/Security）。形态同 trojan flat。
    let v = if v.get("address").and_then(|a| a.as_str()).is_some() {
        let mut obj = v.as_object().cloned().unwrap_or_default();
        obj.insert(
            "vnext".into(),
            serde_json::json!([{
                "address": v.get("address"),
                "port": v.get("port"),
                "users": [{
                    "id": v.get("id"),
                    "security": v.get("security"),
                    "level": v.get("level"),
                    "email": v.get("email"),
                }],
            }]),
        );
        serde_json::Value::Object(obj)
    } else {
        v
    };
    let vnext = v
        .get("vnext")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing vnext array".to_string())?;
    // Go infra/conf/vmess.go：vnext/users 必须恰好 1 个，多端点应配多个 outbound + balancer。
    if vnext.len() != 1 {
        return Err(r#"vmess "vnext" should have one and only one member. Multiple endpoints should use multiple VMess outbounds and routing balancer instead"#.into());
    }
    let first = vnext.first().ok_or_else(|| "vnext array is empty".to_string())?;
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
    let user = users.first().expect("users.len() == 1 checked above");
    let user_id = user
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing vnext[0].users[0].id".to_string())?;
    let uuid = UUID::from_str(user_id)?;
    let security_str = user.get("security").and_then(|v| v.as_str()).unwrap_or("auto");
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
        let is_udp = dest.is_udp();
        Box::pin(async move {
            let server_dest = config.server_destination();
            let sockopt =
                config.stream_settings.as_ref().map(|s| s.socket_options()).unwrap_or_default();
            // bd cjwc G6（Go proxy/vmess/outbound/outbound.go:71）：连接级退避
            // ExponentialBackoff(5, 200)。请求头在 dial 成功后才发送，环内无协议字节。
            let mut conn: Box<dyn Connection> =
                xray_transport::retry::exponential_backoff(5, 200, || async {
                    match &config.stream_settings {
                        Some(s) => xray_transport::dialer::dial(&server_dest, s, &sockopt)
                            .await
                            .map_err(|e| format!("vmess dial server ({}): {e}", s.protocol)),
                        None => xray_transport::system_dialer::dial_system(&server_dest, &sockopt)
                            .await
                            .map_err(|e| format!("vmess dial server (tcp): {e}")),
                    }
                })
                .await
                .map_err(|e| format!("failed to find an available destination: {e}"))?;

            // 2. 解析 security：Auto → 具体算法（与 server 端 has_aes_gcm_hardware_support
            //    同语义）。 客户端发送具体 security 字节，服务端直接使用 → 两端 body 算法必一致。
            let security = resolve_security(config.security)
                .map_err(|e| format!("vmess resolve security: {e}"))?;
            // 3. 构造请求头（resolved security）+ body option bits。
            // rmgy：CHUNK_MASKING (0x04) / GLOBAL_PADDING (0x08) 的判定基于
            // **resolved** security 而非 config.security。之前 config=Auto 路径
            // `use_masking` 为 false（Auto 不在 matches 里），缺 Go AEAD 档常态
            // 特征成 DPI 指纹差。Go client：Auto 落地 GCM/ChaCha 必然 0x04+0x08。
            let mut option = Bitmask::new(request_option::CHUNK_STREAM);
            let use_masking =
                matches!(security, SecurityType::Aes128Gcm | SecurityType::Chacha20Poly1305);
            if use_masking {
                option.set(request_option::CHUNK_MASKING);
            }
            // 票 037f：xray.vmess.padding env（Go outbound.go:231-236 enablePadding
            // + shouldEnablePadding 短路项）：env 设置即对全部 security 开
            // GLOBAL_PADDING；CHUNK_MASKING 仍按 security 判定（Go 同）。
            if should_set_global_padding(
                use_masking,
                xray_common::platform::env::use_vmess_padding(),
            ) {
                option.set(request_option::GLOBAL_PADDING);
            }
            let account = MemoryAccount::new(config.user_uuid.clone()).with_security(security);
            let session = ClientSession::new();
            // command/network 按 dest.network（Go vmess outbound.go:88-91：
            // UDP 目标 → RequestCommandUDP）。
            let command = if is_udp { Command::Udp } else { Command::Tcp };
            let network = if is_udp { Network::UDP } else { Network::TCP };
            let header = RequestHeader::new(
                VERSION,
                command,
                Destination::new(target_addr, target_port, network),
                security,
            )
            .with_option(option);
            let sealed = session
                .encode_request_header(&header, &account.cmd_key())
                .map_err(|e| format!("vmess encode header: {e}"))?;
            conn.write_all(&sealed).await.map_err(|e| format!("vmess write header: {e}"))?;
            conn.flush().await.map_err(|e| format!("vmess flush header: {e}"))?;

            // 5. 构造 body 加密状态（request_body_key/iv 加密上行，response_body_key/iv
            //    解密下行）。 响应头解码移入 down pump（与上行并发）：Go 服务端把响应头缓冲到首块
            //    下行数据才 flush（SetFlushNext），dial 阶段同步等待会造成双向死锁。
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
            // 7. UDP：VmessUdpConn（chunk 即 packet，Go 非 cone 语义——packet 边界 必须保持，duplex
            //    流桥会合并多次 write 破坏边界）；TCP：VmessConn （内部 spawn 双向 chunk
            //    pump；响应头在 down pump 内惰性解码）。
            if is_udp {
                return Ok(Box::new(VmessUdpConn::from_udp_conn(
                    conn,
                    session,
                    req_cipher,
                    req_iv,
                    req_size_parser,
                    use_padding,
                    resp_cipher,
                    resp_iv,
                    resp_size_parser,
                    use_padding,
                )) as Box<dyn Connection>);
            }
            Ok(Box::new(VmessConn::from_conn(
                conn,
                session,
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
    #[allow(clippy::too_many_arguments)] // 与 Go dial 参数集一一对应
    fn from_conn(
        conn: Box<dyn Connection>,
        session: ClientSession,
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
        #[allow(
            clippy::disallowed_methods,
            reason = "热路径豁免（B6 t975）：每帧泵——明文 duplex ↔ chunk AEAD wire 双向搬运，热路径零改动（坑约束 12）；托管接线归 P1 插件装配"
        )]
        let pump = tokio::spawn(async move {
            let (server_r, mut server_w) = tokio::io::split(server_io);
            // up: 明文 duplex → chunk 加密 → wire（请求 body）
            let up = pump_up(server_r, stream_w, req_cipher, req_iv, req_size_parser, req_padding);
            // down: 先惰性解码响应头，再 chunk 解密 → 明文 duplex。
            // 与 up 并发执行：服务端（Go SetFlushNext）把响应头缓冲到首块下行数据，
            // 上行数据必须先于响应头到达，因此不能在 dial 阶段同步等待响应头。
            let down = async move {
                let mut sr = stream_r;
                if let Err(e) = session.decode_response_header_async(&mut sr).await {
                    tracing::debug!(error = %e, "vmess decode response header failed");
                    let _ = server_w.shutdown().await;
                    return;
                }
                pump_down(sr, server_w, resp_cipher, resp_iv, resp_size_parser, resp_padding).await;
            };
            tokio::join!(up, down);
        });
        Self { inner: client_io, _pump: pump }
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

/// VMess UDP 出站连接：chunk 即 packet（Go 非 cone 语义）。
///
/// 上行：每次 [`AsyncWrite::poll_write`] 把传入 buf 编码为**恰好一个** chunk
/// （AEAD seal，见 [`crate::encoding::body_chunk::encode_single_chunk`]）直写底层
/// 连接——duplex 流桥会合并多次 write 破坏 packet 边界，故不走 [`VmessConn`]
/// 的 duplex 泵。下行：spawn task 惰性解响应头后逐 chunk 解密，包经 mpsc 队列
/// 交付，[`AsyncRead::poll_read`] 每次返回一个 packet。
struct VmessUdpConn {
    inner_w: tokio::io::WriteHalf<Box<dyn Connection>>,
    rx: tokio::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
    up_nonce: ChunkNonceGenerator,
    req_cipher: BodyCipher,
    /// Mutex 仅为 Connection::Sync（poll_write 单线程独占，锁无竞争）；
    /// ShakeSizeParserAdapter 内部 XofReader 非 Sync，无法裸存。
    req_size_parser: parking_lot::Mutex<Box<dyn SizeParser + Send>>,
    req_padding: bool,
    /// 单 chunk 明文容量上限（packet 超限截断；UDP relay 实际包 ≤ MTU）
    up_chunk_cap: usize,
    wpending: Vec<u8>,
    wpos: usize,
    _down_task: tokio::task::JoinHandle<()>,
}

impl VmessUdpConn {
    /// 从底层连接构造 UDP 模式连接（响应头由 down task 惰性解码）。
    #[allow(clippy::too_many_arguments)] // 与 Go dial 参数集一一对应
    fn from_udp_conn(
        conn: Box<dyn Connection>,
        session: ClientSession,
        req_cipher: BodyCipher,
        req_iv: [u8; 16],
        req_size_parser: Box<dyn SizeParser + Send>,
        req_padding: bool,
        resp_cipher: BodyCipher,
        resp_iv: [u8; 16],
        mut resp_size_parser: Box<dyn SizeParser + Send>,
        resp_padding: bool,
    ) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let (stream_r, stream_w) = tokio::io::split(conn);
        let up_chunk_cap = crate::encoding::body_chunk::single_chunk_capacity(
            &req_cipher,
            req_size_parser.as_ref(),
        );
        #[allow(
            clippy::disallowed_methods,
            reason = "热路径豁免（B6 t975）：每帧泵——UDP 模式响应头惰性解码 + chunk 解密下行泵，热路径零改动（坑约束 12）；托管接线归 P1 插件装配"
        )]
        let down_task = tokio::spawn(async move {
            let mut sr = stream_r;
            // 响应头惰性解码（Go SetFlushNext：首块下行才 flush，dial 阶段同步
            // 等待会造成双向死锁——与 VmessConn 同语义）。
            if let Err(e) = session.decode_response_header_async(&mut sr).await {
                tracing::debug!(error = %e, "vmess udp decode response header failed");
                let _ = tx
                    .send(Err(std::io::Error::other(format!("vmess udp response header: {e}"))))
                    .await;
                return;
            }
            let mut nonce_gen = ChunkNonceAdapter::new(&resp_iv, 12);
            loop {
                match crate::encoding::body_chunk::decode_single_chunk_async(
                    &mut sr,
                    &resp_cipher,
                    &mut nonce_gen,
                    resp_size_parser.as_mut(),
                    resp_padding,
                )
                .await
                {
                    Ok(Some(pkt)) => {
                        if tx.send(Ok(pkt)).await.is_err() {
                            break; // 读端已 drop
                        }
                    },
                    Ok(None) => break, // 终止 chunk / 干净 EOF = 流结束
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    },
                }
            }
        });
        Self {
            inner_w: stream_w,
            rx,
            up_nonce: ChunkNonceGenerator::new(&req_iv, 12),
            req_cipher,
            req_size_parser: parking_lot::Mutex::new(req_size_parser),
            req_padding,
            up_chunk_cap,
            wpending: Vec::with_capacity(up_chunk_cap + 96),
            wpos: 0,
            _down_task: down_task,
        }
    }
}

impl AsyncWrite for VmessUdpConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        // 排干 pending 帧（一包一帧，不可分）
        while this.wpos < this.wpending.len() {
            let n = std::task::ready!(
                Pin::new(&mut this.inner_w).poll_write(cx, &this.wpending[this.wpos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "vmess udp: frame write stalled",
                )));
            }
            this.wpos += n;
        }
        // 一包一 chunk：与 TCP 泵同款持久缓冲 + next_ref + seal_into（稳态零分配）
        let payload = &buf[..buf.len().min(this.up_chunk_cap)];
        let nonce = this.up_nonce.next_ref();
        encode_frame_into(
            &mut this.wpending,
            payload,
            &this.req_cipher,
            nonce,
            this.req_size_parser.lock().as_mut(),
            this.req_padding,
        )
        .map_err(|e| std::io::Error::other(format!("vmess udp encode: {e}")))?;
        this.wpos = 0;
        while this.wpos < this.wpending.len() {
            let n = std::task::ready!(
                Pin::new(&mut this.inner_w).poll_write(cx, &this.wpending[this.wpos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "vmess udp: frame write stalled",
                )));
            }
            this.wpos += n;
        }
        Poll::Ready(Ok(payload.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner_w).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self.get_mut();
        // 写终止 chunk（seal([])）——服务端 decode 看到空明文即流结束
        if this.wpos >= this.wpending.len() {
            let nonce = this.up_nonce.next_ref();
            encode_frame_into(
                &mut this.wpending,
                &[],
                &this.req_cipher,
                nonce,
                this.req_size_parser.lock().as_mut(),
                this.req_padding,
            )
            .map_err(|e| std::io::Error::other(format!("vmess udp termination: {e}")))?;
            this.wpos = 0;
        }
        Pin::new(&mut this.inner_w).poll_shutdown(cx)
    }
}

impl AsyncRead for VmessUdpConn {
    // 三臂皆 return：单次 poll 只交付一个 packet，迭代由 down task 的真 loop 与
    // 调用方 relay 承担（Go 同语义：buf.Copy 是迭代驱动）
    #[allow(clippy::never_loop)]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            match std::task::ready!(self.get_mut().rx.poll_recv(cx)) {
                Some(Ok(pkt)) => {
                    // 包大于 ReadBuf 时截断剩余（数据报不可分；relay 缓冲 ≥ MTU，
                    // 与 Go buf 单包上限语义一致）
                    let n = pkt.len().min(buf.remaining());
                    buf.put_slice(&pkt[..n]);
                    return Poll::Ready(Ok(()));
                },
                Some(Err(e)) => return Poll::Ready(Err(e)),
                None => return Poll::Ready(Ok(())), // down task 结束 = 流结束
            }
        }
    }
}

impl Connection for VmessUdpConn {
    fn remote_addr(&self) -> std::io::Result<Option<SocketAddr>> {
        Ok(None)
    }

    fn local_addr(&self) -> std::io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

/// GLOBAL_PADDING 判定（Go outbound.go:228-230 `shouldEnablePadding`）：
/// AEAD 档（CHUNK_MASKING 场景）恒开；`xray.vmess.padding` env 设置时对
/// 任意 security 开（enablePadding 短路项）。
fn should_set_global_padding(use_masking: bool, env_padding: bool) -> bool {
    use_masking || env_padding
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
        },
        SecurityType::Unknown => Err(VmessError::Other("unknown security type".into())),
        other => Ok(other),
    }
}

/// VMess body 加密枚举：统一 Aes128Gcm / ChaCha20-Poly1305 为同一类型，
/// 供 pump 函数泛型使用（`Box<dyn AeadCipher>` 不实现 `AeadCipher`，故用枚举统一）。
#[allow(clippy::large_enum_variant)] // 双算法 variant 尺寸差是协议事实，Box 化徒增间接
enum BodyCipher {
    Aes(Aes128Gcm),
    Chacha(ChaCha20Poly1305Aead),
}

impl AeadCipher for BodyCipher {
    fn nonce_size(&self) -> usize {
        match self {
            BodyCipher::Aes(c) => c.nonce_size(),
            BodyCipher::Chacha(c) => c.nonce_size(),
        }
    }

    fn tag_size(&self) -> usize {
        match self {
            BodyCipher::Aes(c) => c.tag_size(),
            BodyCipher::Chacha(c) => c.tag_size(),
        }
    }

    fn key_size(&self) -> usize {
        match self {
            BodyCipher::Aes(c) => c.key_size(),
            BodyCipher::Chacha(c) => c.key_size(),
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
        }
    }

    fn seal_into(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), xray_crypto::aead::CryptoError> {
        match self {
            BodyCipher::Aes(c) => c.seal_into(nonce, aad, plaintext, out),
            BodyCipher::Chacha(c) => c.seal_into(nonce, aad, plaintext, out),
        }
    }

    fn open_in_place<'a>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &'a mut [u8],
    ) -> Result<&'a mut [u8], xray_crypto::aead::CryptoError> {
        match self {
            BodyCipher::Aes(c) => c.open_in_place(nonce, aad, ciphertext),
            BodyCipher::Chacha(c) => c.open_in_place(nonce, aad, ciphertext),
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
        },
        SecurityType::Chacha20Poly1305 => {
            let rk = generate_chacha20poly1305_key(&session.request_body_key);
            let r = BodyCipher::Chacha(ChaCha20Poly1305Aead::new(&rk)?);
            let sk = generate_chacha20poly1305_key(&session.response_body_key);
            let s = BodyCipher::Chacha(ChaCha20Poly1305Aead::new(&sk)?);
            Ok((r, s))
        },
        other => Err(VmessError::Other(format!("unsupported body security: {other:?}"))),
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
) where
    C: AeadCipher + Send,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut nonce_gen = ChunkNonceGenerator::new(&iv, 12);
    let mut buf = [0u8; PUMP_BUF];
    let mut chunk_buf = Vec::with_capacity(PUMP_BUF + 96);
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
                    &mut chunk_buf,
                )
                .await
                .is_err()
                {
                    break;
                }
            },
            Err(e) => {
                tracing::debug!(error = %e, "vmess up body plaintext read failed");
                break;
            },
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
        &mut chunk_buf,
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
    chunk_buf: &mut Vec<u8>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    C: AeadCipher,
{
    let nonce = nonce_gen.next_ref();
    encode_frame_into(chunk_buf, data, cipher, nonce, size_parser, global_padding)?;
    writer.write_all(chunk_buf).await
}

/// 把一帧 `[size_field][sealed][padding]` 构进调用方复用的缓冲（同步、零中间 Vec）。
///
/// TCP 泵 [`write_one_chunk`] 与 UDP [`VmessUdpConn::poll_write`] 共用——两侧
/// 构帧语义必须同一份（SHAKE128 流消费顺序：next_padding_len → encode，与
/// decode 侧对称），否则 wire 会漂移。`pub(crate)`：供同 crate 的分配预算判别器直测。
pub(crate) fn encode_frame_into(
    frame: &mut Vec<u8>,
    data: &[u8],
    cipher: &dyn AeadCipher,
    nonce: &[u8],
    size_parser: &mut (dyn SizeParser + Send),
    global_padding: bool,
) -> std::io::Result<()> {
    let sb = size_parser.size_bytes();
    let padding_size = if global_padding { usize::from(size_parser.next_padding_len()) } else { 0 };
    // 零中间 Vec：sealed/padding 追加进复用的 frame，size_field 前缀
    // 预留后回填。
    frame.clear();
    frame.resize(sb, 0);
    cipher
        .seal_into(nonce, &[], data, frame)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    if padding_size > 0 {
        use rand::RngCore;
        let start = frame.len();
        frame.resize(start + padding_size, 0);
        rand::rng().fill_bytes(&mut frame[start..]);
    }
    // size 字段 u16：超出即显式报错（静默回退 u16::MAX 会致收端按 65535 读、错位）
    let size_value = u16::try_from(frame.len() - sb).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "vmess chunk size exceeds u16")
    })?;
    size_parser.encode(size_value, &mut frame[..sb]);
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
) where
    C: AeadCipher + Send,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut nonce_gen = ChunkNonceGenerator::new(&iv, 12);
    let mut size_field = Vec::with_capacity(18);
    let mut ciphertext = Vec::with_capacity(PUMP_BUF + 96);
    loop {
        // SHAKE128 流消费顺序：next_padding_len → decode（与 encode 侧对称）
        let padding_size =
            if global_padding { usize::from(size_parser.next_padding_len()) } else { 0 };
        let sb = size_parser.size_bytes();
        size_field.resize(sb, 0);
        if stream_r.read_exact(&mut size_field).await.is_err() {
            break;
        }
        let total_size = size_parser.decode(&size_field);
        if total_size == 0 {
            break; // 兼容 Go AuthenticationReader 的 size==0 → EOF 语义
        }
        ciphertext.resize(usize::from(total_size), 0);
        if stream_r.read_exact(&mut ciphertext).await.is_err() {
            break;
        }
        let cipher_len = ciphertext.len().saturating_sub(padding_size);
        let nonce = nonce_gen.next_ref();
        #[allow(clippy::redundant_guards)] // is_empty 守卫表达终止 chunk 语义，模式嵌套反而晦涩
        match cipher.open_in_place(nonce, &[], &mut ciphertext[..cipher_len]) {
            Ok(pt) if pt.is_empty() => break, // 终止 chunk
            Ok(pt) => {
                if server_w.write_all(pt).await.is_err() {
                    break;
                }
            },
            Err(e) => {
                tracing::debug!(error = %e.to_string(), "vmess down body chunk open failed");
                break;
            },
        }
    }
    let _ = server_w.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// bd cjwc G6（Go outbound.go:71）：dial 拒绝退避重试 5 次。关闭的 listener
    /// 无 accept 可计数、dial_system 环路带内部定时器（16s connect timeout）污染
    /// 虚拟时钟 → 真实时钟断言 sleep 阶梯下界（末次失败不再延迟：
    /// 0+200+400+600=1200ms；单次尝试零 sleep 立即返回，≥1.2s 只可能来自跑满
    /// 5 次环）+ 最终返回错误。
    #[tokio::test]
    async fn dial_to_closed_server_backs_off_five_times() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener); // 立即关闭 → connect 全拒

        let cfg = Arc::new(VmessOutboundConfig::new(
            UUID::new(),
            Address::IPv4(std::net::Ipv4Addr::LOCALHOST),
            Port::new(port),
        ));
        let dial_fn = make_vmess_dial_fn(cfg);
        let dest = Destination::tcp(Address::new_domain("example.com"), Port::new(80));

        let start = std::time::Instant::now();
        let r = dial_fn(&dest).await;
        let elapsed = start.elapsed();

        assert!(r.is_err(), "dial to closed listener must fail");
        assert!(
            elapsed >= std::time::Duration::from_millis(1200),
            "5 attempts need the 1200ms backoff ladder, got {elapsed:?}"
        );
        // 上界对齐既有 freedom 重试测试的 30s 宽限（dial_system 单次可耗 ~2s）。
        assert!(elapsed < std::time::Duration::from_secs(30), "{elapsed:?}");
    }

    /// 票 037f：GLOBAL_PADDING 判定对齐 Go `shouldEnablePadding`——AEAD 档恒开，
    /// env（xray.vmess.padding）设置时任意 security 开。
    #[test]
    fn global_padding_decision_matches_go() {
        assert!(should_set_global_padding(true, false), "AEAD 档恒开");
        assert!(should_set_global_padding(true, true));
        assert!(should_set_global_padding(false, true), "env 设置即开（Go enablePadding）");
        assert!(!should_set_global_padding(false, false), "非 AEAD 且未设 env 不开");
    }

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
        assert!(matches!(
            super::parse_security("chacha20-poly1305"),
            SecurityType::Chacha20Poly1305
        ));
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
    #[test]
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

    /// Go infra/conf/vmess.go:112-134 扁平形式：顶层 address/id/security 构造
    /// vnext[0]，覆盖显式 vnext；缺 id 时等价 vnext 路径报 missing id。
    #[test]
    fn parse_vmess_config_flat_top_level_fields() {
        let data = br#"{
            "address": "flat.example.com",
            "port": 8443,
            "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "security": "aes-128-gcm",
            "level": 2,
            "email": "flat@x.test"
        }"#;
        let config = parse_vmess_config(data).unwrap();
        assert_eq!(config.server_port.value(), 8443);
        assert_eq!(config.level, 2);
        assert_eq!(config.email, "flat@x.test");
        assert!(matches!(config.security, SecurityType::Aes128Gcm));
        match &config.server_address {
            Address::Domain(d) => assert_eq!(d, "flat.example.com"),
            other => panic!("unexpected address: {other:?}"),
        }
    }

    #[test]
    fn parse_vmess_config_flat_missing_id_fails() {
        let data = br#"{ "address": "flat.example.com", "port": 443 }"#;
        let err = parse_vmess_config(data).unwrap_err();
        assert!(err.contains("id"), "unexpected error: {err}");
    }

    /// 模拟 Go vmess inbound 的 `SetFlushNext` 缓冲语义：服务端解码请求头后
    /// **不立即**发送响应头，而是缓冲到首块下行数据一起 flush。生产 dial fn 若
    /// 在拨号阶段同步阻塞等待响应头，将与服务端互相等待造成死锁
    /// （Go outbound 的 header/body 并发 copy 不存在此问题）。
    #[tokio::test]
    async fn dial_does_not_block_on_response_header_go_set_flush_next_semantics() {
        use std::{
            io::Read,
            sync::atomic::{AtomicBool, Ordering},
        };

        use crate::{
            encoding::server::{ServerSession, SessionHistory},
            validator::{MemoryUser, TimedUserValidator, Validator},
        };

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let server_port = listener.local_addr().unwrap().port();
        let body_arrived = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&body_arrived);

        #[allow(
            clippy::disallowed_methods,
            reason = "测试脚手架起阻塞 OS 线程持 accept（Go set_flush_next 语义回归探针）；无 PluginContext 可穿，按 clippy.toml 指引逐处登记"
        )]
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let uuid = UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("uuid");
            let validator = TimedUserValidator::new();
            let account = MemoryAccount::new(uuid);
            validator.add(MemoryUser::new("t@example.com", account)).expect("add user");
            let history = SessionHistory::new();
            let mut server = ServerSession::new(&validator, &history);
            let (_req, _) = server.decode_request_header(&mut sock).expect("decode header");
            // 不立即回响应头：等客户端 body 首字节到达（SetFlushNext 语义）。
            let mut b = [0u8; 1];
            sock.read_exact(&mut b).expect("read body byte");
            flag.store(true, Ordering::SeqCst);
            let resp = xray_common::protocol::ResponseHeader::new(Command::Tcp);
            server.encode_response_header(&resp, &mut sock).expect("encode response header");
            // 保持连接片刻，让 down pump 的 chunk 读取自然等 EOF。
            std::thread::sleep(std::time::Duration::from_millis(200));
        });

        let uuid = UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("uuid");
        let cfg = Arc::new(VmessOutboundConfig::new(
            uuid,
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(server_port),
        ));
        let dial = make_vmess_dial_fn(Arc::clone(&cfg));
        let dest =
            Destination::new(Address::from_ipv4_bytes([127, 0, 0, 1]), Port::new(1), Network::TCP);

        // 修复断言 1：dial 不得阻塞等待响应头（修复前此处 2s 超时 panic）。
        let mut conn = tokio::time::timeout(std::time::Duration::from_secs(2), dial(&dest))
            .await
            .expect("dial must not block on response header")
            .expect("dial ok");

        // 修复断言 2：dial 返回后立即写 body（Go 并发 copy 语义），服务端必须收到。
        use tokio::io::AsyncWriteExt;
        conn.write_all(b"payload").await.expect("write body");
        conn.flush().await.expect("flush body");

        for _ in 0..50 {
            if body_arrived.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            body_arrived.load(Ordering::SeqCst),
            "server must receive body without having sent the response header"
        );
    }

    /// vmess UDP（bd uhg2）：一包一 chunk。写侧 poll_write 边界=packet 边界，
    /// server 侧逐 chunk 解出恰好两包。
    #[tokio::test]
    async fn vmess_udp_conn_write_boundaries() {
        use tokio::io::AsyncWriteExt;

        let (client_side, mut server_side) = tokio::io::duplex(16384);
        let mut conn = VmessUdpConn::from_udp_conn(
            Box::new(xray_transport::connection::DuplexConnection::new(client_side)),
            ClientSession::new(),
            BodyCipher::Aes(Aes128Gcm::new(&[0x42u8; 16]).expect("cipher")),
            [0xAAu8; 16],
            Box::new(PlainSizeParser),
            false,
            BodyCipher::Aes(Aes128Gcm::new(&[0x43u8; 16]).expect("cipher")),
            [0xBBu8; 16],
            Box::new(PlainSizeParser),
            false,
        );

        conn.write_all(b"ping").await.unwrap();
        conn.write_all(&[9u8; 600]).await.unwrap();
        conn.flush().await.unwrap();

        // server 侧：同 key/iv 序列解密，应解出恰好两包
        let server_cipher = Aes128Gcm::new(&[0x42u8; 16]).expect("cipher");
        let mut nonce = ChunkNonceAdapter::new(&[0xAAu8; 16], 12);
        let mut sp = PlainSizeParser;
        let p1 = crate::encoding::body_chunk::decode_single_chunk_async(
            &mut server_side,
            &server_cipher,
            &mut nonce,
            &mut sp,
            false,
        )
        .await
        .expect("decode p1")
        .expect("p1 non-terminal");
        assert_eq!(p1, b"ping");
        let p2 = crate::encoding::body_chunk::decode_single_chunk_async(
            &mut server_side,
            &server_cipher,
            &mut nonce,
            &mut sp,
            false,
        )
        .await
        .expect("decode p2")
        .expect("p2 non-terminal");
        assert_eq!(p2, vec![9u8; 600]);
    }

    /// 判别器（NF-1）：UDP poll_write 复用持久帧缓冲——改前每包新建
    /// `Vec::with_capacity(payload+96)`，改后容量在构造期一次预留、写包不再扩容
    /// （与 TCP 泵 `chunk_buf` 同形）。每包分配数见
    /// `encoding::body_chunk::tests::udp_single_packet_frame_alloc_budget`。
    #[tokio::test]
    async fn vmess_udp_conn_reuses_frame_buffer() {
        use tokio::io::AsyncWriteExt;

        let (client_side, _server_side) = tokio::io::duplex(16384);
        let mut conn = VmessUdpConn::from_udp_conn(
            Box::new(xray_transport::connection::DuplexConnection::new(client_side)),
            ClientSession::new(),
            BodyCipher::Aes(Aes128Gcm::new(&[0x42u8; 16]).expect("cipher")),
            [0xAAu8; 16],
            Box::new(PlainSizeParser),
            false,
            BodyCipher::Aes(Aes128Gcm::new(&[0x43u8; 16]).expect("cipher")),
            [0xBBu8; 16],
            Box::new(PlainSizeParser),
            false,
        );
        let cap = conn.wpending.capacity();
        assert_eq!(cap, conn.up_chunk_cap + 96, "帧缓冲构造期一次预留");
        for _ in 0..8 {
            conn.write_all(&[7u8; 1200]).await.unwrap();
        }
        assert_eq!(conn.wpending.capacity(), cap, "每包不得重建/扩容帧缓冲");
    }

    /// decode_single_chunk_async：两个 chunk 的 wire 逐次解出两包；干净 EOF = None。
    #[tokio::test]
    async fn decode_single_chunk_packet_boundaries() {
        use std::io::Cursor;

        let cipher = Aes128Gcm::new(&[0x42u8; 16]).expect("cipher");
        let mut nonce = ChunkNonceAdapter::new(&[0xAAu8; 16], 12);
        let mut sp = PlainSizeParser;
        let mut wire = Vec::new();
        crate::encoding::body_chunk::encode_single_chunk(
            &mut wire, b"hello", &cipher, &mut nonce, &mut sp, false,
        )
        .unwrap();
        crate::encoding::body_chunk::encode_single_chunk(
            &mut wire, b"world!!", &cipher, &mut nonce, &mut sp, false,
        )
        .unwrap();

        let mut cur = Cursor::new(wire);
        let mut dec_nonce = ChunkNonceAdapter::new(&[0xAAu8; 16], 12);
        let mut dec_sp = PlainSizeParser;
        let p1 = crate::encoding::body_chunk::decode_single_chunk_async(
            &mut cur,
            &cipher,
            &mut dec_nonce,
            &mut dec_sp,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(p1, b"hello");
        let p2 = crate::encoding::body_chunk::decode_single_chunk_async(
            &mut cur,
            &cipher,
            &mut dec_nonce,
            &mut dec_sp,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(p2, b"world!!");
        let eof = crate::encoding::body_chunk::decode_single_chunk_async(
            &mut cur,
            &cipher,
            &mut dec_nonce,
            &mut dec_sp,
            false,
        )
        .await
        .unwrap();
        assert!(eof.is_none(), "clean EOF must be None");
    }

    /// wire 字节对拍（判别器）：write_one_chunk 输出必须逐字节等于手工
    /// 构成的 `[size_field || seal(data) || padding]`——零拷贝改写不得改 wire。
    #[tokio::test]
    async fn write_one_chunk_wire_parity() {
        let cipher = Aes128Gcm::new(&[0x42u8; 16]).expect("cipher");
        let mut nonce_gen = ChunkNonceGenerator::new(&[0xAAu8; 16], 12);
        let mut sp = PlainSizeParser;
        let mut chunk_buf = Vec::with_capacity(4096);
        let mut out = Vec::new();
        write_one_chunk(
            &mut out,
            b"hello wire",
            &cipher,
            &mut nonce_gen,
            &mut sp,
            false,
            &mut chunk_buf,
        )
        .await
        .expect("write chunk");
        // 参考构成：分配式 seal + size_field 手工拼接
        let mut ref_nonce = ChunkNonceGenerator::new(&[0xAAu8; 16], 12);
        let sealed = cipher.seal(&ref_nonce.next(), &[], b"hello wire").expect("seal");
        let mut expected = vec![0u8; 2];
        sp.encode(u16::try_from(sealed.len()).expect("small"), &mut expected);
        expected.extend_from_slice(&sealed);
        assert_eq!(out, expected, "chunk wire bytes must match manual composition");
    }

    struct CountingWriter {
        buf: Vec<u8>,
        writes: usize,
    }
    impl AsyncWrite for CountingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.writes += 1;
            self.buf.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// 『零中间 Vec + 合并单次写』结构断言：padding 开启时旧实现 3 次
    /// write（size_field/sealed/padding 各一次），新实现必须每 chunk 1 次；
    /// chunk_buf 跨 chunk 复用不扩容（零中间分配的结构性代理断言）。
    #[tokio::test]
    async fn write_one_chunk_single_write_and_buffer_reuse() {
        let cipher = Aes128Gcm::new(&[0x42u8; 16]).expect("cipher");
        let mut nonce_gen = ChunkNonceGenerator::new(&[0xAAu8; 16], 12);
        let mut sp = ShakeSizeParserAdapter::new(&[0x11u8; 16]);
        let cap = PUMP_BUF + 96;
        let mut chunk_buf = Vec::with_capacity(cap);
        let mut w = CountingWriter { buf: Vec::new(), writes: 0 };
        for _ in 0..2 {
            write_one_chunk(
                &mut w,
                b"payload bytes for one chunk",
                &cipher,
                &mut nonce_gen,
                &mut sp,
                true,
                &mut chunk_buf,
            )
            .await
            .expect("write chunk");
        }
        assert_eq!(w.writes, 2, "each chunk must be one write_all (old impl: 3)");
        assert!(chunk_buf.capacity() <= cap, "chunk_buf must be reused without growth");
    }
}
