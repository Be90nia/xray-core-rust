//! VMess outbound → DialBridge 适配器。
//!
//! 把 VMess 协议接入 dispatcher 的 [`DialBridge`]：提供
//! [`make_vmess_dial_fn`] 闭包，内部拨号到 VMess 服务器 →
//! 写 AEAD 加密请求头 → 返回连接。
//!
//! ## 范围
//!
//! VMess over **raw TCP**：请求头 AEAD 加密 + body chunk AEAD 加密。
//! [`make_vmess_dial_fn`] 闭包拨号到 VMess 服务器 → 写 AEAD 请求头 →
//! 返回 [`VmessConn`]（读写两半**直挂** chunk AEAD wire：无 duplex 环、无泵任务；
//! 响应头在读半惰性解码）。transport 层补全后可注入 TLS-wrapped 拨号闭包。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use skeleton_infra::fx::Spawned;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_app_dispatcher::{
    default::DialFn,
    udp_session::{XudpReframer, XudpUnframer},
};
use xray_common::{
    bitmask::Bitmask,
    net::{address::Address, destination::Destination, network::Network, port::Port},
    protocol::{Command, RequestHeader, SecurityType, request_option},
    uuid::UUID,
};
use xray_crypto::aead::{AeadCipher, Aes128Gcm, ChaCha20Poly1305Aead};
use xray_frame::PluginContext;
use xray_transport::connection::Connection;

use crate::{
    account::MemoryAccount,
    encoding::{
        ChunkNonceGenerator, VERSION,
        body_chunk::{
            AEADSizeParserAdapter, ChunkNonceAdapter, PlainSizeParser, ShakeSizeParserAdapter,
            SizeParser, make_authenticated_length_size_parser,
        },
        client::{ClientSession, ResponseHeaderProgress},
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
    /// 实验特性开关（Go `VMessAccount.Experiments` → `Account.TestsEnabled`）。
    ///
    /// Go 用 `strings.Contains` 判两个子串：`AuthenticatedLength`（length 字段
    /// 单独 AEAD 加密）与 `NoTerminationSignal`（不写终止 chunk）。
    pub experiments: String,
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
            experiments: String::new(),
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

    /// 设置实验特性开关（builder 风格）。
    #[must_use]
    pub fn with_experiments(mut self, experiments: impl Into<String>) -> Self {
        self.experiments = experiments.into();
        self
    }

    /// 服务器 Destination（TCP）。
    fn server_destination(&self) -> Destination {
        Destination::new(self.server_address.clone(), self.server_port, Network::TCP)
    }
}

/// 从 JSON 字符串解析 security 类型。
///
/// Go `infra/conf/vmess.go:26`：`switch strings.ToLower(a.Security)`，只认
/// `"aes-128-gcm"` / `"chacha20-poly1305"` / `"auto"`，**其余一律 AUTO**（含
/// 空串与未知名）。`"none"` / `"zero"` 已被 Go 上游移除（v26.7.28）。
fn parse_security(s: &str) -> SecurityType {
    match s.to_lowercase().as_str() {
        "aes-128-gcm" => SecurityType::Aes128Gcm,
        "chacha20-poly1305" => SecurityType::Chacha20Poly1305,
        // "auto" 与未知名同落 Auto（Go `default:` 分支）
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
    // Go infra/conf/vmess.go:42/164：flat 形态取顶层 `experiments`，vnext 形态取
    // `users[].experiments`（本函数扁平化时只搬 id/security/level/email，故回落顶层）。
    let experiments = user
        .get("experiments")
        .and_then(serde_json::Value::as_str)
        .or_else(|| v.get("experiments").and_then(serde_json::Value::as_str))
        .unwrap_or_default()
        .to_string();

    // alterId≠0 = legacy VMess 配置残留。Go `infra/conf/vmess.go:20-24` 的
    // VMessAccount **没有 alterId 字段** ⇒ encoding/json 忽略未知键、配置照常启动
    // （出站 AEAD 握手本就不用 alterId）。这里同口径：只 warn 不拒启——旧 v2rayN
    // 配置普遍带 `"alterId": 64`，拒启等于整出站消失（bd hsrtv）。
    // 数字/字符串形式都认（老配置生成器输出过字符串 alterId）。
    let alter_id = user
        .get("alterId")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok())))
        .unwrap_or(0);
    if alter_id != 0 {
        // id 是客户端凭据（S-11）：只报 alterId，不落 UUID 原文。
        crate::VMESS_LOG
            .warn(format!("vmess outbound: ignoring legacy alterId={alter_id} (AEAD-only)"));
    }
    Ok(VmessOutboundConfig::new(
        uuid,
        Address::Domain(address.to_string()),
        Port::new(u16::try_from(port).map_err(|_| "port out of range")?),
    )
    .with_security(parse_security(security_str))
    .with_level(level)
    .with_email(email)
    .with_experiments(experiments))
}

use std::str::FromStr;

/// 构造 VMess 的 DialFn 闭包。
///
/// 闭包捕获 `Arc<VmessOutboundConfig>`，每次调用：
/// 1. `dial` 到 VMess 服务器 → `Box<dyn Connection>`
/// 2. 解析 security（Auto → 具体算法）+ `encode_request_header` 写 AEAD 加密请求头
/// 3. 返回 [`VmessConn`]：读写两半直挂 chunk AEAD wire，响应头由读半**惰性**解码
///    （服务端把它缓冲到首块下行数据才 flush，dial 阶段同步等待会双向死锁）
///
/// # Panics
///
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_vmess_dial_fn(config: Arc<VmessOutboundConfig>, ctx: Arc<PluginContext>) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let config = Arc::clone(&config);
        let ctx = Arc::clone(&ctx);
        let target_addr = dest.address().clone();
        let target_port = dest.port();
        let is_udp = dest.is_udp();
        Box::pin(async move {
            let server_dest = config.server_destination();
            let sockopt =
                config.stream_settings.as_ref().map(|s| s.socket_options()).unwrap_or_default();
            // UDP 会话目标（socket 面）：wire 不携带回程来源，裹帧时用它。
            let udp_dest = Destination::udp(target_addr.clone(), target_port);
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
            // Go proxy/vmess/outbound/outbound.go:117-119：`AuthenticatedLength` 实验 →
            // 选项位置位（body length 字段改 AEAD 加密）；`NoTerminationSignal` 不进
            // 选项位，只在请求结束时决定是否写终止 chunk（outbound.go:180）。
            let authenticated_length = config.experiments.contains("AuthenticatedLength");
            let no_termination_signal = config.experiments.contains("NoTerminationSignal");
            if authenticated_length {
                option.set(request_option::AUTHENTICATED_LENGTH);
            }
            let mut account = MemoryAccount::new(config.user_uuid.clone()).with_security(security);
            account.authenticated_length_experiment = authenticated_length;
            account.no_termination_signal = no_termination_signal;
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

            // 6. size parser：AUTHENTICATED_LENGTH → AEAD 长度字段（padding 仍来自 CHUNK_MASKING 的
            //    SHAKE 流）；否则 CHUNK_MASKING → Shake（req/resp 各自 IV 播种），否则 Plain。
            let req_size_parser =
                build_size_parser(authenticated_length, use_masking, req_iv, &session, security)
                    .map_err(|e| format!("vmess build request size parser: {e}"))?;
            let resp_size_parser =
                build_size_parser(authenticated_length, use_masking, resp_iv, &session, security)
                    .map_err(|e| format!("vmess build response size parser: {e}"))?;
            // 7. UDP：VmessUdpConn（chunk 即 packet，Go 非 cone 语义——packet 边界必须保持，
            //    按字节流的连接会合并多次 write 破坏边界）；TCP：VmessConn（读写两半直挂 chunk
            //    wire，响应头在读半惰性解码）。
            if is_udp {
                return Ok(Box::new(VmessUdpConn::from_udp_conn(
                    &ctx,
                    conn,
                    udp_dest,
                    session,
                    req_cipher,
                    req_iv,
                    req_size_parser,
                    use_padding,
                    resp_cipher,
                    resp_iv,
                    resp_size_parser,
                    use_padding,
                    !no_termination_signal,
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
                !no_termination_signal,
            )) as Box<dyn Connection>)
        })
    })
}

/// 下行 wire 缓冲预留（与旧泵的 `pending.reserve` 同档）。
const DOWN_RESERVE: usize = 16 * 1024;

/// VMess outbound 连接：读写两半各自直挂 chunk AEAD wire（**删 duplex 中转层**）。
///
/// 旧实现（`tokio::io::duplex` + `pump_up`/`pump_down` 两个 task）：每方向固定多
/// 2 遍中转 memcpy（写进环 + 读出环）+ 一次 task 唤醒，且上行 chunk 边界由泵任务的
/// 读调度决定（与调用方写入节奏脱钩，请求-响应模式下每帧都多一次唤醒）。
///
/// 新实现：
/// - **写半**：明文进单 chunk 容量暂存 → `encode_frame_into` **同步构帧**（与 UDP
///   路径同一份构帧代码）→ 直落 wire；一次 [`AsyncWrite::poll_write`] 出一个 chunk。
/// - **读半**：wire 字节直落 `BytesMut` → 响应头按**已读字节增量解码**（不足即再读，
///   半截响应头是正常中间态）→ chunk `open_in_place` 原地解密 → 交付调用方。
///
/// **wire 不变量**：帧格式 / nonce 序号 / 构帧代码与旧泵同源——`encode_frame_into`
/// 与旧 `write_chunk_frame` 的逐字节一致由 `write_one_chunk_in_place_matches_seal_and_vec_path`
/// 钉死。
pub struct VmessConn {
    wire: Box<dyn Connection>,
    session: ClientSession,
    // ---- 上行 ----
    req_cipher: BodyCipher,
    req_nonce: ChunkNonceGenerator,
    /// Mutex 仅为 `Connection::Sync`（poll 单线程独占，锁无竞争）；
    /// `ShakeSizeParserAdapter` 内部 XofReader 非 Sync，无法裸存。
    req_size_parser: parking_lot::Mutex<Box<dyn SizeParser + Send>>,
    req_padding: bool,
    /// `NoTerminationSignal` 实验：关闭时不写终止 chunk。
    termination_signal: bool,
    /// 单 chunk 明文容量（构帧预算，与 UDP 路径同源）。
    up_cap: usize,
    /// 上行明文暂存。
    stage: Vec<u8>,
    /// 待落线帧与其游标。
    frame: Vec<u8>,
    frame_pos: usize,
    /// 终止 chunk 已构帧（重入 `poll_shutdown` 不再重复取 nonce）。
    up_done: bool,
    // ---- 下行 ----
    resp_cipher: BodyCipher,
    resp_nonce: ChunkNonceGenerator,
    resp_size_parser: parking_lot::Mutex<Box<dyn SizeParser + Send>>,
    resp_padding: bool,
    /// 未解帧的 wire 字节（`split_to` 切帧为 O(1)）。
    pending: BytesMut,
    /// 已解出的明文待交付（chunk 大于调用方缓冲时保留余量）。
    plain: Bytes,
    /// 响应头已解完。
    hdr_done: bool,
    /// 已解出 size 字段、等帧体到齐时的 `(总长, padding)`。
    ///
    /// SHAKE128 流是**有状态**的（`next_padding_len` → `decode` 各推进一次），
    /// 帧体未到齐时不得重算，否则流位置漂移、后续 chunk 全错。
    chunk_hdr: Option<(usize, usize)>,
    /// 下行结束（终止 chunk / EOF / 解密失败）。
    down_done: bool,
}

impl VmessConn {
    /// 从已写完请求头的底层连接构造（响应头由读半惰性解码）。
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
        termination_signal: bool,
    ) -> Self {
        let up_cap = crate::encoding::body_chunk::single_chunk_capacity(
            &req_cipher,
            req_size_parser.as_ref(),
        );
        Self {
            wire: conn,
            session,
            req_cipher,
            req_nonce: ChunkNonceGenerator::new(&req_iv, 12),
            req_size_parser: parking_lot::Mutex::new(req_size_parser),
            req_padding,
            termination_signal,
            up_cap,
            stage: Vec::with_capacity(up_cap),
            frame: Vec::with_capacity(up_cap + 96),
            frame_pos: 0,
            up_done: false,
            resp_cipher,
            resp_nonce: ChunkNonceGenerator::new(&resp_iv, 12),
            resp_size_parser: parking_lot::Mutex::new(resp_size_parser),
            resp_padding,
            pending: BytesMut::new(),
            plain: Bytes::new(),
            hdr_done: false,
            chunk_hdr: None,
            down_done: false,
        }
    }

    /// 把暂存明文（或终止 chunk 的空载荷）构帧进 `frame`。
    fn seal_frame(&mut self, termination: bool) -> std::io::Result<()> {
        let Self { frame, stage, req_cipher, req_nonce, req_size_parser, req_padding, .. } = self;
        let data: &[u8] = if termination { &[] } else { &stage[..stage.len().min(self.up_cap)] };
        let nonce = req_nonce.next_ref();
        encode_frame_into(
            frame,
            data,
            req_cipher,
            nonce,
            req_size_parser.get_mut().as_mut(),
            *req_padding,
        )?;
        self.frame_pos = 0;
        self.stage.clear();
        Ok(())
    }

    /// 推进待落线帧。`Pending` = wire 未就绪（帧留存，后续 poll 续推）。
    fn poll_out(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.frame_pos < self.frame.len() {
            let n = std::task::ready!(
                Pin::new(&mut self.wire).poll_write(cx, &self.frame[self.frame_pos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
            }
            self.frame_pos += n;
        }
        if !self.frame.is_empty() {
            self.frame.clear();
            self.frame_pos = 0;
        }
        Poll::Ready(Ok(()))
    }

    /// 响应头增量解码：返回「本轮是否有进展」（不足 = false，继续读）。
    fn try_decode_header(&mut self) -> std::io::Result<bool> {
        match self.session.decode_response_header_from_buf(&self.pending) {
            Ok(ResponseHeaderProgress::Need(_)) => Ok(false),
            Ok(ResponseHeaderProgress::Done(_header, used)) => {
                self.pending.advance(used);
                self.hdr_done = true;
                Ok(true)
            },
            Err(e) => {
                crate::VMESS_LOG.debug(format!("vmess decode response header failed error={e}"));
                self.down_done = true;
                Ok(false)
            },
        }
    }

    /// 响应 body chunk 增量解码：整帧到齐才推进 nonce；不足返回 false。
    fn try_decode_chunk(&mut self) -> std::io::Result<bool> {
        let Self { resp_cipher, resp_nonce, resp_size_parser, resp_padding, pending, .. } = self;
        let sp = resp_size_parser.get_mut();
        let sb = sp.size_bytes();
        let (total, padding) = match self.chunk_hdr {
            Some(v) => v,
            None => {
                if pending.len() < sb {
                    return Ok(false);
                }
                // SHAKE128 流消费顺序：next_padding_len → decode（与 encode 侧对称）
                let padding = if *resp_padding { usize::from(sp.next_padding_len()) } else { 0 };
                let total = usize::from(sp.decode(&pending[..sb]));
                if total == 0 {
                    // 兼容 Go AuthenticationReader 的 size==0 → EOF 语义
                    self.down_done = true;
                    return Ok(true);
                }
                self.chunk_hdr = Some((total, padding));
                (total, padding)
            },
        };
        if pending.len() < sb + total {
            return Ok(false);
        }
        // 整帧切出（size 段 + 密文‖tag + padding），wire 缓冲 O(1) 前移
        let mut blob = pending.split_to(sb + total);
        // 恶意/错乱 padding > total 时不得下溢（与 ChunkReader 同口径）
        let cipher_len = total.saturating_sub(padding);
        let nonce = resp_nonce.next_ref();
        let plaintext_len =
            match resp_cipher.open_in_place(nonce, &[], &mut blob[sb..sb + cipher_len]) {
                Ok(pt) => pt.len(),
                Err(e) => {
                    crate::VMESS_LOG.debug(format!("vmess down body chunk open failed error={e}"));
                    self.down_done = true;
                    return Ok(true);
                },
            };
        self.chunk_hdr = None;
        if plaintext_len == 0 {
            // 终止 chunk（seal([])）→ 响应 body 结束
            self.down_done = true;
            return Ok(true);
        }
        blob.advance(sb);
        let mut plain = blob.freeze();
        plain.truncate(plaintext_len); // 丢弃尾部 padding
        self.plain = plain;
        Ok(true)
    }
}

impl AsyncRead for VmessConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        // 写半顺带推进：下行等响应期间上行帧不能停在暂存里（旧泵两 task 并发同效）
        if let Poll::Ready(Err(e)) = me.poll_out(cx) {
            return Poll::Ready(Err(e));
        }
        loop {
            // ① 已解出的明文交付（chunk 大于调用方缓冲时保留余量）
            if !me.plain.is_empty() {
                let n = me.plain.len().min(buf.remaining());
                buf.put_slice(&me.plain[..n]);
                me.plain.advance(n);
                return Poll::Ready(Ok(()));
            }
            if me.down_done {
                return Poll::Ready(Ok(())); // EOF
            }
            // ② 增量解帧（响应头 → body chunk）
            let progressed =
                if me.hdr_done { me.try_decode_chunk()? } else { me.try_decode_header()? };
            if progressed || me.down_done {
                continue;
            }
            // ③ 需要更多 wire 字节：直读进 pending 的 spare 区（零中转拷贝）
            me.pending.reserve(DOWN_RESERVE);
            let n = {
                let spare = me.pending.spare_capacity_mut();
                let mut rb = ReadBuf::uninit(spare);
                match Pin::new(&mut me.wire).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => rb.filled().len(),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            };
            if n == 0 {
                me.down_done = true;
                return Poll::Ready(Ok(()));
            }
            // SAFETY: 刚由底层读入 `n` 个已初始化字节到 pending 的 spare 区，
            // `n ≤ spare.len()`，写入范围与已初始化范围严格一致。
            unsafe { me.pending.advance_mut(n) };
        }
    }
}

impl AsyncWrite for VmessConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        // ① 待落线帧先冲刷（wire 未就绪 → 背压，未消费任何明文）
        std::task::ready!(me.poll_out(cx))?;
        // ② 明文进暂存 → 构帧（一次 poll_write 一个 chunk，对齐 Go AuthenticationWriter）
        let n = buf.len().min(me.up_cap.saturating_sub(me.stage.len()));
        me.stage.extend_from_slice(&buf[..n]);
        if n > 0 {
            if let Err(e) = me.seal_frame(false) {
                return Poll::Ready(Err(std::io::Error::other(format!("vmess chunk frame: {e}"))));
            }
            // ③ 立刻落线（wire Pending 时帧留存，后续 poll_read/poll_write 续推）
            if let Poll::Ready(Err(e)) = me.poll_out(cx) {
                return Poll::Ready(Err(e));
            }
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::task::ready!(me.poll_out(cx))?;
        Pin::new(&mut me.wire).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        // 终止 chunk（seal([])）：服务端 decode 看到空明文即请求 body 结束；
        // `NoTerminationSignal` 实验时省略，靠连接关闭让服务端识别流结束。
        if !me.up_done {
            me.up_done = true;
            if me.termination_signal {
                me.seal_frame(true)
                    .map_err(|e| std::io::Error::other(format!("vmess termination: {e}")))?;
            }
        }
        std::task::ready!(me.poll_out(cx))?;
        std::task::ready!(Pin::new(&mut me.wire).poll_flush(cx))?;
        Pin::new(&mut me.wire).poll_shutdown(cx)
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
/// 上行：每次 [`AsyncWrite::poll_write`] 把传入 buf 按 XUDP 帧切成裸载荷，
/// 每包编码为**恰好一个** chunk（AEAD seal，见
/// [`crate::encoding::body_chunk::encode_single_chunk`]）直写底层连接——按字节流的
/// [`VmessConn`] 会合并多次 write 破坏 packet 边界，故 UDP 不走它的读写两半。
/// 下行：spawn task 惰性解响应头后逐 chunk 解密，包经 mpsc 队列交付，
/// [`AsyncRead::poll_read`] 每次返回一个 packet（裹回 XUDP 帧）。
///
/// **两套表示**（bd t0ls1）：内部 dispatch link 跑 XUDP 帧（自带 per-packet
/// 目标 + GlobalID），VMess wire 跑裸载荷 chunk（目标在请求头）。
struct VmessUdpConn {
    inner_w: tokio::io::WriteHalf<Box<dyn Connection>>,
    rx: tokio::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
    up_nonce: ChunkNonceGenerator,
    req_cipher: BodyCipher,
    /// Mutex 仅为 Connection::Sync（poll_write 单线程独占，锁无竞争）；
    /// ShakeSizeParserAdapter 内部 XofReader 非 Sync，无法裸存。
    req_size_parser: parking_lot::Mutex<Box<dyn SizeParser + Send>>,
    req_padding: bool,
    /// `NoTerminationSignal` 实验：关闭时不写终止 chunk。
    termination_signal: bool,
    /// 单 chunk 明文容量上限（packet 超限截断；UDP relay 实际包 ≤ MTU）
    up_chunk_cap: usize,
    /// 上行剥帧：XUDP 帧流 → 裸载荷
    unframer: XudpUnframer,
    /// 下行裹帧：裸载荷 → XUDP 帧流
    reframer: XudpReframer,
    /// 本轮 poll_write 已收下的字节数（返回 Pending 后重入不再重复喂）
    fed: usize,
    /// 待发的 XUDP 帧头（meta + 2B 载荷长度）
    hdr: Vec<u8>,
    hpos: usize,
    /// 待交付的下行载荷与其游标（帧头先行）
    rpay: Vec<u8>,
    rpos: usize,
    wpending: Vec<u8>,
    wpos: usize,
    _down_task: Spawned<()>,
}

impl VmessUdpConn {
    /// 从底层连接构造 UDP 模式连接（响应头由 down task 惰性解码）。
    #[allow(clippy::too_many_arguments)] // 与 Go dial 参数集一一对应
    fn from_udp_conn(
        ctx: &PluginContext,
        conn: Box<dyn Connection>,
        dest: Destination,
        session: ClientSession,
        req_cipher: BodyCipher,
        req_iv: [u8; 16],
        req_size_parser: Box<dyn SizeParser + Send>,
        req_padding: bool,
        resp_cipher: BodyCipher,
        resp_iv: [u8; 16],
        mut resp_size_parser: Box<dyn SizeParser + Send>,
        resp_padding: bool,
        termination_signal: bool,
    ) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let (stream_r, stream_w) = tokio::io::split(conn);
        let up_chunk_cap = crate::encoding::body_chunk::single_chunk_capacity(
            &req_cipher,
            req_size_parser.as_ref(),
        );
        // for_plugin/装配根 scope 均不 close——闸关态=装配 bug，fail-visible。
        let down_task = ctx
            .spawn(async move {
                let mut sr = stream_r;
                // 响应头惰性解码（Go SetFlushNext：首块下行才 flush，dial 阶段同步
                // 等待会造成双向死锁——与 VmessConn 同语义）。
                if let Err(e) = session.decode_response_header_async(&mut sr).await {
                    crate::VMESS_LOG
                        .debug(format!("vmess udp decode response header failed error={e}"));
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
            })
            .expect("plugin ctx FxScope is never closed (assembly-owned)");
        Self {
            inner_w: stream_w,
            rx,
            up_nonce: ChunkNonceGenerator::new(&req_iv, 12),
            req_cipher,
            req_size_parser: parking_lot::Mutex::new(req_size_parser),
            req_padding,
            termination_signal,
            up_chunk_cap,
            unframer: XudpUnframer::new(),
            reframer: XudpReframer::new(dest),
            fed: 0,
            hdr: Vec::with_capacity(64),
            hpos: 0,
            rpay: Vec::new(),
            rpos: 0,
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
        // 上一轮已收下 buf（Pending 重入）→ 只排干，不再重复喂
        if this.fed == 0 {
            let fed = buf.len();
            let cap = this.up_chunk_cap;
            let mut framed = std::mem::take(&mut this.wpending);
            framed.clear();
            this.wpos = 0;
            let mut encode_err: Option<std::io::Error> = None;
            let parse_err = {
                let Self { unframer, req_cipher, req_size_parser, req_padding, up_nonce, .. } =
                    this;
                unframer
                    .feed(buf, |_, payload| {
                        if encode_err.is_some() {
                            return;
                        }
                        // 一包一 chunk：与 TCP 泵同款持久缓冲 + next_ref + seal_into
                        // （稳态零分配）。超 chunk 容量时截断（UDP 实际包 ≤ MTU）。
                        let payload = &payload[..payload.len().min(cap)];
                        let nonce = up_nonce.next_ref();
                        if let Err(e) = encode_frame_into(
                            &mut framed,
                            payload,
                            req_cipher,
                            nonce,
                            req_size_parser.lock().as_mut(),
                            *req_padding,
                        ) {
                            encode_err =
                                Some(std::io::Error::other(format!("vmess udp encode: {e}")));
                        }
                    })
                    .err()
            };
            this.wpending = framed;
            if let Some(e) = encode_err {
                return Poll::Ready(Err(e));
            }
            if let Some(e) = parse_err {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("vmess udp: XUDP 帧解析: {e}"),
                )));
            }
            this.fed = fed;
        }
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
        let fed = this.fed;
        this.fed = 0;
        this.wpending.clear();
        this.wpos = 0;
        Poll::Ready(Ok(fed))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner_w).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self.get_mut();
        // 写终止 chunk（seal([])）——服务端 decode 看到空明文即流结束；
        // `NoTerminationSignal` 实验时省略（Go outbound.go:180）。
        if this.termination_signal && this.wpos >= this.wpending.len() {
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
    // 每轮循环只交付一段（帧头 → 载荷），迭代由调用方 relay 驱动
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 1) 待发的 XUDP 帧头优先（帧头必须排在载荷之前）
            if this.hpos < this.hdr.len() {
                let n = (this.hdr.len() - this.hpos).min(buf.remaining());
                buf.put_slice(&this.hdr[this.hpos..this.hpos + n]);
                this.hpos += n;
                return Poll::Ready(Ok(()));
            }
            // 2) 当前 packet 载荷未交付完 → 交付剩余（不截断数据报）
            if this.rpos < this.rpay.len() {
                let n = (this.rpay.len() - this.rpos).min(buf.remaining());
                buf.put_slice(&this.rpay[this.rpos..this.rpos + n]);
                this.rpos += n;
                return Poll::Ready(Ok(()));
            }
            // 3) 取下一个 packet 并裹 XUDP 帧头
            match std::task::ready!(this.rx.poll_recv(cx)) {
                Some(Ok(pkt)) => {
                    // 空载荷帧会让下游 PacketReader 判流结束，直接跳过
                    if pkt.is_empty() {
                        continue;
                    }
                    let mut hdr = std::mem::take(&mut this.hdr);
                    let res = this.reframer.write_header(pkt.len(), None, &mut hdr);
                    this.hdr = hdr;
                    this.hpos = 0;
                    if let Err(e) = res {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("vmess udp: XUDP 应答帧头: {e}"),
                        )));
                    }
                    this.rpay = pkt;
                    this.rpos = 0;
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

/// 构造一个方向的 chunk size parser（对齐 Go `encoding/client.go:120-127` 的
/// `EncodeRequestBody` / `:239-246` 的 `DecodeResponseBody`）。
///
/// Go 在 `switch request.Security` 之前就按 `CHUNK_MASKING` 选出 padding 生成器
/// （Shake），`AUTHENTICATED_LENGTH` 只把 `sizeParser` 变量换成 AEAD 解析器——
/// 长度流与 padding 流是两条独立流，故这里也分开持有。
fn build_size_parser(
    authenticated_length: bool,
    masking: bool,
    direction_iv: [u8; 16],
    session: &ClientSession,
    security: SecurityType,
) -> Result<Box<dyn SizeParser + Send>, VmessError> {
    if !authenticated_length {
        return Ok(if masking {
            Box::new(ShakeSizeParserAdapter::new(&direction_iv)) as Box<dyn SizeParser + Send>
        } else {
            Box::new(PlainSizeParser) as Box<dyn SizeParser + Send>
        });
    }
    Ok(Box::new(AuthLenSizeParser {
        // 请求/响应两个方向都从 request_body_key/iv 派生（Go 端同）
        len: make_authenticated_length_size_parser(
            &session.request_body_key,
            &session.request_body_iv,
            security,
        )?,
        padding: masking.then(|| ShakeSizeParserAdapter::new(&direction_iv)),
    }))
}

/// `AUTHENTICATED_LENGTH` 实验的 size parser：长度字段走 AEAD（Go
/// `NewAEADSizeParser`），padding 长度仍取自 CHUNK_MASKING 的 SHAKE 流。
struct AuthLenSizeParser {
    len: AEADSizeParserAdapter,
    padding: Option<ShakeSizeParserAdapter>,
}

impl SizeParser for AuthLenSizeParser {
    fn size_bytes(&self) -> usize {
        self.len.size_bytes()
    }

    fn encode(&mut self, size: u16, out: &mut [u8]) {
        self.len.encode(size, out);
    }

    fn decode(&mut self, input: &[u8]) -> u16 {
        self.len.decode(input)
    }

    fn next_padding_len(&mut self) -> u16 {
        self.padding.as_mut().map_or(0, SizeParser::next_padding_len)
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

    /// 原地 seal（数据面上行热路径）：不覆写则落到 trait 默认实现 seal+split，
    /// 会静默把载荷再搬一遍。
    fn seal_in_place_with_tag(
        &self,
        nonce: &[u8],
        aad: &[u8],
        payload: &mut [u8],
        tag: &mut [std::mem::MaybeUninit<u8>],
    ) -> Result<(), xray_crypto::aead::CryptoError> {
        match self {
            BodyCipher::Aes(c) => c.seal_in_place_with_tag(nonce, aad, payload, tag),
            BodyCipher::Chacha(c) => c.seal_in_place_with_tag(nonce, aad, payload, tag),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::body_chunk::{ChunkFrame, write_chunk_frame};

    /// 单 chunk 读窗上限（与 body_chunk `DEFAULT_PAYLOAD_SIZE` 对齐）。
    const PUMP_BUF: usize = 8192;

    fn test_ctx() -> Arc<PluginContext> {
        Arc::new(PluginContext::for_plugin("vmess"))
    }

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
        let dial_fn = make_vmess_dial_fn(cfg, test_ctx());
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
        let _dial = make_vmess_dial_fn(Arc::clone(&cfg), test_ctx());
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

    /// bd hsrtv：`alterId` 是 Go 侧根本不存在的键（`infra/conf/vmess.go:20-24` 的
    /// VMessAccount 无该字段 ⇒ encoding/json 忽略未知键），配置照常装配。
    /// 旧断言钉住的是「整出站拒启」，与 Go 相反。
    #[test]
    fn parse_vmess_config_alter_id_nonzero_ignored() {
        let data = r#"{
            "vnext": [{
                "address": "server.example.com",
                "port": 8443,
                "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "alterId": 64 }]
            }]
        }"#;
        let cfg = parse_vmess_config(data.as_bytes()).expect("alterId≠0 不得拒启（Go 忽略未知键）");
        assert_eq!(cfg.user_uuid.to_string(), "b831381d-6324-4d53-ad4f-8cda48b30811");
    }

    /// 老配置生成器（v2rayN 等）会输出字符串形式 alterId，同样只 warn 不拒启。
    #[test]
    fn parse_vmess_config_alter_id_string_ignored() {
        let data = r#"{
            "vnext": [{
                "address": "server.example.com",
                "port": 8443,
                "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "alterId": "64" }]
            }]
        }"#;
        assert!(
            parse_vmess_config(data.as_bytes()).is_ok(),
            "字符串 alterId 不得拒启（Go 忽略未知键）"
        );
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
        let dial = make_vmess_dial_fn(Arc::clone(&cfg), test_ctx());
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

    /// 响应头**分两段到达**（第一段 < 18B 长度段）时，直挂读半不得报错/丢字节：
    /// 半截响应头是 Go `SetFlushNext` 的正常中间态，必须等第二段到达后正常解出，
    /// 随后的 body chunk 也要照常解密交付。
    #[tokio::test]
    async fn response_header_arriving_in_two_pieces_still_decodes() {
        use xray_common::protocol::ResponseHeader;

        use crate::{
            encoding::server::{ServerSession, SessionHistory},
            validator::{MemoryUser, TimedUserValidator, Validator},
        };

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let server_port = listener.local_addr().unwrap().port();

        #[allow(
            clippy::disallowed_methods,
            reason = "测试脚手架起阻塞 OS 线程持 accept（半截响应头时序回归探针）；无 PluginContext 可穿，按 clippy.toml 指引逐处登记"
        )]
        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};
            let (mut sock, _) = listener.accept().expect("accept");
            let uuid = UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("uuid");
            let validator = TimedUserValidator::new();
            validator
                .add(MemoryUser::new("t@example.com", MemoryAccount::new(uuid)))
                .expect("add user");
            let history = SessionHistory::new();
            let mut server = ServerSession::new(&validator, &history);
            let (req, _) = server.decode_request_header(&mut sock).expect("decode header");
            let resp = ResponseHeader::new(Command::Tcp);
            let mut head: Vec<u8> = Vec::new();
            server.encode_response_header(&resp, &mut head).expect("encode response header");
            let mut body: Vec<u8> = Vec::new();
            server.encode_response_body(&req, b"pong", &mut body).expect("encode body");
            // 第一段：只发 10B（< 18B 长度段）后停顿，迫使客户端读半停在半截响应头
            sock.write_all(&head[..10]).expect("write head part 1");
            sock.flush().expect("flush part 1");
            std::thread::sleep(std::time::Duration::from_millis(50));
            sock.write_all(&head[10..]).expect("write head part 2");
            sock.write_all(&body).expect("write body");
            sock.flush().expect("flush part 2");
            let mut b = [0u8; 1];
            let _ = sock.read(&mut b);
        });

        let uuid = UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("uuid");
        let cfg = Arc::new(VmessOutboundConfig::new(
            uuid,
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(server_port),
        ));
        let dial = make_vmess_dial_fn(cfg, test_ctx());
        let dest =
            Destination::new(Address::from_ipv4_bytes([127, 0, 0, 1]), Port::new(1), Network::TCP);
        let mut conn = dial(&dest).await.expect("dial");

        use tokio::io::AsyncReadExt;
        let mut got = [0u8; 4];
        tokio::time::timeout(std::time::Duration::from_secs(5), conn.read_exact(&mut got))
            .await
            .expect("半截响应头不得让读半挂死")
            .expect("read pong");
        assert_eq!(&got, b"pong", "响应头两段后 body chunk 必须正常解密");
    }

    /// 构造一帧 XUDP（link 侧表示；vmess crate 不依赖 xray-xudp，手拼线格式）：
    /// `[2B meta_len][2B session][1B status][1B opt][1B net][2B port][atyp][addr]
    /// [?8B gid][2B len][payload]`。
    fn xudp_frame(payload: &[u8], first: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // session id
        body.push(if first { 1 } else { 2 }); // status: New / Keep
        body.push(1); // opt = Data
        body.push(2); // network = UDP
        body.extend_from_slice(&53u16.to_be_bytes()); // port（PortThenAddress）
        body.push(1); // atyp = IPv4
        body.extend_from_slice(&[8, 8, 8, 8]);
        if first {
            body.extend_from_slice(&[3u8; 8]); // GlobalID（仅 New）
        }
        let mut f = Vec::new();
        f.extend_from_slice(&(body.len() as u16).to_be_bytes());
        f.extend_from_slice(&body);
        f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn udp_dest() -> Destination {
        Destination::new(Address::from_ipv4_bytes([8, 8, 8, 8]), Port::new(53), Network::UDP)
    }

    /// vmess UDP（bd uhg2 / t0ls1）：link 侧 XUDP 帧按包剥帧，一包一 chunk。
    /// server 侧逐 chunk 解出恰好两包（裸载荷，不含 XUDP 帧头）。
    #[tokio::test]
    async fn vmess_udp_conn_write_boundaries() {
        use tokio::io::AsyncWriteExt;

        let (client_side, mut server_side) = tokio::io::duplex(16384);
        let mut conn = VmessUdpConn::from_udp_conn(
            &test_ctx(),
            Box::new(xray_transport::connection::DuplexConnection::new(client_side)),
            udp_dest(),
            ClientSession::new(),
            BodyCipher::Aes(Aes128Gcm::new(&[0x42u8; 16]).expect("cipher")),
            [0xAAu8; 16],
            Box::new(PlainSizeParser),
            false,
            BodyCipher::Aes(Aes128Gcm::new(&[0x43u8; 16]).expect("cipher")),
            [0xBBu8; 16],
            Box::new(PlainSizeParser),
            false,
            true,
        );

        conn.write_all(&xudp_frame(b"ping", true)).await.unwrap();
        conn.write_all(&xudp_frame(&[9u8; 600], false)).await.unwrap();
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
            &test_ctx(),
            Box::new(xray_transport::connection::DuplexConnection::new(client_side)),
            udp_dest(),
            ClientSession::new(),
            BodyCipher::Aes(Aes128Gcm::new(&[0x42u8; 16]).expect("cipher")),
            [0xAAu8; 16],
            Box::new(PlainSizeParser),
            false,
            BodyCipher::Aes(Aes128Gcm::new(&[0x43u8; 16]).expect("cipher")),
            [0xBBu8; 16],
            Box::new(PlainSizeParser),
            false,
            true,
        );
        let cap = conn.wpending.capacity();
        assert_eq!(cap, conn.up_chunk_cap + 96, "帧缓冲构造期一次预留");
        for _ in 0..8 {
            conn.write_all(&xudp_frame(&[7u8; 1200], false)).await.unwrap();
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

    /// wire 字节对拍（判别器）：原地 seal 装帧输出必须逐字节等于手工构成的
    /// `[size_field || seal(data) || padding]`——零拷贝改写不得改 wire。
    #[tokio::test]
    async fn write_one_chunk_wire_parity() {
        let cipher = Aes128Gcm::new(&[0x42u8; 16]).expect("cipher");
        let mut nonce_gen = ChunkNonceGenerator::new(&[0xAAu8; 16], 12);
        let mut sp = PlainSizeParser;
        let mut frame = ChunkFrame::new(2);
        frame.write_plaintext(b"hello wire");
        let mut out = Vec::new();
        write_chunk_frame(&mut out, &mut frame, 10, &cipher, nonce_gen.next_ref(), &mut sp, false)
            .await
            .expect("write chunk");
        // 参考构成：分配式 seal + size_field 手工拼接
        let mut ref_nonce = ChunkNonceGenerator::new(&[0xAAu8; 16], 12);
        let sealed = cipher.seal(ref_nonce.next_ref(), &[], b"hello wire").expect("seal");
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

        // 裸 TCP 形态：底层支持 vectored ⇒ 一帧（size/密文/padding）一次 syscall 交付
        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            self.writes += 1;
            let mut total = 0;
            for b in bufs {
                self.buf.extend_from_slice(b);
                total += b.len();
            }
            Poll::Ready(Ok(total))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// 『原地密封 + 一次向量写』结构断言：padding 开启时一帧是 3 段
    /// （size_field / 密文‖tag / padding），仍须 1 次 `poll_write_vectored`；
    /// 装帧块跨 chunk 复用不扩容（零中间分配的结构性代理断言）。
    #[tokio::test]
    async fn write_one_chunk_single_write_and_buffer_reuse() {
        let cipher = Aes128Gcm::new(&[0x42u8; 16]).expect("cipher");
        let mut nonce_gen = ChunkNonceGenerator::new(&[0xAAu8; 16], 12);
        let mut sp = ShakeSizeParserAdapter::new(&[0x11u8; 16]);
        let mut frame = ChunkFrame::new(2);
        let cap = frame.plaintext_max(cipher.tag_size());
        let mut w = CountingWriter { buf: Vec::new(), writes: 0 };
        let pt = b"payload bytes for one chunk";
        for _ in 0..2 {
            frame.clear();
            frame.write_plaintext(pt);
            write_chunk_frame(
                &mut w,
                &mut frame,
                pt.len(),
                &cipher,
                nonce_gen.next_ref(),
                &mut sp,
                true,
            )
            .await
            .expect("write chunk");
        }
        assert_eq!(w.writes, 2, "each chunk must be one vectored write (3 segments)");
        frame.clear(); // 与泵一致：每帧先 clear 再取读区
        assert_eq!(
            frame.plaintext_max(cipher.tag_size()),
            cap,
            "frame block must be reused without growth"
        );
        assert!(!w.buf.is_empty());
    }

    /// size parser 三态：Plain（默认）/ Shake（CHUNK_MASKING）/ AEAD（AuthenticatedLength）。
    #[derive(Clone, Copy)]
    enum SpKind {
        Plain,
        Shake,
        AeadLen,
    }

    impl SpKind {
        fn make(self) -> Box<dyn SizeParser + Send> {
            match self {
                SpKind::Plain => Box::new(PlainSizeParser),
                SpKind::Shake => Box::new(ShakeSizeParserAdapter::new(&[0x11u8; 16])),
                SpKind::AeadLen => Box::new(
                    make_authenticated_length_size_parser(
                        &[0x22u8; 16],
                        &[0x33u8; 16],
                        SecurityType::Aes128Gcm,
                    )
                    .expect("aead length parser"),
                ),
            }
        }
    }

    /// wire 三路对拍（判别器）：同一 plaintext+nonce 下
    /// ① UDP 路径 `encode_frame_into`（Vec 构帧 + 分配式 seal）
    /// ② TCP 路径 `write_chunk_frame`（原地 seal + 2~3 段写）
    /// ③ 手工 `cipher.seal()` 构成 `[size_field][sealed][padding]`
    /// 三者逐字节相同 ⇒ 原地零拷贝改写没改 wire，两条构帧路径也没漂移。
    #[tokio::test]
    async fn write_one_chunk_in_place_matches_seal_and_vec_path() {
        let aes = Aes128Gcm::new(&[0x42u8; 16]).expect("aes");
        let chacha = ChaCha20Poly1305Aead::new(&[0x11u8; 32]).expect("chacha");
        let ciphers: [(&str, &dyn AeadCipher); 2] = [("aes128gcm", &aes), ("chacha20", &chacha)];
        // 空（终止 chunk 形态）/ 小载荷 / 读区上界（块容量 − 帧头预留 − tag）
        // 帧头预留宽度随 size parser 变（Plain/Shake 2B、AuthenticatedLength 18B），
        // 取最宽的 18 ⇒ 三档都能装到下界（AEAD 档正好卡在上界）。
        let payloads: [&[u8]; 3] = [b"", b"hello wire", &[0x5Au8; PUMP_BUF - 18 - 16]];
        for (name, cipher) in ciphers {
            for kind in [SpKind::Plain, SpKind::Shake, SpKind::AeadLen] {
                for pt in payloads {
                    assert_wire_triplet(name, cipher, pt, kind, false).await;
                }
                assert_wire_triplet(name, cipher, b"padded chunk", kind, true).await;
            }
        }
    }

    async fn assert_wire_triplet(
        name: &str,
        cipher: &dyn AeadCipher,
        pt: &[u8],
        kind: SpKind,
        global_padding: bool,
    ) {
        let nonce = [0x3Cu8; 12];

        // ① UDP 路径：Vec 构帧
        let mut vec_frame = Vec::with_capacity(pt.len() + 160);
        encode_frame_into(&mut vec_frame, pt, cipher, &nonce, kind.make().as_mut(), global_padding)
            .expect("vec 构帧");

        // ② TCP 路径：原地 seal + 单缓冲写（无 padding）/ 2 段写（padding 档）
        let mut frame = ChunkFrame::new(kind.make().size_bytes());
        frame.write_plaintext(pt);
        let mut sink = CountingWriter { buf: Vec::new(), writes: 0 };
        write_chunk_frame(
            &mut sink,
            &mut frame,
            pt.len(),
            cipher,
            &nonce,
            kind.make().as_mut(),
            global_padding,
        )
        .await
        .expect("原地密封装帧");
        let got = &sink.buf;

        // ③ 手工参考：seal() + [size][sealed]（padding 长度同序取自 SHAKE128 流）
        let mut sp = kind.make();
        let sb = sp.size_bytes();
        let padding = if global_padding { usize::from(sp.next_padding_len()) } else { 0 };
        let sealed = cipher.seal(&nonce, &[], pt).expect("seal");
        let mut want = vec![0u8; sb];
        sp.encode(u16::try_from(sealed.len() + padding).expect("fits u16"), &mut want);
        want.extend_from_slice(&sealed);

        let payload_end = sb + sealed.len();
        assert_eq!(got[..payload_end], want[..], "{name}: size+密文段必须等于 seal() 构成");
        if padding == 0 {
            assert_eq!(got.len(), want.len(), "{name}: 无 padding 帧长");
            assert_eq!(got, &want[..], "{name}: 原地 seal wire 必须等于 seal() 构成");
            assert_eq!(got, &vec_frame[..], "{name}: 两条构帧路径不得漂移");
        } else {
            // padding 是随机字节：只钉长度（SHAKE128 流同源 ⇒ 长度必须一致）
            assert_eq!(got.len(), want.len() + padding, "{name}: 帧长（含 padding）");
            assert_eq!(got[payload_end..].len(), padding, "{name}: padding 段长度");
            assert_eq!(got[..payload_end], vec_frame[..payload_end], "{name}: padding 档前段一致");
            assert_eq!(got.len(), vec_frame.len(), "{name}: padding 档帧长一致");
        }
    }

    /// 41se0：Go `infra/conf/vmess.go:26` 用 `strings.ToLower(a.Security)` 匹配，
    /// 大小写不敏感——`"AES-128-GCM"` 必须命中 AES128_GCM（旧实现精确小写匹配 → Auto）。
    #[test]
    fn parse_security_is_case_insensitive() {
        assert!(matches!(parse_security("AES-128-GCM"), SecurityType::Aes128Gcm));
        assert!(matches!(parse_security("Chacha20-Poly1305"), SecurityType::Chacha20Poly1305));
        assert!(matches!(parse_security("Auto"), SecurityType::Auto));
    }

    /// 41se0：Go switch 只认三值，其余（含臆造的 `@shadowsocks.org` 别名）一律 AUTO。
    #[test]
    fn parse_security_unknown_falls_back_to_auto() {
        for s in
            ["aes-128-gcm@shadowsocks.org", "chacha20-poly1305@shadowsocks.org", "none", "zero", ""]
        {
            assert!(matches!(parse_security(s), SecurityType::Auto), "{s} must map to Auto");
        }
    }

    /// y3t1z：`experiments` 从配置读入（vnext 形态的 `users[].experiments` 与
    /// flat 形态的顶层 `experiments` 都认，Go vmess.go:42/164）。
    #[test]
    fn parse_vmess_config_reads_experiments() {
        let vnext_form = r#"{
            "vnext": [{
                "address": "server.example.com",
                "port": 443,
                "users": [{
                    "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                    "security": "aes-128-gcm",
                    "experiments": "AuthenticatedLength|NoTerminationSignal"
                }]
            }]
        }"#;
        let cfg = parse_vmess_config(vnext_form.as_bytes()).expect("vnext form");
        assert_eq!(cfg.experiments, "AuthenticatedLength|NoTerminationSignal");

        let flat_form = r#"{
            "address": "server.example.com",
            "port": 443,
            "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "security": "AES-128-GCM",
            "experiments": "AuthenticatedLength"
        }"#;
        let cfg = parse_vmess_config(flat_form.as_bytes()).expect("flat form");
        assert_eq!(cfg.experiments, "AuthenticatedLength");
        // 41se0：大小写不敏感
        assert!(matches!(cfg.security, SecurityType::Aes128Gcm));

        let none = r#"{
            "vnext": [{
                "address": "server.example.com",
                "port": 443,
                "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }]
            }]
        }"#;
        assert_eq!(parse_vmess_config(none.as_bytes()).expect("default").experiments, "");
    }

    /// y3t1z：`experiments: "AuthenticatedLength"` 必须落到 wire——
    /// ① 请求头 option 带 `AUTHENTICATED_LENGTH`（Go outbound.go:117-119）；
    /// ② body length 字段真的走 AEAD（服务端用 AEAD size parser 才解得出 payload）。
    #[tokio::test]
    async fn experiments_authenticated_length_reaches_wire() {
        use tokio::net::TcpListener;

        use crate::{
            encoding::{
                body_chunk::{
                    ChunkNonceAdapter, decode_single_chunk_async,
                    make_authenticated_length_size_parser,
                },
                server::{ServerSession, SessionHistory},
            },
            validator::{MemoryUser, TimedUserValidator, Validator},
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let uuid = UUID::new();
        let server_uuid = uuid.clone();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let validator = TimedUserValidator::new();
            validator
                .add(MemoryUser::new("alice@example.com", MemoryAccount::new(server_uuid)))
                .expect("add user");
            let history = SessionHistory::new();
            let mut session = ServerSession::new(&validator, &history);
            let (header, _user) =
                session.decode_request_header_async(&mut sock).await.expect("decode header");
            let mut sp = AuthLenSizeParser {
                len: make_authenticated_length_size_parser(
                    &session.request_body_key,
                    &session.request_body_iv,
                    header.security,
                )
                .expect("aead size parser"),
                // GLOBAL_PADDING 对 AEAD 档恒开（shouldEnablePadding），padding 长度来自
                // CHUNK_MASKING 的 SHAKE 流（req IV 播种）——解块前必须先消费它。
                padding: Some(ShakeSizeParserAdapter::new(&session.request_body_iv)),
            };
            let cipher = Aes128Gcm::new(&session.request_body_key).expect("cipher");
            let mut nonce_gen = ChunkNonceAdapter::new(&session.request_body_iv, 12);
            let pkt = decode_single_chunk_async(&mut sock, &cipher, &mut nonce_gen, &mut sp, true)
                .await
                .expect("decode body chunk");
            (header.option, pkt)
        });

        let cfg = Arc::new(
            VmessOutboundConfig::new(
                uuid,
                Address::from_ipv4_bytes([127, 0, 0, 1]),
                Port::new(port),
            )
            .with_security(SecurityType::Aes128Gcm)
            .with_experiments("AuthenticatedLength"),
        );
        let dial = make_vmess_dial_fn(cfg, test_ctx());
        let dest = Destination::tcp(Address::from_ipv4_bytes([127, 0, 0, 1]), Port::new(port));
        let mut conn = dial(&dest).await.expect("dial");
        conn.write_all(b"ping").await.expect("write body");
        conn.flush().await.expect("flush body");

        let (option, pkt) = server.await.expect("server task");
        assert!(
            option.has(request_option::AUTHENTICATED_LENGTH),
            "request header must carry AUTHENTICATED_LENGTH option"
        );
        assert_eq!(pkt.as_deref(), Some(&b"ping"[..]), "AEAD length field must decode");
    }

    /// y3t1z：`NoTerminationSignal` → 上行流结束不写终止 chunk（Go outbound.go:180）。
    /// Plain size parser + 无 padding 时帧长固定：数据帧 = 2 + (5 + 16)，终止帧 = 2 + 16。
    #[tokio::test]
    async fn no_termination_signal_omits_final_empty_chunk() {
        async fn wire_len(termination_signal: bool) -> usize {
            let data_cipher = || BodyCipher::Aes(Aes128Gcm::new(&[0x42u8; 16]).expect("cipher"));
            let wire = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let mut conn = VmessConn::from_conn(
                Box::new(SinkConn(Arc::clone(&wire))),
                ClientSession::new(),
                data_cipher(),
                [0xAAu8; 16],
                Box::new(PlainSizeParser) as Box<dyn SizeParser + Send>,
                false,
                data_cipher(),
                [0x11u8; 16],
                Box::new(PlainSizeParser) as Box<dyn SizeParser + Send>,
                false,
                termination_signal,
            );
            conn.write_all(b"hello").await.expect("write body");
            conn.shutdown().await.expect("shutdown");
            wire.lock().len()
        }
        assert_eq!(wire_len(true).await, 23 + 18, "默认写终止 chunk（2 size + 16 tag）");
        assert_eq!(wire_len(false).await, 23, "NoTerminationSignal 只留数据帧");
    }

    /// 只吞不吐的连接桩（量上行 wire 字节；读侧恒 EOF）。
    struct SinkConn(Arc<parking_lot::Mutex<Vec<u8>>>);

    impl AsyncRead for SinkConn {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for SinkConn {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.0.lock().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Connection for SinkConn {
        fn remote_addr(&self) -> std::io::Result<Option<SocketAddr>> {
            Ok(None)
        }

        fn local_addr(&self) -> std::io::Result<Option<SocketAddr>> {
            Ok(None)
        }
    }
}
