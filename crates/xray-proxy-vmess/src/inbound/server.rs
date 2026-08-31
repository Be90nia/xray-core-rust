//! VMess inbound server：accept TCP → decode_request_header → body chunk pump → dispatch。
//!
//! 对应 Go `app/proxyman/inbound/always.go::handle_connection` +
//! `proxy/vmess/inbound/inbound.go::Process`。最小端到端切片：
//! TCP accept → decode_request_header_async → RequestHeader → Destination →
//! body chunk pump（duplex + 双向 AEAD 加解密）→ `DispatchHandler::dispatch(dest, link)`。
//!
//! 不含：TLS 包装（raw TCP）、UDP/Mux 命令（warn 跳过）、XUDP。

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::net::TcpListener;
use xray_app_dispatcher::default::SimpleOhm;
use xray_app_dispatcher::{DispatchHandler, OutboundHandlerManager, UdpDispatchSession};
use xray_buf::io::{new_reader, new_writer};
use xray_common::protocol::{Command, ResponseCommand, ResponseHeader, SecurityType};
use xray_crypto::aead::{AeadCipher, Aes128Gcm, ChaCha20Poly1305Aead, NoOpAeadCipher};
use xray_transport::link::Link;
use xray_common::net::destination::Destination;

use crate::encoding::server::{ServerSession, SessionHistory};
use crate::encoding::{generate_chacha20poly1305_key, ChunkNonceGenerator};
use crate::encoding::body_chunk::{
    ChunkNonce, ChunkNonceAdapter, PlainSizeParser, ShakeSizeParserAdapter, SizeParser,
    make_authenticated_length_size_parser,
};
use crate::request_option;
use crate::validator::TimedUserValidator;
/// Duplex 缓冲大小（与 chunk payload 上限 8 KiB 对齐，留足一个 chunk 余量）。
const DUPLEX_BUF: usize = 16_384;

/// VMess body 加密枚举：统一 Aes128Gcm / ChaCha20Poly1305 两种安全类型为同一类型，
/// 供 pump 函数泛型使用（避免 `Box<dyn AeadCipher>` 跨 await 的 Send 问题）。
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

/// Pump 单次 read 缓冲（与 body_chunk `DEFAULT_PAYLOAD_SIZE` 对齐）。
const PUMP_BUF: usize = 8192;

/// VMess inbound 服务入口。
///
/// 绑定 `listener` 监听，每个连接 spawn 独立 task：
/// 1. `decode_request_header_async` 解析 VMess 请求头（含 AuthID + AEAD 解密 + 反重放）
/// 2. TCP 命令的 address+port → `Destination`；UDP/Mux warn 跳过
/// 3. `encode_response_header_async` 发送响应头（客户端收到后开始 body 流）
/// 4. body chunk pump：duplex 桥接，客户端→server 方向解密 chunks 为明文交给 dispatch，
///    dispatch 回的明文按 chunk 格式加密发回客户端
///
/// # 参数
/// - `listener`：已绑定的 TCP listener
/// - `ohm`：出站管理器（至少有 default handler）
/// - `validator`：VMess 用户 validator（AuthID → MemoryUser）
///
/// # 错误
/// accept 循环自身错误返回；单个连接错误只 log 不中断循环。
///
/// # 限制
/// 仅支持 `Aes128Gcm` + `Chacha20Poly1305` + `PlainSizeParser`（默认 body 选项）。
/// `AUTHENTICATED_LENGTH` / `CHUNK_MASKING` 选项 warn 后关闭连接（YAGNI）。
pub async fn serve_vmess(
    listener: TcpListener,
    ohm: Arc<SimpleOhm>,
    validator: Arc<TimedUserValidator>,
    tls: Option<Arc<xray_transport::TlsAcceptor>>,
) -> std::io::Result<()> {
    // Go VMess inbound 无 detour 字段（未知 JSON 字段被忽略）：流量一律走默认出站 handler。
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    let history = Arc::new(SessionHistory::new());

    tracing::info!(
        addr = %listener.local_addr()?,
        "vmess inbound listening"
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "vmess accept failed");
                continue;
            }
        };
        let _ = peer;

        let handler = Arc::clone(&handler);
        let validator = Arc::clone(&validator);
        let history = Arc::clone(&history);
        let tls = tls.clone();
        tokio::spawn(async move {
            let result = if let Some(acc) = tls {
                match acc.accept(stream).await {
                    Ok(tls_stream) => handle_connection(tls_stream, &handler, &validator, &history, false).await,
                    Err(e) => { tracing::warn!(error = %e, "vmess TLS accept failed"); return; }
                }
            } else {
                // Go：裸 TCP/Unix 连接认证失败时 drain 防时序指纹；TLS 连接不 drain
                handle_connection(stream, &handler, &validator, &history, true).await
            };
            if let Err(e) = result {
                tracing::debug!(error = %e, "vmess connection ended with error");
            }
        });
    }
}

pub async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    handler: &Arc<dyn DispatchHandler>,
    validator: &Arc<TimedUserValidator>,
    history: &Arc<SessionHistory>,
    is_drain: bool,
) -> std::io::Result<()> {
    let (mut stream_r, mut stream_w) = tokio::io::split(stream);

    // 1. decode VMess 请求头（async：先读 16B auth_id → AEAD 解密 → 解析）
    let mut session = ServerSession::new(validator, history);
    let decoded = session.decode_request_header_async(&mut stream_r).await;
    let (header, _user) = match decoded {
        Ok(v) => v,
        Err(e) => {
            // Go `server.go::DecodeRequestHeader`：认证失败先 AcknowledgeReceive（已读
            // 字节），裸 TCP 连接再读走 drainer 决定的字节数才关闭（防时序指纹）。
            let err = std::io::Error::other(format!("vmess decode header: {e}"));
            if is_drain {
                use xray_common::drain::{BehaviorSeedLimitedDrainer, Drainer as _};
                let drainer =
                    BehaviorSeedLimitedDrainer::new(crate::validator::Validator::behavior_seed(validator.as_ref()) as i64, 16 + 38, 3266, 64);
                drainer.acknowledge_receive(16); // auth_id 已读（AEAD 内部计数不可得，近似）
                // Go 由 SetReadDeadline(handshake timeout) 限制 decode+drain 总时长，对齐 4s
                let _ = tokio::time::timeout(std::time::Duration::from_secs(4), drainer.drain(&mut stream_r)).await;
            }
            return Err(err);
        }
    };

    // 2. TCP/UDP 走完整数据路径；Mux 暂 warn 跳过（zx7 在 xray-core 层另行处理）。
    if header.command == Command::Mux {
        tracing::warn!("vmess mux command not yet supported, closing connection");
        return Ok(());
    }

    // 3. 构造 SizeParser（支持 AUTHENTICATED_LENGTH / CHUNK_MASKING / Plain 三条路径）
    let req_key = session.request_body_key;
    let req_size_parser: Box<dyn SizeParser + Send> = if header
        .option
        .has(request_option::AUTHENTICATED_LENGTH)
    {
        match make_authenticated_length_size_parser(&req_key, &session.request_body_iv, header.security) {
            Ok(sp) => Box::new(sp),
            Err(e) => return Err(std::io::Error::other(format!("vmess auth_len size parser: {e}"))),
        }
    } else if header.option.has(request_option::CHUNK_MASKING) {
        Box::new(ShakeSizeParserAdapter::new(&session.request_body_iv))
    } else {
        Box::new(PlainSizeParser)
    };
    let resp_size_parser: Box<dyn SizeParser + Send> = if header
        .option
        .has(request_option::AUTHENTICATED_LENGTH)
    {
        match make_authenticated_length_size_parser(&req_key, &session.request_body_iv, header.security) {
            Ok(sp) => Box::new(sp),
            Err(e) => return Err(std::io::Error::other(format!("vmess auth_len size parser: {e}"))),
        }
    } else if header.option.has(request_option::CHUNK_MASKING) {
        Box::new(ShakeSizeParserAdapter::new(&session.response_body_iv))
    } else {
        Box::new(PlainSizeParser)
    };
    let global_padding = header.option.has(request_option::GLOBAL_PADDING);
    let no_termination = header.option.has(request_option::NO_TERMINATION_SIGNAL);

    // 5. 发送响应头（客户端收到后开始 body 流）
    let resp_header = ResponseHeader {
        command: header.command,
        option: header.option,
        response_command: ResponseCommand::None,
    };
    session
        .encode_response_header_async(&resp_header, &mut stream_w)
        .await
        .map_err(|e| std::io::Error::other(format!("vmess encode response header: {e}")))?;

    // 4. 取 dest + body 加密状态（已由 parse_decoded_header_payload 填充）
    let dest = header.destination.clone();
    let req_iv = session.request_body_iv;
    let resp_iv = session.response_body_iv;

    // 6. 构造 body ciphers（按 request.security 分支，与 encoding/server.rs 同语义）
    // 6. 构造 body ciphers（按 request.security 分支，统一封装为 BodyCipher 避免类型不匹配）
    let (req_cipher, resp_cipher): (BodyCipher, BodyCipher) = match header.security {
        SecurityType::Aes128Gcm => {
            let r = Aes128Gcm::new(&session.request_body_key)
                .map_err(|e| std::io::Error::other(format!("vmess aes128 req key: {e}")))?;
            let s = Aes128Gcm::new(&session.response_body_key)
                .map_err(|e| std::io::Error::other(format!("vmess aes128 resp key: {e}")))?;
            (BodyCipher::Aes(r), BodyCipher::Aes(s))
        }
        SecurityType::Chacha20Poly1305 => {
            let rk = generate_chacha20poly1305_key(&session.request_body_key);
            let r = ChaCha20Poly1305Aead::new(&rk)
                .map_err(|e| std::io::Error::other(format!("vmess chacha req key: {e}")))?;
            let sk = generate_chacha20poly1305_key(&session.response_body_key);
            let s = ChaCha20Poly1305Aead::new(&sk)
                .map_err(|e| std::io::Error::other(format!("vmess chacha resp key: {e}")))?;
            (BodyCipher::Chacha(r), BodyCipher::Chacha(s))
        }
        #[allow(deprecated)]
        SecurityType::None | SecurityType::Zero => (BodyCipher::NoOp(NoOpAeadCipher), BodyCipher::NoOp(NoOpAeadCipher)),

        other => {
            return Err(std::io::Error::other(format!(
                "vmess unsupported security: {other:?}"
            )));
        }
    };

    // 7. TCP：duplex pump + dispatch；UDP：chunk 即 packet（Go 非 cone 语义）
    if header.command == Command::Udp {
        return pump_udp_session(
            stream_r, stream_w, &dest, Arc::clone(handler),
            req_cipher, resp_cipher, req_iv, resp_iv,
            req_size_parser, resp_size_parser, global_padding, no_termination,
        )
        .await;
    }

    let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF);
    let (server_r, server_w) = tokio::io::split(server_io);
    let (client_r, client_w) = tokio::io::split(client_io);
    let link = Link::new(new_reader(client_r), new_writer(client_w));

    let pump_a = pump_request_body(stream_r, server_w, req_cipher, req_iv, req_size_parser, global_padding);
    let pump_b = pump_response_body(server_r, stream_w, resp_cipher, resp_iv, resp_size_parser, global_padding, no_termination);
    let dispatch_fut = handler.dispatch(&dest, link);

    // 三路并发：pump_a / pump_b / dispatch，全部完成后返回
    let _ = tokio::join!(pump_a, pump_b, dispatch_fut);
    Ok(())
}
///
/// chunk 格式：`[size_field][AEAD ciphertext][padding]`。
/// size_field 长度由 `size_parser.size_bytes()` 决定（Plain/Shake=2, AEAD=18）。
/// 终止 chunk = `seal([])` → 解密后 plaintext 为空即终止信号。
/// EOF 或解密失败时 break 并 shutdown sink。
async fn pump_request_body<C, R>(
    mut stream_r: R,
    mut server_w: WriteHalf<DuplexStream>,
    cipher: C,
    iv: [u8; 16],
    mut size_parser: Box<dyn SizeParser + Send>,
    global_padding: bool,
) where
    C: AeadCipher + Send,
    R: AsyncRead + Unpin,
{
    let mut nonce_gen = ChunkNonceAdapter::new(&iv, 12);
    loop {
        // SHAKE128 流同步：先 next_padding_len 再 decode（与 body_chunk decode 一致）。
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
        let total_size = usize::from(size_parser.decode(&size_field));
        if total_size == 0 {
            break;
        }
        let ciphertext_size = total_size.saturating_sub(padding_size);
        let mut ciphertext = vec![0u8; total_size];
        if stream_r.read_exact(&mut ciphertext).await.is_err() {
            break;
        }
        let nonce = nonce_gen.next();
        match cipher.open(&nonce, &[], &ciphertext[..ciphertext_size]) {
            Ok(pt) if pt.is_empty() => break, // 终止 chunk：seal([]) → 解密为空
            Ok(pt) => {
                if server_w.write_all(&pt).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                tracing::debug!(
                    error = %e.to_string(),
                    "vmess request body chunk open failed"
                );
                break;
            }
        }
    }
    // shutdown 写半边，让 dispatch reader 看到 EOF（标记请求 body 结束）
    let _ = server_w.shutdown().await;
}

/// 读取明文 sink 字节，按 VMess response body chunk 格式加密写入 stream。
///
/// chunk 格式：`[size_field][encrypted][padding]`，size_field 由 SizeParser 编码。
/// 流结束（EOF 或错误）时写终止 chunk：`seal([])`（no_termination=true 时跳过）。
async fn pump_response_body<C, W>(
    mut server_r: ReadHalf<DuplexStream>,
    mut stream_w: W,
    cipher: C,
    iv: [u8; 16],
    mut size_parser: Box<dyn SizeParser + Send>,
    global_padding: bool,
    no_termination: bool,
) where
    C: AeadCipher + Send,
    W: AsyncWrite + Unpin,
{
    let mut nonce_gen = ChunkNonceAdapter::new(&iv, 12);
    let mut buf = [0u8; PUMP_BUF];
    loop {
        match server_r.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let nonce = nonce_gen.next();
                let sealed = match cipher.seal(&nonce, &[], &buf[..n]) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(
                            error = %e.to_string(),
                            "vmess response body chunk seal failed"
                        );
                        break;
                    }
                };
                let padding_size = if global_padding {
                    usize::from(size_parser.next_padding_len())
                } else {
                    0
                };
                let encrypted_size = sealed.len();
                let size_value =
                    u16::try_from(encrypted_size + padding_size).unwrap_or(u16::MAX);
                let sb = size_parser.size_bytes();
                let mut size_field = vec![0u8; sb];
                size_parser.encode(size_value, &mut size_field);
                if stream_w.write_all(&size_field).await.is_err() {
                    break;
                }
                if stream_w.write_all(&sealed).await.is_err() {
                    break;
                }
                if padding_size > 0 {
                    let mut pad = vec![0u8; padding_size];
                    use rand::RngCore;
                    rand::rng().fill_bytes(&mut pad);
                    if stream_w.write_all(&pad).await.is_err() {
                        break;
                    }
                }
            }
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "vmess response body plaintext read failed"
                );
                break;
            }
        }
    }
    // 写终止 chunk：seal([]) → 仅 tag 字节，客户端 decode 看到 plaintext 为空即返回
    if !no_termination {
        let nonce = nonce_gen.next();
        if let Ok(sealed) = cipher.seal(&nonce, &[], &[]) {
            let sb = size_parser.size_bytes();
            let mut size_field = vec![0u8; sb];
            size_parser.encode(
                u16::try_from(sealed.len()).unwrap_or(u16::MAX),
                &mut size_field,
            );
            let _ = stream_w.write_all(&size_field).await;
            let _ = stream_w.write_all(&sealed).await;
        }
    }
    let _ = stream_w.flush().await;
    let _ = stream_w.shutdown().await;
}

/// 将 payload 加密为单个 response chunk 写入 stream（VMess UDP 会话专用）。
///
/// 与 [`pump_response_body`] 的 chunk 写法一致；`payload` 为空时即终止 chunk
/// （`seal([])`，客户端 chunk reader 以空明文为流结束信号）。
async fn write_udp_chunk<W: AsyncWrite + Unpin>(
    stream_w: &mut W,
    cipher: &BodyCipher,
    nonce_gen: &mut ChunkNonceAdapter,
    sp: &mut (dyn SizeParser + Send),
    global_padding: bool,
    payload: &[u8],
) -> std::io::Result<()> {
    let nonce = nonce_gen.next();
    let sealed = cipher
        .seal(&nonce, &[], payload)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let padding_size = if global_padding {
        usize::from(sp.next_padding_len())
    } else {
        0
    };
    let size_value = u16::try_from(sealed.len() + padding_size).unwrap_or(u16::MAX);
    let sb = sp.size_bytes();
    let mut size_field = vec![0u8; sb];
    sp.encode(size_value, &mut size_field);
    stream_w.write_all(&size_field).await?;
    stream_w.write_all(&sealed).await?;
    if padding_size > 0 {
        use rand::RngCore;
        let mut pad = vec![0u8; padding_size];
        rand::rng().fill_bytes(&mut pad);
        stream_w.write_all(&pad).await?;
    }
    Ok(())
}

/// VMess UDP 会话（Go 非 cone 语义）：chunk 边界即 UDP packet 边界。
///
/// - up：解密 request chunk → `UdpDispatchSession::send_packet`
/// - down：`UdpDispatchSession::recv_packet` → 加密为 response chunk 写回
///
/// 数据报经 dispatch（routing 规则选择 outbound），不再 per-session 直连
/// raw socket；目标取自 request header，域名不本地解析（outbound 侧解析）。
/// chunk 读取（多次 read_exact）不可取消，up 独立 async block 经 channel
/// 与 relay 循环并发；客户端断开（up EOF）后保留收尾窗口，双侧同退。
async fn pump_udp_session<R, W>(
    mut stream_r: R,
    mut stream_w: W,
    dest: &Destination,
    handler: Arc<dyn DispatchHandler>,
    req_cipher: BodyCipher,
    resp_cipher: BodyCipher,
    req_iv: [u8; 16],
    resp_iv: [u8; 16],
    mut req_sp: Box<dyn SizeParser + Send>,
    mut resp_sp: Box<dyn SizeParser + Send>,
    global_padding: bool,
    no_termination: bool,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let udp_dest = Destination::udp(dest.address().clone(), dest.port());
    let mut session = UdpDispatchSession::new(handler);

    // up：解密 request chunk（与 pump_request_body 同构）→ channel 交 relay。
    let (up_tx, mut up_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    let up = async move {
        let mut nonce_gen = ChunkNonceAdapter::new(&req_iv, 12);
        loop {
            // padding → size → ciphertext → open
            let padding_size = if global_padding {
                usize::from(req_sp.next_padding_len())
            } else {
                0
            };
            let sb = req_sp.size_bytes();
            let mut size_field = vec![0u8; sb];
            if stream_r.read_exact(&mut size_field).await.is_err() {
                break;
            }
            let total_size = usize::from(req_sp.decode(&size_field));
            if total_size == 0 {
                break; // 终止 chunk
            }
            let ciphertext_size = total_size.saturating_sub(padding_size);
            let mut ciphertext = vec![0u8; total_size];
            if stream_r.read_exact(&mut ciphertext).await.is_err() {
                break;
            }
            let nonce = nonce_gen.next();
            match req_cipher.open(&nonce, &[], &ciphertext[..ciphertext_size]) {
                // 空明文 chunk = 请求流终止（chunk writer Close 语义），不作为
                // 数据报转发（dispatch 侧也会丢弃空 payload，转发即死锁）。
                Ok(packet) if packet.is_empty() => break,
                Ok(packet) => {
                    if up_tx.send(packet).await.is_err() {
                        break; // relay 已退出
                    }
                }
                Err(_) => break,
            }
        }
        drop(up_tx); // 唤醒 relay 退出
    };

    // relay：session 双向。up 包 → send_packet（select 分支体内 await，不可
    // 取消，无半帧风险）；recv_packet → 加密写回 stream_w（recv_packet 可
    // 取消：半帧累积在 session 内部，取消不丢数据）。
    let relay = async {
        // up 结束后仍保留收尾窗口：在途回包可能晚于终止 chunk 到达
        //（Go 由 CancelAfterInactivity(ConnectionIdle) 管理，此处取短窗口）。
        const UP_DONE_IDLE: std::time::Duration = std::time::Duration::from_millis(500);
        let mut nonce_gen = ChunkNonceAdapter::new(&resp_iv, 12);
        let mut up_done = false;
        loop {
            let incoming = if up_done {
                tokio::time::timeout(UP_DONE_IDLE, session.recv_packet())
                    .await
                    .unwrap_or(Ok(None)) // 收尾窗口超时 → 会话结束
            } else {
                tokio::select! {
                    pkt = up_rx.recv() => {
                        match pkt {
                            Some(p) => {
                                if session.send_packet(&udp_dest, &p).await.is_err() {
                                    break; // dispatch link 已断
                                }
                                continue;
                            }
                            None => { up_done = true; continue; }
                        }
                    }
                    r = session.recv_packet() => r,
                }
            };
            let (_source, payload) = match incoming {
                Ok(Some(v)) => v,
                Ok(None) => break, // outbound 关闭
                Err(_) => break,
            };
            if write_udp_chunk(
                &mut stream_w,
                &resp_cipher,
                &mut nonce_gen,
                resp_sp.as_mut(),
                global_padding,
                &payload,
            )
            .await
            .is_err()
            {
                break;
            }
            let _ = stream_w.flush().await;
        }
        // 会话结束：写终止 chunk（seal([])），与 pump_response_body 流结束
        // 行为一致——客户端 chunk reader 以空明文为流结束信号，缺失则挂起。
        if !no_termination {
            let _ = write_udp_chunk(
                &mut stream_w,
                &resp_cipher,
                &mut nonce_gen,
                resp_sp.as_mut(),
                global_padding,
                &[],
            )
            .await;
        }
        let _ = stream_w.shutdown().await;
    };

    tokio::join!(up, relay);
    Ok(())
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::MemoryAccount;
    use crate::encoding::client::ClientSession;
    use crate::encoding::VERSION;
    use crate::validator::{MemoryUser, Validator};
    use tokio::net::TcpListener;
    use xray_app_dispatcher::default::DialBridge;
    use xray_common::net::address::Address;
    use xray_common::net::destination::Destination;
    use xray_common::net::port::Port;
    use xray_common::protocol::RequestHeader;
    use xray_common::uuid::UUID;
    use xray_proxy_freedom::{make_freedom_dial_fn, FreedomDispatchBridge};

    const SAMPLE_UUID_STR: &str = "66ad4540-b58c-4ad2-9926-ea63445a9b57";

    /// 构造测试用 validator（含一个已注册用户）+ 对应 cmd_key。
    fn make_validator_with_user() -> (Arc<TimedUserValidator>, [u8; 16]) {
        let uuid = UUID::parse(SAMPLE_UUID_STR).expect("uuid");
        let account = MemoryAccount::new(uuid);
        let cmd_key = account.cmd_key();
        let user = MemoryUser::new("alice@example.com", account);
        let v = TimedUserValidator::new();
        v.add(user).expect("add user");
        (Arc::new(v), cmd_key)
    }

    /// 启动 echo server，返回监听端口。
    async fn spawn_echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        port
    }

    /// 构造 SimpleOhm + freedom 默认 outbound。
    fn make_ohm_with_freedom() -> Arc<SimpleOhm> {
        let ohm = Arc::new(SimpleOhm::new());
        // 与生产 wiring（xray-core/src/outbound.rs）一致：
        // TCP 走 DialBridge，UDP 走 FreedomDispatchBridge → freedom udp::relay。
        let tcp_bridge = Arc::new(DialBridge::new("freedom", make_freedom_dial_fn()));
        let bridge = Arc::new(FreedomDispatchBridge::from_bridge(tcp_bridge))
            as Arc<dyn DispatchHandler>;
        ohm.set_default(bridge);
        ohm
    }

    /// 端到端测试核心：VMess client → serve_vmess → freedom → echo。
    async fn run_vmess_e2e(security: SecurityType) {
        // 1. echo server
        let echo_port = spawn_echo_server().await;

        // 2. dispatcher: freedom outbound → SimpleOhm default
        let ohm = make_ohm_with_freedom();

        // 3. validator + serve_vmess
        let (validator, cmd_key) = make_validator_with_user();
        let vmess_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vmess_addr = vmess_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        let validator_clone = Arc::clone(&validator);
        tokio::spawn(async move {
            let _ = serve_vmess(vmess_listener, ohm_clone, validator_clone, None).await;
        });

        // 4. VMess client：connect → encode header → decode response header → echo round-trip
        let mut client = tokio::net::TcpStream::connect(vmess_addr)
            .await
            .unwrap();
        let client_session = ClientSession::new();
        let dest = Destination::tcp(
            Address::ipv4(std::net::Ipv4Addr::LOCALHOST),
            Port::new(echo_port),
        );
        let header = RequestHeader::new(VERSION, Command::Tcp, dest, security);

        let sealed_header = client_session
            .encode_request_header(&header, &cmd_key)
            .expect("encode header");
        client.write_all(&sealed_header).await.unwrap();

        // 读响应头（客户端收到后才能开始 body 流）
        let _resp = client_session
            .decode_response_header_async(&mut client)
            .await
            .expect("decode response header");

        // 发请求 body（一次性 chunk stream，含终止 chunk）
        let payload = b"hello vmess proxy!";
        client_session
            .encode_request_body_async(&header, payload, &mut client)
            .await
            .expect("encode request body");

        // 读响应 body（一次性 chunk stream，读到终止 chunk 返回）
        let response = client_session
            .decode_response_body_async(&header, &mut client)
            .await
            .expect("decode response body");
        assert_eq!(
            response, payload,
            "should receive echo through vmess proxy ({security:?})"
        );
    }

    #[tokio::test]
    async fn vmess_inbound_to_freedom_outbound_e2e_aes128gcm() {
        run_vmess_e2e(SecurityType::Aes128Gcm).await;
    }

    #[tokio::test]
    async fn vmess_inbound_to_freedom_outbound_e2e_chacha20poly1305() {
        run_vmess_e2e(SecurityType::Chacha20Poly1305).await;
    }

    /// 无效用户（validator 中不存在）→ server 关闭连接，client 收到 EOF 或 reset。
    #[tokio::test]
    async fn vmess_inbound_rejects_unknown_user() {
        let ohm = make_ohm_with_freedom();

        // 空 validator（无任何用户）
        let validator = Arc::new(TimedUserValidator::new());
        let vmess_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vmess_addr = vmess_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        let validator_clone = Arc::clone(&validator);
        tokio::spawn(async move {
            let _ = serve_vmess(vmess_listener, ohm_clone, validator_clone, None).await;
        });

        // client 用未注册的随机 UUID
        let unknown_uuid = UUID::new();
        let cmd_key = crate::account::cmd_key_of(&unknown_uuid);
        let mut client = tokio::net::TcpStream::connect(vmess_addr)
            .await
            .unwrap();

        let client_session = ClientSession::new();
        let dest = Destination::tcp(
            Address::ipv4(std::net::Ipv4Addr::LOCALHOST),
            Port::new(80),
        );
        let header = RequestHeader::new(
            VERSION,
            Command::Tcp,
            dest,
            SecurityType::Aes128Gcm,
        );
        let sealed_header = client_session
            .encode_request_header(&header, &cmd_key)
            .expect("encode header");
        client.write_all(&sealed_header).await.unwrap();

        // server 因 UserNotFound 关闭 → client 读响应得到 EOF 或 reset
        let mut buf = [0u8; 16];
        let result = client.read(&mut buf).await;
        match result {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => {}
            other => panic!("expected EOF or connection reset, got {other:?}"),
        }
    }
    /// VMess UDP e2e：client Command::Udp → server chunk→packet 转发 → UDP echo → 回包 chunk。
    /// 对应 Go 非 cone 语义（chunk 边界即 packet 边界）。
    #[tokio::test]
    async fn vmess_inbound_udp_relay_e2e() {
        use tokio::net::UdpSocket;

        // 1. UDP echo server
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], from).await;
            }
        });

        // 2. serve_vmess（UDP 经 dispatch → freedom outbound 转发）
        let ohm = make_ohm_with_freedom();
        let (validator, cmd_key) = make_validator_with_user();
        let vmess_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vmess_addr = vmess_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        let validator_clone = Arc::clone(&validator);
        tokio::spawn(async move {
            let _ = serve_vmess(vmess_listener, ohm_clone, validator_clone, None).await;
        });

        // 3. client：UDP command header 指向 echo
        let mut client = tokio::net::TcpStream::connect(vmess_addr).await.unwrap();
        let client_session = ClientSession::new();
        let dest = Destination::udp(
            Address::ipv4(std::net::Ipv4Addr::LOCALHOST),
            Port::new(echo_addr.port()),
        );
        let header = RequestHeader::new(VERSION, Command::Udp, dest, SecurityType::Aes128Gcm);

        let sealed_header = client_session
            .encode_request_header(&header, &cmd_key)
            .expect("encode header");
        client.write_all(&sealed_header).await.unwrap();
        let _resp = client_session
            .decode_response_header_async(&mut client)
            .await
            .expect("decode response header");

        // 4. 发一个 UDP packet chunk（encode_request_body_async 含终止 chunk）
        let payload = b"hello vmess udp!";
        client_session
            .encode_request_body_async(&header, payload, &mut client)
            .await
            .expect("encode request body");

        // 5. 读回包（终止 chunk 前收到 echo packet chunk）
        let response = client_session
            .decode_response_body_async(&header, &mut client)
            .await
            .expect("decode response body");
        assert_eq!(response, payload);
    }
}
