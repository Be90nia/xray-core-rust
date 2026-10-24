//! HTTP proxy 服务端——HTTP CONNECT 隧道 + plain HTTP 转发（keep-alive 循环）
//! + Proxy-Authorization 认证。
//!
//! 对应 Go `proxy/http/server.go` 的 `Process` + `handleConnect` +
//! `handlePlainHTTP` + `parseBasicAuth`。
//!
//! ## 连接模型（对齐 Go）
//!
//! - **CONNECT 终结性**：tunnel 结束（或 dial 失败）即关连接，不回循环 （Go `handleConnect` 直接
//!   return）。
//! - **plain HTTP**：每请求拨一条新上游连接（对齐 Go `Dispatch` 每请求新 link），响应后按「客户端
//!   `Proxy-Connection: keep-alive` **且** 上游响应 Content-Length >=
//!   0」双条件决定回循环读下一请求（Go `goto Start`）， 否则关连接。
//! - 每轮读头 deadline 60s（Go `SetReadDeadline(Timeouts.Handshake)`）。

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use skeleton_infra::fx::{FxScope, Spawned};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tracing::{info, warn};
use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_features::inbound::{InboundError, InboundHandler};

use crate::{
    config::ServerConfig,
    error::{HttpProxyError, Result},
};

/// HTTP 请求行版本（plain HTTP/1.x 仅此两档；解析见 [`parse_http_version`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    /// `HTTP/1.0`——连接缺省非持久（RFC 7230 §A.1）。
    H10,
    /// `HTTP/1.1` 及其它未知版本——缺省持久（未知版本按 1.1 处理是既有
    /// 行为：此前版本段整段被丢弃不校验，不引入新的拒绝行为）。
    H11,
}

/// 请求行第三段 → 版本。仅精确匹配 `HTTP/1.0` 判 1.0（Go `http.ReadRequest`
/// 只接受 HTTP/1.x，此处保持纯增量：非 1.0 一律按 1.1 语义，不新增拒绝）。
#[must_use]
pub fn parse_http_version(token: &str) -> HttpVersion {
    if token.eq_ignore_ascii_case("HTTP/1.0") { HttpVersion::H10 } else { HttpVersion::H11 }
}

/// HTTP 握手结果——包含解析出的目标、方法、请求行 target 和 headers。
///
/// CONNECT 隧道只需 `dest` + `method`；plain HTTP 代理需要 `target` + `headers`
/// 重建转发请求（对应 Go `handlePlainHTTP`）。
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    /// 解析出的目标地址（CONNECT 从 authority，plain HTTP 从 Host header）。
    pub dest: Destination,
    /// HTTP 方法（大写）。
    pub method: String,
    /// 请求行 target 字段（CONNECT = `host:port`，plain HTTP = 绝对 URL 或路径）。
    pub target: String,
    /// 请求行版本段（keep-alive 判定按版本分叉，RFC 7230 §A.1）。
    pub http_version: HttpVersion,
    /// 解析出的 headers（key 全小写）。同名多值保留（对齐 Go `http.Header`
    /// `map[string][]string`——双 Cookie 等逐行转发，不折叠丢失）。
    pub headers: HashMap<String, Vec<String>>,
}

/// Hop-by-hop headers（RFC 7230 §6.1）+ 代理专有 header——转发时移除。
///
/// 注意不含 `transfer-encoding`：本实现不解析请求体，body 的 chunked 帧原样
/// 透传，剥掉该头目标会按无 body 请求解析 → chunked POST 丢体（bd 04n8）。
/// Go 的 wire 等价路径：ReadRequest 解码 body 后 `request.Write` 重新 chunked
/// 编码——保留头 + 原样帧透传与之线路上等价。
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailers",
    "upgrade",
];

/// 每连接请求头读取超时。对应 Go `Process` 的
/// `conn.SetReadDeadline(time.Now().Add(s.policy().Timeouts.Handshake))`，
/// 默认值 60s（Go `features/policy/policy.go:130`）。Go 无独立空闲超时——
/// 同一 deadline 覆盖「空闲等待请求头」。
const REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(60);

/// 优雅关闭时读向排空的上限——等客户端关写或超时（防 RST 丢最终响应，
/// 见 [`graceful_close`]）。
const CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// 头解析失败 / 非透明 origin-form 的 400 响应（字节与既有 origin-form 分支一致）。
const RESPONSE_BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\n\
    Proxy-Connection: close\r\n\
    Connection: close\r\n\
    Content-Length: 0\r\n\r\n";

/// plain HTTP 读上游响应失败 / 响应头非法的 503 响应（对齐 Go handlePlainHTTP
/// 503 分支：Close=true + 双 close 头 + Content-Length 0）。
const RESPONSE_SERVICE_UNAVAILABLE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Connection: close\r\n\
    Proxy-Connection: close\r\n\
    Content-Length: 0\r\n\r\n";

/// 从请求行 target 提取 path（含 query）。
///
/// `http://example.com/path?q=1` → `/path?q=1`
/// `/path` → `/path`（透明代理）
/// `example.com:8080/path` → `/path`（无 scheme）
/// `example.com` → `/`（无 path）
pub fn extract_request_path(target: &str) -> String {
    let after_scheme = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);
    match after_scheme.find('/') {
        Some(slash) => after_scheme[slash..].to_string(),
        None => "/".to_string(),
    }
}

/// 构建转发给目标服务器的 HTTP 请求（request line + headers）。
///
/// 移除 hop-by-hop headers，强制 `Connection: close`；同名多值头逐行写
/// （Go `request.Write` 语义）。
/// 对应 Go `handlePlainHTTP` 中 `request.Header.Set("Connection", "close")` + `request.Write`。
pub fn build_forwarded_request(
    method: &str,
    path: &str,
    headers: &HashMap<String, Vec<String>>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(method.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(path.as_bytes());
    buf.extend_from_slice(b" HTTP/1.1\r\n");
    for (key, values) in headers {
        if HOP_BY_HOP_HEADERS.contains(&key.as_str()) {
            continue;
        }
        for value in values {
            buf.extend_from_slice(key.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
    }
    buf.extend_from_slice(b"connection: close\r\n\r\n");
    buf
}

/// HTTP proxy inbound 服务器。
///
/// 切片2：listen + accept + HTTP CONNECT handshake + 认证。
pub struct HttpServer {
    tag: String,
    config: ServerConfig,
    /// 监听器 + accept loop 任务句柄。close 时 abort 任务取消 accept().
    /// 任务经 FxScope 托管（坑约束 5）；scope 随 handler drop 兜底 abort 在途任务。
    slot: Mutex<Option<(Arc<TcpListener>, Spawned<()>)>>,
    /// 组件内自持托管 scope（B6，app 家族同款；不接 close，闸关不可达）。
    fx: Arc<FxScope>,
}

impl HttpServer {
    /// 构造 HTTP 代理服务端。
    #[must_use]
    pub fn new(tag: impl Into<String>, config: ServerConfig) -> Self {
        Self { tag: tag.into(), config, slot: Mutex::new(None), fx: Arc::new(FxScope::new()) }
    }

    /// 获取监听端口（start 后有效，否则返回 0）。对齐 `xray-proxy-socks` 同名方法。
    pub async fn bound_port(&self) -> u16 {
        self.slot
            .lock()
            .await
            .as_ref()
            .and_then(|(l, _)| l.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(0)
    }
}

#[async_trait]
impl InboundHandler for HttpServer {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self) -> std::result::Result<(), InboundError> {
        let addr: SocketAddr = "127.0.0.1:0"
            .parse()
            .map_err(|e| InboundError::ListenError(format!("invalid addr: {e}")))?;
        let listener = Arc::new(
            TcpListener::bind(addr)
                .await
                .map_err(|e| InboundError::ListenError(format!("bind failed: {e}")))?,
        );
        let bound = listener
            .local_addr()
            .map_err(|e| InboundError::ListenError(format!("local_addr: {e}")))?;
        info!(tag = %self.tag, addr = %bound, "HTTP proxy server started");

        let tag = self.tag.clone();
        let config = self.config.clone();
        let listener_clone = Arc::clone(&listener);
        let fx = Arc::clone(&self.fx);
        // 预制克隆源：async move 块捕获 fx_conns，避免块自捕获 fx 与 spawn 接收者
        // 借用冲突（E0505）。
        let fx_conns = Arc::clone(&fx);
        let handle = fx
            .spawn(async move {
                loop {
                    match listener_clone.accept().await {
                        Ok((stream, peer)) => {
                            let tag = tag.clone();
                            let config = config.clone();
                            let fx = Arc::clone(&fx_conns);
                            fx.spawn(async move {
                                handle_connection(stream, config, tag, peer).await;
                            })
                            .expect("internal FxScope is never closed");
                        },
                        Err(e) => {
                            warn!(tag = %tag, error = %e, "accept failed");
                            break;
                        },
                    }
                }
            })
            .expect("internal FxScope is never closed");

        *self.slot.lock().await = Some((listener, handle));
        Ok(())
    }

    async fn close(&self) -> std::result::Result<(), InboundError> {
        if let Some((_listener, handle)) = self.slot.lock().await.take() {
            handle.abort();
            info!(tag = %self.tag, "HTTP proxy server closed");
        }
        Ok(())
    }

    fn port(&self) -> u16 {
        // 同步方法无法读 async Mutex; 返回 0 让调用方用 bound_port().await
        0
    }
}

/// 单连接处理：读头 → 转发（CONNECT 隧道 / plain HTTP），连接终结性对齐 Go。
///
/// 对应 Go `Process`：读头带 handshake deadline（默认 60s，`policy.go:130`）；
/// **CONNECT 终结性**——tunnel 结束/失败即关连接（Go `handleConnect` 直接
/// return，隧道结束后字节流已非 HTTP 边界）；plain HTTP 按 keep-alive 双条件
/// 回循环（见 [`serve_connection`]）。
async fn handle_connection(
    mut stream: TcpStream,
    config: ServerConfig,
    tag: String,
    peer: SocketAddr,
) {
    serve_connection(&mut stream, &config, &tag, peer).await;
    graceful_close(&mut stream).await;
}

/// 优雅关闭：先 shutdown 写向（让已写响应先出去），再短排空读向。
///
/// Windows 上直接 drop 带未读数据的 socket 会 RST，连带丢弃发送缓冲中的
/// 最终响应（400 / EOF 前的最后写入）；读空接收缓冲后 close 才是干净 FIN。
async fn graceful_close(stream: &mut TcpStream) {
    if stream.shutdown().await.is_err() {
        return;
    }
    let _ = tokio::time::timeout(CLOSE_DRAIN_TIMEOUT, async {
        let mut sink = [0u8; 4096];
        loop {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {},
            }
        }
    })
    .await;
}

/// 单连接处理体（关闭策略见 [`graceful_close`]）。
///
/// 对应 Go `Process` 的 `Start` 循环：每轮读头带 handshake deadline（默认 60s，
/// `policy.go:130`）。CONNECT → 隧道后终结（Go `handleConnect` return）；非
/// CONNECT → plain HTTP 转发（[`handle_plain_http`]），客户端请求头
/// `Proxy-Connection: keep-alive` 且上游响应 Content-Length >= 0 时回循环读
/// 下一请求（Go `goto Start`），否则关连接。
async fn serve_connection(
    stream: &mut TcpStream,
    config: &ServerConfig,
    tag: &str,
    peer: SocketAddr,
) {
    loop {
        // 对应 Go Start 段的 handshake read deadline（policy 默认 60s）；
        // 超时同时覆盖"空闲等待请求头"——Go 无独立空闲超时。
        let handshake =
            tokio::time::timeout(REQUEST_HEADER_TIMEOUT, http_server_handshake(stream, config));
        let mut hs = match handshake.await {
            Err(_) => {
                info!(
                    tag = %tag,
                    peer = %peer,
                    timeout = ?REQUEST_HEADER_TIMEOUT,
                    "HTTP proxy connection idle/header timeout, closing"
                );
                return;
            },
            Ok(Err(e)) => {
                // 400/407 响应已在 handshake 内写回；EOF/解析失败一律关闭
                warn!(
                    tag = %tag,
                    peer = %peer,
                    error = %e,
                    "HTTP proxy handshake failed, closing connection"
                );
                return;
            },
            Ok(Ok(hs)) => hs,
        };
        if hs.method != "CONNECT" {
            // Go Process: keepAlive := TrimSpace(ToLower(Proxy-Connection)) == "keep-alive"
            let keep_alive_req = request_keep_alive(&hs.headers);
            match handle_plain_http(stream, &mut hs).await {
                // Go: err == errWaitAnother → keepAlive ? goto Start : err = nil
                Ok(PlainOutcome::WaitAnother) if keep_alive_req => continue,
                Ok(PlainOutcome::WaitAnother) => {},
                Ok(PlainOutcome::Close) => {},
                Err(e) => {
                    warn!(
                        tag = %tag,
                        peer = %peer,
                        method = %hs.method,
                        error = %e,
                        "plain HTTP forwarding failed, closing connection"
                    );
                },
            }
            return;
        }
        info!(tag = %tag, peer = %peer, dest = ?hs.dest, "HTTP proxy CONNECT established");
        // CONNECT 终结性（对齐 Go handleConnect → return）：tunnel 成功、dial 失败、
        // 拷贝错误任一结局都关连接——隧道结束后字节流已非 HTTP 边界。
        match dial_destination(&hs.dest).await {
            Err(e) => {
                warn!(
                    tag = %tag,
                    peer = %peer,
                    dest = ?hs.dest,
                    error = %e,
                    "CONNECT dial failed, closing connection"
                );
            },
            Ok(mut upstream) => {
                if let Err(e) = tokio::io::copy_bidirectional(stream, &mut upstream).await {
                    warn!(
                        tag = %tag,
                        peer = %peer,
                        dest = ?hs.dest,
                        error = %e,
                        "CONNECT tunnel copy failed, closing connection"
                    );
                    return;
                }
                info!(tag = %tag, dest = ?hs.dest, "CONNECT tunnel finished, closing connection");
            },
        }
        return;
    }
}

/// plain HTTP 转发结果——对应 Go `handlePlainHTTP` 的返回值语义：
/// `errWaitAnother`（响应已完成且上游响应可保持连接）或 `nil`（必须关连接）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlainOutcome {
    /// 响应已完整回写；是否复用客户端连接由调用方按客户端 keep-alive 请求头决定。
    WaitAnother,
    /// 必须关连接（上游响应不可定界 / 显式 close / 请求体不支持）。
    Close,
}

/// 上游读响应空闲上限。Go 读响应无 deadline（dispatcher 侧 policy 管理）；本
/// crate 直连无 policy 层，此上限仅兜"上游 accept 后永不响应"的挂死连接——
/// 正常慢响应（数据持续到达）不受影响。
const UPSTREAM_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// 头里是否声明 chunked 传输编码（请求体/响应体通用判定）。
fn headers_indicate_chunked(headers: &HashMap<String, Vec<String>>) -> bool {
    headers
        .get("transfer-encoding")
        .is_some_and(|vals| vals.iter().any(|v| v.to_ascii_lowercase().contains("chunked")))
}

/// plain HTTP 转发（对应 Go `handlePlainHTTP`）。
///
/// 每次调用拨一条新上游连接（对齐 Go `Dispatch` 每请求新 link）。请求体按
/// Content-Length 定长原样透传（不解码不重编码）；chunked 请求体不支持，回
/// 400 明确报错。响应按上游可定界性分派：
/// - Content-Length >= 0 → 回写 keep-alive 头，body 定长透传，返回 [`PlainOutcome::WaitAnother`]；
/// - chunked / close-delimited → 回写 close 头，body 原样透传，返回 [`PlainOutcome::Close`]；
/// - 读响应失败 → 503 + close 头，返回 [`PlainOutcome::WaitAnother`]（对齐 Go： 503 分支不重置
///   `result`，`Process` 层仍按客户端 keep-alive 头决定循环）。
async fn handle_plain_http(
    client: &mut TcpStream,
    hs: &mut HandshakeResult,
) -> Result<PlainOutcome> {
    // Go net/http transfer.go `parseTransferEncoding`（:631-641，Issue 12785）：
    // `!protoAtLeast(1, 1)` 时先 `delete(t.Header, "Transfer-Encoding")` 再直接
    // return——HTTP/1.0 请求声明的 Transfer-Encoding 不参与 body 定界，
    // 按 Content-Length / 无 body 处理，且该头不转发给上游。对齐后走私防护
    // 不弱于 Go：TE 声明在 1.0 侧被剥除，1.1 chunked 仍显式拒绝。
    if hs.http_version == HttpVersion::H10 {
        hs.headers.remove("transfer-encoding");
    } else if headers_indicate_chunked(&hs.headers) {
        // chunked 请求体明确报错（Go 经 ReadRequest 解码支持；本实现原样透传
        // 无 body 边界解析，静默截断不可接受）
        warn!(method = %hs.method, "chunked request body not supported by plain HTTP forwarding");
        let _ = client.write_all(RESPONSE_BAD_REQUEST).await;
        return Ok(PlainOutcome::Close);
    }
    let req_body_len = parse_content_length(&hs.headers)?;

    // Go: request.Host = request.URL.Host（绝对 URI 时覆盖 Host 头）
    if let Some(host) = extract_url_host(&hs.target) {
        hs.headers.insert("host".into(), vec![host.to_string()]);
    }
    let path = extract_request_path(&hs.target);

    // Go: dispatcher.Dispatch(ctx, dest) —— 每请求新上游连接
    let mut upstream = dial_destination(&hs.dest).await?;

    // requestDone：Connection: close + 请求头 + body 定长透传
    let forwarded = build_forwarded_request(&hs.method, &path, &hs.headers);
    upstream.write_all(&forwarded).await?;
    if let Some(n) = req_body_len {
        copy_exact_n(client, &mut upstream, n).await?;
    }
    // 转发请求带 Connection: close，上游响应完即关——响应读取阶段无独立
    // half-close 需求；upstream 在本函数返回时 drop（Go defer Close(link.Writer)）。

    // responseDone
    let resp = match tokio::time::timeout(
        UPSTREAM_RESPONSE_TIMEOUT,
        read_response_head(&mut upstream, client),
    )
    .await
    {
        Err(_) | Ok(Err(_)) => {
            // 对齐 Go：503 + 双 close 头；result 保持 errWaitAnother
            let _ = client.write_all(RESPONSE_SERVICE_UNAVAILABLE).await;
            return Ok(PlainOutcome::WaitAnother);
        },
        Ok(Ok(resp)) => resp,
    };

    let chunked_resp = headers_indicate_chunked(&resp.headers);
    // 非法 Content-Length 属上游协议错 → 同 503 路径
    let declared_len = match parse_content_length(&resp.headers) {
        Ok(len) => len,
        Err(_) => {
            let _ = client.write_all(RESPONSE_SERVICE_UNAVAILABLE).await;
            return Ok(PlainOutcome::WaitAnother);
        },
    };
    // HEAD / 204 / 304：有长度声明但无 body（Go http.ReadResponse 语义——
    // HEAD 无 CL 头时 ContentLength 也按 0 处理，仍走 keep-alive 分支）
    let bodyless = hs.method == "HEAD" || resp.code == 204 || resp.code == 304;

    if !chunked_resp && (bodyless || declared_len.is_some()) {
        // Go: response.ContentLength >= 0 → keep-alive 三头 + Close=false，
        // result 保持 errWaitAnother
        let head = serialize_response_head(&resp, true);
        client.write_all(&head).await?;
        let body_len = if bodyless { 0 } else { declared_len.unwrap_or(0) };
        copy_exact_n(&mut upstream, client, body_len).await?;
        return Ok(PlainOutcome::WaitAnother);
    }

    // Go: response.Close = true; result = nil —— chunked / close-delimited 不循环
    let head = serialize_response_head(&resp, false);
    client.write_all(&head).await?;
    if !bodyless {
        if chunked_resp {
            forward_chunked_body(&mut upstream, client).await?;
        } else if declared_len.is_none() {
            // close-delimited：透传到上游 EOF
            let mut buf = [0u8; 8192];
            loop {
                let n = upstream.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                client.write_all(&buf[..n]).await?;
            }
        }
    }
    Ok(PlainOutcome::Close)
}

/// 从请求/响应头解析 Content-Length（首个值）。缺失 → None；非法值 → 报错
/// （静默当 0 会截断 body）。
fn parse_content_length(headers: &HashMap<String, Vec<String>>) -> Result<Option<u64>> {
    match headers.get("content-length").and_then(|vals| vals.first()) {
        None => Ok(None),
        Some(v) => v.trim().parse::<u64>().map(Some).map_err(|_| {
            HttpProxyError::InvalidRequest(format!("malformed Content-Length: {v:?}"))
        }),
    }
}

/// 客户端请求是否要求代理级 keep-alive。
///
/// 对应 Go `Process`：`TrimSpace(ToLower(Get("Proxy-Connection"))) == "keep-alive"`。
fn request_keep_alive(headers: &HashMap<String, Vec<String>>) -> bool {
    headers
        .get("proxy-connection")
        .and_then(|vals| vals.first())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("keep-alive"))
}

/// 从请求行 target 提取绝对 URI 的 authority（对齐 Go `request.URL.Host`）。
///
/// 仅 `http://`/`https://` 前缀（absolute-form）有 authority；origin-form /
/// authority-form 返回 `None`（等价 Go `request.URL.Host == ""`）。
fn extract_url_host(target: &str) -> Option<&str> {
    let after_scheme =
        target.strip_prefix("http://").or_else(|| target.strip_prefix("https://"))?;
    let authority = after_scheme.split('/').next().unwrap_or_default();
    (!authority.is_empty()).then_some(authority)
}

/// 上游响应头（解析结果）。
struct ResponseHead {
    /// 原始状态行（如 `HTTP/1.1 200 OK`），回写时原样保留。
    status_line: String,
    /// 状态码。
    code: u16,
    /// 解析出的 headers（key 全小写，同名多值保留）。
    headers: HashMap<String, Vec<String>>,
}

/// 读上游响应头。1xx 中间响应头块原样透传给客户端后继续读最终响应
/// （对齐 Go `readResponseAndHandle100Continue`）。
async fn read_response_head(
    upstream: &mut TcpStream,
    client: &mut TcpStream,
) -> Result<ResponseHead> {
    loop {
        let status_line = read_http_line(upstream).await?;
        let code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or_else(|| {
                HttpProxyError::InvalidRequest(format!("malformed status line: {status_line:?}"))
            })?;
        let mut headers: HashMap<String, Vec<String>> = HashMap::new();
        loop {
            let line = read_http_line(upstream).await?;
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers
                    .entry(k.trim().to_ascii_lowercase())
                    .or_default()
                    .push(v.trim().to_string());
            }
        }
        if (100..200).contains(&code) {
            // 1xx：透传头块，继续读最终响应（非代理处理目标）
            let mut block = format!("{status_line}\r\n");
            for (k, vals) in &headers {
                for v in vals {
                    block.push_str(&format!("{k}: {v}\r\n"));
                }
            }
            block.push_str("\r\n");
            client.write_all(block.as_bytes()).await?;
            continue;
        }
        return Ok(ResponseHead { status_line, code, headers });
    }
}

/// 序列化回写给客户端的响应头：hop-by-hop 头移除后按 keep-alive 分支改写
/// 连接性头（对齐 Go `RemoveHopByHopHeaders` + `response.Header.Set` 三头/
/// `response.Close`）。
fn serialize_response_head(resp: &ResponseHead, keep_alive: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(resp.status_line.as_bytes());
    buf.extend_from_slice(b"\r\n");
    for (key, values) in &resp.headers {
        if HOP_BY_HOP_HEADERS.contains(&key.as_str()) {
            continue;
        }
        for value in values {
            buf.extend_from_slice(key.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
    }
    if keep_alive {
        buf.extend_from_slice(
            b"proxy-connection: keep-alive\r\n\
              connection: keep-alive\r\n\
              keep-alive: timeout=60\r\n\r\n",
        );
    } else {
        buf.extend_from_slice(b"connection: close\r\nproxy-connection: close\r\n\r\n");
    }
    buf
}

/// 定长透传 `n` 字节（请求/响应 body）。上游提前 EOF → 错误（静默截断不可接受）。
async fn copy_exact_n(from: &mut TcpStream, to: &mut TcpStream, n: u64) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    let mut remaining = n;
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let read = from.read(&mut buf[..want]).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("peer closed with {remaining} body bytes remaining"),
            ));
        }
        to.write_all(&buf[..read]).await?;
        remaining -= read as u64;
    }
    Ok(())
}

/// chunked 响应体透传：逐帧 size 行/数据/CRLF/trailer 原样转发，到终止块
/// （size 0 + trailer 结束）为止，不等 EOF——close-delimited 兜底路径才有
/// EOF 语义。帧字节原样透传（不解码重编码），客户端按原 transfer-encoding 解析。
async fn forward_chunked_body(upstream: &mut TcpStream, client: &mut TcpStream) -> Result<()> {
    loop {
        let size_line = read_http_line(upstream).await?;
        let size =
            usize::from_str_radix(size_line.split(';').next().unwrap_or_default().trim(), 16)
                .map_err(|_| {
                    HttpProxyError::InvalidRequest(format!("malformed chunk size: {size_line:?}"))
                })?;
        client.write_all(size_line.as_bytes()).await?;
        client.write_all(b"\r\n").await?;
        if size == 0 {
            // trailer 段透传到空行（无 trailer 时首行即空）
            loop {
                let line = read_http_line(upstream).await?;
                client.write_all(line.as_bytes()).await?;
                client.write_all(b"\r\n").await?;
                if line.is_empty() {
                    return Ok(());
                }
            }
        }
        copy_exact_n(upstream, client, size as u64).await?;
        // 数据帧分隔 CRLF：upstream 侧消费后原样转发（client 侧帧完整性）
        let mut crlf = [0u8; 2];
        upstream.read_exact(&mut crlf).await?;
        client.write_all(&crlf).await?;
    }
}

/// 按 [`Destination`] 拨号 TCP。IP 直连；域名走系统解析（tokio `ToSocketAddrs`）。
async fn dial_destination(dest: &Destination) -> Result<TcpStream> {
    let port = dest.port().value();
    let target = match dest.address().ip() {
        Some(ip) => SocketAddr::new(ip, port),
        None => {
            let domain = dest.address().as_domain().unwrap_or_default();
            return TcpStream::connect((domain, port)).await.map_err(HttpProxyError::Io);
        },
    };
    TcpStream::connect(target).await.map_err(HttpProxyError::Io)
}

/// HTTP proxy 服务端握手。解析请求行 + 认证 + 解析目标。
///
/// 返回 [`HandshakeResult`]（含 dest、method、target、headers）。
/// CONNECT → 回 `200 Connection established`；非 CONNECT → 不回响应（由调用方处理 plain HTTP
/// 转发）。请求行/头协议格式错 → 回 400 后返回错误；EOF（客户端关闭）直接返回错误不回写。
///
/// ## 流程
///
/// 1. 读 HTTP/1.1 请求行（`METHOD TARGET HTTP/1.1\r\n`）
/// 2. 读 headers 直到空行（`\r\n`）
/// 3. 如配置了 accounts：校验 `Proxy-Authorization: Basic <base64>`
/// 4. 解析 dest：CONNECT 的 target（`host:port`）或 Host header
/// 5. CONNECT → 回 `HTTP/1.1 200 Connection established\r\n\r\n`
pub async fn http_server_handshake<RW>(
    stream: &mut RW,
    config: &ServerConfig,
) -> Result<HandshakeResult>
where
    RW: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // 1+2. 读请求行 + headers；协议格式错 → 400 后关连接；
    // EOF（客户端正常关闭）不写 400 直接断
    let (method, target, http_version, headers) = match read_request_head(stream).await {
        Ok(head) => head,
        Err(e @ HttpProxyError::InvalidRequest(_)) => {
            let _ = stream.write_all(RESPONSE_BAD_REQUEST).await;
            return Err(e);
        },
        Err(e) => return Err(e),
    };

    // 3. 认证（如配置了 accounts）
    if !config.accounts.is_empty() {
        let auth_ok = headers
            .get("proxy-authorization")
            .and_then(|vals| vals.first())
            .and_then(|v| parse_basic_auth(v))
            .map(|(user, pass)| config.has_account(&user, &pass))
            .unwrap_or(false);
        if !auth_ok {
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n")
                .await?;
            return Err(HttpProxyError::AuthFailed(
                "invalid or missing Proxy-Authorization".into(),
            ));
        }
    }

    // 4. 解析 dest
    let dest = if method == "CONNECT" {
        parse_host_port(&target, 443)?
    } else {
        // 普通 HTTP 代理从 Host header 提取 dest
        let host = headers
            .get("host")
            .and_then(|vals| vals.first())
            .ok_or_else(|| HttpProxyError::InvalidRequest("missing Host header".into()))?;
        parse_host_port(host, 80)?
    };
    // 4.5 透明代理检查（对应 Go handlePlainHTTP proxy/http/server.go:209：
    // `!AllowTransparent && request.URL.Host == ""` → 400 Bad Request）。
    // target 非绝对 URI（无 scheme）等价 Go `request.URL.Host == ""`。
    if method != "CONNECT" && !config.allow_transparent && !target.contains("://") {
        stream.write_all(RESPONSE_BAD_REQUEST).await?;
        return Err(HttpProxyError::InvalidRequest(
            "origin-form request target requires allowTransparent".into(),
        ));
    }

    // 5. 回 200（CONNECT）
    if method == "CONNECT" {
        stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
    }

    Ok(HandshakeResult { dest, method, target, http_version, headers })
}

/// 读请求行 + headers（握手第 1-2 步）。
///
/// 返回 (method 大写, target, 请求行版本, headers)；EOF/超长行/超行数/malformed 请求行
/// 统一报 [`HttpProxyError::InvalidRequest`]（或 IO 错），由调用方决定 400。
async fn read_request_head<RW>(
    stream: &mut RW,
) -> Result<(String, String, HttpVersion, HashMap<String, Vec<String>>)>
where
    RW: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // 读请求行
    let request_line = read_http_line(stream).await?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(HttpProxyError::InvalidRequest(format!(
            "malformed request line: {request_line:?}"
        )));
    }
    let method = parts[0].to_ascii_uppercase();
    let target = parts[1].to_string();
    let http_version = parse_http_version(parts[2]);

    // 读 headers（最多 [`MAX_HTTP_HEADER_LINES`] 行，防无界头部注入；
    // Go http.ReadRequest 语义下请求行+headers 共享 1MB 总预算，此处按行数收紧）
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();
    let mut header_lines = 0usize;
    loop {
        let line = read_http_line(stream).await?;
        if line.is_empty() {
            break;
        }
        header_lines += 1;
        if header_lines > MAX_HTTP_HEADER_LINES {
            return Err(HttpProxyError::InvalidRequest(format!(
                "too many HTTP header lines (>{MAX_HTTP_HEADER_LINES})"
            )));
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.entry(k.trim().to_ascii_lowercase()).or_default().push(v.trim().to_string());
        }
    }
    Ok((method, target, http_version, headers))
}

/// 单行（请求行/头部行）字节上限。Go `http.ReadRequest` 对请求行+headers 共享
/// `DefaultMaxHeaderBytes`(1MB) 总预算；本实现逐字节读行，按 16KB/行收紧
/// （正常 HTTP 头远低于此），防御恶意无界行撑爆内存。
const MAX_HTTP_LINE_BYTES: usize = 16 * 1024;
/// 请求头最大行数（不含请求行）。Go 无显式行数限制（受 1MB 总预算约束）；
/// 此处 128 行等价收紧，防慢速逐行注入。
const MAX_HTTP_HEADER_LINES: usize = 128;
/// 读一行 HTTP header（到 `\r\n`，返回不含 `\r\n` 的内容）。
async fn read_http_line<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<String> {
    let mut buf = Vec::with_capacity(128);
    let mut prev_was_cr = false;
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await.map_err(HttpProxyError::Io)?;
        if n == 0 {
            if buf.is_empty() {
                // 客户端正常关闭（EOF）不是协议错误：走 Io/UnexpectedEof，
                // 上层不回 400 直接断链（读头中途断仍走 malformed → 400）
                return Err(HttpProxyError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before request",
                )));
            }
            break;
        }
        if prev_was_cr && byte[0] == b'\n' {
            break;
        }
        prev_was_cr = byte[0] == b'\r';
        if !prev_was_cr {
            buf.push(byte[0]);
            if buf.len() > MAX_HTTP_LINE_BYTES {
                return Err(HttpProxyError::InvalidRequest(format!(
                    "http header line exceeds {MAX_HTTP_LINE_BYTES} bytes"
                )));
            }
        }
    }
    String::from_utf8(buf)
        .map_err(|e| HttpProxyError::InvalidRequest(format!("non-utf8 header: {e}")))
}

/// 解析 `host:port` 字符串为 [`Destination`]。无端口时用 `default_port`。
fn parse_host_port(host_port: &str, default_port: u16) -> Result<Destination> {
    // 处理 IPv6 [::1]:443 格式
    if let Some(rest) = host_port.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let ipv6_str = &rest[..end];
            let ip: Ipv6Addr = ipv6_str
                .parse()
                .map_err(|_| HttpProxyError::InvalidRequest(format!("invalid IPv6: {ipv6_str}")))?;
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(default_port);
            return Ok(Destination::tcp(Address::IPv6(ip), Port::new(port)));
        }
    }

    // 普通 host:port
    let (host, port) = match host_port.rfind(':') {
        Some(idx) => {
            let h = &host_port[..idx];
            let p_str = &host_port[idx + 1..];
            // p_str 可能是端口号，也可能是 IPv6 的一部分（如 ::1 无方括号）
            match p_str.parse::<u16>() {
                Ok(port) => (h, port),
                Err(_) => (host_port, default_port),
            }
        },
        None => (host_port, default_port),
    };

    let address = parse_host_to_address(host)?;
    Ok(Destination::tcp(address, Port::new(port)))
}

/// 把 host 字符串转换为 [`Address`]。按 IPv4 → IPv6 → Domain 顺序尝试。
fn parse_host_to_address(host: &str) -> Result<Address> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(Address::IPv4(ip));
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        return Ok(Address::IPv6(ip));
    }
    if host.is_empty() {
        return Err(HttpProxyError::InvalidRequest("empty host".into()));
    }
    Ok(Address::Domain(host.to_string()))
}

/// 解析 `Proxy-Authorization: Basic <base64>` header 值为 (username, password)。
///
/// 对应 Go `parseBasicAuth`。返回 `None` 表示格式不合法。
fn parse_basic_auth(header_value: &str) -> Option<(String, String)> {
    const PREFIX: &str = "Basic ";
    let rest = header_value.strip_prefix(PREFIX)?;
    let decoded = base64_decode(rest)?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let sep = decoded_str.find(':')?;
    Some((decoded_str[..sep].to_string(), decoded_str[sep + 1..].to_string()))
}

/// 手写 base64 解码（标准编码，含 padding）。对应 Go `base64.StdEncoding.DecodeString`。
///
/// 避免 crate 级 base64 依赖（ponytail：15 行手写 < 加 Cargo.toml 依赖）。
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = input.trim_end_matches('=');
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in input.bytes() {
        let val = TABLE.iter().position(|&t| t == c)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::*;

    // ===== base64 / parse_host_port 纯函数测试 =====

    #[test]
    fn base64_decode_vectors() {
        assert_eq!(base64_decode("dXNlcjpwYXNz"), Some(b"user:pass".to_vec()));
        assert_eq!(base64_decode("YWJjZA=="), Some(b"abcd".to_vec()));
        assert_eq!(base64_decode(""), Some(vec![]));
        assert_eq!(base64_decode("!!!"), None);
    }

    #[test]
    fn parse_basic_auth_roundtrip() {
        let (u, p) = parse_basic_auth("Basic dXNlcjpwYXNz").unwrap();
        assert_eq!(u, "user");
        assert_eq!(p, "pass");
        assert!(parse_basic_auth("basic xyz").is_none());
        assert!(parse_basic_auth("Basic bm9jb2xvbg==").is_none()); // no colon
    }

    #[test]
    fn parse_host_port_variants() {
        let d = parse_host_port("example.com:443", 80).unwrap();
        assert_eq!(d.port().value(), 443);

        let d = parse_host_port("example.com", 8080).unwrap();
        assert_eq!(d.port().value(), 8080);

        let d = parse_host_port("1.2.3.4:80", 443).unwrap();
        assert!(matches!(d.address(), Address::IPv4(_)));
        assert_eq!(d.port().value(), 80);

        let d = parse_host_port("[::1]:443", 80).unwrap();
        assert!(matches!(d.address(), Address::IPv6(_)));
        assert_eq!(d.port().value(), 443);

        assert!(parse_host_port("", 80).is_err());
    }

    // ===== plain HTTP 转发辅助函数测试 =====

    #[test]
    fn extract_url_host_variants() {
        assert_eq!(extract_url_host("http://example.com/path"), Some("example.com"));
        assert_eq!(extract_url_host("https://example.com:8443/"), Some("example.com:8443"));
        assert_eq!(extract_url_host("http://example.com"), Some("example.com"));
        // origin-form / authority-form 无绝对 URI host（等价 Go request.URL.Host == ""）
        assert_eq!(extract_url_host("/path?q=1"), None);
        assert_eq!(extract_url_host("example.com:8080"), None);
        assert_eq!(extract_url_host("http:///path"), None);
    }

    #[test]
    fn parse_content_length_variants() {
        let mut h: HashMap<String, Vec<String>> = HashMap::new();
        assert_eq!(parse_content_length(&h).unwrap(), None);
        h.insert("content-length".into(), vec!["123".into()]);
        assert_eq!(parse_content_length(&h).unwrap(), Some(123));
        h.insert("content-length".into(), vec![" 456 ".into()]);
        assert_eq!(parse_content_length(&h).unwrap(), Some(456));
        h.insert("content-length".into(), vec!["abc".into()]);
        assert!(parse_content_length(&h).is_err(), "malformed value must error");
        h.insert("content-length".into(), vec!["-1".into()]);
        assert!(parse_content_length(&h).is_err(), "negative must error");
    }

    #[test]
    fn request_keep_alive_detection() {
        let mut h: HashMap<String, Vec<String>> = HashMap::new();
        assert!(!request_keep_alive(&h));
        h.insert("proxy-connection".into(), vec!["Keep-Alive".into()]);
        assert!(request_keep_alive(&h), "case-insensitive");
        h.insert("proxy-connection".into(), vec![" keep-alive ".into()]);
        assert!(request_keep_alive(&h), "trimmed");
        h.insert("proxy-connection".into(), vec!["close".into()]);
        assert!(!request_keep_alive(&h));
    }

    #[test]
    fn serialize_response_head_keep_alive_branch() {
        let mut headers: HashMap<String, Vec<String>> = HashMap::new();
        headers.insert("content-type".into(), vec!["text/plain".into()]);
        headers.insert("connection".into(), vec!["close".into()]); // hop-by-hop，必被移除
        let resp = ResponseHead { status_line: "HTTP/1.1 200 OK".into(), code: 200, headers };
        let out = String::from_utf8(serialize_response_head(&resp, true)).unwrap();
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "{out}");
        assert!(out.contains("content-type: text/plain\r\n"), "{out}");
        assert!(!out.contains("connection: close"), "old hop-by-hop must go: {out}");
        assert!(out.contains("proxy-connection: keep-alive\r\n"), "{out}");
        assert!(out.contains("connection: keep-alive\r\n"), "{out}");
        assert!(out.contains("keep-alive: timeout=60\r\n"), "{out}");
    }

    #[test]
    fn serialize_response_head_close_branch() {
        let resp = ResponseHead {
            status_line: "HTTP/1.1 200 OK".into(),
            code: 200,
            headers: HashMap::new(),
        };
        let out = String::from_utf8(serialize_response_head(&resp, false)).unwrap();
        assert!(out.contains("connection: close\r\n"), "{out}");
        assert!(out.contains("proxy-connection: close\r\n"), "{out}");
        assert!(!out.contains("keep-alive"), "{out}");
    }

    // ===== TCP 端到端 handshake 测试 =====

    /// 简化 helper：bind TCP listener, client 发请求字节, server 跑 handshake, 返回 (response_str,
    /// result)
    async fn tcp_handshake(
        request: &[u8],
        config: ServerConfig,
    ) -> (String, std::result::Result<HandshakeResult, HttpProxyError>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            http_server_handshake(&mut stream, &config).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(request).await.unwrap();
        client.flush().await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut response = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_millis(100), client.read(&mut response))
            .await
            .map(|r| r.unwrap_or(0))
            .unwrap_or(0);
        response.truncate(n);

        let result = server.await.unwrap();
        (String::from_utf8_lossy(&response).to_string(), result)
    }

    #[tokio::test]
    async fn handshake_connect_no_auth_200() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let (resp, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert_eq!(hs.method, "CONNECT");
        assert_eq!(hs.dest.port().value(), 443);
        assert!(resp.contains("200"), "got: {resp}");
    }

    #[tokio::test]
    async fn handshake_connect_valid_auth_200() {
        let req =
            b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n";
        let mut cfg = ServerConfig::default();
        cfg.accounts.insert("user".into(), "pass".into());
        let (resp, result) = tcp_handshake(req, cfg).await;
        result.unwrap();
        assert!(resp.contains("200"), "got: {resp}");
    }

    #[tokio::test]
    async fn handshake_connect_invalid_auth_407() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic d3Jvbmc6Y3JlZHM=\r\n\r\n";
        let mut cfg = ServerConfig::default();
        cfg.accounts.insert("user".into(), "pass".into());
        let (resp, result) = tcp_handshake(req, cfg).await;
        assert!(result.is_err());
        assert!(resp.contains("407"), "got: {resp}");
        assert!(resp.contains("Proxy-Authenticate"));
    }

    #[tokio::test]
    async fn handshake_rejects_oversized_line() {
        // 请求行超长（> MAX_HTTP_LINE_BYTES）→ InvalidRequest。Go http.ReadRequest
        // 以 DefaultMaxHeaderBytes(1MB) 总预算拒绝超界流量，此处按 16KB/行收紧。
        let mut req = b"CONNECT ".to_vec();
        req.extend(std::iter::repeat_n(b'a', MAX_HTTP_LINE_BYTES + 1));
        req.extend_from_slice(b":443 HTTP/1.1\r\n\r\n");
        let (_, result) = tcp_handshake(&req, ServerConfig::default()).await;
        assert!(result.is_err(), "oversized request line must be rejected");
    }

    #[tokio::test]
    async fn handshake_rejects_too_many_header_lines() {
        // 129 个 header 行（> MAX_HTTP_HEADER_LINES）→ InvalidRequest。
        // Go 无显式行数限制（1MB 总预算约束），此处按 128 行收紧。
        let mut req = b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec();
        for i in 0..=MAX_HTTP_HEADER_LINES {
            req.extend_from_slice(format!("X-Pad-{i}: v\r\n").as_bytes());
        }
        req.extend_from_slice(b"\r\n");
        let (_, result) = tcp_handshake(&req, ServerConfig::default()).await;
        assert!(result.is_err(), "too many header lines must be rejected");
    }

    #[tokio::test]
    async fn handshake_connect_missing_auth_407() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let mut cfg = ServerConfig::default();
        cfg.accounts.insert("admin".into(), "secret".into());
        let (resp, result) = tcp_handshake(req, cfg).await;
        assert!(result.is_err());
        assert!(resp.contains("407"), "got: {resp}");
    }

    #[tokio::test]
    async fn handshake_connect_ipv4_dest() {
        let req = b"CONNECT 1.2.3.4:8080 HTTP/1.1\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert!(matches!(hs.dest.address(), Address::IPv4(_)));
        assert_eq!(hs.dest.port().value(), 8080);
    }

    #[tokio::test]
    async fn handshake_connect_ipv6_dest() {
        let req = b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert!(matches!(hs.dest.address(), Address::IPv6(_)));
        assert_eq!(hs.dest.port().value(), 443);
    }

    #[tokio::test]
    async fn handshake_connect_default_port_443() {
        let req = b"CONNECT example.com HTTP/1.1\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert_eq!(hs.dest.port().value(), 443);
    }

    #[tokio::test]
    async fn handshake_get_extracts_host_port_80() {
        let req = b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert_eq!(hs.method, "GET");
        assert!(matches!(hs.dest.address(), Address::Domain(_)));
        assert_eq!(hs.dest.port().value(), 80);
    }

    // ===== plain HTTP proxy 辅助函数测试 =====

    #[test]
    fn extract_request_path_absolute_url() {
        assert_eq!(extract_request_path("http://example.com/path?q=1"), "/path?q=1");
        assert_eq!(extract_request_path("https://example.com/"), "/");
        assert_eq!(extract_request_path("http://example.com:8080/deep/path"), "/deep/path");
    }

    #[test]
    fn extract_request_path_no_path() {
        assert_eq!(extract_request_path("http://example.com"), "/");
        assert_eq!(extract_request_path("example.com:8080"), "/");
    }

    #[test]
    fn extract_request_path_transparent() {
        assert_eq!(extract_request_path("/index.html"), "/index.html");
        assert_eq!(extract_request_path("/"), "/");
    }

    #[test]
    fn build_forwarded_request_strips_hop_by_hop() {
        let mut headers = HashMap::new();
        headers.insert("host".into(), vec!["example.com".into()]);
        headers.insert("proxy-connection".into(), vec!["keep-alive".into()]);
        headers.insert("connection".into(), vec!["keep-alive".into()]);
        headers.insert("user-agent".into(), vec!["curl/8.0".into()]);
        headers.insert("proxy-authorization".into(), vec!["Basic abc".into()]);

        let req = build_forwarded_request("GET", "/path", &headers);
        let req_str = String::from_utf8(req).unwrap();

        assert!(req_str.starts_with("GET /path HTTP/1.1\r\n"));
        assert!(req_str.contains("host: example.com"));
        assert!(req_str.contains("user-agent: curl/8.0"));
        assert!(!req_str.contains("proxy-connection"));
        assert!(!req_str.contains("proxy-authorization"));
        assert!(req_str.contains("connection: close\r\n\r\n"));
    }

    #[test]
    fn build_forwarded_request_post() {
        let mut headers = HashMap::new();
        headers.insert("host".into(), vec!["api.example.com".into()]);
        headers.insert("content-length".into(), vec!["42".into()]);

        let req = build_forwarded_request("POST", "/submit", &headers);
        let req_str = String::from_utf8(req).unwrap();

        assert!(req_str.starts_with("POST /submit HTTP/1.1\r\n"));
        assert!(req_str.contains("content-length: 42"));
    }

    #[test]
    fn build_forwarded_request_keeps_transfer_encoding() {
        // bd 04n8：chunked body 原样透传，transfer-encoding 头必须保留——
        // 剥掉后目标按无 body 解析，chunked 帧被当垃圾丢弃。
        let mut headers = HashMap::new();
        headers.insert("host".into(), vec!["echo.example".into()]);
        headers.insert("transfer-encoding".into(), vec!["chunked".into()]);

        let req = build_forwarded_request("POST", "/upload", &headers);
        let req_str = String::from_utf8(req).unwrap();

        assert!(req_str.contains("transfer-encoding: chunked\r\n"));
        assert!(req_str.contains("connection: close\r\n\r\n"));
    }

    #[test]
    fn build_forwarded_request_keeps_multi_value_headers() {
        // bd z8i0：同名多值头（双 Cookie）逐行保留，不折叠丢失（Go request.Write 语义）
        let mut headers = HashMap::new();
        headers.insert("host".into(), vec!["api.example.com".into()]);
        headers.insert("cookie".into(), vec!["a=1".into(), "b=2".into()]);

        let req = build_forwarded_request("GET", "/", &headers);
        let req_str = String::from_utf8(req).unwrap();

        assert!(req_str.contains("cookie: a=1\r\n"));
        assert!(req_str.contains("cookie: b=2\r\n"));
    }

    #[tokio::test]
    async fn handshake_get_returns_target_and_headers() {
        let req = b"GET http://example.com/page?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert_eq!(hs.method, "GET");
        assert_eq!(hs.target, "http://example.com/page?q=1");
        assert_eq!(hs.headers["host"][0], "example.com");
        assert_eq!(hs.headers["user-agent"][0], "test");
    }

    #[tokio::test]
    async fn handshake_preserves_multi_value_headers() {
        // bd z8i0：同一 header 出现两次（双 Cookie）都保留，按序 push
        let req = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert_eq!(hs.headers["cookie"], vec!["a=1".to_string(), "b=2".to_string()]);
    }

    // ===== allowTransparent（透明代理）分支 =====

    #[tokio::test]
    async fn handshake_origin_form_rejected_without_allow_transparent() {
        // origin-form（相对路径 target）在非透明模式下 400，对齐 Go
        // proxy/http/server.go:209 `!AllowTransparent && request.URL.Host == ""`。
        let req = b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (resp, result) = tcp_handshake(req, ServerConfig::default()).await;
        assert!(result.is_err(), "origin-form should be rejected");
        assert!(resp.contains("400"), "got: {resp}");
        assert!(resp.contains("Connection: close"), "got: {resp}");
    }

    #[tokio::test]
    async fn handshake_origin_form_allowed_with_transparent() {
        // allowTransparent=true 放行 origin-form，dest 从 Host header 解析。
        let req = b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let cfg = ServerConfig { allow_transparent: true, ..Default::default() };
        let (_, result) = tcp_handshake(req, cfg).await;
        let hs = result.unwrap();
        assert_eq!(hs.method, "GET");
        assert_eq!(hs.target, "/path?q=1");
        assert!(matches!(hs.dest.address(), Address::Domain(_)));
    }

    #[tokio::test]
    async fn handshake_absolute_url_unaffected_by_transparent_flag() {
        // 绝对 URI（代理正规形态）不受 allowTransparent 影响。
        let req = b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (resp, result) = tcp_handshake(req, ServerConfig::default()).await;
        assert!(result.is_ok());
        assert!(!resp.contains("400"), "got: {resp}");
    }

    #[tokio::test]
    async fn start_close_releases_listener_port() {
        // 回归测试 68n: close 后 accept loop abort，端口释放
        let server = HttpServer::new("test-close", ServerConfig::default());
        server.start().await.unwrap();
        let port = server
            .slot
            .lock()
            .await
            .as_ref()
            .and_then(|(l, _)| l.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(0);
        assert!(port > 0, "server should bind to a port");

        server.close().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let addr = format!("127.0.0.1:{port}");
        let result = tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(&addr)).await;
        if let Ok(Ok(_)) = result {
            panic!("listener should be closed after close()");
        }
    }

    // ===== 连接终结性测试（对齐 Go：CONNECT 终结，无 keep-alive 循环）=====

    /// 起 HttpServer 并返回 (server, 绑定端口)。server 需保活到断言结束。
    async fn start_server(config: ServerConfig) -> (HttpServer, u16) {
        let server = HttpServer::new("test-ka", config);
        server.start().await.unwrap();
        let port = server
            .slot
            .lock()
            .await
            .as_ref()
            .and_then(|(l, _)| l.local_addr().ok())
            .map(|a| a.port())
            .expect("server should bind a port");
        (server, port)
    }

    /// 制造一个当前无监听的端口（bind 后立刻 drop；端口被第三方复用的竞态
    /// 概率可忽略，仅本地测试用）。
    async fn dead_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr.port()
    }

    /// 回显 TCP 服务：读到什么回什么，EOF 关闭。
    async fn spawn_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            },
                        }
                    }
                });
            }
        });
        (addr, handle)
    }

    /// 逐字节读到 HTTP 响应头结束（`\r\n\r\n`），返回响应头文本。
    async fn read_response_head(client: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = client.read(&mut byte).await.unwrap();
            assert!(n > 0, "unexpected EOF while reading response head");
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
            assert!(buf.len() < 8192, "response head too large");
        }
        String::from_utf8(buf).unwrap()
    }

    async fn read_eof(client: &mut TcpStream) -> usize {
        let mut byte = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(5), client.read(&mut byte))
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0)
    }

    #[tokio::test]
    async fn connect_dial_failure_closes_connection() {
        // 对齐 Go `handleConnect`：dial/DispatchLink 失败 → 错误返回 → 连接关闭。
        // 200 已回（对齐 Go：200 在 dial 前写），客户端读到 EOF。
        let dead = dead_port().await;
        let (_server, port) = start_server(ServerConfig::default()).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client
            .write_all(format!("CONNECT 127.0.0.1:{dead} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let resp = tokio::time::timeout(Duration::from_secs(5), read_response_head(&mut client))
            .await
            .expect("response timeout");
        assert!(resp.contains("200"), "got: {resp}");
        assert_eq!(read_eof(&mut client).await, 0, "dial failure must close connection");
    }

    #[tokio::test]
    async fn connect_tunnel_echo_then_close() {
        // 派单验收①"数据正确" + 返工①：CONNECT tunnel 建立后双向转发，echo
        // 回显逐字节一致；tunnel 结束（客户端写半关）后连接必须关闭
        // （Go handleConnect → return 语义）。
        let (echo_addr, echo) = spawn_echo().await;
        let (_server, port) = start_server(ServerConfig::default()).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(format!("CONNECT {echo_addr} HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
        let resp = read_response_head(&mut client).await;
        assert!(resp.contains("200"), "got: {resp}");

        client.write_all(b"ping-1").await.unwrap();
        let mut echoed = [0u8; 6];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echoed))
            .await
            .expect("echo roundtrip timeout")
            .unwrap();
        assert_eq!(&echoed, b"ping-1");

        // 写半关驱动 tunnel EOF → 服务端终结连接
        client.shutdown().await.unwrap();
        assert_eq!(read_eof(&mut client).await, 0, "server should close after tunnel EOF");
        echo.abort();
    }

    #[tokio::test]
    async fn keepalive_connection_close_terminates() {
        // `Connection: close` 头被容忍且行为不变：200 响应后服务端必须关闭。
        // （CONNECT 本就终结，close 头不再改变结局——钉住该头不引发异常路径。）
        let dead = dead_port().await;
        let (_server, port) = start_server(ServerConfig::default()).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client
            .write_all(
                format!("CONNECT 127.0.0.1:{dead} HTTP/1.1\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let resp = tokio::time::timeout(Duration::from_secs(5), read_response_head(&mut client))
            .await
            .expect("response timeout");
        assert!(resp.contains("200"), "got: {resp}");
        assert_eq!(read_eof(&mut client).await, 0, "server must close after Connection: close");
    }

    #[tokio::test]
    async fn connect_proxy_connection_close_terminates() {
        // `Proxy-Connection: close` 头被容忍且行为不变（CONNECT 本就终结）。
        let dead = dead_port().await;
        let (_server, port) = start_server(ServerConfig::default()).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client
            .write_all(
                format!("CONNECT 127.0.0.1:{dead} HTTP/1.1\r\nProxy-Connection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let resp = tokio::time::timeout(Duration::from_secs(5), read_response_head(&mut client))
            .await
            .expect("response timeout");
        assert!(resp.contains("200"), "got: {resp}");
        assert_eq!(
            read_eof(&mut client).await,
            0,
            "server must close after Proxy-Connection: close"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn connect_idle_timeout_closes_connection() {
        // 连上不发请求 → 60s（Go policy Handshake 默认）后关闭。
        // start_paused 下 tokio auto-advance 虚拟时钟，测试瞬时完成。
        let (_server, port) = start_server(ServerConfig::default()).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut byte = [0u8; 1];
        let n = client.read(&mut byte).await.unwrap_or(0);
        assert_eq!(n, 0, "server should close connection after idle timeout");
    }

    #[tokio::test]
    async fn malformed_request_400_then_close() {
        // 头解析失败 → 400 → 关连接。
        let (_server, port) = start_server(ServerConfig::default()).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(b"GARBAGE\r\n\r\n").await.unwrap();
        let resp = tokio::time::timeout(Duration::from_secs(5), read_response_head(&mut client))
            .await
            .expect("400 response timeout");
        assert!(resp.contains("400"), "got: {resp}");
        assert_eq!(read_eof(&mut client).await, 0, "connection must close after 400");
    }

    // ===== plain HTTP TE 语义（Go net/http transfer.go parseTransferEncoding）=====

    /// 驱动一次 `handle_plain_http`：mock 上游回显收到的请求头 + 固定 200 响应，
    /// 返回 (上游 task 句柄, 客户端收到的响应头, handler 结论)。提前 return 的
    /// 路径（如 400）不会拨上游——句柄保持 pending，调用方按需 await。
    async fn run_plain_http(
        http_version: HttpVersion,
        headers: &[(&str, &str)],
    ) -> (tokio::task::JoinHandle<String>, String, PlainOutcome) {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut sock, _) = upstream_listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                head.extend_from_slice(&buf[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            String::from_utf8(head).unwrap()
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let server_side = tokio::spawn(async move { proxy_listener.accept().await.unwrap().0 });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let mut server_stream = server_side.await.unwrap();

        let dest = parse_host_port(&format!("127.0.0.1:{}", upstream_addr.port()), 80).unwrap();
        let mut hs = HandshakeResult {
            dest,
            method: "POST".into(),
            target: format!("http://127.0.0.1:{}/up", upstream_addr.port()),
            http_version,
            headers: headers.iter().map(|(k, v)| (k.to_string(), vec![v.to_string()])).collect(),
        };
        let outcome = handle_plain_http(&mut server_stream, &mut hs).await.unwrap();
        drop(server_stream);
        client.shutdown().await.unwrap();
        let mut resp = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut resp)).await;
        (upstream, String::from_utf8_lossy(&resp).into_owned(), outcome)
    }

    #[tokio::test]
    async fn plain_http_h10_transfer_encoding_ignored_like_go() {
        // Go net/http 对 1.0 忽略 TE（删头、按 CL/无 body 定界）：不 400，
        // 转发头不含 transfer-encoding。
        let (upstream, client_resp, outcome) = run_plain_http(
            HttpVersion::H10,
            &[("transfer-encoding", "chunked"), ("host", "127.0.0.1")],
        )
        .await;
        let upstream_head = upstream.await.unwrap();
        assert!(
            !upstream_head.to_ascii_lowercase().contains("transfer-encoding"),
            "1.0 TE must be stripped, forwarded head = {upstream_head}"
        );
        assert!(client_resp.starts_with("HTTP/1.1 200"), "got: {client_resp}");
        assert_eq!(outcome, PlainOutcome::WaitAnother);
    }

    #[tokio::test]
    async fn plain_http_h11_chunked_still_rejected() {
        // 1.1 chunked 请求体维持既有 400 拒绝（本实现无 body 帧解析）；
        // 提前 return 未拨上游（句柄 pending），不 await。
        let (_upstream, client_resp, outcome) = run_plain_http(
            HttpVersion::H11,
            &[("transfer-encoding", "chunked"), ("host", "127.0.0.1")],
        )
        .await;
        assert!(client_resp.starts_with("HTTP/1.1 400"), "got: {client_resp}");
        assert_eq!(outcome, PlainOutcome::Close);
    }
}
