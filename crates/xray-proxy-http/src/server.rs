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
    sync::{Arc, LazyLock},
    time::Duration,
};

use async_trait::async_trait;
use skeleton_infra::fx::{FxScope, Spawned};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_features::inbound::{InboundError, InboundHandler};
use xray_frame::LogFacade;

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
    /// 请求行版本段（HTTP/1.0 侧剥除 Transfer-Encoding 等按版本分叉，
    /// Go net/http transfer.go `parseTransferEncoding`）。
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
///
/// 头序对齐 Go `Response.Write`（`net/http/header.go:186-224` 按 canonical 名排序 +
/// `response.go` 尾段补 CL:0）：`Connection` 先于 `Proxy-Connection`，`Content-Length: 0`
/// 落在最后（Go 实测锚点：同一构造路径的 503 头块）。
const RESPONSE_BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\n\
    Connection: close\r\n\
    Proxy-Connection: close\r\n\
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
        Some(slash) => escape_path(&after_scheme[slash..]),
        None => "/".to_string(),
    }
}

// 字节 ↔ String 的无损承载共用件（头行由 `from_utf8_lossy` 会把 `e9ff` 变成
// `efbfbdefbfbd`，bd t3lzr；DNS QNAME 同款需求）。实现在 `xray-common::text`，
// 此处 re-export 保持既有 `xray_proxy_http::latin1_*` 调用点不变（禁复制第二份）。
pub use xray_common::text::{latin1_decode, latin1_encode};

/// 只剥 SP / HTAB（Go `textproto.trimString` 语义）。
///
/// `str::trim` 连带剥掉 U+0085 / U+00A0 等 Unicode 空白——Latin-1 解码后它们正是
/// 原始字节 0x85 / 0xA0，剥掉即丢字节。
pub fn trim_ows(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\t')
}

/// 路径段里的非 ASCII 字节 → `%XX`（Go `url.URL.EscapedPath`：`URL.Path` 按字节
/// 重新转义，≥0x80 不在 `encodePath` 允许集内，实测锚点 `/t2/\xe9` → `/t2/%E9`）。
///
/// query（`?` 之后）在 Go 侧走 `RawQuery` 原样写出，故保持原字节不动。
///
/// shortcut: 只转义 ≥0x80 字节——Go `encodePath` 还会转义 `" < > [ ] { } | \ ^ \``
/// 这类可打印 ASCII（客户端本就会先转义，实测对拍未覆盖）；需要逐字符对齐 Go 转义集
/// 时再扩。
fn escape_path(path_and_query: &str) -> String {
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };
    let mut out = String::with_capacity(path_and_query.len());
    for b in latin1_encode(path) {
        if b < 0x80 {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    if let Some(q) = query {
        out.push('?');
        out.push_str(q);
    }
    out
}

/// 构建转发给目标服务器的 HTTP 请求（request line + headers）。
///
/// 布局对齐 Go `handlePlainHTTP` 的 `request.Write`（`net/http/request.go:674-735`）：
/// 1. 请求行；
/// 2. `Host: <host>`（`request.go:679` 单独先写）；
/// 3. `User-Agent: <v>`（仅当头存在且非空；Go 对空 UA 不写）；
/// 4. `transferWriter.writeHeader`：chunked 时 `Transfer-Encoding: chunked`， 否则 `Content-Length:
///    N`（`transfer.go:278-320` + `shouldSendContentLength`）；
/// 5. 其余头（含强制 `Connection: close`）按 canonical 名排序（`header.go:167-224`
///    `WriteSubset`），跳过头名在 `Connection` 值中点名的那些头 （`RemoveHopByHopHeaders`，Go
///    `common/protocol/http/headers.go:59-66`）。
///
/// 头名写 canonical 形态、头序确定——上游可见字节与 Go 逐字节一致（D-H7/D-H8）；
/// 排序也消除了原 `HashMap` 迭代序导致的每次运行头序不同（非确定性）。
pub fn build_forwarded_request(
    method: &str,
    path: &str,
    headers: &HashMap<String, Vec<String>>,
) -> Vec<u8> {
    // 删除集 = hop-by-hop 固定名单 + `Connection` 头点名的其它头。
    let mut named: Vec<String> = Vec::new();
    if let Some(values) = headers.get("connection") {
        for value in values {
            for token in value.split(',') {
                named.push(trim_ows(token).to_ascii_lowercase());
            }
        }
    }
    let is_hop = |key: &str| HOP_BY_HOP_HEADERS.contains(&key) || named.iter().any(|n| n == key);
    let first = |key: &str| headers.get(key).and_then(|values| values.first());

    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(method.as_bytes());
    buf.push(b' ');
    // 头值/路径按 Latin-1 还原原始字节（读入侧 [`latin1_decode`] 的逆）：非 UTF-8
    // 头值原样到达上游（bd t3lzr）。方法名与头名已被 tchar 校验为 ASCII。
    buf.extend_from_slice(&latin1_encode(path));
    buf.extend_from_slice(b" HTTP/1.1\r\n");

    // Go 恒写 Host 行（空 host 亦是合法 Host 值）。
    buf.extend_from_slice(b"Host: ");
    buf.extend_from_slice(&latin1_encode(first("host").map_or("", String::as_str)));
    buf.extend_from_slice(b"\r\n");
    if let Some(ua) = first("user-agent").filter(|value| !value.is_empty()) {
        buf.extend_from_slice(b"User-Agent: ");
        buf.extend_from_slice(&latin1_encode(ua));
        buf.extend_from_slice(b"\r\n");
    }

    // transferWriter：chunked 优先（`shouldSendContentLength` 在 chunked 时返 false）。
    let chunked = headers.get("transfer-encoding").is_some_and(|values| {
        values.len() == 1 && trim_ows(&values[0]).eq_ignore_ascii_case("chunked")
    });
    if chunked {
        buf.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    } else if let Some(n) = first("content-length")
        .and_then(|value| trim_ows(value).parse::<u64>().ok())
        .filter(|n| *n > 0 || matches!(method, "POST" | "PUT" | "PATCH"))
    {
        // Go 写的是解析后的十进制值（`strconv.FormatInt`），不是原始字符串。
        buf.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
    }

    // 其余头：canonical 名 + 按名排序；`Connection: close` 参与同一排序
    // （Go 由 `request.Header.Set("Connection","close")` 放入 map 后经 WriteSubset 写出）。
    let mut entries: Vec<(String, Vec<&str>)> = headers
        .iter()
        .filter(|(key, _)| {
            !matches!(key.as_str(), "host" | "user-agent" | "content-length" | "transfer-encoding")
                && !is_hop(key)
        })
        .map(|(key, values)| {
            (canonical_header_key(key), values.iter().map(String::as_str).collect())
        })
        .collect();
    entries.push(("Connection".into(), vec!["close"]));
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, values) in entries {
        for value in values {
            buf.extend_from_slice(&latin1_encode(&key));
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(&latin1_encode(value));
            buf.extend_from_slice(b"\r\n");
        }
    }
    buf.extend_from_slice(b"\r\n");
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
    /// 域规范日志门面（nn8os 2b 打回处置，socks SocksServer 同型）：target 钉死
    /// `xray_frame::http` + mask_secrets 过 L3；spawn 任务只持克隆门面。
    log: LogFacade,
}

impl HttpServer {
    /// 构造 HTTP 代理服务端。
    #[must_use]
    pub fn new(tag: impl Into<String>, config: ServerConfig) -> Self {
        Self {
            tag: tag.into(),
            config,
            slot: Mutex::new(None),
            fx: Arc::new(FxScope::new()),
            log: LogFacade::new("http", vec![]),
        }
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
        self.log.info(format!("HTTP proxy server started tag={} addr={bound}", self.tag));

        let tag = self.tag.clone();
        let config = self.config.clone();
        let listener_clone = Arc::clone(&listener);
        let fx = Arc::clone(&self.fx);
        // 预制克隆源：async move 块捕获 fx_conns，避免块自捕获 fx 与 spawn 接收者
        // 借用冲突（E0505）。
        let fx_conns = Arc::clone(&fx);
        // 任务内日志只持克隆门面（spawn 的 future 不得借用 self；socks 同款）。
        let log = self.log.clone();
        let handle = fx
            .spawn_tracked(async move {
                loop {
                    match listener_clone.accept().await {
                        Ok((stream, peer)) => {
                            let tag = tag.clone();
                            let config = config.clone();
                            let fx = Arc::clone(&fx_conns);
                            fx.spawn_tracked(async move {
                                handle_connection(stream, config, tag, peer).await;
                            })
                            .expect("internal FxScope is never closed");
                        },
                        Err(e) => {
                            log.warn(format!("accept failed tag={tag} error={e}"));
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
            self.log.info(format!("HTTP proxy server closed tag={}", self.tag));
        }
        Ok(())
    }

    fn port(&self) -> u16 {
        // 同步方法无法读 async Mutex; 返回 0 让调用方用 bound_port().await
        0
    }
}

/// 连接处理路径诊断门面（nn8os 2b 同型处置：tracing 宏 → LogFacade——本项目
/// 工具链上 `disallowed_macros` 对 proc-macro 不认任何 allow（fn/stmt/文件顶
/// 三形态实测无效），迁移为唯一关红路径。域 = "http"，target 钉死
/// `xray_frame::http` + mask_secrets。free 函数不持 ctx，模块级门面 = 最小
/// 涟漪形态（socks RELAY_LOG / dokodemo OUTBOUND_LOG 同款；克隆穿参需改
/// 3 个私有签名无收益）。
static CONN_LOG: LazyLock<LogFacade> = LazyLock::new(|| LogFacade::new("http", vec![]));

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
                CONN_LOG.info(format!(
                    "HTTP proxy connection idle/header timeout, closing tag={tag} \
                     peer={peer} timeout={REQUEST_HEADER_TIMEOUT:?}"
                ));
                return;
            },
            Ok(Err(e)) => {
                // 400/407 响应已在 handshake 内写回；EOF/解析失败一律关闭
                CONN_LOG.warn(format!(
                    "HTTP proxy handshake failed, closing connection tag={tag} \
                     peer={peer} error={e}"
                ));
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
                    CONN_LOG.warn(format!(
                        "plain HTTP forwarding failed, closing connection tag={tag} \
                         peer={peer} method={} error={e}",
                        hs.method
                    ));
                },
            }
            return;
        }
        CONN_LOG.info(format!(
            "HTTP proxy CONNECT established tag={tag} peer={peer} dest={:?}",
            hs.dest
        ));
        // CONNECT 终结性（对齐 Go handleConnect → return）：tunnel 成功、dial 失败、
        // 拷贝错误任一结局都关连接——隧道结束后字节流已非 HTTP 边界。
        match dial_destination(&hs.dest).await {
            Err(e) => {
                CONN_LOG.warn(format!(
                    "CONNECT dial failed, closing connection tag={tag} peer={peer} \
                     dest={:?} error={e}",
                    hs.dest
                ));
            },
            Ok(mut upstream) => {
                if let Err(e) = tokio::io::copy_bidirectional(stream, &mut upstream).await {
                    CONN_LOG.warn(format!(
                        "CONNECT tunnel copy failed, closing connection tag={tag} \
                         peer={peer} dest={:?} error={e}",
                        hs.dest
                    ));
                    return;
                }
                CONN_LOG.info(format!(
                    "CONNECT tunnel finished, closing connection tag={tag} dest={:?}",
                    hs.dest
                ));
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
        CONN_LOG.warn(format!(
            "chunked request body not supported by plain HTTP forwarding method={}",
            hs.method
        ));
        let _ = client.write_all(RESPONSE_BAD_REQUEST).await;
        return Ok(PlainOutcome::Close);
    }
    let req_body_len = parse_content_length(&hs.headers)?;

    // Go `handlePlainHTTP`：`request.Host = request.URL.Host`（绝对 URI 的 host
    // 优先，origin-form 时即 Host 头）→ 转发请求的 Host 头用同一个值。
    if let Some(host) = resolve_request_host(&hs.target, &hs.headers) {
        hs.headers.insert("host".into(), vec![host]);
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
    // Go `response.ContentLength`（readTransfer/fixLength 语义）：chunked → -1；
    // HEAD → 声明的 CL（无则 0）；204/304 → 0；其余 → 声明的 CL（无则 -1）。
    // `>= 0` ⇔ Go 的 keep-alive 三头 + `response.Close = false`。
    let effective_cl: Option<u64> = if chunked_resp {
        None
    } else if bodyless {
        Some(if hs.method == "HEAD" { declared_len.unwrap_or(0) } else { 0 })
    } else {
        declared_len
    };
    let keep_alive = effective_cl.is_some();

    if keep_alive {
        // Go: response.ContentLength >= 0 → keep-alive 三头 + Close=false，
        // result 保持 errWaitAnother
        let head = serialize_go_response_head(
            &resp.status_line,
            resp.code,
            &resp.headers,
            effective_cl,
            chunked_resp,
        );
        client.write_all(&head).await?;
        let body_len = if bodyless { 0 } else { declared_len.unwrap_or(0) };
        copy_exact_n(&mut upstream, client, body_len).await?;
        return Ok(PlainOutcome::WaitAnother);
    }

    // Go: response.Close = true; result = nil —— chunked / close-delimited 不循环
    let head = serialize_go_response_head(
        &resp.status_line,
        resp.code,
        &resp.headers,
        effective_cl,
        chunked_resp,
    );
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
#[must_use]
pub fn request_keep_alive(headers: &HashMap<String, Vec<String>>) -> bool {
    headers
        .get("proxy-connection")
        .and_then(|vals| vals.first())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("keep-alive"))
}

/// 从请求行 target 提取绝对 URI 的 authority（对齐 Go `request.URL.Host`）。
///
/// 仅 `http://`/`https://` 前缀（absolute-form）有 authority；origin-form /
/// authority-form 返回 `None`（等价 Go `request.URL.Host == ""`）。
/// scheme 大小写不敏感（Go `url.Parse` 会把 scheme 归一为小写）。
///
/// authority 里的 `user:pass@` 归 `URL.User`，不进 host（Go `net/url`
/// `parseAuthority`：`LastIndex("@")` 之后才是 host）——不剥会把整段当域名去解析，
/// 必然 503（H30）。
fn extract_url_host(target: &str) -> Option<&str> {
    let lower = target.get(..target.len().min(8))?.to_ascii_lowercase();
    let after_scheme = if lower.starts_with("http://") {
        target.get(7..)?
    } else if lower.starts_with("https://") {
        target.get(8..)?
    } else {
        return None;
    };
    let authority = after_scheme.split('/').next().unwrap_or_default();
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    (!host.is_empty()).then_some(host)
}

/// 请求目标 host（Go `http.ReadRequest` + `Process` 语义）。
///
/// Go：`request.Host = request.URL.Host`，URL 的 host 为空时才取 Host 头
/// （net/http/request.go:1149）——即**绝对 URI 的 host 决定路由**，客户端给的
/// Host 头只在 origin-form 时生效（空 Host 头 → 无 host → Go 报
/// "malformed proxy host" 断链）。重复 Host 已在读头阶段拒收。
#[must_use]
pub fn resolve_request_host(
    target: &str,
    headers: &HashMap<String, Vec<String>>,
) -> Option<String> {
    if let Some(host) = extract_url_host(target) {
        return Some(host.to_string());
    }
    headers
        .get("host")
        .and_then(|vals| vals.first())
        .map(|v| trim_ows(v).to_string())
        .filter(|v| !v.is_empty())
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
                    .entry(trim_ows(k).to_ascii_lowercase())
                    .or_default()
                    .push(trim_ows(v).to_string());
            }
        }
        if (100..200).contains(&code) {
            // 1xx：透传头块，继续读最终响应（非代理处理目标）。逐字节还原
            // （Latin-1 逆编码），非 UTF-8 头值不在透传中变形。
            let mut block = Vec::with_capacity(256);
            block.extend_from_slice(&latin1_encode(&status_line));
            block.extend_from_slice(b"\r\n");
            for (k, vals) in &headers {
                for v in vals {
                    block.extend_from_slice(&latin1_encode(k));
                    block.extend_from_slice(b": ");
                    block.extend_from_slice(&latin1_encode(v));
                    block.extend_from_slice(b"\r\n");
                }
            }
            block.extend_from_slice(b"\r\n");
            client.write_all(&block).await?;
            continue;
        }
        return Ok(ResponseHead { status_line, code, headers });
    }
}

/// Go `http.Response.Write` 的响应头字节布局（Go v26.10.17 实测逐字节对齐）。
///
/// Go 的写出顺序（net/http/response.go:296-330 + transfer.go:278-330）：
/// 1. 状态行 + CRLF；
/// 2. `transferWriter.writeHeader`：`Close` 时先写 `Connection: close` （hop-by-hop 已移除 → map
///    内无 Connection token → 必写），随后 `Content-Length: N`（CL > 0）或 `Transfer-Encoding:
///    chunked`；
/// 3. 其余响应头：`Header.WriteSubset` 语义——canonical 名 + 按名排序 + 逐值成行 （排除
///    Content-Length / Transfer-Encoding / Trailer 与 hop-by-hop）； keep-alive
///    分支的三个连接头也在此集合内（Go `Header.Set` 后参与排序）；
/// 4. `Content-Length: 0`（CL == 0 且状态允许 body）追加在排序头之后；
/// 5. 空行结束头块。
///
/// `content_length` 即 Go 的 `response.ContentLength`：`Some(n)`（>= 0）→
/// keep-alive 三头；`None`（-1，长度未知）→ close 语义。
#[must_use]
pub fn serialize_go_response_head(
    status_line: &str,
    code: u16,
    headers: &HashMap<String, Vec<String>>,
    content_length: Option<u64>,
    chunked: bool,
) -> Vec<u8> {
    /// Go `RemoveHopByHopHeaders` 的头名集合（小写形态）。
    /// 注意 `trailer` 是 Go 侧拼写，与请求侧 `HOP_BY_HOP_HEADERS` 的 `trailers` 不同源，勿合并。
    const GO_HOP_BY_HOP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];

    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(&latin1_encode(status_line));
    buf.extend_from_slice(b"\r\n");
    // Go：ContentLength < 0 → response.Close = true → 只由 transferWriter 写
    // "Connection: close"（**不发 Proxy-Connection**——Go 仅在 400/503 错误路径
    // `proxy/http/server.go:218-219` / `:294-295` 才成对置位）。实测取证：
    // Go 26.10.17 二进制在 chunked 上游下响应头恰为 `Connection: close` +
    // `Transfer-Encoding: chunked`。
    let keep_alive = content_length.is_some();
    if !keep_alive {
        buf.extend_from_slice(b"Connection: close\r\n");
    }
    // Go：CL > 0 → transferWriter 先写 Content-Length；chunked → Transfer-Encoding。
    let mut sent_content_length = false;
    if chunked {
        buf.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    } else if let Some(n) = content_length.filter(|n| *n > 0) {
        buf.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
        sent_content_length = true;
    }
    // 其余响应头：canonical 名 + 排序（Go `Header.WriteSubset`）。
    let mut entries: Vec<(String, Vec<&str>)> = headers
        .iter()
        .filter(|(key, _)| {
            !GO_HOP_BY_HOP.contains(&key.as_str())
                && !matches!(key.as_str(), "content-length" | "transfer-encoding" | "trailer")
        })
        .map(|(key, values)| {
            (canonical_header_key(key), values.iter().map(String::as_str).collect())
        })
        .collect();
    if keep_alive {
        entries.push(("Connection".into(), vec!["keep-alive"]));
        entries.push(("Keep-Alive".into(), vec!["timeout=60"]));
        entries.push(("Proxy-Connection".into(), vec!["keep-alive"]));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, values) in entries {
        for value in values {
            buf.extend_from_slice(&latin1_encode(&key));
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(&latin1_encode(value));
            buf.extend_from_slice(b"\r\n");
        }
    }
    // Go `Response.Write` 尾段：CL == 0 且状态允许 body → 追加 "Content-Length: 0"。
    if !chunked && !sent_content_length && content_length == Some(0) && body_allowed(code) {
        buf.extend_from_slice(b"Content-Length: 0\r\n");
    }
    buf.extend_from_slice(b"\r\n");
    buf
}

/// 状态码是否允许 body（Go `bodyAllowedForStatus`：1xx / 204 / 304 不允许）。
fn body_allowed(code: u16) -> bool {
    !(code / 100 == 1 || code == 204 || code == 304)
}

/// 头名 canonical 化（Go `textproto.CanonicalMIMEHeaderKey`）：首字母与
/// `-` 后的字母大写，其余小写。
fn canonical_header_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut upper = true;
    for ch in key.chars() {
        if ch == '-' {
            out.push('-');
            upper = true;
        } else if upper {
            out.extend(ch.to_uppercase());
            upper = false;
        } else {
            out.extend(ch.to_lowercase());
        }
    }
    out
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
        client.write_all(&latin1_encode(&size_line)).await?;
        client.write_all(b"\r\n").await?;
        if size == 0 {
            // trailer 段透传到空行（无 trailer 时首行即空）
            loop {
                let line = read_http_line(upstream).await?;
                client.write_all(&latin1_encode(&line)).await?;
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
    // 1+2. 读请求行 + headers；协议格式错 → **断链不回响应**（Go
    // `http.ReadRequest` 失败 → `Process` 直接 return error → 连接关闭，Go 不写
    // 400）；EOF（客户端正常关闭）同样直接断。
    let (method, target, http_version, headers) = match read_request_head(stream).await {
        Ok(head) => head,
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

    // 4. 解析 dest（Go `Process`：`defaultPort = 80`，`strings.EqualFold(URL.Scheme, "https")` →
    //    443；`host = request.Host`，而 `http.ReadRequest` 令 `request.Host` = 绝对 URI 的 host
    //    优先、其次 Host 头——即 **URL 的 host 决定路由**，客户端给的 Host 头不参与选路（重复 Host
    //    已在读头阶段拒收））。
    let default_port =
        if target.get(..8).is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://")) {
            443
        } else {
            80
        };
    let dest = if method == "CONNECT" {
        // CONNECT 的 target 是 authority-form：`http.ReadRequest` 把它包成
        // `http://host:port` 再剥掉 scheme → URL.Host = authority → 同一条规则。
        parse_host_port(&target, default_port)?
    } else {
        let host = resolve_request_host(&target, &headers)
            .ok_or_else(|| HttpProxyError::Protocol("missing Host header".into()))?;
        parse_host_port(&host, default_port)?
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
/// 返回 (method 大写, target, 请求行版本, headers)；EOF/超长/畸形请求行/畸形 header
/// 统一报 [`HttpProxyError::Protocol`]（或 [`HttpProxyError::Io`]），**不回任何响应**
/// ——对齐 Go `http.ReadRequest` 失败后 `Process` 直接断链（`proxy/http/server.go:116`）。
async fn read_request_head<RW>(
    stream: &mut RW,
) -> Result<(String, String, HttpVersion, HashMap<String, Vec<String>>)>
where
    RW: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // 读请求行（严格三段，见 [`parse_request_line`]）
    let request_line = read_http_line(stream).await?;
    let (method, target, version_token) = parse_request_line(&request_line)?;
    // Go `net/url` `parse`（url.go:517）：URL 里出现 CTL 字节（<0x20 或 0x7f）直接
    // `invalid control character in URL`。控制字符会被原样写进上游请求行 = 请求注入面。
    if target.bytes().any(|c| c < 0x20 || c == 0x7f) {
        return Err(HttpProxyError::Protocol(format!(
            "invalid control character in request target: {target:?}"
        )));
    }
    let method = method.to_ascii_uppercase();
    let http_version = parse_http_version(version_token);
    let target = target.to_string();

    // 读 headers：总字节预算 [`MAX_HTTP_HEAD_BYTES`]（Go 侧无行数/行长上限，见该常量）。
    // 行首空格/制表符是 obs-fold 续行，按 Go `textproto.readContinuedLineSlice`
    // 折进上一头的值（H21 两侧一致面）。
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();
    // Latin-1 解码后 char 数 = 原始字节数，预算按字节计（Go 侧同）。
    let mut head_bytes = request_line.chars().count() + 2;
    let mut last_name: Option<String> = None;
    loop {
        let line = read_http_line(stream).await?;
        head_bytes += line.chars().count() + 2;
        if head_bytes > MAX_HTTP_HEAD_BYTES {
            return Err(HttpProxyError::Protocol(format!(
                "http request head exceeds {MAX_HTTP_HEAD_BYTES} bytes"
            )));
        }
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            // 首行即续行 → Go `textproto` 报 "malformed MIME header initial line"
            let Some(name) = last_name.as_ref() else {
                return Err(HttpProxyError::Protocol(format!(
                    "malformed MIME header initial line: {line:?}"
                )));
            };
            if let Some(value) = headers.get_mut(name).and_then(|values| values.last_mut()) {
                value.push(' ');
                value.push_str(trim_ows(&line));
            }
            continue;
        }
        let (name, value) = parse_header_line(&line)?;
        let name = trim_ows(name).to_ascii_lowercase();
        headers.entry(name.clone()).or_default().push(trim_ows(value).to_string());
        last_name = Some(name);
    }
    // Go `http.ReadRequest`（net/http/request.go:1138）：多个 Host 头 → 报
    // "too many Host headers" → ReadRequest 失败 → 上层断链（不回响应）。
    // 重复 Host 是请求走私面（首个 Host 决定路由、第二个到达上游），必须拒。
    if headers.get("host").is_some_and(|values| values.len() > 1) {
        return Err(HttpProxyError::Protocol("too many Host headers".into()));
    }
    Ok((method, target, http_version, headers))
}

/// 请求头（请求行 + 全部 header 行）总字节上限。
///
/// Go `http.ReadRequest` 是手工调用，不套 `http.Server` 的 `MaxHeaderBytes`——`ReadMIMEHeader`
/// 的预算参数是 `math.MaxInt64`（`net/textproto/reader.go:512-514`，调用点
/// `net/http/request.go:1133`），实测 Go 接受 16KB 级请求行/头行与 200 个 header
/// （H08/H17/H18）。本实现保留 1MB 上限：即 Go `net/http.DefaultMaxHeaderBytes`
/// 的服务端默认值，作「真实流量绝不会触及、又不让单连接无界吃内存」的界。
const MAX_HTTP_HEAD_BYTES: usize = 1024 * 1024;

/// 读一行 HTTP header（到 `\n`，返回不含行尾 `\r\n` / 裸 `\n` 的内容）。
///
/// 对齐 Go `net/textproto.readLineSlice`：以 `\n` 断行（**裸 LF 合法**，RFC 7230
/// §3.5 容忍），仅在行尾剥一个 `\r`，行内 CR 原样保留。
async fn read_http_line<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<String> {
    let mut buf = Vec::with_capacity(128);
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
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
        if buf.len() > MAX_HTTP_HEAD_BYTES {
            return Err(HttpProxyError::Protocol(format!(
                "http header line exceeds {MAX_HTTP_HEAD_BYTES} bytes"
            )));
        }
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    // 头行按字节透传（Go 不解 UTF-8，≥0x80 原始字节合法，H06）：Latin-1 逐字节
    // 1:1 映射，写回上游/客户端时经 [`latin1_encode`] 原样还原（bd t3lzr）。
    Ok(latin1_decode(&buf))
}

/// 请求行三段切分（对齐 Go `net/http/request.go:1027` `parseRequestLine` +
/// `validMethod` + `ParseHTTPVersion`）。
///
/// 单空格两次 `Cut`：多空格、尾空格、URI 内空格都会把余量留进第三段而版本非法
/// （Go 实测日志 `malformed HTTP version " HTTP/1.1"` / `"HTTP/1.1 "` /
/// `"b HTTP/1.1"`），即 Rust 原实现用 `split_whitespace` 是过宽面（请求走私）。
fn parse_request_line(line: &str) -> Result<(&str, &str, &str)> {
    let malformed = || HttpProxyError::Protocol(format!("malformed request line: {line:?}"));
    let (method, rest) = line.split_once(' ').ok_or_else(malformed)?;
    let (target, version) = rest.split_once(' ').ok_or_else(malformed)?;
    let method_ok = !method.is_empty() && method.bytes().all(is_tchar);
    if !method_ok || target.is_empty() || !is_http_version_token(version) {
        return Err(malformed());
    }
    Ok((method, target, version))
}

/// RFC 7230 `tchar`（Go `validHeaderFieldByte` / `isToken`）。
fn is_tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Go `net/http.ParseHTTPVersion`（request.go:817）：`HTTP/1.1`/`HTTP/1.0` 之外只认
/// **恰好 8 字节**的 `HTTP/<digit>.<digit>`——`HTTP/9.9` 合法（H12 两侧一致），
/// `HTTP/1.1 ` 非法。
fn is_http_version_token(version: &str) -> bool {
    let b = version.as_bytes();
    b.len() == 8
        && &b[..5] == b"HTTP/"
        && b[5].is_ascii_digit()
        && b[6] == b'.'
        && b[7].is_ascii_digit()
}

/// 解析一行 header（对齐 Go `net/textproto/reader.go:544-560` `readMIMEHeader`）。
///
/// 缺冒号 / 空头名 / 头名含 tchar 与空格之外字节 / 值含 CTL → 协议错误。原实现
/// `if let Some((k, v)) = line.split_once(':')` 把这类行**静默丢弃**——无日志、无拒绝，
/// 是走私面（H19/H20）。头名里的空格是 Go 的刻意容忍（go.dev/issue/34540，H16 实测 200）。
fn parse_header_line(line: &str) -> Result<(&str, &str)> {
    let malformed = || HttpProxyError::Protocol(format!("malformed MIME header line: {line:?}"));
    let (name, value) = line.split_once(':').ok_or_else(malformed)?;
    if name.is_empty() || !name.bytes().all(|c| is_tchar(c) || c == b' ') {
        return Err(malformed());
    }
    // Go `validHeaderValueByte`：HTAB / SP / VCHAR / obs-text(≥0x80) 合法
    if value.bytes().any(|c| c != b'\t' && (c < 0x20 || c == 0x7f)) {
        return Err(malformed());
    }
    Ok((name, value))
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
    fn serialize_go_response_head_keep_alive_branch_matches_go_bytes() {
        let mut headers: HashMap<String, Vec<String>> = HashMap::new();
        headers.insert("content-type".into(), vec!["text/plain".into()]);
        headers.insert("content-length".into(), vec!["17".into()]);
        headers.insert("connection".into(), vec!["close".into()]); // hop-by-hop，必被移除
        let out = String::from_utf8(serialize_go_response_head(
            "HTTP/1.1 200 OK",
            200,
            &headers,
            Some(17),
            false,
        ))
        .unwrap();
        // Go v26.10.17 实测布局：Content-Length 由 transferWriter 先写，其余头
        // canonical + 排序（Header.WriteSubset），keep-alive 三头参与排序。
        assert_eq!(
            out,
            "HTTP/1.1 200 OK\r\n\
             Content-Length: 17\r\n\
             Connection: keep-alive\r\n\
             Content-Type: text/plain\r\n\
             Keep-Alive: timeout=60\r\n\
             Proxy-Connection: keep-alive\r\n\r\n"
        );
    }

    #[test]
    fn serialize_go_response_head_close_branch_matches_go_bytes() {
        let mut headers: HashMap<String, Vec<String>> = HashMap::new();
        headers.insert("content-type".into(), vec!["text/plain".into()]);
        let out = String::from_utf8(serialize_go_response_head(
            "HTTP/1.1 200 OK",
            200,
            &headers,
            None,
            false,
        ))
        .unwrap();
        assert_eq!(out, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n");
    }

    #[test]
    fn serialize_go_response_head_chunked_matches_go_bytes() {
        let mut headers: HashMap<String, Vec<String>> = HashMap::new();
        headers.insert("transfer-encoding".into(), vec!["chunked".into()]);
        let out = String::from_utf8(serialize_go_response_head(
            "HTTP/1.1 200 OK",
            200,
            &headers,
            None,
            true,
        ))
        .unwrap();
        assert_eq!(
            out,
            "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n"
        );
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

        let server = xray_common::testing::spawn("tcp-handshake-accept", async move {
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
    async fn handshake_rejects_oversized_head() {
        // 请求头总字节 > MAX_HTTP_HEAD_BYTES（Go DefaultMaxHeaderBytes）→ 拒绝。
        // 单看行长没有独立上限：Go 走 http.ReadRequest 时无任何行长/行数闸
        // （net/textproto/reader.go:511 预算 = math.MaxInt64），故只用总量兜底。
        let mut req = b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec();
        for i in 0..96 {
            req.extend_from_slice(format!("X-Pad-{i}: ").as_bytes());
            req.extend(std::iter::repeat_n(b'a', 12 * 1024));
            req.extend_from_slice(b"\r\n");
        }
        req.extend_from_slice(b"\r\n");
        assert!(req.len() > MAX_HTTP_HEAD_BYTES);
        let (_, result) = tcp_handshake(&req, ServerConfig::default()).await;
        assert!(result.is_err(), "request head over budget must be rejected");
    }

    #[tokio::test]
    async fn handshake_accepts_many_header_lines() {
        // 200 个 header 行（H18）Go 照收——行数不再有闸，只受总预算约束。
        let mut req = b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec();
        for i in 0..200 {
            req.extend_from_slice(format!("X-Pad-{i}: v\r\n").as_bytes());
        }
        req.extend_from_slice(b"\r\n");
        let (_, result) = tcp_handshake(&req, ServerConfig::default()).await;
        assert!(result.is_ok(), "200 header lines must be accepted: {result:?}");
    }

    #[test]
    fn parse_request_line_strict_single_space() {
        // Go parseRequestLine + ParseHTTPVersion：单空格两次切分 + 8 字节版本段
        assert!(parse_request_line("GET http://h/cl HTTP/1.1").is_ok());
        assert!(parse_request_line("GET http://h/cl HTTP/9.9").is_ok());
        assert!(parse_request_line("GET  http://h/cl HTTP/1.1").is_err()); // H03
        assert!(parse_request_line("GET http://h/cl  HTTP/1.1").is_err()); // H04
        assert!(parse_request_line("GET http://h/cl HTTP/1.1 ").is_err()); // H05
        assert!(parse_request_line("GET http://h/a b HTTP/1.1").is_err()); // H13
        assert!(parse_request_line("GET http://h/cl").is_err()); // H02
        assert!(parse_request_line("GET  HTTP/1.1").is_err()); // 空 target
    }

    #[test]
    fn parse_header_line_rejects_malformed() {
        assert!(parse_header_line("BadHeader").is_err()); // H19：无冒号
        assert!(parse_header_line(": v").is_err()); // H20：空头名
        assert!(parse_header_line("X: a\x01b").is_err()); // 值含 CTL
        assert!(parse_header_line("Ho st: x").is_ok()); // H16：Go 刻意容忍名字里的空格
        assert_eq!(parse_header_line("Host: a:b").unwrap(), ("Host", " a:b")); // 值内冒号
    }

    #[test]
    fn extract_url_host_strips_userinfo() {
        // H30：Go net/url parseAuthority 按 LastIndex('@') 切
        assert_eq!(extract_url_host("http://user:pass@127.0.0.1:8080/cl"), Some("127.0.0.1:8080"));
        assert_eq!(extract_url_host("http://user@h/p"), Some("h"));
        assert_eq!(extract_url_host("http://h/p"), Some("h"));
    }

    #[tokio::test]
    async fn handshake_accepts_bare_lf() {
        // H15：裸 LF 断行（Go textproto.ReadLineSlice 只认 '\n'）必须立即正常解析
        let req = b"GET http://example.com/path HTTP/1.1\nHost: example.com\n\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert_eq!(hs.method, "GET");
        assert_eq!(hs.target, "http://example.com/path");
        assert_eq!(hs.headers.get("host").unwrap()[0], "example.com");
    }

    #[tokio::test]
    async fn handshake_folds_obs_fold_continuation() {
        // H21：行首空格是续行，折进上一头的值（Go readContinuedLineSlice）
        let req =
            b"GET http://example.com/p HTTP/1.1\r\nHost: example.com\r\nX-A: v\r\n more\r\n\r\n";
        let (_resp, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert_eq!(hs.headers.get("x-a").unwrap()[0], "v more");
    }

    #[tokio::test]
    async fn handshake_rejects_leading_continuation() {
        // 首行即续行 → Go textproto "malformed MIME header initial line"
        let req = b"GET http://example.com/p HTTP/1.1\r\n Host: example.com\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        assert!(result.is_err(), "leading continuation line must be rejected");
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
    async fn handshake_connect_default_port_80() {
        // Go `net/http/request.go:1118-1130`：CONNECT 的 authority 被包成
        // `http://<authority>` 解析后**清空 scheme** → xray `Process` 的
        // `defaultPort = 80`（只有 `URL.Scheme == "https"` 才是 443）。
        let req = b"CONNECT example.com HTTP/1.1\r\n\r\n";
        let (_, result) = tcp_handshake(req, ServerConfig::default()).await;
        let hs = result.unwrap();
        assert_eq!(hs.dest.port().value(), 80);
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
    fn latin1_roundtrip_preserves_every_byte() {
        // bd t3lzr：任意字节（含非法 UTF-8 序列与合法 UTF-8 多字节序列）必须 1:1 往返
        for raw in [
            &b"e9ff"[..],
            &b"\xe9\xff\x80\x01"[..],
            &b"\xe4\xb8\xad"[..], // 合法 UTF-8（中）
            &b"\x85\xa0"[..],     // U+0085/U+00A0：Unicode 空白，trim 会误剥
            &b""[..],
        ] {
            let s = latin1_decode(raw);
            assert_eq!(latin1_encode(&s), raw, "decode→encode 必须字节全等");
        }
        assert_eq!(trim_ows("\u{85}\u{a0}v\u{85}"), "\u{85}\u{a0}v\u{85}");
        assert_eq!(trim_ows(" \tv \t"), "v");
    }

    #[test]
    fn extract_request_path_percent_encodes_non_ascii_bytes() {
        // Go `url.URL.EscapedPath`：路径段 ≥0x80 字节 → %XX（实测锚点 /t2/%E9）；
        // query 走 RawQuery 原样写出。入参是读头侧 Latin-1 解码后的形态。
        assert_eq!(extract_request_path("/t2/\u{e9}"), "/t2/%E9");
        assert_eq!(extract_request_path("http://h:1/t2/\u{e9}"), "/t2/%E9");
        assert_eq!(extract_request_path("/t2/\u{e9}?q=\u{ff}"), "/t2/%E9?q=\u{ff}");
        assert_eq!(extract_request_path("/t2/%E9"), "/t2/%E9"); // 已转义原样保留
        assert_eq!(extract_request_path("/t2/\u{e9}\u{ff}"), "/t2/%E9%FF");
    }

    #[test]
    fn build_forwarded_request_writes_raw_header_bytes() {
        // bd t3lzr：非 UTF-8 头值原样写上游（读入侧 Latin-1 的逆）
        let mut headers = HashMap::new();
        headers.insert("host".into(), vec!["h".into()]);
        headers.insert("x-bin".into(), vec!["\u{e9}\u{ff}".into()]);
        headers.insert("x-utf8".into(), vec!["\u{e4}\u{b8}\u{ad}".into()]);
        let req = build_forwarded_request("GET", "/t2/%E9", &headers);
        // 转发字节本就可能是非法 UTF-8（这正是本票要保真的），故只按字节断言
        assert!(req.starts_with(b"GET /t2/%E9 HTTP/1.1\r\n"), "request line: {req:?}");
        assert!(find_bytes(&req, b"X-Bin: \xe9\xff\r\n"), "非 UTF-8 头值必须原样写上游: {req:?}");
        // U+00E4/U+00B8/U+00AD 解码自 e4b8ad，编码回来仍是同一串字节
        assert!(find_bytes(&req, b"X-Utf8: \xe4\xb8\xad\r\n"), "UTF-8 头值不变: {req:?}");
    }

    #[tokio::test]
    async fn read_http_line_keeps_non_utf8_bytes() {
        // 读头侧：非 UTF-8 字节不得退化成 U+FFFD
        let mut src = &b"X-Bin: \xe9\xff\r\n"[..];
        let line = read_http_line(&mut src).await.unwrap();
        assert_eq!(line, "X-Bin: \u{e9}\u{ff}");
        assert_eq!(latin1_encode(&line), b"X-Bin: \xe9\xff");
    }

    fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
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
        assert!(req_str.contains("Host: example.com"));
        assert!(req_str.contains("User-Agent: curl/8.0"));
        assert!(!req_str.contains("Proxy-Connection"));
        assert!(!req_str.contains("Proxy-Authorization"));
        assert!(req_str.contains("Connection: close\r\n\r\n"), "get: {req_str:?}");
    }

    #[test]
    fn build_forwarded_request_post() {
        let mut headers = HashMap::new();
        headers.insert("host".into(), vec!["api.example.com".into()]);
        headers.insert("content-length".into(), vec!["42".into()]);

        let req = build_forwarded_request("POST", "/submit", &headers);
        let req_str = String::from_utf8(req).unwrap();

        assert!(req_str.starts_with("POST /submit HTTP/1.1\r\n"));
        // Go：Content-Length 由 transferWriter 写在排序头之前（transfer.go:278-320）。
        assert_eq!(
            req_str,
            "POST /submit HTTP/1.1\r\nHost: api.example.com\r\n\
             Content-Length: 42\r\nConnection: close\r\n\r\n"
        );
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

        assert_eq!(
            req_str,
            "POST /upload HTTP/1.1\r\nHost: echo.example\r\n\
             Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn build_forwarded_request_keeps_multi_value_headers() {
        // bd z8i0：同名多值头（双 Cookie）逐行保留，不折叠丢失（Go request.Write 语义）
        let mut headers = HashMap::new();
        headers.insert("host".into(), vec!["api.example.com".into()]);
        headers.insert("cookie".into(), vec!["a=1".into(), "b=2".into()]);

        let req = build_forwarded_request("GET", "/", &headers);
        let req_str = String::from_utf8(req).unwrap();

        assert!(req_str.contains("Cookie: a=1\r\n"));
        assert!(req_str.contains("Cookie: b=2\r\n"));
    }

    /// D-H7 + D-H8：头名写 canonical（Go `WriteSubset` 写 parser canonicalize 后的名），
    /// 头序固定——`Host` 先、其余按 canonical 名排序（Go `header.go:167-224`），
    /// 与 `HashMap` 迭代序（每次运行不同）解耦。
    #[test]
    fn build_forwarded_request_canonical_names_and_sorted_order() {
        let mut headers = HashMap::new();
        headers.insert("host".into(), vec!["127.0.0.1:8080".into()]);
        headers.insert("x-mixed-case".into(), vec!["v".into()]);
        headers.insert("accept".into(), vec!["*/*".into()]);
        headers.insert("zeta".into(), vec!["1".into()]);
        headers.insert("alpha-beta".into(), vec!["2".into()]);

        let expected = "GET /cl HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\
                        Accept: */*\r\nAlpha-Beta: 2\r\nConnection: close\r\n\
                        X-Mixed-Case: v\r\nZeta: 1\r\n\r\n";
        // 连跑 5 次必须逐字节一致（HashMap 随机种子不得泄到 wire）
        for _ in 0..5 {
            let req = build_forwarded_request("GET", "/cl", &headers);
            assert_eq!(String::from_utf8(req).unwrap(), expected);
        }
    }

    /// D-H10：`Connection` 头点名的其它头一并删除（Go `RemoveHopByHopHeaders`
    /// `common/protocol/http/headers.go:59-66`），不只是固定 hop-by-hop 名单。
    #[test]
    fn build_forwarded_request_deletes_headers_named_by_connection() {
        let mut headers = HashMap::new();
        headers.insert("host".into(), vec!["h".into()]);
        headers.insert("connection".into(), vec!["X-Custom, close".into()]);
        headers.insert("x-custom".into(), vec!["v".into()]);
        headers.insert("x-kept".into(), vec!["v".into()]);

        let req = build_forwarded_request("GET", "/", &headers);
        let req_str = String::from_utf8(req).unwrap();

        assert!(!req_str.to_ascii_lowercase().contains("x-custom"), "get: {req_str:?}");
        assert!(req_str.contains("X-Kept: v"), "get: {req_str:?}");
        assert_eq!(req_str, "GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\nX-Kept: v\r\n\r\n");
    }

    /// Go `transferWriter.shouldSendContentLength`（transfer.go）：`Content-Length: 0`
    /// 只有 POST/PUT/PATCH 才写；GET 的 CL:0 被丢弃（不转发该头）。
    #[test]
    fn build_forwarded_request_drops_zero_content_length_for_get() {
        let mut headers = HashMap::new();
        headers.insert("host".into(), vec!["h".into()]);
        headers.insert("content-length".into(), vec!["0".into()]);

        let get = String::from_utf8(build_forwarded_request("GET", "/", &headers)).unwrap();
        assert_eq!(get, "GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");

        let post = String::from_utf8(build_forwarded_request("POST", "/", &headers)).unwrap();
        assert_eq!(
            post,
            "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
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
        let handle = xray_common::testing::spawn("spawn-echo-accept", async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                xray_common::testing::spawn("spawn-echo", async move {
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
    async fn malformed_request_closes_without_response() {
        // Go 语义（`http.ReadRequest` 失败 → `Process` 直接 return error）：
        // **不回任何响应**，直接关连接（差分矩阵 A31/A32 实测 Go = EMPTY）。
        let (_server, port) = start_server(ServerConfig::default()).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(b"GARBAGE\r\n\r\n").await.unwrap();
        assert_eq!(
            read_eof(&mut client).await,
            0,
            "malformed request must close silently (no 400)"
        );
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
        let upstream = xray_common::testing::spawn("run-plain-http-accept", async move {
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
        let server_side = xray_common::testing::spawn("run-plain-http-accept", async move {
            proxy_listener.accept().await.unwrap().0
        });

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
