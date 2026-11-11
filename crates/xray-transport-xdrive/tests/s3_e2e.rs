//! `s3` 后端**会话级**端到端锚（bd bgiq0）：有状态内存 S3 mock（PUT/GET/DELETE +
//! ListObjectsV2 分页/continuation-token/错误注入）驱动真 dial → 真 serve → 1MiB
//! 双向逐字节 → 双侧 shutdown → collector 回收；错误路径（403 不重试 / 429 退避
//! 重试 / 5xx 耗尽）各一例。纯本机回环，无外网。
//!
//! 分工：`tests/s3_sigv4.rs` 是脚本化响应的 storage 级锚（URL 形态/签名头/重签）；
//! 本文件补**有状态对象存储**与会话层，故 mock 只断言 SigV4 头存在性（算法 golden
//! 在 `src/s3.rs` 单测）。四段骨架对齐 `tests/drive_.rs` 的
//! `drive_transport_lifecycle_and_reclaim` 与 `tests/local_roundtrip.rs`。
//!
//! 端点走 fronting 形态：`streamSettings.address/port` 指向本机 mock（真拨号），
//! `s3.endpoint` 的 host 只作 Host 头与签名 authority——与 `s3_sigv4` 同款。
//!
//! 测试内不裸 `tokio::spawn`（crate `clippy.toml` 闸）：mock 的连接任务挂
//! [`JoinSet`]（drop 即 abort，不脱管）。

use std::{
    collections::{BTreeMap, VecDeque},
    convert::Infallible,
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::{net::TcpListener, sync::Mutex, task::JoinSet};
use xray_transport::dialer::StreamSettings;
use xray_transport_xdrive::{Config, Storage, s3::S3Storage, storage::reset_shared_storage};

/// path-style 桶名（请求路径第一段）。
const BUCKET: &str = "examplebucket";
/// `xdriveSettings.remoteFolder`：对象 key 的顶层前缀（`share_key` 也随之区分）。
const ROOT: &str = "streams";
/// 404 的 S3 白名单码（Go `s3Missing` 只认 NoSuchKey/NotFound）。
const NO_SUCH_KEY: &str = r#"<Error><Code>NoSuchKey</Code></Error>"#;

/// 共享实例表是进程级全局：本文件的会话级用例串行执行。
static SERIAL: Mutex<()> = Mutex::const_new(());

// ── 有状态内存 S3 mock ────────────────────────────────────────────────────

/// 一次请求的响应注入（消费即弹出）。
type Injected = (u16, &'static str);

#[derive(Default)]
struct MockState {
    /// 对象存储本体：相对桶根的 key → 内容。
    objects: BTreeMap<String, Vec<u8>>,
    /// 顺序注入：每个请求先消耗一条（错误路径锚）。
    failures: VecDeque<Injected>,
    /// `Some(code)`：所有请求恒回该状态码（重试环耗尽锚）。
    always: Option<u16>,
    /// ListObjectsV2 单页条目上限（`None` = S3 缺省 1000；调小即测分页）。
    page_size: Option<usize>,
    /// NextContinuationToken 恒回同一值（分页不前进锚）。
    stuck_token: bool,
    requests: usize,
    lists: usize,
    /// 每个 list 请求带的 continuation-token（首条为空的断言面）。
    list_tokens: Vec<String>,
    /// 缺 SigV4 头的请求数（装配校验，应恒 0）。
    unsigned: usize,
}

fn reply(status: u16, body: impl Into<Bytes>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::from_u16(status).expect("valid status code"))
        .body(Full::new(body.into()))
        .expect("valid response"))
}

/// 百分号解码（query/path 通用；key 字母表 = 十六进制/`-._/`，'+' 只出现在
/// query 的 form 形态——本 mock 两处都按 '+' → 空格处理，S3 客户端不用 '+
/// 编码路径）。
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 3;
                    },
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    },
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            },
            b => {
                out.push(b);
                i += 1;
            },
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (pct_decode(k), pct_decode(v))
        })
        .collect()
}

/// `/<bucket>/<bucket 内 key>` → 桶内 key（path-style 形态）。
fn object_key_from_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix('/')?.strip_prefix(BUCKET)?;
    Some(pct_decode(rest.strip_prefix('/').unwrap_or("")))
}

/// ListObjectsV2 单页（S3 语义：contents 与 CommonPrefixes 同流分页）。
///
/// key 字母表只有 `[0-9A-Za-z./_-]`（SigV4 path escape 后），故 XML 不做实体
/// 转义；`items` 继承 BTreeMap 的字典序（S3 亦按 key 升序返回）。
fn list_response(st: &mut MockState, params: &BTreeMap<String, String>) -> Response<Full<Bytes>> {
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    let delimiter = params.get("delimiter").cloned().unwrap_or_default();
    let token = params.get("continuation-token").cloned().unwrap_or_default();
    let requested = params.get("max-keys").and_then(|v| v.parse::<usize>().ok()).unwrap_or(1000);
    st.lists += 1;
    st.list_tokens.push(token.clone());
    let page_size = st.page_size.unwrap_or(1000).min(requested).max(1);

    let mut items: Vec<(String, bool)> = Vec::new();
    for key in st.objects.keys().filter(|k| k.starts_with(&prefix)) {
        if !delimiter.is_empty() {
            if let Some(idx) = key[prefix.len()..].find(&delimiter) {
                let group =
                    format!("{prefix}{}", &key[prefix.len()..prefix.len() + idx + delimiter.len()]);
                // 同一公共前缀的 key 在字典序里连续 ⇒ 只看上一条目即可去重。
                if items.last().map(|(name, _)| name.as_str()) != Some(group.as_str()) {
                    items.push((group, true));
                }
                continue;
            }
        }
        items.push((key.clone(), false));
    }

    // `stuck_token`：服务端永不推进 ⇒ 恒重放第一页 + 同一个 token（客户端必须
    // 靠「token 重复」判环，而不是靠服务端自己停下）。
    let start = if token.is_empty() || st.stuck_token {
        0
    } else {
        items.iter().position(|(name, _)| name.as_str() > token.as_str()).unwrap_or(items.len())
    };
    let end = (start + page_size).min(items.len());
    let truncated = end < items.len();
    let next = if truncated {
        if st.stuck_token { "stuck-token".to_string() } else { items[end - 1].0.clone() }
    } else {
        String::new()
    };

    let mut xml = String::from("<ListBucketResult><IsTruncated>");
    xml.push_str(if truncated { "true" } else { "false" });
    xml.push_str("</IsTruncated>");
    if truncated {
        xml.push_str("<NextContinuationToken>");
        xml.push_str(&next);
        xml.push_str("</NextContinuationToken>");
    }
    for (name, is_prefix) in &items[start..end] {
        if *is_prefix {
            xml.push_str("<CommonPrefixes><Prefix>");
            xml.push_str(name);
            xml.push_str("</Prefix></CommonPrefixes>");
        } else {
            xml.push_str("<Contents><Key>");
            xml.push_str(name);
            xml.push_str("</Key></Contents>");
        }
    }
    xml.push_str("</ListBucketResult>");
    Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from(xml)))
        .expect("valid response")
}

async fn handle(
    req: Request<Incoming>,
    state: Arc<Mutex<MockState>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let target = req.uri().path_and_query().map(|pq| pq.as_str().to_string()).unwrap_or_default();
    let signed = req.headers().contains_key("x-amz-date")
        && req.headers().contains_key("x-amz-content-sha256");
    let body = req.into_body().collect().await.map(|c| c.to_bytes()).unwrap_or_default();
    let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
    let params = parse_query(query);

    let mut st = state.lock().await;
    st.requests += 1;
    if !signed {
        st.unsigned += 1;
    }
    if let Some((status, body)) = st.failures.pop_front() {
        return reply(status, body);
    }
    if let Some(status) = st.always {
        return reply(status, "<Error><Code>InjectedFailure</Code></Error>");
    }
    if params.get("list-type").map(String::as_str) == Some("2") {
        return Ok(list_response(&mut st, &params));
    }
    let Some(key) = object_key_from_path(path) else {
        return reply(400, "<Error><Code>InvalidURI</Code></Error>");
    };
    match method {
        Method::PUT => {
            st.objects.insert(key, body.to_vec());
            reply(200, Bytes::new())
        },
        Method::GET => match st.objects.get(&key) {
            Some(data) => reply(200, Bytes::from(data.clone())),
            None => reply(404, NO_SUCH_KEY),
        },
        Method::DELETE => {
            st.objects.remove(&key);
            reply(204, Bytes::new())
        },
        _ => reply(405, Bytes::new()),
    }
}

async fn serve_connection(tcp: tokio::net::TcpStream, state: Arc<Mutex<MockState>>) {
    let service = service_fn(move |req: Request<Incoming>| {
        let state = Arc::clone(&state);
        async move { handle(req, state).await }
    });
    let _ = http1::Builder::new().serve_connection(TokioIo::new(tcp), service).await;
}

async fn accept_loop(listener: TcpListener, state: Arc<Mutex<MockState>>) {
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((tcp, _)) = accepted else { return };
                let state = Arc::clone(&state);
                let _ = conns.spawn(serve_connection(tcp, state));
            },
            // 回收已结束的连接任务（空集时不轮询 join_next——那会忙等）。
            Some(_) = conns.join_next(), if !conns.is_empty() => {},
        }
    }
}

/// mock 服务端句柄：`state` 供断言/注入，drop 即 abort 所有连接与 accept 循环。
struct MockServer {
    state: Arc<Mutex<MockState>>,
    port: u16,
    tasks: JoinSet<()>,
}

impl MockServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock s3");
        let port = listener.local_addr().expect("mock local addr").port();
        let state = Arc::new(Mutex::new(MockState::default()));
        let mut tasks = JoinSet::new();
        let _ = tasks.spawn(accept_loop(listener, Arc::clone(&state)));
        Self { state, port, tasks }
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}

// ── 设置与构造 ────────────────────────────────────────────────────────────

/// 会话级设置：小段/快轮询/短 TTL（collector 回收判据秒级可观测）+ 本机 mock 端点。
fn s3_settings(port: u16) -> StreamSettings {
    StreamSettings::from_json(Some(&json!({
        "network": "xdrive",
        "address": "127.0.0.1",
        "port": port,
        "xdriveSettings": {
            "service": "s3",
            "remoteFolder": ROOT,
            "secrets": ["AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"],
            "segmentBytes": 256 * 1024,
            "flushIntervalMs": 5,
            "pollIntervalMs": 5,
            "maxPollIntervalMs": 20,
            "sessionTtlSeconds": 1,
            "concurrency": 4,
            "s3": {
                "endpoint": format!("http://s3.local:{port}"),
                "region": "us-east-1",
                "bucket": BUCKET,
                "pathStyle": true
            }
        }
    })))
}

fn new_storage(settings: &StreamSettings) -> Arc<dyn Storage> {
    let config = Config::from_settings(settings).expect("config from settings");
    Arc::new(S3Storage::new(settings, &config).expect("s3 storage"))
}

// ── 用例 ─────────────────────────────────────────────────────────────────

/// 会话级四段锚（bd bgiq0 验收①）：真 dial → 真 serve → 1MiB 双向逐字节 →
/// 双侧 shutdown → collector 回收 `streams/<sid>`。
///
/// 回收断言用「预置孤儿会话 + 全对象清空」双保险：孤儿会话证明 collector 真跑了，
/// 全清空证明已关会话没有残留对象（WAL 段/`.end`/announce）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_dial_serve_roundtrip_1mib_and_reclaim() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use xray_common::net::{
        address::Address, destination::Destination, network::Network, port::Port,
    };
    use xray_transport::{connection::Connection, listener_registry::ConnHandler};
    use xray_transport_xdrive::{dial, serve};

    let _guard = SERIAL.lock().await;
    let server = MockServer::start().await;
    // 走真实 `new_storage` 的 s3 分派臂（不注测试工厂）。
    reset_shared_storage();

    // 孤儿会话：永不被 claim，只能由 collector 按 TTL 整前缀删除。
    server
        .state
        .lock()
        .await
        .objects
        .insert(format!("{ROOT}/streams/deadbeef/c2s/000000000.seg"), vec![0u8; 8]);

    let settings = s3_settings(server.port);
    let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel::<Box<dyn Connection>>(4);
    let handler: ConnHandler = Arc::new(move |conn| {
        // 同步投递（容量 4、单连接）：测试内不派后台任务。
        let _ = conn_tx.try_send(conn);
    });
    let listener = serve(
        "127.0.0.1:0".parse().expect("listen addr"),
        settings.clone(),
        Default::default(),
        handler,
    )
    .await
    .expect("serve must start");

    let dest = Destination::new(Address::new_domain("xdrive.test"), Port::new(443), Network::TCP);
    let mut client = dial(&dest, &Default::default(), &settings).await.expect("dial");

    let mut peer = tokio::time::timeout(Duration::from_secs(20), conn_rx.recv())
        .await
        .expect("listener must accept the announced session in time")
        .expect("handler channel closed");

    // 上行 1MiB（256KiB/段 ⇒ 多段）逐字节比对。
    let payload: Vec<u8> = (0..1024 * 1024usize).map(|i| (i * 7 % 251) as u8).collect();
    client.write_all(&payload).await.expect("uplink write");
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(60), peer.read_exact(&mut received))
        .await
        .expect("1MiB uplink must arrive in time")
        .expect("uplink read");
    assert_eq!(received, payload, "1MiB uplink must arrive byte-equal");

    // 下行回写 → 客户端读（对端分段对象逐字节重组）。
    peer.write_all(&received).await.expect("downlink write");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(60), client.read_exact(&mut echoed))
        .await
        .expect("1MiB downlink must arrive in time")
        .expect("downlink read");
    assert_eq!(echoed, payload, "1MiB downlink must arrive byte-equal");

    client.shutdown().await.expect("client shutdown");
    peer.shutdown().await.expect("peer shutdown");
    drop(listener);

    // collector：sessionTtl 1s、每 500ms 一轮；孤儿会话 + 已关会话残留对象必须删净。
    let mut reclaimed = false;
    let mut left = Vec::new();
    for _ in 0..48 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let st = server.state.lock().await;
        if st.objects.is_empty() {
            reclaimed = true;
            break;
        }
        left = st.objects.keys().cloned().collect();
    }
    assert!(reclaimed, "collector must reclaim every streams/ object, left: {left:?}");
    assert_eq!(server.state.lock().await.unsigned, 0, "every request must carry SigV4 headers");

    reset_shared_storage();
}

/// 分页完整性（验收②）：7 key / 每页 3 条 ⇒ 3 跳 ListObjectsV2 全量列出，
/// continuation-token 逐跳前进。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_objects_v2_pagination_walks_every_page() {
    let server = MockServer::start().await;
    server.state.lock().await.page_size = Some(3);
    let storage = new_storage(&s3_settings(server.port));
    for i in 0..7 {
        storage.put(&format!("d/{i}.bin"), format!("v{i}").as_bytes()).await.expect("put");
    }

    let entries = storage.list("d").await.expect("list");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["0.bin", "1.bin", "2.bin", "3.bin", "4.bin", "5.bin", "6.bin"],
        "every key must be listed across pages"
    );

    let st = server.state.lock().await;
    assert_eq!(st.lists, 3, "7 keys / 3 per page = 3 ListObjectsV2 calls");
    assert_eq!(st.list_tokens[0], "", "the first page carries no continuation-token");
    assert!(st.list_tokens[1..].iter().all(|t| !t.is_empty()), "{:?}", st.list_tokens);
    assert_ne!(st.list_tokens[1], st.list_tokens[2], "the continuation-token must advance");
    assert_eq!(st.unsigned, 0);
}

/// 分页防环（验收②）：服务端恒回同一 NextContinuationToken ⇒ 第二跳即显式失败，
/// 不退化成无限翻页。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_objects_v2_stuck_token_is_rejected() {
    let server = MockServer::start().await;
    {
        let mut st = server.state.lock().await;
        st.page_size = Some(1);
        st.stuck_token = true;
    }
    let storage = new_storage(&s3_settings(server.port));
    for i in 0..3 {
        storage.put(&format!("d/{i}.bin"), b"x").await.expect("put");
    }

    let err = storage.list("d").await.expect_err("a stuck token must fail, not loop forever");
    assert!(err.to_string().contains("did not advance"), "{err}");
    assert_eq!(server.state.lock().await.lists, 2, "detected on the second page");
}

/// 错误路径 1（验收③）：403 = 鉴权类不可重试错误，一次尝试即上抛（不静默重试）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forbidden_is_surfaced_without_retry() {
    let server = MockServer::start().await;
    server.state.lock().await.always = Some(403);
    let storage = new_storage(&s3_settings(server.port));

    let err = storage.put("k.bin", b"x").await.expect_err("403 must surface");
    assert!(err.to_string().contains("403"), "{err}");
    assert!(err.to_string().contains("InjectedFailure"), "{err}");
    assert_eq!(server.state.lock().await.requests, 1, "403 is not retryable");
}

/// 错误路径 2（验收③）：429 走既有退避环重试，退避后成功（重试环确实生效）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn too_many_requests_is_retried_then_succeeds() {
    let server = MockServer::start().await;
    server.state.lock().await.failures.push_back((429, "<Error><Code>SlowDown</Code></Error>"));
    let storage = new_storage(&s3_settings(server.port));

    storage.put("k.bin", b"payload").await.expect("429 must be retried, not surfaced");
    assert_eq!(server.state.lock().await.requests, 2, "exactly one retry");
    assert_eq!(server.state.lock().await.objects.get("streams/k.bin"), Some(&b"payload".to_vec()));
}

/// 错误路径 3（验收③）：5xx 恒失败 ⇒ 重试环耗尽（Go `driveMaxAttempts` = 8）后
/// 把最后一错显式上抛。退避 jitter（half + [0,half)）实测约 10-12s，是重试环
/// 本身的成本。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_error_exhausts_the_retry_loop() {
    let server = MockServer::start().await;
    server.state.lock().await.always = Some(503);
    let storage = new_storage(&s3_settings(server.port));

    let err = storage.put("k.bin", b"x").await.expect_err("exhausted retries must surface");
    assert!(err.to_string().contains("503"), "{err}");
    assert_eq!(server.state.lock().await.requests, 8, "8 attempts, then give up");
}
