//! `s3` 后端 HTTP 行为锚（bd hjtlk B3 验收①②）：mock hyper 服务端回放脚本化
//! 响应，断言请求面（method/path/query/签名头）与客户端结果（404 语义、分页、
//! 递归删除、429 重签）。签名算法 golden 向量在 `src/s3.rs` 单测（离线手推）。

#![allow(clippy::disallowed_methods)]
#![allow(clippy::unwrap_used)] // 测试断言便利豁免（bd g3cr）
#![allow(clippy::print_stderr)]

use std::{
    convert::Infallible,
    sync::Arc,
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::{net::TcpListener, sync::Mutex};
use xray_transport::dialer::StreamSettings;
use xray_transport_xdrive::{Storage, s3::S3Storage, storage::is_not_found};

// ── 脚本化 mock（按请求序回放固定响应 + 记录请求面）─────────────────────────

#[derive(Clone)]
struct Step {
    status: StatusCode,
    body: String,
    /// 非 false：响应前压到「下一个整秒界 + 延迟」（429 重签测试的 x-amz-date
    /// 跨秒确定性对齐）。
    hold_to_next_second: bool,
}

impl Step {
    fn at(status: StatusCode, body: impl Into<String>) -> Self {
        Self { status, body: body.into(), hold_to_next_second: false }
    }

    fn held(status: StatusCode, body: impl Into<String>) -> Self {
        Self { status, body: body.into(), hold_to_next_second: true }
    }
}

#[derive(Clone, Default)]
struct Recorded {
    method: String,
    /// path + "?" + query（原样）。
    target: String,
    host: String,
    authorization: String,
}

#[derive(Default)]
struct MockState {
    script: Vec<Step>,
    requests: Vec<Recorded>,
}

async fn handle(
    req: Request<Incoming>,
    state: Arc<Mutex<MockState>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let recorded = Recorded {
        method: req.method().to_string(),
        host: req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(),
        authorization: req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        target: req.uri().path_and_query().map(|pq| pq.as_str().to_string()).unwrap_or_default(),
    };
    // x-amz 侧签名头必须齐（golden 已锁算法，这里锚存在性）。
    assert!(
        req.headers().contains_key("x-amz-date")
            && req.headers().contains_key("x-amz-content-sha256"),
        "missing SigV4 headers on {} {}",
        recorded.method,
        recorded.target
    );
    let (_, body) = req.into_parts();
    let _ = body.collect().await;
    let step = {
        let mut state = state.lock().await;
        state.requests.push(recorded);
        let index = state.requests.len() - 1;
        state
            .script
            .get(index)
            .cloned()
            .unwrap_or_else(|| Step::at(StatusCode::INTERNAL_SERVER_ERROR, ""))
    };
    if step.hold_to_next_second {
        // 压到下一个整秒界：客户端下次 attempt 的 x-amz-date 必然 +1s。
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
        let into_second = now.subsec_nanos();
        tokio::time::sleep(Duration::from_nanos(1_000_000_000 - u64::from(into_second))).await;
    }
    Ok(Response::builder().status(step.status).body(Full::new(Bytes::from(step.body))).unwrap())
}

async fn start_mock(script: Vec<Step>) -> (Arc<Mutex<MockState>>, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = Arc::new(Mutex::new(MockState { script, ..MockState::default() }));
    let server_state = Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { break };
            let state = Arc::clone(&server_state);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let state = Arc::clone(&state);
                    async move { handle(req, state).await }
                });
                let _ = http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).await;
            });
        }
    });
    (state, port)
}

fn s3_settings(port: u16, path_style: bool, bucket: &str) -> StreamSettings {
    StreamSettings::from_json(Some(&json!({
        "network": "xdrive",
        "address": "127.0.0.1",
        "port": port,
        "xdriveSettings": {
            "service": "s3",
            "remoteFolder": "streams",
            "secrets": ["AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"],
            "s3": {
                "endpoint": format!("http://s3.local:{port}"),
                "region": "us-east-1",
                "bucket": bucket,
                "pathStyle": path_style
            }
        }
    })))
}

fn new_storage(settings: &StreamSettings) -> Arc<dyn Storage> {
    Arc::new(
        S3Storage::new(settings, &xray_transport_xdrive::Config::from_settings(settings).unwrap())
            .unwrap(),
    )
}

// ── 用例 ─────────────────────────────────────────────────────────────────────

/// PUT + GET 往返：path-style URL 形态、签名头齐、二进制一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_get_roundtrip_path_style() {
    let payload = "hello s3".repeat(64);
    let (state, port) =
        start_mock(vec![Step::at(StatusCode::OK, ""), Step::at(StatusCode::OK, &payload)]).await;
    let storage = new_storage(&s3_settings(port, true, "examplebucket"));

    storage.put("f.bin", payload.as_bytes()).await.unwrap();
    let got = storage.get("f.bin").await.unwrap();
    assert_eq!(got, payload.as_bytes());

    let requests = state.lock().await.requests.clone();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "PUT");
    assert_eq!(requests[0].target, "/examplebucket/streams/f.bin");
    assert_eq!(requests[0].host, format!("s3.local:{port}"));
    assert!(
        requests[0].authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"),
        "{}",
        requests[0].authorization
    );
    assert!(requests[0].authorization.contains("/us-east-1/s3/aws4_request"));
    assert_eq!(requests[1].method, "GET");
    assert_eq!(requests[1].target, "/examplebucket/streams/f.bin");
    // 两次请求独立签名（时间戳粒度内可能相同，但 Authorization 必然存在）。
    assert!(!requests[1].authorization.is_empty());
}

/// 404 + NoSuchKey → NotFound 哨兵（调用方 [`is_not_found`] 判定）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_missing_maps_to_not_found() {
    let (state, port) = start_mock(vec![Step::at(
        StatusCode::NOT_FOUND,
        r#"<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>x</Message></Error>"#,
    )])
    .await;
    let storage = new_storage(&s3_settings(port, true, "examplebucket"));
    let err = storage.get("absent").await.unwrap_err();
    assert!(is_not_found(&err), "{err}");
    assert_eq!(state.lock().await.requests.len(), 1);
}

/// 404 但码非 NoSuchKey/NotFound → 普通错误（Go s3Missing 白名单）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_404_other_code_is_plain_error() {
    let (_state, port) = start_mock(vec![Step::at(
        StatusCode::NOT_FOUND,
        r#"<Error><Code>BucketNotFound</Code></Error>"#,
    )])
    .await;
    let storage = new_storage(&s3_settings(port, true, "examplebucket"));
    let err = storage.get("absent").await.unwrap_err();
    assert!(!is_not_found(&err), "BucketNotFound must not map to the sentinel: {err}");
    assert!(err.to_string().contains("BucketNotFound"), "{err}");
}

/// LIST 分页：第二跳带 continuation-token；首段截断 + CommonPrefixes 合并去重。
/// （mock 数据对齐 S3 语义：服务端只回 `prefix=streams/a.txt/` 命中的 key。）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_pagination_uses_continuation_token() {
    let page1 = "<ListBucketResult><IsTruncated>true</IsTruncated>\
        <NextContinuationToken>tok-2</NextContinuationToken>\
        <Contents><Key>streams/a.txt/part1</Key></Contents>\
        <Contents><Key>streams/a.txt/mid</Key></Contents></ListBucketResult>";
    let page2 = "<ListBucketResult><IsTruncated>false</IsTruncated>\
        <Contents><Key>streams/a.txt/z</Key></Contents>\
        <CommonPrefixes><Prefix>streams/a.txt/dir/</Prefix></CommonPrefixes></ListBucketResult>";
    let (state, port) =
        start_mock(vec![Step::at(StatusCode::OK, page1), Step::at(StatusCode::OK, page2)]).await;
    let storage = new_storage(&s3_settings(port, true, "examplebucket"));

    let entries = storage.list("a.txt").await.unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    // 顺序 = 服务端返回序（Go add() 逐 key 首段截断；CommonPrefixes 走 prefix 面）。
    assert_eq!(names, vec!["part1", "mid", "z", "dir"], "首段截断 + prefix 合并");

    let requests = state.lock().await.requests.clone();
    assert_eq!(requests.len(), 2);
    // 对齐 Go target("", query)：base 恒以 `/` 结尾 ⇒ 空 key 的 list path 保留尾斜杠。
    assert_eq!(
        requests[0].target,
        "/examplebucket/?delimiter=%2F&list-type=2&max-keys=1000&prefix=streams%2Fa.txt%2F"
    );
    assert!(
        requests[1]
            .target
            .contains("continuation-token=tok-2&delimiter=%2F&list-type=2&max-keys=1000&prefix=streams%2Fa.txt%2F"),
        "{}",
        requests[1].target
    );
}

/// DELETE 递归：list query 带尾 `/` 前缀（防 streams/abcd 误删），逐 key 删除。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_recursive_scoped_by_trailing_slash() {
    let page = "<ListBucketResult><IsTruncated>false</IsTruncated>\
        <Contents><Key>streams/abc/x</Key></Contents>\
        <Contents><Key>streams/abc/sub/y</Key></Contents></ListBucketResult>";
    let (state, port) = start_mock(vec![
        Step::at(StatusCode::NO_CONTENT, ""),
        Step::at(StatusCode::OK, page),
        Step::at(StatusCode::NO_CONTENT, ""),
        Step::at(StatusCode::NO_CONTENT, ""),
    ])
    .await;
    let storage = new_storage(&s3_settings(port, true, "examplebucket"));

    storage.delete("abc").await.unwrap();

    let requests = state.lock().await.requests.clone();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].method, "DELETE");
    assert_eq!(requests[0].target, "/examplebucket/streams/abc");
    assert!(requests[1].target.contains("prefix=streams%2Fabc%2F"), "{}", requests[1].target);
    assert!(
        !requests[1].target.contains("delimiter"),
        "递归层无 delimiter：{}",
        requests[1].target
    );
    assert_eq!(requests[2].method, "DELETE");
    assert_eq!(requests[2].target, "/examplebucket/streams/abc/x");
    assert_eq!(requests[3].method, "DELETE");
    assert_eq!(requests[3].target, "/examplebucket/streams/abc/sub/y");
}

/// 递归层回传 prefix 越界 key ⇒ 拒（防坏服务端拖删非请求子树）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_recursive_rejects_outside_prefix() {
    let page = "<ListBucketResult><IsTruncated>false</IsTruncated>\
        <Contents><Key>streams/abcd/y</Key></Contents></ListBucketResult>";
    let (_state, port) =
        start_mock(vec![Step::at(StatusCode::NO_CONTENT, ""), Step::at(StatusCode::OK, page)])
            .await;
    let storage = new_storage(&s3_settings(port, true, "examplebucket"));
    let err = storage.delete("abc").await.unwrap_err();
    assert!(err.to_string().contains("outside the requested prefix"), "{err}");
}

/// 429 → 重试且重签：首响应压到下一整秒界，第二次 attempt 的 x-amz-date 必
/// 跨秒 ⇒ Authorization 必不同。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_429_re_signs_with_fresh_signature() {
    let (state, port) = start_mock(vec![
        Step::held(StatusCode::TOO_MANY_REQUESTS, r#"<Error><Code>SlowDown</Code></Error>"#),
        Step::at(StatusCode::OK, ""),
    ])
    .await;
    let storage = new_storage(&s3_settings(port, true, "examplebucket"));

    storage.put("retry.bin", b"data").await.unwrap();

    let requests = state.lock().await.requests.clone();
    assert_eq!(requests.len(), 2, "重试后成功");
    assert!(!requests[0].authorization.is_empty());
    assert!(!requests[1].authorization.is_empty());
    assert_ne!(
        requests[0].authorization, requests[1].authorization,
        "429 后必须带新签名（x-amz-date 已跨秒）"
    );
}

/// virtual-hosted：bucket 进 authority（fronting 拨真地址，URL host 作 Host 头
/// 与签名 authority），path 不含 bucket 段。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn virtual_hosted_url_form() {
    let (state, port) = start_mock(vec![Step::at(StatusCode::OK, "vh")]).await;
    let storage = new_storage(&s3_settings(port, false, "mybucket"));
    let got = storage.get("vh.bin").await.unwrap();
    assert_eq!(got, b"vh");

    let requests = state.lock().await.requests.clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].host, format!("mybucket.s3.local:{port}"));
    assert_eq!(requests[0].target, "/streams/vh.bin");
    assert!(requests[0].authorization.contains("host;"), "{}", requests[0].authorization);
}

/// 共享会话视图：session() 返回独立闸的视图（put/get 语义同基座）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_view_shares_backend_semantics() {
    let (state, port) =
        start_mock(vec![Step::at(StatusCode::OK, ""), Step::at(StatusCode::OK, "via-session")])
            .await;
    let storage = new_storage(&s3_settings(port, true, "examplebucket"));
    let session = storage.session().expect("s3 backend provides a session view");
    session.put("s.bin", b"ignored").await.unwrap();
    let got = session.get("s.bin").await.unwrap();
    assert_eq!(got, b"via-session");
    session.close().await.unwrap();

    let requests = state.lock().await.requests.clone();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].target, "/examplebucket/streams/s.bin");
    assert_eq!(requests[1].target, "/examplebucket/streams/s.bin");
}
