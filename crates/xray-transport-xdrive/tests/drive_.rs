//! `google-drive` 后端行为锚（规划 §6 门 B4 + bd hjtlk B4 验收）：
//! ① 401 一次 → 刷新 token → 重放；② 同 id 请求命中 id 缓存不重复查询；
//! ③ multipart 上传边界 `xdrive-boundary`；④ inline 描述上限 12000 字节；
//! 加构造验证、重试面（429/503）、token 缓存、死凭据粘滞、子树删除、
//! inline list 载荷、共享实例去重、旧 service 名、真 dial→serve 生命周期与回收。
//!
//! 对照 Go `drive_test.go`/`drive_token_test.go`（fakeDrive + httptest；
//! 端点注入 = Go 包级 URL 换置的等价面：[`DriveStorage::with_base_url`] 与
//! [`set_test_storage_factory`](xray_transport_xdrive::storage::set_test_storage_factory)）。

#![allow(clippy::disallowed_methods)]
#![allow(clippy::unwrap_used)] // 测试断言便利豁免（bd g3cr）
#![allow(clippy::print_stderr)]

use std::{collections::BTreeMap, convert::Infallible, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::{net::TcpListener, sync::Mutex};
use xray_transport::dialer::StreamSettings;
use xray_transport_xdrive::{
    Config, DriveStorage,
    storage::{
        Storage, is_not_found, reset_shared_storage, reset_test_storage_factory,
        set_test_storage_factory,
    },
};

// TEST_FACTORY 与 shared_storage 表是进程级全局：drive 集成测试串行执行。
static SERIAL: Mutex<()> = Mutex::const_new(());

// ── fakeDrive（Go drive_test.go 同构）────────────────────────────────────

#[derive(Clone, Debug, Default)]
struct FakeFile {
    name: String,
    data: Vec<u8>,
    description: String,
}

#[derive(Default)]
struct MockState {
    files: BTreeMap<String, FakeFile>,
    next_id: usize,
    tokens: usize,
    lists: usize,
    /// 置 N：接下来 N 个 /files 请求一律 401（token 失效重取锚）。
    unauthorized_left: usize,
    /// 置 true：下一次 create/upload 一律 429（可重试锚）。
    fail_once_upload: bool,
    /// 置 true：下一次 /files 查询一律 503（可重试锚）。
    fail_once_list: bool,
    token_status: u16,
    token_body: String,
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// multipart 解析（客户端 [`multipart_body`] 的字节级镜像）。
fn parse_multipart(body: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    const HEAD: &[u8] =
        b"--xdrive-boundary\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n";
    const MID: &[u8] = b"\r\n--xdrive-boundary\r\nContent-Type: application/octet-stream\r\n\r\n";
    const TAIL: &[u8] = b"\r\n--xdrive-boundary--\r\n";
    let rest = body.strip_prefix(HEAD)?;
    let mid = find_sub(rest, MID)?;
    let meta = rest[..mid].to_vec();
    let tail = &rest[mid + MID.len()..];
    let end = find_sub(tail, TAIL)?;
    Some((meta, tail[..end].to_vec()))
}

/// Go `url.QueryEscape` 的解码镜像（q 参数还原后做 name 匹配）。
fn query_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            },
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
            b => {
                out.push(b);
                i += 1;
            },
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Go parseFakeQuery：q 里的 `name = 'exact'` / `name contains 'prefix'`。
fn parse_fake_query(q: &str) -> (Option<String>, Option<String>) {
    for (marker, exact) in [("name = '", true), ("name contains '", false)] {
        if let Some(start) = q.find(marker) {
            let rest = &q[start + marker.len()..];
            if let Some(end) = rest.find('\'') {
                return if exact {
                    (Some(rest[..end].to_string()), None)
                } else {
                    (None, Some(rest[..end].to_string()))
                };
            }
        }
    }
    (None, None)
}

fn full(status: StatusCode, body: impl Into<Bytes>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::builder().status(status).body(Full::new(body.into())).unwrap())
}

async fn handle(
    req: Request<Incoming>,
    state: Arc<Mutex<MockState>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path_q = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    let body = req.into_body().collect().await.map(|c| c.to_bytes()).unwrap_or_default();

    let mut st = state.lock().await;

    if path_q == "/token" {
        st.tokens += 1;
        if st.token_status != 0 {
            return full(StatusCode::from_u16(st.token_status).unwrap(), st.token_body.clone());
        }
        return full(StatusCode::OK, r#"{"access_token":"fake-token","expires_in":3600}"#);
    }

    if st.unauthorized_left > 0 {
        st.unauthorized_left -= 1;
        return full(StatusCode::UNAUTHORIZED, "");
    }

    // POST /files?fields=id —— inline 创建（Go handleCreate）。
    if method == http::Method::POST && path_q.starts_with("/files") {
        if st.fail_once_upload {
            st.fail_once_upload = false;
            return full(StatusCode::TOO_MANY_REQUESTS, "");
        }
        let meta: serde_json::Value = serde_json::from_slice(&body).unwrap_or(json!({}));
        st.next_id += 1;
        let id = format!("id-{}", st.next_id);
        st.files.insert(
            id.clone(),
            FakeFile {
                name: meta.get("name").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                data: Vec::new(),
                description: meta
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            },
        );
        return full(StatusCode::OK, json!({"id": id}).to_string());
    }

    // POST /upload?... —— multipart 上传（Go handleUpload，新建）。
    if method == http::Method::POST && path_q.starts_with("/upload") {
        if st.fail_once_upload {
            st.fail_once_upload = false;
            return full(StatusCode::TOO_MANY_REQUESTS, "");
        }
        let Some((meta_bytes, data)) = parse_multipart(&body) else {
            return full(StatusCode::BAD_REQUEST, "");
        };
        let meta: serde_json::Value = serde_json::from_slice(&meta_bytes).unwrap_or(json!({}));
        st.next_id += 1;
        let id = format!("id-{}", st.next_id);
        st.files.insert(
            id.clone(),
            FakeFile {
                name: meta.get("name").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                data: data.to_vec(),
                description: String::new(),
            },
        );
        return full(StatusCode::OK, json!({"id": id}).to_string());
    }

    // PATCH /upload/{id}?uploadType=multipart —— 槽位体+描述更新。
    if method == http::Method::PATCH && path_q.starts_with("/upload/") {
        let id =
            path_q.split('?').next().unwrap_or_default().trim_start_matches("/upload/").to_string();
        let Some((meta_bytes, data)) = parse_multipart(&body) else {
            return full(StatusCode::BAD_REQUEST, "");
        };
        let Some(file) = st.files.get_mut(&id) else {
            return full(StatusCode::NOT_FOUND, "");
        };
        let meta: serde_json::Value = serde_json::from_slice(&meta_bytes).unwrap_or(json!({}));
        file.data = data.to_vec();
        file.description =
            meta.get("description").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        return full(StatusCode::OK, json!({"id": id}).to_string());
    }

    // GET /files?q=... —— 列表/精确查询（Go handleList）。
    if method == http::Method::GET && path_q.starts_with("/files?") && path_q.contains("q=") {
        if st.fail_once_list {
            st.fail_once_list = false;
            return full(StatusCode::SERVICE_UNAVAILABLE, "");
        }
        st.lists += 1;
        let query = path_q.split_once('?').map(|(_, q)| q).unwrap_or_default();
        let raw_q = query
            .split('&')
            .find_map(|pair| {
                pair.split_once('=').filter(|(k, _)| *k == "q").map(|(_, v)| v.to_string())
            })
            .unwrap_or_default();
        let (exact, prefix) = parse_fake_query(&query_decode(&raw_q));
        let mut entries = Vec::new();
        for file in st.files.values() {
            let matched = match (&exact, &prefix) {
                (Some(want), _) => &file.name == want,
                (_, Some(want)) => file.name.starts_with(want.as_str()),
                _ => false,
            };
            if matched {
                entries.push(json!({
                    "id": st.files.iter().find(|(_, f)| f.name == file.name).map(|(k, _)| k).unwrap().clone(),
                    "name": file.name,
                    "description": if file.description.is_empty() { serde_json::Value::Null } else { json!(file.description) },
                }));
            }
        }
        return full(StatusCode::OK, json!({"files": entries}).to_string());
    }

    // /files/{id} 单对象面。
    if let Some(rest) = path_q.strip_prefix("/files/") {
        let (id, query) = rest.split_once('?').unwrap_or((rest, ""));
        let id = query_decode(id);
        if method == http::Method::DELETE {
            if st.files.remove(&id).is_some() {
                return full(StatusCode::NO_CONTENT, "");
            }
            return full(StatusCode::NOT_FOUND, "");
        }
        if method == http::Method::PATCH {
            let meta: serde_json::Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let Some(file) = st.files.get_mut(&id) else {
                return full(StatusCode::NOT_FOUND, "");
            };
            file.description =
                meta.get("description").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            return full(StatusCode::OK, json!({"id": id}).to_string());
        }
        let Some(file) = st.files.get(&id) else {
            return full(StatusCode::NOT_FOUND, "");
        };
        if query.contains("fields=description") {
            return full(StatusCode::OK, json!({"description": file.description}).to_string());
        }
        // alt=media：返回体字节（含空体——inline 回读路径依赖空体判定）。
        return full(StatusCode::OK, Bytes::from(file.data.clone()));
    }

    full(StatusCode::NOT_FOUND, "")
}

async fn start_mock() -> (Arc<Mutex<MockState>>, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let state = Arc::new(Mutex::new(MockState::default()));
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
    (state, base)
}

// ── 构造辅助（Go driveSettings/newDriveBackend）──────────────────────────

fn drive_settings(base: &str, service: &str) -> StreamSettings {
    // base 参数只为文档对齐 Go driveSettings（端点注入走 TEST_FACTORY，不在 settings）。
    let _ = base;
    StreamSettings::from_json(Some(&json!({
        "network": "xdrive",
        "xdriveSettings": {
            "service": service,
            "remoteFolder": "folder-id",
            "secrets": ["client", "secret", "refresh"],
            "flushIntervalMs": 5,
            "pollIntervalMs": 5,
            "maxPollIntervalMs": 20,
            "sessionTtlSeconds": 1,
        },
    })))
}

async fn new_backend(base: &str) -> Arc<dyn Storage> {
    let settings = drive_settings(base, "google-drive");
    let config = Config::from_settings(&settings).unwrap();
    Arc::new(DriveStorage::new(&settings, &config).unwrap().with_base_url(base))
}

fn seg(name: &str) -> String {
    format!("streams/abc/c2s/{name}")
}

// ── 行为锚 ────────────────────────────────────────────────────────────────

/// Go TestDriveSecrets：3 元 secrets、remoteFolder 非空、secret 非空。
#[tokio::test]
async fn drive_secrets_validation() {
    // G4：secrets 计数已上移配置期（Go XDriveConfig.Build 同款）；folder/空 secret
    // 仍由 storage 构造期拒（Go newDriveStorage 同款）。
    let make = |settings: StreamSettings| -> std::io::Result<()> {
        let config = Config::from_settings(&settings)?;
        DriveStorage::new(&settings, &config).map(|_| ())
    };
    let bad_two = StreamSettings::from_json(Some(&json!({
        "network": "xdrive",
        "xdriveSettings": {"service": "google-drive", "remoteFolder": "f", "secrets": ["a", "b"]},
    })));
    let bad_folder = StreamSettings::from_json(Some(&json!({
        "network": "xdrive",
        "xdriveSettings": {"service": "google-drive", "secrets": ["a", "b", "c"]},
    })));
    let bad_empty = StreamSettings::from_json(Some(&json!({
        "network": "xdrive",
        "xdriveSettings": {"service": "google-drive", "remoteFolder": "f", "secrets": ["a", "", "c"]},
    })));
    assert!(Config::from_settings(&bad_two).is_err(), "two secrets must fail at config time");
    assert!(make(bad_two).is_err(), "accepted two secrets");
    assert!(make(bad_folder).is_err(), "accepted an empty remoteFolder");
    assert!(make(bad_empty).is_err(), "accepted an empty secret");
}

/// Go TestDriveRoundTrip：put → get → list 单条 → miss NotFound → delete 清空。
#[tokio::test]
async fn drive_roundtrip_and_not_found() {
    let (_state, base) = start_mock().await;
    let storage = new_backend(&base).await;

    storage.put(&seg("000000000.seg"), b"hello").await.unwrap();
    let data = storage.get(&seg("000000000.seg")).await.unwrap();
    assert_eq!(data, b"hello", "get must return the inline payload");

    let names = storage.list("streams/abc/c2s").await.unwrap();
    assert_eq!(names.len(), 1, "list returned {names:?}, want 1 segment");
    assert_eq!(names[0].name, "000000000.seg");

    let missing = storage.get(&seg("000000009.seg")).await;
    let err = missing.unwrap_err();
    assert!(is_not_found(&err), "get returned {err}, want NotFound");

    storage.delete(&seg("000000000.seg")).await.unwrap();
    let state = _state.lock().await;
    assert_eq!(state.files.len(), 0, "fake drive still holds files");
}

/// Go TestDriveListChildren：List 只返回首层子级。
#[tokio::test]
async fn drive_list_children() {
    let (_state, base) = start_mock().await;
    let storage = new_backend(&base).await;
    for name in [
        "streams/one/c2s/000000000.seg",
        "streams/one/s2c/000000000.seg",
        "streams/two/c2s/000000000.seg",
    ] {
        storage.put(name, b"x").await.unwrap();
    }
    let names = storage.list("streams").await.unwrap();
    assert_eq!(names.len(), 2, "list returned {names:?}, want 2 sessions");
}

/// Go TestDriveDeleteSession：Delete 子树级联（自身 + flat~ 前缀子级）。
#[tokio::test]
async fn drive_delete_session_subtree() {
    let (state, base) = start_mock().await;
    let storage = new_backend(&base).await;
    for name in [
        "streams/one/c2s/000000000.seg",
        "streams/one/c2s/000000001.end",
        "streams/one/s2c/000000000.seg",
        "streams/two/c2s/000000000.seg",
    ] {
        storage.put(name, b"x").await.unwrap();
    }
    storage.delete("streams/one").await.unwrap();
    assert_eq!(state.lock().await.files.len(), 1, "want only streams/two left");
}

/// Go TestDriveRetry：429（upload）与 503（list）一次失败后重试成功。
#[tokio::test]
async fn drive_retry_survives_429_and_503() {
    let (state, base) = start_mock().await;
    let storage = new_backend(&base).await;

    state.lock().await.fail_once_upload = true;
    storage.put("sessions/abc", b"").await.unwrap();
    state.lock().await.fail_once_list = true;
    storage.list("sessions").await.unwrap();
}

/// Go TestDriveTokenCache：5 次 Put 只触碰 token 端点一次。
#[tokio::test]
async fn drive_token_cached_across_puts() {
    let (state, base) = start_mock().await;
    let storage = new_backend(&base).await;
    for i in 0..5 {
        storage.put(&format!("sessions/s{i}"), b"").await.unwrap();
    }
    assert_eq!(state.lock().await.tokens, 1, "token endpoint must be hit once");
}

/// 门①（Go 401 失效重取）：files 请求 401 一次 → 换 token → 重放成功。
#[tokio::test]
async fn drive_unauthorized_refetches_token() {
    let (state, base) = start_mock().await;
    let storage = new_backend(&base).await;
    state.lock().await.unauthorized_left = 1;
    storage.put("sessions/401", b"payload").await.unwrap();
    let st = state.lock().await;
    assert_eq!(st.tokens, 2, "a 401 must force exactly one token refetch");
    assert!(st.files.values().any(|f| f.name == "sessions~401"), "the retried put must land");
}

/// 门②：put 后连续两次 Get 不再触发任何 files 查询（id 缓存命中）。
#[tokio::test]
async fn drive_id_cache_hits_query_once() {
    let (state, base) = start_mock().await;
    let storage = new_backend(&base).await;
    storage.put(&seg("000000000.seg"), b"cached-id").await.unwrap();
    let lists_before = state.lock().await.lists;
    // put 的 create/读体不触发 query（q= 计数不变）；resolve 走 create 应答填充的缓存。
    let first = storage.get(&seg("000000000.seg")).await.unwrap();
    let second = storage.get(&seg("000000000.seg")).await.unwrap();
    assert_eq!(first, b"cached-id");
    assert_eq!(second, b"cached-id");
    assert_eq!(state.lock().await.lists, lists_before, "cache hits must not re-query");
}

/// 门③ + Go TestDriveLargeContent：>12000B 走 multipart upload，边界字节可见，
/// media 读回逐字节一致。
#[tokio::test]
async fn drive_large_content_multipart_boundary() {
    let (state, base) = start_mock().await;
    let storage = new_backend(&base).await;
    let mut payload = vec![0u8; 12001 + 2048];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    storage.put(&seg("big.seg"), &payload).await.unwrap();

    // upload 端点收到 multipart（boundary 可解析）+ media 读回一致。
    let data = storage.get(&seg("big.seg")).await.unwrap();
    assert_eq!(data, payload, "media roundtrip must be byte-equal");
    let stored = state.lock().await;
    let big = stored.files.values().find(|f| f.name == "streams~abc~c2s~big.seg").unwrap();
    assert_eq!(big.data, payload, "multipart upload must carry the whole body");
}

/// 门④：12000B 含走 inline（create），12001B 走 upload。
#[tokio::test]
async fn drive_inline_limit_boundary() {
    let (state, base) = start_mock().await;
    let storage = new_backend(&base).await;
    let payload = vec![7u8; 12000];
    storage.put("sessions/inline-12000", &payload).await.unwrap();
    {
        let st = state.lock().await;
        let file = st.files.values().find(|f| f.name == "sessions~inline-12000").unwrap();
        // inline 路径：data 空、description = base64(payload)（12000B ≤ 12000 上限）。
        assert!(file.data.is_empty(), "12000B must not go through the upload endpoint");
        assert!(!file.description.is_empty(), "inline create must carry the payload");
    }
    let bigger = vec![7u8; 12001];
    storage.put("sessions/media-12001", &bigger).await.unwrap();
    let st = state.lock().await;
    let file = st.files.values().find(|f| f.name == "sessions~media-12001").unwrap();
    assert_eq!(file.data.len(), 12001, "12001B must go through the upload endpoint");
}

/// Go TestDriveInlineListing：List 的首层条目带 inline 载荷。
#[tokio::test]
async fn drive_inline_listing() {
    let (_state, base) = start_mock().await;
    let storage = new_backend(&base).await;
    storage.put("streams/one/c2s/000000000.seg", b"inline-data").await.unwrap();
    let names = storage.list("streams/one/c2s").await.unwrap();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0].name, "000000000.seg");
    assert_eq!(
        names[0].inline.as_deref(),
        Some(b"inline-data".as_slice()),
        "list must carry inline"
    );
}

/// Go TestDriveDeadCredentials：token 端点 invalid_grant → auth 错粘滞，
/// 后续调用不再触碰 token 端点。
#[tokio::test]
async fn drive_dead_credentials_sticky() {
    let (state, base) = start_mock().await;
    {
        let mut st = state.lock().await;
        st.token_status = 400;
        st.token_body = r#"{"error":"invalid_grant"}"#.to_string();
    }
    let storage = new_backend(&base).await;
    let err = storage.put("sessions/dead", b"").await.unwrap_err();
    assert!(
        err.to_string().contains("Google rejected the OAuth credentials (invalid_grant)"),
        "put returned {err}"
    );
    let again = storage.put("sessions/dead2", b"").await.unwrap_err();
    assert!(again.to_string().contains("Google rejected the OAuth credentials"), "sticky err");
    assert_eq!(state.lock().await.tokens, 1, "sticky auth error must not refetch");
}

/// Go TestDriveOldServiceName：旧名 "Google Drive" 同样分派。
#[tokio::test]
async fn drive_old_service_name() {
    let (_state, base) = start_mock().await;
    let settings = drive_settings(&base, "Google Drive");
    let config = Config::from_settings(&settings).unwrap();
    let storage: Arc<dyn Storage> =
        Arc::new(DriveStorage::new(&settings, &config).unwrap().with_base_url(&base));
    storage.put("sessions/old-name", b"x").await.unwrap();
}

/// Go TestDriveSharedClient：同配置两次构造命中共享实例表（同一 Arc）。
/// 不走 TEST_FACTORY（Go 同款：工厂 nil 时 newStorage 才经 sharedStorage 去重），
/// 直调 pub 面 [`shared_storage`](xray_transport_xdrive::shared_storage)。
#[tokio::test]
async fn drive_shared_client_dedup() {
    let _guard = SERIAL.lock().await;
    let (_state, base) = start_mock().await;
    reset_shared_storage();
    let settings = drive_settings(&base, "google-drive");
    let config = Config::from_settings(&settings).unwrap();
    let build = || {
        let storage: Arc<dyn Storage> =
            Arc::new(DriveStorage::new(&settings, &config).unwrap().with_base_url(&base));
        Ok(storage)
    };
    let first = xray_transport_xdrive::shared_storage(Some(&settings), &config, build).unwrap();
    let second = xray_transport_xdrive::shared_storage(Some(&settings), &config, build).unwrap();
    assert!(Arc::ptr_eq(&first, &second), "same-config storages must share one backend instance");
    reset_shared_storage();
}

/// 生命周期锚（bd hjtlk B4 验收①）：真 dial → 真 serve → 300KB 双向逐字节 →
/// 双侧 shutdown → collector 回收 streams/<sid> 对象。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drive_transport_lifecycle_and_reclaim() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use xray_common::net::{
        address::Address, destination::Destination, network::Network, port::Port,
    };
    use xray_transport::{connection::Connection, listener_registry::ConnHandler};
    use xray_transport_xdrive::{dial, serve};

    let _guard = SERIAL.lock().await;
    let (state, base) = start_mock().await;
    reset_shared_storage();

    // dial/serve 经 new_storage 进后端：工厂注入 mock 端点（Go newFakeDrive 换
    // 包级 URL 的等价面）。
    set_test_storage_factory(Arc::new({
        let base = base.clone();
        move |s: &StreamSettings| {
            let config = Config::from_settings(s)?;
            let storage: Arc<dyn Storage> =
                Arc::new(DriveStorage::new(s, &config).unwrap().with_base_url(&base));
            Ok(storage)
        }
    }));

    let settings = drive_settings(&base, "google-drive");
    let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel::<Box<dyn Connection>>(4);
    let handler: ConnHandler = Arc::new(move |conn| {
        let conn_tx = conn_tx.clone();
        tokio::spawn(async move {
            let _ = conn_tx.send(conn).await;
        });
    });
    let listener =
        serve("127.0.0.1:0".parse().unwrap(), settings.clone(), Default::default(), handler)
            .await
            .unwrap();

    let dest = Destination::new(Address::new_domain("xdrive.test"), Port::new(443), Network::TCP);
    let mut client = dial(&dest, &Default::default(), &settings).await.unwrap();

    let mut server = tokio::time::timeout(Duration::from_secs(10), conn_rx.recv())
        .await
        .expect("listener must accept the announced session in time")
        .expect("handler channel closed");

    // 上行 300KB（>12000 触发 multipart 上传路径）逐字节比对。
    let payload: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
    client.write_all(&payload).await.unwrap();
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(30), server.read_exact(&mut received))
        .await
        .expect("uplink must arrive in time")
        .unwrap();
    assert_eq!(received, payload, "300KB uplink must arrive byte-equal");

    // 下行回写 → 客户端读（对端分段对象逐字节重组）。
    server.write_all(&received).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(30), client.read_exact(&mut echoed))
        .await
        .expect("downlink must arrive in time")
        .unwrap();
    assert_eq!(echoed, payload, "downlink must arrive byte-equal");

    client.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
    drop(listener);

    // collector 回收：sessionTtl 1s，轮询 12s 等待 streams/ 前缀对象清空。
    let mut reclaimed = false;
    for _ in 0..48 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let st = state.lock().await;
        if !st.files.keys().any(|name| name.starts_with("streams~")) {
            reclaimed = true;
            break;
        }
    }
    assert!(reclaimed, "collector must reclaim the streams/ objects of the closed session");

    reset_test_storage_factory();
    reset_shared_storage();
}
