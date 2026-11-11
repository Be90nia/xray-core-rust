//! `template` 后端操作面行为锚（规划 §6 门 B2）：
//! 1. put/get/list/delete 四操作的 method+path+auth 头断言（mock hyper 服务端）；
//! 2. `hrefPath` 两跳正例（第一跳 200 + `{"href":…}` → 第二跳带 body 且**无 auth 头**）
//!    与反例（`hrefPath` 指向不存在的 JSON 路径 → 拒）；
//! 3. oauth2：token 端点复用（缓存命中不重取）+ 401 失效重取；
//! 4. `retry.status`（429）/ `retry.rateReason`（403+reason）退避重试后成功；
//! 5. basic auth 头逐字节对齐；`subst` 变量（folder/secret0/name/prefix）替换。
//!
//! 对照 Go `template_test.go`（fakeStore + httptest，flatten=true 形态）。

#![allow(clippy::disallowed_methods)]
#![allow(clippy::unwrap_used)] // 测试断言便利豁免（bd g3cr）
#![allow(clippy::print_stderr)]

use std::{collections::BTreeMap, convert::Infallible, sync::Arc};

use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std_ext::encode::{Base64Alphabet, base64_encode};
use tokio::{net::TcpListener, sync::Mutex};
use xray_transport::dialer::StreamSettings;
use xray_transport_xdrive::{Config, TemplateStorage, storage::Storage};

// ── mock 存储（Go fakeStore 形态：flatten 键空间 + PROPFIND href 列举）────────

#[derive(Clone, Debug)]
struct Record {
    method: String,
    path: String,
    auth: String,
}

#[derive(Default)]
struct MockState {
    objects: BTreeMap<String, Vec<u8>>,
    log: Vec<Record>,
    tokens: usize,
    auth_seen: String,
    /// 置 N：接下来 N 个请求一律 401（oauth2 失效重取锚）。
    unauthorized_left: usize,
    /// 置 N：接下来 N 个 PUT 一律 429（retry.status 锚）。
    too_many_left: usize,
    /// 置 N：接下来 N 个请求一律 403 + rate-reason 体（retry.rateReason 锚）。
    forbidden_left: usize,
    /// /upload/ 二跳收到的 PUT 数。
    uploads: usize,
}

fn full(
    status: StatusCode,
    body: impl Into<bytes::Bytes>,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    Ok(Response::builder().status(status).body(Full::new(body.into())).unwrap())
}

fn query_param(path: &str, key: &str) -> Option<String> {
    let query = path.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        pair.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v.to_string())
    })
}

async fn handle(
    req: Request<Incoming>,
    state: Arc<Mutex<MockState>>,
    base: Arc<String>,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    let auth =
        req.headers().get("Authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let body = req.into_body().collect().await.map(|c| c.to_bytes()).unwrap_or_default();

    let mut st = state.lock().await;
    if path == "/token" {
        st.tokens += 1;
        return full(StatusCode::OK, r#"{"access_token":"tok-fake","expires_in":3600}"#);
    }
    let record = || Record { method: method.to_string(), path: path.clone(), auth: auth.clone() };
    if st.unauthorized_left > 0 {
        st.unauthorized_left -= 1;
        st.log.push(record());
        return full(StatusCode::UNAUTHORIZED, bytes::Bytes::from_static(b""));
    }
    if !auth.is_empty() {
        st.auth_seen = auth.clone();
    }
    if st.forbidden_left > 0 {
        st.forbidden_left -= 1;
        st.log.push(record());
        return full(
            StatusCode::FORBIDDEN,
            r#"{"error":{"description":"rate limited by upstream"}}"#,
        );
    }
    if method == Method::PUT && st.too_many_left > 0 {
        st.too_many_left -= 1;
        st.log.push(record());
        return full(StatusCode::TOO_MANY_REQUESTS, bytes::Bytes::from_static(b""));
    }
    st.log.push(record());

    let route = path.split('?').next().unwrap_or_default().to_string();

    // 两跳的第二跳落点（Go presigned：URL 原样、无 auth、无自定义头）。
    if let Some(key) = path.strip_prefix("/upload/") {
        st.objects.insert(key.to_string(), body.to_vec());
        st.uploads += 1;
        return full(StatusCode::CREATED, bytes::Bytes::from_static(b""));
    }
    if route == "/api/link" {
        let name = query_param(&path, "name").unwrap_or_default();
        return full(StatusCode::OK, format!(r#"{{"href":"{base}/upload/{name}"}}"#));
    }

    let Some(key) = route.strip_prefix("/folder/") else {
        return full(StatusCode::NOT_FOUND, bytes::Bytes::from_static(b"no route"));
    };
    match method.as_str() {
        "PUT" => {
            st.objects.insert(key.to_string(), body.to_vec());
            full(StatusCode::CREATED, bytes::Bytes::from_static(b""))
        },
        "GET" => match st.objects.get(key) {
            Some(data) => Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(bytes::Bytes::copy_from_slice(data)))
                .unwrap()),
            None => full(StatusCode::NOT_FOUND, bytes::Bytes::from_static(b"")),
        },
        "DELETE" => {
            // flatten 键空间无真目录；"streams~<sid>" 前缀按子树语义回收
            // （对应 local 后端 rm_all 的 Storage::delete 契约，collector 消费）。
            if key.starts_with("streams~") {
                let prefix = key.to_string();
                st.objects.retain(|k, _| !k.starts_with(&prefix));
            } else {
                st.objects.remove(key);
            }
            full(StatusCode::NO_CONTENT, bytes::Bytes::from_static(b""))
        },
        "PROPFIND" => {
            let mut listing = String::new();
            for name in st.objects.keys() {
                listing.push_str(&format!("<d:href>/folder/{name}</d:href>\n"));
            }
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(listing.into_bytes().into()))
                .unwrap())
        },
        _ => full(StatusCode::METHOD_NOT_ALLOWED, bytes::Bytes::from_static(b"")),
    }
}

async fn start_mock() -> (Arc<Mutex<MockState>>, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = Arc::new(format!("http://{addr}"));
    let state = Arc::new(Mutex::new(MockState::default()));
    let (server_state, server_base) = (Arc::clone(&state), Arc::clone(&base));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { break };
            let (state, base) = (Arc::clone(&server_state), Arc::clone(&server_base));
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let (state, base) = (Arc::clone(&state), Arc::clone(&base));
                    async move { handle(req, state, base).await }
                });
                let _ = http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).await;
            });
        }
    });
    (state, (*base).clone())
}

// ── 配置面 ────────────────────────────────────────────────────────────────

fn template_json(
    base: &str,
    auth: serde_json::Value,
    retry: serde_json::Value,
) -> serde_json::Value {
    json!({
        "flatten": true,
        "auth": auth,
        "put": {"method": "PUT", "url": format!("{base}/folder/{{name}}")},
        "get": {"method": "GET", "url": format!("{base}/folder/{{name}}")},
        "delete": {"method": "DELETE", "url": format!("{base}/folder/{{name}}")},
        "list": {
            "method": "PROPFIND",
            "url": format!("{base}/folder/?prefix={{prefix}}"),
            "namesRegex": "<d:href>/folder/([^<]+)</d:href>"
        },
        "retry": retry
    })
}

fn template_settings(tmpl: serde_json::Value) -> StreamSettings {
    StreamSettings::from_json(Some(&json!({
        "network": "xdrive",
        "xdriveSettings": {
            "service": "template",
            "remoteFolder": "folder",
            "secrets": ["refresh-secret"],
            "flushIntervalMs": 5,
            "pollIntervalMs": 5,
            "maxPollIntervalMs": 20,
            "sessionTtlSeconds": 2,
            "segmentBytes": 65536,
            "eagerWindowMs": 200,
            "template": tmpl
        }
    })))
}

fn backend(base: &str, auth: serde_json::Value, retry: serde_json::Value) -> Arc<dyn Storage> {
    let settings = template_settings(template_json(base, auth, retry));
    let config = Config::from_settings(&settings).unwrap();
    Arc::new(TemplateStorage::new(&settings, &config).unwrap())
}

fn auth_none() -> serde_json::Value {
    json!({"type": "none"})
}

fn retry_429_5xx() -> serde_json::Value {
    json!({"status": [429, 500, 502, 503]})
}

// ── 用例 1：四操作 method+path+auth 与 404 哨兵 ──────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn template_ops_put_get_list_delete() {
    let (state, base) = start_mock().await;
    let storage = backend(&base, auth_none(), retry_429_5xx());
    let s = storage.as_ref();

    s.put("streams/abc/c2s/000000000.seg", b"hello").await.unwrap();
    let data = s.get("streams/abc/c2s/000000000.seg").await.unwrap();
    assert_eq!(data, b"hello", "get 必须取回 put 的载荷");

    let entries = s.list("streams/abc/c2s").await.unwrap();
    assert_eq!(entries.len(), 1, "flatten list 必须回首层条目: {entries:?}");
    assert_eq!(entries[0].name, "000000000.seg");

    assert!(
        xray_transport_xdrive::storage::is_not_found(
            &s.get("streams/abc/c2s/missing.seg").await.unwrap_err()
        ),
        "缺失对象必须映射 NotFound 哨兵"
    );

    s.delete("streams/abc/c2s/000000000.seg").await.unwrap();
    assert_eq!(state.lock().await.objects.len(), 0, "delete 后对象必须消失");
    s.delete("streams/abc/c2s/never-existed.seg").await.unwrap();

    let log = &state.lock().await.log;
    assert_eq!(log[0].method, "PUT");
    assert_eq!(log[0].path, "/folder/streams~abc~c2s~000000000.seg");
    assert_eq!(log[1].method, "GET");
    assert_eq!(log[2].method, "PROPFIND");
    assert_eq!(log[2].path, "/folder/?prefix=streams~abc~c2s");
    assert_eq!(log[3].method, "GET", "get(missing)");
    assert_eq!(log[4].method, "DELETE");
    assert_eq!(log[5].method, "DELETE");
}

// ── 用例 2：hrefPath 两跳（正/反） ─────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn template_href_two_step_put() {
    let (state, base) = start_mock().await;
    let settings = template_settings(json!({
        "flatten": true,
        "auth": auth_none(),
        "put": {
            "method": "POST",
            "url": format!("{base}/api/link?name={{name}}"),
            "hrefPath": "href",
            "hrefMethod": "PUT"
        },
        "get": {"method": "GET", "url": format!("{base}/folder/{{name}}")},
        "delete": {"method": "DELETE", "url": format!("{base}/folder/{{name}}")},
        "list": {
            "method": "PROPFIND",
            "url": format!("{base}/folder/?prefix={{prefix}}"),
            "namesRegex": "<d:href>/folder/([^<]+)</d:href>"
        },
        "retry": retry_429_5xx()
    }));
    let config = Config::from_settings(&settings).unwrap();
    let s: Arc<dyn Storage> = Arc::new(TemplateStorage::new(&settings, &config).unwrap());

    s.put("streams/two/step/file.seg", b"two-hop-payload").await.unwrap();
    {
        let st = state.lock().await;
        assert_eq!(st.uploads, 1, "第二跳必须落到 /upload/");
        assert_eq!(st.objects["streams~two~step~file.seg"], b"two-hop-payload");
        // 第一跳带 auth 面（none → 空），第二跳（presigned）恒无 auth 头。
        let put_log: Vec<&Record> = st.log.iter().filter(|r| r.path.contains("/upload/")).collect();
        assert_eq!(put_log.len(), 1);
        assert!(put_log[0].auth.is_empty(), "第二跳不得携带 auth 头（Go presigned）");
        assert_eq!(st.log[0].path, "/api/link?name=streams~two~step~file.seg");
    }

    // 反例：hrefPath 越界（JSON 里没有该路径）→ 操作被拒。
    let bad = template_settings(json!({
        "flatten": true,
        "auth": auth_none(),
        "put": {
            "method": "POST",
            "url": format!("{base}/api/link?name={{name}}"),
            "hrefPath": "response.payload.href",
            "hrefMethod": "PUT"
        },
        "get": {"method": "GET", "url": format!("{base}/folder/{{name}}")},
        "delete": {"method": "DELETE", "url": format!("{base}/folder/{{name}}")},
        "list": {
            "method": "PROPFIND",
            "url": format!("{base}/folder/?prefix={{prefix}}"),
            "namesRegex": "<d:href>/folder/([^<]+)</d:href>"
        },
        "retry": retry_429_5xx()
    }));
    let bad_config = Config::from_settings(&bad).unwrap();
    let bad_storage: Arc<dyn Storage> = Arc::new(TemplateStorage::new(&bad, &bad_config).unwrap());
    let err = bad_storage.put("streams/x/y.seg", b"p").await.unwrap_err();
    assert!(
        err.to_string().contains("no href at response.payload.href"),
        "越界 hrefPath 必须显式拒绝: {err}"
    );
}

// ── 用例 3：oauth2 token 复用与 401 失效重取 ────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn template_oauth2_token_reuse_and_invalidation() {
    let (state, base) = start_mock().await;
    let auth = json!({
        "type": "oauth2",
        "tokenUrl": format!("{base}/token"),
        "form": {"grant_type": "refresh_token", "refresh_token": "{secret0}"},
        "header": {"Authorization": "Bearer {token}"}
    });
    let storage = backend(&base, auth, retry_429_5xx());
    let s = storage.as_ref();

    s.put("streams/o/0.seg", b"1").await.unwrap();
    s.get("streams/o/0.seg").await.unwrap();
    {
        let st = state.lock().await;
        assert_eq!(st.tokens, 1, "缓存命中不得重取 token");
        assert_eq!(st.auth_seen, "Bearer tok-fake");
    }

    state.lock().await.unauthorized_left = 1;
    s.put("streams/o/1.seg", b"2").await.unwrap();
    let st = state.lock().await;
    assert_eq!(st.tokens, 2, "401 必须失效 token 并重取");
    assert!(st.objects.contains_key("streams~o~1.seg"), "重取后操作必须成功");
}

// ── 用例 4：retry.status 与 rateReason 退避重试 ─────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn template_retry_on_configured_status() {
    let (state, base) = start_mock().await;
    let storage = backend(&base, auth_none(), retry_429_5xx());
    let s = storage.as_ref();

    state.lock().await.too_many_left = 2;
    s.put("streams/r/0.seg", b"payload").await.unwrap();
    let st = state.lock().await;
    let puts: Vec<&Record> = st.log.iter().filter(|r| r.method == "PUT").collect();
    assert_eq!(puts.len(), 3, "两次 429 + 一次成功 = 3 次请求: {puts:?}");
    assert!(st.objects.contains_key("streams~r~0.seg"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn template_retry_on_rate_reason() {
    let (state, base) = start_mock().await;
    let storage = backend(&base, auth_none(), json!({"rateReason": "error.description"}));
    let s = storage.as_ref();

    state.lock().await.forbidden_left = 1;
    s.put("streams/rr/0.seg", b"payload").await.unwrap();
    let st = state.lock().await;
    let puts: Vec<&Record> = st.log.iter().filter(|r| r.method == "PUT").collect();
    assert_eq!(puts.len(), 2, "403 + rate reason 必须重试一次: {puts:?}");
    assert!(st.objects.contains_key("streams~rr~0.seg"));
}

// ── 用例 5：basic auth 与 subst 变量 ───────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn template_basic_auth_header() {
    let (state, base) = start_mock().await;
    let auth = json!({
        "type": "basic",
        "username": "user-{folder}",
        "password": "pass-{secret0}"
    });
    let storage = backend(&base, auth, retry_429_5xx());
    let s = storage.as_ref();
    s.put("streams/b/0.seg", b"x").await.unwrap();
    let expected = format!(
        "Basic {}",
        base64_encode(b"user-folder:pass-refresh-secret", Base64Alphabet::Std, true)
    );
    assert_eq!(state.lock().await.auth_seen, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn template_subst_variables_in_url_and_headers() {
    let (state, base) = start_mock().await;
    let settings = template_settings(json!({
        "flatten": true,
        "auth": {"type": "none"},
        "put": {
            "method": "PUT",
            "url": format!("{base}/folder/{{name}}?f={{folder}}&s={{secret0}}"),
            "headers": {"X-Folder": "{folder}"}
        },
        "get": {"method": "GET", "url": format!("{base}/folder/{{name}}")},
        "delete": {"method": "DELETE", "url": format!("{base}/folder/{{name}}")},
        "list": {
            "method": "PROPFIND",
            "url": format!("{base}/folder/?prefix={{prefix}}"),
            "namesRegex": "<d:href>/folder/([^<]+)</d:href>"
        },
        "retry": retry_429_5xx()
    }));
    let config = Config::from_settings(&settings).unwrap();
    let s: Arc<dyn Storage> = Arc::new(TemplateStorage::new(&settings, &config).unwrap());
    s.put("streams/v/0.seg", b"x").await.unwrap();
    let st = state.lock().await;
    assert_eq!(
        st.log[0].path, "/folder/streams~v~0.seg?f=folder&s=refresh-secret",
        "name/folder/secret0 变量必须替换"
    );
    assert_eq!(st.auth_seen, "", "auth none 不得带 Authorization 头");
}
