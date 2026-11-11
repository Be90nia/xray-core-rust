//! `s3` 后端**对真实 S3 服务**的端到端锚：对象面（moto 侧独立观测 xdrive 写的
//! 对象，逐字节比对）+ 会话面（真 dial → 真 serve → 1MiB 双向逐字节 → 双侧
//! shutdown → collector 回收）。进程内 mock（`tests/s3_e2e.rs`）仍是快速面；本
//! 文件跑**独立实现**（`python -m moto.server`），证明 SigV4/分页/对象布局对第三
//! 方 S3 实现成立。
//!
//! 门控（双闸，两道都过才真跑）：
//! - `#[ignore]`：需要外部 moto 进程，默认 `cargo test` 不碰；
//! - `XDRIVE_S3_ENDPOINT`（如 `http://127.0.0.1:5000`）：未设即打印 SKIP 返回。
//!
//! 复跑：
//! ```text
//! python -m moto.server -p 5000
//! XDRIVE_S3_ENDPOINT=http://127.0.0.1:5000 \
//!   cargo test -p xray-transport-xdrive --test s3_real_backend -- --ignored --nocapture
//! ```
//!
//! moto 的两条实测约束（观测客户端因此带固定假签名头）：①不校验 SigV4 真伪，但
//! **要求请求带 `Authorization`**（无凭据的 GET 返 403）；②对象 PUT 必须带非 form
//! 的 `Content-Type`（`application/x-www-form-urlencoded` 会被 werkzeug 当表单吃掉
//! body，静默存成 0 字节）——xdrive 自己的 PUT 固定 `application/octet-stream`。

use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    sync::Mutex,
};
use xray_transport::dialer::StreamSettings;
use xray_transport_xdrive::{
    dial, serve,
    storage::{new_storage, reset_shared_storage},
};

/// `xdriveSettings.remoteFolder`：对象 key 的顶层前缀。
const ROOT: &str = "streams";
/// 端点门（`http://host:port`）。
const ENDPOINT_ENV: &str = "XDRIVE_S3_ENDPOINT";

/// 共享实例表是进程级全局：本文件两个用例串行执行。
static SERIAL: Mutex<()> = Mutex::const_new(());
/// 同一次运行内的桶名去重（pid 已区分不同次运行）。
static SEQ: AtomicU32 = AtomicU32::new(0);

// ── moto 观测客户端（独立实现侧读，不经 xdrive 的 S3 客户端）────────────────

struct Endpoint {
    host: String,
    port: u16,
}

fn endpoint() -> Option<Endpoint> {
    let raw = std::env::var(ENDPOINT_ENV).ok()?;
    let rest = raw.trim_end_matches('/');
    let Some(rest) = rest.strip_prefix("http://") else {
        panic!("{ENDPOINT_ENV} must be an http:// URL (moto server), got {raw}")
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.parse().expect("endpoint port")),
        None => (rest.to_string(), 80),
    };
    Some(Endpoint { host, port })
}

/// moto 只要求有凭据头（不验签），故固定一份假 SigV4 头。
const AUTH_HEADER: &str = concat!(
    "Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/us-east-1/s3/",
    "aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=0000\r\n",
    "x-amz-date: 20260101T000000Z\r\n",
    "x-amz-content-sha256: UNSIGNED-PAYLOAD\r\n",
);

/// 一条 HTTP/1.1 请求（`Connection: close` + 读到 EOF，无需 chunked 解码）。
async fn moto(ep: &Endpoint, method: &str, target: &str, body: Option<&[u8]>) -> (u16, Vec<u8>) {
    let mut sock = TcpStream::connect((ep.host.as_str(), ep.port)).await.expect("connect moto");
    let mut head = format!(
        "{method} {target} HTTP/1.1\r\nHost: {}:{}\r\n{AUTH_HEADER}Connection: close\r\n",
        ep.host, ep.port
    );
    if let Some(body) = body {
        head.push_str(&format!(
            "Content-Type: application/octet-stream\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    head.push_str("\r\n");
    sock.write_all(head.as_bytes()).await.expect("write moto request");
    if let Some(body) = body {
        sock.write_all(body).await.expect("write moto body");
    }
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).await.expect("read moto response");
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("moto headers") + 4;
    let status = std::str::from_utf8(&raw[..split])
        .expect("ascii headers")
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .expect("moto status line");
    (status, raw[split..].to_vec())
}

async fn create_bucket(ep: &Endpoint, bucket: &str) {
    let (status, _) = moto(ep, "PUT", &format!("/{bucket}"), None).await;
    assert_eq!(status, 200, "PUT /{bucket} must create the moto bucket");
}

/// ListObjectsV2 全量 key（单页 1000 条足够：本文件对象数远小于此）。
async fn list_keys(ep: &Endpoint, bucket: &str, prefix: &str) -> Vec<String> {
    let target = format!("/{bucket}?list-type=2&prefix={prefix}&max-keys=1000");
    let (status, body) = moto(ep, "GET", &target, None).await;
    assert_eq!(status, 200, "ListObjectsV2 must succeed");
    let xml = String::from_utf8(body).expect("xml body");
    let mut keys = Vec::new();
    let mut rest = xml.as_str();
    while let Some(start) = rest.find("<Key>") {
        let tail = &rest[start + 5..];
        let Some(end) = tail.find("</Key>") else { break };
        keys.push(tail[..end].to_string());
        rest = &tail[end..];
    }
    keys
}

fn new_bucket(tag: &str) -> String {
    format!("xdrive-real-{}-{tag}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed))
}

/// 会话级设置：小段/快轮询/短 TTL（collector 回收判据秒级可观测）+ 真 moto 端点。
fn s3_settings(ep: &Endpoint, bucket: &str) -> StreamSettings {
    StreamSettings::from_json(Some(&json!({
        "network": "xdrive",
        "address": ep.host,
        "port": ep.port,
        "xdriveSettings": {
            "service": "s3",
            "remoteFolder": ROOT,
            "secrets": ["AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"],
            "segmentBytes": 256 * 1024,
            "flushIntervalMs": 10,
            "pollIntervalMs": 20,
            "maxPollIntervalMs": 100,
            "sessionTtlSeconds": 1,
            "concurrency": 4,
            "s3": {
                "endpoint": format!("http://{}:{}", ep.host, ep.port),
                "region": "us-east-1",
                "bucket": bucket,
                "pathStyle": true
            }
        }
    })))
}

// ── 用例 ─────────────────────────────────────────────────────────────────

/// 对象面（验收①/③）：走真实 `new_storage` 的 s3 分派臂写一个 64KiB 对象 → moto
/// 侧独立列出并逐字节读回 → 删除后 moto 侧列表清空。
#[ignore = "needs a running moto S3 server (XDRIVE_S3_ENDPOINT)"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_object_plane_is_observable_from_moto() {
    let Some(ep) = endpoint() else {
        eprintln!("SKIP: {ENDPOINT_ENV} unset (needs a running moto server)");
        return;
    };
    let _guard = SERIAL.lock().await;
    let bucket = new_bucket("obj");
    create_bucket(&ep, &bucket).await;
    reset_shared_storage();

    let settings = s3_settings(&ep, &bucket);
    let storage = new_storage(&settings).expect("s3 dispatch arm must build");
    let name = "objcheck/000000000.seg";
    let payload: Vec<u8> = (0..64 * 1024usize).map(|i| (i * 7 % 251) as u8).collect();
    storage.put(name, &payload).await.expect("put through the s3 backend");

    let key = format!("{ROOT}/{name}");
    let keys = list_keys(&ep, &bucket, ROOT).await;
    assert_eq!(keys, vec![key.clone()], "moto must list exactly the object xdrive wrote");
    let (status, body) = moto(&ep, "GET", &format!("/{bucket}/{key}"), None).await;
    assert_eq!(status, 200, "moto GET must succeed");
    assert_eq!(body, payload, "moto must return the exact bytes xdrive wrote");
    eprintln!("moto s3: {key} -> {} bytes read back byte-equal", body.len());

    storage.delete(name).await.expect("delete through the s3 backend");
    let left = list_keys(&ep, &bucket, ROOT).await;
    assert!(left.is_empty(), "delete must clear the object, left: {left:?}");
    reset_shared_storage();
}

/// 会话面（验收②）：真 dial → 真 serve → 1MiB 双向逐字节 → 双侧 shutdown →
/// collector 回收（moto 侧独立观测 `{ROOT}/` 前缀清空）。
#[ignore = "needs a running moto S3 server (XDRIVE_S3_ENDPOINT)"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_dial_serve_roundtrip_1mib_over_moto() {
    use xray_common::net::{
        address::Address, destination::Destination, network::Network, port::Port,
    };
    use xray_transport::{connection::Connection, listener_registry::ConnHandler};

    let Some(ep) = endpoint() else {
        eprintln!("SKIP: {ENDPOINT_ENV} unset (needs a running moto server)");
        return;
    };
    let _guard = SERIAL.lock().await;
    let bucket = new_bucket("sess");
    create_bucket(&ep, &bucket).await;
    reset_shared_storage();

    let settings = s3_settings(&ep, &bucket);
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
    let mut peer = tokio::time::timeout(Duration::from_secs(60), conn_rx.recv())
        .await
        .expect("listener must accept the announced session in time")
        .expect("handler channel closed");

    // 上行 1MiB（256KiB/段 ⇒ 多段）逐字节比对。
    let payload: Vec<u8> = (0..1024 * 1024usize).map(|i| (i * 7 % 251) as u8).collect();
    client.write_all(&payload).await.expect("uplink write");
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(120), peer.read_exact(&mut received))
        .await
        .expect("1MiB uplink must arrive in time")
        .expect("uplink read");
    assert_eq!(received, payload, "1MiB uplink must arrive byte-equal");

    // 下行回写 → 客户端读（对端分段对象逐字节重组）。
    peer.write_all(&received).await.expect("downlink write");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(120), client.read_exact(&mut echoed))
        .await
        .expect("1MiB downlink must arrive in time")
        .expect("downlink read");
    assert_eq!(echoed, payload, "1MiB downlink must arrive byte-equal");

    client.shutdown().await.expect("client shutdown");
    peer.shutdown().await.expect("peer shutdown");
    drop(listener);

    // collector：sessionTtl 1s、每 500ms 一轮；moto 侧独立观测对象表清空。
    let mut left = Vec::new();
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        left = list_keys(&ep, &bucket, ROOT).await;
        if left.is_empty() {
            break;
        }
    }
    assert!(left.is_empty(), "collector must reclaim every {ROOT}/ object, left: {left:?}");
    eprintln!(
        "moto s3: 1MiB uplink+downlink byte-equal, collector reclaimed every {ROOT}/ object \
         (bucket {bucket})"
    );
    reset_shared_storage();
}
