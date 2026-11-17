//! `template` 后端生命周期锚（bd hjtlk B2 验收①）：
//! 真 dial → 真 serve → 对象读写删 → collector 回收 streams/<sid>。
//! mock hyper 服务端承载 flatten 键空间（Go `xdrive_test.go` fakeStore 形态，
//! DELETE 对 `streams~<sid>` 前缀按子树语义回收 = `Storage::delete` 契约）。

#![allow(clippy::disallowed_methods)]
#![allow(clippy::unwrap_used)] // 测试断言便利豁免（bd g3cr）
#![allow(clippy::print_stderr)]

use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    sync::{Mutex, mpsc},
};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_transport::{
    connection::Connection, dialer::StreamSettings, listener_registry::ConnHandler,
};
use xray_transport_xdrive::{dial, serve};

// ── mock 对象存储（flatten 键空间） ──────────────────────────────────────────

#[derive(Default)]
struct MockState {
    objects: BTreeMap<String, Vec<u8>>,
    // PUT 计数（bd xss2v 断言承重件）：`.seg` 在 store 里是 PUT→GET→DELETE 瞬态，
    // 在场断言不可靠 ⇒ 改数单调 PUT 次数（不受删除时序影响）。
    puts: AtomicUsize,
}

async fn handle(
    req: Request<Incoming>,
    state: Arc<Mutex<MockState>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    let body = req.into_body().collect().await.map(|c| c.to_bytes()).unwrap_or_default();

    let mut st = state.lock().await;
    let route = path.split('?').next().unwrap_or_default();
    let Some(key) = route.strip_prefix("/folder/") else {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .unwrap());
    };
    match method.as_str() {
        "PUT" => {
            st.puts.fetch_add(1, Ordering::Relaxed); // bd xss2v 断言计数
            st.objects.insert(key.to_string(), body.to_vec());
            Ok(Response::builder()
                .status(StatusCode::CREATED)
                .body(Full::new(Bytes::new()))
                .unwrap())
        },
        "GET" => match st.objects.get(key) {
            Some(data) => Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::copy_from_slice(data)))
                .unwrap()),
            None => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::new()))
                .unwrap()),
        },
        "DELETE" => {
            if key.starts_with("streams~") {
                let prefix = key.to_string();
                st.objects.retain(|k, _| !k.starts_with(&prefix));
            } else {
                st.objects.remove(key);
            }
            Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::new(Bytes::new()))
                .unwrap())
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
        _ => Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::new()))
            .unwrap()),
    }
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

fn template_settings(base: &str) -> StreamSettings {
    StreamSettings::from_json(Some(&json!({
        "network": "xdrive",
        "xdriveSettings": {
            "service": "template",
            "remoteFolder": "folder",
            "flushIntervalMs": 5,
            "pollIntervalMs": 5,
            "maxPollIntervalMs": 20,
            "sessionTtlSeconds": 2,
            "segmentBytes": 65536,
            "eagerWindowMs": 200,
            "template": {
                "flatten": true,
                "auth": {"type": "none"},
                "put": {"method": "PUT", "url": format!("{base}/folder/{{name}}")},
                "get": {"method": "GET", "url": format!("{base}/folder/{{name}}")},
                "delete": {"method": "DELETE", "url": format!("{base}/folder/{{name}}")},
                "list": {
                    "method": "PROPFIND",
                    "url": format!("{base}/folder/?prefix={{prefix}}"),
                    "namesRegex": "<d:href>/folder/([^<]+)</d:href>"
                },
                "retry": {"status": [429, 500, 502, 503]}
            },
            "xmux": {"maxConnections": {"from": 1, "to": 1}}
        }
    })))
}

/// 用例：dial→serve→1MiB 双向逐字节相等→双侧关闭→collector 回收（对象级断言）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn template_roundtrip_1mib_and_collector_reclaim() {
    let (state, base) = start_mock().await;
    let settings = template_settings(&base);

    // serve（生产入口）：accept 到的连接进 channel。
    let (conn_tx, mut conn_rx) = mpsc::channel::<Box<dyn Connection>>(4);
    let handler: ConnHandler = Arc::new(move |conn| {
        // 满载即随 drop 走兜底关闭序（测试面单会话，通道容量恒够）。
        let _ = conn_tx.try_send(conn);
    });
    let listener =
        serve("127.0.0.1:0".parse().unwrap(), settings.clone(), Default::default(), handler)
            .await
            .unwrap();

    // 出站侧：真 dial（配置解析 + 共享 template 后端 + announce 投递 + WAL Conn）。
    let dest = Destination::new(Address::new_domain("xdrive.test"), Port::new(443), Network::TCP);
    let mut client = dial(&dest, &Default::default(), &settings).await.unwrap();

    // 入站侧 accept（announce → claim → Conn 交付）。
    let mut server = tokio::time::timeout(Duration::from_secs(10), conn_rx.recv())
        .await
        .expect("listener must accept the announced session in time")
        .expect("handler channel closed");

    // 段 PUT 计数基线（此刻 announce 已 PUT，put 计数 = 1）。
    let seg_puts_before = state.lock().await.puts.load(Ordering::Relaxed);

    // 1MiB 上行：客户端写 → 服务端读，逐字节相等（全部经 template PUT 分段承载）。
    let payload: Vec<u8> = (0..1024 * 1024usize).map(|i| (i * 7 % 251) as u8).collect();
    client.write_all(&payload).await.unwrap();
    let mut received = vec![0u8; payload.len()];
    server.read_exact(&mut received).await.unwrap();
    assert_eq!(received, payload, "1MiB uplink must arrive byte-equal");

    // 1MiB 下行：服务端回写 → 客户端读（对端分段对象逐字节重组）。
    server.write_all(&received).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload, "1MiB downlink must arrive byte-equal");

    // 中途校验：对象确经 mock 服务端存储（读写删走 HTTP 四操作）。
    // bd xss2v 修正：`.seg` 在 store 里是 PUT→GET→DELETE 的**瞬态**——读侧 poll 把
    // 段推给消费者通道的同一刻就把段名投进 discard 队列（wal.rs `tx.send` 后紧跟
    // `discards_tx.try_send`），与 app 是否已 read 无关；传输完成后 store 被删净是
    // 常态（CI Linux --release 每次都赢下这场 µs 级竞速 ⇒ 轮询 objects=[] 假失败，
    // 且传输停止后不再有新 PUT，等待只会更空）。改用单调 PUT 计数：字节相等本身
    // 证明段经 mock 中转（store-and-forward 唯一管道），计数不受删除时序影响。
    let puts_after = state.lock().await.puts.load(Ordering::Relaxed);
    assert!(
        puts_after.saturating_sub(seg_puts_before) >= 32,
        "1MiB 双向 = 32 个 WAL 段必须经 mock PUT 中转（传输前 {seg_puts_before}，传输后 {puts_after}）: {:?}",
        state.lock().await.objects.keys().collect::<Vec<_>>()
    );

    // 双侧关闭（Go Close 序：冲净 + `.end` → 对端 EOF）。
    client.shutdown().await.unwrap();
    server.shutdown().await.unwrap();

    // streams/<sid> 被 collector 回收：TTL 2s + collect 间隔 1s，给 12s 余量轮询。
    let mut reclaimed = false;
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if !state.lock().await.objects.keys().any(|k| k.starts_with("streams~")) {
            reclaimed = true;
            break;
        }
    }
    assert!(reclaimed, "collector must reclaim streams/ objects after both conns closed");

    listener.close().unwrap();
}
