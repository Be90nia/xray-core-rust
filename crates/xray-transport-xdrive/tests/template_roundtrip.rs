//! `template` 后端生命周期锚（bd hjtlk B2 验收①）：
//! 真 dial → 真 serve → 对象读写删 → collector 回收 streams/<sid>。
//! mock hyper 服务端承载 flatten 键空间（Go `xdrive_test.go` fakeStore 形态，
//! DELETE 对 `streams~<sid>` 前缀按子树语义回收 = `Storage::delete` 契约）。

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
    {
        let st = state.lock().await;
        assert!(
            st.objects.keys().any(|k| k.starts_with("streams~") && k.ends_with(".seg")),
            "WAL 分段必须落在 mock 对象存储: {:?}",
            st.objects.keys().collect::<Vec<_>>()
        );
    }

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
