//! B0 U1 spike：hyper extended CONNECT（RFC 8441 `:protocol`）全链路验证。
//!
//! 规划：`docs/architecture/xray-frame-masque-实施计划-2026-11-11.md` §5 B0 / §6 门 B0。
//!
//! 断言（四条，缺一即失败）：
//! ① server 侧收到 `:protocol=connect-ip` 与 `:method=CONNECT`
//!   （`:protocol` 经 `hyper::ext::Protocol` extensions 暴露，
//!   hyper-1.10.1 `proto/h2/server.rs:306-308`）
//! ② client 拿到 `200` + `Upgraded`（全双工）
//! ③ 双向各 1 KB 字节一致
//! ④ CONNECT 请求体非空 → 必须 `Err`（hyper-1.10.1 `proto/h2/client.rs:722-731`
//!   `new_user_invalid_connect()`；经 `send_request().await` 上抛）
//!
//! hyper 1.x 的 `Upgraded` 只实现 `hyper::rt::{Read, Write}`（`upgrade.rs:166,176`），
//! tokio 侧读写经 `hyper_util::rt::TokioIo` 适配。
//!
//! 测试基建 spawn 豁免（坑约束 #5）：本文件内的 `tokio::spawn` 均为测试 server/client
//! 任务基建（spawn 三分类②「压测/测试基建」），随用随弃，无托管需求。
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use http_body_util::Full;
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    ext::Protocol,
    service::service_fn,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

const ECHO_LEN: usize = 1024;

// 请求体统一 Full<Bytes>（SendRequest 的 body 类型参数与之一致）；
// CONNECT 空 body = Full::new(Bytes::new())（exact size 0 → hyper 允许，client.rs:716-721）。
fn empty_body() -> Full<Bytes> {
    Full::new(Bytes::new())
}

/// 起一个 auto(h2) server，`enable_connect_protocol()` 打开 extended CONNECT；
/// 记录收到的 (:protocol, :method) 到 `captured`；对 CONNECT 流做 1KB 回声。
async fn spawn_echo_server(
    captured: Arc<Mutex<Option<(String, Method)>>>,
) -> tokio::io::DuplexStream {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut builder =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        builder
            .http2()
            .enable_connect_protocol()
            .serve_connection_with_upgrades(
                hyper_util::rt::TokioIo::new(server_side),
                service_fn(move |req: Request<Incoming>| {
                    let captured = Arc::clone(&captured);
                    async move {
                        // ① 记录 :protocol（extensions）与 :method
                        let protocol = req
                            .extensions()
                            .get::<Protocol>()
                            .map_or("<missing>", |p| p.as_str())
                            .to_string();
                        *captured.lock().await = Some((protocol, req.method().clone()));

                        // ② CONNECT 成功路径：响应空 body 后走 upgrade 回声
                        let upgrade = hyper::upgrade::on(req);
                        tokio::spawn(async move {
                            let upgraded = match upgrade.await {
                                Ok(io) => io,
                                Err(e) => {
                                    eprintln!("server upgrade failed: {e}");
                                    return;
                                },
                            };
                            let mut io = hyper_util::rt::TokioIo::new(upgraded);
                            let mut buf = vec![0u8; ECHO_LEN];
                            if io.read_exact(&mut buf).await.is_err() {
                                return;
                            }
                            if io.write_all(&buf).await.is_err() {
                                return;
                            }
                            let _ = io.flush().await;
                        });

                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(empty_body())
                                .expect("static response builds"),
                        )
                    }
                }),
            )
            .await
            .expect("server h2 connection should serve cleanly");
    });
    client_side
}

/// 与 [`spawn_echo_server`] 同款 server，但只记录请求不做回声（供断言④复用）。
async fn spawn_record_only_server(
    captured: Arc<Mutex<Option<(String, Method)>>>,
) -> tokio::io::DuplexStream {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut builder =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        builder
            .http2()
            .enable_connect_protocol()
            .serve_connection_with_upgrades(
                hyper_util::rt::TokioIo::new(server_side),
                service_fn(move |req: Request<Incoming>| {
                    let captured = Arc::clone(&captured);
                    async move {
                        let protocol = req
                            .extensions()
                            .get::<Protocol>()
                            .map_or("<missing>", |p| p.as_str())
                            .to_string();
                        *captured.lock().await = Some((protocol, req.method().clone()));
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(empty_body())
                                .expect("static response builds"),
                        )
                    }
                }),
            )
            .await
            .ok(); // 断言④路径 client 可能中途断开，server 侧错误不打断测试
    });
    client_side
}

async fn spawn_client(
    io: tokio::io::DuplexStream,
) -> hyper::client::conn::http2::SendRequest<Full<Bytes>> {
    let (send_request, connection) =
        hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .handshake(hyper_util::rt::TokioIo::new(io))
            .await
            .expect("client h2 handshake should succeed");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("client connection ended: {e}");
        }
    });
    send_request
}

#[tokio::test]
async fn extended_connect_full_chain() {
    let captured = Arc::new(Mutex::new(None));
    let io = spawn_echo_server(Arc::clone(&captured)).await;
    let mut send_request = spawn_client(io).await;

    // CONNECT-IP 请求形态（规划 §2.3 / Go connectip/request.go:20-42）：
    // :method=CONNECT + :protocol=connect-ip + 绝对 URL + 空 body。
    let mut req = Request::builder()
        .method(Method::CONNECT)
        .uri("https://masque.example/.well-known/masque/ip/*/*/")
        .body(empty_body())
        .expect("request builds");
    req.extensions_mut().insert(Protocol::from_static("connect-ip"));

    // ② 200 + Upgraded
    let response =
        send_request.send_request(req).await.expect("② extended CONNECT should get a 200 response");
    assert_eq!(response.status(), StatusCode::OK, "② server must answer 200 to extended CONNECT");
    let upgraded = hyper::upgrade::on(response)
        .await
        .expect("② client must receive the upgraded full-duplex stream");
    let mut upgraded = hyper_util::rt::TokioIo::new(upgraded);

    // ③ 双向各 1KB：client → server → client 逐字节一致
    let payload: Vec<u8> = (0..ECHO_LEN).map(|i| (i % 251) as u8).collect();
    upgraded.write_all(&payload).await.expect("③ write 1KB onto upgraded stream");
    upgraded.flush().await.expect("③ flush");
    let mut echoed = vec![0u8; ECHO_LEN];
    upgraded.read_exact(&mut echoed).await.expect("③ read 1KB echo back");
    assert_eq!(echoed, payload, "③ 1KB payload must round-trip byte-identical");

    // ① server 侧视角
    let (protocol, method) =
        captured.lock().await.clone().expect("① server must have received the request");
    assert_eq!(protocol, "connect-ip", "① server must see :protocol=connect-ip");
    assert_eq!(method, Method::CONNECT, "① server must see :method=CONNECT");
}

#[tokio::test]
async fn connect_with_non_empty_body_errors() {
    let captured = Arc::new(Mutex::new(None));
    let io = spawn_record_only_server(captured).await;
    let mut send_request = spawn_client(io).await;

    let mut req = Request::builder()
        .method(Method::CONNECT)
        .uri("https://masque.example/.well-known/masque/ip/*/*/")
        .body(Full::new(Bytes::from_static(b"connect-cannot-carry-body")))
        .expect("request builds");
    req.extensions_mut().insert(Protocol::from_static("connect-ip"));

    // ④ 非空 body：hyper 在 h2 client 派发层直接判 user error
    // （proto/h2/client.rs:722-731），经 send_request().await 上抛 Err。
    let result = send_request.send_request(req).await;
    assert!(
        result.is_err(),
        "④ CONNECT with non-empty body must Err (hyper new_user_invalid_connect)"
    );
}
