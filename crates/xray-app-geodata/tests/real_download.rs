//! Real AssetDownloader 真下载测试。
//!
//! 对应 Go `downloader.download` — 用 std::net TCP 写最小 HTTP/1.1 GET。
//! 测试环境：loopback TcpListener 返回固定响应。

// 集成测试夹具不在 `#[test]` 函数体内，根 clippy.toml 的 allow-unwrap-in-tests 覆盖不到。
#![allow(clippy::unwrap_used, reason = "集成测试夹具不在 #[test] 函数体内")]

use std::{
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use xray_app_geodata::{
    GeodataError,
    downloader::{AssetDownloader, RealAssetDownloader},
};

/// 一次性 HTTP 服务器：accept 一个连接，回写固定 response。
struct OneShotServer {
    addr: std::net::SocketAddr,
    request_log: Arc<Mutex<Vec<String>>>,
}

fn spawn_server(body: Vec<u8>) -> OneShotServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let log_clone = Arc::clone(&log);
    let body_for_thread = body.clone();
    #[allow(
        clippy::disallowed_methods,
        reason = "测试：本地 HTTP stub 服务器线程，随进程退出回收"
    )]
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let mut req = Vec::new();
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        req.extend_from_slice(&buf[..n]);
                        if req.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    },
                    Err(_) => break,
                }
            }
            log_clone.lock().unwrap().push(String::from_utf8_lossy(&req).to_string());
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                body_for_thread.len()
            );
            stream.write_all(resp.as_bytes()).unwrap();
            stream.write_all(&body_for_thread).unwrap();
            stream.flush().ok();
        }
    });
    OneShotServer { addr, request_log: log }
}

#[allow(
    clippy::disallowed_methods,
    reason = "713x6：测试 unique_dir 取时保持原语义（测试计时不得改语义）"
)]
fn unique_dir(name: &str) -> PathBuf {
    let mut base = std::env::temp_dir();
    base.push(format!(
        "xray-app-geodata-real-{}-{}-{name}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}

#[test]
fn real_downloader_fetches_via_loopback_http() {
    let server = spawn_server(b"PAYLOAD-123".to_vec());
    let dir = unique_dir("loopback_ok");
    let dl = RealAssetDownloader::new(dir.clone());

    let url = format!("http://{}/geoip.dat", server.addr);
    let temp = dir.join("downloaded.tmp");
    dl.download_to(&url, &temp).expect("download ok");

    let content = std::fs::read(&temp).unwrap();
    assert_eq!(content, b"PAYLOAD-123");

    let log = server.request_log.lock().unwrap();
    assert!(log[0].starts_with("GET /geoip.dat"));
    assert!(log[0].to_lowercase().contains("host:"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn real_downloader_errors_on_non_2xx() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    #[allow(
        clippy::disallowed_methods,
        reason = "测试：本地 HTTP stub 服务器线程，随进程退出回收"
    )]
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf);
            stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").unwrap();
            stream.flush().ok();
        }
    });
    let dir = unique_dir("loopback_404");
    let dl = RealAssetDownloader::new(dir.clone());
    let url = format!("http://{}/x.dat", addr);
    let temp = dir.join("x.tmp");
    let err = dl.download_to(&url, &temp).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("404") || msg.to_lowercase().contains("status"),
        "expected 404 status error, got: {msg}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn real_downloader_errors_on_connection_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let dir = unique_dir("refused");
    let dl = RealAssetDownloader::new(dir.clone());
    let url = format!("http://{}/x.dat", addr);
    let temp = dir.join("x.tmp");
    let err = dl.download_to(&url, &temp).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("refused")
            || msg.to_lowercase().contains("connect")
            || msg.to_lowercase().contains("io")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn real_downloader_resolve_target_under_dir() {
    let dir = unique_dir("resolve");
    let dl = RealAssetDownloader::new(dir.clone());
    let target = dl.resolve_target("geoip.dat").unwrap();
    assert!(target.starts_with(&dir));
    assert!(target.ends_with("geoip.dat"));
}

#[test]
fn real_downloader_resolve_rejects_empty() {
    let dir = unique_dir("resolve_empty");
    let dl = RealAssetDownloader::new(dir);
    assert!(dl.resolve_target("").is_err());
}

#[test]
fn real_downloader_follows_redirect_to_next_hop() {
    // 302 → https://127.0.0.1:1/f.dat：证明循环真按 Location 重新拨号（端口 1 必被拒）。
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    #[allow(
        clippy::disallowed_methods,
        reason = "测试：本地 HTTP stub 服务器线程，随进程退出回收"
    )]
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf);
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:1/f.dat\r\nContent-Length: 0\r\n\r\n",
                )
                .unwrap();
            stream.flush().ok();
        }
    });
    let dir = unique_dir("redirect_follow");
    let dl = RealAssetDownloader::new(dir.clone()).with_timeout(Duration::from_millis(500));
    let url = format!("http://{}/x.dat", addr);
    let temp = dir.join("x.tmp");
    let err = dl.download_to(&url, &temp).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("connect 127.0.0.1:1"), "expected second-hop dial, got: {msg}");
    assert!(!temp.exists(), "redirect must not write temp file");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn real_downloader_rejects_insecure_redirect() {
    // Go CheckRedirect：目标 scheme != https → InsecureRedirect（http→http 也拒）。
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    #[allow(
        clippy::disallowed_methods,
        reason = "测试：本地 HTTP stub 服务器线程，随进程退出回收"
    )]
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 301 Moved\r\nLocation: http://{addr}/plain.dat\r\nContent-Length: 0\r\n\r\n"
            );
            stream.write_all(resp.as_bytes()).unwrap();
            stream.flush().ok();
        }
    });
    let dir = unique_dir("redirect_insecure");
    let dl = RealAssetDownloader::new(dir.clone());
    let url = format!("http://{}/x.dat", addr);
    let temp = dir.join("x.tmp");
    let err = dl.download_to(&url, &temp).unwrap_err();
    assert!(matches!(err, GeodataError::InsecureRedirect(_)), "got {err:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn real_downloader_rejects_redirect_without_location() {
    // 无 Location 的 3xx 无从跟随 → Go fetch 的 ">= 300 → unexpected status" 语义。
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    #[allow(
        clippy::disallowed_methods,
        reason = "测试：本地 HTTP stub 服务器线程，随进程退出回收"
    )]
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf);
            stream.write_all(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n").unwrap();
            stream.flush().ok();
        }
    });
    let dir = unique_dir("redirect_no_location");
    let dl = RealAssetDownloader::new(dir.clone());
    let url = format!("http://{}/x.dat", addr);
    let temp = dir.join("x.tmp");
    let err = dl.download_to(&url, &temp).unwrap_err();
    assert!(matches!(err, GeodataError::UnexpectedStatus(304)), "got {err:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn real_downloader_respects_request_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    #[allow(clippy::disallowed_methods, reason = "测试：本地 HTTP stub 服务器线程，随进程退出回收")]
    let h = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            std::thread::sleep(Duration::from_secs(5));
            drop(stream);
        }
    });
    let dir = unique_dir("timeout");
    let dl = RealAssetDownloader::new(dir.clone()).with_timeout(Duration::from_millis(300));
    let url = format!("http://{}/x.dat", addr);
    let temp = dir.join("x.tmp");
    #[allow(clippy::disallowed_methods, reason = "测试：timeout 断言计时起点")]
    let start = std::time::Instant::now();
    let res = dl.download_to(&url, &temp);
    let elapsed = start.elapsed();
    assert!(res.is_err(), "expected timeout error, got {res:?}");
    assert!(
        elapsed < Duration::from_secs(3),
        "timeout should fire within reasonable window, took {elapsed:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    drop(h);
}
