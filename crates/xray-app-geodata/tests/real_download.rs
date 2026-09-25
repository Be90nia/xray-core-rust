//! Real AssetDownloader 真下载测试。
//!
//! 对应 Go `downloader.download` — 用 std::net TCP 写最小 HTTP/1.1 GET。
//! 测试环境：loopback TcpListener 返回固定响应。

use std::{
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use xray_app_geodata::downloader::{AssetDownloader, RealAssetDownloader};

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
fn real_downloader_respects_request_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
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
