#![allow(dead_code)] // 共享 helper：按测试需要选择性使用
//! Go<->Rust interop test shared helpers.
// Go xray-core subprocess management, port wait, HTTP test request,
// JSON config generation. All interop test files share this module.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::{Child, Command},
    time,
};

// -- Error types -------------------------------------------------------

/// Interop test error.
#[derive(Debug)]
pub enum InteropError {
    GoBinaryNotFound { path: PathBuf },
    GoProcessStartFailed { source: std::io::Error },
    PortTimeout { port: u16, timeout_ms: u64 },
    HttpRequestFailed(String),
    ConfigWrite(String),
    Io(std::io::Error),
}

impl std::fmt::Display for InteropError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GoBinaryNotFound { path } => {
                write!(f, "Go xray binary not found: {}", path.display())
            },
            Self::GoProcessStartFailed { source } => {
                write!(f, "Go xray process failed to start: {source}")
            },
            Self::PortTimeout { port, timeout_ms } => {
                write!(f, "Port {port} not ready within {timeout_ms}ms")
            },
            Self::HttpRequestFailed(s) => write!(f, "HTTP request through proxy failed: {s}"),
            Self::ConfigWrite(s) => write!(f, "Config write error: {s}"),
            Self::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for InteropError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::GoProcessStartFailed { source } => Some(source),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for InteropError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, InteropError>;

// -- Go binary path ----------------------------------------------------

/// Resolve Go xray-core binary path.
///
/// 查找链（PM 拍板 2026-10-22）：`$XRAY_GO_BIN` → 仓内
/// `reports/night-run-*/tmp/*/xray-go.exe` → `dist/xray-go.exe`。
/// 都没有 → `None`，调用方经 [`go_binary_ready`] 打一行 skip 日志后跳过——
/// 禁静默 return，CI/评审必须能在默认 test output 里看到哪些用例没跑。
/// `$XRAY_GO_BIN` 显式指定时不做存在性兜底：路径配错要在 spawn 时响
/// （GoBinaryNotFound），不许把显式配置错配偷偷降级成 skip。
pub fn go_xray_bin_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("XRAY_GO_BIN") {
        return Some(PathBuf::from(p));
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo = manifest.parent()?;
    if let Some(hit) = first_repo_go_binary(repo) {
        return Some(hit);
    }
    let dist = repo.join("dist").join("xray-go.exe");
    dist.is_file().then_some(dist)
}

/// 扫仓内 `reports/night-run-*/tmp/*/xray-go.exe`（排序保证确定性，命中即返）。
/// 手写三层 `read_dir` 而非引入 glob crate——tests 的 dev-deps 不为此加依赖。
fn first_repo_go_binary(repo: &std::path::Path) -> Option<PathBuf> {
    let mut runs: Vec<PathBuf> = std::fs::read_dir(repo.join("reports"))
        .ok()?
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("night-run-")))
        .collect();
    runs.sort();
    for run in runs {
        let Ok(tmps) = std::fs::read_dir(run.join("tmp")) else {
            continue;
        };
        let mut tmps: Vec<PathBuf> =
            tmps.filter_map(std::result::Result::ok).map(|e| e.path()).collect();
        tmps.sort();
        for tmp in tmps {
            let cand = tmp.join("xray-go.exe");
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

/// 互通用例的 Go 二进制门槛：缺失时打一行 skip 日志并返回 `false`，调用方
/// 直接 `return`。禁静默跳过——日志直写 stderr（绕过 libtest 捕获，见
/// [`force_visible_log`]），评审在默认 `cargo test` 输出里就能看到哪些用例没跑。
pub fn go_binary_ready() -> bool {
    match go_xray_bin_path() {
        Some(_) => true,
        None => {
            force_visible_log(
                "skipping: go xray binary not found (set XRAY_GO_BIN or place dist/xray-go.exe)",
            );
            false
        },
    }
}

/// 绕过 libtest 输出捕获直写 stderr。libtest 的捕获是线程局部 OUTPUT_CAPTURE
/// 替换（OS 层 fd 不动），通过用例的 println/eprintln 默认被吞——只有
/// `--nocapture` 或失败才回放；跳过必须默认可见，故从 raw fd/handle 重建
/// `File` 写入。`ManuallyDrop`：所有权不归我们，绝不 close。
fn force_visible_log(msg: &str) {
    use std::io::Write as _;
    #[cfg(unix)]
    {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let mut err = std::mem::ManuallyDrop::new(unsafe {
            std::fs::File::from_raw_fd(std::io::stderr().as_raw_fd())
        });
        let _ = err.write_all(msg.as_bytes());
        let _ = err.write_all(b"\n");
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        let mut err = std::mem::ManuallyDrop::new(unsafe {
            std::fs::File::from_raw_handle(std::io::stderr().as_raw_handle())
        });
        let _ = err.write_all(msg.as_bytes());
        let _ = err.write_all(b"\n");
    }
}

// -- Go xray subprocess management -------------------------------------

/// Start Go xray-core subprocess with the given config file.
// Returns child handle. kill_on_drop is set so child dies if handle drops.
pub async fn start_go_xray(config_path: &std::path::Path) -> Result<Child> {
    let Some(bin) = go_xray_bin_path() else {
        return Err(InteropError::GoBinaryNotFound { path: PathBuf::from("dist/xray-go.exe") });
    };
    if !bin.exists() {
        return Err(InteropError::GoBinaryNotFound { path: bin });
    }

    let mut child = Command::new(&bin)
        .arg("run")
        .arg("-c")
        .arg(config_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|source| InteropError::GoProcessStartFailed { source })?;

    // Drain stdout/stderr to log files in the background. Without this, Go
    // xray blocks once its 64KiB pipe buffer fills (access-log traffic),
    // which manifests as the Rust client hanging in read calls.
    // Filenames are unique per spawn（PID + 进程内序号）：同一测试进程并行起
    // 多只 Go 子进程时互不覆盖——此前只有 PID，ss2022 两用例并行时互相截断
    // 日志，现场取证只剩最后落盘的那只。
    static NEXT_GO_SPAWN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let log_id = format!(
        "{}_{}",
        std::process::id(),
        NEXT_GO_SPAWN.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let log_dir = std::env::temp_dir().join("xray_interop_go_logs");
    std::fs::create_dir_all(&log_dir).ok();
    if let Some(stdout) = child.stdout.take() {
        let path = log_dir.join(format!("go_{log_id}_stdout.log"));
        tokio::spawn(async move {
            let mut s = stdout;
            if let Ok(f) = tokio::fs::File::create(path).await {
                let mut f = f;
                let _ = tokio::io::copy(&mut s, &mut f).await;
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let path = log_dir.join(format!("go_{log_id}_stderr.log"));
        tokio::spawn(async move {
            let mut s = stderr;
            if let Ok(f) = tokio::fs::File::create(path).await {
                let mut f = f;
                let _ = tokio::io::copy(&mut s, &mut f).await;
            }
        });
    }

    Ok(child)
}

// -- Port wait ---------------------------------------------------------

/// Wait until port is connectable (TCP connect succeeds).
// Poll interval 100ms, returns error on timeout.
pub async fn wait_for_port(port: u16, timeout_ms: u64) -> Result<()> {
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .map_err(|_| InteropError::PortTimeout { port, timeout_ms })?;

    let deadline = time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if time::Instant::now() >= deadline {
            return Err(InteropError::PortTimeout { port, timeout_ms });
        }
        time::sleep(Duration::from_millis(100)).await;
    }
}

// -- SOCKS5 proxy HTTP request -----------------------------------------

/// Send HTTP GET through SOCKS5 proxy, return response body.
// Minimal SOCKS5 handshake + HTTP/1.1 GET, no external HTTP library.
pub async fn http_get_via_socks5(
    proxy_addr: SocketAddr,
    target_host: &str,
    target_port: u16,
    target_path: &str,
) -> Result<String> {
    let mut stream = TcpStream::connect(proxy_addr).await?;

    // SOCKS5 handshake: no auth
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(InteropError::HttpRequestFailed(format!(
            "SOCKS5 handshake failed: version={}, method={}",
            resp[0], resp[1]
        )));
    }

    // SOCKS5 CONNECT: domain type
    let host_bytes = target_host.as_bytes();
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    connect_req.extend_from_slice(host_bytes);
    connect_req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&connect_req).await?;

    // Read SOCKS5 connect reply
    let mut connect_resp = vec![0u8; 256];
    let mut total = 0;
    while total < 4 {
        let n = stream.read(&mut connect_resp[total..]).await?;
        if n == 0 {
            return Err(InteropError::HttpRequestFailed("SOCKS5 connect response EOF".into()));
        }
        total += n;
    }
    let addr_len = match connect_resp[3] {
        0x01 => 4,
        0x03 => connect_resp[4] as usize + 1,
        0x04 => 16,
        other => {
            return Err(InteropError::HttpRequestFailed(format!(
                "SOCKS5 unknown address type: {other}"
            )));
        },
    };
    let need = 4 + addr_len + 2;
    while total < need {
        let n = stream.read(&mut connect_resp[total..]).await?;
        if n == 0 {
            return Err(InteropError::HttpRequestFailed(
                "SOCKS5 connect response truncated".into(),
            ));
        }
        total += n;
    }
    if connect_resp[1] != 0x00 {
        return Err(InteropError::HttpRequestFailed(format!(
            "SOCKS5 connect failed: rep={}",
            connect_resp[1]
        )));
    }

    // Send HTTP/1.1 request through tunnel
    let http_req = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        target_path, target_host, target_port
    );
    stream.write_all(http_req.as_bytes()).await?;

    // Read response
    let mut body = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&buf[..n]),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::ConnectionReset {
                    break;
                }
                return Err(InteropError::HttpRequestFailed(format!("HTTP read error: {e}")));
            },
        }
    }

    String::from_utf8(body)
        .map_err(|e| InteropError::HttpRequestFailed(format!("response not UTF-8: {e}")))
}

// -- Echo servers ------------------------------------------------------

/// Start TCP echo server, return listen port.
// Each connection echoes data back.
pub async fn spawn_echo_server() -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        loop {
            if let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            },
                        }
                    }
                });
            }
        }
    });
    Ok(port)
}

/// Start HTTP echo server, return listen port.
// Returns fixed JSON {"status":"ok"} for any request.
pub async fn spawn_http_echo_server() -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        for _ in 0..10 {
            if let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let body = r#"{"status":"ok"}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        }
    });
    Ok(port)
}

// -- Go xray JSON config generation ------------------------------------

/// Go xray top-level config structure.
#[derive(serde::Serialize)]
pub struct XrayConfig {
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
}

/// Inbound config.
#[derive(serde::Serialize)]
pub struct Inbound {
    pub port: u16,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_settings: Option<serde_json::Value>,
    pub tag: String,
}

/// Outbound config.
#[derive(serde::Serialize)]
pub struct Outbound {
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_settings: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// Freedom outbound config.
pub fn freedom_outbound() -> Outbound {
    Outbound {
        protocol: "freedom".into(),
        // Go xray v26 freedom blocks private targets (127.0.0.0/8 etc.) by
        // default when the inbound is trojan/vless/vmess/ss (SSRF guard,
        // proxy/freedom/freedom.go getDefaultFinalRule). Tests dial local
        // echo servers, so allow loopback explicitly.
        settings: Some(serde_json::json!({
            "domainStrategy": "asis",
            "finalRules": [{ "action": "allow", "ip": ["127.0.0.0/8"] }]
        })),
        stream_settings: None,
        tag: Some("direct".into()),
    }
}

/// Blackhole outbound config.
pub fn blackhole_outbound() -> Outbound {
    Outbound {
        protocol: "blackhole".into(),
        settings: None,
        stream_settings: None,
        tag: Some("block".into()),
    }
}

// -- VMess config generation -------------------------------------------

/// Go xray VMess server inbound config.
pub fn vmess_server_inbound(port: u16, uuid: &str) -> Inbound {
    Inbound {
        port,
        protocol: "vmess".into(),
        listen: Some("127.0.0.1".into()),
        settings: Some(serde_json::json!({
            "clients": [{ "id": uuid, "alterId": 0 }]
        })),
        stream_settings: None,
        tag: "vmess-in".into(),
    }
}

/// Go xray VMess client outbound config.
pub fn vmess_outbound(server_port: u16, uuid: &str) -> Outbound {
    Outbound {
        protocol: "vmess".into(),
        settings: Some(serde_json::json!({
            "vnext": [{
                "address": "127.0.0.1",
                "port": server_port,
                "users": [{ "id": uuid, "alterId": 0, "security": "auto" }]
            }]
        })),
        stream_settings: None,
        tag: Some("vmess-out".into()),
    }
}

// -- VLESS config generation -------------------------------------------

/// Go xray VLESS server inbound config.
pub fn vless_server_inbound(port: u16, uuid: &str) -> Inbound {
    Inbound {
        port,
        protocol: "vless".into(),
        listen: Some("127.0.0.1".into()),
        settings: Some(serde_json::json!({
            "clients": [{ "id": uuid, "flow": "" }],
            "decryption": "none"
        })),
        stream_settings: None,
        tag: "vless-in".into(),
    }
}

/// Go xray VLESS client outbound config.
pub fn vless_outbound(server_port: u16, uuid: &str) -> Outbound {
    Outbound {
        protocol: "vless".into(),
        settings: Some(serde_json::json!({
            "vnext": [{
                "address": "127.0.0.1",
                "port": server_port,
                "users": [{ "id": uuid, "flow": "", "encryption": "none" }]
            }]
        })),
        stream_settings: None,
        tag: Some("vless-out".into()),
    }
}

// -- Trojan config generation ------------------------------------------

/// Go xray Trojan server inbound config (plain TCP, no TLS for test).
pub fn trojan_server_inbound(port: u16, password: &str) -> Inbound {
    Inbound {
        port,
        protocol: "trojan".into(),
        listen: Some("127.0.0.1".into()),
        settings: Some(serde_json::json!({
            "clients": [{ "password": password }]
        })),
        stream_settings: Some(serde_json::json!({
            "network": "tcp",
            "security": "none"
        })),
        tag: "trojan-in".into(),
    }
}

/// Go xray Trojan client outbound config (plain TCP, no TLS for test).
pub fn trojan_outbound(server_port: u16, password: &str) -> Outbound {
    Outbound {
        protocol: "trojan".into(),
        settings: Some(serde_json::json!({
            "servers": [{
                "address": "127.0.0.1",
                "port": server_port,
                "password": password
            }]
        })),
        stream_settings: Some(serde_json::json!({
            "network": "tcp",
            "security": "none"
        })),
        tag: Some("trojan-out".into()),
    }
}

// -- Shadowsocks config generation -------------------------------------

/// Go xray Shadowsocks server inbound config.
pub fn ss_server_inbound(port: u16, password: &str, method: &str) -> Inbound {
    Inbound {
        port,
        protocol: "shadowsocks".into(),
        listen: Some("127.0.0.1".into()),
        settings: Some(serde_json::json!({
            "method": method,
            "password": password,
            "network": "tcp"
        })),
        stream_settings: None,
        tag: "ss-in".into(),
    }
}

/// Go xray Shadowsocks-2022 (SIP022) server inbound config.
/// 2022 cipher 走 Go `infra/conf/shadowsocks.go:56-58` buildShadowsocks2022 路由
/// （inbound protocol 仍为 "shadowsocks"，单用户 password 即 base64 PSK）。
pub fn ss2022_server_inbound(port: u16, psk_b64: &str, method: &str) -> Inbound {
    Inbound {
        port,
        protocol: "shadowsocks".into(),
        listen: Some("127.0.0.1".into()),
        settings: Some(serde_json::json!({
            "method": method,
            "password": psk_b64,
            "network": "tcp"
        })),
        stream_settings: None,
        tag: "ss2022-in".into(),
    }
}

/// Go xray Shadowsocks client outbound config.
pub fn ss_outbound(server_port: u16, password: &str, method: &str) -> Outbound {
    Outbound {
        protocol: "shadowsocks".into(),
        settings: Some(serde_json::json!({
            "servers": [{
                "address": "127.0.0.1",
                "port": server_port,
                "method": method,
                "password": password
            }]
        })),
        stream_settings: None,
        tag: Some("ss-out".into()),
    }
}

// -- SOCKS5 / HTTP inbound for Go xray client side ---------------------

/// Go xray SOCKS5 inbound config (for client-side proxy entry).
pub fn socks5_inbound(port: u16) -> Inbound {
    Inbound {
        port,
        protocol: "socks".into(),
        listen: Some("127.0.0.1".into()),
        settings: Some(serde_json::json!({
            "auth": "noauth",
            "udp": false
        })),
        stream_settings: None,
        tag: "socks-in".into(),
    }
}

/// Go xray HTTP inbound config (for client-side proxy entry).
pub fn http_inbound(port: u16) -> Inbound {
    Inbound {
        port,
        protocol: "http".into(),
        listen: Some("127.0.0.1".into()),
        settings: None,
        stream_settings: None,
        tag: "http-in".into(),
    }
}

// -- Config file writer ------------------------------------------------

/// Write config to a temp file, return path.
pub fn write_config_to_temp(config: &XrayConfig, prefix: &str) -> Result<PathBuf> {
    let dir = std::env::temp_dir().join("xray_interop_tests");
    std::fs::create_dir_all(&dir)
        .map_err(|e| InteropError::ConfigWrite(format!("create temp dir: {e}")))?;

    let path = dir.join(format!("{prefix}-{}.json", std::process::id()));
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| InteropError::ConfigWrite(format!("serialize: {e}")))?;

    std::fs::write(&path, json)
        .map_err(|e| InteropError::ConfigWrite(format!("write file: {e}")))?;

    Ok(path)
}
