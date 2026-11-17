//! XDRIVE 三方向对拍矩阵（A/B/C 缺一不算过）。
//!
//! 规划：`docs/architecture/xray-frame-xdrive-实施计划-2026-11-11.md` §5 B6（互操作锚）。
//! 介质 = `local` 后端**共享文件夹**（离线，无网络后端）；代理面 = VLESS + mux
//! （Go `validateXDrive` 硬要求 ENC + mux 开启）+ `xdrive` 传输。
//!
//! | 方向 | 测试 | 门控 | 判据 |
//! |---|---|---|---|
//! | A：Rust client → **Go server** | `go_server_64k_roundtrip` | `#[ignore]` + `XDRIVE_GO_XRAY` | ①socks5 隧道取回 64KiB 逐字节相等 ②共享文件夹出现 session（`streams/<sid>`）③双向都有分段落地（c2s/s2c 段计数 ≥ 1） |
//! | B：**Go client** → Rust server | `go_client_64k_roundtrip_via_rust_server` | `#[ignore]` + `XDRIVE_GO_XRAY` | 同 A（判据面在 Rust 服务端一侧的文件夹） |
//! | C：Rust client ↔ **Rust server** | `rust_to_rust_64k_roundtrip` | 默认跑（零外部依赖） | 同 A + 段计数**确定性**断言：存储边界单调 PUT 计数（c2s/s2c 各 ≥ ⌈64KiB/16KiB⌉），与消费删除时序无关 |
//!
//! 运行（A/B，需 Go v26.11.9 二进制 + 本仓 `cargo build -p xray-cli` 产物）：
//! ```text
//! XDRIVE_GO_XRAY=D:/tmp/xray-v2611/xray.exe \
//!   cargo test -p xray-transport-xdrive --test xdrive_go_interop -- --ignored --nocapture
//! ```
//! 运行（C，默认套件）：
//! ```text
//! cargo test -p xray-transport-xdrive --test xdrive_go_interop -- --nocapture
//! ```
//!
//! Rust 二进制解析顺序：`XDRIVE_RUST_XRAY` → 测试可执行文件同级的 `target/<profile>/xray[.exe]`。
//! Go 二进制解析顺序：`XDRIVE_GO_XRAY` → `D:/tmp/xray-v2611/xray.exe`。
//! 两个二进制都是**完整 xray 进程**（A/B 是真机对拍，不是进程内替身）。
//!
//! 对拍坑（B6 实测，沿用）：VLESS 入站的 freedom 有内建「私网阻断」最终规则
//! （Go `proxy/freedom/freedom.go:165-178`），环回目标必须用
//! `finalRules: [{"action":"allow","ip":["127.0.0.1"]}]` 覆盖，否则黑洞 30-90s。
//!
//! 测试基建 spawn 豁免（坑约束 #5）：子进程与 echo/watch 任务均为测试基建（①类外的
//! 测试夹具），故文件级 allow。
#![allow(clippy::disallowed_methods)]

use std::{
    collections::HashSet,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_transport::{dialer::StreamSettings, listener_registry::ConnHandler};
use xray_transport_xdrive::{
    LocalStorage, dial, serve,
    storage::{Entry, Storage, reset_test_storage_factory, set_test_storage_factory},
};

// ── 常量：VLESS ENC 对（Go `infra/conf/transport_test.go:513-519` 的 xdriveEnc/xdriveDec）
// 与 xdrive 调参（B6 三方向互操作实测值：小段 + 快轮询，秒级可观测）。

const UUID: &str = "27848739-7e62-4138-9fd3-098a63964b6b";
const ENC: &str = "mlkem768x25519plus.native.0rtt.XKbaq1BuzJKKKPxZbwgRpn-gYQbnhrYketgezASCL1I";
const DEC: &str = "mlkem768x25519plus.native.600s.UKfUEMDdjlEnycTMBP0a08acky8vRRKSrM1MRnaYk3s";

/// 判据下限：每方向至少 64KiB 逐字节相等。
const PAYLOAD_BYTES: usize = 64 * 1024;
/// 分段大小（段计数判据的分母）。
const SEGMENT_BYTES: usize = 16 * 1024;
/// 每方向整体护栏（含进程冷启动）。
const DIRECTION_TIMEOUT: Duration = Duration::from_secs(180);

// ── 二进制解析 ──────────────────────────────────────────────────────────────

/// Go xray 二进制（v26.11.9；`D:/Project/Xray-core` @ 676eaf66 `go build ./main`）。
fn go_binary() -> PathBuf {
    let bin = std::env::var("XDRIVE_GO_XRAY")
        .unwrap_or_else(|_| "D:/tmp/xray-v2611/xray.exe".to_string());
    let bin = PathBuf::from(bin);
    assert!(
        bin.is_file(),
        "Go xray binary missing at {}: build via `cd D:/Project/Xray-core && go build -o {} ./main`",
        bin.display(),
        bin.display()
    );
    bin
}

/// 本仓 `xray` 二进制（`cargo build -p xray-cli`）：先 env，再按测试可执行文件
/// 所在的 `target/<profile>/` 反推（兼容 `CARGO_TARGET_DIR`）。
fn rust_binary() -> PathBuf {
    if let Ok(bin) = std::env::var("XDRIVE_RUST_XRAY") {
        let bin = PathBuf::from(bin);
        assert!(bin.is_file(), "XDRIVE_RUST_XRAY points at a missing file: {}", bin.display());
        return bin;
    }
    let exe = std::env::current_exe().expect("test executable path");
    // target/<profile>/deps/<test>.exe → target/<profile>/xray[.exe]
    let bin = exe
        .parent()
        .and_then(Path::parent)
        .map(|p| p.join(format!("xray{}", std::env::consts::EXE_SUFFIX)))
        .expect("test executable must live under target/<profile>/deps");
    assert!(
        bin.is_file(),
        "Rust xray binary missing at {}: run `cargo build -p xray-cli` or set XDRIVE_RUST_XRAY",
        bin.display()
    );
    bin
}

// ── 配置（形态同 Go `xray run -c`；B6 实测通过的同一份） ──────────────────────

/// xdrive 传输设置：`local` 共享文件夹 + 小段 + 快轮询。
///
/// `pollIntervalMs` 刻意取 20ms（B6 脚本用 5ms）：段被消费后即删（wal reader
/// 投递即 discard），存活窗 ≈ 对端轮询节奏；A/B 的首见采样命中概率与整体传输
/// 耗时都受它影响。判据③已改单调计数（FolderStats 首见累计 / SegPutCountStorage
/// PUT 计数），不再依赖存活窗。20ms 仍是秒级完成，不改变任何传输语义。
fn xdrive_settings(folder: &Path) -> Value {
    json!({
        "remoteFolder": folder.to_string_lossy(),
        "service": "local",
        "flushIntervalMs": 5,
        "pollIntervalMs": 20,
        "maxPollIntervalMs": 50,
        "segmentBytes": SEGMENT_BYTES,
        // 判据②③在传输后立刻读文件夹 ⇒ TTL 必须远大于测试时长（collector 回收
        // 会把 `streams/<sid>` 删掉）。
        "sessionTtlSeconds": 60,
        "eagerWindowMs": 200,
        "holeTimeoutMs": 30000,
    })
}

/// 服务端 = VLESS 入站（xdrive 传输）+ freedom 出站（环回显式放行）。
fn server_config(folder: &Path, port: u16) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "xdrive-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": UUID, "email": "interop"}],
                "decryption": DEC,
            },
            "streamSettings": {
                "network": "xdrive",
                "xdriveSettings": xdrive_settings(folder),
            },
        }],
        // 环回目标放行（freedom 内建私网阻断，见文件头）。
        "outbounds": [{
            "protocol": "freedom",
            "tag": "direct",
            "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1"]}]},
        }],
    })
}

/// 客户端 = socks5 入站（UDP 关，判据面只要 TCP）+ VLESS 出站（mux 必须开）。
fn client_config(folder: &Path, socks_port: u16, server_port: u16) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": false},
        }],
        "outbounds": [{
            "tag": "xdrive-out",
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "127.0.0.1",
                "port": server_port,
                "users": [{"id": UUID, "encryption": ENC}],
            }]},
            "streamSettings": {
                "network": "xdrive",
                "xdriveSettings": xdrive_settings(folder),
            },
            "mux": {"enabled": true},
        }],
    })
}

// ── 测试基建：端口 / 临时根 / 子进程 / socks5 / echo / 文件夹观察 ────────────

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("free port probe");
    listener.local_addr().expect("probe addr").port()
}

/// 测试临时根：Drop 删树（子进程先被 kill，故重试几次躲开 Windows 文件占用）。
struct TempRoot(PathBuf);

impl TempRoot {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("xdrive-go-interop-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp root");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        for _ in 0..10 {
            match std::fs::remove_dir_all(&self.0) {
                Ok(()) => return,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return,
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }
}

/// 被测 xray 进程（Drop 必须杀掉；日志落文件供失败定位）。
struct XrayProcess {
    role: &'static str,
    child: Child,
    log: PathBuf,
}

impl XrayProcess {
    fn spawn(role: &'static str, bin: &Path, cfg: &Path, log: &Path) -> Self {
        let out = std::fs::File::create(log).expect("create child log");
        let child = Command::new(bin)
            .arg("run")
            .arg("-c")
            .arg(cfg)
            .stdout(Stdio::from(out.try_clone().expect("clone log handle")))
            .stderr(Stdio::from(out))
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {role} ({}): {e}", bin.display()));
        Self { role, child, log: log.to_path_buf() }
    }

    /// 进程若已退出，附日志尾巴失败（启动期配置错误在此暴露）。
    fn assert_alive(&mut self) {
        if let Some(status) = self.child.try_wait().expect("try_wait") {
            panic!("{} exited during startup ({status}); log tail:\n{}", self.role, self.tail());
        }
    }

    fn tail(&self) -> String {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        // 按字符切：日志含中文，字节下标可能落在 UTF-8 中间而 panic。
        match text.char_indices().rev().nth(1199) {
            Some((start, _)) => text[start..].to_string(),
            None => text,
        }
    }
}

impl Drop for XrayProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// 等端口可连（真 TCP listener：xdrive 入站**不**真 bind，故只对 socks 端口用）。
async fn wait_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// 最小 socks5 客户端（无认证 CONNECT；够判据用）。
async fn socks5_connect(proxy: SocketAddr, target: SocketAddr) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(io::Error::other(format!("socks5 greeting rejected: {greeting:?}")));
    }
    let SocketAddr::V4(v4) = target else {
        return Err(io::Error::other("test target must be IPv4"));
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(io::Error::other(format!("socks5 connect failed: {reply:?}")));
    }
    // 吞掉 BND.ADDR + BND.PORT（按 ATYP 定长）。
    let addr_len = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0])
        },
        atyp => return Err(io::Error::other(format!("socks5 bad atyp {atyp}"))),
    };
    let mut rest = vec![0u8; addr_len + 2];
    stream.read_exact(&mut rest).await?;
    Ok(stream)
}

/// 测试侧 TCP echo（服务端 freedom 的出站目标；逐字节回写）。
async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("echo bind");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let (mut read, mut write) = conn.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    addr
}

/// 判据②③的单调计数快照。A/B = 文件夹**首见累计**（外部进程唯一可观测边界）；
/// C = 存储边界 PUT 计数。两者都只在 PUT/首见时增长，与消费删除时序无关。
struct DirectionCounts {
    announces: usize,
    sessions: usize,
    c2s: usize,
    s2c: usize,
}

/// 共享文件夹的可观测中间态（判据②③；A/B 外部进程唯一可观测的存储边界）。
///
/// **首见累计**口径（bd xss2v 同族修复）：段被消费后 µs 级即删（wal reader 投递
/// 即 discard），「当下在场数」采样在 CI 高负载下必漏；这里把每个见过的对象名
/// 累计进集合——计数单调不减，任一样本命过即永久计入，不受删除时序影响。
#[derive(Default)]
struct FolderStats {
    announces: HashSet<String>,
    sessions: HashSet<String>,
    c2s_segments: HashSet<String>,
    s2c_segments: HashSet<String>,
}

impl FolderStats {
    fn observe(&mut self, folder: &Path) {
        for entry in std::fs::read_dir(folder.join("sessions")).into_iter().flatten().flatten() {
            self.announces.insert(entry.file_name().to_string_lossy().into_owned());
        }
        for session in std::fs::read_dir(folder.join("streams")).into_iter().flatten().flatten() {
            let sid = session.file_name().to_string_lossy().into_owned();
            self.sessions.insert(sid.clone());
            for (dir, bucket) in [("c2s", &mut self.c2s_segments), ("s2c", &mut self.s2c_segments)]
            {
                for seg in
                    std::fs::read_dir(session.path().join(dir)).into_iter().flatten().flatten()
                {
                    bucket.insert(format!("{sid}/{dir}/{}", seg.file_name().to_string_lossy()));
                }
            }
        }
    }

    fn counts(&self) -> DirectionCounts {
        DirectionCounts {
            announces: self.announces.len(),
            sessions: self.sessions.len(),
            c2s: self.c2s_segments.len(),
            s2c: self.s2c_segments.len(),
        }
    }
}

/// 轮询共享文件夹做首见累计（2ms 采样；首见即永久计入，不靠段存活窗）。
fn spawn_folder_watch(folder: PathBuf) -> (Arc<Mutex<FolderStats>>, Arc<AtomicBool>) {
    let stats = Arc::new(Mutex::new(FolderStats::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let (stats_handle, stop_handle, folder_handle) =
        (Arc::clone(&stats), Arc::clone(&stop), folder);
    tokio::spawn(async move {
        while !stop_handle.load(Ordering::Relaxed) {
            if let Ok(mut guard) = stats_handle.lock() {
                guard.observe(&folder_handle);
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });
    (stats, stop)
}

/// 停采样并回填最后一次观测（判据②③的判据面）。
fn finish_watch(
    stats: &Arc<Mutex<FolderStats>>,
    stop: &Arc<AtomicBool>,
    folder: &Path,
) -> FolderStats {
    stop.store(true, Ordering::Relaxed);
    let mut guard = stats.lock().expect("folder stats");
    guard.observe(folder);
    std::mem::take(&mut *guard)
}

// ── 测试侧 Storage 计数装饰器（方向 C 的判据③计数面） ────────────────────────

/// 包一层真 `LocalStorage`，`put` 发生时按对象名前缀分桶单调计数——计数与消费
/// 删除解耦（bd xss2v 终态写法），方向 C 的段计数断言由此确定性成立。经
/// `set_test_storage_factory` 注入（Go `testStorageFactory` 等价面）：dial 与
/// serve 各自的 `new_storage` 都命中同一实例；桶按 key 前缀分方向
/// （`sessions/` = announce，`/c2s/`、`/s2c/` = WAL 段与 `.end` 标记）。
struct SegPutCountStorage {
    inner: Arc<dyn Storage>,
    counters: PutCounters,
}

/// 断言面句柄：`snapshot()` 取单调计数快照（读数不受删除时序影响）。
#[derive(Clone)]
struct PutCounters {
    announce_puts: Arc<AtomicUsize>,
    c2s_puts: Arc<AtomicUsize>,
    s2c_puts: Arc<AtomicUsize>,
    stream_sids: Arc<Mutex<HashSet<String>>>,
}

impl PutCounters {
    fn snapshot(&self) -> DirectionCounts {
        DirectionCounts {
            announces: self.announce_puts.load(Ordering::Relaxed),
            sessions: self.stream_sids.lock().expect("stream sids").len(),
            c2s: self.c2s_puts.load(Ordering::Relaxed),
            s2c: self.s2c_puts.load(Ordering::Relaxed),
        }
    }
}

/// PUT 对象名 → 会话 id（`sessions/<nanos>-<sid>` announce 与 `streams/<sid>/…`
/// 段两形态；判据②「会话在场」的对象名投影）。
fn session_of(name: &str) -> Option<String> {
    if let Some(rest) = name.strip_prefix("sessions/") {
        return rest.rsplit('-').next().map(str::to_string);
    }
    name.strip_prefix("streams/").map(|rest| rest.split('/').next().unwrap_or(rest).to_string())
}

impl SegPutCountStorage {
    fn new(folder: &Path) -> (Arc<Self>, PutCounters) {
        let counters = PutCounters {
            announce_puts: Arc::new(AtomicUsize::new(0)),
            c2s_puts: Arc::new(AtomicUsize::new(0)),
            s2c_puts: Arc::new(AtomicUsize::new(0)),
            stream_sids: Arc::new(Mutex::new(HashSet::new())),
        };
        let storage = Arc::new(Self {
            inner: Arc::new(LocalStorage::new(&folder.to_string_lossy()).expect("local storage")),
            counters: PutCounters {
                announce_puts: Arc::clone(&counters.announce_puts),
                c2s_puts: Arc::clone(&counters.c2s_puts),
                s2c_puts: Arc::clone(&counters.s2c_puts),
                stream_sids: Arc::clone(&counters.stream_sids),
            },
        });
        (storage, counters)
    }
}

#[async_trait::async_trait]
impl Storage for SegPutCountStorage {
    async fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let c = &self.counters;
        if name.starts_with("sessions/") {
            c.announce_puts.fetch_add(1, Ordering::Relaxed);
        } else if name.contains("/c2s/") {
            c.c2s_puts.fetch_add(1, Ordering::Relaxed);
        } else if name.contains("/s2c/") {
            c.s2c_puts.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(sid) = session_of(name) {
            c.stream_sids.lock().expect("stream sids").insert(sid);
        }
        self.inner.put(name, data).await
    }

    async fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        self.inner.get(name).await
    }

    async fn delete(&self, name: &str) -> io::Result<()> {
        self.inner.delete(name).await
    }

    async fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        self.inner.list(prefix).await
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

// ── 方向驱动（A/B 共用；C 走进程内 API） ─────────────────────────────────────

/// 判定串：64KiB 逐字节相等 + 会话/分段落地（判据②③）。
///
/// `counts` 一律是**单调计数**（A/B 文件夹首见累计 / C 存储边界 PUT 计数），
/// 不受消费删除时序影响——bd xss2v 同族修复的统一断言面。
fn assert_roundtrip(
    tag: &str,
    sent: &[u8],
    got: &[u8],
    counts: &DirectionCounts,
    min_segments: usize,
) {
    assert_eq!(got.len(), sent.len(), "[{tag}] payload length mismatch");
    assert_eq!(got, sent, "[{tag}] 64KiB payload must arrive byte-equal");
    assert!(
        counts.announces >= 1,
        "[{tag}] no announce ever appeared under sessions/ (transport did not use the folder)"
    );
    assert!(
        counts.sessions >= 1,
        "[{tag}] no session ever appeared under streams/ (session was not established)"
    );
    assert!(
        counts.c2s >= min_segments && counts.s2c >= min_segments,
        "[{tag}] both directions must carry >= {min_segments} segments (c2s={} s2c={})",
        counts.c2s,
        counts.s2c
    );
}

/// 起 server/client 两个进程 → socks5 走 64KiB 往返 → 停进程。
async fn run_direction(
    tag: &'static str,
    client_bin: &Path,
    server_bin: &Path,
    root: &Path,
) -> (usize, FolderStats) {
    let folder = root.join("store");
    std::fs::create_dir_all(&folder).expect("create shared folder");
    let echo = start_echo().await;
    let (server_port, socks_port) = (free_port(), free_port());

    let cfg_dir = root.join("cfg");
    std::fs::create_dir_all(&cfg_dir).expect("create cfg dir");
    let server_cfg = cfg_dir.join("server.json");
    let client_cfg = cfg_dir.join("client.json");
    std::fs::write(&server_cfg, server_config(&folder, server_port).to_string())
        .expect("write server config");
    std::fs::write(&client_cfg, client_config(&folder, socks_port, server_port).to_string())
        .expect("write client config");

    let (stats, stop_watch) = spawn_folder_watch(folder.clone());

    let mut server =
        XrayProcess::spawn("server", server_bin, &server_cfg, &root.join("server.log"));
    // xdrive 入站不真 bind（对象存储介质），只能靠"活着"判就绪。
    tokio::time::sleep(Duration::from_secs(3)).await;
    server.assert_alive();
    let client = XrayProcess::spawn("client", client_bin, &client_cfg, &root.join("client.log"));
    assert!(
        wait_port(socks_port, Duration::from_secs(30)).await,
        "[{tag}] client socks inbound never listened; client log tail:\n{}",
        client.tail()
    );

    let sent: Vec<u8> = (0..PAYLOAD_BYTES).map(|i| (i * 7 % 251) as u8).collect();
    let mut got = vec![0u8; PAYLOAD_BYTES];
    let mut last_err = String::new();
    let mut matched = 0usize;
    // 冷路径首连可能撞 mux 建链窗口：整体重试到护栏。
    let deadline = Instant::now() + DIRECTION_TIMEOUT;
    while Instant::now() < deadline {
        match socks5_connect(SocketAddr::from(([127, 0, 0, 1], socks_port)), echo).await {
            Ok(mut conn) => {
                let attempt = async {
                    conn.write_all(&sent).await?;
                    conn.read_exact(&mut got).await
                };
                match tokio::time::timeout(Duration::from_secs(60), attempt).await {
                    Ok(Ok(_)) => {
                        matched = got.len();
                        break;
                    },
                    Ok(Err(e)) => last_err = format!("socks io error: {e}"),
                    Err(_) => last_err = "64KiB roundtrip timed out (60s)".to_string(),
                }
            },
            Err(e) => last_err = format!("socks5 connect: {e}"),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        matched == PAYLOAD_BYTES,
        "[{tag}] 64KiB roundtrip failed: {last_err}\nclient log tail:\n{}\nserver log tail:\n{}",
        client.tail(),
        server.tail()
    );

    // 让最后一批段落地，再停采样。
    tokio::time::sleep(Duration::from_millis(300)).await;
    let observed = finish_watch(&stats, &stop_watch, &folder);
    // 判据③（A/B）：VLESS+mux 的分段节奏由对端实现决定，写入侧与消费侧逐段交错
    // ⇒ 判「双向都真实承载过分段」（首见累计 ≥ 1），不判条数（那由对端调度决定，
    // 不是本仓语义）。方向 C 经 SegPutCountStorage 在存储边界确定性断言
    // ⌈64KiB/16KiB⌉。
    assert_roundtrip(tag, &sent, &got, &observed.counts(), 1);
    (matched, observed)
}

// ── 方向 A：Rust client → Go server ─────────────────────────────────────────

/// 方向 A：本仓 Rust client（socks5 + VLESS/mux/xdrive）→ **Go v26.11.9 server**。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "env 门控：需要 Go v26.11.9 二进制（XDRIVE_GO_XRAY）——规划 §5 B6 互操作锚"]
async fn go_server_64k_roundtrip() {
    let root = TempRoot::new("a");
    let (matched, stats) = run_direction("A", &rust_binary(), &go_binary(), root.path()).await;
    let counts = stats.counts();
    println!(
        "[A] Rust-client -> Go-server: {matched} bytes matched; \
         announces={} sessions={} c2s={} s2c={} (first-seen counts)",
        counts.announces, counts.sessions, counts.c2s, counts.s2c
    );
}

// ── 方向 B：Go client → Rust server ─────────────────────────────────────────

/// 方向 B：**Go v26.11.9 client** → 本仓 Rust server（同一份配置，角色互换）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "env 门控：需要 Go v26.11.9 二进制（XDRIVE_GO_XRAY）——规划 §5 B6 互操作锚"]
async fn go_client_64k_roundtrip_via_rust_server() {
    let root = TempRoot::new("b");
    let (matched, stats) = run_direction("B", &go_binary(), &rust_binary(), root.path()).await;
    let counts = stats.counts();
    println!(
        "[B] Go-client -> Rust-server: {matched} bytes matched; \
         announces={} sessions={} c2s={} s2c={} (first-seen counts)",
        counts.announces, counts.sessions, counts.c2s, counts.s2c
    );
}

// ── 方向 C：Rust client ↔ Rust server（默认套件，零外部依赖） ────────────────

/// 方向 C：进程内 `dial`↔`serve`（真传输 + 真 `LocalStorage`），判据同 A/B；
/// 判据③走 `SegPutCountStorage` 的存储边界单调 PUT 计数（A/B 走文件夹首见累计）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_to_rust_64k_roundtrip() {
    let root = TempRoot::new("c");
    let folder = root.path().join("store");
    std::fs::create_dir_all(&folder).expect("create shared folder");
    let settings = StreamSettings::from_json(Some(&json!({
        "network": "xdrive",
        "xdriveSettings": xdrive_settings(&folder),
    })));
    // 判据③计数面：经 TEST_FACTORY 注入计数装饰器（dial/serve 各自的 new_storage
    // 都命中它）。本二进制默认套件只有本用例，无需串行守卫；--ignored 并跑时 A/B
    // 是外部进程，不经本进程的 new_storage。
    let (counting, counters) = SegPutCountStorage::new(&folder);
    set_test_storage_factory(Arc::new(move |_settings: &StreamSettings| {
        Ok(Arc::clone(&counting) as Arc<dyn Storage>)
    }));

    let (conn_tx, mut conn_rx) =
        tokio::sync::mpsc::channel::<Box<dyn xray_transport::connection::Connection>>(4);
    let handler: ConnHandler = Arc::new(move |conn| {
        let _ = conn_tx.try_send(conn);
    });
    let listener = serve(
        "127.0.0.1:0".parse().expect("listen addr"),
        settings.clone(),
        Default::default(),
        handler,
    )
    .await
    .expect("serve");

    let dest = Destination::new(Address::new_domain("xdrive.test"), Port::new(443), Network::TCP);
    let mut client = dial(&dest, &Default::default(), &settings).await.expect("dial");

    let mut server = tokio::time::timeout(Duration::from_secs(30), conn_rx.recv())
        .await
        .expect("listener must claim the announced session")
        .expect("handler channel closed");

    let sent: Vec<u8> = (0..PAYLOAD_BYTES).map(|i| (i * 7 % 251) as u8).collect();
    client.write_all(&sent).await.expect("uplink write");
    let mut received = vec![0u8; PAYLOAD_BYTES];
    server.read_exact(&mut received).await.expect("uplink read");
    assert_eq!(received, sent, "[C] uplink 64KiB must arrive byte-equal");

    // 下行：服务端回写 → 客户端读（同样逐字节相等）。
    server.write_all(&received).await.expect("downlink write");
    let mut echoed = vec![0u8; PAYLOAD_BYTES];
    client.read_exact(&mut echoed).await.expect("downlink read");

    // 判据②③：单调计数断言（PUT 发生时递增，与消费删除解耦——bd xss2v 终态写法；
    // 两侧 read_exact 返回即全段已 PUT，无需等待或采样）。⌈64KiB/16KiB⌉ 段/向。
    assert_roundtrip(
        "C",
        &sent,
        &echoed,
        &counters.snapshot(),
        PAYLOAD_BYTES.div_ceil(SEGMENT_BYTES),
    );

    client.shutdown().await.expect("client shutdown");
    server.shutdown().await.expect("server shutdown");
    listener.close().expect("listener close");
    reset_test_storage_factory();

    let counts = counters.snapshot();
    println!(
        "[C] Rust-client <-> Rust-server: {} bytes matched; \
         announces={} sessions={} c2s={} s2c={} (monotonic PUT counts)",
        echoed.len(),
        counts.announces,
        counts.sessions,
        counts.c2s,
        counts.s2c
    );
}
