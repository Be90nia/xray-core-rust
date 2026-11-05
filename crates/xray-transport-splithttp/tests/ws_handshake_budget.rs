//! bd i37bz 复审：**ws 握手请求/响应的字节预算**与 32 KiB 帧缓冲的关系（只测不改码）。
//!
//! # 测什么
//!
//! 两个**互不相同**的尺寸域，本文件各测各的：
//!
//! 1. **HTTP Upgrade 握手请求/响应**（`GET /… HTTP/1.1` + 头块）：由 ws 客户端
//!    `build_request`（`crates/xray-transport-websocket/src/client.rs:437`）构造， 伪装头走
//!    `xray_common::browser::try_default_headers_with(.., "ws")` （同
//!    client.rs:481）。本文件用**同一个共享函数**实测该头块字节数。
//! 2. **握手后帧负载**（ws Binary 消息）：单帧 ≤ 64 KiB（copy 循环块上限）。
//!
//! # 为什么握手尺寸不由 `read_buffer_size`/`write_buffer_size` 决定
//!
//! tungstenite 0.26.2 里这两项**只喂帧编解码器**：
//! `protocol/mod.rs:382` `FrameCodec::new(conf.read_buffer_size)` →
//! `protocol/frame/mod.rs:125` `in_buffer: BytesMut::with_capacity(in_buf_len)`；
//! `protocol/mod.rs:397` `set_out_buffer_write_len(conf.write_buffer_size)` →
//! 写侧 flush 阈值。
//!
//! HTTP Upgrade 握手走的是另一条路：`handshake/machine.rs:23`
//! `HandshakeMachine::start_read(stream)` → `ReadBuffer`（固定 4096 B/块，
//! `lib.rs:35 READ_BUFFER_CHUNK_SIZE`）+ httparse（`handshake/headers.rs:10`
//! `MAX_HEADERS = 124` 行）+ `AttackCheck`（`handshake/machine.rs:169-170`
//! `MAX_BYTES = 65536` 总字节 / `MAX_PACKETS = 512`）。**握手路径与 32 KiB 无关。**
//!
//! # 判据（跨实现上限）
//!
//! - Go ws 服务端：`transport/internet/websocket/hub.go:136` `MaxHeaderBytes: 8192` ⇒ 握手头块 > 8
//!   KiB 直接 431 （`net/http/server.go:2043-2050` `errTooLarge` → "431 Request Header Fields Too
//!   Large"；读上限 = 8192 + 4096 bufio 余量，`server.go:940-942`）。
//! - 本仓 Rust ws 服务端：tungstenite `AttackCheck` 64 KiB 总字节上限。
//! - 唯一能把手撑大的变量 = **early data**：`Sec-WebSocket-Protocol` 头承载 base64url(ed
//!   字节)（client.rs:496-508）⇒ 头块随 ed **4/3** 膨胀。
//!
//! # 跑法
//!
//! ```text
//! cargo test -p xray-transport-splithttp --test ws_handshake_budget -- --nocapture
//! ```
//!
//! 位置说明：ws crate（`crates/xray-transport-websocket`）不在本票独占面内，本文件
//! 落在本 crate 的 tests/ 下——被测的 `xray_common::browser` 是 ws/splithttp/httpupgrade
//! **共用**的伪装头来源（`crates/xray-common/src/browser.rs:281`
//! `apply_masqueraded_headers` 的 "ws" variant 分支）。

use xray_common::browser::try_default_headers_with;

/// 客户端请求行（`GET {path} HTTP/1.1`，path 取常见值）。
const REQUEST_LINE: &str = "GET /ws HTTP/1.1\r\n";

/// tungstenite 生成的 5 个强制头（`handshake/client.rs:120-124` + :154-160）：
/// Host / Connection: Upgrade / Upgrade: websocket / Sec-WebSocket-Version: 13 /
/// Sec-WebSocket-Key（16 随机字节 → 24 字符 base64）。此处用**最坏** host 长度
/// （255 字节 = DNS 名上限，`net/http`'s domain limit）算上限。
const MANDATORY_HEADERS: [(&str, usize); 5] = [
    ("Host", 255),
    ("Connection", 9),            // "Upgrade"
    ("Upgrade", 9),               // "websocket"
    ("Sec-WebSocket-Version", 2), // "13"
    ("Sec-WebSocket-Key", 24),    // 24 字符 base64
];

/// 服务端响应（`handshake/server.rs:97-110` `write_response`）：
/// 状态行 + Server / Date / Upgrade / Connection / Sec-WebSocket-Accept(28 字符 base64)。
const RESPONSE_FIXED_BYTES: usize = 200; // 保守上界（含状态行 + 5 个头 + 空行）

/// Go ws 服务端**头块配置上限**（`hub.go:136` `MaxHeaderBytes: 8192`）。
const GO_WS_MAX_HEADER_BYTES: usize = 8192;

/// Go `http.Server` 对请求头（**含请求行**）的**实际读上限** =
/// `MaxHeaderBytes` + 4096 bufio 余量（`net/http/server.go:940-942`
/// `initialReadLimitSize()`）；超限 ⇒ `errTooLarge` ⇒ 431
/// （`net/http/server.go:2043-2050`）。
const GO_WS_REQUEST_HEAD_READ_LIMIT: usize = GO_WS_MAX_HEADER_BYTES + 4096;

/// 本仓 Rust ws 服务端握手总字节上限（tungstenite `AttackCheck` `MAX_BYTES`）。
const RUST_WS_MAX_HANDSHAKE_BYTES: usize = 65536;

/// base64url 无填充编码长度（`base64::engine::general_purpose::URL_SAFE_NO_PAD`）。
const fn b64url_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// 序列化头块字节数（`Name: Value\r\n`，与 tungstenite `generate_request` 同形）。
fn header_block_bytes(headers: &[(String, String)]) -> usize {
    headers.iter().map(|(k, v)| k.len() + 2 + v.len() + 2).sum()
}

/// 客户端握手请求总字节（不含 early data 头）。
fn client_request_bytes(headers: &[(String, String)]) -> usize {
    REQUEST_LINE.len()
        + MANDATORY_HEADERS.iter().map(|(name, vlen)| name.len() + 2 + vlen + 2).sum::<usize>()
        + header_block_bytes(headers)
}

/// early data 头（`Sec-WebSocket-Protocol`）字节数。
fn early_data_header_bytes(ed: usize) -> usize {
    if ed == 0 {
        return 0;
    }
    "Sec-WebSocket-Protocol".len() + 2 + b64url_len(ed) + 2
}

/// 伪装头块实测字节数（ws variant）——本文件的核心读数。
fn measured_masquerade_bytes() -> usize {
    let mut headers: Vec<(String, String)> = Vec::new();
    try_default_headers_with(&mut headers, "ws");
    header_block_bytes(&headers)
}

/// 无 early data 时，客户端握手请求总字节（实测伪装头 + 解析式强制头）。
#[test]
fn client_handshake_request_size_without_early_data() {
    let masquerade = measured_masquerade_bytes();
    let mut headers: Vec<(String, String)> = Vec::new();
    try_default_headers_with(&mut headers, "ws");
    let total = client_request_bytes(&headers);
    // 打印真实读数（伪装头 + 请求行 + 5 强制头）。
    println!("[ws-handshake] masquerade header block = {masquerade} B");
    println!("[ws-handshake] client request (no early data) = {total} B");
    // 上界：host 取 255 B 最坏值时仍远低于 Go 的 8192 头上限。
    assert!(
        total < GO_WS_MAX_HEADER_BYTES,
        "无 early data 的握手请求 {total} B 必须 < Go 头上限 {GO_WS_MAX_HEADER_BYTES} B"
    );
    // 伪装头是主体（强制头 ~340 B，host 实际远短于 255）。
    assert!(
        masquerade > 300 && masquerade < 2000,
        "ws 伪装头块字节数应在数百量级，实测 {masquerade} B"
    );
}

/// early data（`Sec-WebSocket-Protocol`）把手撑大的量级 —— 唯一能撞 Go 头上限的项。
#[test]
fn early_data_is_the_only_term_that_can_exceed_go_header_budget() {
    let mut headers: Vec<(String, String)> = Vec::new();
    try_default_headers_with(&mut headers, "ws");
    let base = client_request_bytes(&headers);
    let mut rows: Vec<(usize, usize, bool, bool)> = Vec::new();
    for ed in [0usize, 2048, 4096, 6144, 8192, 16384] {
        let total = base + early_data_header_bytes(ed);
        // Go 侧闸门 = 实际读上限（含请求行）⇒ 超限即 431。
        let fits_go = total < GO_WS_REQUEST_HEAD_READ_LIMIT;
        // 本仓 Rust 侧闸门 = tungstenite AttackCheck 总握手字节 64 KiB。
        let fits_rust = total < RUST_WS_MAX_HANDSHAKE_BYTES;
        rows.push((ed, total, fits_go, fits_rust));
        println!(
            "[ws-handshake] ed={ed} B ⇒ request = {total} B (Go 读上限 {}: {}, Rust 64 KiB 握手上限: {})",
            GO_WS_REQUEST_HEAD_READ_LIMIT,
            if fits_go { "fit" } else { "431" },
            if fits_rust { "fit" } else { "OVER" }
        );
    }
    // ed=2048（常见配置）⇒ 远低于 Go 上限。
    assert!(rows[1].1 < GO_WS_REQUEST_HEAD_READ_LIMIT, "ed=2048 应仍低于 Go 读上限");
    // 实测边界：ed=8192 ⇒ 11777 B，仍在 Go 读上限 12288 内（勉强过）；
    // ed=16384 ⇒ 22701 B ⇒ 超限 ⇒ Go 侧 431（本仓 Rust 侧仍可过）。
    assert!(rows[4].2, "ed=8192（11777 B）实测仍在 Go 读上限 12288 内");
    assert!(rows[4].3, "ed=8192 在本仓 Rust 服务端（64 KiB 握手上限）可过");
    assert!(!rows[5].2, "ed=16384（22701 B）必须超 Go 读上限");
    assert!(rows[5].3, "ed=16384 在本仓 Rust 服务端（64 KiB 握手上限）仍可过");
    // 越过 Go 读上限所需的最小 ed（线性 ⇒ 取 ed=16384 已越，ed=8192 未越）。
    assert!(
        rows[5].1 > GO_WS_REQUEST_HEAD_READ_LIMIT && rows[4].1 <= GO_WS_REQUEST_HEAD_READ_LIMIT,
        "Go 读上限的越界点应落在 ed 8192..16384 之间"
    );
}

/// 结论钉子：32 KiB 帧缓冲既不是握手尺寸的上限，也不由握手尺寸决定 —— 两者是独立维度。
#[test]
fn frame_buffer_and_handshake_budget_are_independent_dimensions() {
    // 握手请求上限由 Go 8 KiB 头块 / Rust 64 KiB 握手总字节决定，与帧缓冲无关：
    // 32 KiB << Go 8 KiB? 否 —— 32 KiB > 8 KiB，但两者管的不是同一段字节。
    // 帧面：单帧负载 ≤ 64 KiB（copy 循环块上限）⇒ 32 KiB 初始帧缓冲小于单帧负载，
    // 读帧首帧即需扩容（tungstenite `protocol/frame/mod.rs:195` `in_buffer.reserve(len)`）。
    let frame_payload_max = 64 * 1024;
    let frame_read_buffer = 32 * 1024;
    assert!(
        frame_read_buffer < frame_payload_max,
        "32 KiB 初始帧缓冲 < 64 KiB 单帧负载 ⇒ 读帧路径必然扩容一次"
    );
    // 握手请求（无 early data）远小于两者 ⇒ 握手不受帧缓冲影响。
    let mut headers: Vec<(String, String)> = Vec::new();
    try_default_headers_with(&mut headers, "ws");
    let req = client_request_bytes(&headers);
    assert!(req < frame_read_buffer, "握手请求 {req} B 远小于帧缓冲，握手与帧缓冲互不约束");
}

/// 服务端握手**响应**尺寸：固定部分 ~200 B + 回写的 `Sec-WebSocket-Protocol`
/// （本仓 `server.rs:374-380` 与 Go `hub.go:55-59` 都把 early data 头原样回写）。
#[test]
fn server_handshake_response_size_is_small_even_with_early_data() {
    // 无 early data：响应固定部分就是全部。
    let resp_no_ed = RESPONSE_FIXED_BYTES;
    assert!(resp_no_ed < 512, "无 early data 的握手响应应仅数百字节");
    // 带 early data：响应回写同一个 base64url 头（Go `hub.go:58` /
    // 本仓 `server.rs:378` 同款）⇒ 响应随 ed 4/3 膨胀，与请求同量级。
    for ed in [2048usize, 8192] {
        let resp = resp_no_ed + early_data_header_bytes(ed);
        println!("[ws-handshake] ed={ed} B ⇒ server response ≈ {resp} B");
        assert!(
            resp < RUST_WS_MAX_HANDSHAKE_BYTES,
            "ed={ed} 的握手响应 {resp} B 应远低于 Rust 侧 64 KiB 握手上限"
        );
    }
}
