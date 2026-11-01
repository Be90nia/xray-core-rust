VERDICT: PASS

# Wave7 输入面三票清偿（dp2dm / y5cy9 / 0snlt）

仪器：`fix/scripts/wave7_input_probe.py`（CPU/RSS/响应字节）、`fix/scripts/wave7_e2e_leftover.py`（字节不丢）；
二进制：修前 `fix/tmp/wave7-before.exe`（HEAD 树 `target/release/xray.exe`，Nov 1 08:43，早于本轮所有改动）、
修后 `fix/tmp/wave7-after.exe`（本轮改动 release 构建）；Go 基准 `D:/tmp/go2617/xray.exe`（26.10.17，92ccc93）。
CPU = psutil `cpu_times(user+system)` 差分（Windows 计数粒度 ~15.6ms，故「0.000」= 低于一个 tick），
单跑不并发，测量前确认无残留 xray/cargo 进程。

---

## 1. dp2dm（P1 security）SOCKS4 USERID 无上限逐字节读

### 根因
`crates/xray-proxy-socks/src/server.rs` 的 `read_until_null` 没有任何长度界：匿名 socks 入站发
`0x04` 后持续灌非 NUL 字节即可让单连接无限读下去（1 字节/次 syscall），60s 握手上限到点前
CPU 与堆都被吃满。Go 侧 `ReadUntilNull`（`proxy/socks/protocol.go:288`）每读一字节检查
`b.IsFull()`，缓冲容量是 `buf.StackNew()` = `common/buf.Size` = **8192**，写满即 `buffer overrun`
拒绝；README 写的「8KB 上限」就是这个常量（`common/buf/buffer.go:14`）。

### 修法
- 新增 `SOCKS4_MAX_FIELD_BYTES = 8192`，`read_until_null` 累加到上限即返回
  `HandshakeFailed("... buffer overrun")`（超限**拒绝**，不静默截断继续），USERID 与 SOCKS4a
  域名共用同一上限（与 Go 同款：两处各用一个新的 StackNew 缓冲）。
- 逐字节 `read_exact` 保留（Go 是「从 buf.Reader 取整块、再按字节切片」；Rust 这里没有 pushback
  读器，块读会把 4a 域名/隧道首批字节吃掉），以注释 `shortcut:` 登记上限语义与升级条件。

### 反证（同一攻击：`0x04` + CMD/port/ip 后灌 64KB 块，10s 窗口，两轮交替）
| 轮 | 二进制 | CPU 秒 | RSS 峰值 | 客户端写入量 |
|---|---|---|---|---|
| R1 | before | **10.359** | 32.9 MB | 12,779,520 B |
| R1 | after | **0.000** | 15.3 MB | 8,585,216 B（写进内核即被对端丢弃，进程侧不读） |
| R2 | before | **10.547** | 32.9 MB | 12,779,520 B |
| R2 | after | **0.000** | 14.4 MB | 8,585,216 B |

修前 ≈ 100% 单核持续 10s（与审计记录的 12.44 CPU 秒/10s 同量级），修后 CPU 低于计数精度、
RSS 从 32.9MB 回到 14-15MB 空闲水位。

### 验证
- 新增 `socks4_userid_without_terminator_rejected_at_cap`（8KB+ 无 NUL → 判 `buffer overrun`）。
- 既有 `socks4a_handshake_domain_connect_succeeds` / `socks4_handshake_ipv4_connect_succeeds` 仍绿
  → 上限没有卡死正常 4a 域名路径。

---

## 2. y5cy9（P1 security）HTTP 请求头逐字节无缓冲读

### 根因
`crates/xray-proxy-http/src/server.rs` 的 `read_http_line` 用 `read(&mut [0u8;1])` 逐字节读：
1MB 头 = 100 万次 syscall。Go 侧 `proxy/http/server.go:108`
`bufio.NewReaderSize(readerOnly{conn}, buf.Size)` = 8KB 块读，逐字节只是内存切片。

### 修法
1. `read_http_line<R: AsyncBufRead>()` 改为 `fill_buf`/`consume`：一次拿满调用方 `BufReader` 的
   8KB 内部缓冲，在块内找 `\n`、只 consume 到行尾——**行后多余字节留在读器里**，请求体 / 下一
   keep-alive 请求 / CONNECT 隧道数据都不丢（`LineStep{Done,More,Eof}` 三态）。
   语义逐条保留：裸 LF 合法、仅剥行尾一个 CR、空行即 EOF 走 `UnexpectedEof`、Latin-1 透传、
   单行 1MB 上限（`MAX_HTTP_HEAD_BYTES`，= Go `DefaultMaxHeaderBytes`，已有）。
2. 头之后必须有「同一个读器」续读，故边界上提（Go 的 bufio 就是随连接走的）：
   - `http_server_handshake` / `read_request_head` 的 bound 从 `AsyncReadExt` 换成 `AsyncBufRead`；
   - xray-core `serve_http`：连接进入即 `PeekAhead::new(stream)`；`PeekAhead` 新增 `AsyncBufRead`
     impl（`poll_fill_buf` 块读 8KB 进 `peeked`，`consume` 只丢已解析部分）。`peeked` 非空时
     `into_link_io` 早已走「连缓冲一起交给读侧」分支，CONNECT 隧道天然不丢字节；
   - `serve_mixed_conn` 本来就用同一个 `PeekAhead`，无需改动；
   - `xray-proxy-http` 自己的监听路径：`serve_connection` 用 `BufReader::new(stream)`，握手/plain
     转发/CONNECT `copy_bidirectional` 全走它；上游响应也改成 `BufReader`（`read_response_head`
     / `forward_chunked_body` / `copy_exact_n` 泛化为 `AsyncBufRead`/`AsyncRead`+`AsyncWrite`）。

### 反证（1MB 头：`GET http://127.0.0.1:9/ HTTP/1.1\r\n` + 不带 CRLF 终止的头字节，3s 窗口，两轮交替）
| 并发 | 轮 | before CPU 秒 | after CPU 秒 | 倍数 | before/after RSS |
|---|---|---|---|---|---|
| 1 路 × 1MB | R1 | **2.172** | **0.000** | ≥ 2000× | 17.3 / 17.3 MB |
| 1 路 × 1MB | R2 | **2.188** | **0.000** | ≥ 2000× | 17.3 / 17.3 MB |
| 20 路 × 1MB | R1 | **42.484** | **0.141** | **301×** | 50.9 / 51.5 MB |
| 20 路 × 1MB | R2 | **42.844** | **0.078** | **549×** | 40.4 / 48.8 MB |

RSS 基本不变（1MB 头上限未动，仍是 Go `DefaultMaxHeaderBytes` 量级）：本票治的是 CPU 放大，
不是内存上限；内存界由既有 1MB 头上限兜住（实测单路 17MB / 20 路 ≤52MB 常量级）。

### 字节不丢取证（`wave7_e2e_leftover.py`，真实 http 入站 + freedom）
| 用例 | 构造 | after 结果 |
|---|---|---|
| post-body | 请求头 + `Content-Length: 11` body **一次 write** | 上游收到 11 字节 → `200 OK` / `got=11` |
| connect-pipe | `CONNECT ...\r\n\r\n` + 隧道首批 `PINGPONG` **一次 write** | 目标收到 `PINGPONG`，隧道原样回显，状态行 `200 Connection established` |

两个用例在 before 二进制上同样通过（before 无预读，天然不丢）→ 本用例是**回归护栏**，
证明缓冲化没有把 body/隧道字节吃进读器。

### 验证
- 新增 `read_http_line_leaves_bytes_after_newline_in_reader`（行后字节仍可从同一读器读到）。
- `e2e/http_proxy_e2e.rs` 三处握手改成 `BufReader`（POST 用例本就「头+体同段」，正是护栏点），
  CONNECT 用例加 `assert!(buffer().is_empty())` 声明「客户端等到 200 才发隧道数据」。

---

## 3. 0snlt（P2 gap）HTTP 入站错误响应方向与 Go 相反

### 根因（E1 实测，非源码推断）
传票记的「缺 Host → Go 400 / Rust 静默关；坏 CL → Go 静默关 / Rust 400」两半都对，但坏 CL 只在
**origin-form** 形态复现——真正原因是**校验次序**：

- Go `http.ReadRequest` 内部就跑 `readTransfer`→`fixLength`（坏 CL 直接失败 → `Process` 断链不回
  响应），之后 `ParseHost("")` 又不报错，缺 Host 的 origin-form 一路走到 `handlePlainHTTP` 的
  `!AllowTransparent && request.URL.Host == ""` 才回 400；
- Rust 旧序：握手期先解析 host（缺 Host → 报错静默断链），CL 校验留在 `handle_plain_http`（因此
  origin-form + 坏 CL 会先命中透明代理 400）。两段逻辑顺序颠倒 → 两种畸形请求的方向整体互换。

### 修法
1. 透明代理 400 判定提到 dest 解析之前（条件不变：`method != CONNECT && !allow_transparent &&
   !target.contains("://")`，等价 Go `!AllowTransparent && request.URL.Host == ""`）；
2. Content-Length 校验前移到读头阶段（等价 Go 在 `ReadRequest` 内的 `fixLength`），并顺带把
   `parse_content_length` 收紧到 Go 口径：纯十进制（拒绝 `+5`）、≤ `i64::MAX`、**多值必须一致**
   （不一致报 `conflicting Content-Length headers`）；非法即 `Protocol` 错误 → 静默断链。

### 反证 + 对齐对照（同一构造请求，三端原始字节）
| 用例 | Go 26.10.17 | Rust before | Rust after |
|---|---|---|---|
| 缺 Host 的 origin-form | `400 Bad Request` + Connection/Proxy-Connection/CL:0 | **空（静默关）** | `400 Bad Request` + 同四头（逐字节相同） |
| 坏 CL + origin-form | **空（静默关）** | `400 Bad Request` | **空（静默关）** |
| 坏 CL + absolute-form | 空（静默关） | 空（静默关） | 空（静默关） |
| 控制组：absolute-form 无 Host 头 | `503 Service Unavailable` | `503 ...`（同字节） | `503 ...`（同字节） |

after 的 400/503 字节块与 Go 主表逐字节一致（同 `RESPONSE_BAD_REQUEST` /
`RESPONSE_SERVICE_UNAVAILABLE` 常量），四个用例方向全部对齐。

### 验证
- 新增 `handshake_origin_form_without_host_returns_400`、`handshake_bad_content_length_closes_without_response`、
  `parse_content_length_matches_go_strictness`；
- 既有 `handshake_origin_form_rejected_without_allow_transparent` / `_allowed_with_transparent` /
  `handshake_absolute_url_unaffected_by_transparent_flag` 全绿（证明次序调整没有误伤放行分支）。

---

## 4. 验收命令与输出

```
$ cargo test -p xray-proxy-socks -p xray-proxy-http --all-targets
running 89 tests  ... test result: ok. 89 passed; 0 failed; 0 ignored        # xray-proxy-http lib
running 22 tests  ... test result: ok. 22 passed; 0 failed; 0 ignored        # xray-proxy-http 其它 target
running 7  tests  ... test result: ok. 7  passed; 0 failed; 0 ignored
running 90 tests  ... test result: ok. 89 passed; 0 failed; 1 ignored        # xray-proxy-socks lib
running 2  tests  ... test result: ok. 2  passed; 0 failed; 0 ignored        # e2e_proxy
running 4  tests  ... test result: ok. 4  passed; 0 failed; 0 ignored        # error_variants
running 10 tests  ... test result: ok. 10 passed; 0 failed; 0 ignored        # plugin_contract
合计 223 passed / 0 failed / 1 ignored

$ cargo clippy -p xray-proxy-socks -p xray-proxy-http --all-targets -- -D warnings
=== CLIPPY EXIT: 0 ===      （零告警）

$ cargo fmt -p xray-proxy-http -p xray-proxy-socks -- --check
MY_CRATES_FMT_EXIT=0        （另 rustfmt --check crates/xray-core/src/inbound.rs = 0）

$ cargo check --all-targets -p xray-core -p xray-proxy-http -p xray-proxy-socks
Finished `dev` profile ... (exit 0)   # 含 xray-core 侧 PeekAhead/serve_http 接线
```

> `cargo fmt -p xray-core -- --check` 当前红，但 diff 全在 `crates/xray-core/src/functions.rs`（同波次
> MuxUdp 在途新增的 UDP 测试注释/折行，非本票文件，已通报对方）；`inbound.rs` 本身 fmt 干净。

入站路径未新增 `unwrap()` / `panic!()`：新增代码全部走 `Result`/`?`；测试内的 `unwrap` 属既有
测试脚手架（crate 级 `#[allow]`）。

## 5. 残余风险与未做
- **SOCKS4 仍是逐字节读**（`shortcut:` 已登记）：单连接代价被 8192 次读封顶，不是块读；根治需要
  入站侧统一的 pushback 读器（把多读字节回灌给 4a 域名/隧道），本轮不做。
- **头内存上限未变**（1MB = Go `DefaultMaxHeaderBytes`）：20 路并发各灌 1MB 时 RSS 仍到 ~50MB
  （与修前同量级），本票只治 CPU 放大。
- `xray-proxy-http` 自身 plain 路径对 **chunked 请求体**仍回 400（该 crate 的既有已登记方言，
  与 xray-core 的生产路径支持 chunked 不同），不在本票范围。
- 传输校验只对齐了 Content-Length：坏 `Transfer-Encoding` 时 xray-proxy-http 自身路径仍会回
  400（xray-core 生产路径静默断链，与 Go 一致）；未纳入本票。
- 未跑 workspace 全量测试与 32/32 真机互通（验收只要求两个 crate 的 test/clippy；xray-core
  侧只做 `cargo check --all-targets`，其 lib test 由同波次 DnsWriter 一并跑）。
- `CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7In` 已在使用后删除（report 之外的产物：
  `fix/tmp/wave7-{before,after}.exe` 保留作复现）。
