VERDICT: PASS

# 1xfap：splithttp h3 + stream-one 组合 Rust 侧空响应（定位 + 修复 + 回归）

改动文件：`crates/xray-transport-splithttp/src/dialer.rs`、`crates/xray-transport-splithttp/src/h3_client.rs`、
`crates/xray-transport-splithttp/src/transport.rs`（仅新增测试）。无新依赖、无 wire 语义改动、未 commit。
未碰 `crates/xray-mux/**`、`crates/xray-core/src/functions.rs`、`crates/xray-core/src/outbound.rs`。

---

## 1. 现状核实（当前 HEAD 仍复现，且 G4 的方向记录需更正）

**核实命令**（release 构建 = 当前 HEAD + 本轮改动之前的树）：
```
python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7_h3_matrix.py \
    --rust target-Wave7H3/release/xray.exe --go D:/tmp/go2617/xray.exe
```
（脚本为本轮新建：3 mode × {h2,h3} × 3 方向 = 18 测；判据 = 64 KiB 上行 → 本地 echo 回显 →
逐字节比对，`UP:65536 DOWN:65536 bytes-identical`；h3 由两端 `tlsSettings.alpn=["h3"]` 选路，
与 Go `dialer.go:95` / Rust `dialer.rs::decide_http_version` 同口径。）

**修前输出（HEAD，16/18）**：
```
[FAIL] #16 Rust->Rust h3/stream-one  UP:65536 DOWN:0 BYTES-MISMATCH
[FAIL] #17 Rust->Go  h3/stream-one  UP:65536 DOWN:0 BYTES-MISMATCH
其余 16 条全 PASS（h2/h3 × packet-up/stream-up × 三向 + Go->Rust h3/stream-one）
```

**方向更正（与 G4 记录的差异）**：G4 报告写「失败 2 项 = `h3/stream-one` × {Rust→Rust, **Go→Rust**}」，
并归因为「**Rust 服务端** h3 stream-one 回空」。本轮实测：**Go→Rust（Go 客户端 + Rust 服务端）一直 PASS**，
失败的是**带 Rust 客户端**的两条（Rust→Rust、Rust→Go）——即**坏的是 Rust 客户端侧，Rust 服务端是好的**。
（这解释了 G4 当时的误判方向：Rust 服务端确实能回空响应，但只要客户端不是 Rust 就正常。）

**对照表（修前，h3 组合）**：

| 组合 | 服务端 | 客户端 | 修前结果 |
|---|---|---|---|
| h3 + stream-one | Rust | Rust | **FAIL**（DOWN:0 空响应） |
| h3 + stream-one | Go | Rust | **FAIL**（DOWN:0 空响应） |
| h3 + stream-one | Rust | Go | PASS（字节一致） |
| h3 + stream-up / packet-up | Rust/Go | Rust/Go | PASS（16 条全绿） |
| h2 + 三 mode | Rust/Go | Rust/Go | PASS（9 条全绿） |

---

## 2. 根因与改法（两处缺陷，缺一不可）

### 缺陷 1：H3Conn 生命周期锚缺失 → 连接在上传开始前就被关掉

**取证**（Rust 客户端 `RUST_LOG=trace` + 服务端 trace，服务端收到的连接关闭帧）：
```
客户端: TRACE wrote 1059 bytes stream=client bidirectional stream 0   ← 请求头已发出
客户端: TRACE connection closed
服务端: TRACE got frame Close(Application(ApplicationClose { error_code: 0, reason: b"client conn dropped" }))
```
`"client conn dropped"` 是本仓 `H3Conn::close()` / `H3Conn::drop` 里的字面量
（`h3_client.rs`：`quinn_conn.close(VarInt::from_u32(0), b"client conn dropped")`）——**关闭方是 Rust 客户端**。
h3 crate 侧对应 `SendRequest::drop`（最后���个 SendRequest 释放即以
`H3_NO_ERROR / "Connection closed by client"` 关连接）。临时插桩（已撤）打出的上传任务错误即：
```
send_data err Connection error: Local error: Application { code: H3_NO_ERROR, reason: "Connection closed by client" }
```

**机理**：`H3Conn` 内持 h3 `SendRequest`（h3 crate 文档：「所有实例 drop 后连接自动关闭」）。
`dial_h3_stream_one` 返回后，调用方的 `Arc<H3Conn>` 释放；而上传任务里那个 `this` 捕获**在任务体内从未被使用**
——Rust 生成器的 drop-liveness 会**立刻**释放它 ⇒ `H3Conn` 提前 drop ⇒ `SendRequest` drop ⇒ QUIC 连接被关 ⇒
上行 `send_data` 失败 ⇒ 下行 0 字节（curl 52 Empty reply from server）。

**改法**（`dialer.rs::dial_h3_stream_one`）：把 `H3Conn` 挂到连接的 `on_close` 上作生命周期锚，与同文件
`dial_h3_packet_up`（:495）/ `dial_h3_stream_up`（:525）**同款**（那两个分支本来就挂了，本分支此前漏挂）：
```rust
let conn = conn_with_download(download_body, pipe_client, remote, local);
let h3_for_close = Arc::clone(&client);
conn.set_on_close(move || { h3_for_close.close(); });
Ok(conn)
```
（连接结束 → on_close → 显式关 QUIC 连接 ✓，与 Go `splitConn.onClose → tr.Close()` 同语义。）

### 缺陷 2：收发串行 → 上传是活流时永远读不到响应

**机理**：h3 的 `RequestStream` **收发共用 `&mut self`**（`send_data` / `recv_response` / `recv_data` 都要 `&mut`），
旧实现把「发完整个 body」与「读响应」串在一个 task 的两段里。xhttp stream-one 的真实形态是**活流上传**
（客户端不会先关写向）⇒ body 永不结束 ⇒ 永远走不到 `recv_response()` ⇒ **下行永挂**（curl 超时）。
Go 侧是**并发收发**：`OpenStream` 起 goroutine 跑 `client.Do(req)`，http3 transport 另起 task 发 body，
响应头一到即可读（`proxy/socks`… `transport/internet/splithttp/client.go:60-105`）。

> 缺陷 1 修好后，缺陷 2 立刻显形：矩阵里 #16/#17 从「DOWN:0 空响应」变成「下载超时」——正是活流上传读不到响应。

**改法**（`h3_client.rs::open_stream_uploading`）：按 h3 官方 `RequestStream::split()` 拆成收发两半
（服务端 `serve_h3_request` 同款用法），**上行 task 驱动 send_half（body → finish）**、
**下行 task 驱动 recv_half（响应头 → 响应体 → 下行流）**，收发并发。
wire 语义不变（同样的帧、同样的顺序；只是收/发不再互相阻塞）。

---

## 3. 互通矩阵输出（修后）

```
$ python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7_h3_matrix.py \
      --rust target-Wave7H3/release/xray.exe --go D:/tmp/go2617/xray.exe
[PASS] #01 Rust->Rust h2/packet-up   UP:65536 DOWN:65536 bytes-identical
[PASS] #02 Rust->Go  h2/packet-up   UP:65536 DOWN:65536 bytes-identical
[PASS] #03 Go->Rust  h2/packet-up   UP:65536 DOWN:65536 bytes-identical
[PASS] #04 Rust->Rust h2/stream-up   UP:65536 DOWN:65536 bytes-identical
[PASS] #05 Rust->Go  h2/stream-up   UP:65536 DOWN:65536 bytes-identical
[PASS] #06 Go->Rust  h2/stream-up   UP:65536 DOWN:65536 bytes-identical
[PASS] #07 Rust->Rust h2/stream-one  UP:65536 DOWN:65536 bytes-identical
[PASS] #08 Rust->Go  h2/stream-one  UP:65536 DOWN:65536 bytes-identical
[PASS] #09 Go->Rust  h2/stream-one  UP:65536 DOWN:65536 bytes-identical
[PASS] #10 Rust->Rust h3/packet-up   UP:65536 DOWN:65536 bytes-identical
[PASS] #11 Rust->Go  h3/packet-up   UP:65536 DOWN:65536 bytes-identical
[PASS] #12 Go->Rust  h3/packet-up   UP:65536 DOWN:65536 bytes-identical
[PASS] #13 Rust->Rust h3/stream-up   UP:65536 DOWN:65536 bytes-identical
[PASS] #14 Rust->Go  h3/stream-up   UP:65536 DOWN:65536 bytes-identical
[PASS] #15 Go->Rust  h3/stream-up   UP:65536 DOWN:65536 bytes-identical
[PASS] #16 Rust->Rust h3/stream-one  UP:65536 DOWN:65536 bytes-identical   ← 修前 FAIL（DOWN:0）
[PASS] #17 Rust->Go  h3/stream-one  UP:65536 DOWN:65536 bytes-identical   ← 修前 FAIL（DOWN:0）
[PASS] #18 Go->Rust  h3/stream-one  UP:65536 DOWN:65536 bytes-identical

=== splithttp 矩阵: 18/18 PASS ===
```

全量互通 CI（`dist/interop_ci.py`，本机 43 用例口径）：
```
$ python dist/interop_ci.py --rust target-Wave7H3/release/xray.exe --go D:/tmp/go2617/xray.exe --upstream local
...
[PASS] #43 Rust/Go reality               HTTP body=   1024B
=== 互通 CI: 43/43 PASS ===
```

---

## 4. 回归测试（新增用例，修前必红）

`crates/xray-transport-splithttp/src/transport.rs`（tests 模块）：
`h3_stream_one_returns_full_response_body` —— 真 h3 服务端（自签证书 + ALPN h3 + QUIC listener）
+ 真 `H3Conn` 客户端 + 生产同款 `dialer::dial_h3_stream_one`：
上行 64 KiB（**上传不结束**，不半关写向）→ 服务端 echo → 下行必须 64 KiB **逐字节一致**。

| 状态 | 结果 |
|---|---|
| 修前（HEAD） | **FAILED** — `assertion left == right failed: h3 stream-one must return the full response body` / `left: []`（下行 0 字节）；插桩同时打出 `send_data err ... "Connection closed by client"` |
| 只修缺陷 1（生命周期锚） | 仍 **FAILED** — 下行**超时**（活流上传读不到响应，缺陷 2 显形） |
| 修缺陷 1+2（交付态） | **PASS**（1 passed / 0 failed），且覆盖「上传不结束也能下行」这一真实形态 |

既有 `h3_server_receives_stream_one`（Wave6Tests 修完的那条）仍绿 ✓。

```
$ cargo test -p xray-transport-splithttp --all-targets
test result: ok. 268 passed; 0 failed; 0 ignored   (lib)
test result: ok. 4 passed;   0 failed; 0 ignored
test result: ok. 1 passed;   0 failed; 0 ignored
test result: ok. 12 passed;  0 failed; 0 ignored
test result: ok. 1 passed;   0 failed; 0 ignored
test result: ok. 2 passed;   0 failed; 0 ignored
合计 288 passed / 0 failed / 0 ignored

$ cargo clippy -p xray-transport-splithttp --all-targets -- -D warnings   → 零告警
$ cargo fmt -p xray-transport-splithttp -- --check                       → FMT_EXIT=0
```

---

## 5. 残余风险与未做
- **矩阵脚本为本轮新建**（G4 用的 18 测脚本未入库）：`fix/scripts/wave7_h3_matrix.py`（18 测，h2/h3 × 3 mode × 3 方向）。
  它替代不了 CI 的 43 测（后者也全绿 ✓），但它是「h3 + stream-one」这一组合的唯一可复现入口，建议入库。
- **未跑 32/32 真机互通**（本票验收只列互通矩阵 + splithttp 单测/clippy）。
- **上传方向仍不主动半关**：stream-one 的请求体由对端结束（Go 同款）；本仓客户端在代理连接关闭时才 finish。
- `H3Conn` 的生命周期锚挂在 `on_close` 上：连接被 drop 时显式关 QUIC 连接（与 packet-up / stream-up 同款），
  未新增新的关闭路径。
- 临时插桩（`eprintln!`）已全部撤除；`h3_client.rs` 的上传/下行任务结构改动仅限本 crate 内部，无公共 API 变化。
- 收尾：`CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7H3` 已在交付后删除。
