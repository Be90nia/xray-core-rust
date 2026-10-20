# pipe 丢唤醒修复 + DoH 管线 4s 停顿根治（bd 34nk）

> 2026-10-20 · 交付人：PipeWakeupFix 子代理 · 母代理：Main
> 一句话结论：**DNS 查询经共享拨号器（dispatcher 管线）时的「下行唤醒丢失」已根治**——
> `xray-buf` pipe 的等待注册改为**跨 poll 持久化**（waker 槽），`LinkStream` 改走 poll 形态；
> P0 旁路（DNS 一律直连）已回滚，DNS 重新经路由出站。
> 真机 E2E：首请求 **16.51s → 0.54s**（DoH 走 dispatcher 管线，判据 1-6 全绿）。

---

## 0. 根因（一句话 + 机制）

`xray-buf::pipe` 的读/写等待靠 `tokio::sync::Notify`（`CountingNotify`）登记 waiter。
`LinkStream::poll_read`（`crates/xray-app-dns/src/dial.rs`）**每次 poll 新建并立即丢弃**
`reader.read_multi_buffer()` future —— future 一丢，其内部 `Notify::notified()` 的 waiter
注册随之销毁；写端 `signal()` 只剩计数、**无 waker 可唤醒** → 下行数据到达时读端不被唤醒。
唯一推进读端的是调用方自己的 `timeout(query_timeout)`（tokio `Timeout::poll` 先 poll inner
再查 deadline → 数据在 deadline 那一刻才被交付，表现为「恰好 4.0s 台阶」）。

调用链：`connect_stream` → `DispatcherDnsDialer::dial_tcp` → `dispatch_with_access`
（建两对 `xray_buf::pipe`）→ `LinkStream`（MultiBuffer↔AsyncRead 桥）→ TLS/h2 → DoH 应答。

---

## 1. 改动清单（file:line）

### 1.1 `crates/xray-buf/src/io.rs`（trait 新增 poll 形态方法 + Box 转发）

| 位置 | 改动 |
|---|---|
| `io.rs:6-11` | import 补 `task::{Context, Poll}` |
| `io.rs:79-95` | `trait Reader` 新增 `poll_read_multi_buffer(&mut self, cx) -> Poll<Result<MultiBuffer>>`，**带默认实现**（建 future 轮询一次 = 现状语义），不改任何现有实现者 |
| `io.rs:105-123` | `trait Writer` 新增 `poll_write_multi_buffer(&mut self, cx, mb: &mut MultiBuffer) -> Poll<Result<()>>`，同样带默认实现（mb 所有权交给 `write_multi_buffer` 轮询一次） |
| `io.rs:147-159` | `impl Reader for Box<dyn Reader>`：**转发** `poll_read_multi_buffer` 到内层（不转发则经 Box 调用退回默认实现，丢掉 pipe 的 override） |
| `io.rs:161-177` | `impl Writer for Box<dyn Writer>`：转发 `poll_write_multi_buffer` |

> 与 10-11 参考版（`76feeba3`）的差异：那一版把 `poll_*` 设为**必实现**（要改 32 个文件，
> 是 10-12 架构回退 `d820547f` 的诱因之一）。本次用**默认实现**把影响面收到 3 个文件。

### 1.2 `crates/xray-buf/src/pipe.rs`（waker 槽 + poll 形态读写）

| 位置 | 改动 |
|---|---|
| `pipe.rs:11-20` | import 补 `task::{Context, Poll}`；**移除** `tokio::sync::Notify`（不再需要） |
| `pipe.rs:36-88` | `CountingNotify`：`count` + **`wakers: Mutex<Vec<Waker>>`** 槽（`wakers` 字段在 `:41`）；新增 `wake_all()`（`:57`，signal 与 close 共用）、`register()`（`:65`，同任务 `will_wake` 覆盖旧条目，不堆积）、`poll_wait(cx)`（`:77`，**先查计数 → 注册 waker → 双检**，防丢唤醒窗口） |
| `pipe.rs:152-160` | `PipeShared::mark_closed`：close 时 `read_signal.wake_all()` + `write_signal.wake_all()`（**close/interrupt 路径也必须唤醒对侧**——只做数据路径会留下「close 后全体挂起」的死锁） |
| `pipe.rs:143` | 移除 `closed_notify: Notify` 字段与 `wait_close()`（poll 形态下已无引用；状态检查 + waker 槽覆盖其语义） |
| `pipe.rs:189-200` | `Reader` 由 tuple struct 改为 `{ shared, idle }`；`idle: Option<Pin<Box<tokio::time::Sleep>>>`（`:193`）= **跨 poll 存活的 idle 定时器**（读成功即重置；每次 poll 重建的 sleep 永远等不到超时）；手写 `Clone`（克隆体各自持有独立 deadline） |
| `pipe.rs:206-273` | 新增 `Reader::poll_read`：取数据 → 状态检查 → 错误槽 → `poll_wait` 注册 + `closed_now` 复查 → idle 定时器 → 无信号则 `Pending` |
| `pipe.rs:275-277` | `Reader::read_multi_buffer`（async）改为 `poll_fn` 包住 poll 形态（所有既有调用方受益，签名不变） |
| `pipe.rs:336-345` | `impl BufReader for Reader` 覆写 `poll_read_multi_buffer`（`:344`）→ `Reader::poll_read` |
| `pipe.rs:370-421` | 新增 `Writer::poll_write`（就地消费 `&mut MultiBuffer`：Pending 时**数据留在 mb 里不丢**）；`WriteAction` 增 `Discard` 变体（`discard_overflow` 路径） |
| `pipe.rs:423-425` | `Writer::write_multi_buffer`（async）改为 `poll_fn` 包住 poll 形态 |
| `pipe.rs:465-484` | `impl BufWriter for Writer` 覆写 `poll_write_multi_buffer`（`:474`） |
| `pipe.rs:885-950` | **新增 2 个回归测试**（见 §3） |

### 1.3 `crates/xray-app-dns/src/dial.rs`（LinkStream 改 poll 形态 + 回滚 P0 旁路）

| 位置 | 改动 |
|---|---|
| `dial.rs:178-181` | `LinkStream::poll_read`：`let mut fut = reader.read_multi_buffer(); fut.poll(cx)` → **`xray_buf::io::Reader::poll_read_multi_buffer(&mut this.reader, cx)`**（`:181`） |
| `dial.rs:213-214` | `LinkStream::poll_write` → **`xray_buf::io::Writer::poll_write_multi_buffer(&mut this.writer, cx, &mut mb)`**（`:214`） |
| `dial.rs:298-320` | **回滚 P0 旁路**：`connect_stream` 恢复 `force_local` 语义——`force_local=false` 且共享 dialer 在场时走 `dialer.dial_tcp(dest)`（带 `timeout(query_timeout)`）；`force_local=true` 仍直连（Go Local mode 传 nil dispatcher 的等价语义，bd wmdn②） |
| `dial.rs:131-134` | 新增 crate 级 `#[cfg(test)] pub(crate) static DIALER_SLOT_LOCK`（共享 dialer 槽是**进程级全局**，各模块各持一把锁 = 槽仍会被别的模块的测试改写 → 跨模块串扰） |
| `dial.rs:388-420` | 修正测试 `connect_stream_force_local_bypasses_shared_dialer`：`force_local=false` 段由「也不走 dialer」改为**断言 dialer 被调用**（calls == 1） |
| `dial.rs:499-534` | **新增回归测试** `link_stream_pipe_read_woken_by_downlink_data`（`:507`） |
| `dial.rs:283-348` | 顺带修 4 处**存量 rustfmt 违规**（HEAD 已存在、stable/nightly 都报；纯空白改动，行为不变）——为让 `cargo fmt -p xray-app-dns -- --check` 绿 |

### 1.4 `crates/xray-app-dns/src/nameserver/tcp.rs` / `udp.rs`

| 位置 | 改动 |
|---|---|
| `tcp.rs:305-308` / `udp.rs:341-344` | 改用 crate 级 `crate::dial::DIALER_SLOT_LOCK`（原为各模块私有锁 → 跨模块串扰） |
| `tcp.rs:458-490` | 测试 `tcp_query_routes_through_dialer` 的 P0 断言（`recorded.len() == 0`）改回 **`== 1`**（`:484`）+ dest 原样传递断言 |

---

## 2. 机制说明（为什么这样改）

1. **waker 存槽跨 poll 存活**（10-11 已验证形态的最小复刻）：
   `poll_wait` 先查计数 → 把 `cx.waker()` 存进共享槽 → **再查一次计数**（双检）。
   注册窗口内到达的 signal 不会丢；future 被丢弃时注册仍在槽里 → 写端 `signal()`
   取走 waker 唤醒 → 读端真的被叫醒。
2. **waker 槽是列表不是单槽**（本次实测踩坑，见 §6）：pipe 允许多写者
   （Go pipe 语义，`test_multi_writer_close_keeps_one_whole_write` 用 10 个 writer）。
   单槽只保留最后一个 waker → close 时其余 writer 永不被唤醒 → 全体挂起 = 死锁。
   列表 + `will_wake` 去重（同一任务重复 poll 覆盖旧条目，不堆积）。
3. **close/interrupt 走同一条唤醒路径**：`mark_closed` 唤醒两侧全部等待者，
   等待者醒来看到 `State::Closed/Errord` → EOF / WriteError。
4. **idle timeout 语义保留**：定时器存 `Reader.idle`（跨 poll 存活），读成功即重置；
   每次 poll 重建 `sleep` 会导致「永远等不到超时」（poll 不再回来）。
5. **写端数据不丢**：`poll_write_multi_buffer` 就地消费 `&mut MultiBuffer`，
   管道满时数据留在 mb 里等下次 poll（默认实现做不到这点，故 pipe 必须覆写）。

---

## 3. 测试：先失败后通过（证据）

### 3.1 xray-buf（新增 2 个回归测试，`crates/xray-buf/src/pipe.rs`）

用**自定义 waker 计数器**判定「是否真被唤醒」（不是「是否拿到数据」——
tokio `Timeout` 先 poll inner 再查 deadline，丢唤醒时数据仍会在 deadline 那一刻交付，
用「拿到数据」判定会假绿）。

**修复前（RED）**：
```
test pipe::tests::test_poll_once_writer_woken_when_reader_drains ... FAILED
test pipe::tests::test_poll_once_reader_woken_by_write ... FAILED

---- pipe::tests::test_poll_once_writer_woken_when_reader_drains stdout ----
thread '...' panicked at crates\xray-buf\src\pipe.rs:879:9:
读端腾出空间后写端未被唤醒（丢唤醒）：写入只能等外部超时轮询才推进

---- pipe::tests::test_poll_once_reader_woken_by_write stdout ----
thread '...' panicked at crates\xray-buf\src\pipe.rs:843:9:
写端写入后读端未被唤醒（丢唤醒）：数据只能等外部超时轮询才被取走

test result: FAILED. 201 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.13s
```

**修复后（GREEN）**：
```
test pipe::tests::test_poll_once_reader_woken_by_write ... ok
test pipe::tests::test_poll_once_writer_woken_when_reader_drains ... ok
...
test result: ok. 203 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.13s
```

### 3.2 xray-app-dns（新增 1 个回归测试，`crates/xray-app-dns/src/dial.rs`）

`link_stream_pipe_read_woken_by_downlink_data`：`LinkStream` 读 pipe，下行数据 50ms 后到达，
超时给 3s，按**交付时刻**判定（< 500ms）。

**修复前（RED）**：
```
---- dial::tests::link_stream_pipe_read_woken_by_downlink_data stdout ----
thread '...' panicked at crates\xray-app-dns\src\dial.rs:529:9:
LinkStream 读端未被下行数据唤醒（丢唤醒）：数据在 3.0050978s 才交付（等超时轮询）

test result: FAILED. 3 passed; 1 failed; 0 ignored; 0 measured; 190 filtered out; finished in 3.01s
```

**修复后（GREEN）**：
```
test dial::tests::link_stream_pipe_read_woken_by_downlink_data ... ok
test result: ok. 194 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.54s
```

### 3.3 crate 全量

```
cargo test -p xray-buf --lib       → test result: ok. 203 passed; 0 failed; 0 ignored
cargo test -p xray-app-dns --lib    → test result: ok. 194 passed; 0 failed; 0 ignored
cargo test -p xray-app-dispatcher --lib → test result: ok. 132 passed; 0 failed; 0 ignored
    （dispatcher 是 pipe 的主消费方——10-11 历史里「dispatcher 130/130 复绿」是
      poll 化/waker 修复的验收闸门；本次 132/132 复绿）
```

### 3.4 静态闸

```
cargo clippy -p xray-buf -p xray-app-dns --all-targets -- -D warnings → 无 error
    （仅 vendor/rustls 与 build script 的存量 warning，非本次 crate）
cargo fmt -p xray-buf -p xray-app-dns -- --check        （本地 nightly）→ 0 diff
cargo +stable fmt -p xray-buf -p xray-app-dns -- --check （CI 工具链）→ 0 diff
```

---

## 4. 真机 E2E（T0 修前 / T1 修后配对）

配置 `D:/tmp/dohfix/e2e.json`（socks 10991 + freedom + `https://dns.alidns.com/dns-query`
+ `domainStrategy: IPIfNonMatch`——AsIs 时域名交 OS resolver，配置的 DoH 不参与，会假绿）。
二进制 `target/release/xray.exe`；计时脚本 `D:/tmp/dohfix/e2e_run.py`
（`curl --socks5-hostname 127.0.0.1:10991 http://example.com/`）。

### 4.1 timing 表

| 轮次 | T0（回滚旁路、未修唤醒） | T1（回滚旁路 + 唤醒修复，最终二进制） |
|---|---|---|
| 1（首请求，含 DNS） | **16.510s** (HTTP 200) | **0.515s** (HTTP 200) |
| 2 | 16.468s | 0.406s |
| 3 | 16.465s | 0.422s |

T0 = 4 × query_timeout(4s) 台阶（每次 DoH 查询 2 段 4s，serial 模式两次查询）；
T1 = 无任何 4s 台阶，首请求 0.515s（**< 1.5s 达标**）。

### 4.2 T0 日志（`D:/tmp/dohfix/e2e_T0.log`）——4s 台阶实锤

```
09:26:03.556 DEBUG DNS resolution decision domain=example.com client_names=["DoH:dns.alidns.com:443"]
09:26:03.557  INFO from  accepted tcp:dns.alidns.com:443 [direct]
09:26:07.574 DEBUG doh: tls established alpn=Some([104, 50])        ← +4.017s
09:26:11.583 DEBUG doh: response TIMEOUT (4000ms)                 ← +4.009s
09:26:15.593 DEBUG doh: tls established alpn=Some([104, 50])        ← +4.010s
09:26:19.606 DEBUG doh: response TIMEOUT (4000ms)                 ← +4.013s
09:26:19.606  INFO failed to lookup ip in serial query mode server=DoH:dns.alidns.com:443 domain=example.com error=record not found
09:26:19.606 DEBUG router dns resolve failed, rules match by domain only error=DNS resolution failed: record not found
09:26:19.606  INFO from 127.0.0.1:13545 accepted tcp:example.com:80 [socks-in >> direct]
```
统计：`response TIMEOUT` ×6、`record not found` ×3（每轮一次查询两段）。

### 4.3 T1 日志（`D:/tmp/dohfix/e2e_T1.log`，最终二进制）——判据 1-6 全绿

```
10:11:34.133601Z DEBUG DNS resolution decision domain=example.com client_names=["DoH:dns.alidns.com:443"]
10:11:34.134092Z  INFO from  accepted tcp:dns.alidns.com:443 [direct]        ← 判据5：查询走 dispatcher 管线
10:11:34.158999Z DEBUG doh: tls established alpn=Some([104, 50])              ← 判据2：ALPN=h2
10:11:34.167378Z DEBUG doh: response headers received status=200              ← 判据3：应答到手
10:11:34.167584Z  INFO from  accepted tcp:dns.alidns.com:443 [direct]
10:11:34.193282Z DEBUG doh: tls established alpn=Some([104, 50])
10:11:34.204854Z DEBUG doh: response headers received status=200
10:11:34.662115Z DEBUG DNS resolution decision domain=example.com client_names=["DoH:dns.alidns.com:443"]
```
DNS 决策 → 应答 headers：**34ms**（T0 同段 = 4.017s）。

判据逐条：
1. ✅ `DNS resolution decision ... client_names=["DoH:dns.alidns.com:443"]`（3 次）
2. ✅ `doh: tls established alpn=Some([104, 50])`（2 次）
3. ✅ `doh: response headers received status=200`（2 次）
4. ✅ `response TIMEOUT` **0** 次 / `record not found` **0** 次 / `FRAME_SIZE_ERROR` **0** 次 /
   `router dns resolve failed` **0** 次
5. ✅ `accepted tcp:dns.alidns.com:443 [direct]`（dispatcher 派发记录；DNS 走共享 dialer
   = 走管线，非直连旁路——T0/T1 同一记录格式，且 T0 证明该记录出现即代表管线路径）
6. ✅ 首请求 0.515s（< 1.5s），日志无 +4.0s 台阶

### 4.4 真实 v2rayN 配置回归（`D:/Program Files/v2rayN-windows-64/binConfigs/config.json`）

- 副本改 inbound 端口 `10808 → 10993`（10808 被真 v2rayN 占用），落 `D:/tmp/dohfix/v2rayn_regression.json`；
  资产目录用 `export XRAY_LOCATION_ASSET="D:/Program Files/v2rayN-windows-64/bin"`
  （否则 `geosite:google` 规则 fail-closed 启动失败——与本次改动无关的环境问题）。
- 结果（最终二进制）：`round 1: curl_time_total=1.229836 200`、`round 2: 0.979554 200`
  → mixed inbound、10 条 routing 规则、含 DoH 的 DNS 全部正常，**无退化**。

---

## 5. 未修 / 存疑点

| # | 项 | 说明 |
|---|---|---|
| P2-1 | `doh.rs` h2c 传空 server_name | `from_config_h2c` 用 `String::new()` 当 server_name → URI 变 `https:///dns-query` 非法 → 静默早退被上层吞成 `record not found`。**本次不修**（契约非目标）。 |
| P2-2 | `cached.rs` 吞错误 | 上游任何错误统一吞成 `RecordNotFound`（排查噪声源）。**本次不修**（契约非目标）。 |
| P3-1 | `LinkStream::poll_write` 满管道丢数据 | `poll_write_multi_buffer` Pending 时数据留在 `mb`，但 `LinkStream` 的 `mb` 是局部变量 → 随 poll 结束丢弃。**修前同样丢**（旧代码丢整个 future），**非本次引入的回归**；修法需给 LinkStream 加 pending 缓冲（跨 poll 语义），属扩大改动面，未做。 |
| P3-2 | 装饰层未转发 poll 形态 | `xray-app-dispatcher` 的 `stats::maybe_wrap_reader/writer`（仅在 stats 开启时启用）未覆写 `poll_*` → 走默认实现。默认实现下 pipe 的 waker 槽仍持久有效（唤醒可恢复），但「数据留在 mb」这一层不成立。stats 默认关闭，未触发。 |
| 顺带发现 | `xray-core/src/instance.rs:630` | `get_feature::<DefaultDnsFeature>()` 与实际 `xray_app_dns::DnsService` 不同型 → 恒 false → 日志误报 `no dns feature configured, injecting default`（实际 DnsService 生效，只是多注入一个兜底）。**本次不修**。 |
| 顺带发现 | 测试隔离缺陷 | 共享 dialer 槽是进程级全局，但 dial.rs / tcp.rs / udp.rs **各持一把不同的锁** → 跨模块串扰（udp 测试偶发拿到 tcp 的 mock dialer 而失败）。本次统一为 crate 级一把锁（`crate::dial::DIALER_SLOT_LOCK`）。 |

---

## 6. 过程教训（本次实测踩坑，值得记）

1. **waker 单槽 = 多等待者死锁**：第一版按 10-11 参考实现用 `Option<Waker>` 单槽，
   `test_multi_writer_close_keeps_one_whole_write`（10 个 writer）**挂死 600s 超时**——
   close 时只唤醒最后一个 writer，其余 9 个永挂。改为 `Vec<Waker>` + `will_wake` 去重后复绿。
   **教训**：poll-based 唤醒槽从「单读者」假设起步时，必须先问「这个 pipe 允许几个并发等待者」。
2. **`tokio::Timeout` 会掩盖丢唤醒**：用「是否在超时内拿到数据」判定唤醒会假绿
   （`Timeout::poll` 先 poll inner 再查 deadline → 数据在 deadline 那一刻交付）。
   判定必须看**交付时刻**或**waker 计数**。
3. **端到端必须配对测**：只跑单测会漏掉「单 waker 槽」这类只在并发下暴露的死锁
   （单测全绿 ≠ 端到端真通，用户口供）。

---

## 7. 复现命令

```bash
# 单测
cmd /c "set BORING_BSSL_ASSUME_PATCHED=1&& set BORING_BSSL_SOURCE_PATH=D:\Project\Xray-core-rust\target\boringssl-patched&& set PROTOC=D:/Project/tools/bin/protoc.exe&& set LIBCLANG_PATH=D:\Program Files\llvm\bin&& cargo test -p xray-buf --lib"
cmd /c "... cargo test -p xray-app-dns --lib"

# E2E
cmd /c "... cargo build --release -p xray-cli"
python D:/tmp/dohfix/e2e_run.py D:/tmp/dohfix/e2e.json D:/tmp/dohfix/e2e_T1.log 10991 http://example.com/ 3
```

产物：`D:/tmp/dohfix/e2e_T0.log`（修前）、`D:/tmp/dohfix/e2e_T1.log`（修后）、
`D:/tmp/dohfix/e2e_v2rayn.log`（v2rayN 真实配置回归）、
`D:/tmp/dohfix/e2e_run.py`（计时脚本）、`D:/tmp/dohfix/v2rayn_regression.json`（回归配置副本）。
