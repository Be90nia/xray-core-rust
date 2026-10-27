# W5 面 3 步 3 · tokio 虚拟钟预算站点 → `xray-frame::deadline::Budget`（tuic / vless / vmess / transport）

- 日期：2026-10-27
- 面：能力收敛方案 §2 面 3 步 3（§5.2 波次表 W5）
- 范围（独占文件面）：`crates/xray-proxy-tuic/src/**`、`crates/xray-proxy-vless/src/**`、`crates/xray-proxy-vmess/src/**`、`crates/xray-transport/src/**` 的 **tokio 虚拟钟预算站点**
- 产出二进制：`D:/tmp/w5v5/xray-B.exe`（落码后，A/B 的 B 态）、`D:/tmp/w5v5/xray-A.exe`（仅回退本面 10 文件的 A 态）
- 证据脚手架：`D:/tmp/w5v5/{swap.py,ab.py,aballoc.py}` + `manifest-{A,B}.json`（全树 1443 文件的 sha256/mtime 快照）

---

## VERDICT: PASS（附 2 条须 PM 决策的残余 + 1 条框架层事实上报）

- **站点对账 1:1**：HEAD 34 处 tokio 预算站点 → **迁移 22 处 / 例外登记 12 处（逐处 allow+理由）**，无静默丢弃。
- **四门**：四 crate `check/test` 全绿、`1 处真回归（栈溢出）已定位并修复复测`、fmt 本面为 0 diff、workspace clippy 见 §4。
- **性能门**：同窗 A/B 交错 6 窗口/态，**B 相对 A +1.13%（不降）**，alloc/MB 同簇对比 −0.24%/+0.47%（噪声内）；单变量取证与进程快照双取证齐备（§5）。
- **interop 12/12 PASS**（Rust→Go ×6 + Go→Rust ×6，body=200028B）。
- **32/32 VPS 未跑**（按任务书归 PM）。

---

## 1. 站点对账（HEAD 34 → 迁移 22 / 例外 12）

### 1.1 迁移表（22 处，逐站点）

| # | 文件:HEAD 行 | HEAD 形态 | 落码形态 | 归属 |
|---|---|---|---|---|
| 1 | `xray-proxy-tuic/src/dispatcher.rs:127` | `tokio::time::timeout(30s, client.dial(addr))` | `Budget::tokio().deadline(30s).timeout(...)` | 前任 |
| 2 | `xray-proxy-tuic/src/dispatcher.rs:202` | `tokio::time::timeout(30s, c.dial(...))` | 同上（match 臂保留） | 前任 |
| 3 | `xray-proxy-tuic/src/pool.rs:181` | `tokio::time::timeout(dial_timeout, connector())` | `Budget::tokio().deadline(dial_timeout).timeout(...)` | 前任 |
| 4 | `xray-proxy-tuic/src/udp.rs:132` | `tokio::time::timeout(timeout, recv)` | `Budget::tokio().deadline(timeout).timeout(...)` | 前任 |
| 5 | `xray-proxy-tuic/src/udp.rs:247` | `tokio::time::timeout(to, conn.read_datagram())` | `Budget::tokio().deadline(to).timeout(...)` | 前任 |
| 6 | `xray-proxy-vless/src/dispatcher.rs:477` | `tokio::time::timeout(handshake_timeout, client.handshake(conn))` | `Budget::tokio().deadline(...).timeout(...)` | 前任 |
| 7 | `xray-proxy-vless/src/inbound/server.rs:333` | `tokio::time::Instant::now() + handshake_timeout` | `Budget::tokio().deadline(...)` | 前任（本任换形态） |
| 8 | `xray-proxy-vless/src/inbound/server.rs:348` | `tokio::time::timeout_at(deadline, read_half.read())` | `xray_frame::deadline::timeout(fut, deadline.remaining())` | 前任（本任换形态） |
| 9 | `xray-proxy-vless/src/inbound/server.rs:375` | `tokio::time::timeout_at(deadline, decode_fut)` | 同上 | 前任（本任换形态） |
| 10 | `xray-proxy-vless/src/inbound/server.rs:846` | `tokio::time::Instant::now() + handshake_timeout` | `Budget::tokio().deadline(...)` | 前任（本任换形态） |
| 11 | `xray-proxy-vless/src/inbound/server.rs:851` | `tokio::time::timeout_at(deadline, decode_request_header())` | `xray_frame::deadline::timeout(fut, remaining())` | 前任（本任换形态） |
| 12 | `xray-proxy-vmess/src/inbound/server.rs:246` | `tokio::time::Instant::now() + handshake_timeout` | `Budget::tokio().deadline(handshake_timeout)` | 本任 |
| 13 | `xray-proxy-vmess/src/inbound/server.rs:247` | `tokio::time::timeout_at(deadline, decode_request_header_async())` | `xray_frame::deadline::timeout(fut, remaining())` | 本任 |
| 14 | `xray-proxy-vmess/src/inbound/server.rs:284` | `tokio::time::timeout_at(deadline, drainer.drain())` | 同上 | 本任 |
| 15 | `xray-proxy-vmess/src/inbound/server.rs:688` | `tokio::time::timeout(UP_DONE_IDLE, session.recv_packet())` | `xray_frame::deadline::timeout(fut, UP_DONE_IDLE)` | 本任 |
| 16 | `xray-transport/src/finalmask/realm/portmap/natpmp.rs:216` | `Instant::now() + self.timeout`（tokio） | `Budget::tokio().deadline(self.timeout)` | 本任 |
| 17 | `…/natpmp.rs:224` | `(Instant::now() + backoff).min(deadline)` | `deadline.remaining().min(backoff)` | 本任 |
| 18 | `…/natpmp.rs:225` | `timeout_at(round_end, sock.recv())` | `xray_frame::deadline::timeout(recv, round)` | 本任 |
| 19 | `…/natpmp.rs:231` | `Instant::now() >= deadline` | `deadline.is_expired()` | 本任 |
| 20 | `xray-transport/src/finalmask/realm/portmap/upnp.rs:472` | `Instant::now() + timeout`（tokio） | `Budget::tokio().deadline(timeout)` | 本任 |
| 21 | `…/upnp.rs:474` | `while Instant::now() < deadline` | `while !deadline.is_expired()` | 本任 |
| 22 | `…/upnp.rs:475` | `timeout_at(deadline, sock.recv_from())` | `deadline.timeout(sock.recv_from())` | 本任 |

**计数口径**：pattern = `tokio::time::Instant::now` / `tokio::time::timeout(_at)` / 经 `use` 解析到的裸名（`Instant`/`timeout`/`timeout_at` 来自 tokio 者）；只数**生产行**（`#[cfg(test)]` 块与 `tests/` 已剔除）；函数指针形态（`Instant::now` 不带括号）全仓 grep 0 命中。
**对账数**：`HEAD=34 → 工作树=12`，迁移 22 + 例外残留 12 = 34（1:1）。

### 1.2 例外登记（12 处，逐处理由）

| # | 站点 | 处数 | 例外理由（Budget API 构造约束） | 登记形态 |
|---|---|---|---|---|
| E1 | `xray-proxy-tuic/src/server.rs:593,612,655,675` | 4 | `Sleep::reset` 只收 `tokio::time::Instant`；`Budget`/`BudgetDeadline` 刻意**不外露绝对时刻**（双源统一入口的设计约束）→ 无法表达 `reset(now + d)` | 两处 fn 级 `#[allow]` + reason（本任把 713x6 旧理由更新为面 3 例外理由） |
| E2 | `xray-proxy-vless/src/inbound/server.rs:691` | 1 | 同上：`sleep_until(deadline)` 需要绝对 `tokio::time::Instant` | 语句级 `#[allow]` + reason（同上更新） |
| E3 | `xray-transport/src/happy_eyeballs.rs:123,162` | 2 | 同上：`timer.reset(Instant::now())` / `(now + try_delay)` | 文件内注释登记（transport clippy 未禁 `tokio::time::Instant::now`，无需 allow） |
| E4 | `xray-transport/src/bridge.rs:408,417,464,473,520` | 5 | **数据面热路径**：`up_reader`/`down_reader` 泵**每读一次**的超时（splice 通路）；坑约束 ⑫「数据面热路径零改动」+ splice 双 revert 史实 + 该文件属 W6 面（`8a200d7b` 刚入库） | 本报告登记，未改代码 |

**E4 须 PM 决策**：这 5 处语义上是**恒等替换**（`timeout(d,f)` → `Budget::tokio().deadline(d).timeout(f)` 同为 `timeout_at(now+d)`），但落在每读热路径。建议单开一个 splice-safe 波次（带抓包 + 同窗 A/B + p7lm 关闭的前提下）再做，而不是混在控制面波次里。若 PM 判「本波就该做」，请下指令，我按恒等替换落码并重跑性能门。

### 1.3 明确范围外（不属「tokio 虚拟钟预算点」，未动）

| 类别 | 处数 | 归属/理由 |
|---|---|---|
| `std::time::Instant::now`（vless dispatcher/preconnect/reverse/encryption、tuic pool、vmess encoding） | 9（生产） | **std 墙钟面** = W3b `compat::clock` 面，非 tokio 虚拟钟；本波不动 |
| `tokio::time::sleep` / `sleep_until` / `interval` | 多处 | `Budget` **无 sleep 面**（面 3 API 只有 `deadline/timeout/is_expired/remaining/elapsed`），不属取时点 |
| `SystemTime::now`（vmess `aead/mod.rs:595`、`encoding/client.rs:166`） | 2 | 协议 **wire 时间戳**（Go 兼容语义），方案 §2 面 3「不可迁残余 3」明确留协议 crate |

---

## 2. 前任半成品核对（5 文件 11 站点）

**结论：语义与原 HEAD 逐点等价，无静默语义漂移；本任做了 2 处修正（1 处真回归 + 1 处形态统一）。**

| 核对项 | 结论 |
|---|---|
| tuic `dispatcher.rs`（2）/ `pool.rs`（1）/ `udp.rs`（2） | 恒等替换（`timeout(d,f)` → 预算截止点 `.timeout(f)`），match/错误分支原样保留；`.timeout()` 返回值轮廓不变（`Result<_, Elapsed>`）→ 分支语义零变化 |
| vless `dispatcher.rs`（1） | 同上；ENC 握手超时窗口不变 |
| vless `inbound/server.rs`（5） | `Instant::now()+handshake_timeout` → `Budget::tokio().deadline(...)`；`timeout_at(deadline,..)` → 同一绝对截止点。**但形态用了 `BudgetDeadline::timeout` 的 async-fn 形态** → 本任统一为构造式（见 §3 根因） |
| 编译态 | 开工前 `cargo check --workspace --all-targets` 绿（D1：5m09s，0 error） |
| 测试态 | 修完栈回归后四 crate test 全绿（§4） |

**两处修正**

1. **vmess 巨型 future 栈溢出**（新落码触发，见 §3）→ 三个站点改构造式。
2. **vless 5 站点形态统一**：async-fn 形态 → 构造式（`xray_frame::deadline::timeout(fut, remaining())`），与 vmess 同形态。理由不是风格，是**栈足迹**：`handle_connection` 同为巨型 async fn，async-fn 包装每站点都会加厚 future（§3 已在 vmess 上实测溢出）。改后 vless 全绿（287 + 14 + 2 passed）。

---

## 3. 本波发现的真回归（栈溢出）——根因、取证、修法、框架启示

**症状**（四 crate 测试首跑）：`inbound::server::tests::vmess_inbound_udp_relay_e2e` → `STATUS_STACK_OVERFLOW (0xc00000fd)`。

**单变量取证**

| 步骤 | 命令 | 结果 |
|---|---|---|
| 1 · 隔离复现 | `cargo test -p xray-proxy-vmess --lib vmess_inbound_udp_relay_e2e` | overflow（确定性，非 flaky） |
| 2 · HEAD 对照 | 同文件换回 `git show HEAD:…` 后同命令 | `1 passed; 0 failed`（0.52s） |
| 3 · 修后复测 | 构造式落码后同命令 | `1 passed`（0.54s） |

**根因**：`BudgetDeadline::timeout` 是 **async fn**（内部 `match &self.source` + Wall 臂 `tokio::select!` + `wall_expiry_watch`），在**巨型 async fn** 里逐站点叠加会加厚生成 future 的栈足迹。vmess `handle_connection` 尾部是 `tokio::join!(up, relay)`，UDP relay 循环内再套一层 async-fn 包装 → 单测线程（libtest 默认 2MiB 栈）溢出。**这不是测试特有的**：生产 worker 线程栈同为 2MiB 量级，future 变厚 = 每连接栈占用变高。

**修法**：改用框架既有「构造式」 `xray_frame::deadline::timeout(fut, d)`（`deadline.rs` 里 P0-3 的**唯一超时包装点**，返回具名 `tokio::time::Timeout<F>`，与裸 `tokio::time::timeout` 同类型同体积），绝对截止点由 `BudgetDeadline::remaining()` 每次现算承接（漂移 = 计算间隙，纳秒级；整条握手仍被同一绝对预算封顶）。仍是**预算端口**，不是退回裸 tokio。

**框架层启示（须上报；本波不改 xray-frame 源码）**：面 3 方案 §「风险」只写了「Budget::now() 多一层调用」，**漏了「async-fn 形态会加厚巨型 future」这条**。建议：①文档补该风险 + 判据（巨型 async fn 优先用构造式）；②或给 `BudgetDeadline` 补一个返回具名类型的构造形态（现 `Budget::deadline(d)` + `deadline::timeout(fut, d)` 组合已够用，属可选优化）。

---

## 4. 门尾部（实跑，2026-10-27 19:2x）

```
=== CLIPPY WORKSPACE ===
$ cargo clippy --workspace --all-targets -j 8 -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 25.75s
CLIPPY_EXIT=0

=== FMT WORKSPACE ===
$ cargo fmt --all -- --check
（零输出）
FMT_EXIT=0

=== TESTS 4 CRATES ===
$ cargo test -p xray-proxy-vmess -p xray-proxy-vless -p xray-proxy-tuic -p xray-transport --all-targets -j 8
xray-proxy-tuic     : 68 + 1 + 1 + 1 + 5 + 9 + 2 =  87 passed / 0 failed
xray-proxy-vless    : 287 + 14 + 2 + 0 =             303 passed / 0 failed（2 ignored）
xray-proxy-vmess    : 165 + 7 + 12 + 2 + 0 =         186 passed / 0 failed（1 ignored）
xray-transport      : 662 passed / 0 failed（2 ignored）
合计                : 1238 passed / 0 failed / 5 ignored
```

D1（落码前树绿）：开工首跑 `cargo check --workspace --all-targets` → `Finished dev profile in 5m09s`，0 error（含前任半成品）。
编译污染处置：首轮 workspace clippy 被**非本面** untracked 探针 `crates/xray-app-dispatcher/examples/ohm_lookup_ab.rs:61`（CR1aC 的 A/B 计时器）挡住 → 按 D4 只报根因不抢改（已 broadcast + PM 点给 owner）；owner 补 `#![allow(clippy::disallowed_methods, reason=...)]` 后复跑 exit 0。

---

## 5. 性能门（同窗 A/B 相对差 · 单变量 + 进程快照双取证）

### 5.1 A/B 定义

| 态 | 构造方式 |
|---|---|
| **A** | **仅**把本面 10 个文件回退到 HEAD（`git show HEAD:<path> > <path>`），其余在树增量（W4 的 core/mux/dns 未提交项等）**全保留** |
| **B** | 本波落码后（当前工作树） |
| 构建 | 同 target 目录（`target-w5v5`）、同命令 `cargo build --release -p xray-cli -j 8`：B 18m18s / A 9m39s |
| 复原校验 | A 测完 `swap.py toB` → 与备份 **10/10 逐字节一致**（`verifyB`） |

### 5.2 单变量取证（manifest 全树 sha256）

```
manifest-A vs manifest-B（1443 个 tracked 文件）:
  sha-diff 文件数 = 10   ← 全部是本面 10 文件
  only-A = []   only-B = []
  mtime-diff 文件数 = 10 ← 同一批；"内容相同但 mtime 变" = 0
```

**窗口后的第三方改动（不破坏 A/B 单变量）**：测量收工后（19:2x）工作树另有 2 文件变动 ——
`crates/xray-transport-splithttp/src/dialer.rs`（PM 补 W6 漏跑的 fmt 门，**纯格式**）与
`docs/benchmarks/baseline.md`（文档）。两者都在 A/B 两次构建之后、且与 A↔B 差集无关，
故 A/B 单变量结论不受影响（`manifest-final` 复核：本面 10 文件仍与 B 态逐字节一致）。

### 5.3 时间线 + 进程快照（并发编译污染取证）

| 时刻 | 事件 | cargo/rustc 进程快照 |
|---|---|---|
| 18:49–19:06 | **W4V5 自披露**跑了 workspace clippy + 17min release 构建（协议违规，PM 已批评） | — |
| 19:05:04 | B 态 release 构建完成 + manifest-B 快照 | — |
| 19:14:53 | A 态 release 构建完成 + manifest-A 快照 + 复原 B（10/10 一致） | — |
| 19:14:57 | **测量前快照** | `cargo.exe` 0，`rustc.exe` 0，`clippy-driver.exe` 0 |
| 19:15:00–19:19:14 | **A/B 交错测量窗（12 个 200MB 窗口）** | 窗口内无编译（期间仅 CR1aC 的 ns/op 探针，见下） |
| 19:19:14 | **测量后快照** | `cargo.exe` 0，`rustc.exe` 0 |

**污染判定**：W4V5 污染窗 18:49–19:06 与本测量窗 19:15:00–19:19:14 **零重叠** → 无需作废重测（依 PM 口径「窗口都在 19:06 之后则记录取证即可」）。
**旁证**：CR1aC 的 A/B 微基准（19:19–19:2x）只编译 example、不起 xray 进程、端口段 19100+/19199 与 bench 的 18100/11081/18453 隔离，且其编译起始时刻在我吞吐窗之后 → 12 个吞吐窗口内无并发编译。

### 5.4 吞吐（192MB 文件 via `xhttp+reality+vless(mlkem-enc)` 链，各态 6 窗口交错）

| 轮 | A（MB/s） | B（MB/s） | 配对差 |
|---|---|---|---|
| 1 | 154.5 | 166.4 | +11.9 |
| 2 | 155.2 | 157.3 | +2.0 |
| 3 | 160.1 | 150.7 | −9.4 |
| 4 | 152.1 | 155.4 | +3.3 |
| 5 | 159.3 | 157.8 | −1.5 |
| 6 | 150.9 | 155.0 | +4.0 |
| **均值** | **155.4** | **157.1** | **+1.13%** |
| 最好 | 160.1 | 166.4 | +3.90% |

- **判据**：同窗 A/B 相对差 → **B 不降（+1.13%）= PASS**；逐轮配对差 −9.4…+11.9 MB/s，即本窗噪声带约 **±6%**，任何单轮差都落在噪声内（故用 6 窗均值 + 配对符号，不用单轮）。
- **绝对值说明**：本测量窗 150–166 MB/s；`docs/benchmarks/baseline.md`「2026-10-27 复测校准」已钉死**绝对值不可跨窗口比较**（同锚基线二进制当日仅 128.6–131.1 MB/s，窗口内有并发编译抢 CPU）。本波绝对值同样只与同窗 A 态比。
- 结构上也无回归面：迁移的 22 处全在**控制面**（握手 / 拨号 / NAT-PMP / SSDP / UDP 收尾窗），数据面热路径文件 `bridge.rs` 一字未动（§1.2 E4）。

### 5.5 alloc/MB（`--alloc-stats`，各态 3 窗交错）

| 窗口 | A srv / cli | B srv / cli |
|---|---|---|
| 1 | 1,789,962 / 3,107,948 | 1,923,962 / 3,103,074 |
| 2 | 1,831,953 / 2,435,444 | 1,798,445 / 2,429,620 |
| 3 | 1,800,235 / 2,440,179 | 1,837,081 / 3,100,874 |

- **采样呈双峰**（cli 每态都出现 ~2.43M 与 ~3.10M 两簇；srv 亦然）：1s 采样周期 × ~1.4s 下载窗，末次采样是否跨 tick 决定落哪簇 —— **两态都出现同一双峰 = 采样伪影，不是本波引入**。
- **同簇口径**（min-of-3，避开伪影）：`cli −0.24%`、`srv +0.47%` → 噪声内（门限 ≤1%）。中位数因双峰不可用，已明示。
- 结论：alloc/MB **无上升**。

---

## 6. interop 12/12（RUST = `D:/tmp/w5v5/xray-B.exe`）

```
== A: Rust client -> Go server ==
[PASS] #01..#06  vmess / vless_vision_tls / trojan_tls / vless_ws / ss / ss2022   HTTP body= 200028B
== B: Go client -> Rust server ==
[PASS] #07..#12  同上六协议                                           HTTP body= 200028B
=== 互操作矩阵: 12/12 PASS ===
```

跑法：`dist/interop_matrix.py` 本体零改动，内存内把 `RUST = 'dist/xray.exe'` 常量替换为本次产物后以 `__main__` 语义 exec（与 W6 同款 runner 思路）。

## 7. 32/32 真机

**未跑**：按任务书「32/32 VPS 不跑（归 PM）」——VPS 面不在本波授权范围。

---

## 8. 残余风险 / 未做

| 项 | 说明 |
|---|---|
| E4（`bridge.rs` 5 处） | 数据面热路径未迁（§1.2），**须 PM 决策**：单开 splice-safe 波次（抓包 + 同窗 A/B） |
| E1/E2/E3（7 处 `Sleep::reset`/`sleep_until`） | `Budget` 无「绝对时刻 / timer-arm」面 → 7 处在结构上不可迁；若要收口需框架补面（属 xray-frame 改动，本波非目标） |
| `BudgetDeadline::timeout` async-fn 形态的栈代价 | 本波实测可把巨型 future 推过 2MiB 线程栈（§3）。方案稿风险节未记 → 已在 §3 上报；**其余波次（W4 的 app-dns `dot.rs` 等）若在巨型 future 内多点使用同形态，建议同法复核** |
| alloc/MB 双峰 | 采样伪影未修（`tools/loopback_alloc_bench.py` 采样窗与下载窗竞态）→ 建议后续把采样改为按下载起止显式打点，否则 alloc 门只能用同簇 min 判 |
| 生产栈占用 | 迁移后 vmess/vless `handle_connection` future 体积**回到 HEAD 水平**（构造式与裸 `timeout` 同型），未增加每连接栈占用 |

## 9. 5 轴自评

- **准确性 5/5**：34→22+12 对账由可复现脚本产出（HEAD/工作树逐行 census，`#[cfg(test)]` 剔除、裸名经 `use` 解析）；栈回归有 HEAD 对照实测（PASS→overflow→PASS）；性能数字逐轮列出 + 定义 A 态构造与两构建间 1443 文件 sha256 差集；alloc 双峰伪影如实披露而非掩盖。
- **完整性 4/5**：本面 34 处全部给出归宿（22 迁 + 12 例外，无静默丢弃），四门 + interop + 性能门齐跑；扣分：32/32 未跑（归 PM，非本任授权）、E4 未落码（数据面热路径，等 PM 决策）。
- **清晰度 5/5**：三段式（对账 / 例外 / 性能门），每条数字附命令与尾部落盘证据，A 态定义、污染时间线、伪影判读均显式交代。
- **可执行性 5/5**：报告给出可复跑命令与产出物路径（`D:/tmp/w5v5/{swap.py,ab.py,aballoc.py,manifest-{A,B}.json,xray-{A,B}.exe}`），E4 的落码方式与验收条件已写明，框架层两条建议可径直落成文档/API 改动。
- **简洁性 4/5**：扣分 —— §1.1 表 22 行与 §2 核对表存在小段信息重叠（为同时满足「逐站点对账」与「半成品核对」两个验收项）。
