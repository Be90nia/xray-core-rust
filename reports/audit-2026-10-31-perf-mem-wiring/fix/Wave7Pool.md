VERDICT: PASS

# il9lh 剩余两项：MW-4（ws 池惰性 TTL） + MW-5（ArmScopeRegistry 只登记不摘）

改动文件：`crates/xray-transport-websocket/src/pool.rs`、`crates/xray-frame/src/scope.rs`（各 crate 内单文件，
无新依赖、无公共 API 破坏性变更；`xray-core` 消费方 API 未变 → `cargo check -p xray-core --all-targets` exit 0）。
「修前」数字取法：把修法临时短路回旧形态跑同一批新用例（失败输出即修前形态证据），随后复原。

---

## 1. MW-4 ws 池惰性 TTL / 空 key 不摘

### 定位
`crates/xray-transport-websocket/src/pool.rs`：
- `try_acquire`（旧 :219-237）：过期扫描**只作用于本次被访问的那个 key**，且条目被扫光后
  **key 留在表里**（空 key 永不回收）；
- `release`（旧 :263）：`guard.entry(key).or_default()` **先建 key 再判容量**——池满时留下一条
  永不回收的空 key；
- 全文件**没有任何全量回收路径**：一个 key 一旦不再被访问，它的空闲连接（至多
  `max_idle_per_key` 条 socket）与 key 本身永久留在池里。

### 语义澄清（先查证再改）
- 池语义：**预连接池**（virgin-connection pool）——池内只存「握手完成、零内层字节」的预连接；
  承载过会话数据的连接无归还路径（交付侧无归还代码）。
- key = `(host, port, path, tls_server_name, fingerprint, mask)`；**key 的 host = 出站 ws 服务器
  地址** ⇒ key 空间由用户配置的 ws 出站数封顶（与票面「严重度 Low」一致）。
- TTL = `max_idle_duration`（默认 10s）；容量 = `max_idle_per_key`（默认 12，**per key**）。
- 复用判据 = `now - last_used > max_idle_duration`（FIFO 先入先过期）。**本轮不改 TTL、不改容量
  语义**——只补「回收路径」与「空 key 摘除」，故复用窗口与命中率口径不变。

### 修法
1. **后台扫除任务**（每池一个，`OnceLock` 幂等闸）：周期 = `clamp(TTL/4, 100ms, 30s)`；持
   `Weak(inner)` + `Weak(config)`（池 drop 后 `upgrade` 失败 → 任务自行退出，不延长池寿命、
   不留孤儿任务）；每轮扫**全部** key：摘过期条目（同一判据）+ 连带摘空 key。任务在
   `release`/`try_acquire` 时按需启动（`Handle::try_current()` 失败则不启，惰性路径仍在）。
2. `try_acquire`：条目被扫光 / 被取光 → **key 一并摘除**（空 key 不留）。
3. `release`：容量判定**先于**建条目——池满时不再留下空 key。
4. 新增诊断面 `WsConnectionPool::stats()` → `PoolStats { keys, entries }`（key 数含空 key，
   即泄漏信号）。

### 反证（修前 = 把后台任务短路回旧形态跑同一用例）
| 用例 | 修前 | 修后 |
|---|---|---|
| `idle_entries_reclaimed_without_any_access`（2 key 各 1 条，TTL 200ms，**全程不调用 try_acquire**，等 600ms） | **FAILED — left: 2, right: 0**（TTL 过后条目数**不降**、key 也不摘） | **passed** — entries 2→0、keys 2→0，且**对端 socket 读到 EOF**（连接真被关闭，不是只删计数） |
| `key_removed_when_last_entry_taken`（取走最后一条） | **FAILED**（取空后 key 仍在表里） | **passed** — keys 1→0 |
| `reuse_within_ttl_keeps_hit_rate`（TTL 500ms 内 20 轮 release→acquire） | 20/20 命中 | **20/20 命中（100%，不下降）** |
| `sweeper_keeps_entries_within_ttl`（TTL 1s，扫除周期已过但未到 TTL） | — | **passed** — 条目存活（回收未做成「更激进」） |

既有池语义用例全绿（`burst_12_full_stock_never_cold_dials` / `burst_15_handshakes_within_ticket_budget` /
`empty_pool_cold_start_then_replenish_refills_next_wave` / `concurrent_replenish_gate_admits_exactly_capacity`
/ `pool_sweeps_expired` / `probe_admits_alive_and_discards_dead_preconnections` 等）——容量与复用路径未回归。

### 验证
```
$ cargo test -p xray-transport-websocket --all-targets
WS: passed=124 failed=0 ignored=1
$ cargo clippy -p xray-transport-websocket -p xray-frame --all-targets -- -D warnings
（零告警；仅 vendor rustls 的既有 2 条 warning）
$ cargo fmt -p xray-transport-websocket -p xray-frame -- --check
FMT_EXIT=0
```

---

## 2. MW-5 ArmScopeRegistry 只登记不摘

### 定位
`crates/xray-frame/src/scope.rs` 的 `ArmScopeRegistry`：`entries: Mutex<Vec<(String, Arc<ArmScope>)>>`，
`register` 只 `push`（旧 :274-277），`close_all_reverse` 出清。消费方唯一登记点 =
`crates/xray-core/src/inbound.rs:3662-3664`（`spawn_inbound_serve`，每个 inbound 一次）。

### 语义澄清（先查证，结论 = 票面描述成立，可安全改）
1. 登记表**每宿主实例一份**（`xray-core` `Instance.arm_scopes` / `InboundRuntime.arm_scopes`），
   不是全局表 ⇒ 同名条目不可能代表「跨实例多份」。
2. tag = 入站身份：宿主 slot 表 `BoundedRegistry<String, InboundSlot>` 按 tag **唯一**，重复 tag
   直接 `AlreadyExists`（`inbound.rs:3466-3468` + 既有测试
   `start_inbound_same_tag_concurrent_only_one_wins`）⇒ **同名多条 = 重复，不是合法多实例**。
3. 移除路径已负责关停：`remove_inbound` → per-inbound token cancel → 停机监视
   `arm.arm_scope().shutdown_timeout(...)`（`inbound.rs:3727-3731`）⇒ 旧 scope 在重新登记前
   **已被关过**，upsert 时再 close 一次是幂等无害。
⇒ 结论：按 tag upsert 不会改坏任何合法用法。

### 修法（`ArmScopeRegistry::register`）
- 同 tag **upsert**：旧条目摘除、新的挂到登记序**末尾**（`close_all_reverse` 仍是「后登记先关」
  = 后起的 arm 先停，逆序语义不变）。
- 被替换的旧 scope **显式 close**（幂等）：移除路径已关过则无害；未关过时避免它成为宿主
  close 编排表外的孤儿 arm（表外 = 宿主停机不再关它）。
- 同一 scope 重复登记走 `Arc::ptr_eq` 豁免：**不**把刚登记的 arm 关掉（否则当场自伤）。
- 并发：全段在同一把毒锁容忍的互斥锁内完成（无 await、无锁序交叉）——gRPC 并发
  `AddInbound`/`RemoveInbound` 不引入竞态或死锁。

### 反证（修前 = 把 `register` 临时改回 push-only 跑同一用例）
| 用例 | 修前 | 修后 |
|---|---|---|
| `register_same_tag_upserts_single_entry`（同 tag 登记 5 次） | **FAILED — left: 5, right: 1**（5 条永久条目） | **passed** — `registered() == 1`；被替换的旧 scope 均已 closed；最后登记的那条仍 open |
| `register_same_scope_twice_keeps_it_open`（同一 scope 登记两次） | — | **passed** — 1 条且 scope **未被关**（ptr_eq 豁免生效） |
| `concurrent_register_same_tag_keeps_single_entry`（8 线程 × 50 次同 tag） | — | **passed** — 终态恒 1 条，无死锁 |
| `concurrent_register_and_close_all_no_deadlock`（4 线程登记 ∥ 1 线程 `close_all_reverse`） | — | **passed** — 无 panic/死锁，终态条目数有界 |
| `register_distinct_tags_keep_all_entries`（不同 tag） | — | **passed** — 2 条（多入站场景未误伤） |

### 验证
```
$ cargo test -p xray-frame --all-targets
FRAME: passed=229 failed=0 ignored=0
$ cargo clippy -p xray-transport-websocket -p xray-frame --all-targets -- -D warnings → 零告警
$ cargo fmt -p xray-transport-websocket -p xray-frame -- --check → FMT_EXIT=0
$ cargo check -p xray-core --all-targets → exit 0（消费方 API 未变）
```

---

## 3. 残余风险与未做
- **未跑 workspace 全量测试与 32/32 真机互通**（本票验收只列两个 crate 的 test/clippy；xray-core
  侧做到 `cargo check --all-targets` 绿）。
- **ws 池后台任务的生命周期**：池在 runtime 外被首次触碰（`Handle::try_current()` 失败）时不启任务，
  此时回收退化为惰性路径（与修前同）——生产路径的 `release`/`try_acquire` 均在 runtime 内，无影响。
- **upsert 关闭旧 scope 的语义**：若同一 tag 在**未移除**的情况下被重复登记（宿主 slot 表会拒，
  属非法态），旧 arm 的在途连接会被级联取消——这是「同名新 arm 取代旧 arm」的合理处置，非回归。
- **a5pe6（h2 块池多流常驻）**：按票面说明本票不处理（MemWiring 已定性为天然满足）。
- **MW-3（TPROXY fake_cache 上界 + LRU）**：波 1 已完成，本票未触碰
  `crates/xray-core/src/inbound.rs` 的 fake_cache 部分。
- 红线遵守：未动 `crates/xray-core/src/outbound.rs`、`crates/xray-core/src/functions.rs`、
  `crates/xray-proxy-{socks,http}/src/server.rs`；未引入新依赖；未 commit。
- 收尾：`CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7Pool` 已删除。
