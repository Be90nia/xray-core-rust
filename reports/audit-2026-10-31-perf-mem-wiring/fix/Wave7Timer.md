VERDICT: DONE（Budget 补 timer-arm 面（arm_timer/BudgetTimer）+ 5 处豁免全迁全删；虚拟推进语义保留（5 个 start_paused 用例锁定）；反证 L3 门有效；三 crate 379/0 全绿）

# 23vrp：Budget 补 timer-arm 面 —— tuic/anytls 生产 tokio-Instant 豁免迁移

> 票面（DOD D3 复核缺口 3）：`Budget`/`BudgetDeadline` 刻意不外露绝对时刻，而 `Sleep::reset` /
> `timeout_at` 只吃 `tokio::time::Instant` ⇒ 5 处生产站点无法迁 Budget，只能 fn 级登记豁免。
> 本票：Budget 补 timer-arm 面（绝对时刻/重置锚，保留 tokio 虚拟推进语义）→ 逐站点迁移 → 删豁免。

## 待办清单
- [x] §1 两条约束解读
- [x] §2 API 设计与取舍（为何不破构造约束）
- [x] §3 逐站点迁移（tuic ×4 idle reset、anytls ×1 握手 timeout_at）+ 删豁免（deadline.rs 现状 + git log -S 动机 + 豁免站点语义差异）
- [ ] §2 API 设计与取舍（为何不破构造约束）
- [ ] §3 逐站点迁移（tuic ×4 idle reset、anytls ×1 握手 timeout_at）+ 删豁免
- [x] §4 行为等价证据（idle 重置重新计时 / 握手到期断开）
- [x] §5 虚拟推进测试（tokio pause/advance 驱动，不依赖真实等待）
- [x] §6 豁免清零证明 + 反证（迁回 tokio::time::Instant → 门禁红）
- [x] §7 门禁（xray-frame / xray-proxy-tuic / xray-proxy-anytls 三 crate test+clippy+fmt）
- [x] §8 残余风险

---

## 1. 两条约束解读

### 1.1 「刻意不外露绝对时刻」的现状与动机

`xray-frame/src/deadline.rs`（面 3 · 能力收敛方案 §2 面 3；ADR-1 派生三段式）：

- `BudgetInstant`（绝对时刻的两源统一表达）是**私有枚举**：`Tokio(tokio::time::Instant)` /
  `Wall(std::time::Instant)`。调用方能拿到的只有 `Budget`（源 + 起点）、`BudgetDeadline`
  （源 + 截止点），以及 `elapsed()` / `remaining()` / `is_expired()` / `timeout(fut)` ——
  没有任何方法把 `tokio::time::Instant` / `std::time::Instant` 交出去。
- 动机（模块注释 + impl 级豁免登记）：**入口统一，不是时钟实现统一**——tokio
  `advance/timeout_at` 只收 `tokio::time::Instant`，接 udf `Clock` 会作废虚拟推进测试语义
  （713x6 裁决「tokio 面不迁 udf」）；墙钟语义走 `Budget::wall(Clock)` 出口（`MockClock`
  可冻结/推进）。两源若在调用方手里可互换/可读出，就会有人拿 tokio Instant 去接 std Clock
  判定（钟族混换，nn8os reaudit 登记过的禁混换纪律）——所以构造约束是「绝对时刻不过框架边界」。
- 现有能力盘点：`BudgetDeadline::timeout(fut)` **已覆盖 `timeout_at` 形态**（tokio 源臂 =
  `tokio::time::timeout_at`，保 advance 语义）——anytls 站点缺的不是新 API，是把
  `tokio::time::Instant` 换成 `BudgetDeadline`；真正缺的只有 **`Sleep::reset` 的可重置面**
  （tuic idle-reset）⇒ 需要新的 timer-arm API。

### 1.2 五处站点语义差异（两种需求，非一种）

| 站点 | 形态 | 需要的 API 面 |
|---|---|---|
| tuic `udp_assoc_direct` / `udp_assoc_dispatch`（server.rs:594-668 两 fn，各 2 处 reset） | **可重置 idle 计时器**：`tokio::pin!(sleep(d))` 进 `select!`，每包活动 `idle.as_mut().reset(Instant::now()+d)`，触发即淘汰 assoc。reset 是**在已武装的计时器上重锚**，且 select 竞争输掉后状态必须保留 | timer-arm：`arm_timer(d)` + `reset(d)` + `expired()`（方案 A） |
| anytls `handle_conn` + `handle_session`（:234 一处锚点，:236/256/284/316/333/362 六处 `timeout_at`） | **绝对握手 deadline**：锚点算一次，六个顺序 await 共用（`Instant::now() + timeout` 反复传给 `timeout_at`） | `Budget::deadline(d)` + `BudgetDeadline::timeout(fut)`——**既有 API 已覆盖**，无需新增 |

即：tuic 需要「可重置」、anytls 需要「可传递的绝对截止句柄」——后者框架里已经有了。

---

## 2. API 设计与取舍（方案 A；B 不需要新设计）

**落地面**：`Budget::arm_timer(d) -> BudgetTimer`，`BudgetTimer { reset(d) / expired() / is_expired() }`。

- **选 A 的理由**：tuic 的 reset 形态是「状态ful 计时器被 select 轮询、活动时重锚」——`Sleep`
  本体是状态载体，必须由框架持有一等封装才能把 `Instant::now()` 收进桥（方案 B 的
  `remaining()+timeout_at` 每次重算绝对点，等价于每次新建 timer 顶替 reset，**改变并发行为**
  ——票面明令禁止）。方案 B 对 anytls 场景其实就是既有的 `BudgetDeadline`，不构成新设计。
- **不破构造约束**：`BudgetTimer` 内部存 `TimerInner`（Tokio 臂 = `Pin<Box<Sleep>>` + 私有锚点
  `at: tokio::time::Instant`；Wall 臂 = `Clock` + `at: std::time::Instant`）——绝对时刻只在
  xray-frame 内部，构造入口唯一（`Budget::arm_timer`），公开方法无任何 Instant 出入口。
  `clippy::disallowed_methods` 登记面从「每协议 fn 级」收敛回「xray-frame 桥本体 impl 级」
  （与 Budget/BudgetDeadline 同一面），L3 静态闸恢复全覆盖。
- **tokio 虚拟推进语义保留**：Tokio 臂 `expired()` = `sleep.as_mut().await`（原生 Sleep，
  advance/pause 全语义）；Wall 臂 = 墙钟轮询（冻结永不触发，语义同 `BudgetDeadline::timeout`
  wall 臂）。`is_expired` 锚点与 arm/reset 同步更新。
- **语义对齐细节**：`reset(d)` = `Sleep::reset(Instant::now() + d)`（自此刻重新计时，非
  「新建 timer 顶替」——同一 `Sleep` 本体重锚，select 取消安全）；arm 锚点 = arm 调用时刻
  （idle 业务语义「自最近一次活动起」）；溢出 → 锚点停在当前时刻（立即触发，fail-closed，
  同 `Budget::deadline` 溢出臂）。Wall 臂不在 `expired()` 外挂 tokio 兜底计时器（避免冻结语义
  失真，与 `BudgetDeadline::timeout` wall 臂同一取舍）。

---

## 3. 逐站点迁移 + 豁免删除

| 站点 | 迁移 | 豁免删除 |
|---|---|---|
| tuic `udp_assoc_direct` | `let mut idle = Budget::tokio().arm_timer(UDP_ASSOC_IDLE);`；2× `idle.as_mut().reset(Instant::now()+d)` → `idle.reset(d)`；`_ = &mut idle` → `_ = idle.expired()` | fn 级 allow + doc 例外块删除 |
| tuic `udp_assoc_dispatch` | 同上形态 | fn 级 allow + doc 例外块删除 |
| anytls `handle_conn` | `Budget::tokio().deadline(handshake_timeout())`；5× `timeout_at(deadline, fut)` → `deadline.timeout(fut)`；spawn 传参 `handshake_deadline.clone()`（Fn 闭包每次调用独立份，非 Copy 差异） | fn 级 allow + nn8os 台账注释删除 |
| anytls `handle_session` | 参数 `first_packet_deadline: tokio::time::Instant` → `BudgetDeadline`；1× `timeout_at` → `.timeout()` | 无需豁免（原 fn 本就无 Instant::now 调用） |

---

## 4. 行为等价证据（迁移前后同场景时间行为一致）

| 场景 | 证据 | 结果 |
|---|---|---|
| anytls 握手 deadline 到期断开 | `server_closes_connection_after_first_packet_timeout`（真实 TLS + session 全链路：对端认证后不发首包 → deadline 到期 → FIN+shutdown 关连接）——迁移后原样通过 | ✅ ok |
| anytls 六处 `timeout_at` 语义 | `BudgetDeadline::timeout` tokio 源臂实现体 = `tokio::time::timeout_at(at, fut)`（deadline.rs，本票未改）——同一锚点同一 fut，语义恒等；`tests/deadline_budget.rs` 既有 6 用例（advance 判负精确到预算点 / 冻结不判负）全绿 | ✅ ok |
| tuic idle 重置后重新计时 | `udp_assoc_reuses_session_across_packets`（两包间隔内 `idle.reset()` 真实发生：出口 socket 复用 = assoc 未被淘汰；reset 语义若坏，第二包会新开 socket → 出口端口变 → 测试红） | ✅ ok |
| tuic idle 到期淘汰（触发臂） | `select` 竞争/触发语义由框架层锁定：`timer_arm_survives_select_race_cancellation` + `timer_arm_fires_exactly_at_virtual_deadline`（§5，start_paused 确定性）| ✅ ok |
| BudgetDeadline / Budget 既有面 | 零改动（本票只新增 timer-arm），既有 6 预算用例照常通过 | ✅ ok |

## 5. 虚拟推进仍可测（start_paused 驱动，零真实等待）

新增 5 用例全部 `#[tokio::test(start_paused = true)]` + `tokio::time::advance`（`tests/deadline_budget.rs`）：

| 用例 | 证明 |
|---|---|
| `timer_arm_fires_exactly_at_virtual_deadline` | advance(999ms) 未触发 / +1ms 触发——走虚拟时间轴、精确到预算点 |
| `timer_arm_reset_re_arms_window` | 600ms 活动 → reset(1s) → 999ms 不触发 / +1ms 触发——reset 是**重新计时** |
| `timer_arm_survives_select_race_cancellation` | 复刻 tuic select 形态：expired 输掉竞争（future drop）→ reset → 完整 1s 窗重来（状态在 timer 本体不在 future） |
| `timer_arm_reset_after_fire_re_arms` | 已触发态 reset 同样重武装（`Sleep::reset` 契约） |
| `timer_arm_wall_source_follows_clock` | Wall 源：`MockClock` 冻结 → 真实 50ms 内不触发；advance(120s) → 轮询间隔内触发（误挂 tokio 计时器会假触发，本测试即防） |

## 6. 豁免清零证明 + 反证

- `grep -rn "tokio::time::Instant" crates/xray-proxy-{tuic,anytls}/src/` → **零命中**（唯一残字是
  anytls server.rs:227 迁移注释里的文字描述）。
- fn 级豁免登记：tuic 2 处 + anytls 1 处 **全部删除**（`#[allow(clippy::disallowed_methods)]`
  连同「待 Budget 补 timer-arm 面再收」台账注释）。
- 反证（回迁裸时钟 → 门红）：在 `udp_assoc_direct` 塞一行无豁免的
  `let _bare = tokio::time::Instant::now();`，clippy 立即红：

  ```
  error: use of a disallowed method `tokio::time::Instant::now`
     --> crates\xray-proxy-tuic\src\server.rs:596:17
  ```

  即：豁免删除后 L3 静态闸重新全覆盖——任何回迁不经登记就合不进来。探针已还原。

## 7. 门禁

| 门禁 | 结果 |
|---|---|
| `cargo test -p xray-frame -p xray-proxy-tuic -p xray-proxy-anytls --all-targets` | **379 passed / 0 failed** |
| `cargo clippy` 同三 crate `--all-targets -- -D warnings` | 零告警 |
| `cargo fmt` 三 crate `-- --check` | 0 diff |

改动面（未 commit）：`xray-frame/src/deadline.rs`（+107：BudgetTimer + arm_timer + 登记）
`xray-frame/tests/deadline_budget.rs`（+86：5 用例）`xray-proxy-tuic/src/server.rs`（迁移 + 删 2 豁免）
`xray-proxy-anytls/src/server.rs`（迁移 + 删 1 豁免）。

## 8. 残余风险

- xray-frame 桥豁免面 +1 个 impl 块（`BudgetTimer`，登记理由与 Budget/BudgetDeadline 同一口径）
  ——框架桥自身的 tokio 面豁免从 2 收敛为「3 个 impl 块、协议侧 0」，是本方案的预期终态。
- tuic 60s idle 淘汰无端到端测试（迁移前后都没有——start_paused 下跑真 quinn mock server
  风险大于收益）；触发臂语义已由框架层 start_paused 用例确定性锁定。
- Wall 臂 `expired()` 为 10ms 轮询（检出延迟上界 = 间隔），与 `BudgetDeadline::timeout` wall 臂
  同取舍；生产站点均走 Tokio 臂，该臂仅测试/未来 Wall 站点使用。

（本节完 → 落盘）
