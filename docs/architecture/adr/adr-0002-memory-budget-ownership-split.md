# ADR-0002：装配面登记簿——常量簿上浮 `xray-frame::budget`，预算门留 xray-core

- 状态：Accepted（PM 口径拍板 2026-11-06）
- 日期：2026-11-06
- 关联：bd azcoe（登记簿立项）· bd sgdwm（登记簿扩面）· 37vjq（本轮归属裁决）·
  CLAUDE.md §3.5.5（ADR-1 三判据）

## 背景

`crates/xray-core/src/memory_budget.rs`（bd azcoe · 256MB 小鸡口径）当前承载
两部分：

1. **容器登记簿**：14+ 条 `pub const`（整机 96MB 预算、每连接 pipe/socket 4MiB、
   QUIC/UDP 缺省缓冲、握手在飞上限、DNS/TLS 缓存上限、finalmask 池上限、hyper
   idle 上限、新池总上限、预留余量等）——每容器一条，能从实现处导入的以交叉
   断言钉住；
2. **装配期预算门**：`check_startup_budget(&BuiltConfig)`——在
   `start_full` / `start_full_with_outbound_handlers` 两路入口执行，配置派生值 +
   实际占用面合计超 `XRAY_BUDGET_BYTES` 即逐条列违例拒启。

归属未裁：登记簿常量散在 xray-core，被 `xray-transport::sockopt`、
`xray-transport::handshake_gate`、`xray-buf` 等实现处以**值对齐**引用（执行点在
主仓、口径登记在 xray-core），拆分/上浮方向不明。

## 决策（PM 拍板口径，2026-11-06）

**二分归属，口径唯一**：

- **纯常量簿**（14+ 条 `pub const`）→ 上浮 **`xray-frame::budget`**。
  判定：判据 1（零 Xray 语义）不成立——常量含 Xray 预算语义（96MB 小鸡口径、
  quic-go parity、Go 同源坑豁免），按 ADR-1（§3.5.5）判据 2 走默认答案归**派生
  层 xray-frame**；常量零类型依赖（只有 `usize`/`Duration`），平移无接口变化。
- **`check_startup_budget` 留 `xray-core`**。理由（判据 3 逐条举证成立）：该门
  吃 `xray_conf::BuiltConfig`，而 `xray-conf` 已依赖 `xray-frame`——上浮即
  `xray-frame → xray-conf` **反向依赖成环**（§3.5.3 依赖方向单向红线）；
  预算门属装配语义（校验 `BuiltConfig` 配置派生面），不是进程级通用机制。

## 后果

- 常量消费方（登记簿交叉断言、sockopt/handshake_gate 值对齐）随上浮切到
  `xray-frame::budget` 路径，主仓删本地副本（§3.5.2 禁留双份）。
- `check_startup_budget` 留守，继续在两路启动入口执行（fail-visible 拒启纪律
  不变）；其引用的登记簿常量改从 `xray-frame::budget` 导入。
- 拆分执行在飞（独立工作流处理 `memory_budget.rs`），本 ADR 定**归属口径**，
  不锁执行节奏；执行落地后本节补一行「已落地 commit」即可，无需新 ADR。

## 备选否决

- **全部留主仓**：违背 ADR-1 判据 2——常量簿可平移、不举证 = 判「留主仓」=
  打回项（§3.5.5）。
- **`check_startup_budget` 一并上浮**：`xray-frame → xray-conf` 反向依赖成环，
  编译不可达；即便引入 trait 抽象解耦 `BuiltConfig` 也属为上浮而造新抽象
  （禁止范围外抽象）。
- **上浮 udf**：常量含 Xray 语义（Go 兼容语义算 Xray 语义，判据 1 不成立），
  地基不收。

## 验证方式

- 交叉断言：登记簿常量 vs 实现处值的交叉断言测试（`memory_budget.rs`
  `mod tests` 现有形态）随上浮迁到 `xray-frame::budget` 侧继续钉住——改任一侧
  实现值即红。
- 回归门：上浮后 `cargo test -p xray-core`（含装配期预算门行为测试）与消费方
  crate（xray-transport / xray-buf）测试全绿；`cargo doc` 无悬空内链
  （登记簿路径迁移后的 doc 链接同步）。
- 反向自检：预算门违例路径（bufferSize 负值硬拒 / 合计超 96MB 拒启）有既有
  测试覆盖，上浮不得改变其行为。
