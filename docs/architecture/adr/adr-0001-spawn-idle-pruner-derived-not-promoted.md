# ADR-0001：派生件扩面——`spawn_idle_pruner` 留 xray-frame，不上浮 udf

- 状态：Accepted
- 日期：2026-11-06
- 关联：bd jovl4（缺口 3）· bd hj3jf · udf issue#23（not planned 关闭）·
  CLAUDE.md §3.5.2/§3.5.3/§3.5.5

## 背景

hysteria udphop 的缓冲池（udf `ObjectPool<Vec<u8>>`）需要**闲置老化**：Go 的
`sync.Pool` 靠 GC 回收闲置块，Rust 无 GC ⇒ 池必须显式修剪，否则 idle 槽即内存
常驻。udf `ObjectPool::prune_idle_with_clock`（issue#22 正典口，Clock 注入）只
提供**调用口**，明确「池不起后台线程」——老化循环由宿主承担。宿主侧因此需要：
托管任务（禁裸 spawn，CLAUDE.md §3.5.6 ①）+ 周期 tick + 双时钟注入（`MockClock`
确定性测试 / tokio 虚拟时间 tick 节奏 / `SystemClock` 生产兜底）。

udf 侧曾收到「`spawn_idle_pruner` 托管老化任务」提案（issue#23），**按 not
planned 关闭**，理由（udf CHANGELOG 原文）：纯组合无新语义（`FxScope::spawn_tracked`
+ `tokio::time::interval` + `prune_idle_with_clock`）、`period`/`max_idle_age`
是宿主策略、与「池不起后台线程」既定纪律冲突——宿主侧 ~15 行派生，迁移 snippet
已贴 issue#23。按 §3.5.2，udf 明确不收的件，消费方**派生**而非复制或强推上游。

## 决策

`xray-frame::pool::spawn_idle_pruner`（`crates/xray-frame/src/pool.rs`）作为
**B 类继承派生件**落地：组合包装 udf `ObjectPool::prune_idle_with_clock` +
`FxScope::spawn_tracked`（零复制 udf 机制），签名按「上游日后落同一件即可删本口
换 udf 版」的形状设计（`pool / clock / period / max_idle_age`）。**不上浮 udf**。

- 归属判定（§3.5.5 三判据）：判据 1 不成立——件含 Xray 语义（绑定坑约束 5 的
  spawn 托管纪律与 xray-frame 审计 target `xray_frame::pool`）；默认答案 = 判据
  2 归派生层 xray-frame。
- 唯一生产消费点：`crates/xray-transport-hysteria/src/udphop.rs`（连接自有
  `ManagedScope` 的 fx 句柄挂 pruner；scope 随连接存活，close/Drop 即 abort，
  无孤儿循环）。

## 后果

- +xray-frame 承担该派生件的维护与测试（托管端到端 + MockClock 确定性推进）。
- 协议/传输 crate **禁止**再手写同类老化循环（单账本；旧手写 ManagedScope loop
  已删，bd jovl4 缺口 3 收口为统一托管口）——新需求走本口接线。
- 上游解除 NOT_PLANNED 落同一件时：删 `spawn_idle_pruner`，消费点换 udf 版
  （调用面零重排），本 ADR 改 Superseded。

## 备选否决

- **上浮 udf**：违背 issue#23 not planned 裁决与「池不起后台线程」纪律；
  `period`/`max_idle_age` 是宿主策略，进 udf = 地基感知宿主语义（§3.5.3 反向）。
- **协议 crate 手写老化循环**（旧 ManagedScope loop 形态）：裸 spawn/双账本风险
  （bd 9utc3、jovl4），已被统一托管口取代，复活即打回。
- **池自身起后台线程**：udf 纪律红线，直接否决。

## 验证方式

- 托管端到端：xray-frame `pool::tests::idle_pruner_releases_aged_idle_on_tick`
  （`start_paused` 虚拟时间 + `MockClock`，tick 后超龄 idle 必释放、scope 关闸
  后无孤儿循环）。
- 老化语义：hysteria `udphop::tests::prune_idle_releases_aged_blocks`——**反向
  自检锚点**：不接老化任务，idle 恒 8 必红。
- 接线：hysteria `udphop::tests::idle_pruner_is_hosted_by_connection_scope`——
  构造后在途恰 1（pruner 循环体），close 三段排空后归零。
- 命令：`cargo test -p xray-frame --lib pool` 与
  `cargo test -p xray-transport-hysteria --lib` 全绿。
