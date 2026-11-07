# ADR 目录（架构决策记录）

本目录存放 Xray-core-rust 的**架构决策记录**（ADR）。每条 ADR 记录一个不可逆或
高影响面的架构归属/选型决策：背景、决策、后果、被否决的备选、以及验证方式。

## 格式（五节体，缺一不可）

每条 ADR 必须包含以下五节：

1. **背景**——问题是什么，为什么现在要决策；引用 bd 票号 / 用户口供 / 上游裁决。
2. **决策**——拍了什么，一句话可复述；落点（crate::路径）写清。
3. **后果**——采纳后的正面/负面后果、维护义务、迁移路径。
4. **备选否决**——考虑过并被否决的方案，逐条给否决理由（不写「没想过」）。
5. **验证方式**——怎么证明决策仍成立：测试名、命令、反向自检锚点。

## 编号规约

- 文件名 `adr-NNNN-<短横线-slug>.md`，NNNN 四位零填充，从 0001 递增，**不复用**。
- 决策被取代时：旧 ADR 状态改 `Superseded by ADR-NNNN`，**不删除**（历史裁决链）。
- 状态字段取值：`Accepted`（生效）/ `Superseded`（被取代）。草案不进本目录。

## 索引

| 编号 | 标题 | 状态 | 日期 |
|---|---|---|---|
| [ADR-0001](adr-0001-spawn-idle-pruner-derived-not-promoted.md) | 派生件扩面：`spawn_idle_pruner` 留 xray-frame，不上浮 udf | Accepted | 2026-11-06 |
| [ADR-0002](adr-0002-memory-budget-ownership-split.md) | 装配面登记簿：常量簿上浮 `xray-frame::budget`，预算门留 xray-core | Accepted | 2026-11-06 |

## 附件

- [api-ledger-2026-11-06.md](api-ledger-2026-11-06.md)——批次 `e737e904..HEAD` 新增
  公共 API 逐项记账表（67 项，每项归入 ADR 或给「无需 ADR」理由）。

## 与治理宪法的关系

本目录是 CLAUDE.md §3.5（三层定位与继承派生纪律）与 `docs/ARCHITECTURE.md` 的
**执行层细则**：宪法定判据（三判据顺序固定），ADR 记个案裁决。冲突时以宪法为准、
以新 ADR 修订旧 ADR。
