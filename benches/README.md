# benches/ — 性能基准测试

> cargo bench 入口；记录 baseline + 性能回归的源头
> 与 `docs/benchmarks/baseline.md` 对齐

## 用途

5 个 criterion 风格基准（buf/crypto/readv/router/transport）—— 数据面/控制面关键路径的循环内分配、读向量、加密吞吐等基线。

## 用法

```bash
# 跑全部
cargo bench --workspace

# 单跑某个
cargo bench --bench buf_bench
cargo bench --bench readv_bench   # 真实端点同窗 A/B 锚点（88m0 战役）

# 对比基线（需 criterion 0.4+）
cargo bench --bench buf_bench -- --save-baseline my-feature
cargo bench --bench buf_bench -- --baseline my-feature
```

## 与 5 维审计关系

- **P1-001 perf**（85% P1 债 = 0；含 AUDIT-PERF-001 trait Box::pin）依赖本目录回归
- **DEBT-023**（v2 性能 baseline CI 钩）**直接消费**本目录产物
- 8 sum/enc8x 战役均依赖本目录的 `readv_bench` 同窗交替 A/B

## 红线

- 不删现有 bench 文件（每次战役的基线遗产）
- 新增 bench 必须带 `--baseline` 命名约定（避免命名冲突）
- bench 文件不写集成测试（用 `tests/` 而非 benches/）
