# tools/ — 性能/调试/工具脚本

> 跨 crate 的工具脚本集中地（非 cargo 内的辅助）
> PM 工单：30 条前瞻性债的工程化钩（性能 baseline / 依赖图 / ADR 等）放这里

## 用途

| 类别 | 脚本 | 用途 |
|---|---|---|
| 性能 | `loopback_alloc_bench.py` | alloc/MB + loopback 吞吐基线采样（DEBT-023 钩子）|
| 性能 | `pgo_workload.py` | PGO 训练数据（profile 优化）|
| 依赖 | `check_stress_leak.py` | 压测泄漏检查（s9/s10 战役工具）|
| 构建 | `inject_btls_cache.py` / `inject_btls_post_handshake.py` | btls-sys 冷编产物注入（绕 OMP 冷编坑）|
| 构建 | `setup_boringssl_reality.py` | REALITY 符号打补丁（5 符号）|
| 调试 | `xhttp_strace.sh` / `xhttp_tcpctl.sh` / `xhttp_tcpnotls.sh` | xhttp 协议族调试钩子|

## 归档目录

- `tools/logs/` — 临时调试 log 归档（之前散在根的 3 个 log 已移过来）
- 清理策略：每次战役结束清理过期 log（建议保留最近 30 天）

## 用法示例

```bash
# alloc/MB baseline
python tools/loopback_alloc_bench.py --tag my-feature --xray target/release/xray.exe --runs 3

# btls-sys 冷编产物注入（CI 跑冷 worktree 必做）
python tools/inject_btls_cache.py

# 压测泄漏
python tools/check_stress_leak.py
```

## 新增脚本规范

- 脚本顶部必须 shebang + 描述（目的/输入/输出/退出码）
- 用 argparse 不用 sys.argv
- 错误用 sys.exit(N) 而非 raise（便于 PM 工具链调用）
- 不修改红线资产（dist/vendor/.github/workflows/ARCHITECTURE.md）
