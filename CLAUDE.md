# CLAUDE.md — Xray-core-rust 项目指南

> **给 OMP/AI 子代理 + 人类贡献者的"5 分钟上手"**
> **优先级**：本文件覆盖**全局** `AGENTS.md`（`C:\Users\Begonia\.omp\agent\AGENTS.md`）的本项目规则
> **必读对象**：所有 PM/子代理派单、新协作者、审计师

---

## 0. 项目一句话

**Xray-core-rust** = Go Xray-core v26.9.9 Rust 复刻，私有仓 `github.com/Be90nia/xray-core-rust`，master `87d72569`，CI 9 绿，32/32 协议全通，7 万行 Rust，20+ crate。

---

## 1. 5 分钟上手

```bash
# 1. 构建（btls-sys 冷编坑——见 §6 踩坑；PROTOC/LIBCLANG 缺任一即构建/测试链挂）
cmd /c "set BORING_BSSL_ASSUME_PATCHED=1&& set BORING_BSSL_SOURCE_PATH=D:\Project\Xray-core-rust\target\boringssl-patched&& set PROTOC=D:/Project/tools/bin/protoc.exe&& set LIBCLANG_PATH=D:\Program Files\llvm\bin&& cargo build --release -p xray-cli"

# 2. 测试（CI 9 宽门镜像）
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo doc --workspace --no-deps

# 3. 跑
./target/release/xray.exe run -c <config.json>
```

**工作流（高频用）**：
- `python tools/loopback_alloc_bench.py --tag <feature> --xray target/release/xray.exe --runs 3` —— 性能 baseline
- `cmd /c "set BORING_BSSL_ASSUME_PATCHED=1 && set BORING_BSSL_SOURCE_PATH=... && python tools/inject_btls_cache.py"` —— btls 冷编注入
- `bd create --title "..." --priority N --label audit` —— 新建 bd 票（前置 `export BD_IGNORE_SCHEMA_SKEW=1`）

---

## 2. 当前状态（2026-10-12 立项级审计后）

| 维度 | 评分 | 报告 |
|---|---|---|
| 架构 | 3.8/5 | `docs/audit-架构-2026-10-12.md` |
| 性能 | 3.6/5 | `docs/audit-性能-2026-10-12.md` |
| 安全 | 3.4/5 | `docs/audit-安全-2026-10-12.md` |
| 规范（3 维合一）| 3.3/5 | `docs/audit-规范-2026-10-12.md` |
| 9 票架构审视（专项）| 4.3/5 | `D:/tmp/audit-bd-arch-report.md` |
| **综合** | **3.5/5** | `docs/audit-立项级别-2026-10-12.md` **GO-WITH-CONDITIONS** |

**9 open bd 票**（15 票里 1 根 + 7 独立可做 + 3 框架依赖 + 6 前瞻债）：
- 根票：`6su8` epic(framework) 五阶段立项
- 独立可做 5 张：`2ktp` M2 / `fzir` M1 / `75rv` M6 / `sf5b` M7 / `syvm` tls-fork
- 框架依赖 3 张：`mc11` M3 / `akqh` M4 / `8pne` M5
- 前瞻债：`9h06` prereq-debt / `w20a` runtime-debt / `0jnp` longterm-debt / 3 张规划项承接

---

## 3. 文档地图

| 文档 | 用途 |
|---|---|
| **`ARCHITECTURE.md`（在 `docs/`）** | **治理宪法**——MVVM 五层 + 八条原则 + 五阶段映射（必读）|
| **`docs/refs/`** | 治理输入（v1/v2/v3 裁决 + alloc-audit 报告）——**红线** |
| **`docs/benchmarks/baseline.md`** | 性能 baseline（loopback 154-167 MB/s + alloc/MB 2.15/2.22）|
| **`docs/audit-*.md`** | 5 维审计 6 份 + 综合 + 立项级 |
| **`D:/tmp/audit-*.md`** | PM 工具链产物（审计上下文 + 9 票审视 + 框架前瞻债 v1/v2）|
| **`bd list --status open`** | 当前活跃票面（label=audit/framework/standards 等）|

---

## 4. 红线清单（**绝对不动**）

| 红线 | 备注 |
|---|---|
| `dist/xray.exe` | baseline 二进制 |
| `xray-transport-tcp/register.rs` | 已知债（4 维不动）|
| `vendor/` | quinn-proto patch |
| `tests/`、`.github/workflows/`、`.gitignore`、根 `cargo*` 配置 | 验证资产 |
| `docs/refs/` | 治理裁决（v1/v2/v3 + alloc-audit）|
| `docs/ARCHITECTURE.md`（**新位置**：从根移来）| 治理宪法 |
| `protos/` | Go proto 镜像——**只读** |
| `cloudflared` 配置 + cert / sing-box 二进制 | 用户自管红线 |
| `feature/framework` 分支起点 `f242e67b` | 框架资产**先验证再合 master**（d820547f 教训）|

**13 红线来源**：`docs/audit-架构-2026-10-12.md` §13.1

---

## 5. 已知踩坑（必须知道）

### btls-sys 冷编（5-10 min 全量重编）
- **症状**：build/main.rs:646 run() 静默早退 + bindings.rs 缺失
- **解决**：`BORING_BSSL_ASSUME_PATCHED=1` + `BORING_BSSL_SOURCE_PATH=D:/Project/Xray-core-rust/target/boringssl-patched`（**指向已打补丁树**，非主仓 out/boringssl）
- **共享**：`python tools/inject_btls_cache.py`（CI CMakeCache 注入）

### vision splice 触发逻辑（雷区）
- **历史**：d8562b56 + a427613b 双 revert
- **禁**：池化改造**不碰** vision gate/DIRECT 切换
- **池化方式**：caller-scratch + padding_scratch mem::take 容量流转（已 commit 7681f7cc）

### framework merge 摩擦（d820547f 教训）
- **症状**：poll 化全仓重编 4 轮 CI 红
- **预防**：缺**渐进开关** `#[cfg(feature = "framework-poll")]` + 缺**小步合入粒度拆分**
- **修复方向**：见 `D:/tmp/framework-tech-debt-2026-10-12.md`（v1+v2 共 30 条债）

### 整数边界（7 处 u16 截断已识）
- **VMess chunk size u16 截断静默替换 u16::MAX**——M2 onv9 短期 sync 含此条

### tcping window 钉窗（88m0 战役）
- **症状**：吞吐 = 64KB / RTT
- **修复**：TCP SO_RCVBUF 4MB 缺省（已落地 bd 88m0 + 3e755458）

### h2 窗钉（enc8x 战役）
- **症状**：hyper 默认 send_buf 400KB → min(4MB, 4MB)/0.45s ≈ 8.8 Mbps
- **修复**：客户端流窗 16MB + 服务端 send_buf 16MB

---

## 6. OMP 偏好（用户多会话重申）

| 偏好 | 出处 | 应用 |
|---|---|---|
| **"log 经常功能要调用..应该写到框架里面"** | 5 维审计 9 票审视 D1 多源验证 | 5 维报告 P1-001 + 5 维规范 P1-001 → 6su8 P3 log facade |
| **诚实交付不注水** | PM 工作流 | 子代理报告"完成"必须可验证 |
| **审计 5 维自评** | 5 维审计模板 | 所有 specialist 报告结尾必带 5 维自评 |
| **Ponytail 模式只出报告** | 5 维审计红线 | 子代理不实施修复，由 fullstack 执行 |
| **CLAUDE.md/AGENTS.md 优先于全局** | 5 维盲区债 DEBT-028 | 派单任务书必带 CLAUDE.md 路径 |
| **跨会话引用基础设施 IP 以 MEMORY.md 为准** | 5 维盲区教训 | 不信压缩摘要里的 IP 字面值 |
| **kill -9 失败先杀子进程再父进程** | 5 维盲区教训 | bash 工具的 OMP 拦截经验 |

---

## 7. 派单约定（PM 工作流）

- **3 并行上限**（实测高并发曾互斥崩盘+拖垮机器）→ 滚动补位
- **任务书 7-part contract**：目标 / 上下文 / 验收 / 非目标 / 调研源 / 目标环境 / 输出格式
- **只派自家 specialist**：architect / performance-reviewer / security-reviewer / reviewer / debugger / e2e-runner / docs-writer / test-engineer / tdd-guide / metis / momus / oracle / librarian
- **禁派** scout / fullstack-engineer 做审计
- **Ponytail 模式**：只出报告不修代码（红线外可建议改，**不实施**）
- **红线条目**（§4）= 触动一次 = 派回原 agent + 全报告重审

---

## 8. bd 票面约定

```bash
# 必用 prefix
export BD_IGNORE_SCHEMA_SKEW=1   # db v65 领先 binary v53

# 常用命令
bd list --status open
bd create --title "..." --priority N --label "audit,framework,perf,security,standards" --description "..."
bd close <id> --force  # 遇到 blocks 关系
bd update <id> --append-notes "..."  # 追加，不删历史
```

**当前标签**：`audit` / `framework` / `perf` / `security` / `standards` / `debt` / `gap` / `evaluation` / `supply-chain` / `sync`

---

## 9. 文档同步策略

- 每次新裁决（v4/v5）→ `docs/refs/` + `docs/ARCHITECTURE.md` 同步双更新
- 每次审计 → `docs/audit-*.md` 落档 + `bd update <id> --append-notes`
- 每次 commit → `git log --oneline` 简短，不写废文
- 5 维+9 票+立项级 3 份大报告**未 commit**（per 5 维审计 §14.2）—— 待 PM 评审后批量 commit

---

## 10. 给未来协作者的最快路径

1. **读完本文**（10 min）
2. **读 `docs/ARCHITECTURE.md` §0.1 三层隐喻**（30 min）—— 宪法骨架
3. **读 `docs/refs/oracle-framing-v3.md`**（1h）—— MVVM 增补裁决
4. **读 `docs/audit-立项级别-2026-10-12.md`**（30 min）—— 立项决议
5. **跑 §1 上手命令**（5 min）
6. **看 `bd list --status open`**（5 min）—— 当前在飞

总计 ~2.5 小时达到"理解项目 + 能上手"。

---

**CLAUDE.md 优先于全局 AGENTS.md 在本项目的规则**

— PM 维护，下次更新：立项级审计后任何状态变化（master commit / 5 维重审 / bd 重大决议）
