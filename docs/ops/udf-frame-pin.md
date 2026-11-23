# udf-frame revision 钉死与更新流程（issue #68，2026-11-18）

## 模型一览

| 面 | 机制 | 阻断性 |
|---|---|---|
| required CI / release 消费 | pin 文件 `.github/udf-frame.rev`（单行 40-hex 全 SHA）；`fetch-udf` action fetch 该 SHA + 硬校验 `rev-parse HEAD == pin`，缺失/坏格式/不等一律 fail-closed | 阻断（失败即红） |
| 锚校验 | `crates/xray-conf/tests/udf_rev_anchor.rs` 比对工作副本 HEAD vs pin；CI 与本地同源真校验（收口 bd yyoy9 的 CI-SKIP） | 阻断（测试即红） |
| main 最新测试 | `.github/workflows/udf-canary.yml`：每日 cron + 手动，拉 main 最新跑 `cargo test --manifest-path crates/udf-frame/Cargo.toml --workspace --lib --tests`（不含 doctest，理由见 workflow 内注） | **非阻断**（`continue-on-error`，红不拉红 required CI） |

缓存键接口不变：rust-cache 的 `key` 注入 `UDF_HEAD`（= pin），两个不同 pin 的 run
天然各自成缓存空间。

> 历史依据：bd jyjko（锚测试立票）→ bd yyoy9（CI 侧 SKIP 缺口，本改动收口）→
> bd ym69a（三层本地子集闸，随 issue #68 移除 fail-open，职责移交 canary）。

## pin 更新流程（人工，走 PR——唯一的 pin 前进通道）

1. **候选验证（fail-closed 口径）**：候选 commit 的上游 check-runs 必须**全部完成且无红**——
   pending / 缺失 / 坏数据 / 限流一律**不得视为绿**（issue #68 acceptance）：

   ```bash
   gh api repos/Be90nia/udf-frame/commits/<候选SHA>/check-runs \
     --jq 'if (.total_count // 0) == 0 then "FAIL: 无 check-run 记录（不得视为绿）"
           elif ([.check_runs[] | select(.conclusion == null)] | length) > 0 then "FAIL: 有 pending check"
           elif ([.check_runs[] | select(.conclusion != "success" and .conclusion != "skipped" and .conclusion != "neutral")] | length) > 0 then "FAIL: 有红项（见 udf-frame/actions）"
           else "PASS" end'
   ```

   交叉对照 <https://github.com/Be90nia/udf-frame/actions> 与本仓 `udf-canary` 最新 run。

   **main 头有红时的候选选取**（2026-11-23 实例补充）：上游自身 CI 坏掉时，main 头
   check-runs 必红 ⇒ 不得升 main 头。取 main 上**最后一个自身 push CI 全绿**的
   commit 作候选（按 `gh api "repos/Be90nia/udf-frame/actions/runs" --jq
   '.workflow_runs[] | select(.name=="udf-frame CI") | "\(.head_sha[0:7]) \(.conclusion)"'`
   倒查），候选本身仍须过上面那条 fail-closed 查询。实例：main 头 902c265 全红
   ⇒ 候选 0d9a7cd（最后一个全绿 push）。**禁**用「本地 udf 子集测试绿」替代上游
   全绿（见下方明确禁止）。

2. **换本地工作副本**：

   ```bash
   git -C crates/udf-frame fetch origin
   git -C crates/udf-frame checkout --detach <候选SHA>
   ```

3. **更新 pin**（一行全 SHA，LF）：

   ```bash
   git -C crates/udf-frame rev-parse HEAD > .github/udf-frame.rev
   ```

4. **本地锚测试 + 全门**（四环境变量见 CLAUDE.md §1）：

   ```bash
   cargo test -p xray-conf udf_rev_anchor        # 锚：HEAD == pin
   cargo test --workspace --all-targets
   cargo clippy --workspace --all-targets -- -D warnings
   cargo fmt --all -- --check
   cargo doc --workspace --no-deps
   ```

5. **PR**：diff 必须只动 `.github/udf-frame.rev` 一行；Xray 自身 required CI 全绿后合入
   （issue #68：「候选 pin 上游全绿 + 本仓全绿」双闸后才被接受）。

## CI summary 里在哪看

| 项 | 位置 |
|---|---|
| **pinned SHA** | 任意 required job 的 `Fetch udf-frame at pinned revision` step summary（标题 `### udf-frame 拉料（pinned，issue #68）`，每个 job 都有） |
| **canary SHA + 红绿判定** | `udf-canary` workflow 的 `Summary (verdict + SHA)` step（GitHub → Actions → udf-canary → 最新 run），同一 summary 里附 pinned SHA 对照 |

## 明确禁止

- 回退消费移动 `main`（required CI 的 `git clone main` 已移除，不得复活）
- 把 canary 加进 branch protection required 列表（它 `continue-on-error`，加了也拦不住）
- 用本地 udf 子集测试替代「上游全绿」作为改 pin 依据（fail-open 已移除）
