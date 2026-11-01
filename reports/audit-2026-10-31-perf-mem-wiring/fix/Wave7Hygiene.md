VERDICT: NEEDS-ATTENTION
（首要风险：`.gitignore` 只忽略 `/target`，`target-Wave7*` 兄弟目录（合计 ~40GB，5.1 万个
文件）处于 `??` 未跟踪态——PM 若 `git add -A` / `git add .` 会把构建产物整库吞进索引。
其次：8 个未跟踪的新源码/测试文件**必须** `git add`，否则提交后他机编译必红（模块/测试
文件缺失）；reports/ 已 1.5GB，内含 3 个 200MB+ 的 big.bin 与 5 个 ~50MB 的 .exe。行尾
检查通过：全部改动 .rs 文件 CRLF=0。）

数据基线：`git status --porcelain` 共 248 项（65 个已跟踪改动 + 8 个未跟踪源码/测试 +
`dist/tmp_udp_tunnel/` + `target-Wave7Hyst/` + `target-Wave7Verify/` + 大量 reports 未跟踪）。
磁盘余量 219G（489G 总量，56% 已用）。

## §1 改动文件分类表（已跟踪改动，按归属票）

**源码改动（.rs）**——归属按文件内 `bd <id>` 注释判定：

| 文件 | 归属票（主要 bd 标记） | 备注 |
|---|---|---|
| crates/xray-app-commander/src/grpc.rs | 9c8k6 / o1a9p | 动态配置/规则面 |
| crates/xray-app-dispatcher/src/default.rs | 4a1zy / s6h2j / 9c8k6 | 指标 tag 门 + 动态规则 |
| crates/xray-app-dispatcher/src/udp_session.rs | **lppdz** / kol4a / tini5 / 1fm1l | slice-parse + access 通道 |
| crates/xray-app-metrics/src/{feature,lib,metrics,outbound}.rs + Cargo.toml | 0z7zt / 3xmjx（Wave7Metrics） | 指标 tag_mode |
| crates/xray-app-router/src/{command/mod,router}.rs | 9c8k6 / il49 | 动态规则 API |
| crates/xray-cli/src/commands/{api_args,api_exec}.rs | 归属不明 / 9c8k6 / c89uy | api 子命令面 |
| crates/xray-core/src/arm_builders/inbound.rs | ctiwx（hysteria 用户管理器）+ zb2ee 解阻塞（import/clone，见 Wave7QuicIn §6） | ⚠ 混多票 |
| crates/xray-core/src/functions.rs | lu37q / jezb / 39hko + lppdz 回归测试 | ⚠ 混多票 |
| crates/xray-core/src/inbound.rs | hl8q6 / lfrg / ctiwx / **zb2ee（白名单 +quic）** | ⚠ 混多票（本波已知） |
| crates/xray-core/src/lib.rs | 75rv / c89uy / nip4p | lib 导出面 |
| crates/xray-core/src/outbound.rs | **kol4a**（cone 白名单）/ 4jyhm / jwg8y / o91s4 | ⚠ 混多票 |
| crates/xray-frame/src/{deadline,scope}.rs + tests/deadline_budget.rs | 23vrp / 86i4h / il9lh | 框架时限/scope |
| crates/xray-mux/src/worker.rs | **kol4a**（XUDP hit 打点）/ zv9l / lahx | cone 观测点 |
| crates/xray-proxy-anytls/src/{server,uot}.rs | 86i4h / 23vrp / 33ll3 | AnyTLS |
| crates/xray-proxy-freedom/src/udp.rs | **lppdz** / 1fm1l / 1ksxu / 2yj2 | UDP 数据面 |
| crates/xray-proxy-http/src/server.rs + tests/http_proxy_e2e.rs | t3lzr / y5cy9 / 0snlt | HTTP/1xx |
| crates/xray-proxy-hysteria/src/{config,inbound}.rs | ctiwx（hysteria 用户管理器） | 用户热更 |
| crates/xray-proxy-socks/src/{relay,server,udp}.rs | **kol4a** / hzjgv / dp2dm / jzre9 / lppdz / 1fm1l | socks UDP 源 + cone |
| crates/xray-proxy-tuic/src/{client,protocol/*,server,udp}.rs | j7de2 / t975 / wp9o / 8cry | TUIC 面 |
| crates/xray-proxy-tun/src/inbound.rs | **kol4a**（tun fd 接线）/ ipb5 | tun access |
| crates/xray-transport-grpc/src/* | enc8x / s8eio / dppv | grpc 窗口/池 |
| crates/xray-transport-hysteria/{Cargo.toml,hub,lib,quinn_adapter}.rs | 4zcki / ctiwx / x8vsd | hysteria 用户面 |
| crates/xray-transport-splithttp/src/*（9 文件）+ tests/*（4 文件） | s42cg / wz2b / dppv / g3cr | splithttp 重构+测试 |
| crates/xray-transport-websocket/src/* | s8eio / cqyj / lmjw / il9lh（Wave7WsWin/池） | ws 池 |
| crates/xray-xudp/src/packet.rs | **lppdz** / 1fm1l / zu7tk | slice-parse + 写侧 |

**配置改动**：`Cargo.lock`（随源码联动）；`crates/xray-app-metrics/Cargo.toml`、
`crates/xray-transport-hysteria/Cargo.toml`（同票联动）。根 `Cargo.toml` 无改动。

**报告与文档**：`reports/**` 大量未跟踪（见 §2/§4）；`docs/**` 被 `.gitignore` 的 `docs/*`
规则忽略（带 `!docs/refs/`、`!docs/benchmarks/`、`!docs/audit-*.md` 例外），无改动外泄。

## §2 未跟踪文件三档清单

**建议纳入（必须 git add，否则他机编译红）**——8 个新源码/测试文件：
- `crates/xray-core/src/account.rs`（被 inbound.rs 引用的模块拆分件）
- `crates/xray-transport-hysteria/src/masq_proxy.rs`
- `crates/xray-app-metrics/tests/tag_mode_e2e.rs`、`crates/xray-proxy-hysteria/tests/users_e2e.rs`、
  `crates/xray-proxy-tuic/tests/third_party_udp.rs`、`crates/xray-transport-splithttp/tests/xmux_reuse.rs`、
  `crates/xray-transport-websocket/tests/pool_default_off.rs`、`crates/xray-transport-quic/tests/`（目录）

**建议忽略（先加 .gitignore 再提交）**：
- `target-Wave7Hyst/`（32G）、`target-Wave7Verify/`（7.9G）——两个在用代理的构建目录。
  **建议 .gitignore 增加 `target-*/`**（防 `git add -A` 事故；等两代理收尾后再物理删除）。
- `reports/audit-2026-10-31-perf-mem-wiring/fix/tmp/`（内含 big.bin 210MB + 3 个 ~50MB exe）、
  `reports/audit-2026-10-29/tmp/`、`reports/framework-audit-2026-10-24/tmp/`、
  `reports/audit-2026-10-26/tmp/`——各票的抓包/二进制 scratch。建议 `.gitignore` 加
  `reports/**/tmp/`（或提交时手工排除），大文件去留交 PM。
- `dist/tmp_udp_tunnel/`（互通 harness 的 json 输出，~26MB 小文件 ×几百）——建议忽略或只收
  `*_29090.json` 结论文件。
- `reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/__pycache__/`——已被全局 `__pycache__/`
  规则覆盖？实测仍在 `??` 列表 ⇒ 规则只匹配根级；建议改 `**/__pycache__/` 或提交时排除。

**建议删除（本机 scratch，与 git 无关）**：
- `D:/tmp/wave7_quic/`、`D:/tmp/wave7_cone*`（我票的探针 scratch，已用完）；
- 各 `target-Wave7*` 孤儿目录（见 §5）在对应代理收尾后物理删除。

## §3 行尾（CRLF）检查 —— 通过

- `git diff --numstat` 最大值：`xray-xudp/src/packet.rs 599/11`、`inbound.rs 582/9`、
  `outbound.rs 412/30`……全部为**真实内容改动量级**，无整文件重写（zb2ee 那次 CRLF 事故
  的 2.6 万行形态未复现——当时已当场归一回 LF，见 Wave7QuicIn.md §6）。
- 逐文件字节级扫描：65 个改动 `.rs` 全部 `CRLF=0`。**无 CRLF 污染残留**。

## §4 大文件 / 异常体积

- `reports/` 未跟踪总量 **1.5GB / 5004 个文件**。异常大件：
  - `reports/audit-2026-10-29/tmp/hhlnfdig/big/big.bin` **268MB**
  - `reports/framework-audit-2026-10-24/tmp/big.bin` **210MB**
  - `reports/audit-2026-10-31-perf-mem-wiring/fix/tmp/big.bin` **210MB**
  - `reports/audit-2026-10-31-perf-mem-wiring/fix/tmp/{wave7-dl-after,wave7-h3-after,wave7-before}.exe`
    3 × ~50MB
  - `reports/audit-2026-10-29/tmp/HystFix/bin/{xray-fixed,xray-before}.exe` 2 × 50MB
  - ⇒ 8 个文件 ≈ **0.9GB**，全是抓包/二进制 scratch，建议 git 排除（见 §2 忽略档）。
- `dist/tmp_udp_tunnel/`：~26MB json（互通 harness 输出），无 exe。
- 仓库根：无意外 `*.md`/`*.txt`（`*.log` 全局忽略，status 中 0 个 log）。

## §5 target 目录与磁盘

| 目录 | 大小 | 状态 |
|---|---|---|
| `target/`（根） | 未计入（被 `/target` 忽略，不在 status） | 共享历史目录，多代理复用 |
| `target-Wave7Hyst/` | **32G** | **在用**（Hyst 代理，未收尾） |
| `target-Wave7Verify/` | **7.9G** | **在用**（Verify 代理，未收尾） |
| `target-Wave7QuicIn/` `target-Wave7Cone*` `target-Wave7Slice*` `target-Wave7Mux*` 等 | 已不存在 | 本波已按契约自删（zb2ee/lppdz/kol4a/Mux 票均已删） |

磁盘余量：**219G 可用 / 489G**（56% 已用）——无紧迫风险，但 Hyst 的 32G 若继续增量值得盯。

## §6 报告完整性

`reports/audit-2026-10-31-perf-mem-wiring/fix/` 下本波报告 48 份（Wave7*.md 33 份 +
G1-G11/P0/Wave5-Wave6/汇总 15 份），含本波各票：Wave7Udp（1fm1l+lppdz）、Wave7Cone（kol4a）、
Wave7QuicIn（zb2ee）、Wave7Mobile（ifnl9）、Wave7Input/Wave7Dns/Wave7HystUsers/Wave7Metrics/
Wave7WsWin/Wave7Xmux/Wave7Tuic/Wave7Pool/Wave7Masq/Wave7User/Wave7Um/Wave7Dyn/Wave7Timer/
Wave7Lsr/Wave7Massif/Wave7Rtt/Wave7Dl/Wave7H3/Wave7AnyTls/Wave7Cdn/Wave7Mux/Wave7Quic/
Wave7Verify 均在。
- 老票 `dp2dm` `uwq9n` `y5cy9` `0snlt` `il9lh`：**无独立报告文件**；在 `SUMMARY.md`、
  `Wave7Input.md`、`Wave7Dns.md`、`GROUPS.md` 中有提及（旧票合并进相应 Wave7 报告）——
  按 PM 口径「老票可能无报告」判定为**符合预期**。
- 项目外落盘检查：本波报告全部在仓内 `reports/**`；仅探针 scratch 写过 `D:/tmp/`
  （wave7_quic 等，已列删除档），**无报告内容滞留项目外**。

## §7 提交前必办事项（按严重度排序）

1. **[高] 防误吞 40GB 构建产物**：`.gitignore` 增加一行 `target-*/`（当前只忽略 `/target`，
   `target-Wave7Hyst`/`target-Wave7Verify` 的 5.1 万个文件全在 `??` 态）。**在 `git add` 之前做**。
2. **[高] 显式 `git add` 8 个新源码/测试文件**（§2 纳入档；尤其 `crates/xray-core/src/account.rs`
   与 `crates/xray-transport-hysteria/src/masq_proxy.rs`——被已跟踪文件 `mod`/`use` 引用，
   漏掉即他机编译红）。不要用 `git add -A`。
3. **[中] 排除 reports 大件**：提交时排除 `reports/**/tmp/`（3 个 big.bin ≈ 690MB + 5 个 exe
   ≈ 250MB）与 `scripts/__pycache__/`；或先补 `reports/**/tmp/` 忽略规则。
4. **[中] `dist/tmp_udp_tunnel/`**：建议忽略；若要留证据，只收 `cone_reuse.json` /
   `interop_udp_tunnel.json` 两个结论文件。
5. **[低] `reports/_archive/`、`reports/parity/` 等历史未跟踪目录**：内容为既往战役文档，
   由 PM 决定随本波一起入库或另批处理（非本波新增，不阻塞）。
6. **[提示] 提交粒度**：65 个改动文件混 18+ 张票（本波已知混票热点：
   `inbound.rs`/`outbound.rs`/`functions.rs`/`arm_builders/inbound.rs` 各含 ≥3 票改动）。
   若按票拆 commit，需按 §1 归属表手工分 hunk；若整波一个 commit，建议 commit message
   列票号清单（数据源 = 本报告 §1）。
