VERDICT: PASS

# Wave5Rtt — 撤除 h2 send_buf 的 RTT 阶梯（CDN 场景误缩导致吞吐被钉）

分支 `feature/fix-inbound-parity`（基 HEAD `707cd30e`），改动范围：`crates/xray-transport-splithttp`（仅本 crate，6 文件，+103 / -122）。

## 1. 定位证据

物理关系：单流吞吐 ≤ **min(对端收窗, 本端 send_buf) / RTT**，此处 RTT 是**数据路径端到端 RTT**。

- `33bacd22`（bd rjzw2，2026-10-29）在 `flow_window.rs` 引入阶梯：`tier_send_buf(rtt)` → `<40ms` → 8MB、`40-99ms` → 12MB、`≥100ms`/None → 不缩（16MB），结果写进 `max_send_buf`。
- 客户端探针 `probe_rtt(host, port)` 只对 `dial_target` 建一条一次性 TCP 连接计时 ⇒ 测到的是**本机 → host** 这一段的 RTT。生产 xhttp 入站走 CDN（入站证书 `cdn_us1.begonia92.top`，`mode=packet-up`）时，这一段 ≈ **CDN 边缘 RTT ~30ms**；真实数据路径（客户端 → CDN → 美国源站）端到端 RTT ≈ 200ms。
- 于是 send_buf 落 8MB 档，吞吐上限 = 8MB / 0.2s ≈ **40 MB/s**，与实测 35 MB/s（历史 50-60）物理吻合。
- 同一提交里的 `TCP_NOTSENT_LOWAT` 已由 `dbdfc83d` revert，但**阶梯本身没被撤**——本票处理的就是它。
- 反向确认：Go 侧没有「按 RTT 缩 send_buf」的机制（Go xray 的 h2 发送缓冲恒为静态值），用户已拍板「对齐 Go」。
- 本机 loopback 测不出该问题（RTT≈0 → BDP 极小，8MB 与 16MB 都够用），所以修复只能靠单测 + 用户真机验证，见 §5/§6。

## 2. 选了哪条修法及理由

**修法 1：直接对齐 Go——删掉 send_buf 的 RTT 阶梯，`max_send_buf` 恒等于各端静态保底 16MiB。**

理由：修法 2（只在「能确认直连」时缩）需要对端拓扑知识，而探针拿不到——同一个低 RTT 观测既可能是低延迟直连，也可能是高延迟链路的薄边缘；客户端无法区分 CDN/前置中转/隧道。判据不存在 ⇒ 该优化**没有可判定的适用范围**，「保守缩窗」写不出可执行的判据，只能是「猜」。故整条阶梯删除，保留静态保底 = Go 行为。

代码面（`src/flow_window.rs`）：

- 删除 `RTT_TIER_FAST_MS` / `RTT_TIER_MID_MS` / `TIER_FAST_SEND_BUF` / `TIER_MID_SEND_BUF` / `tier_send_buf`（无残留、无死代码、无「仅测试辅助」残留）。
- `windows_for()` 不再按 RTT 改 `max_send_buf`；现在**唯一**能改动窗值的路径是诊断 env 覆盖（`XRAY_H2_FLOW_WINDOW_OVERRIDE_BYTES` / `XRAY_H2_SEND_BUF_OVERRIDE_BYTES`）。
- `client_windows_from_rtt` / `server_windows_from_rtt` 签名不变（调用方 `client.rs` / `dialer.rs` / `transport.rs` / `hub.rs` 零改动），`rtt` 参数降级为**日志标签**（`h2_adaptive_window rtt_ms=`），`XRAY_H2_RTT_HINT_MS` 保留：仍优先于探针、仍省掉一次探测握手，只是不再影响任何窗值。
- 头部注释重写：写明「为什么不再按 RTT 缩 send_buf」，引用本次定位（CDN 边缘 RTT ≠ 端到端 RTT；吞吐 = send_buf / 端到端 RTT ⇒ 8MB/0.2s ≈ 40MB/s）。
- 顺手修掉 6 处因本次改动而失真的既有注释（`client.rs` / `dialer.rs` / `transport.rs` ×4 / `register.rs` / `hub.rs`），把它们从「按 RTT 阶梯驱动」改为「静态保底，rtt 只进日志」——注释与行为同步，无代码面变化。

**未动（红线）**：流窗/连窗静态值（客户端 32MB/32MB、服务端 16MB/32MB）、`H2_MAX_CONCURRENT_STREAMS`、`transport.rs` 的 `max_concurrent_streams` 接线、TCP_NOTSENT_LOWAT（保持删除状态）。

## 3. 单测改动

`src/flow_window.rs::tests`

| 测试 | 变化 |
|---|---|
| `ladder_locks_send_buf_per_rtt` | **删除**（逐值锁阶梯，语义已不存在） |
| `low_rtt_tier_shrinks_only_send_buf` | **删除**（同上） |
| `send_buf_is_rtt_independent` | **新增**：遍历 `None / 1 / 20 / 39 / 40 / 80 / 99 / 100 / 240ms / 5s`，断言客户端与服务端 `max_send_buf == 16MiB` **且整组窗 == 各自 FALLBACK** —— 这就是「任意 RTT 下 send_buf == 16MB」的钉子 |
| `tiers_keep_flow_windows_at_role_static` | 改名 `flow_windows_do_not_follow_rtt`，断言保留（32/32MB 客户端、16/32MB 服务端，不随 RTT 变） |
| `client_fallback_equals_pre_rjzw2_static` / `server_fallback_equals_pre_rjzw2_static` | **保留原样**（含 `client_windows_from_rtt(None) == CLIENT_FALLBACK`、`server_windows_from_rtt(None) == SERVER_FALLBACK`） |
| `rtt_hint_parse_bounds` / `rtt_hint_wins_over_probed` / `overrides_apply_flow_then_send` / `env_override_parse_bounds` / `probe_rtt_*` | 保留（env 与探针语义未变，只是下游不再缩窗） |

`src/client.rs::tests`

| 测试 | 变化 |
|---|---|
| `h2_adaptive_windows_tier_by_rtt`（断言 8MB/12MB 档） | 改为 `h2_windows_do_not_follow_rtt`：`None` + `1/20/39/40/80/99/100/200ms` 全档断言 `max_send_buf == 16MiB`、`stream_window == 32MB`、整组 == `CLIENT_FALLBACK` |

## 4. 反证输出（把阶梯临时改回去 → 测试变红）

临时在 `windows_for()` 加回 `if eff < 40ms { w.max_send_buf = 8MB }` 后：

```
running 1 test
test flow_window::tests::send_buf_is_rtt_independent ... FAILED

---- flow_window::tests::send_buf_is_rtt_independent stdout ----

thread ... panicked at crates\xray-transport-splithttp\src\flow_window.rs:224:13:
assertion `left == right` failed: 客户端 send_buf 随 RTT 变（rtt=Some(1ms)）
  left: 8388608
 right: 16777216

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 266 filtered out
error: test failed, to rerun pass `-p xray-transport-splithttp --lib`
```

撤掉临时补丁后该测试恢复绿（见 §5 第 1 条）。测试确实咬住这次回归。

## 5. 验证记录

1. `cargo test -p xray-transport-splithttp --lib flow_window` → **10 passed / 0 failed**（含 `send_buf_is_rtt_independent`、`flow_windows_do_not_follow_rtt`、两个 fallback 测试）。
2. `cargo clippy -p xray-transport-splithttp --all-targets -- -D warnings` → `Finished dev profile ... in 20.15s`，**零告警**。
2b. `cargo fmt -p xray-transport-splithttp -- --check` → **FMT CLEAN**（先 `cargo fmt` 落定纯排版改动，随后 lib 测试与 clippy 复跑仍全绿：10 passed / 零告警）。
3. `cargo test -p xray-transport-splithttp --all-targets --no-fail-fast` →
   - `src/lib.rs`：**266 passed / 1 failed** — 唯一失败 = `transport::tests::h3_server_receives_stream_one`（**既有已知红**，`no server certificate chain resolved`，与本票无关）
   - `tests/hub_limits.rs` 4 passed；`tests/mock_h3_server.rs` 1 passed；`tests/mock_server.rs` 12 passed；`tests/reality_integration.rs` 1 passed；`tests/stream_h2.rs` 2 passed
4. loopback 不退化（release 二进制由本票改动独立构建于 `target-Wave5Rtt/release/xray.exe`，未覆盖 `target/release`）：

```
$ python tools/loopback_alloc_bench.py --tag rttfix \
    --xray target-Wave5Rtt/release/xray.exe --runs 2 --floor 0
[via-enc-chain] #1: speed=151054858.0 B/s (151.1 MB/s) size=209715200 time=1.388399s
[via-enc-chain] #2: speed=167620630.0 B/s (167.6 MB/s) size=209715200 time=1.251186s
transferred=419430400 bytes (400.0 MiB)
floor check: best=167.6 MB/s vs floor=0.0 MB/s
```

best **167.6 MB/s**（验收线 ≥115，历史基线 ~120-126）——无退化，且比带阶梯时更快（loopback RTT≈0，16MB send_buf 不再限制在飞字节）。注：该二进制在同一份代码上构建于 fmt 之前（fmt 只改排版/注释换行，语义逐字节等价），故数字有效。

## 6. 用户可验证步骤（真机 CDN 场景）

**A. 先复现元凶（旧行为可解释）** —— 服务端与客户端**都**设 `XRAY_H2_RTT_HINT_MS=200` 重启：

- 该 env ≥100ms ⇒ 旧阶梯不缩 ⇒ `max_send_buf` = 16MB ⇒ 若上行吞吐回到 **50-60 MB/s**，即确认「按边缘 RTT 裁 send_buf」就是 35MB/s 天花板的元凶（日志 `h2_adaptive_window role=client rtt_ms=200 ... send=16777216` 可直接佐证）。
- 反向对照：把该 env 设成 `20` 重启，旧代码会缩到 8MB ⇒ 吞吐应回落到 ~35-40 MB/s。

**B. 修复后验收** —— **删掉** `XRAY_H2_RTT_HINT_MS`（不再需要），两端跑本票代码重启，同样方法测速：

- 期望：上行天花板不再是 8MB/端到端 RTT ≈ 40MB/s，实测应 ≥ 50-60 MB/s（更高则受源站/家宽上行约束）。
- 客户端日志 `h2_adaptive_window ... send=16777216` 恒成立，`rtt_ms` 只是观测值、不再影响窗（顺序：设 `XRAY_LOG_LEVEL=debug` 或等价开关看该行）。
- 顺带确认下行无回归（流窗/连窗未动：客户端 32/32MB、服务端 16/32MB）。

## 7. 残余风险 / 未做

- **RTT 探针仍每会话拨一条零字节 TCP**（`register.rs` 里 `resolve_rtt` 调用点，bd vkirx① 记录的「Rust 2 条 vs Go 1 条」）。阶梯撤了以后它**零收益、只喂日志**，是干净的可删项；但删除要动 `register.rs` 调用点 + `resolve_rtt`/`probe_rtt` 两个函数，超出本票「只改 flow_window.rs」的红线，未做。建议开跟踪票：删探针后 `XRAY_H2_RTT_HINT_MS` 与 `rtt_ms` 日志字段一并删除。
- **单流内存占用上限回到 16MiB**（低 RTT 大并发多流时比 8MB 档多占）。这是 Go 的行为；h2 `send_buf` 是真实分配，若要再降只能改「每流 send_buf」策略（另票，且不得用边缘 RTT 做判据）。
- 本机 loopback 无法验证 CDN 场景（无 RTT），修复效果以 §6 真机数字为准。
- 未 commit（按任务要求）。
- `target-Wave5Rtt/`（4.1G，本票独立构建目录，含 §5.4 用的 release 二进制）保留未删——主代理若已无需要可直接 `rm -rf target-Wave5Rtt`；删除后重跑 loopback 需 ~9.5 分钟重建。
