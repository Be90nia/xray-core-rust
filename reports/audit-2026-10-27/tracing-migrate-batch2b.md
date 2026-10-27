# tracing-migrate-batch2b：4 crate 裸 tracing 宏 → LogFacade 迁移报告

> 票面：nn8os tracing 面批 2b（`xray-proxy-{wireguard,tun,freedom,vmess}`）
> 日期：2026-10-27 ｜ 执行：TracingBatch2bCont（接续阵亡代理 TracingBatch2b 半成品）
> VERDICT: PASS

## 0. 结论

**88 处生产裸 tracing 宏全部迁 `LogFacade`**（票面 PM 粗测 ~74，开工逐行重derive实数 88：
wireguard 26 / tun 26 / freedom 18 / vmess 18；差异来源见 §2 口径注），**零残留、零
`tracing::event!` 逃生（PM 2026-10-27 裁决：event! 逃生口随 `redline_sites` 门关闭）**。
4 个 crate 级单例门面（`static <域>_LOG: LazyLock<LogFacade>`，域 = crate 名，secrets 均
`vec![]`）；4 个 crate 的 `clippy.toml` 补齐 tuic 同款 tracing 五宏禁令，**探针实证真拦截**
（临时站点 → `error: use of a disallowed macro tracing::debug` → 删）。
**迁后禁令宏 + `tracing::event!` + 裸 `use tracing` grep 实数 = 0**（src + tests 全域）。
测试断言改动 = **0**（四 crate tests/ 面开工扫描零 tracing 站点，无 capture 依赖）。
tun 遗留编译红（`TUN_LOG` dead_code）随调用点迁完消除。

## 1. 前任半成品处置（先 diff 再续，未推倒）

TracingBatch2b 阵亡时 wireguard 5 文件已改（config 1 + dispatcher 1 + driver 5 + inbound 5 迁完 +
inbound 2 处 `debug!`→`event!`「R1 逃生」）+ tun lib.rs 仅声明 `TUN_LOG`（零调用点 = workspace
唯一编译红）。处置：

- **保留**：前任已迁对的 12 处 wireguard 站点 + `WG_LOG`/`TUN_LOG` 门面声明（crate 级单例形态，
  域 = 协议名，与 2a 逐文件门面同取法、少重复泄漏 target 字符串，doc 注释已自述理由）。
- **拆除**：inbound.rs 两处「R1 event! 逃生」——PM 补充裁决明令禁用（`xray-frame` redline 门
  `bare_tracing_event_only_exists_in_registered_redline_files` 全仓扫描 event!，未登记即红），
  两处改迁 `WG_LOG.debug(format!(...))`（原 R1 理由「overload 才触发的丢弃分支非稳态逐包路径」
  保留为注释，迁移后与同函数其余站点形态一致）。
- **补完**：wireguard 残余 12 处 + tun 26 处 + freedom 19 处 + vmess 18 处 + freedom/vmess 门面。

## 2. 迁移对账（HEAD 生产裸宏数 = 本 diff 删除侧数，1:1）

口径：`\b(tracing::)?(trace|debug|info|warn|error)!` + `tracing::event!`，逐行核对
`#[cfg(test)]` 边界（**全部站点均在测试模块之前 = 全生产**，freedom/vmess 逐文件边界核对见
执行记录；四 crate `tests/` 目录扫描零命中）。PM 粗测残留合计 74 vs 本表 HEAD 全量 88：
差值 +14 全部来自 wireguard 前任半成品（已删 12 + event! 化 2 不在残留 grep 内），其余三
crate 与 PM 粗测完全一致。

| crate | HEAD 生产站点 | 门面（域/target） | 迁移后 grep |
|---|---|---|---|
| xray-proxy-wireguard | **26**（前任已迁 12 + event! 化 2 + 残留 12） | `WG_LOG` lib.rs（`xray_frame::wireguard`） | **0** |
| xray-proxy-tun | **26**（inbound 21 + sysroute/executor 2 + sysroute/mod 3） | `TUN_LOG` lib.rs（`xray_frame::tun`） | **0** |
| xray-proxy-freedom | **18**（config 3 + dispatcher 4 + handler 5 + inbound 3 + udp 3） | `FREEDOM_LOG` lib.rs（`xray_frame::freedom`） | **0** |
| xray-proxy-vmess | **18**（dispatcher 5 + plugin 2 + aead/mod 1 + inbound/server 10） | `VMESS_LOG` lib.rs（`xray_frame::vmess`） | **0** |
| **合计** | **88** | 4（本批新增 2：FREEDOM/VMESS；续用 2：WG/TUN） | **0** |

PM 粗测口径注：PM 报 wireguard 12/tun 26/freedom 18/vmess 18 = **残留口径**（当前树）；本表
为 **HEAD 全量对账口径**（wireguard +14 = 前任已删 12 + event! 化 2）。两口径在删除侧逐条
对上：`git diff` 删除侧匹配行 wireguard 26 / tun 26 / freedom 18 / vmess 18 = 88（1:1，无漏迁无多迁）。

逐文件迁移明细（HEAD 处数 → 迁移处数；新取法均为 `<域>_LOG.<level>(format!("msg key=val"))`，
字段按 `%`/`?` 原语义折叠 `Display`/`Debug`，无插值字面量直传）：

| 文件 | HEAD→迁后 | 备注 |
|---|---|---|
| wireguard/src/inbound.rs | 14→14 | 含 2 处 event!→LogFacade 拆除（§1）；`run_wg_udp_session` 循环内 5 站全为错误/丢弃/关闭分支 |
| wireguard/src/netstack.rs | 3→3 | lazy listen 失败 ×2 + sweep 计数 |
| wireguard/src/plugin.rs | 1→1 | domainStrategy 弃用告警（字面量直传，保留 `\` 续行原串） |
| wireguard/src/tunnel.rs | 1→1 | key rotation debug |
| wireguard/src/config.rs / dispatcher.rs / driver.rs | 0→0 | 前任已迁 7 处，本轮复核未动 |
| tun/src/inbound.rs | 21→21 | 含 3 处字面量直传（queue full ×2 / main loop started）；`run_udp_relay` 循环内 6 站全为错误/丢弃分支 |
| tun/src/sysroute/executor.rs | 2→2 | 另同步 2 处 doc 注释（`tracing::info!`→`TUN_LOG.info` 措辞） |
| tun/src/sysroute/mod.rs | 3→3 | **3 处原带自定义 `target: "xray_proxy_tun"`**——grep 全仓证实无任何消费者依赖该 target（命中全为 crate 路径/拨号函数名），并入 `xray_frame::tun` 域；另同步 1 处 doc 注释 |
| freedom/src/config.rs | 3→3 | finalRule 预检 debug ×2 + blackhole info（delay Debug 折叠） |
| freedom/src/dispatcher.rs | 4→4 | PROXY protocol warn ×2 + udp relay ended + ForceIP abort |
| freedom/src/handler.rs | 5→5 | blocked info + dial debug + PROXY write/header/skip ×3 |
| freedom/src/inbound.rs | 3→3 | accept/start/close |
| freedom/src/udp.rs | 3→3 | 帧丢弃/上下行 Block 判定 debug（逐帧循环内，全为丢弃分支） |
| vmess/src/dispatcher.rs | 5→5 | legacy warn + 响应头/体 debug ×4（泵循环内错误分支） |
| vmess/src/plugin.rs | 2→2 | legacy warn + validator skip |
| vmess/src/aead/mod.rs | 1→1 | KDF 截断 warn（format! 内联 `{n}` 原样保留） |
| vmess/src/inbound/server.rs | 10→10 | listening/accept/TLS/ended/mux + 泵内 chunk open/seal/u16 越界 ×5（全为错误/中止分支） |

数据面热路径处置（坑约束⑫）：循环内站点**全部位于错误/丢弃/关闭分支**（`break`/`return`/
`continue`-丢弃），稳态逐包路径零日志站点；format+派发仅在错误发生时付一次（批 1 ss / 批 2a
同款论证）。wireguard 两处前 R1 站点（overload 丢弃分支）按 PM 裁决随批迁移。

## 3. clippy.toml（4 crate 补 tracing 五宏禁令 + 探针实证）

`crates/xray-proxy-{wireguard,tun,freedom,vmess}/clippy.toml` 的 `disallowed-macros` 各补
`tracing::{info,warn,error,debug,trace}` 5 条（reason 与 tuic 2a 批逐字同款）。既有
spawn 族/时钟族/println 条目零改动（tun 原缺 `tokio::task::spawn` 别名条目 = 既有差异，
非本票面，未动）。

**探针验证**（rust-pitfalls「路径写错=静默 no-op」护栏）：tun lib.rs 临时插入
`tracing::debug!("probe")` → `cargo clippy -p xray-proxy-tun --all-targets -- -D warnings`：

```
error: use of a disallowed macro `tracing::debug`
  = note: `#[deny(clippy::disallowed_macros)]` implied by `#[deny(warnings)]`
error: could not compile `xray-proxy-tun` (lib) due to 1 previous error
```

→ 禁令真拦截（非静默 no-op），探针已删。

## 4. 验收四门（实跑尾部）

工具链：仓内 `rust-toolchain.toml` 钉 nightly；共享 target 目录 + `-j 8`（并发期纪律），
四门全绿。测试清单与 HEAD 恒等（本批零测试代码改动）⇒ 全过即不劣化。

1. **check（4 crate --all-targets）**：
   ```
   xray-proxy-wireguard  Finished dev profile in 18.96s   EXIT=0
   xray-proxy-tun        Finished dev profile in 12.00s   EXIT=0
   xray-proxy-freedom    Finished dev profile in 14.89s   EXIT=0
   xray-proxy-vmess      Finished dev profile in 19.69s   EXIT=0
   ```
2. **clippy（我面收窄 + workspace 全量）**：
   ```
   $ cargo clippy -p xray-proxy-wireguard -p xray-proxy-tun -p xray-proxy-freedom \
       -p xray-proxy-vmess --all-targets -j 8 -- -D warnings
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 27.32s
   MY_CLIPPY_EXIT=0

   $ cargo clippy --workspace --all-targets -j 8 -- -D warnings
       Checking xray-integration-tests v0.1.0 (…\tests)
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 27.88s
   WORKSPACE_CLIPPY_EXIT=0        ← 全仓唯一红（tun TUN_LOG dead_code）已清，全绿
   ```
3. **测试（4 crate --all-targets，0 failed）**：
   ```
   wireguard: 110 lib + 6 integration = 116 passed; 0 failed
   tun:       154 lib + 10 + 0       = 164 passed; 0 failed
   freedom:    92 lib + 12           = 104 passed; 0 failed
   vmess:     165 lib + 7 + 12 + 2   = 186 passed; 0 failed; 1 ignored（既有）
                                              合计 570 passed / 0 failed / 1 ignored
   ```
4. **fmt（4 crate --check）**：首跑 wireguard/vmess DIRTY（我面 format! 多行形态）→
   `cargo fmt -p` 归一（只触 4 crate 内文件，diff 全量 27 文件核实无外溢）→ 复验：
   ```
   xray-proxy-wireguard FMT_CLEAN / xray-proxy-tun FMT_CLEAN /
   xray-proxy-freedom FMT_CLEAN / xray-proxy-vmess FMT_CLEAN
   ```
5. **redline 门（PM 追加验收）**：
   ```
   $ cargo test -p xray-frame --test redline_sites
   test bare_tracing_event_only_exists_in_registered_redline_files ... ok
   test result: ok. 4 passed; 0 failed; 0 ignored
   REDLINE_EXIT=0   ← wireguard inbound.rs:482 前任 event! 残留拆除后全绿
   ```
6. **迁移对账（硬指标）**：`git diff` 删除侧裸宏匹配行 = wireguard 26 / tun 26 / freedom 18 /
   vmess 18 = **88 = HEAD 生产站点数（1:1）**；测试断言改动 = **0**。

diff 面：27 文件 +282/−176（4 clippy.toml + 23 src），全部在票面 4 crate 内（逐文件清单
核实无 tests/examples 外溢）。

## 5. 残留分类

| 分类 | 站点数 | 说明 |
|---|---|---|
| 生产（迁） | 88 | 全部迁 LogFacade，含前 R1 event! 2 处 |
| 测试面（豁免） | 0 | 四 crate src 测试模块 + tests/ 目录开工扫描零 tracing 站点 |
| 红线（保留 + event! 登记） | 0 | 本批无 vision-splice 级站点；event! 逃生口已按 PM 裁决关闭 |
| `tracing` dep unused | — | 四 crate 迁后 `tracing` 依赖疑似 unused；**Cargo.toml/Cargo.lock 零改动**（红线；批 1/2a 同款保留先例，`unused_crate_dependencies` 未启用、CI 无 udeps 门，不报红） |

## 6. code-simplifier 自检

自检改动 0 处 / 触碰禁区 0 / diff +282/−176：迁移为纯机械置换（宏→门面 + 字段折叠），
无新抽象（4 个 static 门面为 2a 既定形态）、无 lint suppress、公共 API 零变更（4 门面均
`pub(crate)` 文件级 static）、测试断言零改动。3 处 doc 注释同步（tun sysroute 两处 + 执行
器一处）仅更新过期宏名引用。

## 7. 自我评估

- 准确性 5/5 — 站点数开工 grep 逐行实测（88），对账用 `git diff` 删除侧逐条核对（88=88）；
  全部门禁为实跑完整尾部（§4 原样贴出），探针拦截有输出实证
- 完整性 5/5 — 票面 P0 验收 4 项 + PM 追加 2 项（event! 禁用/redline 门）全部执行并留证；
  前任半成品逐 hunk 核对后续接未推倒
- 清晰度 5/5 — 按「结论→半成品处置→对账→禁令→门禁→残留→自评」结构，两套口径
  （残留/HEAD 全量）显式区分
- 可执行性 5/5 — 所有验证命令可在仓根直接复跑（含 env 前置），门禁输出含尾部耗时
- 简洁性 4/5 — 扣分：§2 口径注与 §0 结论有少量重复（保留是为报告可独立引用）

## 8. 剩余（非本批）

proxy 层 tracing 面至此批后：批 1 已清 loopback/dns/ss/vless，批 2a 已清 tuic/anytls/trojan/
hysteria，本批已清 wireguard/tun/freedom/vmess——剩 socks/http/dokodemo/blackhole（+transport/
app/cli 面）另行排队。

