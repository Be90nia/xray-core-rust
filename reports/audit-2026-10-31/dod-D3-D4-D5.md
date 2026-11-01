# DOD 机械复核报告：D3 / D4 / D5（dodB）

- 日期：2026-10-31 · 复核人：dodB（只读复核，零代码改动）
- 树：`feature/fix-inbound-parity` @ `65733da7`（工作树 176 条未提交变更，复核以盘面为准）
- epic：bd `99ifi`（xray-frame 深度融合战役），DOD 定义源：`docs/architecture/xray-frame-深度融合战役计划-2026-10-26.md` §D3/D4/D5
- 方法：静态闸清单盘点 + 全仓 clippy 实跑（独立 `target-dodB`）+ 独立探针 crate + 生产站点普查（cfg(test) 剥离 + 字符串/注释掩码）+ 逐站点人工核对 + 16 夹具真机实跑 + udf 符号逐项 call-chain 核对

---

## 总裁决

| DOD | 裁决 | 一句话 |
|---|---|---|
| **D3** L2 运行期能力（闸 56/56 + 探针 + 豁免清零） | **CONDITIONAL** | 核心断言成立（16 协议 crate 运行面零裸 spawn/tracing，Instant 仅剩登记豁免；clippy 全仓 exit 0；探针独立复验）；但「闸 56/56」数字口径不可复现（实为 54/56 成员），且「迁移点豁免清零」未清零（16 crate 内剩 5 处生产 Instant 豁免，理由均带裁决引证） |
| **D4** L4 夹具真实实例 16/16 | **PASS** | 16/16 夹具接真实插件实例（Default 实例 → Framework register → bring_up → shutdown → 报告内容断言 `stopped==["<crate>"]` 钉空报告边界）；16 夹具实跑 161 tests 全绿；contract_assert.rs 头注「13 crate 仍框架原语夹具」（bd 2zi1o 时点）已过时 |
| **D5** udf 契约族 13/13 有生产调用点 | **FAIL（11/13）** | 11 项有符号级生产 call-chain；**testing 零调用点**（全仓 src+tests 零引用），**ConfigFile 仅 dev-dep 影子比对**（票 xiuvr），无任何生产调用点 |

---

## D3 — L2 运行期能力供给

### D3.1 静态闸清单盘点（`crates/*/clippy.toml` + root）

盘点脚本遍历 `crates/*/clippy.toml`（54 份，udf-frame 工作副本不计）：

| 禁令 | 覆盖 |
|---|---|
| `disallowed-methods` 节存在 | **54/54** |
| `tokio::spawn` 禁令 | **54/54** |
| `std::thread::spawn` 禁令 | 53/54（缺：xray-frame） |
| `Instant::now`（std/tokio 任一）禁令 | **52/54**（缺：xray-buf、xray-frame） |
| `SystemTime::now` 禁令 | 48/54 |
| `disallowed-macros` 节存在 | 29/54 |
| `tracing::{info,warn,error,debug,trace}` 禁令 | **27/54**（16 proxy + 11 app） |
| **16 个 xray-proxy-\* 全量 L3**（spawn/task::spawn/thread/Instant×2/SystemTime + println/eprintln + tracing×5） | **16/16** ✅ |

样板：`crates/xray-proxy-vless/clippy.toml`（6 method 禁令 + 7 macro 禁令，全带 reason）。

**「56/56」口径核对**：workspace 成员 = **56**（`cargo metadata --no-deps` = 54 个 `crates/*` + `tests`（xray-integration-tests）+ `benches`（xray-benchmarks））。`crates/*` 全部有闸（54/54，无一缺失）；**tests/ 与 benches/ 两成员无 clippy.toml**（root clippy.toml 仅 `allow-unwrap-in-tests`，无 disallowed-methods，向上查找不落闸）→ 按成员数口径实为 **54/56**。W0 证据报告（reports/audit-2026-10-26/l3-rest-gates.md §2）记「55/55」，bd a5r4j 关票注记「56/56」——三处数字互不一致，**当前树面机械事实 = 54/56 成员、54/54 产品 crate**。两未闸成员为纯测试/基准 harness crate，不在「16 协议 crate 运行面」范围内，不影响 D3 核心断言，但 DOD 字面「闸 56/56」不可复现。

### D3.2 全仓 clippy 实跑（真跑，非引用旧证据）

```
$ CARGO_TARGET_DIR=repo/target-dodB cargo clippy --workspace --all-targets -- -D warnings
    Checking …409 个编译目标（370 unique crate，含全部依赖）
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 09s
WS_CLIPPY_EXIT=0
```

- 日志全量落盘：`reports/audit-2026-10-31/clippy-dodB-raw.log`（561 行）。
- 仅有的 warning 来自 vendor patch 的 `rustls`（2 条，cap-lints 封顶非 error）——与 W0 证据「vendor rustls 2 告警为仓内常态」一致，非本战役面。
- 16 个协议 crate 的 lib+tests+bench+example 全目标均在 409 目标内被检查，零告警。

### D3.3 探针抽验（独立复验，非引用存档）

探针 crate `D:/tmp/probe_dodB`（workspace 外，零依赖），**复制 `crates/xray-proxy-vless/clippy.toml` 为闸**：

| 变体 | 代码 | 结果 |
|---|---|---|
| 违规面 | `Instant::now` + `SystemTime::now` + `thread::spawn` | clippy 报 `use of a disallowed method` ×3；`-- -D warnings` 下 **exit=101** |
| 违规面 + 宏 | 追加 `println!` | 追加 `use of a disallowed macro std::println` ×1 |
| 豁免面 | `#[allow(clippy::disallowed_methods, reason="probe exemption")] let t = Instant::now()` | **exit=0**（豁免机制生效；且 method 级 allow 不掩盖 macro 禁令——同文件残留 `println!` 仍 exit=101） |

结论：闸文件真实生效、reason 豁免路径真实放行、`-D warnings` 下违规必红。存档探针（W0：xray-xudp 注入→exit 101→undo→复绿，l3-rest-gates.md §3）与本独立探针互证。

### D3.4 生产站点普查与豁免留痕核对

普查口径：`crates/*/src/**`（排除 udf-frame 工作副本、`crates/*/tests/`、root `tests/`、`#[cfg(test)]` 块 brace 剥离、字符串/注释掩码）。脚本与明细：`D:/tmp/probe_dodB/census.py` + `census.json`。**clippy 绿是合规的权威判据（所有被禁 API 站点必已迁移或登记）；普查数为对账参考，含少量已人工甄别的假阳性（smoltcp Instant、fn 定义、测试区漏剥）。**

全树合计（对账参考）：950 站点 = tokio::spawn 295 + Instant::now 163（含 smoltcp 假阳性）+ tracing! 471（full 436 + bare 35）+ SystemTime::now 16 + thread::spawn 3 + bare spawn( 2。tracing! 大头在**未禁 tracing 的 crate**（xray-core 164 / app-dns 35 / commander 23 / dispatcher 21…）——27 个闸内 crate 之外的存量，不属 D3「16 协议 crate」范围（归 D7/D8 面）。

**16 协议 crate 运行面逐条甄别（本 DOD 核心）**：

| crate | 生产裸 spawn | 生产 Instant::now | 生产 tracing! | 备注 |
|---|---:|---:|---:|---|
| anytls | 0 | **1**（server.rs:224 tokio，fn 级 allow+reason「tokio 虚拟钟预算面（数据面热路径）…713x6 判定 tokio 一律不迁」） | 0 | 握手 deadline 与 timeout 同钟族 |
| freedom | 0 | 0（udp.rs:731/733 为 `#[tokio::test]` 测试，fn 级 allow「测试耗时断言配套」） | 0 | |
| tuic | 0 | **4**（server.rs:593/612/655/675 tokio，两 fn 级 allow+reason「面 3 步 3 例外：Budget 无绝对时刻面，Sleep::reset 只能收 tokio Instant（待 Budget 补 timer-arm 面）」） | 0 | udp.rs:76 为 fn 定义非调用 |
| tun | 0 | 0（netstack.rs:74 等 = **smoltcp** `time::Instant`，非被禁 def-path；其余均测试区） | 0 | |
| wireguard | 0 | 0（同上 smoltcp 口径；驱动 Instant 均测试区） | 0 | driver.rs:508 为 fn 定义 |
| vless/vmess/ss/trojan/socks/http/dns/blackhole/dokodemo/loopback/hysteria | 0 | 0（vless:802/vmess:1085/vmess:1628 均测试区） | 0 | |
| **合计 16 crate** | **0** | **5（全部 allow+reason 登记）** | **0** | |

**「迁移点豁免清零」核对：未清零**——5 处生产 Instant 豁免存活（tuic×4 + anytls×1），但每处理由均引证裁决（713x6「tokio 一律不迁」/ Budget timer-arm 面待补），属**语义豁免**而非迁移欠账；严格按 DOD 字面则本项不满足。

### D3 VERDICT: CONDITIONAL

- ✅ 16 协议 crate 运行面零裸 `tokio::spawn`、零裸 `tracing!`；`Instant::now` 仅剩 5 处登记豁免（带裁决引证）。
- ✅ clippy 全仓实跑 exit 0（409 目标）；独立探针红/绿双向验证。
- ❌ 「闸 56/56」数字不可复现：机械事实 54/56 成员（tests/benches 两成员无闸）、54/54 产品 crate；三处历史记录（55/55、56/56、31/56）口径互相矛盾。
- ❌ 「迁移点豁免清零」未清零：5 处生产豁免（语义豁免，非欠账形态）。

---

## D4 — L4 夹具真实实例 16/16

机制：`xray-frame::assert_plugin_contract!`（`src/contract_assert.rs:202`，`#[macro_export]`）→ `<$plugin as Default>::default()` 构造**真实插件类型实例**（非 mock——类型即生产 `impl Plugin`）→ `assert_contract_for` 逐条款断言（条款面 + N/A 理由非空 + 不与 clauses 重叠）。

**每 crate 一行证据**（夹具 = `tests/plugin_contract.rs`；黑名单 crate 的装配链在独立文件）：

| crate | 宏调用 (file:line) | 真实实例装配链（file:line：构造→register→bring_up→shutdown→报告断言） |
|---|---|---|
| anytls | plugin_contract.rs:61 | 107→111→117→120→121（stopped 断言） |
| blackhole | plugin_contract.rs:37 | **plugin_assembly.rs**:28→32→38→41→42-43 |
| dns | plugin_contract.rs:32 | 112→125→131→134→135 `assert_eq!(stopped,["dns"])` + built_config 字段核对:139-143 |
| dokodemo | plugin_contract.rs:34 | 86→97→103→106→107 |
| freedom | plugin_contract.rs:37 | 107→116→122→125→126 |
| http | plugin_contract.rs:32 | 97→105→111→114→115 |
| hysteria | plugin_contract.rs:38 | 83→92→98→101→102 |
| loopback | plugin_contract.rs:30 | 72→76→82→85→86 |
| socks | plugin_contract.rs:32 | 77→86→92→95→96 `assert_eq!(stopped,["socks"])` |
| ss | plugin_contract.rs:60 | 52→41→114→117→118 |
| trojan | plugin_contract.rs:31 | 76→83→89→92→93 |
| tuic | plugin_contract.rs:37 | 82→92→98→101→102 `assert_eq!(stopped,["tuic"])` + built_config 逐字段:106-110 |
| tun | plugin_contract.rs:36 | 101→110→116→119→120 |
| vless | plugin_contract.rs:41 | 94→102→108→111→112 `assert_eq!(stopped,["vless"])` |
| vmess | plugin_contract.rs:39 | 84→90→96→99→100 |
| wireguard | plugin_contract.rs:56 | 101→105→111→114→115 `assert_eq!(stopped,["wireguard"])` |

**真机实跑**（`cargo test -p <16 crates> --test plugin_contract`，target-dodB）：**16 个夹具二进制全部 ok，合计 171 passed / 0 failed**。分 crate：anytls 10 / blackhole 9 / dns 11 / dokodemo 9 / freedom 12 / http 7 / hysteria 12 / loopback 11 / socks 10 / ss 17 / trojan 12 / tuic 9 / tun 10 / vless 14 / vmess 12 / wireguard 6（前 11 crate 为逐 crate 实测标注，后 5 crate 依 16 目标一次运行的顺序对位，两轮结果计数一致）。

**变异证据（改坏→红）**：宏级负向内建——`xray-frame/tests/contract_assert.rs:96-98 empty_na_reason_fails_contract_macro`（N/A 理由清空→红）；每 crate 装配负向（缺段→build `Err` fail-fast，样板 tuic `missing_section_fails_fast_at_build`、vless decryption/flow 非法、wg 私钥/hex/port 溢出等，各 crate plugin_contract.rs 尾部）。

**空报告边界钉**：bd wkemq 指出「空 `ShutdownReport` 的 `is_clean()` 恒 true」——现 16/16 夹具用**报告内容断言**（`per_component` 映射后 `assert_eq!(stopped, ["<crate名>"])`）钉死：插件不注册 stop → 报告为空/缺名 → 红。抽查 dns:135 / socks / wireguard / vless / tuic 均确认。

**过时注记警示**：`contract_assert.rs:38-40` 头注（bd 2zi1o，2026-10-26 复核）称「仅 vless/ss/trojan 3 crate 真实实例夹具，其余 13 crate 仍框架原语夹具」——**与当前树面不符（已 16/16）**，该文档段需随 DOD 收口更新。

### D4 VERDICT: PASS

---

## D5 — udf 契约族 13/13 生产调用点（符号级 call-chain）

判据：主仓生产代码（`crates/*/src`，非 test、非 udf-frame 工作副本）中，谁（crate::fn）调用 udf 哪个符号。**逐项甄别，不接受纯计数。**

| # | udf 项（符号） | 生产 call-chain | 判定 |
|---|---|---|---|
| 1 | **memgov** `skeleton_infra::memgov::BoundedRegistry` | xray-app-dispatcher `default.rs:20`（import）→ `:2046 fn new_handler_registry() → BoundedRegistry::new(MAX_TAGGED_HANDLERS, Eviction::Reject)` → `:2079-2080` dispatcher 生产状态字段 `tagged/shadow: RwLock::new(new_handler_registry())` | ✅ |
| 2 | **compose** `skeleton_infra::compose::combine!` | xray-frame `state_loop.rs:45-46 use skeleton_infra::combine` → `AssemblyRoot::new` `:467 combine!(LifecycleReducer…)` + `:485 combine!(AuditReducer…)` → `AssemblyLoop`（Framework bring_up/shutdown 状态环载体，`:552`） | ✅ |
| 3 | **testing** `skeleton_infra::testing::{TestStore, ScriptedRuntime, MockEnv}` / `parse_mock` | **全仓零引用**（src + 全部 tests 目录 + root tests，含 0 个测试引用；xray-frame 测试用的 `MockEnv` 来自 `skeleton::config`，非本族） | ❌ **0 调用点** |
| 4 | **ConfigFile** `skeleton_infra::config::ConfigFile<C>` | 生产 **0**；仅 xray-conf `Cargo.toml:29` **dev-dependency** + `tests/config_file_shadow.rs:15`（影子比对，票 xiuvr）；xray-frame `config.rs:129-134` 显式记录不包装 `ConfigFile::merge_over`（数组整体替换语义与 Xray tag 合并互斥，复用的是 udf 解码件与层序观念） | ❌ **无生产调用点**（W3c「影子比对先行…才允许切换」——比对件在，切换未发生） |
| 5 | **pool** `skeleton::pool::PoolManaged` + `skeleton_infra::pool::PoolBase` | xray-frame `pool.rs:24-25`（import）→ `:148 ManagedBufferPool::new → PoolBase::new(max, idle_cap)`、`:265 impl PoolManaged for ManagedBufferPool` → 生产装配 `assembly.rs:475 .with_pool(Arc::new(ManagedBufferPool::new(XrayBufPool::new(8,8), 8, 8)))`（PluginContext 缓冲接缝） | ✅ |
| 6 | **fx** `skeleton_infra::fx::FxScope` | 生产构造点成片：xray-app-dns `server.rs:97`、commander `commander.rs:299`/`grpc.rs:548`、metrics `metrics.rs:388`、observatory `observer.rs:17`/`burst_observer.rs:34`、proxyman `worker.rs:28`/`uot.rs:46`、nameserver doh/dot/quic/tcp/udp/mod 六文件 import（Spawned 句柄持管） | ✅ |
| 7 | **shutdown** `skeleton_infra::shutdown::ShutdownCoordinator` | xray-core `shutdown_bridge.rs:23`（import）→ `:77 ShutdownCoordinator::new().with_default_timeout(timeout)`（`Instance::close` 编排）；xray-frame `assembly.rs:198`（Framework 装配缺省协调器） | ✅ |
| 8 | **logx** `skeleton_infra::logx::{ChannelRegistry, ChannelSink, mask_secrets}` | xray-common `log/mod.rs:21`（import）→ `:100-101 static CHANNELS: LazyLock<ChannelRegistry> = ChannelRegistry::new`、`:136 logx::mask_secrets`、`:140 pub fn register_channel`（general/access/dns 三通道单入口）→ xray-app-log `instance.rs:19,671,765`（装配期注册消费） | ✅ |
| 9 | **cache** `std_ext::cache::LruCache` | xray-app-dns `fakedns/mod.rs:28`（import）→ `:147 initialize() → LruCache::new(lru_size.max(1))`（fakedns 引擎池重建，:96 注释引 §3.5.2 差异①） | ✅ |
| 10 | **retry** `std_ext::retry::{RetryPolicy, retry, retry_if_async}` | xray-transport `retry.rs:17`（import）→ `:61 pub async fn exponential_backoff` → `:89 retry_if_async(&policy…)`；xray-transport-kcp `output.rs:12` → `:106-107 RetryPolicy::new + retry(\|\|write_segment, &policy, &SystemClock)`（kcp 输出写路径） | ✅ |
| 11 | **scheduler** `std_ext::scheduler::Scheduler` | xray-app-geodata `scheduler.rs:25`（import `Scheduler as UdfScheduler`）→ `:52 CronScheduler::new → UdfScheduler::new(Arc::new(SystemClock))`（`:63` with_clock 变体、`:141` closed 后重建） | ✅ |
| 12 | **clock** `skeleton::clock::{Clock, SystemClock}` | 生产注入面：geodata `scheduler.rs:52,55`（喂 UdfScheduler）、kcp `output.rs:11`（:107 retry 时钟）、dns `cache_controller.rs:18`、observatory `observer.rs:16`、burst `:33`、proxyman `worker.rs:27`、geodata `downloader.rs:11`、app-log `instance.rs:18`（`MockClock` 仅测试面，符合设计） | ✅ |
| 13 | **json** `std_ext::json::{decode, decode_str, decode_slice, JsonMode}` | xray-conf `json.rs:14`（import）→ `:24 json_mode()`（env 切 Strict/Tolerant）→ `:36/:44/:51 decode`、`:56 decode_str`、`:61 decode_slice`（pub `decode_json*` 族）→ 生产消费 `confloader.rs:52`、`config.rs:101`、`vformat.rs:79`；xray-frame `config.rs:22` JsonMode（policy 分层折叠） | ✅ |

### D5 VERDICT: FAIL（按「13/13 有生产调用点」字面）——11/13 达成

- ❌ **testing**：契约测试替身族（TestStore/ScriptedRuntime/MockEnv/parse_mock）主仓**零消费**（连测试引用都没有）；CLAUDE.md §3.5.2 白拿清单所列与树面不符。
- ❌ **ConfigFile**：仅 dev-dep 影子比对（xiuvr），生产切换未发生；xray-frame 按裁决改用「组合包装 udf 解码件 + 自建折叠」路线（config.rs:129-134 有判定注记）。
- ✅ 其余 11 项均有上表符号级生产 call-chain（含跨 crate 消费面与装配接线点）。

---

## 缺口清单（逐条一行）

1. **[D3]** 闸数口径：「56/56」不可复现；机械事实 = 54/56 成员（`tests`/`benches` 两 harness 成员无 clippy.toml）、54/54 产品 crate；历史记录 31/56→55/55→56/56 三处口径矛盾，收口前应统一写法。
2. **[D3]** 闸内容方差：xray-frame 闸缺 `std::thread::spawn`/`Instant::now` 禁令、xray-buf 闸缺 `Instant::now` 禁令（52/54）——两 crate 无 PluginContext 面属可辩护，但与「三禁令」字面不符。
3. **[D3]** 迁移点豁免未清零：tuic server.rs ×4 + anytls server.rs ×1 生产 tokio-Instant 豁免（理由引证 713x6 / Budget timer-arm 待补），属语义豁免；「待 Budget 补 timer-arm 面」无对应 bd 票锚（tuic reason 所指），建议补票。
4. **[D3]** 普查对账（归 D7/D8）：27 个非 tracing 闸 crate 仍有 ~436 处裸 tracing!（xray-core 164 / app-dns 35…）未属 D3 范围。
5. **[D4]** `contract_assert.rs` 头注接线现状段（bd 2zi1o，3/16）已过时，应更新为 16/16 并随本报告收口。
6. **[D5]** testing 族零消费：TestStore/ScriptedRuntime/parse_mock 主仓 0 引用——要么接消费点（reducer/store 契约测试），要么在融合度口径中如实计 0。
7. **[D5]** ConfigFile 生产切换未发生（W3c 影子比对件在、切换未做）：主路径仍是 xray-conf 自有装载器；收口时 D5 该项应按「影子阶段未完成」记账。

## 复现命令

```bash
# D3 clippy（独立 target）
export BORING_BSSL_PATH=D:/Project/Xray-core-rust/target/boringssl-asm/prebuilt BORING_BSSL_ASSUME_PATCHED=1 \
  BORING_BSSL_SOURCE_PATH=D:/Project/Xray-core-rust/target/boringssl-patched \
  PROTOC=D:/Project/tools/bin/protoc.exe LIBCLANG_PATH="D:/Program Files/llvm/bin" \
  CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-dodB
cargo clippy --workspace --all-targets -- -D warnings   # 实测 exit 0（见 clippy-dodB-raw.log）
# D4 夹具
cargo test -p xray-proxy-{anytls,blackhole,dns,dokodemo,freedom,http,hysteria,loopback,socks,ss,trojan,tuic,tun,vless,vmess,wireguard} --test plugin_contract
# D3 普查脚本：D:/tmp/probe_dodB/census.py（json 明细 census.json）；探针 crate：D:/tmp/probe_dodB/
```

## 五维自评

- 准确性 5/5 — 每条裁决附一手实测（clippy exit/探针 exit/夹具 pass 数/逐站点行号），假阳性逐条甄别注明（smoltcp/fn-def/测试区）。
- 完整性 4/5 — 三条 DOD 全覆盖+缺口清单；扣 1 分：D7/D8 全树精确站点台账未做（非本任务范围，已给近似数与归口建议）。
- 清晰度 5/5 — 裁决表 + 每表可定位到 file:line。
- 可执行性 5/5 — 复现命令全给出，独立 target 不踩兄弟代理。
- 简洁性 4/5 — 单文件报告；普查原始 json 未入库（在 D:/tmp，报告已含甄别后结论）。
