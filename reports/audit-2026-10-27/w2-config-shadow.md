VERDICT: PASS

# W2 · 配置装配面（面 1）：xray-conf Value 级折叠切 xray-frame `XrayConfigLayers`

> 规格：`docs/architecture/xray-frame-能力收敛方案-2026-10-27.md` §2 面 1（步 2 影子 + 步 3 切换）+ §5.2 W2 行 + §6 通用门
> 文件面（独占）：`crates/xray-conf/src/{serial,json,confloader}.rs` + `crates/xray-conf/tests/**` + `crates/xray-conf/Cargo.toml`（diff: 5 files, +268/−16）
> W1 事实锚：`reports/audit-2026-10-27/w1-frame-derive.md` §5（`block_replace_keys` 含 transport；Value 折叠保留未知键 → 差异先判语义归属）

---

## 1. 切换点清单（clean cutover）

| # | 文件 | 改动 |
|---|---|---|
| 1 | `Cargo.toml` | `[dependencies]` 增 `xray-frame = { path = "../xray-frame" }`（依赖方向 xray-conf → xray-frame 无环；生产树引入 tokio/bytes/xray-buf——方案已接受的启动期代价） |
| 2 | `json.rs` | `config_from_value` 提为 `pub(crate)`（折叠终态单一 typed 装配口）；新增 `decode_json_value`（Value 级解码，同 `json_mode()` env 语义） |
| 3 | `confloader.rs` | 新增 `pub(crate) load_value(path) -> Result<Value>`：JSON 走 udf `std_ext::json` Value 级解码（注释容忍/strict 与 `load_file` 同源）；YAML/TOML 先 typed 装配再转 Value（解析器留仓，方案「格式解析留仓 + 折叠入框架」分层）。**错误构造与 `load_file` 逐字同型** |
| 4 | `serial.rs` | **`merge_configs` 换轨**：`load_value` 逐文件 → `XrayConfigLayers::push_value_from(value, path)` → `merge(xray_policy())` → `config_from_value`。空列表显式报错（保留切换前文案 "no config files to merge"）。旧 typed 循环体删除 |
| 5 | `serial.rs` | 模块文档表更新 + `override_with` 头部补存续说明（见 §4 偏差 1） |
| 6 | `tests/config_file_shadow.rs` | 追加 W2 三路影子测试组（5 个测试 + 6 个 w2 夹具，见 §2） |

**删除的旧路径**：`merge_configs` 内的 typed `Option<Config>` + `override_with` 循环体（约 20 行）。**无 shim、无双轨**：生产多文件装载只剩折叠一条路。

## 2. 影子三路对照（门 1）

三路定义与证据链：
- **旧行为**：`load_file` + `Config::override_with` 循环（= 切换前 `merge_configs` 原文，`override_with` 存续使该参照可常驻测试，钉住两实现持续等价）。
- **新折叠**：切换后 `merge_configs`（xray-frame `XrayConfigLayers` + `xray_policy()`）。
- **Go typed 语义**：Go `infra/conf/serial.mergeConfigs`（builder.go）→ `Config.Override`（本仓 Go 参照 xray.go:502-588 实读）→ `MarshalToJson(c, true)`；用 **Go 源仓（v26.10.17, 92ccc939）自建临时工具 `tmp_w2_dumpconf` 调 `serial.MergeConfigFromFiles`** 取同层 dump（现成 `xray-go.exe` 26.7.28 的 `-dump` 走 proto 域 marshal，与本对照不同层，弃用）。

### 2.1 旧 = 新（typed 域，cargo test 内常驻断言）

`cargo test -p xray-conf --test config_file_shadow -- --nocapture`（10 passed / 0 failed），W2 组对照表：

| 组 | 字段数 旧/新 | 差异 |
|---|---|---|
| 01-minimal / 02-full-apps / 03-multi-inbounds / 04-outbound-chain / 05-with-comments.jsonc / 07-missing-sections（6 Golden 单文件） | 20/20 · 52/52 · 41/41 · 29/29 · 8/8 · 1/1 | **0** |
| w2/base-a（未知键+transport+env）· override-b · mt-base · mt-override · third-layer · zz-tail-append（6 构造单文件） | 18/18 · 21/21 · 12/12 · 6/6 · 7/7 · 4/4 | **0** |
| base+override（tag 命中/前插） | 20/20 | **0** |
| base-a+override-b（transport 整体替换/env 键级合并/未知键） | 30/30 | **0** |
| mt-base+mt-override（缺 tag "" 零值替换） | 10/10 | **0** |
| 三层链 base-a+override-b+third | 32/32 | **0** |
| base-a+tail（tail 来源追加） | 22/22 | **0** |

覆盖验收点名场景：tag 合并（命中替换+未命中追加）、outbounds prepend、transport 整体替换、未知键保留、**数组 tag 合并 vs merge_over 整体替换的语义区分**（`w2_shadow_layered_parity` 断言 fold 产出并集 `["in-a","in-b","in-c"]` / 前插 `["socks-new","direct","block"]`；merge_over 对照组由既有 `shadow_layered_merge_diff_report` 承担，其预期非 0 差异保持非 0）。错误路径：坏 JSON / 缺文件两侧错误文案**逐字相等**，空列表同败。

### 2.2 新 = Go（合并决策域，真 Go 内核实测）

对同 12 组（9 Golden + 3 构造分层 + 03 等）双端 dump 结构比对：

**合并签名域（tag/protocol/listen/port 决策序 + 14 块键存在集 + loglevel + env 键值）＝ 12/12 全等，SIGNATURE DIFFS = 0**——即 tag 命中替换/追加/prepend/tail 追加/块整体替换/env 键级合并的全部合并决策与 Go 逐项一致。

**dump 全量形态差（54 条，逐类举证语义归属；全部为序列化形态、非合并语义，且全部被「旧=新 0 差异」证明为切换前既有）**：

| 类 | 语义归属（证据） | 例 |
|---|---|---|
| C1 Go typed 物化 | Go conf 结构体**非指针零值字段恒物化**（policy.go:12-14 `bool` 非指针）、`duration.Duration` int64 基座物化为 ns（observatory.go `ProbeInterval duration.Duration`）、typed 展开数组元素（dns 字符串 server → 对象） | `dnsLog:false`、`probeInterval:10000000000`（=输入 "10s"）、`dns.servers[0]` 展开对象、`inbounds` 缺省不 emit（nil slice omitempty） |
| C2 Rust typed 物化 | `Config.inbound_configs/outbound_configs: Vec` 无 `skip_serializing_if` 恒 emit | 空配置 dump 出 `inbounds:[]/outbounds:[]`（07 组 raw dump 实证） |
| C3 Value 直传（设计） | lib.rs「切片策略：协议 settings/占位段用 `serde_json::Value`」——Rust 不 typed 展开 | `dns.servers` 保持输入字符串、`streamSettings` 原样、`routing.balancers` 无 `strategy:{}` 展开 |
| C4 Rust 方言序列化 | `PolicyLevel.uplink` 带 `alias="uplinkOnly"`：官方键解析、Rust 方言名序列化（app_config.rs:50-55 明示 + `policy_official_uplink_downlink_only_keys` 测试钉住） | dump 键名 `uplink`/`downlink`（输入 `uplinkOnly`/`downlinkOnly`） |

逐条原始 diff 落盘：`reports/audit-2026-10-27/tmp/`（比对脚本 `w2_go_dump_compare.py`、Go dumps `go_dumps/`，含 12 组原始输出）。

**未知键语义归属（W1 预埋风险点，PM 追加口径）**：Value 级折叠**刻意保留**未知键（顶层/log 块内/条目内），Go typed 丢弃是**解析副作用非合并语义**；终态 `config_from_value` typed 解析丢弃 → 与旧路径终态一致。由 `w2_unknown_keys_survive_fold_only` 钉住（fold 层保留断言 + typed 终态消失断言）。**未用默认值掩盖任何差异**。

## 3. 验收门

| 门 | 命令 | 结果 |
|---|---|---|
| 影子三路 | 见 §2 | **0 实差异**（typed 域 18 组 0；合并签名域 12/12；形态差全分类举证） |
| cargo test | `cargo test -p xray-conf --all-targets -j 8` | **216 passed + 10 passed / 0 failed**（lib 全量 + shadow 全量；切换零回归） |
| clippy 隔离 | `cargo clippy -p xray-conf -p xray-frame --all-targets -j 8 -- -D warnings` | **Finished，0 error**（仅 vendor/rustls 2 条既有 warning，不入 -D 面） |
| clippy workspace | `cargo clippy --workspace --all-targets -j 8 -- -D warnings` | 见 §5 门尾（W3b 的 xray-transport 曾红 9 处 unused import，其本人修复后已绿） |
| fmt | `cargo fmt -p xray-conf -- --check` | **FMT_CLEAN** |
| interop 12/12 | `python reports/audit-2026-10-27/tmp/w2_interop_matrix.py`（`dist/interop_matrix.py` 副本：RUST 指 `target-w2/debug/xray.exe`＝含本切换的新构建；kill() 改为只终止本脚本拉起的进程，防按映像名 taskkill 误伤用户 v2rayN 内核） | 见 §5 门尾 |
| 32/32 VPS | **未跑（按任务书归 PM 收尾统一跑）** | 待 PM |

## 4. 与方案草案的偏差（逐条举证）

1. **`Config::override_with` 未删除**（草案步 3 要求删）：**仓内存活消费者 `crates/xray-cli/src/commands/tool.rs:354`**（`convert pb` 的 `load_convert_inputs`，Go `protobuf.go:48 core.LoadConfig` 对应物）在我文件面之外，删除即破 workspace 构建。该路径按 reader/URL 装载后天然 typed 面合并，与 Go 同构（Go `protobuf.go` 同样调 `Config.Override`）——**保留是 Go 对齐而非双轨**：生产多文件装载链（`merge_configs`）已单轨折叠。**彻底删除需 1 行 xray-cli 迁移 + 删 API，归 PM 派单**。
2. **多文件合并的 per-tag info 日志消失**：切换前 `override_with` 循环逐条 emit `[file] updated/appended/prepend outbound with tag: x`；折叠在 xray-frame 内静默进行，`merge_configs` 保留每文件 `Reading config:` 行。值面零影响（影子 0 差异），仅 info 级装配日志减项。若需日志等价，归 xray-frame 折叠面加 audit 挂点（另波）。
3. **dump 域 HashMap 序**：`env` 为 `HashMap`，Rust dump 键序逐进程随机（Go json 排序）——**切换前既有行为**（typed 路径同一 HashMap），非本引入；结构比对不受影响。

## 5. 门尾（实测）

```
cargo test -p xray-conf --all-targets -j 8
  test result: ok. 216 passed; 0 failed; 0 ignored   (lib)
  test result: ok. 10 passed; 0 failed; 0 ignored    (config_file_shadow)

cargo clippy -p xray-conf -p xray-frame --all-targets -j 8 -- -D warnings
  Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.04s

cargo fmt -p xray-conf -- --check
  FMT_CLEAN

# 三路合并签名域
SIGNATURE DIFFS = 0   (12/12 组：9 Golden + base+override + base-a+override-b + tail + mt + 三层链)
```

（workspace clippy / interop 12/12 尾部见 §5.1 追加节）

### 5.1 追加门尾（终态实测）

```
cargo clippy --workspace --all-targets -j 8 -- -D warnings
  EXIT=0
  warning lines: 3（全部为 vendor/rustls 2 条既有 warning + 其汇总行，不入 -D 面）
  error lines: 0
  Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.61s

python reports/audit-2026-10-27/tmp/w2_interop_matrix.py   # 副本 RUST=target-w2/debug/xray.exe（含本切换）
  == A: Rust client -> Go server ==
  [PASS] #01 vmess  [PASS] #02 vless_vision_tls  [PASS] #03 trojan_tls
  [PASS] #04 vless_ws  [PASS] #05 ss  [PASS] #06 ss2022      （各 HTTP body=200028B）
  == B: Go client -> Rust server ==
  [PASS] #07 vmess  [PASS] #08 vless_vision_tls  [PASS] #09 trojan_tls
  [PASS] #10 vless_ws  [PASS] #11 ss  [PASS] #12 ss2022      （各 HTTP body=200028B）
  === 互操作矩阵: 12/12 PASS ===
```

说明：Rust 侧跑的是 `target-w2/debug/xray.exe`＝本切换后的新构建（`cargo build -p xray-cli`，
W3b 的 xray-transport 编译债收口后构建成功）；`dist/xray.exe`（红线基线，无 `--dump` 旗标的旧构建）
未触碰。PM 收尾跑 32/32 前需按其自身流程出正式 release 产物。

## 6. 未做 / 残余

1. **32/32 VPS 真机套件未跑**（任务书明确归 PM 收尾统一跑）。
2. **`override_with` 彻底删除**：需迁移 xray-cli `tool.rs`（文件面外），见 §4 偏差 1。
3. **折叠期 per-tag info 日志**：见 §4 偏差 2。
4. **YAML/TOML 文件走 typed 转 Value 进折叠**：未知键在格式解析层已丢（JSON 直接 Value 解码不丢）——三格式混合层叠时 YAML/TOML 层的未知键不参与折叠层保留；终态 typed 域仍等价。方案 §2 面 1 分层设计使然，非缺陷。
5. **临时工具清理**：Go 参照仓内 `tmp_w2_dumpconf/` 已删（比对完成后清理）；`D:/tmp/w2_dumpconf.exe` 保留至 PM 复核后可删。比对脚本与 Go dumps 留 `reports/audit-2026-10-27/tmp/` 供复核。
6. **target-w2 删除**：三方协议（W3a 已跳过、W3b 仍在用 20-40 分钟）——最后完工方 `rm -rf`；本报告交付时 W3b 未收尾，**本轮不删**，由 PM/W3b 收尾时清理（可再生缓存）。

## 7. 自我评估（5 轴）

- **准确性 5/5**：每条声明有实证——影子表来自 `--nocapture` 实跑输出；Go 列来自源码实读（xray.go:502-588、builder.go、observatory.go、policy.go）+ 自建工具真跑 dump；形态差 4 类逐类给了源码行级证据；两处标签反转/工具参数错误在交付前被 raw dump 交叉验证抓出并修正。
- **完整性 5/5**：验收 5 项全处理（32/32 按任务书显式归 PM 并注明）；验收点名的 5 个边界场景全部有具名夹具+断言；错误路径三态（坏 JSON/缺文件/空列表）进常驻测试。
- **清晰度 5/5**：三路定义、证据链、形态差分类表（C1-C4）、偏差表均按「结论+证据+归属」组织；切换点逐文件可查。
- **可执行性 4/5**：门命令全部可复制复跑；扣 1 分——Go 对照工具依赖临时构建（`D:/tmp/w2_dumpconf.exe`），PM 复跑三路 Go 列需按 §2.2 说明重建（一条 `go build` 命令，脚本已留 fetch-go 模式）。
- **简洁性 4/5**：生产 diff +32/−16 行最小切换（无抽象新增）；扣 1 分——影子测试新增 207 行（含 6 夹具与 5 测试），是常驻等价钉的必要体量，但 `merge_configs_legacy` 参照与生产 `override_with` 存在语义重复，属「测试自持特征化 oracle」的刻意选择。
