VERDICT: PASS

# G1Assembly — 装配期 fail-fast 门 + 动态配置补齐（8 票）

## 7. 验收回访补录（PM 打回轮，2026-10-31）

- **① `arm_lookup_missing_key_fails_visible` 修复**（`arm_builders/tests.rs`，属本组面）：
  波1 G2/vdl95 把 inbound 表 miss 从 `Ok(None)`（warn+skip）改为
  `Err(InvalidInput, "unknown inbound protocol: <kind>")`，测试旧断言
  `.expect("unsupported inbound must skip, not error")` 已翻转为断言
  `Err` 且 `ErrorKind::InvalidInput` + 错误文案点名协议（未放宽成不检查）。
  复跑：`cargo test -p xray-core --lib arm_lookup_missing_key` →
  `test arm_builders::tests::arm_lookup_missing_key_fails_visible ... ok`（1 passed; 0 failed）。
- **② mux 两条回归定位（只定位不修）**：`git worktree add D:/tmp/check-5fe9 5fe98b90`
  （波1 父提交）+ junction 接 udf-frame，`cargo test -p xray-core --lib mux` →
  `test result: ok. 21 passed; 0 failed`，**含两条失败测试本身绿**
  （`mux_bridge_dispatch_with_access_carries_global_id_for_udp`、
  `integration_udp_relay_through_outbound_mux`）。
  **判定：波1（98c8a360）引入的回归，非既有债** → 派回 UDP 组修 mux 数据面。
  worktree / junction / target-check5fe9 已删。


环境变量（所有 cargo 命令）：`BORING_BSSL_PATH=target/boringssl-asm/prebuilt`、
`BORING_BSSL_ASSUME_PATCHED=1`、`PROTOC=D:/Project/tools/bin/protoc.exe`、
`LIBCLANG_PATH="D:/Program Files/llvm/bin"`、`CARGO_TARGET_DIR=target-G1Assembly`（已按契约删除，复跑命令见文末）。

## 1. 单测（命令 + 输出）

```
cargo test -p xray-core -p xray-app-router -p xray-app-commander -p xray-proxy-freedom --lib
  xray-app-commander: test result: ok. 93 passed; 0 failed
  xray-proxy-freedom: test result: ok. 160 passed; 0 failed   （含 5w5z0 新增 3 条）
  xray-app-router:    test result: ok（含在 4-crate run 内，0 failed）
  xray-core:          test result: FAILED. 507 passed; 3 failed
      arm_builders::tests::arm_lookup_missing_key_fails_visible
      outbound::tests::mux_bridge_dispatch_with_access_carries_global_id_for_udp
      functions::tests::integration_udp_relay_through_outbound_mux
```

**3 处失败全部为既有失败（非本组 diff），归因证据 = 干净基线复跑**：

```
git worktree add D:/Project/xray-g1-baseline HEAD   # HEAD=98c8a360（波1 已提交，零本波改动）
# junction 接入 git-excluded 的 crates/udf-frame 后：
cd D:/Project/xray-g1-baseline && cargo test -p xray-core --lib mux
  → mux_bridge_dispatch_with_access_carries_global_id_for_udp FAILED
      （同断言原文："UDP New frame must carry source-derived GlobalID" left: None）
  → integration_udp_relay_through_outbound_mux FAILED（同 "timeout waiting for udp via outbound mux echo"）
cargo test -p xray-core --lib arm_lookup_missing_key
  → arm_lookup_missing_key_fails_visible FAILED（panicked: "unsupported inbound must skip, not error:
     Custom { kind: InvalidInput, error: \"unknown inbound protocol: no-such-protocol\" }"）
```

即：mux 两条是 mux/xudp/GlobalID 面的既有问题，arm_lookup 一条是波1 G2（inbound 硬错）提交时
没同步更新的旧断言（"unsupported inbound must skip" 与 G2 新行为矛盾）。三处都不是本组面。

## 2. clippy（CI 门）

```
cargo clippy -p xray-core -p xray-app-router -p xray-app-commander -p xray-proxy-freedom \
  --all-targets -- -D warnings
  → Finished `dev` profile ... in 38.49s   （零 warning，绿）
```

## 3. fmt

```
cargo fmt -p xray-core -p xray-app-commander -p xray-app-router -p xray-proxy-freedom   （写）
cargo fmt -p ... -- --check  → FMT_OK
```

## 4. 端到端（release 真实二进制，5/5 全部 exit=1 + stderr 明确错误）

```
cargo build --release -p xray-cli  →  Finished `release` profile ... in 14m 27s
exe = target-G1Assembly/release/xray.exe（version=26.10.11 git_rev=98c8a360 profile=release）

xray.exe run -c <cfg>                                  → exit  stderr 首行错误
fix/G1Assembly/bad-route.json                          → 1  Error: failed to start xray: instance init failed:
                                                            router init failed: routing config JSON parse:
                                                            routing rule network: unknown network token 'tpc'
fix/G1Assembly/bad-protocol.json                       → 1  ... outbound registration failed: outbound protocol
                                                            `no-such-protocol` is not supported
fix/G1Assembly/bad-final-rule.json                     → 1  ... outbound registration failed: outbound `direct`
                                                            (freedom): freedom finalRule: invalid freedom config:
                                                            finalRule ip: invalid IP: not-an-ip
fix/G1Assembly/removed-noise.json                      → 1  ... outbound `direct` (freedom): The feature
                                                            noise = { ... } has been removed and migrated to
                                                            noises = [ { ... } ] ...
fix/G1Assembly/removed-proxysettings.json              → 1  ... outbound `chained` (freedom): outbound
                                                            "proxySettings" has been removed; use
                                                            "streamSettings.sockopt.dialerProxy"
```

## 5. assembly_path_equivalence

```
cargo test -p xray-core --test assembly_path_equivalence
  test assembly_path_difference_ledger ... ok
  test unknown_difference_is_reported_not_absorbed ... ok
  test production_path_rejects_unsupported_outbound ... ok
  test result: ok. 3 passed; 0 failed
```

- 删改理由：原 `production_path_skips_unsupported_outbound_silently` 断言的「生产路对未知协议
  warn+skip、不返回错误」**正是 o91s4 要消灭的行为**（E1：WARN skip → 默认出站前移 → 明文直连），
  故整测试翻转为断言「必须 Err 且错误点名协议」，属行为变更配套，非放宽。
- 台账其他条目未动：① 覆盖差（mux/naive、dokodemo-door 别名）、③ 框架额外门
  （DialerProxy/Mux/ProxyChainTag/SendThrough 四键常量原文未改）、④ 入站同源，逐字保留；
  仅 ② 行文案从「生产 warn+skip / 框架拒启」改为「两路均拒启，差异仅时机与文案」，
  仍登记为 known（`unknown_difference_is_reported_not_absorbed` 绿证明台账反证机制未被削弱）。

## 6. error.rs 新变体的错误链完整性

`CommanderError::ServiceNotRegistered { services }`（error.rs:38-43，`#[derive(Debug, Error)]` +
`#[error("api service(s) declared but no backend injected: {services}")]`）传播链：
`serve_grpc` 返回该值 → `impl Feature for Commander::start`（commander.rs:794-806）
`map_err(|e| FeatureError::StartFailed { name: "commander", message: e.to_string() })`
→ `From<FeatureError> for CoreFunctionError`（functions.rs:117-128，StartFailed → InstanceInit）
→ `run.rs:264-265` `CliError::StartFailed` → `bin/xray.rs:367-383` 打印 `Error: {e}` 并返回
`ExitCode::FAILURE`（=1；仅 ConfigNotFound/ConfigLoadFailed/InvalidConfig 走 23）。
Display/Debug 全程 thiserror/derive，无 panic 路径。commander 测试
`listen_mode_declared_without_backend_fails_start`（93 passed 内）断言错误含 "StatsService" 与
"no backend injected"。

## 平台/出站「可启动 → 拒绝启动」清单（o91s4 预期行为，供例外白名单决策）

|出站|平台|旧行为|新行为|
|---|---|---|---|
|`tun`|Windows / macOS（一切非 linux/android/freebsd）|`Unsupported` → warn+skip（默认出站前移）|拒启：`outbound protocol "TUN outbound is only supported on Linux/Android/FreeBSD" is not supported`|
|任何未注册协议名（arm 表 miss）|全平台|warn+skip|拒启（Go 同拒）|
|settings 非法（uuid/servers/流设置等）|全平台|warn+skip|拒启（Go 解码期同拒）|
|`proxySettings` / freedom `noise` / trojan `flow`|全平台|消费或 warn+忽略|拒启（Go 26.10.17 已移除，同拒）|
|`geodata.outbound` 非空|全平台|静默直连下载|拒启|
|freedom finalRules 含非法 ip/port 项、`geoip:` 项|全平台|丢项→匹配域扩大|拒启|

其中唯一「Go 能跑而 Rust 现在拒」的条目 = 上表前三行里的 **Windows/macOS tun**（Go 支持 tun）与
**freedom finalRules `geoip:`**（Go 经 geodata 资产支持）；其余全部是 Go 侧同样拒启的口径对齐。

## 跨面改动

- `crates/xray-app-commander/src/error.rs`：+1 变体（见 §6，最小 5 行，理由：错误必须能表达
  「声明了没后端」，该类型不在我文件面）。
- `crates/xray-core/tests/assembly_path_equivalence.rs`：验收要求处置，见 §5。

## 残余风险 / 已知差异（Go 能跑 Rust 拒的部分）

1. **Windows/macOS `tun` outbound**：从可启动（静默跳过、实际无隧道）变为拒启。fail-visible 方向正确，
   但若真有用户依赖「配了 tun 也能起（走兜底出站）」，需要白名单决策。
2. **freedom finalRules `geoip:`**：Go 支持（geodata 资产），Rust 无 loader → 拒启。
3. **`geodata.outbound`**：Go 走 tagged dispatcher，Rust 拒启。
4. **API senderSettings 仍是 JSON 约定**：Go CLI `ado` 发 protobuf 字节（`SenderConfig`），Rust 现在
   硬错 "senderSettings is not JSON"（此前静默丢字段）。Go→Rust API 互通需后续补 prost 解码。
5. **`ChainSlot` 死账本**：proxySettings 拒启后生产 `register_outbounds` 的 Phase 2 链回填与
   `proxy_chain_tag` 通路恒空（framework 路自持 ChainSlot 仍用 `set_proxy_chain`）；彻底清账需连带
   `arm_builders/*`（不在本组文件面）。
6. **HandlerService 未纳入声明门**：仅 logger/stats/routing/observatory 四个 `.flatten()` 服务做
   「声明即必须有后端」；HandlerService 缺后端仍是请求期错误（避免误伤既有测试装配）。
7. **既有失败 3 条**（基线复现，见 §1）移交主代理：mux 两条（mux/xudp 面）+ arm_lookup 一条
   （波1 G2 提交时漏更新断言）。

## 复跑命令（目录已按契约删除，重建即可）

```
export BORING_BSSL_PATH=D:/Project/Xray-core-rust/target/boringssl-asm/prebuilt
export BORING_BSSL_ASSUME_PATCHED=1
export PROTOC=D:/Project/tools/bin/protoc.exe
export LIBCLANG_PATH="D:/Program Files/llvm/bin"
export CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-G1Assembly
cargo test -p xray-core -p xray-app-router -p xray-app-commander -p xray-proxy-freedom --lib
cargo clippy -p xray-core -p xray-app-router -p xray-app-commander -p xray-proxy-freedom --all-targets -- -D warnings
cargo test -p xray-core --test assembly_path_equivalence
cargo build --release -p xray-cli
for c in bad-route bad-protocol bad-final-rule removed-noise removed-proxysettings; do
  target-G1Assembly/release/xray.exe run -c reports/audit-2026-10-31-perf-mem-wiring/fix/G1Assembly/$c.json; echo exit=$?
done
```
