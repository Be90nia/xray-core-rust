VERDICT: CONDITIONAL

# Wave5Align — 两张「行为对齐 Go」票（qscjv / zi7bx）

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `707cd30e`（工作树含并行代理改动：splithttp / workflows，非本组文件面）。
- Go 裁定基准 `D:/tmp/go2617/xray.exe` = 26.10.17（`92ccc93-dirty`，源码 `D:/Project/Xray-core`）。
- 构建环境：`BORING_BSSL_PATH=target/boringssl-asm/prebuilt` + `BORING_BSSL_ASSUME_PATCHED=1` + `PROTOC` + `LIBCLANG_PATH`，`cargo build --release -p xray-cli` 11m51s 出 `target/release/xray.exe`（50563072 B）。

## 结论速览

|票|状态|一句话|
|---|---|---|
|qscjv（P1 缺省指纹）|**已修**|缺省 TLS 由 rustls 原生 hello（252 B、无 GREASE）→ btls Chrome uTLS（1546 B、GREASE + X25519MLKEM768），与 Go 形态对齐；代价是 TLS 数据面 −10~27% 且**要求汇编构建**|
|zi7bx（P2 freedom 默认拦私网）|**不改（前提被 E1 证伪）**|Go 26.10.17 在同一配置下**同样拦私网**（vless/vmess/trojan，E1 三协议实测）；Rust 现状已与 Go 逐项一致。「对齐 Go」= 保持现状，改动反而是制造偏差|

**CONDITIONAL 的三条**：① 发布构建必须带 BoringSSL 汇编（见§性能）；② zi7bx 请按本节证据重新裁决（用户拍板所依据的「Go 不拦」不成立）；③ 残留指纹面差异（hello 仍 1546 B vs Go 1.7-1.8 KB；grpc / splithttp 的「无指纹→rustls」分支按非目标未动）。

---

## qscjv — 未配 fingerprint 时的缺省指纹

### 改法（唯一文件 `crates/xray-transport-tcp/src/register.rs::wrap_security`，红线文件仅此功能面）

原来三分支：`fingerprint` 非空 → btls；`ECH 且无 fingerprint` → btls(warn)；其余 → `utls::client`（rustls）。
合并为单路（净 −35 行）：

```rust
let fp = xray_tls::fingerprint::get_fingerprint(fp_name)   // 空串 → Fingerprint::Chrome（Go GetFingerprint("")）
    .map_err(|e| io::Error::other(format!("invalid fingerprint: {e}")))?;
let alpn = cfg.alpn_protocols.clone();
let tls_conn = xray_tls::utls::u_client_with_alpn(conn, &sni, cfg, fp, ech,
    settings.security_json.as_ref(), Some(&alpn)).await?;
```

- ALPN 必须显式传：`u_client` 的 `alpn=None` 会「保持模板 ALPN」，用户 `tlsSettings.alpn` 会被忽略（Go 是按配置发的）。用 `u_client_with_alpn` + `cfg.alpn_protocols`（缺省即 `["h2","http/1.1"]`）两侧等价。
- 证书验证路径不降级：btls 走既有 pz6c「指纹保真 + 握手后回接 rustls verifier 验链/主机名」，`pin`/`vcn`/`useSystemCA` 语义不变（`build_server_cert_verifier(security_json)`）。
- 副作用（正向）：`minVersion`/`maxVersion` 不再对缺省配置生效——**与 Go 一致**（Go 只要 security=tls 就恒走 utls 模板，版本门永不生效）。G6Tls 报告里登记的 `G1b_min13_nofp` / `G3b_max12_nofp`（Go accept / Rust 拒）随之消失，见下方 hello 表。
- `ECH 无 fingerprint` 的 warn 分支被合并掉（行为更一致，不再有特殊提示）。

### 代价

1. **性能**：TLS 数据面 183-249 MB/s（btls）vs 253-272 MB/s（rustls），见§性能。这是「反审查 vs 吞吐」的既定取舍，用户已拍板选对齐 Go。
2. **构建面**：btls 在 Windows 无汇编时约 7.6× 慢（CLAUDE.md §5 / bd jyipl）。现在**所有** `security=tls` 用户（不止显式配 fingerprint 的）都在 btls 上，所以「发布构建必须带 `BORING_BSSL_PATH=target/boringssl-asm/prebuilt`」从「性能优化项」升级为**功能验收前置**。CI/`release.yml` 仍是裸 cargo → 发出去的 Windows 包会慢（bd jyipl 相邻票，未在本票授权内改动）。

### 证据

**(1) ClientHello 实测（`fix/tmp/e1_hello_align.py` 抓首 record，Go vs 本改动后的 Rust；完整 JSON `fix/tmp/e1_hello_align_results.json`）**

|用例|Go（恒 utls）|Rust 改动前（G6 快照）|Rust 改动后|
|---|---|---|---|
|`hello_default`（无 fp）|GREASE、`[GREASE,0304,0303]`、16 套件、MLKEM768+X25519、1781 B|**252 B、无 GREASE、10 套件、仅 X25519**|**GREASE、`[GREASE,0304,0303]`、17 套件、MLKEM768(1216 B)+X25519、1546 B** ✅|
|`hello_min13_nofp`|同上（模板忽略版本门）1717 B|244 B、仅 `[0304]`（rustls 硬门）|`[GREASE,0304,0303]`、1546 B（与 Go 同为「忽略」）✅|
|`hello_max12_nofp`|`[GREASE,0304,0303]` 1717 B|170 B、仅 `[0303]`、无 key_share|`[GREASE,0304,0303]`、1546 B ✅|
|`hello_alpn_h1`|`alpn=["http/1.1"]` 1810 B|`["http/1.1"]` 249 B|`["http/1.1"]` 1543 B（ALPN 覆盖生效）✅|
|`hello_chrome_fp`（回归锚）|1717 B|1546 B|1546 B（未变）✅|

**(2) 单测（新增，落 `crates/xray-transport-tcp/tests/tcp_tls_dial.rs`）**
`tcp_tls_without_fingerprint_sends_chrome_hello`：裸 TCP 监听端抓首 record，断言 `len > 1000`（改动前 rustls 为 252 B → 该断言必红；改动后 1546 B 通过）。同文件另两条既有用例（`tcp_plus_tls_wraps_tls_and_echoes` / `..._with_fingerprint_uses_btls`）继续通过。

**(3) 真机互通（`dist/interop_ci.py --upstream local`，TLS 层未改坏）**
- rust 套件 12/12 PASS（含 `vless_vision_tls` r1/r2、`trojan_tls` r1/r2）。
- `--suites go,rust_to_go --cross-protos vless_vision_tls,trojan_tls` → **8/8 PASS**（Go/Rust 与 Rust/Go 双向 vision+trojan 各 PASS）。
- 首次四套件混跑曾出现 r2 批量 `os error 10048`（端口占用）与一条 `peer cert is unrecognized`：均为上一轮进程未释放端口后连到陈旧监听，单跑 `--suites rust` 复现为 **12/12 PASS**（harness teardown 抖动，非本次改动）。

---

## zi7bx — freedom 默认不拦私网（对齐 Go）→ **不改**

### 现场结论

票面写「Rust 未配 finalRules 时拦私网；Go 26.10.17 不拦」。**E1 实测相反**：Go 在同一份 config 下也拦。

**(A) E1 对拍矩阵（`fix/tmp/e1_freedom_private.py`；拓扑 = socks 客户端 → 服务端协议入站 → freedom → `127.0.0.1:29601`；两侧同一份 config，只换可执行文件）**

|服务端入站|Go 26.10.17|Rust（本次构建）|判定|
|---|---|---|---|
|vless|`blocked target: tcp:127.0.0.1:29601, blackholing connection for 1m0s` → 无回显|`target blocked by final rule, blackholing connection ... delay=56s` → 无回显|**一致（都拦）**|
|vmess|同上（46s）|同上（81s）|**一致**|
|trojan|同上（40s）|同上（72s）|**一致**|
|socks|`echo-ok`（无拦截日志）|`echo-ok`|**一致（都不拦）**|

**(B) 显式 allow 逃生阀（同一 harness，服务端 freedom 加 `settings.finalRules=[{"action":"allow"}]`）**
Go `echo-ok` / Rust `echo-ok` —— 显式配置仍然生效，两侧一致。

### 为什么审计结论不成立

`reports/.../fix/G6Tls.md §顺带发现 1` 引的是 Go `freedom.go:186-214`（`Init`，只构建**配置里的** `finalRules`），漏了 `Process` 里的默认规则链：

- `freedom.go:160-174` `getDefaultFinalRule(inbound)`：`vless-reverse`→BlockAll；`vless/vmess/trojan/hysteria/wireguard` 与 `shadowsocks*`→**BlockPrivate**；其余 nil。
- `freedom.go:261-265` `if !h.usesDialerProxy { defaultRule = getDefaultFinalRule(inbound) }`。
- `freedom.go:177-186` `matchFinalRule`：配置规则优先，未命中再试 defaultRule，命中 Block 即黑洞（`:352-366` 打印 `blocked target`）。

Rust 侧是逐行翻译且站点齐全：`config.rs::get_default_rule_type`（同为 vless/vmess/trojan/hysteria/wireguard/shadowsocks* / vless-reverse）、`DEFAULT_BLOCK_PRIVATE_CIDRS`（18 条，与 Go `geodata/consts.go:12-29` 逐条相同）、`dispatcher.rs` 默认规则注入 + `arm_builders/outbound.rs:126` 的 `!uses_dialer_proxy` 门。既有单测 `dispatcher.rs::inbound_default_rule_map_derives_block_private` 已锁两侧行为（vless-in 拦 / socks-in 不拦）。

### 如果仍要「默认不拦」

那是**与 Go 分叉**（不是对齐），且改动面不止「一个默认值」——需要摘掉整条默认规则链：`xray-core/src/outbound.rs:152-156` 的 tag→规则映射、`arm_builders/outbound.rs:127` 的注入、`handler.rs::resolve_default_rule` 的 tag 推导（3 处 + 相关测试）。私网部署的正确姿势已存在且两侧一致：显式 `"finalRules": [{"action": "allow"}]`（本报告 (B) 已实测）。**故本票建议以「前提证伪，无偏差」关闭**；若用户仍要 Rust 单边不拦，请回话，我按上述 3 处改并在报告里标注为已知 Go 偏差。

### 顺带发现（未修，面外）

`crates/xray-proxy-freedom/src/handler.rs:114` 用 `session.inbound.tag`（配置 tag，如 `"vless-in"`）当协议名喂 `get_default_rule_type`，而 Go 用的是 `inbound.Name`（协议名）。`Session.inbound.name` 字段存在但全仓无写入点 → **框架路（`xray-cli framework-assembly`）的 freedom 默认私网拦截实际不生效**（欠拦，与生产主路相反方向）。属独立票，本票不动。

---

## 性能影响实测

**(1) 项目标准 loopback 锚（`python tools/loopback_alloc_bench.py --tag qscjv --xray target/release/xray.exe --runs 2`）**

```
[via-enc-chain] #1: speed=126580145.0 B/s (126.6 MB/s) size=209715200 time=1.656859s
[via-enc-chain] #2: speed=138007842.0 B/s (138.0 MB/s) size=209715200 time=1.519656s
floor check: best=138.0 MB/s vs floor=120.0 MB/s   ← PASS
```
该拓扑是 xhttp+reality+vless（不含 tls 指纹面），**本改动不经过它**，数字仅作「没把树搞坏」的回归锚（略低于 baseline.md 154-167 MB/s，本机当前有并行代理在跑，仍在 floor 之上）。

**(2) TLS 数据面 A/B（`fix/tmp/e1_tls_perf_align.py`，vless+tcp+tls，128 MB 单向，同机同配置，各 2 轮）**

|实现|security|mbps|cli CPU µs/MB|core_fraction|
|---|---|---|---|---|
|rustls（改动前 `xray-g6.exe`）|none|290.4 / 315.1|3143 / 2910|0.913 / 0.917|
|rustls（改动前）|**tls**|**253.8 / 271.7**|3609 / 3493|0.916 / 0.949|
|btls（本次 exe）|none|304.9 / 293.9|3260 / 3143|0.994 / 0.924|
|btls（本次 exe）|**tls**|**183.2 / 248.9**|4657 / 3725|0.853 / 0.927|

结论：走 btls 后 TLS 吞吐 **−10% ~ −27%**（best 271.7 → 248.9），CPU 增量 +3~29%。**远非 NO_ASM 的 7.6× 塌方**，说明本机构建确实吃到了汇编（下方核验）。

**(3) 汇编核验（`python tools/build_boringssl_asm.py --check`）**
```
[ok] NASM: D:\Project\tools\nasm.exe
[ok] CMakeCache 无 OPENSSL_NO_ASM
[ok] CMAKE_ASM_NASM_COMPILER_WORKS=1
[info] 已组装 crypto.lib: 7050528 B（无汇编约 7,006,776 B）
```
即：本报告所有 btls 数字都来自 `BORING_BSSL_PATH=target/boringssl-asm/prebuilt` 的汇编产物。**若发布构建不带该 env**，Windows 侧 btls 走 `OPENSSL_NO_ASM`，按项目自身基线（CLAUDE.md §5 jyipl：31.6 → 241.2 MB/s 的 A/B）落到 ~30 MB/s 一档——那时所有缺省 tls 用户都会中招，属必须阻塞发布的门。

---

## 改动文件

- `crates/xray-transport-tcp/src/register.rs`（`wrap_security` 默认分支，红线文件仅授权功能面）
- `crates/xray-transport-tcp/tests/tcp_tls_dial.rs`（+40 行：`tcp_tls_without_fingerprint_sends_chrome_hello`）
- 未改：`crates/xray-proxy-freedom/**`（zi7bx 结论=不改）、vendor/、protos/、tests/、dist/xray.exe、ws/httpupgrade 指纹面。

## 验收命令与输出

|#|命令|输出|
|---|---|---|
|1|`cargo check -p xray-transport-tcp -p xray-proxy-freedom --all-targets`|`Finished dev profile ... in 44.13s`（无 error/warning）|
|2|`cargo clippy -p xray-transport-tcp -p xray-proxy-freedom --all-targets -- -D warnings`|`Finished dev profile ... in 2.64s`（本仓 crate 零告警；仅上游 `rustls` 自带 2 条非 -D 范围提示）|
|3|`cargo test -p xray-transport-tcp -p xray-proxy-freedom --all-targets`|`100 / 12 / 2 / 1 / 1 / 1 / 3` 组全绿，合 120 passed；0 failed|
|4|`cargo fmt -p xray-transport-tcp -p xray-proxy-freedom -- --check`|`FMT_OK`|
|5|`cargo test -p xray-transport-tcp --test tcp_tls_dial`|`3 passed`（含新增 hello 长度断言）|
|6|`python fix/tmp/e1_hello_align.py`|`hello_default` rust `grease=True len=1546`（改前 `grease=False len=252`）|
|7|`python fix/tmp/e1_freedom_private.py <go\|rust> vless,vmess,trojan,socks`|Go/Rust 双端 4×4 一致（3 拦 1 放行）|
|8|`python dist/interop_ci.py --rust target/release/xray.exe --go D:/tmp/go2617/xray.exe --upstream local --suites rust`|`12/12 PASS`|
|9|`... --suites go,rust_to_go --cross-protos vless_vision_tls,trojan_tls`|`8/8 PASS`|
|10|`python tools/loopback_alloc_bench.py --tag qscjv --xray target/release/xray.exe --runs 2`|`best=138.0 MB/s vs floor=120.0` PASS|

## 残余风险 / 未做

1. **发布构建未带汇编 = 全局 TLS 变慢**（本票不授权改 workflows/CI，bd jyipl 相邻票待办）。这是 CONDITIONAL 的第一条。
2. 指纹形态仍非逐字节等同 Go：Rust btls hello 1546 B / 17 套件，Go 1717-1810 B / 16 套件（多 1 个套件，改动前后均如此，属 btls 模板既有差异，非本票引入）。若要逐字节一致需回改 btls 模板，面外。
3. `grpc` / `splithttp` / `ws` / `httpupgrade` 仍有「无 fingerprint → rustls 原生 hello」分支（ws/httpupgrade 属明列非目标；grpc/splithttp 未授权），qscjv 缺口在那些传输上仍存在。
4. bench 的 alloc/MB 未采到（`alloc/MB=N/A`，需 `--alloc-stats`），本次未评估 btls 路径的分配增量。
5. zi7bx 若用户坚持「Rust 单边不拦」，需按§zi7bx 末的 3 处站点改，并在互通/回归里登记为已知 Go 偏差——等裁决。
