VERDICT: CONDITIONAL

# G6Tls — TLS 票 5 张（idtl1 / qscjv / mwvwd / 1avs1 / slv4n）交付报告

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `98c8a360`（工作树含并行代理改动）。
- 验证二进制：本轮构建产物已归档为 `reports/audit-2026-10-31-perf-mem-wiring/fix/tmp/xray-g6.exe`
  （`version` 自报 `git_rev=98c8a360…`，profile=release；临时 `CARGO_TARGET_DIR=target-G6Tls[R]` 已删除）。
  ⚠️ 因同波代理在写 `xray-core/src/reverse.rs`/`xray-proxy-freedom` 时树一度红，本二进制用
  `RUSTFLAGS="--cap-lints allow"` 出（**不改任何文件、不影响产物语义**，仅为解开 lint 门）；正常
  全绿构建的门（clippy/fmt/test）已在 `-p xray-tls -p xray-conf` 上单独跑过（见证据表）。
  重跑 harness 时把 `fix/e2e/e1_*.py` 里的 `RS` 常量指到该 exe 即可。
- Go 裁定基准 `D:/tmp/go2617/xray.exe` = 26.10.17（`92ccc93-dirty`）。

## 结论速览

|票|状态|一句话|
|---|---|---|
|idtl1（P1 vcn 无 pin 全拒）|**已修**|pin 段空=整段跳过，vcn 段用配置根池做链+名验证；E1 双路径（btls/rustls）由 `拒` → `accept`，与 Go 一致|
|qscjv（P1 缺省指纹）|**未修（红线阻断）**|修改点只存在于 `crates/xray-transport-tcp/register.rs`（§4 红线）；给最小 diff 建议 + 逐字段 wire 证据表|
|mwvwd（P2 三处口径）|**①已修 ②已修 ③拍板保留硬门**|缺证书不再自签（逐连接失败，Go 语义）；服务端套件改按自身偏好序（ServerHello 与 Go 同款）；min/maxVersion 保留硬门并文档化|
|1avs1（P2 系统根）|**已修（能力级）**|`useSystemCA` 真接 OS 信任库 + `certificates[]` 一律追加进根池；缺省=内置 bundle（**勘误**：Go 26.10.17 缺省不是系统根）|
|slv4n（P2 unbuffered 化）|**不改（有量化结论）**|实测 TLS 增量 ≈ 2.0 ms/MB CPU，其中整段拷贝 ~0.1 ms/MB（≤5%）；TLS 路径非 CPU 饱和（core_fraction 0.56-0.73），改写适配层无可测收益|

## idtl1 — vcn（verifyPeerCertByName）无 pin 时全拒

### 根因
`PinnedServerCertVerifier::verify_server_cert` 无条件跑 `verify_chain(.., &self.pins)`：pins 为空时必返
`CertNotFound`，落到「peer cert is unrecognized」分支 → **只配 vcn 的配置任何证书都过不去**（btls 与
rustls 两条路径共用这一处）。

Go 基准（`transport/internet/tls/config.go:280-354` 的 `verifyPeerCert`）是**两段式**：
`PinnedPeerCertSha256 == nil` 时 pin 段整段跳过；`VerifyPeerCertByName` 非空时对**每个名字**做
`certs[0].Verify(Roots=CAs, DNSName=name)`（CAs = `getCertPool()`，pin 命中 CA 时换成该 CA）。

### 改了什么（`crates/xray-tls/src/client_config.rs`）
1. `PinnedServerCertVerifier` 增加 `roots: Arc<RootCertStore>`（Go `r.RootCAs`），`new()` 三参。
2. `verify_server_cert` 按 Go 级联重写：pin 空则跳过 pin 段（不再伪造"未命中"错误）→ vcn 非空则逐名
   `WebPkiServerVerifier` 全验（链+签名+有效期+主机名，任一通过即放行）→ 无 vcn 且 pin 未命中 CA 时用握手
   SNI → 两者皆空直接放行（该路径不会装上本 verifier）。
3. `verifyPeerCertByName` 由 `String` 改 `Vec<String>`（Go `infra/conf/transport_security.go:382-390`
   逗号分隔 + trim + 去空）；新增 `parse_verify_peer_cert_by_name`，`build_client_config` 与
   `build_server_cert_verifier`（btls 回接验证）共用。
4. `build_client_config` 先算 `verifier_roots(&json)`，pin/vcn 分支与普通分支共用同一份根池。

### 证据（E1，真实二进制 × 双实现，同配置）
|case|Go|Rust（修前）|Rust（修后）|
|---|---|---|---|
|D1_vcn_only（btls 路径）|accept|**拒** `peer cert is unrecognized`|**accept** ✅|
|D1b_vcn_only（rustls 路径）|accept|**拒** 同上|**accept** ✅|
|D2_vcn_plus_pin|accept|accept|accept ✅|
|vcn 名不匹配（单测 `e2e_vcn_only_rejects_wrong_name`）|—|—|拒 `not valid for name` ✅|
|vcn 名匹配但链不受信（单测 `e2e_vcn_only_rejects_untrusted_chain`）|—|—|拒（证明仍验链）✅|

## qscjv — 未配 fingerprint 时发 rustls 原生 ClientHello

**未实施（红线）**：唯一改点在 `crates/xray-transport-tcp/register.rs:112-152`（§4 红线"已知债"）；
把默认分支从 `utls::client`（rustls）换成 `u_client(... Fingerprint::Chrome ...)` 即可，但该文件禁改。

### E1 wire 证据（抓首 record，`fix/tmp/e1_hello_results.json`）
|配置|Go（恒 utls）|Rust（当前）|
|---|---|---|
|无 fingerprint|GREASE + `supported_versions=[GREASE,0304,0303]` + 16 suites + key_share{MLKEM768(1216B),X25519}，**1749-1813 B**|**无 GREASE**、`[0304,0303]`、10 suites、仅 X25519，**252 B**|
|`fingerprint=chrome`|GREASE + MLKEM768 + X25519，1781 B|GREASE + MLKEM768 + X25519，1546 B（指纹面已对齐，仅长度差）|
|`minVersion=1.3`（无 fp）|仍 `[GREASE,0304,0303]`（模板固定→忽略）|仅 `[0304]`|
|`maxVersion=1.2`（无 fp）|仍升到 1.3（忽略）|仅 `[0303]`、无 key_share|
|`alpn=["http/1.1"]`|`["http/1.1"]`|`["http/1.1"]`|

套件序（本次已对齐）：Rust `ciphers=[1301,1302,1303,c02b,c02f,…]` 与 Go wire 序逐项相同
（排在前 4 位一致：AES128-GCM / AES256-GCM / CHACHA20 / ECDHE-ECDSA-AES128-GCM）。

### 最小 diff 建议（交 PM/属主实施）
```rust
// crates/xray-transport-tcp/register.rs:112-152 附近，把 "无指纹 → utls::client(rustls)"
// 改为 "无指纹 → 默认 Chrome 指纹走 btls"（与 Go GetFingerprint("")=HelloChrome_Auto 对齐）
let fp = if fp_name.is_empty() { Fingerprint::Chrome } else { get_fingerprint(fp_name)? };
let tls_conn = xray_tls::utls::u_client(conn, &sni, cfg, fp, ech, settings.security_json.as_ref()).await?;
```
⚠️ 前置判断：btls 在本机无汇编时指纹吞吐 ~7.6× 慢（CLAUDE.md §5 / bd jyipl），默认改走 btls 等于把
"未配指纹"的所有用户切到 BoringSSL 路径 —— 这是**性能 vs 反审查**的取舍，需 PM 拍板后才动红线文件。

## mwvwd — 服务端三处口径

### ① 缺 certificates 不再静默自签（已修）
`crates/xray-tls/src/server_config.rs` 删掉 rcgen 自签回退（原注释"保证 TLS 服务端总能启动"），改为
**构建期 warn + 逐连接失败**（Go 语义：进程能起，每条连接报 `tls: no certificates configured`）。
测试 `no_certificates_fail_handshake`（真实 duplex 握手，服务端/客户端双向断言失败）替代原
`tls_without_certificates_falls_back_to_self_signed`；三处依赖回退的既有测试改为显式传证书
（`client_config::with_self_signed`、`btls_client::early_data_accept_reject_replay_roundtrip`、
`xray-core/src/functions.rs` 两处 repro 测试——**后者已按 PM 裁定保留，后续不再碰该文件**）。

E1：`srv_no_certificates` → Go `hs=failed (unrecognized_name / 日志 tls: no certificates configured)`，
Rust `hs=failed (access denied / 日志 no server certificate chain resolved)` —— 两侧都 fail-closed。

### ② 套件协商（已修）
rustls 的 `ServerConfig.ignore_client_order` 缺省 false ⇒ **跟随客户端 offered 顺序**（Go 服务端是按自身
偏好序选）→ 同一客户端对 Go/Rust 服务端拿到不同套件。改动：
- `server_config.rs`：`config.ignore_client_order = true`（服务端偏好序）；
- `config.rs`：新增 `go_cipher_suite_preference()` 并按 Go wire 序重排 provider
  （1301→1302→1303→c02b→c02f→c02c…），用户 `cipherSuites` 仍覆盖。

E1：`srv_sni_mismatch_default` Go `TLS_AES_128_GCM_SHA256` / Rust 修前 `TLS_AES_256_GCM_SHA384` →
修后 **`TLS_AES_128_GCM_SHA256`（与 Go 同款）**；`srv_max12` 同理 `ECDHE-ECDSA-AES128-GCM-SHA256` 对齐。
单测：`e2e_server_prefers_own_cipher_order`（客户端把 AES-256 排首，服务端仍选 AES-128）、
`cipher_suite_preference_matches_go`。

### ③ minVersion/maxVersion — **拍板：保留硬门，不改**
Go 客户端版本门**恒不生效**（`tcp/dialer.go:73` 只要 `GetFingerprint` 非空——空串也返回
`HelloChrome_Auto`——就走 utls，`supported_versions` 由模板固定）。Rust btls 指纹路径同样被模板覆盖，
只有 rustls 路径真生效。
**决定：保留 rustls 路径的硬门**（用户写 `minVersion:"1.3"` 就该 fail-loud，而不是静默降到 1.2）；
需要"跟 Go 一样忽略"的场景写 `fingerprint` 即可（两条路径行为已天然分开）。理由写进
`config.rs::security_params` 的 doc（§"minVersion/maxVersion 口径"）。
E1 残留差异（**已知、已登记**）：`G1b_min13_no_fp` / `G3b_max12_no_fp` —— Go accept / Rust 拒
（`UNSUPPORTED_PROTOCOL`）。若 PM 要求 100% 对齐，改法是把 rustls 路径的版本列表固定为 [1.3,1.2] 并只
warn，属"删安全门"，需显式授权。

## 1avs1 — useSystemCA / 系统根加载路径

### 事实勘误（重要）
Go 26.10.17 **缺省不走系统根**：`config_other.go:17-22` / `config_windows.go:22-25` →
`loadCA(UseSystemCa=false)` = `bundleCertPool()`（`golang.org/x/crypto/x509roots/fallback` 内置 Mozilla
根集）。所以票面"删键不等于与 Go 一致"的担忧**不成立**：Rust 缺省 `webpki-roots`（同源 Mozilla 根集）
与 Go 缺省等价。真正的缺口只有两点：① `useSystemCA=true` 无实现（且被 `xray-conf` 拒启）②
`certificates[]` 在非 `disableSystemRoot` 场景 Rust 只当身份证书、没追加进信任根（Go 三档都追加）。

### 改了什么
- `client_config.rs::verifier_roots` 重写为 Go `getCertPool` 三档 + 统一追加：
  `disableSystemRoot` → 只用 `certificates[]`；`useSystemCA` → `rustls_native_certs::load_native_certs()`
  （OS 信任库，读失败/为空时 warn）；缺省 → webpki-roots；三档之后 `add_json_certs()` 追加 `certificates[]`
  （抽自原 `custom_root_store`，消重）。
- `crates/xray-tls/Cargo.toml`：新增 `rustls-native-certs = "0.8"`（**已在 Cargo.lock 0.8.4**，无新下载；
  `Cargo.lock` 只多一条 xray-tls 依赖边）。⚠️ 依赖新增请审计。
- `crates/xray-conf/src/init.rs`（**面外，最小改动，需审计**）：原 2b 段把 `useSystemCA=true` 硬错
  （文案"not supported … remove the key"，误导）；现改为只校验类型（非 bool 才拒），并把测试
  `strictness_rejects_use_system_ca` 改写为 `strictness_allows_use_system_ca_bool`
  （true/false/null 放行 + 字符串类型硬错点名）。

### 证据
单测（E1，本机真实 OS 信任库）：`verifier_roots_use_system_ca_loads_os_store`（OS 根数 >0 且
`useSystemCA=true` 池非空；缺省池条数 == `webpki_roots::TLS_SERVER_ROOTS.len()`）、
`verifier_roots_appends_certificates_to_bundle`（缺省池 + 用户 CA == bundle+1）。
⚠️ **未做**的端到端：把私有 CA 装进本机 Windows 信任库再走 `useSystemCA=true` 握手——那属改机器状态，
需用户授权，本报告不做。残余风险：`rustls-native-certs` 认 `SSL_CERT_FILE/SSL_CERT_DIR` 环境变量，
Go 的 `x509.SystemCertPool` 不认（仅在用户显式设该 env 时有差异）。

## slv4n — rustls 适配层 unbuffered 化（量化后判定：不改）

### 测量（E1，`fix/e2e/tls_cpu_bench.py`，128 MB 单向，同链路 security=none 作对照，各 3 轮）
|security|mbps|cli CPU s|cli CPU µs/MB|core_fraction(CPU/墙钟)|
|---|---|---|---|---|
|none|351 / 331 / 166|0.391 / 0.359 / 0.578|2910 / 2678 / 4307|1.02 / 0.89 / 0.72|
|tls|153 / 121 / 130|0.641 / 0.625 / 0.688|4733 / 4657 / 5122|0.73 / 0.56 / 0.67|

- TLS 的客户端 CPU 增量 ≈ **2.0 ms/MB**（取中位数 4.77 - 2.91）。
- 逐 record 整段拷贝 = 1.0003 MB/MB，按共享内存 10–15 GB/s 估 ≈ **0.07–0.10 ms/MB**
  ⇒ 占整条链路 CPU 的 **1.5–2.5%**，占 TLS 自身开销的 **4–5%**（[INFERENCE]，基于该带宽区间）。
- TLS 路径 `core_fraction` 仅 0.56–0.73（未饱和）⇒ 即使砍掉拷贝，墙钟收益 ≈ 0；与既有 A/B 一致：
  bbuh7 削 46% 分配时吞吐 397→393 MB/s（零变化）。

### 结论
**不改**（不重写 TLS 适配层替掉 tokio-rustls）。升级触发条件写在这里：当客户端在 TLS 路径上
`core_fraction ≥ ~0.95` 且 `cli CPU µs/MB` 成为吞吐瓶颈时（即 crypto+拷贝 独占一核），再评估 unbuffered
形态——那时拷贝占比也只有 4–5%，收益上限仍是噪声级。票面"1.0003 MB/MB、占 89.9% 分配"事实成立，但
**分配量不等于 CPU 成本**。

## 顺带发现（不在我的文件面，未修）
1. **freedom 缺省拦截私网目标**：本机 bench 中 `freedom` 对 `127.0.0.1:28612` 报
   `freedom: target blocked by final rule, blackholing connection`，而配置里**没有任何 `finalRules`**；
   Go 基线 `freedom.go:193-204` 只在配置给了 `FinalRules` 时才建规则（缺省不拦私网）。这会让
   "本机/内网回环"类部署在 Rust 侧静默黑洞。定位：`crates/xray-proxy-freedom/src/config.rs:1184`、
   `handler.rs:154`（属 G1Assembly 文件面，未动）。
2. **REALITY 服务端套件序未跟随**：`xray-reality/src/mitm.rs:121` 用 `ServerConfig::builder()`
   → 仍 ring 默认序，故 REALITY 服务端 ServerHello 与 Go 仍可区分。修法：把 `security_params`
   的 provider 暴露给 reality（或将 `go_cipher_suite_preference` 提为 `pub`）。属面外，未动。
3. **MITM vcn 展开未接线**：Go `tcp/dialer.go:44-61` 对 `verifyPeerCertByName` 里的 `frommitm`
   会展开父域后缀；Rust `is_from_mitm` 仅测试用到（生产零消费）。

## 实际动过的文件（供审计）
- `crates/xray-tls/src/client_config.rs`（idtl1 + 1avs1 主体 + 测试）
- `crates/xray-tls/src/server_config.rs`（mwvwd①②）
- `crates/xray-tls/src/config.rs`（mwvwd② + ③ 文档 + 单测）
- `crates/xray-tls/src/btls_client.rs`（测试夹具补证书）
- `crates/xray-tls/Cargo.toml`（+`rustls-native-certs`）+ `Cargo.lock`（+1 依赖边）
- `crates/xray-conf/src/init.rs`（useSystemCA lint 放宽 + 测试）**面外，最小改动**
- `crates/xray-core/src/functions.rs`（2 处测试补证书；PM 已裁定保留，后续不再动）
- 未触碰：`crates/xray-transport-tcp/register.rs`、vision/splice、btls 绑定、vendor/

## 【验证命令 + 关键输出】
|#|命令|输出（关键行）|
|---|---|---|
|1|`cargo test -p xray-tls --lib`|`test result: ok. 215 passed; 0 failed; 3 ignored`|
|2|`cargo clippy -p xray-tls -p xray-conf --all-targets -- -D warnings`|`Finished dev profile … in 12.50s`（无 error/warning）|
|3|`cargo fmt -p xray-tls -p xray-conf -- --check`|`FMT_OK`|
|4|`cargo test -p xray-conf --lib`|`test result: ok. 215 passed; 0 failed`|
|5|`python fix/e2e/e1_tls.py`（19 例 × 双实现）|17/19 一致；D1/D1b 由拒转 accept；G1b/G3b 为 ③ 已登记差异|
|6|`python fix/e2e/e1_srv_tls.py`|`srv_no_certificates`: go `hs=failed` / rust `hs=failed`；`srv_sni_mismatch_default`: go `cipher=TLS_AES_128_GCM_SHA256` / rust 同；`srv_max12`: 两侧 `ECDHE-ECDSA-AES128-GCM-SHA256`|
|7|`python fix/e2e/e1_hello.py`|`hello_default`: go `grease=True len=1749` vs rust `grease=False len=252`；rust `ciphers=[1301,1302,1303,c02b,c02f,…]` = Go wire 序|
|8|`python fix/e2e/tls_cpu_bench.py 128`|tls `cli_cpu_us_per_mb` 4733/4657/5122，`core_fraction` 0.73/0.56/0.67；none 2910/2678/4307，1.02/0.89/0.72|
|9|`D:/tmp/go2617/xray.exe run -c fix/tmp/allowinsecure_go.json`|`GO exit: 23` + `The feature "allowInsecure" has been removed and migrated to "pinnedPeerCertSha256"(pcs) and "verifyPeerCertByName"(vcn)`|

### 关于验收项「配 allowInsecure:true → 成功（与 Go 一致）」
该验收前提与 26.10.17 基线**不符**：Go 自己在配置加载期就拒 `allowInsecure`
（`infra/conf/transport_security.go:362-363` → `PrintRemovedFeatureError`，上面第 9 条即 E1 实测
exit=23）。Rust 的同等硬错是正确行为（既有 bd 5x41 待用户裁决）。因此本票的该项按"两侧一致拒绝"验收，
未把它实现成"成功"。

### 产物路径
`reports/audit-2026-10-31-perf-mem-wiring/fix/`：本报告 + `e2e/`（harness 副本，RS 指向本组二进制）+
`tmp/`（`e1_tls_results.json` / `e1_srv_tls_results.json` / `e1_hello_results.json` /
`cpu_bench_results.json` + 各轮 server/client 日志）。
