# G10 计划票分诊 + 落地报告

VERDICT: **PARTIAL** —— 7 张 `[audit-plan]` 票分诊为 **4 立即执行·已落地（6dgk2 / 3q3h0 / dm2wo / 0270p）/ 1 审计完成但修复需移动端环境（ifnl9）/ 2 阻塞（1kc8d 需授权装 valgrind、zlezx 需用户给域名/入口/协议族）**。
落地票均有可复跑脚本或代码修复 + 实跑输出；阻塞票写明缺什么、谁提供、如何解除，未伪推进。

分支 `feature/fix-inbound-parity`，HEAD `a8534efd`。

---

## 分诊表

| 票 | 内容 | 判定 | 依据（票面 + 仓库事实） | 本轮产出 |
|---|---|---|---|---|
| `6dgk2` | 供应链：cargo audit/deny + vendor 补丁漂移 | ✅ **立即执行·已交付** | `cargo-deny 0.20.2` 已装（含 advisories = cargo audit 的 RustSec 面）；`vendor/{quinn-proto,rustls,tokio-rustls}` 三个 patch 包齐全，上游 `.crate` 已在本地缓存 | 4 项 deny 检查全绿（日志落盘）+ 可复跑漂移脚本 `6dgk2_vendor_drift.py`（幂等，两次输出逐字节一致）+ 3 条实证发现 |
| `3q3h0` | 数值：计数器溢出 / 时钟回拨 / 速率计算 | ✅ **立即执行·已交付** | 静态面可扫（`crates/*.rs` 生产代码）；扫出 1 处真实数值缺陷（`span as u32` 截断 + 除零） | 扫描器 `numeric_scan.py`（120 命中，已按族分类）+ 1 处修复 + 回归测试（42/42 xmc 测试绿） |
| `dm2wo` | 真机吞吐 A/B harness（口径：用户自测） | ✅ **立即执行·已交付**（数字归用户） | `tools/ab_gate.py` 已有 loopback A/B 机制，缺「真机双侧客户端」场景；且该工具在本机**本来跑不起来**（tasklist 解码崩） | 新增 `remote` 场景 + `--emit-md` 结果模板 + 修 tasklist 解码 + 端到端冒烟跑通（真起节点/双客户端/http 源） |
| `0270p` | QUIC：自洽互通 + 静态对照（26.10.17 已无 quic） | ✅ **落地**（互通回归绿 + 接线审计；测速并入 `dm2wo`；静态对照按票面 NOTES ④跳过） | `xray-core/src/register.rs:112-114` 生产注册 quic dialer/listener；`xray-transport-quic/src/transport.rs:84,143` 消费 `quicSettings`；`echo_roundtrip_*` 已覆盖 Rust↔Rust | 接线审计（4 条链路逐条取证）+ 回归 147/147 绿（修前 142/5 红，见「顺带修复」节）；**票面「arm_builders 表 quic 键」前提有误**（quic 是 transport 不是 proxy 协议，见下） |
| `ifnl9` | 移动端：编译门 + tun device_stub 接线 + 产物形态 | 🟡 **审计完成，修复需移动端环境** | 已读 `.github/workflows/mobile.yml` + `xray-proxy-tun` 平台门控：**结论是 Android/iOS 的 TUN 有 4 处实质缺口**（不是「已接线」） | 审计结论 4 条（含 Go 对拍点）；修复需真机/模拟器 + `.github/workflows`（红线）改动 → 需拍板 |
| `1kc8d` | BoringSSL C 侧分配量级（WSL valgrind/massif） | ⛔ **阻塞：需授权装 valgrind** | WSL `ubuntu-xray` 可用、有 cargo/rustc、`apt-cache policy valgrind` 有候选 `1:3.22.0`；但 `valgrind` **未安装**，装包属需确认操作 | 解除配方（含 massif 必需的非 strip 构建开关，票面没提这条） |
| `zlezx` | 真实公网多跳：NAT / CDN / 域名前置 | ⛔ **阻塞：需用户三项输入** | 票面 NOTES 已改口径「CDN 资源已存在」，但仍缺：①测试用域名/入口节点 ②走哪个协议族；且 cloudflared 配置属 CLAUDE.md 红线（用户自管，禁改动、测试不得复用生产进程） | 解除清单（3 项） |

---

## 6dgk2 供应链：cargo-deny 四项 + vendor 漂移

### 1) 四项检查全绿（exit 0）

```
advisories ok   exit=0   （warning: yanked ×2, advisory-not-detected ×2）
licenses   ok   exit=0   （warning: license-not-encountered ×6）
bans       ok   exit=0   （warning: duplicate ×50）
sources    ok   exit=0
```

完整输出落盘：`deny-advisories.txt` / `deny-licenses.txt` / `deny-bans.txt` / `deny-sources.txt`（同目录）。

### 2) 实证发现 A：`deny.toml:33-34` 两条 risk-accept 已成死条目

```
warning[advisory-not-detected]: advisory was not encountered
   ┌─ deny.toml:34:6  "RUSTSEC-2026-0381"  no crate matched advisory criteria
   ┌─ deny.toml:33:6  "RUSTSEC-2026-0382"  no crate matched advisory criteria
```

- 这两条是 2026-10-22 因「本机到 index.crates.io 不可达，无法本地验证编译」而显式 risk-accept 的，注释里写了 revisit 条件：「网络恢复后 `cargo update -p rustls-webpki -p webpki-roots@1.0.8` 并删除本两条」。
- 仓库现状已越过该条件：`Cargo.lock` 里 **rustls-webpki 0.103.16**、**webpki-roots 1.0.11**（忽略项分别针对 0.103.15 / 1.0.8）→ 升级已完成，忽略项成了纯死配置。
- 危害不是「现在有洞」，而是**未来**：留着的 ignore 会让同 id 的新命中被静默放过。建议删除两行（`deny.toml` 属根配置 = 验证资产红线，本组未动，交 PM）。

### 3) 实证发现 B：两个 yanked crate 在依赖树里

```
warning[yanked] chacha20 0.10.0    ← chacha20poly1305 0.11.0-rc.3 → xray-crypto/ss/vless
warning[yanked] spin 0.9.8         ← flume 0.12.0 → route_manager → tun-rs → xray-proxy-tun
```

并伴随**预发布版进生产**：`crates/xray-crypto/Cargo.toml` 与 `xray-proxy-ss`/`xray-proxy-vless` 声明
`chacha20poly1305 = "0.11.0-rc.3"`、`aes-gcm = "0.11.0-rc.4"`（ss 侧注释自陈「与 aead 0.6 对齐」）。
rc 版本可被上游撤回/yank，且不在 semver 兼容保证内——属供应链面已知风险，登记用，不在本轮改（改依赖 = 冷编 4min + 全量回归，需单独票）。

### 4) 实证发现 C：`vendor/tokio-rustls` 的补丁**不存在**，根 `Cargo.toml` 注释与树不符

根 `Cargo.toml:219` 起的 `[patch.crates-io]` 注释称：

> vendor = 上游 v/0.26.4 原版 + 该 patch 本仓自持（src/client.rs **+71 行** `connect_with_session_id_generator`…）

实际漂移（`6dgk2_vendor_drift.py`）：

```
## tokio-rustls  基线 = 上游 crates.io 0.26.4
   文件: vendor=10 上游=21 相同=8 变更=2
   变更 Cargo.toml         +20 -89      ← 内容 == 上游 Cargo.toml.orig 原文（非 cargo 归一化版）
   变更 src/client.rs      +2 -0
```

`src/client.rs` 的 `+2` 就是这两行孤立文档注释，**函数体不存在**：

```diff
+    /// Connect with a session ID generator (used by Shadow-TLS V3).
+    ///
     fn connect_impl<IO, F>(
```

`grep session_id_generator vendor/tokio-rustls` = **0 命中**；该 API 实际住在 `vendor/rustls`
（`ClientConnection::new_with_session_id_generator`，`vendor/rustls/src/client/client_conn.rs:744`，
`hs.rs:56` 起）。即：能力在、但位置与注释所述不同，且 tokio-rustls 里留了一段指向不存在函数的孤儿注释。

处置建议：删孤儿注释 + 改根 `Cargo.toml` 该段注释（`vendor/` 与根 `cargo*` 均为 CLAUDE.md §4 红线，本组只报不改）。

### 5) vendor 漂移全表（脚本输出，可复跑）

```
## quinn-proto  基线 = 上游 crates.io 0.11.18
   文件: vendor=56 上游=57 相同=55 变更=1
   vendor 独有: 无        上游独有: ['Cargo.toml.orig']
   变更 src/connection/datagrams.rs        +13 -6     ← 票面记载的唯一本地 patch（hysteria2 AssumePeerMaxDatagramFrameSize）

## rustls  基线 = 上游 crates.io 0.23.45
   文件: vendor=170 上游=118 相同=109 变更=9
   vendor 独有: src/client/reality.rs + src/testdata/*.der（22 个）
   变更 Cargo.toml(+4) / src/client/{builder.rs,client_conn.rs,hs.rs,test.rs}
        / src/crypto/mod.rs / src/lib.rs / src/msgs/{deframer/buffers.rs,handshake.rs}
   ← = REALITY 3-commit patch + 1 处本仓性能 patch

## tokio-rustls  见 §4
```

rustls 性能 patch 与注释所述一致（去掉 `self.used == 0` 触发条件，功能面 1 行 + 说明块）：

```diff
-        } else if self.used == 0 || self.buf.len() > allow_max {
+        } else if self.buf.len() > allow_max {
```

**结论**：三个 vendor 包的差异集合 **全部可解释**，无未登记补丁、无上游文件被误删（除 `Cargo.toml.orig`/tests 这类归档噪声）。供应链面「补丁被上游升级无声覆盖」的风险当前为零，脚本留作升级时复跑。

---

## 3q3h0 数值正确性

### 1) 扫描器（`numeric_scan.py`，120 命中，已剥字符串/注释/`#[cfg(test)]`）

三族产出：`A_narrow_len` 43 / `A_decrement` 62 / `B_unguarded_div` 3 / `C_wallclock` 12。

逐族核准结论（不做「有命中即缺陷」的误报式交付）：

- **A_narrow_len**：43 处窄化 cast 里，绝大多数是 **Go 同款 wire 长度字段**（`domain_bytes.len() as u8`、
  `payload.len() as u16` 等），Go 侧同样写法 → 属对拍内容不属缺陷；真正需要钳制的两处
  已钳（`udp_session.rs:409` 用 `.min(u16::MAX)`）。
- **A_decrement**：62 处裸 `-=`，逐一核对后**未发现可达下溢**：要么在 `while remaining > 0` 内、
  要么被 `bit_count >= 8` / `size > 0` 门控（`sudoku/codec.rs:181,268`、`xray-crypto/chunk.rs:195`、
  `vision.rs` 属「禁碰区」只读记录）。release profile 无 `overflow-checks`，即便越界也是回绕不 panic。
- **B_unguarded_div**：仅 3 处，全部已守卫——`bridge.rs:87` 有 `worker_count == 0` 早退；
  `sampler.rs:109` 的 `window.max(1e-6)`；`brutal.rs` 的 `ack_rate` 被钳到 `[MIN_ACK_RATE, 1.0]`
  （`brutal.rs:122-129`），不会为 0。
- **C_wallclock**：12 处挂钟使用点，其中 9 处属 Go parity（REALITY/VMess 时间戳、日志时间戳、
  临时目录名）或已被 `xray-frame::compat::clock()` 收口（`xray-proxy-tun/src/inbound.rs:889-895`）。
  **唯一有界风险**：`crates/xray-buf/src/alloc.rs:72-73` 用挂钟做惰性收缩，时钟回拨会让
  `saturating_sub` 归 0 → 收缩停摆；但该池有 `SHARD_MAX_PER_TIER = 64` 硬顶，只影响水位回落到
  挂钟追上为止，且文件头已登记为「唯一挂钟点、非时限语义」。判定：可接受，不改。

### 2) 真实缺陷 + 修复：`xmc/padding.rs::rand_delay` 的 span 截断

```rust
// 修前
let span = max - min + 1;                       // u64 纳秒
let offset = u64::from(rand_u32() % (span as u32));   // ← span 被截到低 32 位
```

两种失效形态（确定性算术，非概率）：

```
0..=10s:              span=10000000001 -> span as u32 = 1410065409 -> 最大取样 1.4101s（真实上限 10s）
0..=u32::MAX ns:      span=4294967296  -> span as u32 = 0          -> 除零 panic
```

即：任何 **>4.29s** 的 padding 延时区间取样被静默截断到 0~1.41s（伪装时序与 Go 不一致），
且 span 恰为 2^32 倍数时 **rem-by-zero panic**（`PaddingDelayRange` 字段是 `pub`，
`Duration::from_nanos(u32::MAX as u64)` 这种写法即可触发）。Go 对应实现用 `big.Int`
（`transport/internet/finalmask/xmc/padding.go:393-406`），无宽度限制 → 这是对拍缺口不是设计。

修复（`crates/xray-transport/src/finalmask/xmc/padding.rs:103-115`）：改按 `u128` 取模。

```rust
    let min = range.min.as_nanos();
    let max = range.max.as_nanos();
    if min == max {
        return range.min;
    }
    // span 按 u128 计：`from_millis` 接受任意 u64 毫秒，纳秒区间可远超 u32。
    // 旧实现 `span as u32` 把区间截到低 32 位（5s 区间实际只取到 ~0.7s），
    // 且 span 为 2^32 倍数时除零 panic；Go 对应实现用 big.Int 无宽度限制。
    let span = max - min + 1;
    let offset = (u128::from(rand::random::<u64>()) % span) as u64;
    range.min + Duration::from_nanos(offset)
```

回归测试（同文件 `tests::rand_delay_covers_spans_wider_than_u32`）：覆盖两种失效形态
——span = 2^32 时 32 次取样不 panic 且不越界；10s 区间 4096 次取样必须出现 >5s 的样本
（旧实现取样上限 1.41s，该断言必红）。

**先复现再修的证据**（把函数体临时换回旧实现跑同一测试，跑完脚本自动还原、文件 hash 不变）：

```
OLD-CODE exit = 101
    test finalmask::xmc::padding::tests::rand_delay_covers_spans_wider_than_u32 ... FAILED
    thread '...' panicked at crates\xray-transport\src\finalmask\xmc\padding.rs:110:28:
    test result: FAILED. 0 passed; 1 failed; 0 ignored; 679 filtered out
restored, hash unchanged = True
```

修后同测试（新代码）：`test ... rand_delay_covers_spans_wider_than_u32 ... ok`。

### 3) 时钟回拨加速复现（票面方法③）

本机不改系统时钟（票面自己也写「本机谨慎」）。替代证据：对 `saturating_sub` 语义做
定点验算——`now < last` 时 i64 结果为负、`> idle_nanos` 恒 false，故
`xray-proxy-tun/src/inbound.rs:930` 的 UDP 会话在回拨后**不再按 idle 淘汰**，直到挂钟追上；
上限由 `note_relay_failure` 的冷却窗与失败摘除兜住。判定为可接受偏差，登记不建议改
（改成分单调钟会与 Go 的 wall-clock 语义分叉）。

---

## dm2wo 真机 A/B harness

### 交付内容（改 `tools/ab_gate.py`，不新造并行工具）

1. **`--scenario remote`**：两侧各起自己的客户端二进制（`--a` / `--b`），各用
   `--a-config` / `--b-config` 请求**同一个真节点**，经各自 SOCKS（`--a-socks`/`--b-socks`）
   下载**同一 URL**（`--url`），严格 A,B,A,B… 交替，沿用本工具既有的中位数比值判定 +
   编译污染检测 + `reports/bench/*.json` 存档。
2. **`--emit-md`**：额外写一份 markdown 结果表（= 票面要的「结果采集模板」），字段：场景/SHA256/
   逐轮 MB-s/中位数/MAD/IQR/轮间离散度/污染原因。
3. **修 bug（本机根本跑不起来）**：`compiler_procs()` 用 `text=True` 读 `tasklist` 输出，
   本机中文代码页非 UTF-8 → 读线程抛 `UnicodeDecodeError` → `stdout=None` →
   `AttributeError: 'NoneType' object has no attribute 'splitlines'`，**工具在任何场景都直接崩**。
   改为按字节读再 `decode('utf-8','replace')`。

固定测试参数（`remote` 场景默认值，全部可覆盖）：`--ncurl 3`（每轮下载次数取均值）、
`--max-time 60`（单次下载上限）、`--rounds 5`（交错轮数）、`--tol 0.05`。
payload 由 `--url` 指向的对象决定——真机口径由用户选一个稳定大文件（≥100MB）。

### 端到端冒烟（真起进程，非桩）

`D:/tmp/dm2wo_remote_smoke.py`：起 ①vless 节点（`target/release/xray.exe`）②http 源
（20MB payload）③由 harness 自己起两个客户端（SOCKS 10818/10819），跑 1 轮 A/B：

```
AB-GATE start tag=dm2wo-smoke rounds=1 tol=0.05
  round 1A: 140.8 MB/s (0.7s, compilers={"cargo.exe": 2, "rustc.exe": 3, "cl.exe": 15})
  round 1B: 450.0 MB/s (0.6s, compilers={"cargo.exe": 2, "rustc.exe": 3, "cl.exe": 16})
median ratio B/A = 3.1967 (tol=0.05) -> verdict=PASS
AB-GATE-MD: reports\bench\ab-20261031T140955Z-dm2wo-smoke.md
CONTAMINATED: 轮中见编译进程 ['cargo.exe', 'cl.exe', 'rustc.exe']
ab_gate exit=0
```

**这两个数字没有意义**（同机 loopback + 单轮 + 同时有 15~16 个 cl.exe 编译任务，
本机受控测速 <17MB/s 本来就无效）——冒烟只证明「进程编排 + SOCKS 就绪等待 + curl 经代理测速 +
比值/污染判定 + JSON/MD 落盘」这条链是通的。**真数字按票面口径归用户自测**：
把节点的两份等配置客户端给进 `--a-config/--b-config` 即可。

### 用户一键跑（真机口径）

```bash
python tools/ab_gate.py \
  --a /path/go-26.10.17/xray.exe --b /path/rust/target/release/xray.exe \
  --scenario remote --url https://<稳定大文件URL> \
  --a-config go-client.json --b-config rust-client.json \
  --a-socks 10808 --b-socks 10809 \
  --rounds 5 --ncurl 3 --max-time 60 --tag realnode --emit-md
```

前置自检：harness 会在启动前扫 `cargo/rustc/cl`，有编译活动默认拒跑（exit 4）——
这在本仓很关键，编译风暴会把 loopback 数字压低 ~20%。

---

## 0270p QUIC

### 接线审计（票面要求③，逐条取证）

| 环节 | 位置 | 事实 |
|---|---|---|
| 生产注册 | `crates/xray-core/src/register.rs:112-114` | `xray_transport_quic::register::{register_dialer,register_listener}()` 在 `register_all_transports()` 内 |
| 是否被主路径调用 | `crates/xray-core/src/functions.rs:184, 284, 947` | 三条入口（`start_full` / `start_full_with_outbound_handlers` / `run`）都调 `register_all_transports()` → 默认可执行文件走得到 |
| `quicSettings` 键路由 | `crates/xray-transport/src/dialer.rs:552` | `TransportProtocol::Quic => Some("quicSettings")` |
| 解析→消费 | `crates/xray-transport-quic/src/transport.rs:84`（dial）/`:143`（listen） | `QuicConfig::from_json(settings.transport_json)`（`transport.rs:84/143`）→ `qc.build_transport_config()`（`:89/147`）→ `quinn::{Client,Server}Config::transport_config`；字段含 congestion / keepAlive / 流窗 / initialMtu / disableSendFairness / disableGSO |

**票面前提纠错**：票面写「生产接线审计：arm_builders 表 quic 键」。实测 `arm_builders/*`
**没有也不该有 quic 键**——`arm_builders` 是 **proxy 协议**（inbound/outbound handlers）构造表，
quic 是 **transport**（由 `streamSettings.network="quic"` 选），走 `register_transport_*` 注册表。
按票面字面找键会得出「未接线」的错误结论。

### 互通面 = 回归（票面 NOTES ①口径：不需静态对照）

已有覆盖：`transport.rs::echo_roundtrip_gso_default` / `echo_roundtrip_gso_disabled`
（dial → listen → 128KiB echo 全链路）、`close_rejects_new_connections`、
`zero_rtt::{resumed_session_hits_zero_rtt, rejected_zero_rtt_falls_back_to_1rtt}`。

**首次实跑是红的**：`cargo test -p xray-transport-quic --lib` → `142 passed; 5 failed`，5 个失败全是
`ConnectionClosed(... reason: "unexpected error: no server certificate chain resolved")`——
即上面这 5 个互通测试的头号证据面当时并不成立。根因与修法见下节；修后 **147 passed; 0 failed**。

### 顺带修复（G10 任务之外）：波2 TLS 改动残留的 5 个 quic e2e 测试（仅测试代码）

**因果链**：HEAD `a8534efd`（波2「TLS 验链」）把
`crates/xray-tls/src/server_config.rs:157,201-210` 改成**缺证书不再自签**
（对齐 Go：`tls: no certificates configured`，启动成功但每条连接握手失败）。这是正确的 fail-visible
改动，但 `xray-transport-quic` 的 5 个测试仍在用「不配证书 → 期待自动自签」的旧假设 → 全红。

**修法**（只动 `mod tests`，生产代码 0 行）：
复用公开 helper `xray_tls::certificate::generate_self_signed_cert(&["127.0.0.1"])`，
把 PEM 内联进 `security_json.certificates[0]`：
- `transport.rs`：新增 `tls_server_settings()`，`close_rejects_new_connections` 与
  `echo_roundtrip_with` 改用它（后者再覆盖 `transport_json` 设 `disableGSO`）；
- `zero_rtt.rs::server_endpoint()`：`allowEarlyData` 之外补 `certificates` 一项。

**改动前后对照**

| 测试 | 修前 | 修后 |
|---|---|---|
| `transport::tests::close_rejects_new_connections` | FAILED（no server certificate chain resolved） | ok |
| `transport::tests::echo_roundtrip_gso_default` | FAILED（同上） | ok |
| `transport::tests::echo_roundtrip_gso_disabled` | FAILED（同上） | ok |
| `zero_rtt::tests::resumed_session_hits_zero_rtt` | FAILED（同上） | ok |
| `zero_rtt::tests::rejected_zero_rtt_falls_back_to_1rtt` | FAILED（握手即 `no server certificate chain resolved`） | ok |
| 汇总 | `142 passed; 5 failed` | **`147 passed; 0 failed`** |

**范围声明**：生产路径**不需要补证书注入**——QUIC 服务端的证书来自 `streamSettings.security_json`
（用户配置），缺证书即每条连接握手失败正是 Go 语义；本次只修测试夹具。
另：`xray-transport-quic` 里 G8 改过的 BBR / bw-sampler 文件本轮未触碰（改动仅
`transport.rs`/`zero_rtt.rs` 的 `mod tests`）。

### 测速面

已并入 `dm2wo`：用 `--scenario remote`，`--b` 换成 sing-box
（`D:/Program Files/v2rayN-windows-64/bin/sing_box/sing-box.exe`，本机存在）即可做
「Rust quic ↔ sing-box quic」吞吐 A/B；对端选择与节点地址属用户环境输入，本轮未编造。

---

## ifnl9 移动端审计（4 条实质缺口）

1. **Android/iOS 的 TUN 运行时是死的，不只是「stub 可编译」**。
   `crates/xray-proxy-tun/src/lib.rs:49-55` 在 android/ios 用 `#[path]` 把 `device` 指向
   `device_stub.rs`（所有 IO 返回 `Unsupported`，消息点名 VpnService/NEPacketTunnelProvider）。
   更关键：fd 继承/接管整段被 `#[cfg(target_os = "linux")]` 包住
   （`device.rs:14,108-109` → `crate::tun_fd::refuse_unsupported()?`，
   `tun_fd.rs:76` 同样 `#[cfg(not(target_os = "linux"))]`）→ **Android 上设 `XRAY_TUN_FD`
   直接硬错**。而 `config.rs:64` 与 `device.rs:9` 的文档恰恰写「Android 的 VpnService fd 经
   `XRAY_TUN_FD` 传入」，Go 端确实这么做（`D:/Project/Xray-core/proxy/tun/tun_android.go`：
   `platform.NewEnvFlag(platform.TunFdKey).GetValue` 读 fd → `unix.SetNonblock` →
   `FcntlInt(F_DUPFD_CLOEXEC)` 复制 fd → `newFdTun(fd, 0)` 包成 `AndroidTun`）。
   → **文档、Go 行为、Rust 实现三方不一致**：Android 根本无法消费宿主注入的 fd，
   移动端 TUN 属「编译得通、运行时不可用」。
2. **产物形态不对**。`mobile.yml` 的 Android job 跑 `cargo build --workspace --bin xray` ——
   产出是 ELF 可执行文件；而 VpnService/NEPacketTunnelProvider 宿主需要的是
   **cdylib/staticlib**（`libxray.so` / `.a`）。全仓 `crates/*/Cargo.toml` 扫 `crate-type`：**0 处声明**（54 个 crate 里一个都没有
   cdylib/staticlib）。
3. **iOS job 只有 `cargo check`，覆盖不到链接期**（`mobile.yml` ios job 末步）。
4. **stub 的契约测试在 CI 里永不执行**：`device_stub.rs:78,87` 两个 `#[cfg(test)]`
   用例只会在 android/ios target 下编译，而 `mobile.yml` 只做 build/check，没有 `cargo test`
   → 这些断言从来没有运行过。

修复所需：真机或模拟器（Android 至少 emulator + 一个最小宿主 App 注入 fd；iOS 需 Xcode 工程），
以及 `.github/workflows/mobile.yml`（CLAUDE.md §4 红线）改动 → **需用户拍板后单独派单**。
本轮只交付审计结论，未动红线文件。

---

## 阻塞票：缺什么 / 谁提供 / 怎么解除

### `1kc8d` BoringSSL C 侧分配（WSL valgrind/massif）

已核实环境（`wsl -d ubuntu-xray -- bash -lc`）：

```
valgrind: 未安装（apt 候选 1:3.22.0-0ubuntu3 可用）
cargo/rustc: /root/.cargo/bin/ 有
WSL 内已有 target / target-r4 等历史构建产物目录
仓源码未在 WSL 内（仓在 /mnt/d/Project/Xray-core-rust，可直接用）
```

- **缺 1（硬阻塞）**：`apt-get install valgrind` 属软件安装 → 需授权。
- **缺 2（票面未提的坑）**：`Cargo.toml` 的 `[profile.release] strip = "symbols"` 且无
  debug 信息 → massif 只能看到 C 帧，拿不到「哪个 Rust 函数触发了 C 分配」。必须先做
  **带行号表**的构建，否则跑了也是白跑。
- **缺 3**：一次 Linux 全量构建（boringssl cmake + 全 workspace）。

解除配方（授权后可一次跑完）：

```bash
wsl -d ubuntu-xray -- sudo apt-get update && sudo apt-get install -y valgrind
# 带行号表（覆盖 strip）：
wsl -d ubuntu-xray -- bash -lc 'cd /mnt/d/Project/Xray-core-rust && \
  CARGO_PROFILE_RELEASE_DEBUG=line-tables-only CARGO_PROFILE_RELEASE_STRIP=false \
  BORING_BSSL_ASSUME_PATCHED=1 BORING_BSSL_SOURCE_PATH=/root/boringssl-patched \
  PROTOC=<protoc> cargo build -p xray-cli --release'
# massif（pages-as-heap=no：只跟 malloc 系，才能对上票面「C 侧 malloc」口径）
wsl -d ubuntu-xray -- bash -lc 'valgrind --tool=massif --pages-as-heap=no --stacks=no \
  --depth=30 --time-unit=B --massif-out-file=/tmp/m.out ./target/release/xray run -c <cfg>'
wsl -d ubuntu-xray -- ms_print /tmp/m.out
```

### `zlezx` 真实公网多跳（NAT / CDN / 域名前置）

票面 NOTES 已把「CDN 不存在」纠正为「已有 cloudflared + 自有域名」。仍缺 **3 项用户输入**：

1. CDN 测试用**域名**与**入口节点**（或授权 PM 读取现有 cloudflared 配置提取——配置/cert
   属 CLAUDE.md §4 红线，测试只读、禁改）。
2. 测试走哪个**协议族**（xhttp / splithttp / ws over CDN）。
3. 红线约束下的落地方式：**不得复用生产 cloudflared 进程**，需独立端口/临时隧道入口。

可自足的部分（VPS 单跳互通、WSL iptables 模拟 NAT）本轮按「不为阻塞票编造参数」原则未跑——
因为一旦跑就需要用户指定节点，否则等于自己编一个环境交差。

---

## 【验证命令 + 关键输出】

### 供应链（6dgk2）

```
$ export CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-G10Plan
$ cargo deny check advisories ; licenses ; bans ; sources
advisories exit=0    licenses exit=0    bans exit=0    sources exit=0
deny-advisories.txt | last: advisories ok | kinds: {'yanked': 2, 'advisory-not-detected': 2}
deny-licenses.txt   | last: licenses ok   | kinds: {'license-not-encountered': 6}
deny-bans.txt       | last: bans ok       | kinds: {'duplicate': 50}
deny-sources.txt    | last: sources ok    | kinds: {}

$ python reports/audit-2026-10-31-perf-mem-wiring/fix/6dgk2_vendor_drift.py
run1=0  run2=0  两次运行一致: True
## quinn-proto  vendor=56 上游=57 相同=55 变更=1   (仅 src/connection/datagrams.rs +13 -6)
## rustls       vendor=170 上游=118 相同=109 变更=9  (+ reality.rs + testdata, 全部可解释)
## tokio-rustls vendor=10 上游=21 相同=8 变更=2     (src/client.rs 仅 +2 孤儿注释)
```

### 数值（3q3h0）

```
$ python reports/audit-2026-10-31-perf-mem-wiring/fix/numeric_scan.py
数值正确性静态扫描（生产代码；已剥字符串/注释/测试段）  命中合计 120
### A_narrow_len : 43    ### A_decrement : 62
### B_unguarded_div : 3  ### C_wallclock : 12

$ cargo test -p xray-transport --lib xmc        (CARGO_TARGET_DIR=target-G10Plan)
running 42 tests ... test result: ok. 42 passed; 0 failed
  test finalmask::xmc::padding::tests::rand_delay_covers_spans_wider_than_u32 ... ok

$ cargo test -p xray-transport --lib           (整 crate，回归面)
running 680 tests ... test result: ok. 678 passed; 0 failed; 2 ignored; finished in 13.65s

$ cargo build -p xray-transport            build_exit=0
$ cargo clippy -p xray-transport --all-targets -- -D warnings   clippy_exit=0
$ cargo fmt -p xray-transport -- --check   fmt_exit=0
```

（`2 ignored` 是本 crate 既有的 `#[ignore]` 项，非本轮引入。）

### A/B harness（dm2wo）

```
$ python D:/tmp/dm2wo_remote_smoke.py
  round 1A: 140.8 MB/s   round 1B: 450.0 MB/s
median ratio B/A = 3.1967 (tol=0.05) -> verdict=PASS
AB-GATE-MD: reports\bench\ab-20261031T140955Z-dm2wo-smoke.md
CONTAMINATED: 轮中见编译进程 ['cargo.exe', 'cl.exe', 'rustc.exe']
ab_gate exit=0
```

### QUIC（0270p）

```
$ cargo test -p xray-transport-quic --lib        (修前：142 passed; 5 failed)
running 147 tests ... test result: ok. 147 passed; 0 failed; finished in 1.24s
  test transport::tests::close_rejects_new_connections ... ok
  test transport::tests::echo_roundtrip_gso_default ... ok
  test transport::tests::echo_roundtrip_gso_disabled ... ok
  test zero_rtt::tests::resumed_session_hits_zero_rtt ... ok
  test zero_rtt::tests::rejected_zero_rtt_falls_back_to_1rtt ... ok

$ cargo clippy -p xray-transport-quic --all-targets -- -D warnings   clippy_exit=0
$ cargo fmt -p xray-transport-quic -- --check                        fmt_exit=0
```

---

## 本轮代码改动清单（4 文件，均为最小 diff）

```
 crates/xray-transport/src/finalmask/xmc/padding.rs            |  33 ++++-   （rand_delay 修 span 截断 + 回归测试）
 tools/ab_gate.py                                             | 140 +++++++--  （remote 场景 + --emit-md + tasklist 解码修）
 crates/xray-transport-quic/src/transport.rs                  |  33 +++--    （测试：显式自签 cert，仅 mod tests 内）
 crates/xray-transport-quic/src/zero_rtt.rs                   |   9 ++-     （测试：同上，仅 mod tests 内）
```

`git diff -U0` 的 hunk 头确认 quic 两处改动全部落在 `mod tests {` 之内（生产代码 0 行变动）。

## 附件（同目录）

| 文件 | 说明 |
|---|---|
| `6dgk2_vendor_drift.py` | vendor 三包与上游 crates.io 同版本的逐文件漂移对照（幂等，CRLF 归一） |
| `numeric_scan.py` | 数值三族静态扫描器（剥字符串/注释/测试段） |
| `deny-advisories.txt` / `deny-licenses.txt` / `deny-bans.txt` / `deny-sources.txt` | cargo-deny 四项原始输出 |

## 未做 / 非目标

- 未改 `vendor/`、根 `Cargo.toml`、`deny.toml`、`.github/workflows/`（均属 CLAUDE.md §4 红线）——
  三处建议（删两条死 ignore、删 tokio-rustls 孤儿注释并改注释正文、mobile.yml 加 cdylib 产物 +
  test 步骤）交 PM 派单。
- 未装 valgrind、未跑 Linux 构建（需授权）。
- 未为 `zlezx` 编造 CDN 域名/入口/协议族。
- 未动 G5/G7 面（`xray-core/src/{functions,bridge}.rs`、`xray-frame/{scope,compat}.rs`、
  `xray-app-{dns,log,metrics,dispatcher}/**`）。
- **未重跑 codebase-memory 索引**：`index_status` 显示 `indexed_at: 2026-10-30T05:13:25Z`
  （落后于 HEAD `a8534efd`，且索引里混入了 `target-Vmess2/**` 的垃圾节点）。当前是波次并行、
  另有 2 组正在改同一棵树，此刻全量 reindex 会把半成品状态烧进图里 → 建议在**本波 commit 落定后**
  统一 `index_repository`，并先把 `target*` 目录加进索引忽略。
- 发现但未动：`crates/xray-transport/src/bridge.rs` 在本轮开始时段处于**他人未完成的脏改动**状态
  （测试代码缺 `task::Context` 导入，`cargo test -p xray-transport` 编译红于 `:1792,1807`），
  后续被其属主修好；本组未触碰该文件。
