VERDICT: PASS_WITH_FOLLOWUPS

# G9 测试与 CI（8 票：6 做 + 2 只出方案）

> **PASS_WITH_FOLLOWUPS 的含义**：6 张「可做」票的代码部分全部落地并实跑通过
> （16 crate 契约夹具 + 4 crate 错误变体 + TPROXY 链 + fakeudp reactor，共 210 条断言全绿，
> fmt/clippy 绿）；**4 项需 src 面或需授权的动作**已给完整 diff 草案未执行。另
> **实测出 1 个 P0 产品缺陷（UDP TPROXY 收包循环热自旋）并已修复**——经 PM 专项授权，
> 本组唯一产品代码改动 = `crates/xray-transport/src/udp/hub.rs` 一处函数，修复前后 CPU
> 实测与反证见 §jf1wv。

---

## 逐票

### amynv（P1）L4 夹具持真实插件实例，断言真实副作用 —— DONE（框架面缺口已收窄，残余需 src 面）

**旧形态（审计 F1 实证）**：16 个协议 crate 的 `l4_*` / `l4_behavior_*` 夹具把
`contract_test_context("<插件名字面量>")` 与 `ManagedBufferPool::new(...)` 写死在夹具里——
被断言的池是**夹具自造**的、日志 target 的域是**字面量**，插件实例从未出场。

**本次改动（16 个 crate 的 `tests/plugin_contract.rs`，纯测试面）**：

1. **池条款（4/9）经插件能力句柄**：`PluginContext::set_pool` 注入真实
   `ManagedBufferPool<XrayBufPool>`，借/还都走 `ctx.pool()`（插件唯一拿得到的口），
   记账断言落在**同一个池实例**上（`shared.metrics().borrowed == 4` → drop → `borrowed == 0`）。
   —— 把 `set_pool`/能力句柄接线改坏，或把池换成另一个实例，本条即红。
2. **日志条款（10/11）域取自实例**：`domain: <Plugin>::default().name()`，不再写字面量；
   插件改名/漏改导出即红。
3. **conn_id 条款（3）ctx 域取自实例**：`contract_test_context(<Plugin>::default().name())`。
4. **wireguard 补齐整组**：该 crate 此前**一个 `l4_*` 都没有**，却声明「12 条全适用」——
   新增 `l4_behavior_conn_id_present_unique_monotonic` / `_deadline_effective` /
   `_log_fields_quadruple_masked` / `_pool_discipline_balances` 四条。

**关键诚实声明（不在本组文件面，未假称覆盖）**：

- 条款 3 **conn_id 注入在插件的生产代码里零调用**（`grep next_conn_id` 在 `xray-proxy-*/src/`
  命中 0，与审计 F2 一致）。夹具现在只能断言「框架的 id 生成器 + 域来自实例」，
  **不能**断言「插件产出的连接带 id」——那需要产品侧接线，属另一张票。
- 条款 2 deadline 夹具的 work 闭包仍是空/单次 `yield_now()`（框架原语），
  插件真实握手步不在闭包里 —— 需要插件暴露握手步才能改，属 src 面。
- 契约宏 `assert_contract_for` 仍丢弃 `deps()` 返回值、仍不调 `build()`（`crates/xray-frame/src/contract_assert.rs`，src 面）。

**残余（需 src 面，diff 草案见下）**：

```diff
--- a/crates/xray-frame/src/contract_assert.rs
+++ b/crates/xray-frame/src/contract_assert.rs
 // ① 必选方法集可调；name 非空且稳定；version 非空。
-    let _ = plugin.deps();
+    // deps 拓扑门的执行面：声明了 dep 就必须在注册表里可解析（否则 L5 门空跑）。
+    // 注：本宏不持注册表 → 只断言「dep 名非空且不自我依赖」这一可判面，
+    // 真正的拓扑门由 assembly::Framework::build 覆盖。
+    for dep in plugin.deps() {
+        assert!(!dep.name().is_empty(), "[contract:{type_name}] deps() 含空名依赖");
+        assert_ne!(dep.name(), plugin.name(), "[contract:{type_name}] 自我依赖");
+    }
```
（`build()` 的覆盖不在宏内做——宏无配置根；正确落点是各 crate 已有的
`*_assembles_bring_up_and_shuts_down_clean` 与 `missing_section_fails_fast_at_build`，
两条已在 16 个 crate 中实跑，本次未改动。）

---

### 7k7mj（P1）4 条错误期望随对应票修复而反转 —— 3 条已随波1/2 反转，1 条残留（src 面）

**结论：4 条中 3 条在波1/波2 已由对应组同步反转（本组只做核验与防误改对照）；第 4 条
（`pattern_router_skips_rule_without_outbound_tag`）属 `crates/xray-core/src/router.rs`，
在本组「禁止改 `crates/**/src/**`」边界外 → 给 diff 草案，不执行。**

| # | 位置 | 旧断言（缺陷固化） | 现值 / 新断言 | 对应波次 · 票 | 状态 |
|---|---|---|---|---|---|
| ① | `crates/xray-proxy-anytls/src/inbound.rs` | `handler_without_password_allows_connection`：无口令时**任意口令能建连并 echo 通** | `handler_without_password_rejects_start`：`start` 返 `Err`（生产 builder 起不来 = 拒启） | 波1 · G2 / `bz800` | 已反转（非本组） |
| ② | `crates/xray-core/src/outbound.rs` | `register_vless_invalid_uuid_skipped`：坏 UUID → `register_outbounds(..).unwrap()` + `ohm.get_handler("bad-vless").is_none()`（静默丢弃写进期望） | `register_vless_invalid_uuid_rejected` + `register_socks_missing_servers_rejected`：必须 `Err` 且文案点名协议 | 波2 · G1 / `o91s4`（生产路 fail-fast） | 已反转（非本组） |
| ③ | `crates/xray-core/src/router.rs:453` | `pattern_router_skips_rule_without_outbound_tag`：缺 `outboundTag` → `rules_len_for_test() == 0`（整条规则被丢） | **未变**。`vaye2` 修在装配层（生产路拒启，见下），`PatternRouter` 本身仍是遗留回退类型、仍静默丢 | 波2 · G1 / `vaye2` | **残留**（src 面，见 diff） |
| ④ | `crates/xray-core/src/wiring.rs` | `sniffing_exclusions_bad_rule_skipped_others_kept`：坏规则跳过、好规则保留（注释自陈 Go 为 Build 期硬错） | `sniffing_exclusions_bad_rule_hard_error`：`try_sniffing_request_from_json` 必须 `Err`（逐条硬错） | 波1 · G2 / `vdl95` | 已反转（非本组） |

**③ 的生产语义已有守卫**（同一输入，证明「拒启」不再只是框架路的事）：

```
crates/xray-core/src/wiring.rs:1513  parse_routing_json_missing_both_tags_errors
  → build_router_adapter_from_json(br#"{"rules":[{"domain":["x.com"]}]}"#).unwrap_err()
  → 断言错误含 "neither outboundTag nor balancerTag"            （对位 Go router.go:170-171）
crates/xray-core/src/functions.rs:293-297  bd vaye2 处：routing init 失败 →
  CoreFunctionError::InstanceInit("router init failed: …")，不再回退 PatternRouter
```

即：**「缺 outboundTag 的规则被静默丢弃」这句话在默认可执行文件的启动路径上已不成立**；
`PatternRouter` 只剩测试与陈旧导出在用（全仓 `grep PatternRouter` 生产引用 0，仅
`router.rs` 自身 + `functions.rs` 的过期 doc 注释）。因此 ③ 不是「漏反转」，而是
「测试断言的是已不在生产路上的遗留类型」——两者都要处理，且都在 src 面。

**③ 的 diff 草案（待授权 / 派给 xray-core src 面）**：

```diff
--- a/crates/xray-core/src/router.rs
+++ b/crates/xray-core/src/router.rs
@@ -452,10 +452,22 @@ mod tests {
     #[test]
-    fn pattern_router_skips_rule_without_outbound_tag() {
+    fn legacy_pattern_router_drops_rule_without_tag_but_production_rejects() {
         let json = make_routing_json("[{\"domain\":[\"x.com\"]}]");
         let r = PatternRouter::from_json(&json).unwrap();
-        assert_eq!(r.rules_len_for_test(), 0);
+        // PatternRouter 是 vaye2 之后的**遗留回退类型**（生产路已不回退到此，
+        // 见 functions.rs 的 fail-visible 门）。它仍静默丢规则——在此显式标注为
+        // 历史行为，免得后人把它当生产语义；生产语义由下面这条守卫钉住。
+        assert_eq!(r.rules_len_for_test(), 0, "遗留类型的历史行为（非生产语义）");
+        let err = crate::wiring::build_router_adapter_from_json(&json)
+            .expect_err("生产装配必须拒启：缺 outboundTag 的规则");
+        assert!(
+            err.to_string().contains("neither outboundTag nor balancerTag"),
+            "生产错误文案须点名缺键: {err}"
+        );
     }
```
（配套一行 doc 修正：`functions.rs:200-202` 的「失败时回退 `PatternRouter`」已过期，
改为「失败 → `InstanceInit` 拒启（bd vaye2）」——同属 src 面。）

**防误改清单（本组明确未动，避免与对应票语义冲突）**：

| 测试 | 为什么不能按「拒绝语义」改 |
|---|---|
| `start_from_built_skips_unregistered_kind` / `..._factory_error_skipped`（`functions.rs:1085/1116`） | Go `app/start.go` 确实是 skip 语义（审计 F13 自己给的方向是「补 Go 出处注释」而非反转） |
| `add_inbound_always_returns_other_todo`（`xray-app-proxyman/command/mod.rs:895`） | 断言的是「gRPC `AddInbound` 未实现」这一可观测事实，反转要先实现功能（票外） |
| `register_outbounds_first_success_is_default`（`outbound.rs:3471`） | 断言的是 default 选取规则，与 fail-fast 不冲突 |

---

### 05ac1（P1）56 错误变体补测 —— 非凭据面已补 4 crate；凭据面随 G2 不重做

**范围判定**：G2 已做 `u4efe`（ss 空口令拒启）/ `p45qd`（ss2022 容差常量）/ `bz800`（anytls）。
本组补**未被任何测试触达、且能从公开 API 触达**的变体；触达不到的给出 src 面草案（§残余）。

新增 4 个测试文件（每处一个断言，全部实跑）：

| 文件 | 覆盖的变体（此前零覆盖） | 实测 |
|---|---|---|---|
| `crates/xray-proxy-trojan/tests/error_variants.rs` | `InvalidUserAccount`（缺 account / type_url 非 trojan / payload 解不出）· `EmptyEmail`（`del` 面）· `UserAlreadyExists` · `UserNotFoundByEmail` | 6 passed |
| `crates/xray-proxy-ss/tests/error_variants.rs` | `InvalidCipherName` · `InvalidPassword`（base64 解不出 / **短于** key_size）· `EmptyEmail` · 空 PSK 的实际变体钉死 + 两组对照（等长 PSK 必须通过、合法用户必须进表） | 8 passed |
| `crates/xray-proxy-socks/tests/error_variants.rs` | `AuthFailed` 三处生产拒绝点（密码模式下未提供 0x02 **绝不回落 0x00** / 口令错回 `01 FF` / auth 子协议版本非法）+ 正确口令对照 | （见 §V） |
| `crates/xray-proxy-vmess/tests/error_variants.rs` | 未注册 authID → **`UserNotFound`**（凭据校验本体）· 截断 authID → `Io`（不得 panic/放行） | 2 passed |

**三条「审计映射需修正」的实证发现（报告 PM，不改产品代码）：**

1. **`Ss2022Inbound::new` 的空 PSK 变体与 doc 不符**：doc 头声明「PSK 为空 →
   `Ss2022MissingKey`」，实际走 `derive_psk` 的**长度**分支 → `InvalidPassword("PSK length 0 <
   key_size 32")`。测试按**实际**行为断言并留注释：补 MissingKey 分支或改 doc 都会让该用例变红。
   附：`derive_psk` 的真实规则是「等长直通 / **太长 SHA-256 截断放行** / **太短报错**」
   （sing-shadowsocks `Key()` 语义）——审计 §2.1 的「PSK 长度不匹配」只在**短**方向成立。
2. **`VmessError::InvalidAuth` 不是凭据校验**：审计 §2.1 把它列为「auth id 校验本体」，
   实测未注册 authID 返回 **`VmessError::UserNotFound`**（`validator.rs::get_aead` →
   `AuthIDDecoderHolder::match_auth_id`）；`InvalidAuth` 是**解密后头部 payload 的 FNV1a
   校验和不符**（`encoding/server.rs:282`，篡改检测）。二者都在凭据/完整性面，但触发条件不同，
   测试按真实分层断言（未注册 → `UserNotFound`）。
3. **`TrojanError::EmptyEmail` 只属 `del`，不属 `add`**：Go `Validator.Add` 对空 email 是
   **放行**的（空 email = 不登记 email 索引、只按 key 认证），`GetCount` 因此恒按 email 索引计
   （空 email 用户 `get_count()` 为 0，`get_key_count()` 才是可认证用户数）。测试双向钉住该语义。

**本轮未覆盖（按票面口径清单，可触达性已实测）**：

| 变体 | 为什么只能 src 面 |
|---|---|
| `SsError::Ss2022SaltNotUnique` / `Ss2022TimestampCheck` / `Ss2022InvalidHeaderType` | 只有 `handle_conn` 的 AEAD 解密之后才判定；`Ss2022Inbound::handle` 需真 TCP 流 + 合法密文构造（本质是 e2e，属既有 e2e 覆盖策略） |
| `VmessError::UnknownCommand` / `InvalidTime` / `InvalidAuth` | 需先构造**合法加密头**（客户端 encoder pub）+ 真实用户，再篡改单字节/时间戳；anti-replay 面还要时钟注入（建议单开票） |
| `trojan` 五个帧截断变体（`ReadUserHash`/`ReadPayloadLength`/`ReadCrlf`/`ReadCommand`/`ReadAddressPort`） | 请求帧读取函数非 pub（`server.rs` 内私有）；需 src 面加参数化截断单测 |
| `tuic` / `wg` / `tun` / `dns` / 三个 transport 的错误映射 | 变体经底层库错误映射得出，需在 src 面注入故障源 |

---

### 1gkcf（P1）dokodemo fakeudp 测试 reactor —— 代码 DONE（Linux root + 非特权双身份实测），特权 job 只出方案

**缺陷复现口径（审计实测，ground truth）**：`tproxy_gate_is_runtime_semantics_not_compiled_away`
是裸 `#[test]`；`fake_udp_linux` 末尾 `tokio::net::UdpSocket::from_std` 需要 reactor →
**root（生产 VPS 形态）= FAILED / nobody = ok**。

**改法（`crates/xray-proxy-dokodemo/tests/plugin_contract.rs`）**：

- `#[test]` → `#[tokio::test]`（提供 reactor）；
- Linux 分支从 `let _ = result;`（零断言）改为**两态断言**：
  - `Ok` → 断言绑到请求的本地地址 + **在同一个 runtime 里真收发包**（1 发 1 收 + 源地址核对）
    —— 这才是「socket 真属于本 reactor」的证据；
  - `Err` → 断言 `ErrorKind::PermissionDenied`（证明是 CAP_NET_ADMIN 权限门，不是别的错）。

**CI 特权 job 方案（`.github/workflows/**` 红线，待授权，未执行）**：

```diff
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -176,6 +176,44 @@ jobs:
       - run: cargo test --workspace --release
 
+  # 特权面（TPROXY / fakeudp / SO_MARK / IP_TRANSPARENT / TUN）：
+  # 非特权 runner 上这些路径**恒走 EPERM 分支**，等于没测（jf1wv/1gkcf 实证：
+  # 同一测试 root 红、非 root 绿）。本 job 只跑特权相关子集，控时长。
+  test-linux-privileged:
+    name: Test (linux privileged: net admin)
+    runs-on: ubuntu-latest
+    timeout-minutes: 30
+    env:
+      RUST_MIN_STACK: 16777216
+    steps:
+      - uses: actions/checkout@v4
+      - uses: ./.github/actions/fetch-udf
+      - uses: dtolnay/rust-toolchain@stable
+      - uses: Swatinem/rust-cache@v2
+        with:
+          prefix-key: test-linux-priv
+          key: ${{ env.UDF_HEAD }}
+      - name: Install protoc
+        run: sudo apt-get update -q && sudo apt-get install -y -q protobuf-compiler
+      - uses: ./.github/actions/setup-boringssl
+      # sysctl 同 test job（SO_RCVBUF 断言需要 rmem_max ≥ 8MB）
+      - name: Raise rmem_max
+        run: sudo sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608
+      # 特权分支：sudo 保留环境（cargo/rustup 在 runner 用户 home，须 -E + PATH）
+      - name: Privileged subset (sudo)
+        run: |
+          sudo -E env "PATH=$PATH" \
+            cargo test -p xray-transport --test udp_tproxy_chain -- --nocapture
+          sudo -E env "PATH=$PATH" \
+            cargo test -p xray-proxy-dokodemo --test plugin_contract tproxy_gate -- --nocapture
+      # 反证：同一二进制以 nobody 跑，必须走权限门分支（两身份都要覆盖）
+      - name: Unprivileged counter-check (setpriv nobody)
+        run: |
+          bin=$(ls -t target/debug/deps/udp_tproxy_chain-* | grep -v '\.d$' | head -1)
+          cp "$bin" /tmp/tproxy_unpriv && chmod 755 /tmp/tproxy_unpriv
+          setpriv --reuid=65534 --regid=65534 --clear-groups /tmp/tproxy_unpriv --nocapture
```

风险：`sudo` 下 cargo 会另建 fingerprint（不吃非特权缓存）→ 该 job 首次全量编译 ~15-20min；
建议 `prefix-key: test-linux-priv` 独立缓存 + 只跑两个 test target（不是 `--workspace`）。

---

### jf1wv（P1）UDP TPROXY 链最小断言 —— 代码 DONE（公开 API 覆盖整条链），特权 job 同 1gkcf 方案

**新增 `crates/xray-transport/tests/udp_tproxy_chain.rs`（Linux-only，`#![cfg(target_os = "linux")]`）**：
不碰内部函数，全部走公开 API `UdpHub::listen(addr, &options(..), None)`。

| 用例 | 断言 | 触达的内部链 | 现状 |
|---|---|---|---|
| `tproxy_bind_is_privilege_gated_and_binds_requested_addr` | 特权 → bind 成功 + `local_addr` 是请求地址 + 端口非 0 + `close()` 可调；非特权 → `PermissionDenied` | `bind_udp_tproxy_linux` 的 `IP_TRANSPARENT`/`IP_RECVORIGDSTADDR`/`bind` 三个点 | **PASS**（root + nobody 双身份实测） |
| `plain_hub_roundtrip_delivers_packet` | 不开 TPROXY：`payload`/`source` 正确且 `target == None` | 普通 `recv_from` 循环（对照组，证明 hub 本体没坏、`target` 开关真有判别力） | **PASS** |
| `tproxy_v4_chain_reports_original_destination` | `target == Some(hub 绑定地址)`（v4 cmsg 解析） | `start_recv_loop_tproxy_linux` → `parse_orig_dst_from_cmsg` v4 臂 | `#[ignore]`（被下述**产品缺陷**阻断） |
| `tproxy_v6_chain_reports_original_destination` | `target == Some(::1 绑定地址)` | `IPV6_*` + `is_ipv6_origdst_cmsg` v6 臂 | `#[ignore]`（同上） |
| `tproxy_recv_loop_must_not_starve_current_thread_runtime` | 首包之后 current_thread runtime 必须能 `sleep(20ms)`（≤200ms 醒） | 收包循环的让出语义 | `#[ignore]`（同上；修复后即回归门） |

### ⚠ 本票实测出的产品缺陷（P0 级，`crates/xray-transport/src/udp/hub.rs`）——**已修复（PM 专项授权：本组唯一 src 改动）**

**缺陷机制**：旧 `start_recv_loop_tproxy_linux` 是 `socket.readable().await` → 绕过 `try_io`
直调 `socket2::SockRef::recvmsg` → WouldBlock 就 `continue`。tokio 的 readiness 缓存**只由
`try_io`/`async_io` 清除**，于是**收到第一个包之后**每轮 `readable()` 立即 Ready、`recvmsg`
恒 WouldBlock → `continue` = **热自旋**。真 Linux root 实测：`/usr/bin/time` 报
`CPU user=8.09 sys=1.90 wall=10.00`（整核 100%，到点被 timeout 杀），任何依赖收包循环的
断言都把 runtime 饿死 → 挂死。

**生产影响**：TPROXY UDP 是 dokodemo `followRedirect` 在真 Linux VPS 上的**唯一** UDP 透明
代理路径——多线程 runtime 不挂死，但**持续烧满一个核**；该路径此前零测试所以从未被发现。

**修复落地**（`crates/xray-transport/src/udp/hub.rs::start_recv_loop_tproxy_linux`，约
:409-489，两处结构变化）：

1. `recvmsg` 改走 `socket.try_io(Interest::READABLE, || SockRef::from(&*socket).recvmsg(..))`
   ——WouldBlock 时 `try_io` **清 readiness 缓存**，随后才 `readable().await`（这次才真挂起）；
   close 信号仍走 `select!` 可随时打断；
2. 草案没预料到的一步：`MsgHdrMut` 内持裸指针**非 `Send`**，草案形态会把「msg 活到
   select await」导致 future `!Send`（`FxScope::spawn_tracked` 编译错）。实现把「构造 msg +
   `try_io` + 抄出 control_len/source」收进**块内**，结果以
   `enum Attempt { Packet { .. }, WouldBlock }` 数据形式带出，await 期间不持有任何非 Send 状态。

**修复前后实测对比**（同一场景：wall 10s 预算 + 同一二进制参数）：

| | 修复前 | 修复后 |
|---|---|---|
| `/usr/bin/time -f "CPU user=%U sys=%S wall=%e" timeout 10 <bin> --test-threads=1 tproxy_v4_chain` | **user=8.09 sys=1.90 wall=10.00**（整核烧满，到点被杀） | **user=0.00 sys=0.00 wall=0.02**（suite 自行跑完，5 passed） |
| 3 条回归门（v4 链 / v6 链 / starve 探针，`#[ignore]` 已全部移除） | 挂死：`timeout 240` 整套件到点杀，输出停在 `tproxy_recv_loop_must_not_starve_current_thread_runtime ...`（两轮复现，240s/400s 预算） | **5 passed / 0 failed / 0.03s**（root 与 `setpriv --reuid=65534` 双身份各一遍全绿） |
| `cargo test -p xray-transport --lib`（Windows） | — | 绿（§V.6） |
| `cargo clippy -p xray-transport --all-targets -- -D warnings` | — | 绿（§V.6） |

**反证（回归门是真门）**：只删 `#[ignore]` 不修代码时，starve 用例必挂死（CI 超时即红），
不会静默绿；上方「修复前」两行即该反证的实测记录。

---

### 附加授权修复 ②：`xray-proxy-anytls/src/uot.rs` 空载荷挂死（PM 二次专项授权，同「仅此一处」模式）

- **定性**（来自 86i4hPhase2 报告 + 本组静态复核）：`LengthFramedWriter::write_multi_buffer`
  开头 `if mb.is_empty() { return Ok(()) }` 不写任何字节；`tests` 的 `length_framed_roundtrip`
  空载荷分支构造的正是空 `MultiBuffer` → writer 不写、reader 等 2 字节帧头 → **永久 await**。
  归因 `git log -S"mb.is_empty()"` = 仅波1 `98c8a360`（yfcnr UOT 帧实现），非在途改动。
  行为语义 = 空 datagram 静默丢（Go uot 长度前缀无条件先写）。
- **修法**：删 early-return，空 `MultiBuffer` 也写出 `[0x00,0x00]` 帧头（`mb.len()` u16 上限
  检查保留并前移）；reader 本就支持 `len==0`（`Buffer::with_capacity(len.max(1))` 分支），
  无需改。
- **回归门**：原 `length_framed_roundtrip` 空载荷分支保留（Main 明确不许删）+ 新增
  `empty_datagram_emits_zero_length_frame_on_wire`——空载荷写出后**对端 raw 读到恰好
  `[0x00,0x00]`**（5s 超时墙钟，写端吞帧即红）。
- **验证**：`cargo test -p xray-proxy-anytls --lib` = **39 passed / 0 failed，test 阶段
  0.31s**（修复前：该单测挂死 >60s，86i4hPhase2 实测；修复后 uot 过滤 6/6 含两条新门）；
  `cargo clippy -p xray-proxy-anytls --all-targets -- -D warnings` 零告警；`cargo fmt
  -p xray-proxy-anytls -- --check` 净。

---

### 附加授权修复 ③：全量 `--all-targets` 暴露的 3 条「测试期望没跟上产品行为」（PM 三次专项授权）

三条都由「波1/波2 产品行为变更」引起，修法是**更新测试**，产品校验一行未放宽。

| # | 位置 | 失败原因（产品新语义） | 修法 | 验证 |
|---|---|---|---|---|
| ① | `crates/xray-proxy-anytls/tests/inbound_dispatch.rs` `inbound_dispatches_via_router` | `start()` 报 `ListenError("anytls inbound requires settings.password …")` —— 波1 `bz800`（无口令 = 零认证 → 拒启，P1 安全票） | handler 链补 `.with_password(Some("test-password"))`（与客户端同值），注释点名 bd bz800；**产品校验不动** | `cargo test -p xray-proxy-anytls --test inbound_dispatch` → **1 passed / 0.02s** |
| ② | `crates/xray-transport-hysteria/src/quic_params.rs` `validation_rejects_go_parity` | `unwrap_err()` on `Ok` —— G11 `x0f0r` 把 `quicParams.udpHop` 改为「整键忽略 + warn 指路 `finalmask.udp[{type:"udphop"}]`」（Go 26.10.17 无该字段），旧的 4 条 `bad(udpHop…)` 断言的是已废除的硬拒启 | 从 `bad()` 列表删除 4 条 udpHop 用例 + 新增反转门 `udphop_key_is_ignored_not_rejected`（6 种畸形 udpHop 全须 **Ok 且 `udp_hop.is_none()`**，并断言相邻键 `maxIdleTimeout` 照常解析防「整段短路」）；warn 点在 `quic_params.rs:90-93` 有注释锚定，日志捕获因 callsite-interest 缓存 flake 不做（理由写进测试注释） | `cargo test -p xray-transport-hysteria --lib quic_params` → **8 passed / 0.00s**（含新门） |
| ③ | `tests/integration/grpc_multimode_e2e_test.rs` `grpc_tls_via_vless_e2e` | `echo timeout` —— 波2 G6 `mwvwd` 删掉 rcgen 自签回退：服务端 `security=tls` 缺 `tlsSettings.certificates` 时**每条连接握手失败**（对齐 Go） | 新增 `server_settings_with_cert()`：仅当 `security=tls` 时用 `xray_tls::certificate::generate_self_signed_cert(&["localhost"])` 现场生成 PEM 并注入服务端 `tlsSettings.certificates`；客户端配置不变（`allowInsecure` 只作用客户端验链）。4 个变体共用该 helper，非 TLS 变体零影响 | `cargo test -p xray-integration-tests --test integration_grpc_multimode grpc_tls_via_vless_e2e` → **1 passed / 1.05s** |

**整包验收（三包 `--all-targets` + clippy + fmt）**：

```
cargo test -p xray-proxy-anytls -p xray-transport-hysteria -p xray-integration-tests --all-targets
  → 全部套件 ok（0 failed；ignored 项为本仓既有 #[ignore] 的 VPS/interop 用例）
cargo clippy -p <上三包> --all-targets -- -D warnings   → Finished，零告警
cargo fmt -p <上三包> -- --check                          → FMT_ALL_OK
```

**未碰（PM 指定既有红）**：`xray-proxy-vless|vmess --lib *_outbound_udp_roundtrip_e2e`（P0Wire 用 stash 基线证实修前同红）、
`xray-transport-splithttp --lib h3_server_receives_stream_one`（bd 1xfap）。

---

### 3t30l（P1）Linux 产物 32/32 门 + release build 验证 —— 只出方案（`dist/` 与 workflows 均红线）

**现状（实测定位）**：
- 32/32 唯一入口 `tools/night_probe32_ci.py` 用 **Windows** CI 产物跑 32 节点（Linux 产物只做
  「换核 + `systemctl active` + 监听端口数」= 不作功能验证）；
- `release.yml` 的 5 个产物 job **零测试步**；
- `build-linux-release.yml`（PGO 线，生产实际部署的那条）唯一的测试是
  `cargo test -p xray-reality --test reality_tls_smoke` —— **跑的是源码编出的测试二进制，
  不是上传的那个产物**，`file` 只验 ELF 形态。

**方案 A（最小、可立刻接）：release 产物冒烟（release.yml，待授权）**

```diff
--- a/.github/workflows/release.yml
+++ b/.github/workflows/release.yml
@@ -110,6 +110,14 @@ jobs:
         if: matrix.target != 'x86_64-unknown-linux-musl'
         run: cargo build --release -p xray-cli --target ${{ matrix.target }}
+      # 产物冒烟（3t30l F8）：发出的二进制必须**被亲跑一次** —— glibc 兼容、
+      # 动态链接、数据面 pump 三项都只有真执行才验得到（file/version 都不够）。
+      - name: Smoke the produced artifact (linux)
+        if: startsWith(matrix.target, 'x86_64-unknown-linux')
+        run: |
+          set -euo pipefail
+          bin="target/${{ matrix.target }}/release/${{ matrix.bin }}"
+          "$bin" version
+          python3 tools/smoke_release_bin.py "$bin"
       - name: Upload artifact
         uses: actions/upload-artifact@v4
         with:
```
新增 `tools/smoke_release_bin.py`（约 60 行，零外网依赖）：起临时目录 → 生成
`socks 127.0.0.1:0 → freedom` 最小配置 → 起二进制 → 本地 Python echo 服务 →
`curl -x socks5h://…` 断言 body 一致 → 收工 kill。判据是「产物真能转发 UDP/TCP」，
不是「版本号打得出来」。
musl 目标跳过（静态二进制无 glibc 风险，且需 musl 运行时才能跑）——可在 QEMU/binfmt
job 里另建（非阻塞）。

**方案 B（32/32 进 Linux CI，需 secret + 新 workflow，待授权）**

```diff
--- /dev/null
+++ b/.github/workflows/e2e-nightly.yml
@@ -0,0 +1,58 @@
+# 32/32 真机矩阵（3t30l F7）：用户部署的是 Linux 产物，而 32/32 只在 Windows 跑过。
+# 本 workflow 用**这次构建出来的 Linux 产物**打真节点，验收口径与 run_full32 一致。
+name: e2e-nightly
+on:
+  schedule: [{ cron: '0 17 * * *' }]   # 05:00 CST
+  workflow_dispatch:
+jobs:
+  full32-linux:
+    runs-on: ubuntu-24.04
+    timeout-minutes: 60
+    steps:
+      - uses: actions/checkout@v4
+      - uses: ./.github/actions/fetch-udf
+      - uses: dtolnay/rust-toolchain@stable
+      - uses: Swatinem/rust-cache@v2
+        with: { prefix-key: e2e-nightly, key: '${{ env.UDF_HEAD }}' }
+      - name: Install protoc
+        run: sudo apt-get update -q && sudo apt-get install -y -q protobuf-compiler
+      - uses: ./.github/actions/setup-boringssl
+      - run: cargo build --release -p xray-cli
+      # 节点表 = secret（含真实凭据，不入库、不进 artifact）。
+      # 需用户在仓库 Settings → Secrets 增加 XRAY_NODES_TXT（base64 的 test.txt）。
+      - name: Materialize node list
+        env: { NODES_B64: '${{ secrets.XRAY_NODES_TXT }}' }
+        run: |
+          set -euo pipefail
+          test -n "$NODES_B64" || { echo "secret XRAY_NODES_TXT 未配置"; exit 1; }
+          echo "$NODES_B64" | base64 -d > /tmp/nodes.txt
+          grep -vc '^#' /tmp/nodes.txt
+      - name: 32/32 with the Linux artifact
+        run: |
+          python3 dist/run_full32.py \
+            --bin target/release/xray \
+            --uri-file /tmp/nodes.txt \
+            --work /tmp/w32 \
+            --url https://www.youtube.com/
+      - name: Cleanup node list
+        if: always()
+        run: rm -f /tmp/nodes.txt
+      - uses: actions/upload-artifact@v4
+        if: always()
+        with: { name: full32-linux-log, path: /tmp/w32/f_results.txt }
```

前置/风险：
1. `dist/run_full32.py` 用 `curl` + `subprocess.terminate()`，Linux 下可用（无 Windows API）——**已读码确认**；
2. 真节点凭据进 secret 是新的凭据面，需用户拍板（OPS 侧）；
3. 时长不可控（32 节点 × ~15s ≈ 8min，含 2.5s sleep/节点），只挂 `schedule`，不挂 PR。

---

### t3wtj（P1）差分门基线 26.9.9 → 26.10.17 —— 只出方案（workflows 红线，**待用户授权**）

**实证定位**：
- `ci.yml` parser-parity：`Xray-core/releases/download/v26.9.9/Xray-linux-64.zip` +
  `sha256 1eb9175d…f58b7df`（双钉）；
- `interop.yml`：`v26.9.9/$asset`（**只钉 tag，无 digest**）；
- `dist/interop_ci.py:11` docstring 与默认套件口径写着「Go 26.9.9 全支持」；
- `dist/interop_matrix.py` **已引 26.10.17**（说明新基线在本仓已有共识，只差两个门）。
- ⚠ **26.10.17 的官方产物不可得**：仓库该 tag 的 release API 返回 404（ticket 说本机裁定基准在
  `D:/tmp/go2617/xray.exe`，那是 **Windows 二进制**，与 CI 需要的 `Xray-linux-64.zip`
  不是同一个 artifact → digest 不能互推）。**故本方案不编造 sha256**，给出获取与换钉的程序。

**diff 草案（3 个文件；`PLACEHOLDER` 由授权后的第一步填入）**

```diff
--- /dev/null
+++ b/.github/actions/go-baseline/action.yml
@@ -0,0 +1,58 @@
+# Go 差分基线（唯一来源）——parser-parity 与 interop 两个门都从这里取，
+# 版本/digest 只在本文件出现一次（t3wtj：此前两个门各自硬编码 tag，already drifted）。
+#
+# 换基线流程（一次性，须在能联网的机器上做）：
+#   1) curl -fsSLO https://github.com/XTLS/Xray-core/releases/download/v26.10.17/Xray-linux-64.zip
+#      sha256sum Xray-linux-64.zip       # → 填进下面 *_SHA256 之一
+#   2) 同法取 macOS 产物（macos-arm64-v8a）/（macos-64）并各填一份
+#   3) 两个门跑一遍 --dry-run 与实跑，把**预期差异**逐条登记进 allowlist（见风险 §2）
+name: Go baseline (Xray-core 裁定基准)
+description: 下载 sha256 钉死的 Go 参照二进制并解出 xray
+inputs:
+  asset:
+    description: release asset 名（Xray-linux-64.zip / Xray-macos-arm64-v8a.zip / Xray-macos-64.zip）
+    required: true
+  dest:
+    description: 解出 xray 的目录
+    required: false
+    default: tools/xray-go
+runs:
+  using: composite
+  steps:
+    - name: Download + sha256 verify + extract
+      shell: bash
+      env:
+        GO_BASELINE_VERSION: v26.10.17
+        SHA256_Xray_linux_64: "PLACEHOLDER"
+        SHA256_Xray_macos_arm64_v8a: "PLACEHOLDER"
+        SHA256_Xray_macos_64: "PLACEHOLDER"
+        ASSET: ${{ inputs.asset }}
+        DEST: ${{ inputs.dest }}
+      run: |
+        set -euo pipefail
+        key="SHA256_$(echo "$ASSET" | sed 's/[^A-Za-z0-9]/_/g')"
+        want="$(printenv "$key" || true)"
+        if [ -z "$want" ] || [ "$want" = "PLACEHOLDER" ]; then
+          echo "::error::go-baseline: $ASSET 的 sha256 未登记（见本 action 头流程）"; exit 1
+        fi
+        url="https://github.com/XTLS/Xray-core/releases/download/${GO_BASELINE_VERSION}/${ASSET}"
+        curl -fsSL -o /tmp/xray-go.zip "$url"
+        echo "$want  /tmp/xray-go.zip" | sha256sum -c -
+        mkdir -p "$DEST"
+        unzip -o /tmp/xray-go.zip -d "$DEST" xray
+        chmod +x "$DEST/xray"
+        "$DEST/xray" version
```

```diff
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -214,7 +214,7 @@
   parser-parity:
-    name: Parser Parity (Go v26.9.9 vs Rust)
+    name: Parser Parity (Go baseline vs Rust)
@@ -236,16 +236,10 @@
-      # Go 参照：官方 release（interop.yml 同配方）；对拍门参照须逐字节确定，
-      # 故在 tag 之上再加官方 API digest 校验。21MB 下载秒级，不做缓存。
-      - name: Download Go reference (Xray-core v26.9.9, sha256-pinned)
-        run: |
-          set -euo pipefail
-          curl -fsSL -o /tmp/xray-go.zip \
-            https://github.com/XTLS/Xray-core/releases/download/v26.9.9/Xray-linux-64.zip
-          echo "1eb9175d0f0a8f8149c9230a7fc5ae66ce332ed20a53155ce61fe62e3f58b7df  /tmp/xray-go.zip" | sha256sum -c -
-          mkdir -p /tmp/xray-go
-          unzip -o /tmp/xray-go.zip -d /tmp/xray-go xray
-          chmod +x /tmp/xray-go/xray
-          /tmp/xray-go/xray version
+      # 基线唯一来源：.github/actions/go-baseline（版本+digest 单点登记，t3wtj）
+      - uses: ./.github/actions/go-baseline
+        with: { asset: Xray-linux-64.zip, dest: /tmp/xray-go }
```

```diff
--- a/.github/workflows/interop.yml
+++ b/.github/workflows/interop.yml
@@ -82,16 +82,11 @@
-      # Go 基线 = 官方 release 二进制 (禁 git clone 全仓构建)
-      - name: Download Go baseline (xray-core v26.9.9)
-        shell: bash
-        run: |
-          set -euo pipefail
-          case "$RUNNER_OS:$(uname -m)" in
-            macOS:arm64)   asset=Xray-macos-arm64-v8a.zip ;;
-            macOS:x86_64)  asset=Xray-macos-64.zip ;;
-            Linux:x86_64)  asset=Xray-linux-64.zip ;;
-            Linux:aarch64) asset=Xray-linux-arm64-v8a.zip ;;
-            *) echo "unsupported platform: $RUNNER_OS $(uname -m)"; exit 1 ;;
-          esac
-          curl -fsSL -o /tmp/xray-go.zip \
-            "https://github.com/XTLS/Xray-core/releases/download/v26.9.9/$asset"
-          mkdir -p tools/xray-go
-          unzip -o /tmp/xray-go.zip -d tools/xray-go xray
-          chmod +x tools/xray-go/xray
-          tools/xray-go/xray version
+      # Go 基线 = 官方 release 二进制（禁 git clone 全仓构建）。
+      # 版本/digest 单点在 .github/actions/go-baseline；新增平台先在该 action 登记 digest。
+      - name: Select asset by platform
+        id: goasset
+        shell: bash
+        run: |
+          case "$RUNNER_OS:$(uname -m)" in
+            macOS:arm64)   echo "asset=Xray-macos-arm64-v8a.zip" >> "$GITHUB_OUTPUT" ;;
+            macOS:x86_64)  echo "asset=Xray-macos-64.zip" >> "$GITHUB_OUTPUT" ;;
+            Linux:x86_64)  echo "asset=Xray-linux-64.zip" >> "$GITHUB_OUTPUT" ;;
+            *) echo "::error::unsupported platform: $RUNNER_OS $(uname -m)"; exit 1 ;;
+          esac
+      - uses: ./.github/actions/go-baseline
+        with:
+          asset: ${{ steps.goasset.outputs.asset }}
+          dest: tools/xray-go
```

**影响面（必须一起改，否则门永远绿不了或永远红）**

| 面 | 影响 | 处理 |
|---|---|---|
| `dist/interop_ci.py:11` docstring + 默认套件口径 | 文案过期 | 一并改（`dist/` 授权后） |
| parser-parity 57 例 | 26.10.x 的上游修复会让**预期差异**出现 | 先本地跑 `parity.py` 出差异台账，逐条 allowlist + 上游 commit 依据（Go 镜像 `D:/Project/Xray-core` 在 `92ccc939`） |
| interop 57 例（12+12+12+21） | 同上；hysteria2/anytls/tuic/naive 的 Go 支持面可能变化 | 同上；`interop_ci.py --dry-run` 先列清单 |
| Linux aarch64 | 旧门只在 x86_64 跑，新门若保留 aarch64 分支需先取该 asset 的 digest | 本草案 **显式只登记 3 个 asset**，aarch64 落到 `unsupported` 显式失败（宁红不假绿） |

**风险**
1. 换基线当轮 CI **必然红一次**（差异台账未登记）——建议授权后按「PR 只改 action + 两门引用（digest 全 PLACEHOLDER）→ 独立 PR 填 digest → 独立 PR 登记差异」三步走，避免一次红三件事。
2. `PLACEHOLDER` 会让两个门**立刻失败**（设计如此：宁可红也不静默用旧基线）。
3. 裁定基准从 26.9.9 提到 26.10.17 后，**本仓历史上按 26.9.9 判「通过」的对拍结论需重跑**——这属于审计结论面，须在提交信息里写清。

---

### 0m0f6（P2）interop 门 PR 触发 + run_full32 接入 —— 只出方案（workflows + `dist/` 红线，待授权）

**实证定位**：

| 审计主张 | 实测 |
|---|---|
| `interop.yml` 无 `pull_request` 触发 | **成立**：`on: workflow_dispatch` + `push: [master, main, dev, 'feature/**']` |
| 11 个 `dist/interop_*.py` 只接了 1 个 | **部分成立**：`interop_ci.py` 是 `interop_matrix.py` 的 POSIX 移植版（`rust`/`go`/`rust_to_go`/`extra`=57 测）→ 协议矩阵其实覆盖了；**未接**的是 `interop_kcp.py`（mKCP 传输）/`interop_httpupgrade.py`/`interop_grpc.py`/`interop_splithttp.py`/`interop_reality.py`/`interop_hysteria.py`/`interop_enc.py`/`interop_ext.py`/`interop_gogo.py` 这些**独立 harness** |
| `run_full32.py` 未接任何 workflow | **成立** |
| 这 9 个脚本能否直接接 CI | **不能**：每个都硬编码 `RUST='dist/xray.exe'`、`GO='D:/Project/Xray-core/target/xray-go.exe'`、`WORK='D:/tmp/...'`（Windows 路径）→ 必须先参数化 |

**diff 草案**

```diff
--- a/.github/workflows/interop.yml
+++ b/.github/workflows/interop.yml
@@ -3,7 +3,10 @@
 on:
   workflow_dispatch:
   push:
     branches: [master, main, dev, 'feature/**']
+  # 0m0f6 ①：PR 阶段也要互通门——此前只在 push 到上述分支时跑，
+  # 等于「PR 上的协议回归零拦截」（私仓，无 fork secret 顾虑）。
+  pull_request:
+    branches: [main, master, 'feature/**']
@@ -100,6 +103,25 @@
       - name: Interop tests (Rust<->Rust 12 + Go->Rust 12 + Rust->Go 12 + extra 18 = 54, Go 不支持的方向 runtime 探测自动跳过)
         run: python3 dist/interop_ci.py --rust target/release/xray --go tools/xray-go/xray
 
+      # 0m0f6 ②：传输层 harness（interop_ci 不覆盖 mKCP / HTTPUpgrade）。
+      # 前置：两个脚本已参数化（INTEROP_RUST / INTEROP_GO / INTEROP_WORK 环境变量，
+      # 见 dist/interop_kcp.py、dist/interop_httpupgrade.py 的 RUST/GO/WORK 三行改为
+      # os.environ.get(...)）；未参数化前本步会因 Windows 硬编码路径直接失败。
+      - name: Interop transports (kcp + httpupgrade)
+        if: runner.os == 'Linux'
+        env:
+          INTEROP_RUST: target/release/xray
+          INTEROP_GO: tools/xray-go/xray
+          INTEROP_WORK: /tmp/interop-tx
+        run: |
+          set -euo pipefail
+          python3 dist/interop_kcp.py
+          python3 dist/interop_httpupgrade.py
+
       - name: Upload logs on failure
```
（③ `run_full32.py` 接入见 3t30l 方案 B 的 `e2e-nightly.yml`：它需要节点表 secret，
放在 schedule 上而不放在 PR 上，避免用 PR 凭据跑真节点。）

**影响面 / 风险**

| 项 | 影响 | 缓解 |
|---|---|---|
| `pull_request` 触发 | 每个 PR +2~3 个 job（macos-14 + ubuntu-24.04 × 60min 上限） | 若时长不可接受：`pull_request` 只留 `ubuntu-24.04`（macOS 留 push/schedule）——一条 `if:` 即可，草案里可加 `if: github.event_name != 'pull_request' \|\| matrix.os == 'ubuntu-24.04'` |
| 传输层 harness 参数化 | 9 个脚本各改 3 行（`os.environ.get`）；`dist/` 是红线 | 授权后单独 PR，只动 3 行/脚本，不动用例逻辑 |
| 真机 32/32 | 依赖节点凭据 secret；跑批可能被节点限速 | nightly + `workflow_dispatch`，不进 PR |

---

## 【验证命令 + 关键输出】

环境（每条 cargo 前置）：`BORING_BSSL_PATH=target/boringssl-asm/prebuilt`、
`BORING_BSSL_ASSUME_PATCHED=1`、`PROTOC=D:/Project/tools/bin/protoc.exe`、
`LIBCLANG_PATH="D:/Program Files/llvm/bin"`、`CARGO_TARGET_DIR=target-G9TestCI`、
`CARGO_INCREMENTAL=0`。

### V.1 L4 契约夹具（16 个 crate，本次改动面）

```
for c in anytls blackhole dns dokodemo freedom http hysteria loopback socks ss trojan tuic tun vless vmess wireguard; do
  cargo test -p xray-proxy-$c --test plugin_contract
done
```

| crate | 结果 |
|---|---|
| anytls | ok. **10 passed**; 0 failed |
| blackhole | ok. **9 passed**; 0 failed |
| dns | ok. **11 passed**; 0 failed |
| dokodemo | ok. **9 passed**; 0 failed |
| freedom | ok. **12 passed**; 0 failed |
| http | ok. **7 passed**; 0 failed |
| hysteria | ok. **12 passed**; 0 failed |
| loopback | ok. **11 passed**; 0 failed |
| socks | ok. **10 passed**; 0 failed |
| ss | ok. **17 passed**; 0 failed |
| trojan | ok. **12 passed**; 0 failed |
| tuic | ok. **9 passed**; 0 failed |
| tun | ok. **10 passed**; 0 failed |
| vless | ok. **14 passed**; 0 failed |
| vmess | ok. **12 passed**; 0 failed |
| wireguard | ok. **10 passed**; 0 failed |

合计 **185 passed / 0 failed**。

### V.2 错误变体补测（05ac1）

```
cargo test -p xray-proxy-trojan --test error_variants   → ok. 6 passed
cargo test -p xray-proxy-ss     --test error_variants   → ok. 8 passed
cargo test -p xray-proxy-socks  --test error_variants   → ok. 4 passed
cargo test -p xray-proxy-vmess  --test error_variants   → ok. 2 passed
```
合计 **20 passed / 0 failed**。判别力自证：`ss` 的 `psk_length_mismatch_is_rejected` 首轮红在
「错误文案须点名两侧长度: PSK length 14 < key_size 32」（我自己把 16B 基准串写成了 14B →
被断言抓住并修正），说明断言不是自证式。

### V.3 dokodemo fakeudp reactor（1gkcf）—— 三身份

```
Windows（本机，非 Linux 分支）：cargo test -p xray-proxy-dokodemo --test plugin_contract tproxy_gate
  test tproxy_gate_is_runtime_semantics_not_compiled_away ... ok   （1 passed）
WSL ubuntu-xray root（生产 VPS 形态）：
  test tproxy_gate_is_runtime_semantics_not_compiled_away ... ok   （1 passed）
WSL setpriv --reuid=65534（非特权）：
  test tproxy_gate_is_runtime_semantics_not_compiled_away ... ok   （1 passed）
```
修复前 root 恒 panic（审计实测 root=FAILED / nobody=ok）；现三身份全绿。

### V.4 UDP TPROXY 链（jf1wv）—— 真 Linux，双身份（hub.rs 修复后）

```
WSL root:   cargo test -p xray-transport --test udp_tproxy_chain -- --test-threads=1
  test plain_hub_roundtrip_delivers_packet ... ok
  test tproxy_bind_is_privilege_gated_and_binds_requested_port ... ok
  test tproxy_recv_loop_must_not_starve_current_thread_runtime ... ok
  test tproxy_v4_chain_reports_original_destination ... ok
  test tproxy_v6_chain_reports_original_destination ... ok
  test result: ok. 5 passed; 0 failed; 0 ignored; finished in 0.03s

WSL nobody: cp <bin> /tmp && chmod 755 && setpriv --reuid=65534 --regid=65534 --clear-groups <bin> --test-threads=1
  test result: ok. 5 passed; 0 failed; 0 ignored; finished in 0.00s
  （非特权身份下三条 chain 用例走「bind → PermissionDenied」合法分支）

修复前后 CPU 对比（/usr/bin/time，同一场景 wall 10s 预算）：
  修复前：user=8.09 sys=1.90 wall=10.00  （整核 100%，到点被 timeout 杀 = 热自旋）
  修复后：user=0.00 sys=0.00 wall=0.02   （suite 自行跑完 5 passed，含真实收发）

修复前反证（同二进制同参数，只删 #[ignore] 不修代码）：
  两条 chain/starve 用例挂死，timeout 240 整套件强杀（SUITE_EXIT 124），
  输出停在 tproxy_recv_loop_must_not_starve_current_thread_runtime ...
### V.5 fmt（CI 门口径：仓内钉的 nightly rustfmt）

```
rustfmt 1.9.0-nightly (57d06900fd 2026-05-27)
rustfmt --check --edition 2024 --config-path rustfmt.toml <本次改动/新增的 22 个文件>
  → 全部无 diff（FMT_OK）
```
（用 `rustfmt` 逐文件而非 `cargo fmt -p`：后者会连带格式化并行组正在编辑的 `src/`。）

### V.6 clippy

```
cargo clippy -p xray-transport -p xray-proxy-{anytls,blackhole,dns,dokodemo,freedom,http,hysteria,
  loopback,socks,ss,trojan,tuic,tun,vless,vmess} --all-targets -- -D warnings
  → Finished `dev` profile ... in 24.80s        （零 warning）
cargo clippy -p xray-proxy-wireguard --all-targets -- -D warnings
  → Finished `dev` profile ... in 40.72s        （零 warning）
```
**修复后复跑（hub.rs 改动落地的最终门）**：
```
cargo test -p xray-transport --lib                                    → ok. 675 passed; 0 failed (12.11s)
cargo clippy -p xray-transport --all-targets -- -D warnings           → Finished (零 warning)
```

过程中被 clippy 抓到并修掉 1 处**我方**问题（正是这类门该抓的）：
`crates/xray-proxy-socks/tests/error_variants.rs` 用了裸 `tokio::spawn` →
`clippy::disallowed_methods`（坑约束 5）→ 改成 `tokio::join!` 同 task 驱动两侧，零 spawn。
另有 1 处**兄弟组**的 `needless_borrow`（`xray-proxy-wireguard/src/inbound.rs:505`，
`spawn_reaping(&fx)` → `fx`），已 IRC 通知 86i4hPhase2 并由其修复后复跑绿。

### V.7 未跑的部分（诚实声明）

- **`cargo test --workspace --all-targets` 未跑**：同一棵树上 3 个兄弟代理正在改 `src/`
  （`xray-xudp/src/extension.rs` 一度破口、`xray-mux`/`xray-transport-hysteria` 中间态编译错
  各出现一次），全量跑得到的是别人的中间态。已改为「本组改动面逐 crate 全跑」= 16 + 4 + 1 个
  target 全绿。
- 既有失败已知两条（非本轮引入，PM 已确认）：`vless_outbound_udp_roundtrip_e2e`、
  `mux_bridge_dispatch_with_access_carries_global_id_for_udp` / `integration_udp_relay_through_outbound_mux`。

---

## 残差与新开票（PM 决议清单）

### A. 建议新开票（本组实测发现，均**未改产品代码**）

| # | 级别 | 位置 | 事实（证据在本文各节） |
|---|---|---|---|
| ~~N1~~ | **P0 → 已闭环（本组内修复）** | `crates/xray-transport/src/udp/hub.rs`（PM 专项授权，本组唯一 src 改动） | TPROXY 收包循环热自旋已修（`try_io` 清 readiness + msg 不跨 await），3 个 `#[ignore]` 全部转正为回归门；前后 CPU 实测与反证见 §jf1wv |
| N2 | P2 | `crates/xray-proxy-ss/src/ss2022/inbound.rs` doc | `new` 的 doc 声明「PSK 为空 → `Ss2022MissingKey`」，实际是 `InvalidPassword(0<32)`；另 `derive_psk` 是「太长 SHA-256 截断放行 / 太短报错」，审计 §2.1 的「长度不匹配」只在短方向成立 |
| N3 | P2 | `crates/xray-core/src/router.rs` + `functions.rs:200-202` | `PatternRouter` 已不在生产路（vaye2 修在装配层），但类型与 doc 仍宣称「失败时回退 PatternRouter」；⑦k7mj ③ 的测试因此断言的是一条死路径（diff 草案在 §7k7mj） |
| N4 | P3 | `crates/xray-frame/src/contract_assert.rs` | 宏丢弃 `deps()` 返回值（L5 deps 拓扑门对插件零鉴别力；`arm_registry.rs:187` 的 `expect("当前无 deps 声明")` 因此永不触发）—— diff 草案在 §amynv |

### B. 需 src 面（不在本组文件面，草案已给，未执行）

1. §7k7mj ③ 的 `router.rs` 测试反转 + `functions.rs` doc 修正。
2. §amynv 的 `deps()` 断言（`contract_assert.rs`）。
3. §05ac1 的帧级截断变体（trojan 五个 `Read*`、vmess 合法头构造、tuic/wg/tun/dns/transport 的错误映射）。

### C. 需用户授权（红线，方案已给，一行未动）

1. `t3wtj`：`.github/workflows/{ci,interop}.yml` + 新增 `.github/actions/go-baseline`。
2. `0m0f6`：`interop.yml` 加 `pull_request` + 传输层 harness 参数化（`dist/*.py` 各 3 行）。
3. `3t30l`：`release.yml` 产物冒烟 + 新增 `e2e-nightly.yml`（需 `XRAY_NODES_TXT` secret）。
4. `1gkcf`/`jf1wv` 的 `test-linux-privileged` job。

### D. 未做

- **未 commit / 未 push / 未 close bd 票**（归 PM）。8 张票的落地状态：`amynv`/`7k7mj`/`05ac1`/`1gkcf`/`jf1wv` 代码侧完成（含残差），`3t30l`/`t3wtj`/`0m0f6` **只有方案**。
- 未重跑 `codebase-memory` 索引（非目标）。
- 未跑 `cargo test --workspace --all-targets`（理由见 §V.7）。
- `target-G9TestCI` 已按契约删除（重建命令见 §V）。
