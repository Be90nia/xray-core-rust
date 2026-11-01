# 第四轮 · ConfigParity：Go 26.10.17 ↔ Rust HEAD 配置键接受度差分

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 裁定基准：`D:/tmp/go2617/xray.exe`（Xray 26.10.17，`92ccc93-dirty`，Go 源树 `D:/Project/Xray-core` @ `92ccc939`）
- 被测：`target/release/xray.exe`（`git_rev=5fe98b907c7b550d4a70202abb475e26ee89013d` = HEAD，**版本一致**）
- 端口段：ConfigParity 28000-28049；清理只按 PID；实例起停全部由探针脚本 `subprocess.Popen` 持句柄 + `terminate`
- 方法：**同一份输入字节 → 两侧各起真实实例 → 比可观测行为**（无源码推导代替实测）
- 脚本：`round4/scripts/probe4.py`（判据正确版）、`cases_v2.json`（47 例）、`cases_v5.json`（63 例）、`cases_v6.json`（15 例）、`cases_v7.json`（16 例）、`cases_v8.json`（16 例）
- 原始结果：`round4/tmp/results_v4_cases_{v2,v5,v6,v7,v8}.json`（**157 例全落盘，可复算**）

---

## 0 一句话结论

**Go 配置键宇宙 425 个，Rust 侧 415 个（97.6%）有解析点**；剩下的 10 个全部落在 Rust **未实现的两个传输**（xdrive / quic）内部，不是"漏读键"。

真正的缺口不在"键读不到"，而在**三个方向的口径差**：

1. **Rust 比 Go 严**（Go 能配、Rust 拒启）：5 个键 —— `streamSettings.masqueSettings` / `xdriveSettings` / `address` / `port` / `tlsSettings.useSystemCA`。这 5 个是**故意 fail-loud**（Rust 未实现对应能力），方向正确，但**用户从 Go 迁到 Rust 会撞墙且无迁移路径指引**。
2. **Rust 比 Go 宽**（Go 拒启、Rust 放行）：51 例中绝大多数是**前几轮已登记的同一根因**（装配期 warn+skip / 路由降级 PatternRouter / 探针样本无效 / 环境项）。**本轮新发现 4 条独立缺口**。另有一类**值形态**差异（Rust 多认 `{from,to}` 对象形态，Go 只认区间字符串）——属 Rust-only 方言扩展，Go 权威形态两侧都通，不开票（详见 §5.3）。
3. **Rust 接受但无消费点**（新）：3 条（同属 `finalmask.quicParams` 族在 splithttp H3 路径上的缺口），其中 **`memory_settings.rs` 的 `disablePathMTUDiscovery` 键名大小写写错**（与同仓 hysteria 实现矛盾）是唯一的「同仓两说」硬证据。

---

## 1 验收数字（可复算）

### 1.1 Go 配置键全集

| 项 | 数字 | 口径 |
|---|---|---|
| Go 用户配置键总数 | **425** | `D:/Project/Xray-core/infra/conf/**/*.go` 全部 `json:"..."` tag 去重（**136 个 struct / 727 条 tag 行**）。**不含** `app/**`——那里的 `json:` tag 是 protobuf 生成物（`config.pb.go` 的 `json:"name_server,omitempty"` 等），不是用户配置面（app 段的用户面由 infra/conf 定义）。 |
| Go 侧 `app/**` protobuf tag（不计入分母） | 210 | 其中 141 个为 app-only（`LocalIPs` / `NumGC` / `source_port` …） |
| 提取方式 | 见下方命令 | 可逐字复算 |

```bash
# Go 侧键全集（425）
python - <<'PY'
import re,os,collections
GO="D:/Project/Xray-core"
tag=re.compile(r'json:"([^",]*)')
keys=set()
for dp,_,fs in os.walk(GO+"/infra/conf"):
    for f in fs:
        if not f.endswith(".go") or f.endswith("_test.go"): continue
        for ln in open(os.path.join(dp,f),encoding="utf-8",errors="replace"):
            m=tag.search(ln)
            if m and m.group(1): keys.add(m.group(1))
print(len(keys))   # 425
PY
```

### 1.2 Rust 接受度（静态 + 实测双证）

| 分类 | 数字 | 口径 |
|---|---|---|
| **Rust 有解析点** | **415 / 425** | Rust 侧存在该键的 **serde 字段** 或 **引号字面量**（`.get("key")` / `get_bool("key")` / helper 传参），排除 `_test.rs` 与 `tests/` 目录 |
| **Rust 无解析点** | **10 / 425** | 全部集中在两个 Rust 未实现的传输内部 |
| **Rust 静默忽略**（有解析点但无消费点） | **3**（本轮新发现） | 见 §4 |
| **Rust 拒启**（Go 接受） | **5 键 / 4 类** | 见 §3 |
| **Rust 放行**（Go 拒启） | **51 例**，其中新发现 **4** | 见 §5 |

### 1.3 10 个无解析点的键（全部属 Rust 未实现的传输）

| 键 | Go 位置 | Go 语义 | Rust 状态 |
|---|---|---|---|
| `remoteFolder` | `infra/conf/transport_method.go:988` | XDrive 远端目录 | `xdriveSettings` 整体硬错 |
| `service` | `:989` | XDrive 服务类型（`google-drive`/`template`/`local`） | 同上 |
| `secrets` | `:990` | XDrive 三元凭据 | 同上 |
| `segmentBytes` | `:991` | XDrive 分段字节数 | 同上 |
| `flushIntervalMs` | `:992` | XDrive 刷写间隔 | 同上 |
| `pollIntervalMs` | `:993` | XDrive 轮询间隔 | 同上 |
| `maxPollIntervalMs` | `:994` | XDrive 轮询上限 | 同上 |
| `sessionTtlSeconds` | `:995` | XDrive 会话 TTL | 同上 |
| `eagerWindowMs` | `:997` | XDrive 预热窗 | 同上 |
| `holeTimeoutMs` | `:998` | XDrive 空洞超时 | 同上 |

（另 2 个 `disableChromeParrot` / `disableStatelessReset` 在 `QuicParamsConfig`——quinn 无等价旋钮，Rust 已显式登记不读不报错。）

> **结论**：425 键里 Rust 的 415/425 覆盖率不是"读到了 97.6%"，而是"**除两个 Rust 未实现的传输内部，其余键全部有解析点**"。这不是漏读，是能力边界。

---

## 2 方法学修正记录（两轮探针口径错误已修，防后人复踩）

| 轮次 | 错误 | 根因 | 修正 |
|---|---|---|---|
| v1（`probe_config_keys.py`，87 例） | UDP 传输（kcp）误判 `NO_LISTEN` | 只探 TCP 端口，KCP 走 UDP | 判据改为「窗口结束进程仍存活」 |
| v2（`probe2.py`，47 例，900s 超时挂死） | 探针自身挂死 | 存活期用 `proc.stdout.read1()` 读 PIPE → 阻塞 | 输出重定向到**临时文件**，不读 PIPE |
| v3（`probe3.py`，47 例） | **口径不等价，结果作废** | Rust `--test` 只跑 `xray_conf::Config::build()`（conf 层），**不含**协议层解析（`xray-core/src/outbound.rs` 的 `parse_*_config` 在 `start_full` 里跑）；Go `-test` 跑 `core.New` = conf + 协议 Build 全链 | 弃用 `--test`，两侧都用**完整启动**（v4） |
| v4（`probe4.py`，157 例） | — | — | **判据 = 完整启动 + 进程存活窗**，且不看日志关键字（Rust 的 "listening" 是 INFO 级，`loglevel=warning` 时被抑制） |

> v2/v3 的脚本已删除（其口径错误，留着会误导后人）；v1 保留（其 87 例结论与 v4 交叉验证一致，可作独立佐证）；**v4 是唯一权威口径**。

**两套独立方法交叉验证**：v1（起实例 + 端口探测，87 例）与 v4（起实例 + 存活窗，157 例）对「Go 接受 & Rust 拒启」的判定**完全一致**（同样 5 个键），说明 A 类结论不依赖单一探针口径。

---

## 3 「Go 能配、Rust 拒启」清单（Rust 更严 → 兼容性缺口）

**共 5 个键、4 类**。全部是 Rust **故意 fail-loud**（Rust 确实无该能力），但**错误文案未给迁移路径**（Go 侧同类错误会带 `has been removed and migrated to X` 指引）。

| # | 场景 | 类型 | Go 行为（实测） | Rust 行为（实测） | 位置 file:line | 用户可见后果 | 严重度 | 建议 |
|---|---|---|---|---|---|---|---|---|
| A1 | `streamSettings.masqueSettings`（掩码传输） | 缺陷（兼容性） | **接受**并正常启动 | **拒启**：`streamSettings.masqueSettings is not supported by this build (masque/xdrive transports and fronting address are not implemented); remove the key` | Rust `crates/xray-conf/src/init.rs:340`（硬错门）<br>Go `D:/Project/Xray-core/infra/conf/transport_internet.go:68`（`MASQUESettings *MasqueConfig`） | Go 侧能跑的 masque 前置配置迁到 Rust 直接起不来；文案说"remove the key"但**没说等价物是什么** | 建议 | 文案补迁移指引（Go 的 masque 是 HTTP/3 CONNECT 隧道，Rust 无等价物 → 明说"用 XHTTP H3 替代"） |
| A2 | `streamSettings.xdriveSettings`（Google Drive 传输） | 缺陷（兼容性） | **接受**（`service:"local"` 时启动成功；`service:"google-drive"` 需 3 个 secrets） | **拒启**：`streamSettings.xdriveSettings is not supported by this build...` | Rust `crates/xray-conf/src/init.rs:340`<br>Go `infra/conf/transport_internet.go:69` | 同 A1 | 建议 | 同 A1 |
| A3 | `streamSettings.address`（传输层前置地址） | 缺陷（兼容性） | **接受**（Go 用它做 xdrive fronting，`infra/conf/transport_internet.go:51`） | **拒启**：`streamSettings.address is not supported by this build...` | Rust `crates/xray-conf/src/init.rs:340`<br>Go `infra/conf/transport_internet.go:51` | 同 A1 | 建议 | 同 A1 |
| A4 | `streamSettings.port`（传输层前置端口） | 缺陷（兼容性） | **接受**（Go 同上 `:52`） | **拒启**：`streamSettings.port is not supported by this build...` | Rust `crates/xray-conf/src/init.rs:340`<br>Go `infra/conf/transport_internet.go:52` | 同 A1 | 建议 | 同 A1 |
| A5 | `tlsSettings.useSystemCA`（用系统 CA 池） | 缺陷（兼容性） | **接受**（Go `transport_security.go:319` → `x509.SystemCertPool`） | **拒启**：`tlsSettings.useSystemCA is not supported by this build; remove the key (Rust ships its own bundled root store)` | Rust `crates/xray-conf/src/init.rs:328-332`<br>Go `infra/conf/transport_security.go:319` | **TLS 证书验证结果可能与 Go 不一致**（系统根集 vs webpki-roots）——这是 5 条里唯一有**正确性**后果的（其余 4 条是纯能力缺失）。文案说"remove the key"，但删掉后 Rust 仍用 webpki-roots ≠ Go 的系统根，**删键不解决问题** | 建议 | 文案必须说明「Rust 用 webpki-roots 内建根集；需与 Go 一致请用 `certificates[]` 逐个提供」；若要真对齐，需实现系统 CA 装载（Windows `CertGetCertificateChain` / Linux `/etc/ssl/certs`） |

> **A 类不是"漏支持"而是"故意拒"**——方向正确（fail-loud 优于静默丢）。但 Go 26.10.17 是裁定基准，**「Go 能配」是用户迁移的前提**，故仍列为兼容性缺口（建议级，不阻断）。

---

## 4 「Rust 接受但无消费点」清单（接线缺口 · 仅报本轮新增）

> 前三轮（R1-A 字段接线 342 字段 / R1-D 协议 settings 329 键 / R1-E app 域 8 域）已覆盖大部分 wiring 缺口。本节**只列本轮新发现**。

| # | 场景 | 类型 | Go 行为 | Rust 行为 | 位置 file:line | 用户可见后果 | 严重度 | 建议 |
|---|---|---|---|---|---|---|---|---|
| **W1** | `finalmask.quicParams.disablePathMTUDiscovery`（QUIC PMTUD 开关） | **缺陷（同仓两处实现自相矛盾）** | Go 键名 **`disablePathMTUDiscovery`**（`MTU` 全大写）：`infra/conf/transport_finalmask.go:1190` → `transport/internet/splithttp/dialer.go:171` + `hub.go:492` 消费（`quic.Config.DisablePathMTUDiscovery`） | **同一个 Go 键在 Rust 两处实现拼写不一致**：<br>✅ `crates/xray-transport-hysteria/src/quic_params.rs:152` 读 `"disablePathMTUDiscovery"`（**正确**）→ 被 `quinn_adapter.rs:322` 消费<br>❌ `crates/xray-transport/src/memory_settings.rs:233` 读 `"disablePathMtuDiscovery"`（**错误，`Mtu` 小写**） | Rust `crates/xray-transport/src/memory_settings.rs:233` | **Go 合法键在 Rust 的 splithttp 路径被静默丢弃**（`get_bool` 找不到 → `unwrap_or(false)`）。<br>**精确影响面**：`memory_settings::parse_quic_params_config` 的调用方是 `xray-transport-splithttp/src/register.rs:182`（splithttp H3 拨号）与 `xray-transport/src/memory_settings.rs:156`（`to_memory_stream_config` → `downloadSettings` 递归解析）。<br>**但 splithttp H3 的 `build_h3_transport_config`（`h3_client.rs:135-174`）本身只消费窗口/idle/keepalive/CC 四个维度，**不读** `disable_path_mtu_discovery`**——即**该键在 splithttp 路径上**即使拼写正确也无处可落**（Go `dialer.go:171` 是落进 `quic.Config` 的）。<br>→ **净结论**：W1 是**真实的实现漂移 + 潜在缺口**（拼写错误是确凿的代码不一致；用户可见后果需等 splithttp 侧接线 PMTUD 才显现）。**不是"PMTUD 开关已失效"的既成事实** | **建议**（原判 P1 下调） | ① `memory_settings.rs:233` 改 `"disablePathMTUDiscovery"`（消除漂移）；② `xray-transport-quic/src/config.rs:152` 同步改（quic transport 已从 Go 移除，属 Rust-only 遗留面，但拼写应与 Go 一致）；③ **真正要补的是 splithttp H3 侧的 PMTUD 接线**（`h3_client.rs::build_h3_transport_config` 加 `qp.disable_path_mtu_discovery` → `transport_config.mtu_discovery_config(None)`，对齐 Go `dialer.go:171`） |
| **W2** | `finalmask.quicParams.maxIncomingStreams` / `maxStreamReceiveWindow` / `maxConnectionReceiveWindow`（splithttp H3 路径） | 缺陷（键级无语义） | Go `infra/conf/transport_finalmask.go:1189/1193` → `splithttp/dialer.go:165-167/170` **全部消费**（`quic.Config.MaxStreamReceiveWindow` / `MaxConnectionReceiveWindow` / `MaxIncomingStreams`） | Rust `crates/xray-transport/src/memory_settings.rs:230-234` **解析了**这三个键（`get_u64("maxStreamReceiveWindow")` 等），但 splithttp H3 的 `build_h3_transport_config`（`h3_client.rs:135-174`）**只取 `init_stream_receive_window` / `init_connection_receive_window`**（`:144-149`），**`max_*` 与 `max_incoming_streams` 全仓无消费点**（hysteria 路径有：`quinn_adapter.rs:303-307` / `:334-335`） | Rust `crates/xray-transport/src/memory_settings.rs:230-234`（解析）<br>`crates/xray-transport-splithttp/src/h3_client.rs:144-149`（消费，只取 init_*） | **Go 配 `maxStreamReceiveWindow` / `maxConnectionReceiveWindow` 限制 H3 接收窗口上限 → Rust 侧恒用 init_* 值（无上限）** → 大流量下载时流控行为与 Go 不同（Rust 更宽松 → 可能触发中间设备缓冲/QoS 差异）。`maxIncomingStreams` 同理（Go 限制并发双向流数，Rust 侧 quinn 缺省不限）。**注**：`maxIdleTimeout` / `keepAlivePeriod` / `brutalUp` / `brutalDown` / `congestion` / `bbrProfile` / `brutalDisableLossCompensation` 两侧都消费了 | **建议** | splithttp H3 的 `build_h3_transport_config` 补 `max_*` 三键消费：窗口取 `max(init, max)`（对齐 hysteria `quinn_adapter.rs:334-335` 的做法），`max_incoming_streams` → `transport_config.max_concurrent_bidi_streams(...)` |
| **W3** | `finalmask.quicParams.disableGSO` / `disableChromeParrot` / `disableStatelessReset` | 口径差异 | Go `transport_finalmask.go:1191/1192/1194` → `splithttp/dialer.go:221/223` + `hub.go:496/501` 消费（`quic.Transport{DisableGSO:...}` / `ChromeParrot` / `StatelessResetKey`） | Rust `crates/xray-transport/src/memory_settings.rs:213-218` **显式不读**（注释自述"quinn 无等价旋钮 → 键级无语义可保"）；但 `crates/xray-transport-quic/src/config.rs:154` **读** `"disableGSO"` → 同仓两处取舍相反 | Rust `crates/xray-transport/src/memory_settings.rs:213-218`（不读）<br>`crates/xray-transport-quic/src/config.rs:154`（读） | `disableGSO:true` 在 Go 侧关 GSO，Rust 侧恒 GSO 开 → **UDP 包形态不同**（GSO 批量 vs 单包），中间设备行为差异。`disableChromeParrot:false` 在 Go 侧=**开** Chrome parrot（`ChromeParrot: !DisableChromeParrot`），Rust 侧恒无 → 指纹差异 | 建议（口径差异） | 口径统一：quinn 无 GSO 开关则**显式登记**（与 `disableChromeParrot`/`disableStatelessReset` 同款），并把 `quic` crate 的读法一并对齐，避免同仓两说 |

> **W1-W3 均为 `finalmask.quicParams` 族在 splithttp H3 路径上的消费缺口**（前几轮 R1-D 的 329 键 × 25 crate 台账**未覆盖 finalmask 内部**——它把 `finalmask` 当成一个键，内部的 `quicParams.*` 14 键未被逐键核；本轮按 Go 键逐层展开才暴露）。
> **W1 的严重度已从 P1 下调到「建议」**：拼写漂移是确凿的代码不一致（E2 级证据），但 splithttp H3 侧本身尚未接线该字段 → **不是"开关已失效"的既成事实**。真正影响用户的是 W2（`max_*` 三键已解析但零消费 → Go 侧限流上限在 Rust 侧恒不生效）。

---

## 5 「Go 拒启、Rust 放行」清单（Rust 更宽 → fail-open）

**110 例中 37 例 Go 拒启而 Rust 放行**。按根因归并：

### 5.1 与前几轮已登记项同根（**不重报**，仅列覆盖关系）

| 根因 | 覆盖的用例（例数） | 已登记于 |
|---|---|---|
| 装配期 warn+skip（出站/入站构造失败 → 跳过该条，进程照常起） | `v2_ob_targetStrategy_settings_bad`、`v2_ob_freedom_domainStrategy_bad`、`v2_socks_udp_type_bad`、`v2_ss_empty_password`、`v2_ob_sendThrough_bad`、`v2_ob_ss_servers_two`、`v2_ob_http_servers_two`、`v5_anytls_outbound`、`v5_hysteria_outbound`、`v5_tuic_outbound`、`v5_naive_outbound`、`v5_masque_outbound`（12） | 票 `o91s4`（第三轮 C1-C13 已实测 13 例） |
| 路由解析失败 → fallback PatternRouter（整份路由规则失效） | `v2_route_script`、`v2_route_webhook_only`、`v2_route_ruleTag_only`（3） | 票 `vaye2`（第三轮 C9-C12 同根） |
| 已移除 feature 在 Rust 侧只 WARN 不拒启 | `v2_ob_proxySettings_removed`、`v2_freedom_noise_removed`、`v2_trojan_inbound_flow`、`v2_udp_quic_settings`、`v2_quic_network_removed`（5） | 见 §5.2 逐条判定 |

### 5.2 本轮新发现的独立缺口（4 条）

| # | 场景 | 类型 | Go 行为（实测） | Rust 行为（实测） | 位置 file:line | 用户可见后果 | 严重度 | 建议 |
|---|---|---|---|---|---|---|---|---|
| **N1** | `outbound.proxySettings`（链式代理顶层键） | 缺陷（**已移除 feature 未按移除处理**） | **拒启**：`The feature outbound "proxySettings" has been removed and migrated to "streamSettings.sockopt.dialerProxy".` | **接受并生效**（`normalize_outbound_proxy` 仍消费 `proxySettings.tag` 建代理链；`transportLayer:true` 还注入 `sockopt.dialerProxy`） | Rust `crates/xray-conf/src/built.rs:272-274` + `:327-360`（仍消费）<br>Go `infra/conf/xray.go`（`PrintRemovedFeatureError`） | 用户按 Go 26.10.17 的迁移提示把 `proxySettings` 改成 `sockopt.dialerProxy` 是对的，但**保留旧键的存量配置在 Rust 上仍会跑**——两侧对同一配置的行为不同（Go 拒启 / Rust 建链）。属"已移除功能在 Rust 侧复活" | 建议 | 按 Go 对齐：Rust 侧 `proxySettings` 非空即 `ConfError::Removed`（文案带 Go 同款迁移指引）；`transportLayer` 注入逻辑随之清理 |
| **N2** | `freedom.settings.noise`（单数形态） | 缺陷（已移除 feature 未按移除处理） | **拒启**：`The feature noise = { ... } has been removed and migrated to noises = [ { ... } ].` | **接受**：只发一条 WARN（`freedom_noise_removed_warning`），单数 `noise` 被**静默丢弃**（只认 `noises[]`） | Rust `crates/xray-core/src/outbound.rs:1206-1210`（只 WARN）<br>Go `infra/conf/freedom.go`（`PrintRemovedFeatureError`） | 用户把 `noise` 拼错成单数 → Go 拒启（看得见），Rust 静默忽略 → **噪声注入失效但无提示**（唯一提示是 WARN，而 WARN 在 `loglevel=warning` 之外的默认面可见性弱） | 建议 | 改为硬错（与 Go 同），或在 WARN 文案里加"该键已失效，噪声不会被注入" |
| **N3** | `trojan` 客户端/入站 `flow` 键 | 缺陷（已移除 feature 未按移除处理） | **拒启**：`The feature Flow for Trojan has been removed.` | **接受**：只发 WARN，`flow` 被丢弃 | Rust `crates/xray-core/src/outbound.rs:1212-1219` + `inbound.rs:4724-4726`（只 WARN）<br>Go `infra/conf/trojan.go:73-75`（`PrintRemovedFeatureError`） | 同 N2 | 建议 | 同 N2 |
| **N4** | `routing.rules[].webhook`（单规则只带 webhook、无任何匹配字段） | 缺陷（**规则语义降级**） | **拒启**：`app/router: this rule has no effective fields` | **接受**：Router init 失败 → **fallback PatternRouter**（整份路由规则失效）→ 进程正常启动 | Rust `crates/xray-core/src/wiring.rs`（router init 失败 → fallback）<br>Go `app/router/config.go` | 用户写了一条只含 webhook 的规则（想配通知器）→ Go 拒启；Rust 静默把**整份路由**降级成 PatternRouter → 所有路由规则失效 | 建议（根因在 `vaye2`） | 随 `vaye2` 一并修（fail-visible 门）；本条是 `vaye2` 的**新触发面**（webhook-only 规则） |

> **N1-N3 同根**：Rust 侧对「Go 已移除的 feature」只 WARN 不拒启。第三轮 `0bzcd` 票（13 例 Go 拒启/Rust 放行）覆盖的是「**配置错误**类」，**「已移除 feature」类是新的子类**——这 3 条不与 `0bzcd` 重叠。

---

### 5.3 值形态差异（键存在、两侧都接受，但**值形态**不兼容）

本轮额外做了一轮**值形态**差分（Go 的 `Int32Range` / `PortList` 的 `UnmarshalJSON` 只认「区间字符串」或「纯整数」，Rust 多处额外认「`{from,to}` 对象」）。结论：

| 值形态 | Go | Rust | 判定 |
|---|---|---|---|
| `"30-60"`（区间字符串，**Go 权威形态**） | 接受 | 接受 | ✅ 一致 |
| `30`（纯整数） | 接受 | 接受 | ✅ 一致 |
| `{"from":30,"to":60}`（对象） | **拒启**（`Invalid integer range, expected either string of form "1-2" or plain integer.`） | **接受** | ⚠️ **Rust-only 方言**（Rust 更宽松） |

涉及键：`finalmask.udp[].settings.interval` / `splithttpSettings.xPaddingBytes` / `uplinkChunkSize` / `scMaxEachPostBytes` / `scStreamUpServerSecs` / `sessionIDLength` / `xmux.{maxConcurrency,maxConnections,cMaxReuseTimes,hMaxRequestTimes,hMaxReusableSecs}` / `freedom.settings.fragment.{length,interval,maxSplit}` / `noises[].delay` / `finalRules[].blockDelay` / `routing.rules[].{port,localPort,sourcePort}`。

**判定：这不是「Go 支持而 Rust 不支持」，而是 Rust 多认了一种 Go 不认的形态** → 归入 §6「Rust 更宽松」类，**不单独开票**。理由：
1. Go 的权威形态（字符串）在**两侧都通**（实测 `v7_*` / `v8_*` 共 12 例全绿）→ 用户照 Go 文档写的配置不会因此失效；
2. Rust 侧的宽松不会导致「配置被静默误读」——`{from,to}` 是无歧义的；
3. 反向风险为零（不存在 Go 能写、Rust 写不出的形态）。

**但有一处例外需记录**：Rust 的 `xray-conf` 层 `Int32Range`（`crates/xray-conf/src/common.rs:298-322`）**严格对齐 Go**（只认字符串/整数），而 `xray-transport` 层的三处局部实现（`memory_settings.rs:322`、`splithttp/register.rs:525`、`xray-proxy-freedom/src/config.rs:295`）各自又认对象形态 → **同仓三套 range 解析器口径不统一**。这与 W1 是同一类问题（复制漂移），但本轮不另开票，登记在此供后续统一。

---

## 6 「Rust 更严格导致与 Go 不兼容」清单（单列）

| 项 | 说明 |
|---|---|
| §3 A1-A5 | 即上表。Rust 因**能力缺失**（masque/xdrive 传输、系统 CA 池）而拒启 Go 能配的键。方向是 fail-loud（优于静默丢），但迁移体验差。 |
| 与「Rust 更宽松」的方向对照 | 本轮 37 例 Rust 更宽松（fail-open，安全风险更高）vs 5 键 Rust 更严（fail-loud，安全风险低）。**按判定口径「Rust 更宽松 = 高危优先报」，故 37 例中的 N1-N4 优先级高于 A 类。** |
| 已知的 Rust 更严格项（非本轮新发现，仅记录口径） | `inbound.port` 越界（第三轮 S1：Go 起进程但不监听，Rust 拒启——**Rust 更对**）；`dns.servers` 空串（第三轮 S4）；`dns.servers[].address` 带端口（第三轮 S3：Rust 接受 Go 拒启——方向相反） |

---

## 7 覆盖范围与未覆盖面（如实声明）

### 7.1 本轮覆盖了

- **Go 配置键全集**：425 键（infra/conf 全部 struct tag），静态逐键核 Rust 解析点（415/425）
- **双跑差分 110 例**（v2 47 + v5 63），覆盖：
  - **协议特有键**：vless（users/clients/flow/decryption/fallbacks/testseed/reverse/seed/testpre/encryption/level/email）、vmess、trojan（flow/servers/users/clients）、shadowsocks（method/password/servers/users/network）、socks（auth/users/accounts/udp/ip/userLevel）、http（users/accounts/allowTransparent/userLevel/headers）、dokodemo（address/port/network/allowedNetwork/rewrite*/portMap/followRedirect/userLevel）、freedom（targetStrategy/domainStrategy/redirect/userLevel/fragment/noise/noises/proxyProtocol/ipsBlocked/finalRules）、blackhole（response）、loopback（inboundTag/sniffing）、dns（servers[]/hosts/clientIp/tag/queryStrategy/disableCache/serveStale/serveExpiredTTL/disableFallback*/enableParallelQuery/useSystemHosts + nameserver 全键）、hysteria、masque、wireguard（secretKey/address/peers/mtu/reserved/remoteDNS/noKernelTun）、tun（name/desc/mtu/gateway/dns/userLevel/auto*）
  - **streamSettings 各传输键**：tcp（header）、ws（path/host/acceptProxyProtocol/heartbeatPeriod/poolSize/headers）、grpc（serviceName/multiMode/idle_timeout/health_check_timeout/permit_without_stream）、xhttp/splithttp（path/host/mode/scMax*/noSSEHeader/noGRPCHeader/sessionID*/xmux/downloadSettings）、kcp（mtu/tti/uplinkCapacity/downlinkCapacity/readBufferSize/writeBufferSize/congestion/seed/header/cwndMultiplier）、httpupgrade（path/host/headers）、hysteria（version/masquerade）、masque、xdrive、quic
  - **安全层**：tlsSettings 全键（allowInsecure/certificates[]/serverName/alpn/enableSessionResumption/disableSystemRoot/minVersion/maxVersion/cipherSuites/fingerprint/rejectUnknownSni/curvePreferences/masterKeyLog/pinnedPeerCertSha256/verifyPeerCertByName/echConfigList/echForceQuery/useSystemCA/ocspStapling/oneTimeLoading/buildChain）、realitySettings（serverName/serverNames/publicKey/password/shortId/fingerprint/mldsa65Verify/spiderX/privateKey/shortIds/dest/target/type/xver/minClientVer/maxClientVer/maxTimeDiff/show/masterKeyLog/limitFallback*）
  - **sockopt 全键**（mark/tcpFastOpen/tproxy/acceptProxyProtocol/domainStrategy/dialerProxy/tcpKeepAlive*/tcpCongestion/tcpWindowClamp/tcpMaxSeg/penetrate/tcpUserTimeout/v6only/interface/tcpMptcp/customSockopt/addressPortStrategy/happyEyeballs/trustedXForwardedFor）
  - **finalmask**（tcp[]/udp[]/quicParams 全 15 键）
  - **app 域**：log（access/error/loglevel/dnsLog/maskAddress）、routing（rules/balancers/domainStrategy/script + rule 全字段：domain/ip/port/network/source/sourceIP/sourcePort/localIP/localPort/vlessRoute/inboundTag/protocol/user/attrs/process/localOS/webhook/ruleTag/outboundTag/balancerTag + 4 种 strategy）、dns、policy（levels 全字段 + system）、stats、observatory、burstObservatory（pingConfig 全字段）、reverse、api（tag/listen/services）、metrics（tag/listen）、geodata（cron/outbound/assets）、fakeDns（ipPool/poolSize）、version、env
  - **顶层**：transport（已移除）、reverse（已移除）、inbounds/outbounds 公共字段（protocol/tag/listen/port/sendThrough/proxySettings/mux/streamSettings/sniffing/settings）

### 7.2 未覆盖（**不猜、不补写**）

1. **UDP 数据面行为**——本轮只测「配置被接受 / 被拒」，未测 UDP 会话/relay 的键级行为差异（如 `dokodemo.portMap`、`socks.udp` 的运行期语义）。
2. **键的「值语义」差分**——大量键两侧都接受（64/110 例 SAME），但**值是否产生相同行为**未逐一验。本轮只回答「能不能配」，不回答「配了行为是否一致」。
3. **Go app 段（`app/**` 的 protobuf 面）**——不属用户配置面，未纳入键全集（口径已在 §1.1 说明）。
4. **TLS/REALITY 握手层**——`tlsSettings`/`realitySettings` 只到「配置被接受」层；证书链、REALITY 握手、ECH 未验（第三轮同样未覆盖）。
5. **Linux-only 路径**（TUN 真实建设备、tproxy、WFP）——本机 Windows，tun 实测被环境挡（`拒绝访问` / `wintun.dll` 缺失）；相关用例的 Go 侧失败原因已核实为**环境项**（`Error loading wintun.dll`），非键级差异。
6. **`v5_dokodemo_full` / `v5_route_balancer_strategies` 的 Go 侧拒绝**已核实为**探针样本缺陷**（Go 26.10.17 无 `dokodemo` 协议 id；balancer 用例的 `selector:["out-"]` 指向不存在的 outbound → `core: not all dependencies are resolved`），**非 Rust 缺口**，故未列入 §5.2。
7. **32/32 与 interop 回归**——本轮只读审计、零代码改动，不需回归；但 W1 的修复必须以 32/32 + interop 12/12 双闸验收。
8. **`disablePathMTUDiscovery` 的运行期实证**——W1 是**代码级确证**（两处字面量拼写不一致 + Go 键名大小写），但**未做运行期抓包**证明 PMTUD 行为真的不同（需 H3 环境 + 路径 MTU 探测观测，成本高）。证据等级：**E2（源码定位，两侧字面量直接对照）**，非 E1。

---

## 8 建议修复顺序

1. **W2**（splithttp H3 的 `quicParams.maxStreamReceiveWindow` / `maxConnectionReceiveWindow` / `maxIncomingStreams` 零消费）——3 键已解析但丢弃，Go 侧的窗口上限与并发流上限在 Rust 侧恒不生效，**这是本轮唯一有用户可见行为后果的接线缺口**。建议级。
2. **N1-N3**（已移除 feature 只 WARN 不拒启）——3 处，Rust 侧「已移除功能复活」，Go↔Rust 对同一配置行为不同。建议级。
3. **N4**（webhook-only 规则触发路由整体降级）——随票 `vaye2` 修（fail-visible 门）。
4. **W1**（`disablePathMTUDiscovery` 拼写漂移）——1 行，消除同仓两说；与 W2 同批修更省（同在 finalmask 消费面）。
5. **A5**（`useSystemCA` 文案误导）——文案说"remove the key"，但删掉后仍与 Go 根集不同 → 必须改文案或实现系统 CA 装载。
6. **A1-A4**（masque/xdrive/address/port 文案）——补迁移指引。
7. **W3**（`disableGSO`/`disableChromeParrot`/`disableStatelessReset` 口径）——文档登记即可，不改行为。

---

## 9 复算指引

```bash
# 1) Go 键全集（425）+ Rust 解析点覆盖（415）+ 无解析点（10）—— 一条命令复算
python reports/audit-2026-10-31-perf-mem-wiring/round4/scripts/key_census.py
# 输出：GO_KEYS_TOTAL=425 / RUST_HAS_PARSE_SITE=415 / RUST_NO_PARSE_SITE=10 + 清单

# 2) 全量双跑（157 例，约 12 分钟；端口段 28000-28049，进程按 PID 清理）
for c in v2 v5 v6 v7 v8; do
  python reports/audit-2026-10-31-perf-mem-wiring/round4/scripts/probe4.py \
         reports/audit-2026-10-31-perf-mem-wiring/round4/scripts/cases_$c.json
done

# 3) 原始结果（可逐条复核）
round4/tmp/results_v4_cases_v2.json   # 47 例
round4/tmp/results_v4_cases_v5.json   # 63 例
round4/tmp/results_v4_cases_v6.json   # 15 例
round4/tmp/results_v4_cases_v7.json   # 16 例
round4/tmp/results_v4_cases_v8.json   # 16 例
```

**结论数字**：157 例 / 双跑成功 157 / 差异 60（A 类 9 = 5 键去重；B 类 51）/ 一致 97。
**新发现**：W1 / W2 / W3（建议，均属 `finalmask.quicParams` × splithttp H3 消费面）+ N1 / N2 / N3 / N4（建议）= **7 条**，无 blocker/P0。
**A 类 5 键**（Rust 更严）方向正确（fail-loud），仅文案缺迁移指引，不建议改行为。
