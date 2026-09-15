# impl-d4：Go parity 三票 + 冻结簇仲裁（2026-09-16）

VERDICT: u5ni DONE / 2a35 DONE / 8np8 前提证伪（建议关票） / 仲裁表交付（禁实现遵守）

执行者：impl-d4（Batch D-4）。Go 基准 D:/Project/Xray-core @ v26.9.9（52a412d9）；Rust D:/Project/Xray-core-rust（HEAD 8206c71）。
铁律①三票全部先 grep Go 基准验证票面前提，结论：2 成立 1 证伪。

---

## 一、u5ni（P0）：XUDP MAX_DATA_LEN 2MB → 7526 —— 已落地

### 票面前提验证（Go 实证）
- Go `common/xudp/xudp.go:100`（WriteMultiBuffer 内）：
  `if length == 0 || length+666 > buf.Size { continue }`
  `buf.Size = 8192`（common/buf/buffer.go:13）→ 应用层 packet 上限 = `8192-666 = 7526`，超限静默丢弃（continue）。
- Rust 现状 `crates/xray-xudp/src/packet.rs:31`：`const MAX_DATA_LEN: usize = 2_097_152 - 666;`（≈2MB）。
- **前提成立**，且追加发现：`packet.rs:345/376` 帧 length 字段 `(data.len() as u16).to_be_bytes()`——2MB 上限下 `len > 65535` 会 **u16 截断损坏帧**；7526 < u16::MAX 后该 bug 自然消失。7526 不止 parity，还是正确性修复。

### 改动
- `crates/xray-xudp/src/packet.rs:31-34`：常量改 `8_192 - 666`，附 Go 出处注释（等价性：`len > 8192-666` ≡ Go `len+666 > 8192`）。
- 新增测试 `max_data_len_matches_go_baseline`（断言 `MAX_DATA_LEN == 7526`，改值必红）与 `test_oversized_packet_skipped_go_parity`（7526 写入并可读回；7527 静默跳过，Go continue 同语义）。
- 行为语义对齐核对：Go 空包/超限 → continue（跳过继续处理后续）；Rust 空包/超限 → `return Ok(())`（该包跳过）——write_packet 单包 API 下语义一致。

### 语义边界（非目标，登记）
Go ReadMultiBuffer（xudp.go:150-206）读侧无 7526 上限（按帧 length 读，length 为 u16 天然 ≤65535）；Rust 读侧 `read_packet` 同构，无需改。wire-format 未动（仅本端发送过滤阈值对齐，Go 同值同丢弃语义）。

---

## 二、2a35（P0）：congestion 字面值解析对齐 —— 已落地

### 票面前提验证（Go 实证）
- Go 唯一解析点 `infra/conf/transport_internet.go:245-253`（StreamConfig.Build，finalmask.quicParams 入口）：
  - `strings.ToLower` 归一；
  - `case "", "brutal", "reno", "bbr":` 合法直通；
  - `case "force-brutal":` 需 `up != 0`（BrutalUp 已于 :229-243 解析并校验 >0 时 ≥65536），否则 `"force-brutal requires up"`；
  - `default:` 硬错 `"unknown congestion control: <v>, valid values: reno, bbr, brutal, force-brutal"`。
- Go `transport/internet/config.proto:67-84`：QuicParams.congestion = field 1（string）。
- Rust 缺口 `crates/xray-transport-quic/src/config.rs:64-68`：任意字符串照收，`build_transport_config` 仅 `bbr`→BBR，其余（含 brutal/reno/force-brutal/未知垃圾）静默落 CUBIC，无校验。
- hysteria 路径已对齐（`crates/xray-transport-hysteria/src/quic_params.rs:69-84`，e84a530 已落：同一字面值集合 + force-brutal/brutalUp 联动 + 同文案），本票缺口只在 xray-transport-quic 的 quicSettings 直连路径。

### 改动（仅解析层 parity，CC 算法不实现）
- `config.rs` from_json：congestion 小写归一 + 字面值校验。`""/brutal/reno/bbr` 直通；`force-brutal` → 硬错 `"force-brutal requires up"`（quicSettings 无 brutalUp 字段，忠实映射 Go up==0 分支）；未知 → 硬错（文案与 Go 一致）。
- `build_transport_config`：新增 `"reno" => NewRenoConfig`（quinn-proto 内建 `congestion.rs:14 pub use new_reno::{NewReno, NewRenoConfig}`，零成本真对齐）；`brutal` 落 CUBIC 并注释登记（BrutalSender 为 hysteria crate 专属，本 crate 无实现——票面明示不实现算法）。
- 新增测试：`congestion_go_literal_set_accepted`（合法字面值+大小写归一）、`congestion_unknown_rejected_go_parity`（cubic/new_reno/NewReno/whatever/带空格串全部硬错——Go 合法集合无 "cubic"，旧注释 `""/cubic/new_reno→CUBIC` 无 Go 依据已修正）、`congestion_force_brutal_requires_up`（错误文案逐字断言）。
- 已知解析期报错向上传播路径：`transport.rs:71/120` `QuicConfig::from_json(...)?` → 配置期失败，与 Go conf Build 硬错同型。

### 登记不在本票（残留）
`crates/xray-transport/src/memory_settings.rs:187-211` `parse_quic_params_config`（finalmask.quicParams → 公共 MemoryStreamConfig 路径）congestion 仍无字面值校验；且其 brutalUp 为未解析 String，做 force-brutal 联动需引入带宽解析器（hysteria crate 的 parse_bandwidth_bps 无法反向依赖）。建议另票统一公共层校验（对齐 Go :218-301 全套），本票不越界。

---

## 三、8np8（P1）：Hysteria receive_window —— 前提证伪，建议关票

### 尽调（票面要求的两层口径 + Rust 现值）
| 口径 | stream 窗口 | conn 窗口 | 证据 |
|---|---|---|---|
| Hysteria2 官方 v2（文档 + 代码默认） | 8MB (8388608) | 20MB (20971520) | 官方 Full-Client/Server-Config："default stream and connection receive window sizes are 8MB and 20MB"（v2.hysteria.network/docs/advanced/Full-Client-Config） |
| xray-go 集成层 | 8MB | 20MB | `transport/internet/hysteria/dialer.go:96-107`（客户端）与 `hub.go:300-311`（服务端）：quicParams 字段==0 时填 `8388608` / `8388608*5/2` |
| Rust 现状 | 8MB | 20MB | `crates/xray-transport-hysteria/src/dialer.rs:73-93`（同构 if==0 填默认）+ `quinn_adapter.rs:297-304`（max(initial,max)→quinn 单窗口）；测试 `transport_config_default_windows` 断言 `(8_388_608, 20_971_520)` |

### 判定
- 票面"Rust 默认 768KB"**证伪**：全仓 grep `786_432/768_1024/768*1024` 零匹配；git 历史（`git log -S "8_388_608" -- crates/xray-transport-hysteria/`）显示 8MB/20MB 自初版 67d4737 即存在，e84a530 仅修 idle/keepalive 单位。768KB 在本仓库史上从未存在。
- 三层口径（官方/Go 集成/Rust）完全一致 → **无需改动，无床复测需求（未改任何值）**。建议：关闭 8np8（前提错误）。

---

## 四、冻结簇仲裁表（cftl ↔ c1qh ↔ tiys，PM 决策门输入，未实现任何参数改动）

背景：Go QUIC transport 已整体删除（commit `9a953c07 "Transport: Remove QUIC (#3754)"`，v26.9.9 无 `transport/internet/quic/` 目录）；QuicParams 下沉为 StreamConfig 公共参数（config.proto:62），由 hysteria/splithttp 等消费。cftl 的搬运目标 xray-transport-quic 在 Go baseline 无对拍对象。

| 参数 | ① Go 真实默认 | ② Go 字段有无 | ③ 我们现状 | ④ 建议动作 |
|---|---|---|---|---|
| initial_rtt | quic-go 内建 100ms（RFC 9002；quinn 默认 333ms，quinn-proto config/transport.rs:377）；hysteria dialer/hub 均未覆盖（dialer.go:82-115、hub.go:287-317 无此设置） | **无用户字段**：QuicParams 全 16 字段无 initial_rtt（config.proto:67-84） | hysteria：`quinn_adapter.rs:269` 硬编码 100ms（u9um 已落）＝quic-go 内建 parity；xray-transport-quic：未设＝quinn 333ms | hysteria **保留现状**（硬编码值本身即 Go parity）；**tiys 关闭**——Go 无字段，"加开关"是超集偏离，开关默认值仍需 100ms，无增量 parity 收益；cftl 向 xray-transport-quic 搬 100ms 无 Go 依据（对拍对象已删），如 PM 考虑应注明属"内部一致性"而非 parity |
| keepalive | **disabled**：dialer.go:111-113 是注释掉的死代码（注释内默认值为 **10s**，非 15s），生效行为=KeepAlivePeriod 仅来自用户配置；服务端 hub.go:287-317 根本不设 KeepAlivePeriod | **有**：QuicParams.keep_alive_period（config.proto:78，conf 校验 2-60s @transport_internet.go:271-273） | hysteria：`quinn_adapter.rs:275-280` 用户配置优先，缺省硬编码 15s（u9um 加，理由 NAT 续表）；解析层缺省 0（`quic_params.rs:121-125` 校验 2-60∪{0}） | **c1qh 成立**：删 15s 缺省 → 缺省 disabled（Go parity）。代价：纯 NAT 场景弱化（Go 用户同样暴露此行为，可用 keepAlivePeriod:15 显式找回）；**cftl 的 keepalive15s 方向否决**。注：c1qh 票面"偏离 Go 注释"细节需修正——注释值 10s 且已注释，"disabled" 指 Go 生效行为 |
| MTU / PMTUD | DPLPMTUD 默认启用（`DisablePathMTUDiscovery=false` 默认，dialer.go:89 `quicParams.DisablePathMtuDiscovery ‖ (GOOS 非 linux/windows/darwin)`），quic-go 探测至路径 MTU（以太网 1500）；`MaxDatagramFrameSize=1200`（hysteria config.go:24，注意这是 datagram 帧上限非链路 MTU） | MTU 上界**无用户字段**；disable_path_mtu_discovery 有（config.proto:80） | hysteria：`quinn_adapter.rs:305-313` MtuDiscovery upper_bound(1500)+显式禁用支持（u9um 已落）；datagram frame 1200 已对齐（rjo9，注释含 8192 实测不通记录） | **现状已对齐，无需新做**（cftl 的 MTU1500 项 u9um 已交付）；disable 分支语义 Go 一致（quinn_adapter.rs:310-313） |

### 簇冲突裁决摘要
1. keepalive15s：c1qh（删）**胜**，cftl（补）**否**——Go 生效行为 disabled，票面方向与 Go 相反者让位。
2. initial_rtt100ms：hysteria 现状**保留**；tiys（加开关）**关闭**——无 Go 字段，硬编码值=parity 本体。
3. MTU1500：**已落地**（u9um），cftl 该项无残余工作。
4. cftl 整票：三参数中一项方向错、两项已完成、剩余搬运目标（xray-transport-quic）Go 对拍对象已删（#3754）→ 建议**关闭**；若 PM 认为普通 QUIC transport 也应有 100ms（quinn 333ms 与 quic-go 100ms 的内部一致性差），请显式定性为内部一致性改进另票，不算 parity。
5. u9um 定位更正：该票（initial_rtt+keepalive+MTU 三件套）1/3 是 parity（MTU）、1/3 是 quic-go 内建对齐（initial_rtt）、1/3 是**有意偏离**（keepalive15s，c1qh 判定应回滚）。

---

## 五、验证命令与输出

（占位——测试运行结果见下节补充）

## 六、read 调用审计

- read rule://rust ⇒ 自检纪律（语言规则），已遵循
- bd memories congestion/xudp ⇒ 自检纪律（历史踩坑）：congestion 无记录；xudp 仅 mux 反向相关（禁区，未触碰）
- read Go common/xudp/xudp.go ⇒ u5ni 前提验证（xudp.go:100 实证）
- read Go infra/conf/transport_internet.go ⇒ 2a35 前提验证（:245-253 实证）
- read Go transport/internet/config.proto ⇒ QuicParams 全字段（initial_rtt 无字段实证）
- read Go transport/internet/hysteria/{dialer,hub,config}.go ⇒ 8np8 + 仲裁簇实证
- read crates/xray-xudp/src/packet.rs ⇒ 改动锚定
- read crates/xray-transport-quic/src/config.rs ⇒ 改动锚定
- read crates/xray-transport-hysteria/src/{quic_params,quinn_adapter,dialer}.rs ⇒ 8np8/仲裁现状取证
- read crates/xray-transport/src/memory_settings.rs ⇒ 残留缺口定位
- read quinn-proto 0.11.17 congestion.rs/new_reno.rs/config/transport.rs ⇒ NewRenoConfig 导出与 333ms 默认实证
- read skill://code-simplifier / silent-failure-hunter / agent-self-evaluation ⇒ 收尾纪律（autoload 注入）

## 七、side-effects

- 改动文件：crates/xray-xudp/src/packet.rs（常量+2 测试）；crates/xray-transport-quic/src/config.rs（解析校验+reno 分支+3 测试+注释修正）。
- 未触碰禁区：mux/dispatcher/bridge.rs/ws 指纹/wire-format/xray-transport-tcp/register.rs 均未动。
- 未 commit / 未动 bd 票（按禁区）。

## 八、残余风险与未做

1. memory_settings.rs 公共层 congestion 校验缺口未补（见二·登记，建议另票）。
2. c1qh 若批准实现（删 15s 缺省），需同步改 quinn_adapter.rs:278-279 及其注释，并复核 NAT 场景床表现（PM 安排）。
3. xray-transport-quic（Go 已删 transport 的 Rust 保留实现）整体处于"无 Go 对拍"状态，本票仅对齐字面值解析；其窗口默认（quinn ~500KB 级 vs hysteria 显式 8MB/20MB）与 Go 无关（Go 无此 transport），未动。
