# impl-o93t：TCP 接收窗死锁修复（server inbound 显式 SO_RCVBUF≥BDP）

**结论**：opt-in 配置字段 `receiveBufferSize` 完整落地并实证生效（rb 8MiB / snd_wnd 8-18MB vs 85KB 基线，窗判据 PASS）；但端到端吞吐判据 FAIL——当前 master（49262b6 revert 安全态）上窗死锁前提已不成立（BASE 下 DRC 自然扩窗至 ~800KB，瓶颈为桥泵 app_limited），稳态吞吐 1.0-1.14x（16MB 轮的 18.4x 经 64MB 复核确证为链路大缓冲吸收假象）。

**VERDICT: FAIL**（code-level 双验收 PASS；end-to-end 吞吐判据不达标，且实证表明该票前提在当前基线上失配——详见 §4）

## 1. 铁律①：Go 基准裁定（D:/Project/Xray-core，v26.9.9）

- `transport/internet/config.proto:96-152` SocketConfig **全字段核对：无 receiveBuffSize / receive buffer 类专用字段**。
- 全仓 grep `SO_RCVBUF|RcvBuf|RecvBuffer` **零匹配**——listener 侧（`system_listener.go:23-41 getControlFunc` → `applyInboundSocketOptions`）不设 SO_RCVBUF。
- 唯一相关基建：通用 `customSockopt`（config.proto:86-93，`{system,network,level,opt,value,type}`，int/str 两型；`sockopt_linux.go:174-210` inbound 侧也应用）。Go 无「listener 默认显式 SO_RCVBUF」行为。
- **契约兑现**：按「Go 无此默认 → 修复必须 opt-in 配置化」执行，未改任何默认行为。JSON 命名对齐 Go camelCase 风格（`tcpWindowClamp` 族）定名 `receiveBufferSize`。

## 2. 改动（+58 / -5，单 commit 粒度，未 commit）

| 文件 | 位置 | 内容 |
|---|---|---|
| `crates/xray-transport/src/sockopt/mod.rs` | SocketOptions 结构 | 新字段 `receive_buffer_size: i32`（0=不设=默认；文档注明 Go 无此字段、SOCK_RCVBUF_LOCK 语义、rmem_max 钳制） |
| 同上 | `Default` | `receive_buffer_size: 0` |
| 同上 | `apply_outbound_socket_options` | `receive_buffer_size > 0` 时 `socket.set_recv_buffer_size(...)`（socket2 跨平台：unix/Winsock SO_RCVBUF） |
| 同上 | `apply_inbound_socket_options` | 同上 per-accept（Linux accept 出的连接不继承 listener 的 SO_RCVBUF 锁定语义，必须 per-conn 设） |
| `crates/xray-transport/src/dialer.rs` | `socket_options()` | 解析 JSON `receiveBufferSize`（inbound+outbound 同字段生效） |

- 生效路径全覆盖：`DefaultListener::accept` 与 `InboundTcpListener::accept`（协议 serve 层裸 TCP 路径）均过 `apply_inbound_socket_options`；出站过 `apply_outbound_socket_options`。
- 不触碰禁区：未动 register.rs / ws/httpupgrade 指纹 / wire-format / Cargo.toml / bridge.rs。

## 3. code-level 验收（PASS×4）

```
1) cargo test -p xray-transport --lib
   → test result: ok. 515 passed; 0 failed  （含新测试 receive_buffer_size_applies_and_defaults_off）
2) cmd /c D:\tmp\buildenv.bat cargo test --workspace --lib
   → 全部 "test result: ok … 0 failed"，EXIT=0（20 个测试组，含 515/457/99/93…）
3) sockopt 配置面单测（断言强，改值必红）：
   - dialer.rs socket_options_parses_end_fields_and_custom_sockopt：
     json!{"receiveBufferSize": 1048576} → assert_eq!(o.receive_buffer_size, 1048576)
     缺省 → assert_eq!(d.receive_buffer_size, 0)
   - mod.rs receive_buffer_size_applies_and_defaults_off：
     真实 socket 上 apply_inbound/outbound → 回读 SO_RCVBUF 严格大于默认 socket；
     默认 0 → 回读等于默认（不触碰）
4) workspace 不回归：同 2)
```

## 4. end-to-end 验收（VPS 床 199.115.231.188，netem 161ms/1% on lo，RTT 322ms）

床：`/tmp/r2/`（r3run.sh up / d3run.sh down，双视角 ss 连拍 0.4s 间隔 + listener gate 防残留进程污染）。二进制：xrbuild 容器 Linux release（`xray_o93t`，改动文件 cp 后 grep 验证非陈旧）。

### 4.1 窗证据（验收 4 判据一：窗值显著 > 85KB —— PASS）

FIX 轮（receiveBufferSize=4194304，srv vless-in + freedom-out + cli proxy-out）：

| 指标 | BASE（orig 配置） | FIX（4MiB opt-in） |
|---|---|---|
| 接收腿 rb（skmem，Linux 2x 记账） | rb131072×976、rb2705666×479（DRC 慢爬坡） | **rb8388608×610**（=4MiB×2，显式生效铁证） |
| 发送端 snd_wnd（up，cli→srv 腿） | 608,256 B 峰值 | **8,249,344-18,376,704 B** |
| rcv_ssthresh | 787,845 B 峰值 | **8,257,536 B** |

vs 基线 85KB：FIX 窗上限 ~97x（8.2MB/85KB）。SO_RCVBUF 显式设置端到端生效无争议。

### 4.2 吞吐对照（验收 4 判据二：≥2x —— FAIL）

| 方向 | BASE | FIX（16MB 轮） | FIX 稳态复核（64MB） |
|---|---|---|---|
| up | 1.58 Mbps（85s） | 29.01 Mbps（4.6s）→ **假象** | **1.56-1.60 Mbps**（mid30-90/last60s） |
| down | 1.14 Mbps（235s） | 1.30 Mbps（207s）= 1.14x | — |

- 16MB 轮 29.01Mbps 被 cadence 拆穿：前 4.5s 仅 ~1.5Mbps、尾段 1s 爆发 ~15MB——4MiB rcvbuf+发送端 sndbuf 构成 ~12MB+ 链路吸收空间，非端到端稳态吞吐。64MB 复核稳态与 BASE 持平。
- **对照 Go 新基准（1.19-2.77Mbps）**：Rust BASE/FIX 稳态（1.14-1.60）同层，8sum「18x 劣化」在新基准下不存在（与 9al2 仲裁结论一致）。

### 4.3 根因裁定：票前提在当前基线上失配

- BASE ss 显示 `app_limited` 遍布、`rwnd_limited:1776ms(2.2%)`、重传 4.2%（17.8MB 中 744KB retrans）——**瓶颈=桥泵锁步供数（应用层），非接收窗**。
- BASE 下 DRC 实际在工作：rcvbuf 自动扩至 ~800KB、rcv_ssthresh ~788KB、snd_wnd ~600KB——「窗恒定 64-85KB 冻结」在 master 49262b6 revert 安全态上不出现。o93t 描述的机制（rcvbuf 恒空→DRC 无信号→1 窗/RTT）属 8sum feature 分支 piped 泵时代的床行为；revert 后桥泵拓扑不同，DRC 自然扩窗。
- 因此「显式 SO_RCVBUF≥BDP」在当前基线上：窗上限确实钉大（PASS），但稳态吞吐由桥泵决定，提升不可达（FAIL）。
- 失败分级：**recoverable/前提失配**（非编译/基线回归 fatal；床全程可用）。

### 4.4 建议（供 PM 裁决）

1. o93t 代码部分（opt-in 字段）保留：高 BDP+发送端供数充足的拓扑（如未来 piped 泵合入后）仍是正确运维工具；单测与生效路径已固化。
2. 稳态吞吐提升的正确杠杆=8sum feature 分支的桥泵票（feature/8sum-plan-a），非 sockopt 层。
3. 或将本票收窄为「sockopt 配置面补齐 receiveBufferSize + 窗生效实证」，吞吐判据移交桥泵票。

## 5. 32 节点 wire-format 回归

```
cp target/release/xray.exe dist/xray.exe（新 release 构建，lto=fat，38,723,584 B）
python dist/run_full32.py
→ === 32/32 PASS  0 FAIL  0 PARSE ===   （耗时 281s）
```

## 6. side-effects

无未预期副作用：字段默认 0 时所有路径零行为变化（单测锁定）；VPS 床配置收尾已还原（srv.json/cli.json 复原 orig，残留进程清零）；本机容器/床产物均落在 /tmp 与 D:/tmp/o93t。
