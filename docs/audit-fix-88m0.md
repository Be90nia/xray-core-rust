# audit-fix-88m0：vision 残留 DEATH 定位战役（2026-10-08）

**结论：TRUNC 家族已灭（61ba8fc1 本机 A/B 实证 5/20→0/26）；DEATH（吞吐塌缩 433KB/s）本机 56+ 轮 × 4 触发族未复现，根因定位停在「需 VPS netem 环境」，[P7LM-DW] 收尾面包屑已入库待 VPS 侧取证。**

VERDICT: FAIL（DEATH 未修复——诚实交付：本机无 netem 无法复现，不造无证据的 code change）

---

## 1. 票面与前提核对

- 票：Xray-core-rust-88m0（P2 open）——vision 下载残留 DEATH 1/5（End 模式）。
- 签名（VPS vfix-cli-1 轮）：433KB/s × 120s 连续无间隙（curl --max-time 杀，exit 28），
  缺 58×8192=475,136B≈恰差 1.1s 完成；同轮 bak（pre-61ba8fc1）同签名 → 预存在缺陷。
- A/B：bak 1/5 death + 1/5 trunc；new（61ba8fc1）1/5 death + 0/5 trunc →
  61ba8fc1 消除 TRUNC 未消除 DEATH。
- VisionMac5 终报修正（本轮采纳）：DEATH 非停摆/死气，是**吞吐塌缩**模式——
  trace 全程连续 ~1100 行/s，速率 433KB/s 低于 padded 天花板 0.9-1.3MB/s。

## 2. 本机装置（新增/扩展）

### 2.1 复现装置参数化（crates/xray-proxy-vless/src/encryption/vision_conn.rs）

`tmp_end_mode_segmented_stall_repro` 宏背压旋钮（**缺省行为不变** 40/150）：
- `XRAY_STALL_MACRO_EVERY`（停读周期）、`XRAY_STALL_MACRO_MS`（基准时长 ±50% 抖动）、
  `XRAY_STALL_SEED`（0=时间+pid 每轮独立抽样并打印种子）。

### 2.2 本地全栈测量装置（D:/Project/vision-matrix/，新）

- `local_setup.py`：本地证书（pin 字符串格式）+ 双端配置（freedom finalRules 回环放行）+ 50MB bench。
- `delay_proxy.py`：client↔server 间用户态时延代理——每方向每 chunk（64KB 读）延迟
  RTT_MS/2 + 概率抖动停顿（窗口关闭效应）+ **逐连接字节计数**（c>s / s>c 对账丢失层）。
- `https_origin.py`：内层 TLS origin（触发 vision 写侧 is_tls12_or_above 判定）。
- `local_matrix2.py`：HTTP/HTTPS 双模式矩阵，逐轮 exit/size/speed/wall 判定 OK/DEATH/TRUNC。

### 2.3 服务端收尾面包屑（crates/xray-transport/src/bridge.rs down_writer）

`XRAY_P7LM_TRACE` 门控 eprintln（诊断，零行为变更）：
- `[P7LM-DW] write err at total=NB`（写错误断点）
- `[P7LM-DW] drain done total=NB, shutdown_flush begin`
- `[P7LM-DW] shutdown_flush ok|ERR|TIMEOUT(3s) total=NB`——**"shutdown_flush 覆盖外第二条
  pending 路径"的直接观测点**：若 DEATH/TRUNC 轮出现 ERR/TIMEOUT 或 total<预期，即实锤。

修复 diff 摘要（本轮全部为诊断/装置，无生产行为变更）：
1. vision_conn.rs：装置宏背压参数化（+28 行，cfg(test) 域）。
2. bridge.rs：down_writer 收尾三态面包屑 + 消除重复 shutdown_flush 调用
   （原代码单次调用保持，仅捕获结果打点；+18/-1 行）。

## 3. 实验矩阵与结果

| 触发族 | 轮数 | 二进制 | 结果 |
|---|---|---|---|
| 切碎器装置（FRDBG/VCDBG 开） | 20+12 | 旧/新 | 0 death |
| 抖动代理 12%×100-400ms（HTTP origin） | 20 | 旧 | 5 TRUNC，0 death |
| 抖动代理（HTTP origin） | 10 | **新** | **0 TRUNC 0 death**，1.25-1.54MB/s |
| 抖动代理（HTTPS 内层 TLS origin） | 10 | **新** | **0 TRUNC 0 death**，VCDBG 实证 `frame done cmd=2`（DIRECT 早触发） |
| 深停顿代理 6%×0.8-2s（窗口全闭） | 6 | **新** | 0 TRUNC 0 death，0.58-0.70MB/s（停顿税，符合预期） |

### 3.1 TRUNC A/B（61ba8fc1 有效性实证）

- 旧 exe（0930 11:45 构建，pre-61ba8fc1）：20 轮抖动代理 **5 轮截断**，
  缺口恒 8192 整数倍（3×8192=24,576 / 5×8192=41,056 / 6×8192=49,152），
  截断轮速度正常（非停摆）= 纯收尾蒸发形态。
- 新 exe（HEAD 工作树，含 61ba8fc1）：**26 轮 0 截断**（HTTP 10 + HTTPS 10 + 深停顿 6）。
- **五层字节对账（截断轮）**：curl 实收 = 客户端 vision 交付（差=0，客户端桥无罪）；
  服务端 origin 读 = vision 写 = 52,429,006 全量；代理 s>c 转发比 clean 轮少 ~21KB
  → 尾巴死在**服务端 TLS sendable_tls → socket 之间**，即 61ba8fc1 所修路径；
  新二进制同条件不复现 → 修复有效。

### 3.2 DEATH 未复现的排除记录

- HTTPS 内层 TLS origin：每轮客户端 VCDBG `frame done cmd=2` → DIRECT 均早触发，
  padded-forever（whole_complete 相位冻结假说）在本机 origin（python ssl 16KB 记录）下不成立。
- 深停顿（窗口全闭 2s）：收尾路径无 ERR/TIMEOUT 面包屑异常（`shutdown_flush ok`）。
- 结论：DEATH 需 VPS netem（loss+RTT）环境复现；本机用户态代理无法模拟 loss 的
  CC 收缩动力学。禁 ssh 红线下不在本代理可达范围。

## 4. 验证命令与关键输出

### 4.1 双 crate lib 全绿（验收①）

```
cargo test --lib -p xray-proxy-vless -p xray-transport
running 258 tests
test result: ok. 258 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 49.89s
running 532 tests
test result: ok. 532 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.61s
```

### 4.2 复现装置 ≥20 轮 0 death（验收②）

```
python target/tmp-repro/loop_repro.py 20   # XRAY_FRDBG=1 XRAY_VCDBG=1
round00..round19 rc=0 dead=False
DEATHS=0/20
```
（bg_187 批跑，逐轮 rc=0；此前同装置 12 轮亦 0 death。）

### 4.3 本机全栈矩阵（新二进制基线）

```
python D:/Project/vision-matrix/local_matrix2.py 10        # HTTP origin
hp-round1..10: exit=0 size=52428800 -> OK（10/10，1.25-1.54MB/s）
python D:/Project/vision-matrix/local_matrix2.py 10 https  # HTTPS origin
hs-round1..10: exit=0 size=52428800 -> OK（10/10，1.25-1.63MB/s）
```

## 5. 下一步（交还 PM 排程）

1. **VPS 侧取证**：部署 debug 产物（含 [P7LM-DW] 面包屑 + FRDBG/VCDBG），跑
   vps_verify_matrix.sh 5 轮 × netem——截断/塌缩轮的
   `shutdown_flush ok|ERR|TIMEOUT` + `frame done cmd=` 缺席即"第二条 pending 路径"实锤。
2. WAN 20MB 验收协议（wan_matrix_20mb.sh，PM 已定案）：≥5MB/s 窗口期 10 轮三零。
3. 若 VPS 侧证实 padded-forever 分支（`frame done cmd=` 整轮缺席 + 433KB/s），
   候选最小修复方向（已评估未实施，等复现锚定）：写侧分帧在 TLS12+ 批内按内层记录
   边界取前缀，End/Direct 携边界片，尾片留给 commit 后裸流（Go early-end break 语义），
   确定性退出 padding，消除 64KB 恒定批窗口的相位冻结。

## 6. 残余风险

- DEATH 根因未锚定（本机不可复现），[P7LM-DW] 面包屑是下一发的取证抓手。
- 本机装置的代理天花板 ~6.4MB/s（64KB/10ms），可能掩盖 >6.4MB/s 模式的差异。
- 88m0 票面"End 模式尾批 8KB 批窗口"候选假说保持 open，待 VPS 证据裁决。

## 7. 本机 release 重建配方（下个代理必读）

- **exe 归属 `xray-cli` 包**：`cargo build --release -p xray-core` 只出库不出行内 exe
  （target/release/xray.exe 不会更新）；必须 `-p xray-cli`。
- release 链接报 LNK2019 `SSL_set_reality_rewrite_cb`/`SSL_get_x25519_key_share_private`/
  `SSL_set_reality_server_hello_cb`：release btls-sys out/boringssl 丢 REALITY patch
  （fork build.rs 静默早退坑）。救法（无需 4min 冷编）：
  1. `python -c "import sys,pathlib; sys.path.insert(0,'tools'); from setup_boringssl_reality import apply_reality_patches; apply_reality_patches(pathlib.Path(r'target\release\build\btls-sys-65756d05178d9f5e\out\boringssl'))"`
  2. 带 `BORING_BSSL_ASSUME_PATCHED=1` + `BORING_BSSL_SOURCE_PATH=<上述 out\boringssl 绝对路径>` 重建 `-p xray-cli`
     （新 env 改 fingerprint → build script 重跑 → CMake 增量重编 ssl.lib）。
- freedom 出站默认 BlockPrivate（127.0.0.0/8）：本地回环 origin 必须配
  `"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]`，否则黑洞挂死。
- 客户端 `pinnedPeerCertSha256` 是**字符串**（逗号分隔 hex），JSON 数组形态会被静默忽略
  → 自签证书 UnknownIssuer。

## 8. 源码定位与 RTT 判别实验（88m0 升级任务，2026-10-08 第二轮）

背景：VPS 取证钉死 DEATH 机理 = 连接出生即 2×RTT 锁步泵（burst 2.8ms + 等待 p90
158.7ms≈2×netem RTT，64KB/0.1587s≈413KB/s≈实测 433KB/s）；cmd=1 End 0.27s 早触发；
服务端 drain 全量 + shutdown_flush ok；netem 队列无溢出（dropped 0.074%≈配置值）。
三候选：① raw arm 定时器族未重置 ② padded 相位锚定 ③ 读写互等。

### 8.1 候选逐一排除（代码证据）

- **①排除（双重）**：`RAW_WRITE_ARM_DELAY`(vision_conn.rs:155) 只在 `arm_splice_raw()`
  (:682-697) 武装 `raw_write_gate`，唯一调用点 = `poll_arm_gate` 的 `UpGate::DirectArm`
  分支 (:653-662)；VPS death 轮实测 cmd=1（End）→ DIRECT 分支全程未进入，定时器从未
  存在。End 路径提交闸（:664-676 与分支 1 的 EndCommit arm）为单次一次性 flush 闸，
  commit 后 `uplink_padding=false` 进入无闸 branch 2 直写。且该定时器为 50ms 单发
  sleep，不构成 158.7ms 周期等待。
- **②排除**：cmd=1 于 0.27s 落地即 padded 相位终结，「初始相位锚定错误持续整轮」与
  wire 事实矛盾。
- **③排除（结构证明+实验）**：服务端写泵与 wire **结构性异步**——write_vectored_all
  （xray-buf writer.rs:75-116）只等「字节被消费进 rustls」（rustls Writer 无界缓冲
  sendable_tls，write_io 撞窗仅 Ok 收纳），泵永不等待 wire 完成信号 → 结构上不可能
  自身产生 64KB/RTT 节律；窗口允许时连续馈线，wire 静默期只能来自内核发送侧节律
  （TCP 窗口/pacing）。实验证据见 8.2。

### 8.2 真 RTT 判别实验（delay_proxy v4）

装置升级：v4 读侧即收即入队 + 按就绪时间异步转发（传播延迟不压吞吐）+ 8MB 在途
背压 + 逐连接字节对账（`delay_proxy.py <rtt_ms> <target_port>`；
local_matrix2.py 以 `XRAY_PROXY_RTT_MS` 旋钮注入）。

```
XRAY_PROXY_RTT_MS=75 python local_matrix2.py 30 http   # VPS 同量级 RTT
hp-round1..30: exit=0 size=52428800 全 OK，85-104MB/s 连续流（30/30，0 慢轮）
```

判读：VPS 同量级 RTT 下 30/30 无锁步——若「泵每批等一个 RTT 完成信号」在 xray 代码
内，该装置必现 ~430KB/s 慢轮；实际连续流 → **锁步不在 xray 应用层**。

### 8.3 收敛与下一判别（VPS 侧）

应用层三候选全排除 + 本机 RTT 仿真不复现 + bak/new 同发生率 + 每连接出生掷签
→ 指向 **netem 路径的 TCP 窗口动力学**（内核发送侧 pacing/初始窗口/DRS 未成长，
~20% 掷签 = 连接出生相位）。下一判别（VisionMac5 VPS 侧）：

- death 轮传输中 1s 间隔采样两侧 `ss -tinm`：cwnd/rwnd 若钉在 ~64KB 且随窗口更新
  节律阶跃 = TCP 窗口动力学实锤，应用层无罪；
- `nstat -z TcpExtRetransSegs,TcpExtTCPLostRetransmit` 增量对照。

若实锤：88m0 DEATH 桶建议改判「netem 环境下 TCP 窗口动力学伪影 + curl 120s 边界
掷签」，非 xray 代码缺陷，可关票（TRUNC 部分已由 61ba8fc1 修复并双向实证）。

## 9. 修复（bd 88m0 终版：862340ff/7p1m 同族发送-接收孪生，2026-10-08 第三轮）

Go 对照终裁改判：同内核/同 netem/同拓扑 **Go official 10/10 全净（6.7-13.9MB/s）vs
rust 5/20 异常** → rust 真缺陷（§8.3 的"内核物理"判断修正：内核窗口动力学是**表现
形态**，触发器在 rust 侧套接字配置）。头号线索 = 同族前科 **862340ff（7p1m）**：该票
实锤「快排空 relay 下内核 DRS（tcp_moderate_rcvbuf）结构性自稳定——收端即时排空 →
接收队列恒空 → autotune 永不逃逸 → 接收窗钉死 ~64KB、吞吐=窗/RTT（0.31MB/s）」，
修复=freedom 拨号显式 SO_RCVBUF 4MB。本轮 death 轮 413-433KB/s ≈ 64KB/158.7ms
为**同一机理的下载方向孪生**：客户端 vless 出站 socket（收侧）无 862340ff 的调优 →
接收窗出生掷签钉死 ~64KB → 服务端被窗口更新节律牵着走（服务端泵经 sendable_tls
与 wire 异步， faithfully 转发窗口允许的字节 → 客户端看到 64KB/2×RTT 爆发-等待）。
Go 全净 = Go 运行时调度偶然逃逸 DRS 自稳定（862340ff 票面已有此结论）。

### 修复 diff 摘要（crates/xray-transport/src/sockopt/mod.rs）

- 新增 `TCP_RCVBUF_DEFAULT: i32 = 4MiB` 常量（含机理文档）。
- `apply_outbound_socket_options` / `apply_inbound_socket_options`：SO_RCVBUF 由
  「opt-in 显式才设」改为「缺省 4MB、显式 `receiveBufferSize` 优先」（Linux 显式设
  置锁 DRS 自稳定为记账上限非预分配，空闲零内存代价——862340ff 同语义）。
- 字段/JSON 注释同步（`0` 从"不设置"改为"取 4MB 缺省"）；过期副作用声明修正。
- 测试：`apply_socket_options_on_real_tcp_connection` 增加缺省 4MB 断言；新增
  `outbound_explicit_receive_buffer_size_wins_over_default`（显式优先回归锁）；改写
  `receive_buffer_size_applies_and_defaults_off` → `_4mb`（旧契约即本次翻转的语义）。

### 验证

```
cargo test --lib -p xray-transport -p xray-proxy-vless
test result: ok. 258 passed; 0 failed  (vless)
test result: ok. 533 passed; 0 failed  (transport，含 3 个 rcvbuf 回归测试)
cargo clippy --lib -p xray-transport → 0 warning
```

VPS 20 轮验证（25% 发生率捕获 ~99.7%）由 VisionMac5 在修复二进制部署后执行
（`-p xray-cli` release 产物，含 §2.3 面包屑与本修复）。

