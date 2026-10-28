# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

> 范围：`feature/framework` 框架支线实质变更（领先 master 695 commit，核对基准 `7b336a12`；发版收敛由 PM 负责）。互通红线不变：全部改动过 32/32 真机互通 + interop 12/12。

### Added

- **REALITY 本地双向 wire 互通**（`e235355f`）：`dist/interop_reality.py`（vless+reality+裸 TCP，Rust client↔Go server / Go client↔Rust server）**2/2 PASS ×2 次**；dest 回退走 Go xray vless+tls 实例（Python HTTPS 版会间歇中止 reality 的 dest steal 握手，属工装 artifact）。既有矩阵（6 协议）未动
- **A/B 判定工装**（`tools/ab_gate.py`）：把「性能只能同窗交错 A/B」纪律工具化——严格 A,B,A,B 交替 + 编译进程拒跑/轮间离散度标记 CONTAMINATED + 中位数比值判定 + 逐次存档 `reports/bench/ab-*.json`；A/A 干净窗偏差 3.1%（建议 tol=0.05，无法确认干净时 0.08）
- **xray-frame 六面派生件落地**（能力收敛 W1，`1679a5a7`）：`compat`（进程级能力入口：一次性 install + 作用域守卫 + 兜底=迁移前行为；**禁 thread_local**——tokio 任务跨线程迁移语义错）/ `redline`（红线受控入口：`RedlineSite` 穷举 + 受控执行 + 源码扫描 CI 门）/ `scope`（ConnScope 两级 scope：arm → connection）/ `deadline::Budget`（双源：Tokio 虚拟钟 advance + Wall 由 `Clock` 判负）/ `logging::HotLog`（栈缓冲零分配热路径门面）/ `config::XrayConfigLayers`（tag 合并 + outbounds prepend + tail）；7 份测试随件进 CI
- **ADR-1/ADR-2 入宪**（`CLAUDE.md §3.5.5`，`377c712d`）：能力归属三层判定顺序固定（零 Xray 语义 → udf；否则 → xray-frame；仅当逐条举证才留主仓）+ `compat`/`redline` 两条执行约束（登记集合不随迁移增长）

### Changed

- **ConnScope 级联改事件广播**（bd `mzput`）：`ArmScope`（内嵌 udf `FxScope` + `tokio::sync::watch` 关闭广播）承接父→子级联，取代 `child_of` 的 20ms 轮询——**稳态唤醒 50 次/秒/连接 → 0**；选 watch 非 `Notify`：级联是「状态」非脉冲，watch 终值 + 每接收端独立版本账天然覆盖「父先关 / 子后注册」两窗口；udf 父仓零改动；`start_paused` 测试证明无定时器
- **HotLog 快路径无锁化**（bd `9doy9`）：`enabled()` 每调用加解锁（`metas: Mutex`）→ `AtomicU8` 级别 + `OnceLock` 一次性整表；实测 **18.1 → 5.5 ns/call**（与 `tracing::enabled!` 宏 5.1ns 同级），4 线程竞争聚合吞吐 **13.7 → 550 Mops/s（≈40×）**；API 签名零变化、零新依赖
- **xicmp/system_listener 裸 tracing 收敛**（bd `pdm1q`，`4065d7d0`）：`336d8430` 引入的 8 处 `tracing::` 直调（晚于台账生成 → 门看不见）改为 `hot_log!`（4 处错误条件臂）/ `crate::LOG`（4 处系统/连接级）；事件文本与 target/level 零改动、无新增 allow
- **tracing 收口（proxy 16 crate 生产裸宏 217 → 0）**：批 2a `d3c43a61`（tuic/anytls/trojan/hysteria 109 处）+ 批 2b `96483e8f`（wireguard/tun/freedom/vmess 90 处，含 `event!` 逃生口拆除）；模块级 `LazyLock<LogFacade>` 门面 + per-crate 宏禁令（探针验证真拦截）
- **L3 台账**（`888c6b8f`）：dispatcher/kcp/splithttp 补 spawn/时钟禁令 + 43 处生产站点逐点 allow 登记（reason 含语义归类）
- **时钟收敛**：W3a `b085ff97`（common/tls 9 站 → udf `SystemClock`，删 allow 8 处）；W3b `7d71a6c6`（transport/ss/wireguard/tun 64 站 → `compat::clock`，删 allow 40 项）
- **配置装配切框架件**（W2 `4ec2f28c`）：`merge_configs` 换 `XrayConfigLayers` 折叠（旧 typed 循环删除无 shim）；影子三路对照 = 旧↔新 18 组 0 差异、新↔Go v26.10.17 合并签名域 12/12 全等；未知键保留面由专门测试钉住
- **tokio 虚拟钟预算点**（W5 `bb7b54eb`）：34 站给出去宿——迁 22（tuic 5/vless 6/vmess 4/transport 7）；例外 12 分四类登记（`Sleep::reset`/`sleep_until` 只收绝对 `tokio::time::Instant` 而 `Budget` 刻意不外露绝对时刻 → 结构不可迁；`bridge.rs` 热路径每读超时 5 处不动）
- **热路径日志**（W6 `8a200d7b`）：transport 族 40 站 → `HotLog`（栈缓冲、先过滤后格式化）；**40/40 消息逐字保留**；p7lm 调查通道 9 处一字未动（其 trace 税曾把优化实测毒化成伪影约 36% 吞吐）；A′/B 真单变量交错 3 窗口 Δ 在噪声内
- **红线受控入口接线**（W7 `23769fa0`）：vless vision 数据面错误事件 `tracing::event!` → `redline::event`（结构化 `error` 字段**折叠进 message**，`redline` API 零扩张）；`redline_sites` 四门 4/4（改前 3/1）
- **任务托管归 scope**（W4 `b46d6058`）：mux carrier 4 处 → arm scope（与 inbound 同寿命）、SS 泵 → 每连接 `ConnScope`；`inbound.rs` 生产裸 `tokio::spawn` 清零。**停机语义有意收紧**：泵/carrier 随 arm scope 关闭被级联取消（原 detached 跑完）
- **运行期注册表**（C-R1a `554377d7`）：`SimpleOhm` 的两张 tag→handler 表 → udf `BoundedRegistry`（对外 API **逐字不变**，commander/reverse 零改动）；cap 4096 + `Eviction::Reject` + `error!` 留痕（fail-closed，不静默丢 handler）；`--features dispatcher-dual-write` 双表漂移 0
- **重试编排**（C-R2 `12a3ff2b`）：kcp `RetryableWriter` → udf `std_ext::retry`（固定间隔截平形；`Exhausted.last` 原样回灌）；行为差仅两处严格改善（末次不空睡、零间隔 fail-closed）

### Fixed

- **P1 停机不掐在途连接**（bd `a9xgp`）：`shutdown_token().cancel()` 与 `Instance::close()` 原先只停 accept 层——实测在途长连接在 cancel 后 2s 内仍以 8MB/s 中继 1.29–1.54MB，`close()` 1.3ms 返回后继续回传 1.25MB。根因：`ArmScope::close()` 全仓零调用点 + `child_of` 监视任务持父 Arc 锚 → 级联在停机形态下结构性不可达。修：`xray-frame::ArmScopeRegistry`（装配序 Vec + 逆序 close，登记点收敛到 `spawn_inbound_serve` 唯一漏斗，表属主 `Instance`）+ serve 壳双臂 select（token cancel → `ArmScope::shutdown_timeout(5s)`：广播 → ConnScope 级联 → `abort_all` + 有界排空）。**闸门测试 `shutdown_token_cancel_terminates_inflight_long_connection` 3/3 绿（0.03–0.04s 终止，修复前永不终止）**；过程中修掉一个真竞态（`select!` 双臂随机裁决会跳过级联，join 臂改为 token 已取消时兜底排空）
- **测试端口探测 TOCTOU**（53 处 `crates/` + 约 55 处 `tests/`）：`bind(:0) → drop → 被测方再绑` 在窗口期被并行测试抢走（全量 `--workspace` 下确定性偶发 `os error 10048`）。统一收口为 `xray_common::testing::{pick_free_ports(n), is_addr_in_use_err}` + 换端口重试；**顺带修掉真 bug——旧 helper 用 `"in use"` 字符串匹配，中文 Windows 错误文本是「只允许使用一次」→ 永不命中**。断言零改动、零新增 sleep
- **栈足迹回归**（W5 发现，W4 扩面复核）：`BudgetDeadline::timeout`（**async-fn 形态**）在巨型 future 内加厚栈帧 → `vmess_inbound_udp_relay_e2e` 确定性 `STATUS_STACK_OVERFLOW`（HEAD 版 PASS，三步单变量取证）；改**构造式** `deadline::timeout(fut, remaining())`（具名 `Timeout<F>`，与裸调用同体积）；vmess 3 + vless 5 + core UDP relay 4 处统一。框架结论：**构造式 = 默认正确形态，async-fn = 便利形态有栈代价**
- **红线门对别名隐形**：受控入口若用 `use ... as` 别名调用，字面量扫描门得到空集合直接放过（整个文件对门不可见）→ 改全路径调用
- **W6 fmt 漏跑**（`5baf33cd`）：PM 验收漏跑 fmt 门导致已入库文件带 3 处 rustfmt 差异（CI fmt 会红），补修
- **三处静默失效**（bd `kyy50`）：①生产 `tracing` 订阅者此前是裸 `fmt()`——`mask_secrets` 只在 udf `ChannelRegistry::emit` 一处生效，裸 `tracing::*!`（`inbound.rs` 单文件 629 处匹配）连同 `LogFacade`（secrets 表为空）/`HotLog` 的 tracing 通道全部**绕过掩码**；改为 `MaskingMakeWriter` 逐行掩码 + `xray_common::log::set_secrets` 一次写两处（通道表与 tracing 快照同源），`log::mask_text` 空表零分配透传。②`SystemPolicy.buffer` 在 Go proto 中不存在、全仓无消费点（"gRPC 设了静默无效"）：`Manager::new` 装配期拒启并指明受支持的 `levels.<n>.bufferSize`。③`tcpKeepAliveIdle/-Interval` 负值被 `as_u64()` 吞成 `None`（关 keepalive 的配置静默变成 45s 默认探测）：改有符号解析——任一为负 = 关 keepalive（Go `Enable=false`），符号相反 = 装配期硬错（Go `system_dialer.go:111`）。附带修掉 vmess legacy 告警/错误链里的 UUID 原文（S-11）
- `Cargo.lock` 漏带（`073870b5`）：C-R2 的 kcp 依赖边未随 commit 入库，补齐（干净检出可构建）

### Docs

- **性能门判定纪律定稿**（`docs/benchmarks/baseline.md` 2026-10-27 节，两次自我更正）：绝对吞吐**不可跨窗比较**（并发编译压低约 20%；同一二进制跨窗也可差 ~20%）→ 主判据 = **当场交错的 A/B 相对差**（轮间交错，分块会吃进时段漂移）；测量窗内禁一切 cargo 编译 + 前后进程快照取证；两个测量窗严禁重叠；**A/B 混杂即作废须重跑**
- **显式豁免（非未完成）**：DNS `cache_controller` 留 `xray-app-dns`（ADR-1 判据③逐条举证：DNS 方向件 + Go 语义逐字对齐 + 热路径并发面，udf `TtlCache` 单线程 `&mut self` 适配必加全局锁）；已登记 `udf-promotion-candidate` + 缺口入 bd `n539c`
- **框架装配骨架 `crates/xray-frame`**：强约束插件模型五层落地——`Plugin` 必选方法集 + `PluginContract`（`ClauseId` 12 条款）+ `PluginContext` 能力句柄 + 生命周期编排 + 启动期装配门（deps 缺失/成环 fail-visible）；L3 lint 层 = per-crate `clippy.toml` 禁令（现 33 个 crate）
- **协议插件化**：29 个 crate 接入 `xray-frame`；16 个协议 crate 带 `tests/plugin_contract.rs` 契约测试进 CI（`assert_plugin_contract!` L4 行为夹具）
- **中央协议臂表化**：`xray-core/src/arm_builders/` BTreeMap 构造表成为唯一构造路径（未命中显式失败；旧巨型 match 删除；unix 变体 4 臂残留待收口）
- **udf-frame 地基接线（首批）**：25 个 crate 消费 udf——`std_ext::json`（RFC 8259 严格解码 + 64MiB 输入上限 + 行列位置错误）、`logx::ChannelRegistry`（general/access/dns 三通道单入口 + 密钥掩码）、`FxScope` spawn 托管（协议/app 族先行；传输/核心面收口在途）、`skeleton::clock` / `std_ext::scheduler` 时钟调度；CI 经 `.github/actions/fetch-udf` 拉取 udf main 最新 + 上游 CI 状态闸（红项拒绝消费）
- TUN `IFF_VNET_HDR` 继承 fd 支持（Linux 真机双向流量实测）；xicmp raw socket 真收发（WSL root 取证）；UPnP/NAT-PMP 端口映射（SSDP 兜底 + 真机 IGD 验证）；ws/httpupgrade/splithttp/grpc 四 hub transport 级 Unix 监听 + `spawn_unix_inbound` 生产接线（vless/trojan/vmess/shadowsocks 四协议覆盖）

### Changed

- **CLAUDE.md 升格为项目宪法载体**：三层定位（udf=地基 / udf-frame=骨架 / xray-frame=血肉）+ §3.5 继承派生纪律（禁重复造轮子、方向件留主仓判据）+ §3.5.4 归一化面追踪
- **accept 面定形**：accept 框架不落 xray-frame（P1-3 裁决作废），统一收口于 `xray-transport::accept_policy`（错误分级 + 退避；网络方向件留主仓）
- 配置解析收敛：`xray-conf/src/json.rs` 降为 Xray 语义薄壳（实体机制上浮 udf `std_ext::json`，主仓随版受益）；日志分发收敛为 `logx::ChannelRegistry` 单入口（旧 `HANDLERS` 无差别扇出 + tracing 双写删除）
- 测试面 spawn 纳入 L3 闸：`xray_common::testing::spawn` 单入口，14+ crate `src/**` 测试面裸 spawn 收口（约 159 处）+ 18 个 `tests/*.rs` 60 处迁移
- **生产裸 `tokio::spawn` 收口（FxScope 托管）**：10 个 `xray-proxy-*` 裸 spawn 清零（余 3 处红线/冻结面登台账）；`xray-transport` 129 处、`xray-core`/`xray-common`/`xray-tls` 时钟面 38 处全量分类（可迁者已迁，其余逐点台账 + `clippy.toml` 禁令）
- **裸 spawn 台账收口（bd `f17zu`+`hj3jf`）**：生产裸 `tokio::spawn` **137 → 132**、丢 JoinHandle **99 → 94**、无 `reason` **9 → 0**；5 处迁上游显式脱管口 `FxScope::spawn_detached`（mux carrier/上行泵 2 + xdns recv/send/dr 泵 3），94 处丢句柄逐点裁决（托管 / 脱管 + 寿命归属写入 `reason`）；14 处保留粗粒度 allow 全部举证（分层规则 >20 处/文件 10、表达式位无法挂属性 4）；55 个 crate 的 `clippy.toml` 台账表述同步；复核脚本 `reports/audit-2026-10-28/spawn_ledger.py`（可复跑）
- **生产 `Instant::now` 收口（`ctx.clock`）**：`xray-app-*` 26 处迁移（geodata 证书校验时钟口子收紧）；16 个 `xray-proxy-*` 时钟面全量分类（净迁 2 + 台账 35）
- **inbound 注册表升 `BoundedRegistry`**：`InboundRuntime` 由 `RwLock<Vec>` 线性扫改为 fail-closed 有界注册表（查找 O(n)→O(log n)，删影子双轨）；双写对照 175 次比较差异 0

### Performance

- **vendor/rustls deframer 补丁**（`prepare_read` 缩容条件去 `self.used == 0`）：rustls 拓扑 `tls_read` 分配 **4.76 → 1.00 MB/MB（−79%）**、总分配 −76.7%、客户端 **CPU −17~19%**、吞吐 **341 → 415.5 MB/s（+21.7%）**；TLS wire 逐字节不变（8MB+200MB sha256 双侧 MATCH、tshark record 数精确相等）。代价：空闲连接常驻 ≤allow_max（+12KB/conn）
- **客户端 TLS 读缓冲池化**：`xray-buf` 读路径每次 `poll_read` 的 64KB 新分配改为池化复用（`Buffer::new_pooled` 走 128KB 层），cli **alloc/MB 9.239 → 5.085（−45%）**
- **h2/xhttp 服务端下行发送块池化**：`tokio-util::ReaderStream` 每帧 `reserve(64KiB)` 改池化块 + `Bytes::from_owner` 归还，srv **alloc/MB 2.159 → 1.299（−0.86）**；h2 DATA 载荷双向逐字节相等
- **XUDP 首帧/累积双拷贝清零**：`to_vec` 摊平改 `ChainCursor` 链式喂 `PacketReader`（0 拷贝），每包分配 **3 → 2**
- **Windows 上 btls 恢复汇编**（P1）：`btls-sys` 在 Windows 无条件设 `OPENSSL_NO_ASM=YES` → BoringSSL 排除 `cpu_intel.cc` → AES-NI 探测恒 false → 协商 CHACHA20 且无汇编 → **纯 C 回退**。新增 `tools/build_boringssl_asm.py`（NASM 编带汇编的 BoringSSL + `BORING_BSSL_PATH` 预构建路线）：带 `fingerprint` 的客户端吞吐 **31.6 → 241.2 MB/s（7.6×）**，cli CPU 18.8s → 2.48s，REALITY 组 33.4 → 241.2；32/32 + interop 12/12 保持。附带修正：开汇编后协商 **TLS_AES_128_GCM_SHA256**，与 Go `crypto/tls` 偏好一致

## [26.10.11] - 2026-10-22

### Fixed

- MemoryAccount（SS/Trojan/VLESS/VMess）与 `UUID`/`protocol::ID` Debug 脱敏：凭据禁入 tracing/panic 输出（bd 2ktp ③）
- VMess chunk size u16 溢出 7 处 `unwrap_or(u16::MAX)` 静默替换改显式错误（防收端错位；现行调用面不可达，纯防御）（bd 2ktp ②）
- REALITY 回贴 Go tls.go:233-235 MLKEM768 key share 门：X25519-only ClientHello reject→forward，`parse_key_shares` 对齐 v26.9.30 单轮扫描语义（bd 2ktp ①）
- anytls `padding0_len` 缺上界 → 分配前按 16 KiB 拒绝（Go/sing `UDPBufferSize`；Go 从不按客户端声明分配）（bd 8tfh）
- AEAD 就地 seal 失败路径回滚不变量：AES-128/256-GCM 失败时截断回写，防「残留明文被当密文」在同缓冲复用处上线（bd bqro）
- PROXY protocol 头读取加上界：v1 107 B / v2 4096 B，超限拒连（Go go-proxyproto v2.go:28 拒绝点）（bd 3ghm）
- `Debug` 脱敏扩至 REALITY 私钥与 ML-DSA 种子、inbound `server_private_key`、xmc 口令/RSA 私钥、ECH `private_key`（bd 99kd）
- commander admin TCP bind 失败从 spawn 后异步 ERROR 上升为启动期 fatal（对齐 Go `commander.go:85-92`）（bd 99n3）
- tun netstack UDP 源/目的家族不匹配：`panic` → 丢弃 + `warn`（对齐 Go `tun/stack.go:347-351`）（bd x1fz）
- REALITY 入站 `tcpSettings.header` 伪装头接线补齐（vless/trojan 双路，此前静默失效）（bd 8q0d F3）
- vless enc nonce 轮转对齐 Go：读侧轮转 + `MaxNonce` 回绕 + 写侧「旧钥封→完整记录派生」（bd 8jp6）
- finalmask 配置 fail-loud：xdns `names[]` 展开为多条同参域、realm `tlsConfig` 非 null 拒绝、salamander `packetSize` 拒绝（bd 037f）
- relay `dispatch_via_chain` 补 512 KiB 背压上限（对齐 Go `pipe` + `policy` 默认，防无界蓄洪）（bd exci）
- app-dns 上游错误不再统一吞成 `record not found`：保留错误种类 + per-server 日志带原因（bd pyl1）
- listener backlog 改读 `somaxconn`（fallback 1024；Go Linux fallback 为 128，属有意偏离以保住 VPS overflow 战果）（bd hjtt）
- **Windows TUN 入站此前被 cfg 门整段排除**（bd b8i 显式不支持）→ 开放 Windows：`xray-core` 4 处 cfg gate + `Cargo.toml` 平台依赖声明（`spawn_one_inbound` / `tun_factory` / `parse_tun_inbound_config` / `TunPlaceholder`）。真机实测：适配器 `xray0` Up + `10.66.66.1/30 (Manual)`（bv3w/cv3w）
- **TUN 出站自绕**：`DialerController` 覆盖全部系统拨号路径（`dial_tcp_raw` 主链 / `dial_client_tcp`（ws/splithttp/grpc/httpupgrade）/ happy_eyeballs 候选 / freedom UDP relay），TUN 经 `autoOutboundsInterface` 选择物理网卡并在 connect 前绑定；优先级对齐 Go（controllers 先、用户显式 `sockopt.interface` 后写覆盖）
- Windows `netsh interface ipv4 set interface` 参数名错误：`name=` 不是该子命令的参数（正确为位置参数 `interface=<名>`），此前报 “name is not a valid argument”
- 未知 transport 网络名从**静默接受**改为配置期硬错（文案逐字对齐 Go `Config: unknown transport protocol: <p>`）；`method` 优先于 `network`（Go `transport_internet.go:85-88`）；`xhttpSettings` 回退收窄到 xhttp/splithttp（防 `network:"ws"` 静默吃下 xhttp 配置）
- TUN UDP：目的组播/广播包不进 relay（SSDP/mDNS 洪泛源）+ relay 失败目的级 5s 冷却（防 ~50ms 一轮重建刷日志）（bd ijn7）
- `crates/xray-transport/src/headers/` 删除 5 个零引用变体（dtls/srtp/utp/wechat/wireguard，真身在 `finalmask/mkcp/header.rs`）
- **inbound 监听静默死亡**（生产 P1，bd wsiq）：accept 循环按**错误文本** `contains("closed")` 决定退出，而单条连接的 TLS/WS 握手失败（对端握手成功后断开）文本含 "closed" → 整个 inbound 监听循环退出 → `TcpListener` 被 drop → **端口不再 listen 而进程存活**（日志零线索）→ Cloudflare 回源 connection refused → 节点 521 / -1。根因是复刻把 TLS/WS 握手内联进 accept 循环（Go 的 keepAccepting 把握手放在每连接 goroutine 内，故同样的文本匹配在 Go 侧安全）。全仓 accept 错误处理收敛为统一分级（新增 `xray-transport::accept_policy`）：资源/瞬时类 warn + 退避 500ms + 继续、单连接级 debug + 继续、未知 warn + 继续，**错误永不作为退出条件**（唯一出口是显式 close），循环意外退出打 error 日志；覆盖 ws / tcp / unix / hysteria / httpupgrade / splithttp 6 处

### Added

- 启动日志输出 kernel identity：version/git_rev 降级链 + blake3 exe 指纹 + profile/target triple（对齐 Go 版本可诊断性需求）（bd qxqw）
- **`base64` 子命令族**（`base64 encode|decode [-gzip]`），与 Go `main/commands/all/base64/` 对拍：前缀常量逐字一致、`-`/`stdin:`/output-file 语义一致、错误文本与退出码一致；gzip 与 Go 双向互通（Go 产 Rust 解 / Rust 产 Go 解）
- transport 级 **unix 监听**入口（`listen_unix` + tcp hub unix accept；此前 transport 注册表只能表达 `SocketAddr`）
- realm **结构化 tlsConfig**（替代 `use_tls: bool`，对齐 Go realm `tls.Config` 实读字段，缺省行为不变）
- `tools/export_v2rayn_nodes.py`：从 v2rayN 库导出 share link 节点表（发布前真实节点矩阵用；**不含凭据**，运行时读本机库，输出只落本地临时目录）

### Changed

- `xray-xudp` env 解析测试迁至独立测试二进制：env 读取是进程级 `LazyLock` 缓存，同进程内被其它测试先触发后 `set_var` 永久无效（CI ubuntu 偶发红灯根因）
- `dist/run_full32.py` 参数化（`--bin/--uri-file/--work/--url`）并**删除 `taskkill /F /IM xray.exe`**：原脚本会连带杀掉用户 v2rayN 的内核，且 Go/Rust 连跑互踩
- xdns finalmask 对齐 Go v26.9.30（fc8f8a45）：结构化 DomainProto（lenLimit/labelLimit/types/edns0）+ TypedMessage resolvers + extraPoll；wire 协议重写（poll/small/frag 三形态 + 分片重组 + 攒包下发）；TCP resolver 配置期报错（Rust 栈 UDP-only）（bd 2ktp ④）
- `DialerController` 签名由 `Fn(&Socket2)` 扩为 `Fn(&Socket2, &SocketAddr)`（对齐 Go `Controllers` 的 address 参数；生产注册方为零，无破坏）

## [26.10.10] - 2026-10-10

### Added

- naive 入站实现（88vp 收口）：rustls+hyper h2 CONNECT 隧道（404 fallback/407 恒定时间认证/padding 协商），extra 套件加回 naive；顺带根因修复 outbound PaddingWriter Pending 重入重复发送真 bug
- 互操作矩阵交叉方向扩满：Go→Rust 与 Rust→Go 各 6→12 协议（+splithttp/grpc/reality/hysteria2/anytls/tuic），CI 默认 37→54 测，既有用例零改动
- REALITY mirror 字节级等价（z32z）：新 BoringSSL 原语 `SSL_seal_raw_tls13_record`（inner-plaintext 级 seal，不追加 inner type）经 vendor 注入脚本 → xray-tls 封装（iOS 门控）→ gate 接线恢复发送体，wire 形态与 Go tls.go:417-426 逐字段同构
- readv 热路径 criterion 基准（并发形态吞吐）+ use_readv 闸门收敛单一事实源

### Changed

- 压测 harness 泄漏判定改尾半段拟合（bd 2f8o）：启动爬坡段污染全段最小二乘 → macOS 6h 跑假阳 SUSPECT（5.00/6.27 %/h）；RSS 斜率只取 `samples[n/2..]` 稳态段，基线/阈值不变；run 36237760680 回放 macOS a/b SUSPECT→OK，linux/windows 结论不翻转
- 全库 rustfmt 新规则重排（CI stable 工具链升级致 Format job 全库违规，一次性对齐，零语义）
- CI 修复：runner 镜像不再预装 protoc——clippy/build(三平台)/test/docs/fuzz 五 job 补装

- fuzz 基建：cargo-fuzz 三靶（kcp segment / ss2022 packet / vless inbound 解码）+ CI fuzz job（workflow_dispatch 触发，nightly + ASAN 30s/靶 smoke，不阻塞主干）
- 压测泄漏门禁：`tools/check_stress_leak.py` 斜率判定（fd/RSS 超阈 fail，drain 回落豁免固有 idle 堆积）+ stress 场景 `--drain-secs` 阶段接入 `stress.yml`
- 项目 README 真实化（架构/协议/构建/CI 全文档）+ `CHANGELOG.md` 建立

### Changed

- 供应链锁定：btls/tokio-btls/btls-sys/rustls-fork/tokio-rustls-fork 五个 git 依赖 branch→rev 锁定（当前已审基线，禁漂移）
- 生产 unwrap 系统性审计：295 处逐处分类落表 docs/audit-unwrap-2026-09-25.md（infallible 203 / 前置守卫 90 / 真风险 2 修复），口径含三类测试代码剔除法
- 热路径拷贝批：freedom UDP 泵逐读双拷贝→池化直写；MultiBuffer `remove(0)` O(n²) 残余→单次 drain（split_first_bytes/split_first/read_to）

### Fixed

- SS2022 响应头单帧原子写（bd 8174，面板双节点无流量实锤）：多锁临界区间拆两次写被响应体/keepalive 帧插隔，读端孤立 header 误判 `invalid salt length` 全断——对齐 Go v26.9.30 `ReadTCPResponse` 单次 Read 契约，header+首块 body 单帧落盘（txhn mux 同族第三例）
- WG 握手探测假死（bd dxim）：e2e 探测客户端单发 init 无重传，CI 满载时序 skew 吞首包即挂死（服务端路径 CI 双绿+独立容器单发 PASS 无罪对照）——客户端补 `update_timers` 100ms 泵（REKEY_TIMEOUT 5s 重传）+ 拆 ignore
- mux carrier 高丢包链路 ~2s 静默死亡（bd txhn）：共享写端帧写入非原子——`MuxWriter` 帧头经 `BufferedWriter` 内部缓冲 flush、载荷直写，两个共享锁临界区间可被并发会话完整帧插隔，读端把孤立载荷当帧头解析出 `meta_len too large` 后整条 carrier 连带全部子会话静默断流（VPS loss 0.5%+RTT150ms 下 9/9 复现、8 流冻结无重建）。修为整帧单次落盘（`write_multi_buffer_direct`，对齐 Go writer.go:71-87 单 `WriteMultiBuffer` 形态）+ carrier 终止 error 级日志 + `MuxBridge` dispatch 对齐 Go 16 次重试环（死亡竞窗不再丢 link）
- mux carrier 死亡级联下半程缺失（bd txhn 残留）：`Session::close` 对 app 下行 output 只 flush 不关——pipe 裸 drop 不关闭语义下 dispatcher 下行 bridge 永久悬挂（carrier 死后 8 流 87s 零字节冻结形态；服务端 End 正常收包路径同悬挂）。补 `BufferedWriter::shutdown` 转发内层 + close 时调用（对齐 Go session.go `common.Close(s.output)`；XUDP 分支维持 Go 同款不关）
- VLESS Vision 高 RTT 链路吞吐塌缩（bd 88m0）：TCP 缺省 SO_RCVBUF 4MB 根治下载收侧内核 DRS 自稳定钉窗（862340ff 同族孪生）——接收窗出生掷签钉 ~64KB 致吞吐=窗/RTT（433KB/s 锁步、~25% 连接命中），VPS netem 20 轮 25% 异常→20/20 全净且整体提速；显式 `receiveBufferSize` 优先（`3e755458`）
- VLESS Vision 下载截断（TRUNC）：桥下行收尾 flush+shutdown 写半——TLS BufWriter 滞留尾巴随 drop 蒸发，VPS A/B 5/20→0/26 实证（`61ba8fc1`）
- mux 帧编码 `Network::Unix` 目标远程可达 panic → 显式 `Err`（对齐 Go 无 panic 路径）
- VLESS 0-RTT `handshake_zero_rtt` 会话 TOCTOU expect panic → miss 语义显式拒绝（`expired ticket`）
- vless 入站 UDP relay 串行挂死（WSLEAK，生产 443 CLOSE-WAIT 泄漏根因）：改 uplink 独立 task + `select!` 双方向并发泵 + 滑动 idle deadline + 客户端 EOF 结束会话（对齐 vmess `pump_udp_session` 与 Go `inbound.go:416` ActivityTimer），UDP 目标不回包不再阻塞读客户端

- 互通矩阵扩展 1.5×2：新增 `rust_to_go` 反向套件（Rust→Go 6 协议）+ 新协议 splithttp/gRPC/REALITY/Hysteria2/AnyTLS/TUIC（默认套件 37 测 = Rust↔Rust 12 + Go→Rust 6 + Rust→Go 6 + 新协议 13）（`1dfdb769`）
- interop 新增 splithttp/kcp/httpupgrade 三脚本（双向 + R↔R 共 12 测），Go→Rust go suite 3→6 协议（`22a08743`）
- 压测 harness `xray-stress`：12 场景协议矩阵（REALITY 短连接风暴/长连接大流量/hysteria2 0-RTT/混合 mKCP+UDP/vmess+ws/trojan+grpc 等）+ RSS/FD/吞吐/延迟分位采样 + ps1/sh/Dockerfile 三档载体 + CI `stress.yml`（`61676c1b`、`b27e2e96`、`b160f6b6`，启动期修复 `1df923ad`、`0bb4176d`、`149f2d7c`、`6aa30564`）
- REALITY 服务端 opt-in btls acceptor：`serverAcceptor` 配置三态（默认 rustls 零回归）+ btls 路径后握手 mirror 记录；iOS target 门控（`aa04602a`、`44027f73`）
- REALITY 后握手记录 FFI 原语 `SSL_send_post_handshake_record`（boringssl 注入 + bindgen，wire 形态对齐 Go reality tls.go）（`5c831c58`）
- REALITY 抗主动探测 maxUselessRecords：CCS 三档探测层（tier 1/16/32/MaxInt）+ vless+reality / splithttp 消费侧接线（`ff145750`、`a20b3f01`）
- Hysteria2 出站 0-RTT（DialEarly parity，port-hop 重连同受益）（`c6296071`）
- XHTTP/3 拥塞控制生产接线：quicParams 缺省 BBR/bbr/reno/force-brutal 全语义对齐 Go dialer.go（`012a3239`）
- sockopt QUIC 系 UDP 端点缓冲：默认 8MB 下限（只升不降 + FORCE 回退，sockopt 显式值优先）（`51d6747e`）
- ECH `echConfigList` 从必败降级接通真实 DoH 查询（RFC 9460 HTTPS RR wire 解析 + echm 提取 + TTL 缓存）（`108740b7`）
- mimalloc 全局分配器 feature 默认开启（`c9e11fc2`）
- mKCP TTI 校验上限 1000→5000（对齐 Go PR #5755）（`2fcd3c75`）
- TUIC 服务端拥塞控制配置面 + CC 桥 hysteria_bbr/brutal（`4cc5c99d`、`f49f4542`）
- REALITY 后量子：X25519MLKEM768 混合密钥交换 + ML-DSA-65 验签原语 + ServerHello 捕获（`27dfd1ee`、`4490c921`）

### Changed

- 性能波 A：mux 帧读池化 + vmess/SS/WebSocket 热路径零拷贝小修 + REALITY mirror 解锁（`28bce568`）
- tokio 1.52.3→1.53.1（规避 LIFO 回归）+ RuntimeMetrics 假唤醒护栏（`c142b344`）
- REALITY mirror 发送体删除（26zn 方案 B）：消除 48B 载荷静默污染地雷，gate 命中仅记日志（`3d5b3e1f`、`b76269bd`）
- trojan v2 草案实现恢复保留（官方 trojan 规范先行、Go 滞后，按草案默认值实现）（`5ddd1cb5`）
- VLESS Vision Go→Rust 套件恢复默认（RecordFramer 修复后 VPS 连续 5 次 PASS）（`8646b76f`）
- CI stress 基础设施：Windows ephemeral 端口 + TIME_WAIT 调优、nofile 上限提升、分批 matrix 防 6h 平台墙、boringssl/protoc Windows 路径修复（`d7e5b8bc`、`97402f05`、`028828a7`、`067d86f3`、`5d1cab9b`、`52e29c84`、`352ecc92`、`b93f0df6`）

### Fixed

- 压测资源泄漏：s9 anytls fd 泄漏、s10 vless+splithttp fd+RSS 双泄漏、s12 vmess+splithttp H3 堆泄漏、s6 trojan+grpc fd 泄漏 + H3 连接级关闭缺口（`633778bb`、`171b0e55`）
- interop 收口 10 缺陷：REALITY 跨栈 sig_algs/keyshare 门、splithttp h2 `:authority` host 门、anytls 入站 handler 保活、TUIC 证书 pin 接线、hysteria2/anytls/naive 出站注册接线（`6aa33adc`、`9c4c75c7`、`dec6fd80`）
- VLESS Vision 入站 RecordFramer 记录对齐读：rustls 贪婪 recv 合流裸尾致 Linux 确定性挂的根修（`8cfc17ac`）
- splithttp 非 btls 出站恒拨 127.0.0.1:80（hyper-util legacy client IP 字面量短路 resolver）（`5fd80270`）
- splithttp 非 btls 出站 `alpn_protocols.clear()` 误删致构建即 panic（`0787bbcb`）
- DNS serveStale/serveExpiredTTL/disableCache 全局→per-NS 合并（原全局开关死配置，对齐 Go dns.go）（`402a761a`）
- gRPC path_escape 分号转义对齐 Go url.go（`d4840580`）
- REALITY probe `detect_one` 加 15s 护栏超时（静默对端握手挂死 CI 43min 的根修）（`0c85ffca`）
- VLESS Vision splice 激活闸门：flush inner + DIRECT 帧后封读 inner，根治 macOS 互通竞态（`7c62fd1a`、`71f1a5e2`）
- 三轮审计全量修复 28 票：语义/并发/安全/拷贝落地（routing fail-open、encryption 明文降级、geoip 德摩根、FakeDNS pending 等）（`94d7fe99`）
- REALITY 收尾批 + P3 清扫批：42 票全量收官（`8bb36239`）

### Security

- quinn 0.11.12→0.11.18：6 个远程 DoS/panic 公告修复（GHSA qfwj/2hv7/hmxj/465w/ppcp/3g6h）+ ACK 捆绑性能；hysteria2 vendor patch 正交重放（`6e5745c6`、`cbc0ce52`）
