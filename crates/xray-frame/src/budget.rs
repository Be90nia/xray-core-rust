//! 装配面内存预算**登记簿**（纯常量簿）——bd azcoe · 256MB 小鸡口径。
//!
//! **归属裁决（ADR-B · 2026-11-06，audit ARCH-07）**：登记簿按 §3.5.5 三判据
//! 上浮本件（`xray-frame::budget`，派生层可含 Xray 语义）；**预算门**
//! `check_startup_budget`（吃 `xray_conf::BuiltConfig`）**留
//! `xray-core::memory_budget`**——硬约束：`xray-conf` 已依赖 `xray-frame`
//! （`crates/xray-conf/Cargo.toml`），门若上浮则 `xray-frame` 反向依赖
//! `xray-conf` 成环。两界以 re-export 相接：`xray-core::memory_budget`
//! re-export 本簿全部公开项（单一事实源在 [`self`]，禁两份定义）。
//!
//! 用户定调（2026-11-04）：整机 256MB（含 kernel/基础系统 ~60MB + 陪跑进程
//! ~40MB），xray 保守按 **96MB** 设计；约束现在写死进代码，不留「以后再调」。
//! 三条铁律（`reports/audit-2026-11-04/MEMORY-BUDGET-256MB.md`）：
//! ① 上界一律显式常量，禁从 sysinfo/系统内存推导（换机器不改代码）；
//! ② 禁预分配大缓冲；
//! ③ 超限 fail-fast 立即拒启/丢弃，禁排队（排队 = 内存与请求数同涨）。
//!
//! 每容器一条常量；能从实现处导入的以交叉断言钉住（断言面在
//! `xray-core::memory_budget` 的 `mod tests`——它同时可见实现 crate 与本簿）——
//! 改任一实现值即红；实现常量私有/未落地/属另一票的只声明口径，并在 doc 明示
//! 「仅登记不保证」。
//!
//! 登记 ≠ 入账：桥在途（条目闸口径满载上界
//! [`BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES`]；u440m 字节闸曾钉 4MiB/连接，
//! 真机 A/B 中位比 0.939（−6.1%，BDP 2.39–3.56MB > 2MiB × RTT 161.6ms）超票面
//! 5% 门已回退）是**满载瞬态上界**（写端堵塞 + 读端持续产的瞬态形态），装配
//! 期不可判定 ⇒ 登记为运维判据，不进预算门算式（见该常量 doc）。
//! 二进制 + Rust 运行时 ~25-30MB 属 RSS 实测面（MEMORY-BUDGET-256MB §1「待实测
//! 锚定」），同样不进门，上线由 PM 亲核 RSS。

/// 档位策略（一次探测 + 一次派生：总预算 → 桥每方向字节闸 → 连接数上限）。
///
/// bd 1rc1o-b：从 `xray-common::mem_probe` 整体上浮本层（档位策略绑 Xray 分账
/// ⇒ 判据 ②；探测机制零语义 ⇒ udf 提炼候选，件内有标注）。
pub mod plan;

/// 整机 256MB 分账后 xray 的保守预算（96MB；留 24MB 给抖动/page cache）。
pub const XRAY_BUDGET_BYTES: usize = 96 * 1024 * 1024;

/// 每连接 **pipe** 软上限的硬顶（字节）——**装配期强校验项**。
///
/// 依据：pipe limit 是「单方向可排队字节」的软上限（policy buffer，Go
/// `BufferPolicy.Connection`），x86_64 缺省 512KB、aarch64 缺省 4KB（bd 9utc3）；
/// 一条连接上/下行各一条 pipe ⇒ 每连接占用按 2× 计（预算门算式）。
/// 96MB 预算下安全并发 300–600 连接（audit4-memory §8，每连接常驻 40–200KB）；
/// 4MiB = x86 缺省 8×，留 1–2MiB 级合法调优空间，拦截 `XRAY_BUFSIZE=16+`
/// （16MB/方向 × 数十连接即吃满预算）这类配置级超支。
pub const MAX_PER_CONN_BUFFER_BYTES: i64 = 4 * 1024 * 1024;

/// 每连接 **socket** 缓冲上限（显式值，字节）——与 [`MAX_PER_CONN_BUFFER_BYTES`]
/// **同口径**：二者共用同一个 4 MiB 每连接份额，pipe 与 socket 不重复计账。
///
/// 依据（bd u91se ④ PM 终裁 2026-11-05）：显式 `receiveBufferSize` /
/// `sendBufferSize`（TCP 三 transport 收 + QUIC/UDP 端点收/发各向）分三档——
/// `≤ 4 MiB` 免确认直接生效；`4 MiB < v ≤ 64 MiB` 需 `XRAY_ALLOW_LARGE_RCVBUF=1`
/// 确认；`> 64 MiB` 恒拒。判定用**用户设定值**（Linux 回读受 `rmem_max` 钳制偏小，
/// 回读小 ≠ 没超限），超限 fail-visible 拒拨/拒绑，**禁静默钳制**。
///
/// 记账：每条连接 ≤ 4 MiB，条数 × 4 MiB 计入整机 96 MB（[`XRAY_BUDGET_BYTES`]）。
/// 执行点（Trans2 已落地）：`xray_transport::sockopt::MAX_EXPLICIT_RECEIVE_BUFFER_SIZE`
/// / `MAX_EXPLICIT_UDP_BUFFER_SIZE`（后者 = 64 MiB 硬顶，4 MiB 免确认档同
/// `xray_transport::sockopt::SO_RCVBUF_FREE_TIER_MAX`）。
pub const MAX_EXPLICIT_SOCKET_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// QUIC/UDP socket **缺省**接收缓冲（字节/socket）= 8 MiB，**行为不动**（登记项）。
///
/// Go quic-go `wrapConn` 的 `DesiredReceiveBufferSize` parity
/// （`internal/protocol/params.go:5-9`，`sys_conn.go:51-53`）：缺省
/// `receiveBufferSize=0` ⇒ `xray_transport::sockopt::bind_udp_endpoint` 的
/// `tune_udp_buffer` 只升不降到本值（Linux 再走 `SO_RCVBUFFORCE`，失败只 warn）。
/// 对拍一致优先于本地优化，故本项只登记 + 披露，不改缺省。
///
/// **记账口径（bd sgdwm 修正）**：按 **socket（= quinn Endpoint）** 计——
/// `Endpoint::new(..., sock, ...)` 每 listener/dialer 一个 socket、多连接复用
/// （xray-transport-quic `udp_gso.rs` make_endpoint / xdns doh3 dial 同款），
/// 旧文案「每连接 16 MiB」高估（1 listener 服务 N 连接只占 1 份 socket 账）。
/// 预算门按配置里 QUIC 端点数 × [`QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES`] 入算。
///
/// **Windows 无 `net.core.rmem_max` 钳制** ⇒ 每 socket 真 8 MiB，内核记账 ×2
/// ⇒ 按 [`QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES`]（16 MiB/socket）口径。
/// Linux 受 `net.core.rmem_max` 钳制（stock ≈416 KiB 实际账面）⇒ 8 MiB 只在运维
/// 抬过 `rmem_max` 后成立。TCP 路径缺省为 0（不设，交 OS autotune，bd r5j96）。
pub const QUIC_UDP_DEFAULT_RECV_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// socket 缓冲的**内核记账倍数**：`SO_RCVBUF` 设定值 ×2 才等于内核账面字节
/// （设定值的一半是纯开销，同 `docs/guide-highrtt-sockopt.md` §96-98）。
pub const SOCKET_KERNEL_BOOKKEEPING_FACTOR: usize = 2;

/// QUIC/UDP 缺省接收缓冲的**账面**口径（字节/socket）= 8 MiB × 2 = 16 MiB。
///
/// **记账归属（bd 258qt(c)/nlhht，两栏口径）**：
/// - **显式** `socketSettings.receiveBufferSize`（运维亲手指定）⇒ 按显式值 ×2 计入
///   预算门**硬账**（bind 即真实分配；8 端点 × 64 MiB × 2 = 1 GiB 必须能被拦下）。
/// - **缺省**（本常量）⇒ 只进门的**上限面**（caps 栏 + 启动日志），不进硬账： Linux
///   `net.core.rmem_max` 缺省（stock ≈208 KiB）会把设定值钳死，按 16 MiB/端点
///   预约会**误杀合法配置**（5 端点 = 107.6 MiB > 96 MiB 拒启，本轮实测形态）。
pub const QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES: usize =
    QUIC_UDP_DEFAULT_RECV_BUFFER_BYTES * SOCKET_KERNEL_BOOKKEEPING_FACTOR;

/// QUIC **连接级接收窗**账面（字节/已建立连接）= 32 MiB（quinn
/// `TransportConfig::receive_window`，**应用层真缓冲**）。
///
/// **与 [`QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES`] 不同账**：那是内核
/// `SO_RCVBUF`（每 socket，1 端点 1 份）；本项是流控信用换来的、对端在窗内可
/// **无背压灌满**的缓冲，**每已建立连接一份**。
///
/// **为什么必须入硬账（bd 2026-11-08 D-03）**：已握手的 QUIC 连接**没有连接级
/// 准入闸**（唯一的闸是握手在飞 [`HANDSHAKE_INFLIGHT_MAX`]），旧簿只登记了
/// socket 面 ⇒ N 条连接可占 `N × 32 MiB` 而预算门看不见。现计入预算门硬账，
/// 乘数 = **本预算余量实际装得下几条满窗连接**（`min(并发上限, 余额/32MiB)`；
/// 用档位最大并发当乘数会恒得 10× 超账 ⇒ 告警退化成噪音，PM 2026-11-08 纠偏），
/// 真装不下时 emit WARN 点明「第 N+1 条起不受预算约束」（用户裁决：预算不足
/// **不得拒启**）。
///
/// 值 = 实现缺省
/// `xray_transport_quic::config::DEFAULT_CONNECTION_RECEIVE_WINDOW`
/// （交叉断言钉住，改实现即红）。流窗（[`QUIC_STREAM_RECEIVE_WINDOW_BYTES`]）
/// 的花费由连接窗信用发放 ⇒ 是**连接窗内**的子份额，不叠加记账。
pub const QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES: usize = 32 * 1024 * 1024;

/// QUIC 缺省**流级**接收窗（字节/流）= 16 MiB——与实现缺省交叉断言钉住
/// （防回档：bd wz2b W4 把它从 quinn 缺省 1.25 MiB 抬到 16 MiB，缩回去会钉
/// 高 BDP 吞吐）。**不单独入账**：流的字节花在连接窗信用内
/// （[`QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES`] 已含）。
pub const QUIC_STREAM_RECEIVE_WINDOW_BYTES: usize = 16 * 1024 * 1024;

/// 握手在途任务并发上限（P0-1 accept 解耦后 per-conn 握手任务数）。
///
/// **64**——与实现 `xray_transport::handshake_gate::MAX_INFLIGHT_HANDSHAKES` 同一
/// 值（交叉断言钉住；bd sgdwm 修正旧登记 128 的漂移，PM-04）。
/// **每监听一份**（`HandshakeGate` 由各 accept 循环各自构造），故预算门按
/// 「监听数 × 64 × [`HANDSHAKE_TASK_EST_BYTES`]」入账（bd 258qt(a)：旧簿按进程
/// 记 1 份，7 监听真额 24MiB 只记了 384KiB）。超限 fail-fast 丢弃不排队。
pub const HANDSHAKE_INFLIGHT_MAX: usize = 64;

/// 单条握手在途任务估占（字节）= **55KiB**。
///
/// 依据（实现侧实测，`xray-transport::handshake_gate` 的
/// `MAX_INFLIGHT_HANDSHAKES` doc）：线性斜率 **54,975B/连接**——裸 socket 双方
/// 仅 ~0.9KiB，其余为 ws 握手态 / 任务 future（tungstenite 内部按需分配，本层
/// 不预分配）。取整上沿 55KiB（= 56,320B）作账面。
///
/// bd 258qt(a)：旧簿写 6KiB（MEMORY-BUDGET-256MB §1「128 × ~6KB」口径），比
/// 实现自陈的 55KiB 低 9×；改实现值或复测斜率时本值须同步（交叉断言钉在
/// `xray-core::memory_budget` 的 `handshake_task_est_matches_impl_doc`）。
pub const HANDSHAKE_TASK_EST_BYTES: usize = 55 * 1024;

/// DNS pending map **条数**上界（512 条）——与实现
/// `xray_app_dns::nameserver::udp::MAX_PENDING_QUERIES` 同一值（交叉断言钉住）。
///
/// bd sgdwm 修正旧登记 `DNS_PENDING_MAX_BYTES = 512KiB` 的口径错位：实现是
/// **条数**闸（满则拒发，禁排队），512 条 ≈ 41KiB 实际占用；字节预算按
/// [`DNS_PENDING_EST_BYTES`]（512KiB 保守档）单独登记。
pub const DNS_PENDING_MAX_ENTRIES: usize = 512;

/// DNS pending map 字节预算的**保守档**（实际 ≈41KiB；取整档留裕量给 token/
/// 唤醒器开销）。预算门固定占用用本值。
pub const DNS_PENDING_EST_BYTES: usize = 512 * 1024;

/// DNS 解析缓存条目上界（**已落地**：xray-app-dns `MAX_CACHE_ENTRIES`，交叉断言钉住）。
/// 16384 键 ≈ 4–5MiB：远高于常规解析工作集，且拦住「TTL 窗内唯一域名数 =
/// 内存」的无界增长（Go 同源无界；Rust 侧按预算收口——有界优于逐字节对拍）。
pub const DNS_CACHE_MAX_ENTRIES: usize = 16_384;

/// DNS 缓存字节估算档（16384 键 × ~320B ≈ 5MiB，取上沿）。预算门固定占用用本值
/// （实现闸是条数不是字节，字节账只能估——登记为估算，非保证）。
pub const DNS_CACHE_ESTIMATE_BYTES: usize = 5 * 1024 * 1024;

/// TLS session cache 条目上界（**已落地**：xray-tls
/// `TLS_SESSION_CACHE_CAPACITY`，128 条 LRU + 24h TTL 双界——交叉断言钉住；
/// bd sgdwm 起实现常量转 pub，旧「私有 const 无法断言」作废）。
pub const TLS_SESSION_CACHE_MAX_ENTRIES: usize = 128;

/// TLS session cache 字节估算档（128 条 × ~20KiB ≈ 2.5MiB，单条 2~20KiB 取上沿）。
/// 预算门固定占用用本值（登记为估算，非保证）。
pub const TLS_SESSION_CACHE_ESTIMATE_BYTES: usize = 128 * 20 * 1024;

/// finalmask xmc manager 池字节上界（≤4MB）。执行点：finalmask 池接线票
/// （**未落地 ⇒ 仅登记不保证**；落地时必须回填交叉断言）。
pub const FINALMASK_XMC_POOL_MAX_BYTES: usize = 4 * 1024 * 1024;

/// finalmask xdns 分片重组器（`FragManager`，**每 xdns server 实例一份**，
/// `ServerState.frag`）**最坏堆占用**（字节，bd wpa3o-b）= 43,155,456 ≈ 41.2MiB。
///
/// 账面算式（实现侧 `xray_transport::finalmask::xdns::frag::WORST_CASE_BYTES`
/// 以同一式从实现常量计算，交叉断言钉住——**改 frag 任一上限即红**）：
/// - payload：`FRAG_COUNT(4096) × FRAG_SIZE(4096)` = 16,777,216
/// - 片槽数组：`FRAG_COUNT × 255(u8 片数上限) × 24B(Option<Vec<u8>>)` = 25,063,680 ——slot 结构项与
///   Go 同界（Go slice header 同 24B/槽），名义 25MB 口径即此；
/// - entry 结构 + m 表桶 + by_deadline/sizem 索引面：entry 结构按**平台无关上沿 64B**（Windows
///   `Instant` 16B 携带 QPC 频率 ⇒ 64B；Linux/macOS 56B）， 索引面 ≈0.83MiB ⇒ 取整上沿 1MiB。
///
/// **只登记不改 frag 上限**（票面纪律）：41MiB 是服务端 xdns 分片重组**满表瞬态**
/// （TTL 8s 滑窗、填充度随负载），装配期不可判定 ⇒ **不进预算门固定占用算式**
/// （同桥在途口径，运维判据）；多 server 实例按份叠加。
///
/// **总实算**（bd wpa3o-b 验收：入簿后固定底数 + 本项 ≤ 总额）：
/// `startup_fixed_floor_bytes_for_with_inflight(8, 1, HANDSHAKE_INFLIGHT_MAX)` 23,719,424 +
/// 43,155,456 = 66,874,880 ≈ 63.8MiB ≤ [`XRAY_BUDGET_BYTES`]（96MiB）✓（断言住
/// `xray-core::memory_budget`）。 固定底数含**每监听握手在途**（bd 258qt(a)：监听越多本式越大，见
/// [`startup_fixed_floor_bytes_for`]）。
pub const XDNS_FRAG_WORST_CASE_BYTES: usize = 43_155_456;

/// hyper 每 host **空闲连接数**上界（**已落地**：
/// `xray_transport_splithttp::client::MAX_IDLE_PER_HOST`，交叉断言钉住）。
///
/// bd sgdwm 修正旧登记 `HYPER_MAX_IDLE_PER_HOST_BYTES = 2MiB` 的口径错位（PM-04）：
/// 实现闸是连接数（hyper-util `pool_max_idle_per_host`），不是字节。字节账面 =
/// [`HYPER_MAX_IDLE_PER_HOST_CONNECTIONS`] × [`HYPER_IDLE_CONN_EST_BYTES`] ≈
/// 400KiB/host（client.rs doc：单条空闲连接 RSS < 100KiB）。执行点：bd cgmcj。
pub const HYPER_MAX_IDLE_PER_HOST_CONNECTIONS: usize = 4;

/// 单条 hyper 空闲连接估占（字节）：TLS 状态 + h2 帧缓冲 < 100KiB
/// （client.rs doc 口径）。预算门 xhttp 端点占用用本值 × 空闲连接数。
pub const HYPER_IDLE_CONN_EST_BYTES: usize = 100 * 1024;

/// 小池档合计硬顶（4MB，**条款已重写**——bd sgdwm 修正 PM-04「宪法破」，
/// bd 258qt(a) 再收口成员面）。
///
/// 旧条款自称「全部池/缓存合计 ≤4MB」，被 xray-buf 8MiB 单项破掉。第二条旧条款
/// 把**握手在途**算进本档——那是**每监听**在途任务（64 × 55KiB = 3.4MiB/监听，
/// 随监听数线性），不是进程级池/缓存，塞进固定 4MiB 档必然自相矛盾。
/// 现成员 = **进程级小池/缓存三件**（DNS pending + TLS session cache + hyper
/// idle，合计 ~3.4MiB ≤ 4MiB，交叉断言钉住）；握手在途随固定底数分账
/// （[`startup_fixed_floor_bytes_for`]），大池（xray-buf
/// [`XRAY_BUF_POOL_TOTAL_MAX_BYTES`] 8MiB、splithttp 块池
/// [`SPLITHTTP_SHARED_BLOCK_POOL_MAX_BYTES`] 2MiB）、DNS 解析缓存、finalmask
/// xmc 池**单列分账，不入本条款**。
pub const NEW_POOLS_TOTAL_MAX_BYTES: usize = 4 * 1024 * 1024;

/// xray-buf 分层池**进程级**字节预算（**已落地**：`xray_buf::alloc::POOL_BYTE_BUDGET`
/// = 8MiB，交叉断言钉住；xray-buf 常量本体属另一票，本簿只登记不改值）。
///
/// 全局面 = 本值 + **核数 × 128KiB thread_local**（`xray_buf::alloc::TLS_BYTE_BUDGET`，
/// PM-07 公式口径；预算门按 `available_parallelism()` 折算）。
pub const XRAY_BUF_POOL_TOTAL_MAX_BYTES: usize = 8 * 1024 * 1024;

/// splithttp 进程级共享块池字节预算（**已落地**：
/// `xray_transport_splithttp::pool_stream::POOL_BYTE_BUDGET` = 2MiB，交叉断言钉住；
/// bd kw2si 起全进程唯一一份，同 chunk 不随连接数翻倍）。
///
/// 口径 = **常驻**（空闲块）预算；块借出后随 `Bytes` 进 h2 发送队列的那份内存记在
/// caps 的「per-conn h2 send_buf cap」面（`xhttp_conn_booked_bytes`），本项不重复计账
/// ——池的宇宙（`max`）只是记账上界，不预分配（bd vktyw）。
pub const SPLITHTTP_SHARED_BLOCK_POOL_MAX_BYTES: usize = 2 * 1024 * 1024;

/// hysteria udphop 进程级共享块池字节预算（**已落地**（bd ccy5d）：
/// `xray_transport_hysteria::udphop::POOL_IDLE_CAP`（128 块）× 实现侧
/// `UDP_BUFFER_SIZE`（1500B）= **192_000B**，交叉断言钉住
/// （断言面 `xray-core::memory_budget` tests——它同时可见实现 crate）。
///
/// 旧口径**每连接一份**池（N 连接 = N × 192KB 乘积面，audit4-memory 未入簿）；
/// bd ccy5d 起同尺寸块（1500B）全进程唯一一份池（`xray_frame` 的
/// `SharedPoolRegistry`，尺寸 class 分桶），上界收敛为**进程级常量**。
/// 账面只含 idle 常驻（≤128 块）+ 池内在飞；块随 `UdpPacket` detach 进
/// mpsc 队列/桥后脱离池记账，归 [`MAX_PER_CONN_BUFFER_BYTES`] 每连接份额口径
/// （不与本项重复计账）。连接全关后老化任务随连接 scope 停，残余 idle 块
/// ≤ 本上界驻留至下次连接复用——仍是进程级常量。
pub const HYSTERIA_UDPHOP_SHARED_POOL_MAX_BYTES: usize = 128 * 1500;

/// h2 每连接发送缓冲（**真缓冲**，连接级；**已落地**：splithttp 客户端
/// `H2_MAX_SEND_BUF_SIZE` = 16MiB；服务端 `H2_SERVER_MAX_SEND_BUF_SIZE` = 32MiB 为
/// **上限**，实际按内存档位取 8MiB（tiny）/ 16MiB（small）/ 32MiB（medium/large）——
/// 映射唯一源 `xray_transport::h2_window::h2_server_max_send_buf_for`，交叉断言钉住）。
///
/// 与 SETTINGS 流窗/连窗（信用计数器，零预分配）不同——本值是 hyper 真会堆积的
/// 发送缓冲 ⇒ 每条满载 splithttp 连接最多 16MiB（客户端）/ 8-32MiB（服务端）。
/// bd sgdwm 入簿（PM-05）。
///
/// **记账归属（bd pyka7 / NEW-S2，两栏口径）**：hyper 只在背压时惰性分配，
/// 装配期零连接 ⇒ 不进硬账；按「上限 ≠ 预约」进门的**上限面**（caps 栏 +
/// 启动日志）。**96 MiB 不是运行期硬上界**：xhttp 侧的聚合上界 =
/// `并发连接数 × 本值`，而连接数由配置/负载决定（`MAX_IDLE_PER_HOST` 只限
/// **空闲**连接）。运行期聚合闸需在 hyper 发送缓冲外侧记账，属 transport 侧
/// 后续票（本簿只登记 + 打印，禁假称已强制）。
pub const H2_MAX_SEND_BUF_PER_CONN_BYTES: usize = 16 * 1024 * 1024;

/// splithttp **客户端** h2 SETTINGS 流窗 = 连窗（字节）。**非内存账面**：SETTINGS
/// 窗是零预分配信用计数器，缩它只钉吞吐不省缓冲（flow_window.rs 自陈）——入簿
/// 为防吞吐钉回档（bd wz2b/c9oc），**不计入**预算门算式。
pub const SPLITHTTP_H2_CLIENT_FLOW_WINDOW_BYTES: u32 = 32 * 1024 * 1024;

/// splithttp **服务端** h2 SETTINGS 流窗（字节；服务端不得复用客户端 32MiB，
/// bd rjzw2）。同上，非内存账面，只防回档。
pub const SPLITHTTP_H2_SERVER_STREAM_WINDOW_BYTES: u32 = 16 * 1024 * 1024;

/// xdrive **每会话** WAL 段缓冲账面（字节）= (1 + 3×并发缺省 8) × 段缺省 512KiB
/// = **12.5MiB**（bd yc54c G5）。派生式（实现侧 `xray-transport-xdrive`
/// `params.rs`/`wal.rs` 的缺省常量为私有 ⇒ 按实现代码口径登记，「仅登记不保证」，
/// 改实现侧缺省须同步本式；交叉断言住账本公式锚 `memory_budget` tests）：
/// - 写侧（每方向一个 writer）：累计 buf ≤ 1 段 + 在飞上传 ≤ `concurrency` × 1 段；
/// - 读侧（对端方向一个 reader）：段投递 mpsc（容量 = `concurrency`）× 1 段
///   + 批量取段暂存 ≤ `concurrency` × 1 段。
///
/// `segmentBytes`（上限 16MiB）/ `concurrency`（上限 256）可被配置放大 ⇒ 理论上界
/// 远高于本档；与 xhttp 端点账面（`xray-core::memory_budget` 的
/// `xhttp_conn_booked_bytes`）同口径：按**缺省档**登记，
/// 上限面（caps 栏）按端点数可见，不进硬账（装配期零会话 ⇒ 真实占用 0）。
pub const XDRIVE_SESSION_WAL_BUFFER_BOOKED_BYTES: usize = (1 + 3 * 8) * 512 * 1024;

/// xdrive **h2/h1** 每连接发送缓冲（字节）= hyper 缺省 400KiB（xdrive 的 hyper
/// builder 未覆写 send buf——对照 splithttp 显式 16MiB，enc8x 战役口径）。
/// 上限面（惰性分配，同 [`H2_MAX_SEND_BUF_PER_CONN_BYTES`] 口径），不进硬账。
pub const XDRIVE_H2_SEND_BUF_PER_CONN_BYTES: usize = 400 * 1024;

/// ws（tungstenite）每连接帧编解码缓冲账面 = 读 32KiB + 写 32KiB（**已落地**：
/// `xray_transport_websocket::config::ws_config()`，交叉断言钉住）。
/// bd i37bz 收窄自 256KiB/连接。
pub const WS_PER_CONN_BUFFER_BOOKED_BYTES: usize = 64 * 1024;

/// DoH3 会话 socket 账面 = 8MiB 设定 × 2 内核记账 = 16MiB/**resolver 端点**。
///
/// 依据：`xdns/doh3.rs` dial 走 `bind_udp_endpoint` + `SocketOptions::default()`
/// ⇒ 与 QUIC 端点同款 8MiB 下限（Go quic-go wrapConn parity）；bd 0x4tl/lf69h 起
/// 会话按端点复用（1 端点 1 socket，无每查询 churn——PM-02 的 churn 面已收口，
/// 本簿按复用后口径登记）。账面常量与 QUIC 同源（交叉断言钉住）。
///
/// **预算门消费方（bd 258qt(d)）**：DoH3 resolver 由 dns app 运行期按 server 创建，
/// 装配期 `BuiltConfig` 里数不出端点数 ⇒ 与本值同口径地进门的**上限面**（caps 栏
/// 打印「每 DoH3 resolver 一份」），不进硬账。旧状：常量在簿里但门内零消费方
/// （README 式登记），现在至少是可见的运维判据。
pub const DOH3_SESSION_SOCKET_BOOKED_BYTES: usize = QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES;

/// 桥在途满载上界（字节/连接，**条目闸口径**）= 每方向 mpsc 64 条 + 读/写腿
/// 手上各 1 = 66 条 × 单条顶格 512KiB × 双方向 = 66 MiB（缺省档）。
///
/// 单条字节由**生产侧**决定（`xray-transport/src/bridge.rs` `PIPE_BUF_CAP` 处
/// 注释）：readv 腿顶格 8×64KiB = 512KiB；TLS 腿 ≤64KiB；pipe 腿 ≈ policy
/// bufferSize（缺省 512KiB，受 [`MAX_PER_CONN_BUFFER_BYTES`] 4MiB/方向钳制，
/// 配大时本上界按 66 × 档位 × 双方向线性放大）；冻结腿（h2/h3 Bytes 直交）
/// 单条 = 传输分片可超——闸只管条数不复检字节。
///
/// **字节闸回退记录（bd u440m）**：u440m 曾加每方向 2MiB 字节闸把本值钉在
/// 4MiB/连接（`BRIDGE_BYTE_GATE_PER_DIRECTION_BOOKED_BYTES` 常量随之删除——
/// 闸没了，登记它 = 造假）。回退依据 = 票面自定 5% 门实测触发：到节点 RTT
/// 161.6ms ⇒ BDP @14.8MB/s = 2.39MB、@22.0MB/s = 3.56MB，均 > 2MiB 闸预算
/// ⇒ 闸理论上限 2MiB ÷ 0.162s ≈ 12.9MB/s，真机 A/B 中位比 0.939（−6.1%）
/// ⇒ 撤销限流行为，回到纯条目闸（旁路计数器依赖闸存在才有意义，一并删除）。
///
/// 满载瞬态（写端堵塞 + 读端持续产的瞬态形态，装配期零连接 ⇒ 占用 0，连接数
/// 装配期不可判定）⇒ **登记为运维判据，不进预算门算式**（同 xdns frag 口径）；
/// 条目闸行为由 `crates/xray-transport/tests/bridge_backpressure_entry_cap.rs`
/// 行为级钉住（64 条 mpsc 封顶后拉取数 65..66，改条目容量即红）。
pub const BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES: usize = 66 * 512 * 1024 * 2;

/// DNS singleflight 表（`xray_app_dns::cache_controller::SfMap`）**无显式条目上界**
/// ——已知无上界容器，如实登记（PM-08）：上界 = 同时在飞的不同 key 数（由客户端
/// 查询基数决定），条目由 `SfLeaderGuard::drop` 保证移除（无泄漏，瞬态非常驻）。
/// 软上界收口（如 4096 满则 fail-fast 退化独立查询）属 PM-08 后续票；本簿无法钉
/// 一个不存在的上界，**仅登记不保证**。
///
/// 预算门对它不可判定（运行时容器），不计入固定占用；DNS 面的实际占用闸是
/// [`DNS_PENDING_MAX_ENTRIES`]（512 条拒发）与 [`DNS_CACHE_MAX_ENTRIES`]。
pub const DNS_SINGLEFLIGHT_UNBOUNDED_NOTE: &str =
    "singleflight: unbounded (transient, leader-drop cleaned); PM-08 owns the cap";

/// 预算内最小可跑并发（bd sgdwm 装配期判据）：固定占用 + 端点账面 + 本值 ×
/// 每连接 pipe（双方向）必须 ≤ [`XRAY_BUDGET_BYTES`]，否则配置在 96MB 内连 8 条
/// 满额 pipe 连接都承载不了 ⇒ 拒启。旧判据「96MB 安全并发 300–600 连接」
/// （audit4-memory §8）按 transport 分形后的**下限护栏**（新数字见 impl-sgdwm 报告）。
pub const MIN_VIABLE_CONCURRENCY: usize = 8;

/// 总盘预留余量下限（整机 256MB 口径运维判据：256 − 系统 ~60 − 陪跑 ~40 −
/// xray ~96 ≈ 60MB，票面判据取 ≥50MB）。上线由 PM 亲核实测 RSS，非代码强校验。
pub const RESERVE_MARGIN_MIN_BYTES: usize = 50 * 1024 * 1024;

/// 装配期**固定占用**下限（字节）：进程级池/缓存合计 + 每监听握手在途。
///
/// `listeners` = 配置里真正 listen 的入站数（`BuiltInbound::port.is_some()`）——
/// 握手闸每个 accept 循环各一份（bd 258qt(a)），故该项随监听数线性增长。
/// 不含连接面、爆队上界与二进制/运行时 RSS 面（PM-07 公式口径的其余成员见各常量 doc）。
#[must_use]
pub fn startup_fixed_floor_bytes(listeners: usize) -> usize {
    let cores = std::thread::available_parallelism().map_or(1, usize::from);
    startup_fixed_floor_bytes_for(cores, listeners)
}

/// 同上，核数与监听数显式注入（测试确定性用——换机器断言不随核数漂移，铁律①）。
#[must_use]
pub fn startup_fixed_floor_bytes_for(cores: usize, listeners: usize) -> usize {
    startup_fixed_floor_bytes_for_with_inflight(cores, listeners, effective_handshake_inflight())
}

/// 每监听「在飞握手」有效上限（进程级，唯一事实源）。
///
/// 为什么不是纯常量：`HANDSHAKE_INFLIGHT_MAX × 监听数 × [`HANDSHAKE_TASK_EST_BYTES`]`
/// 是按**满载上界**入账，26 监听 = 93MiB —— 256/512MB 机器上任意多监听配置都会被判
/// 「连 1 条连接都装不下」而拒启（2026-11-08 176 生产真机实证：528MB / 26 监听 /
/// tiny 档 40MiB ⇒ 拒启）。
///
/// 正确口径：**在飞握手数由预算反推**，握手闸按同一值 fail-fast（超限即丢弃，不排队）。
/// 装配期由 `xray-core::memory_budget::check_startup_budget` 调
/// [`set_effective_handshake_inflight`] 写入；未写入时 = 常量上界（原行为）。
static EFFECTIVE_HANDSHAKE_INFLIGHT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(HANDSHAKE_INFLIGHT_MAX);

/// 读当前生效的每监听在飞握手上限（∈ `[1, HANDSHAKE_INFLIGHT_MAX]`）。
#[must_use]
pub fn effective_handshake_inflight() -> usize {
    EFFECTIVE_HANDSHAKE_INFLIGHT
        .load(std::sync::atomic::Ordering::Relaxed)
        .clamp(1, HANDSHAKE_INFLIGHT_MAX)
}

/// 写入每监听在飞握手上限（装配期一次性；夹到 `[1, HANDSHAKE_INFLIGHT_MAX]`）。
pub fn set_effective_handshake_inflight(limit: usize) {
    EFFECTIVE_HANDSHAKE_INFLIGHT
        .store(limit.clamp(1, HANDSHAKE_INFLIGHT_MAX), std::sync::atomic::Ordering::Relaxed);
}

/// 不含握手项 / 指定每监听握手数的固定占用底数。
///
/// `handshake_inflight_per_listener = 0` ⇒ 只算静态面（预算门拿它反解可用握手额度）。
#[must_use]
pub fn startup_fixed_floor_bytes_for_with_inflight(
    cores: usize,
    listeners: usize,
    handshake_inflight_per_listener: usize,
) -> usize {
    XRAY_BUF_POOL_TOTAL_MAX_BYTES
        + cores * xray_buf::alloc::TLS_BYTE_BUDGET
        + SPLITHTTP_SHARED_BLOCK_POOL_MAX_BYTES
        + HYSTERIA_UDPHOP_SHARED_POOL_MAX_BYTES
        + DNS_CACHE_ESTIMATE_BYTES
        + DNS_PENDING_EST_BYTES
        + TLS_SESSION_CACHE_ESTIMATE_BYTES
        + listeners * handshake_inflight_per_listener * HANDSHAKE_TASK_EST_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 固定占用底数（8 核参考机）随簿搬家后数值不变（断言本体住
    /// `xray-core::memory_budget`——它同时可见实现 crate；此处只钉搬家无漂移）。
    /// bd ccy5d 起含 hysteria 共享块池 192_000B：20_316_160 + 192_000 = 20_508_160。
    #[test]
    fn floor_moves_without_drift() {
        // 8 核参考机 + 1 监听：20_114_944（池/缓存）+ 64 × 55KiB（握手在途）= 23_719_424。
        assert_eq!(
            startup_fixed_floor_bytes_for_with_inflight(8, 1, HANDSHAKE_INFLIGHT_MAX),
            23_719_424
        );
        // 每监听一份（bd 258qt(a)）：多一个监听多 64 × 55KiB。
        assert_eq!(
            startup_fixed_floor_bytes_for_with_inflight(8, 2, HANDSHAKE_INFLIGHT_MAX)
                - startup_fixed_floor_bytes_for_with_inflight(8, 1, HANDSHAKE_INFLIGHT_MAX),
            HANDSHAKE_INFLIGHT_MAX * HANDSHAKE_TASK_EST_BYTES
        );
        assert_eq!(XRAY_BUDGET_BYTES, 96 * 1024 * 1024);
        assert_eq!(DNS_CACHE_MAX_ENTRIES, 16_384);
    }
}
