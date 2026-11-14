//! 装配期预算门（bd azcoe · 256MB 小鸡口径）——`check_startup_budget` 本体。
//!
//! **归属裁决（ADR-B · 2026-11-06，audit ARCH-07 拆分）**：本模块只剩两件事——
//! ① **预算门** [`check_startup_budget`]（吃 [`xray_conf::BuiltConfig`]；反向依赖
//! 硬约束 ⇒ 门不可能上浮：`xray-conf` 已依赖 `xray-frame`，门上浮成环）；
//! ② **登记簿 re-export**：纯常量簿上浮 `xray_frame::budget`（派生层，含逐条
//! 口径 doc），本模块 `pub use` 转出——**禁两份常量定义**（§3.5.2）；登记簿
//! 交叉断言（改实现值即红）住本模块 `mod tests`（它同时可见实现 crate 与簿）。
//!
//! 门在 `start_full_dispatched` 入口执行（生产 `start_full` 与 framework
//! `start_full_with_outbound_handlers` 两路共用），违例逐条列出并拒启
//! （对齐 vaye2/o91s4 的启动期硬错纪律）。**两栏口径（bd 258qt/pyka7/nlhht）**：
//! 硬账（[`BudgetReport::hard`]，进判定）+ 上限面（[`BudgetReport::caps`]，只打印
//! ——**96 MiB 不是运行期硬上界**）。校验面（bd sgdwm 扩面 + 本轮口径修正）：
//! 1. 配置派生值：env 缺省档 + policy 各 level `bufferSize`（KB；负值 = 无界 ⇒ 硬拒，Go 同源坑
//!    audit4-memory F8；本仓装配期硬拒负值 ⇒ 96MB 门下不存在「Go 同源
//!    无界」活口，**无界一律硬拒零豁免**；0 = Go 合法「limit 0 不排队」，必须放行）；
//! 2. 硬账面：进程级池/缓存固定占用（[`startup_fixed_floor_bytes`]，**含每监听握手 在途**）+
//!    **显式** `sockopt.receiveBufferSize` 的 UDP 端点账面（×2 内核记账）
//!    + 预算内最小并发 × 每连接 pipe（双向）—— 配置合法但合计超 [`XRAY_BUDGET_BYTES`] 同样拒启；
//!      **另三项瞬时上界也进硬账**（bd 2026-11-08 D-03 / security P2-2；TUIC 面 bd k5pqt）： xdns
//!      frag 满表（[`XDNS_FRAG_WORST_CASE_BYTES`] × server 数）、QUIC 连接接收窗
//!      （[`QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES`] × **预算余量装得下的满窗条数**）与 TUIC dgram
//!      信箱（ `xray_proxy_tuic::udp::DGRAM_INBOX_BYTE_CAP` × tuic 出站数）。三项都**装不下 只 WARN
//!      不拒启**（用户裁决 2026-11-07「预算不足不得拒启」），但账面必须可见、 可对账——旧状 frag
//!      只在 caps 栏（等于不判），QUIC 窗全仓零登记。
//! 3. 上限面（不判、只打印）：QUIC 缺省 socket（Linux `rmem_max` 钳制 ⇒ 按 16MiB
//!    预约会误杀合法配置）、xhttp h2 send_buf（每连接、惰性分配）、DoH3 resolver
//!    socket（装配期不可数）、桥在途。
//! 4. **UDP dispatch 会话面（bd rmbby）**：每会话**常驻** `UDP_SESSION_RESIDENT_BYTES` （8KiB
//!    池化读缓冲，建会话即占）进硬账——条数按**余量口径**反解 （余额 ÷ 常驻字节，上界 =
//!    `MAX_UDP_SESSIONS`）并写进执行点 （`plan::set_effective_max_udp_sessions`，dispatcher
//!    `establish` 读同一份值， 超限 fail-visible 拒建）；**瞬态** `2 × 256KiB` duplex 上限（lazy
//!    背压兜底） 进 caps 栏。旧状该面零登记且上限跨档恒定（4096 条 ⇒ 最坏 ~2GiB）。
//!    **禁**拿瞬态上界反解条数（512MB 档只剩 ~180 条 = 并发回退，D-01 同款教训）。
//!
//! **内存自适应（bd sfqlu，2026-11-07 用户拍板）**：总预算不再钉 96MB，改由
//! `xray_frame::budget::plan::MemoryPlan` 按**探测到的可用内存**分档派生——
//! ≤256MB→40MB / ≤512MB→96MB / ≤1GB→192MB / >1GB→`min(512MB, 可用/4)`。同一份
//! 派生值给出桥每方向字节闸 + 未经本门时的**缺省**连接数（`总预算 / 3MiB` =
//! 13/32/64/170）。**过门后的执行点上限 = 账本余量口径**（bd 3gxez）：
//! `(预算 − 固定面 − 显式 socket) / 每连接 pipe(双向)` —— 档位设计表只是未装配
//! 时的读数，不再当天花板（设计表的每连接单价含 2MiB「在途份额」，而在途已由
//! D-01 裁定为瞬态背压上界 ⇒ 按它封顶会把小内存档压到账本余量以下，成片拒连；
//! `XRAY_MAX_CONNS` 只收紧、不放大）。满载乘积
//! （`max_conns × 2 × gate`）因此**过订**（3.3×–21×）——闸是瞬态背压上界，非每连接
//! 常驻 ⇒ 该上界如实进 caps 栏 + WARN（bd 2026-11-08 D-01，口径经 PM 修正；
//! 全局共享配额终态另票）。预算装不下时**不拒启**：按装得下的并发数降档并 warn，
//! **降档值写进执行点**（`xray_frame::budget::plan::set_effective_max_conns`，桥读
//! 同一份值，D-02；只有连 1 条连接都装不下才拒）。96MB 仍是 `min` 上沿的默认设计点，
//! 故原「96MiB 不是运行期硬上界」口径不变。

// 登记簿常量单一事实源 = `xray_frame::budget`（ADR-B 拆分）；此处只转出，不复制。
// UDP 会话面常量单一事实源 = dispatcher 实现（同 `xray_proxy_tuic::udp::DGRAM_INBOX_BYTE_CAP`
// 口径：登记簿直引实现常量，**禁复制值**——改实现值即改账面，无第二份真相源）。
use xray_app_dispatcher::udp_session::{
    MAX_UDP_SESSIONS, UDP_SESSION_RESIDENT_BYTES, UDP_SESSION_WORST_CASE_BYTES,
};
pub use xray_frame::budget::{
    BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES, DNS_CACHE_ESTIMATE_BYTES, DNS_CACHE_MAX_ENTRIES,
    DNS_PENDING_EST_BYTES, DNS_PENDING_MAX_ENTRIES, DNS_SINGLEFLIGHT_UNBOUNDED_NOTE,
    DOH3_SESSION_SOCKET_BOOKED_BYTES, FINALMASK_XMC_POOL_MAX_BYTES, H2_MAX_SEND_BUF_PER_CONN_BYTES,
    HANDSHAKE_INFLIGHT_MAX, HANDSHAKE_TASK_EST_BYTES, HYPER_IDLE_CONN_EST_BYTES,
    HYPER_MAX_IDLE_PER_HOST_CONNECTIONS, HYSTERIA_UDPHOP_SHARED_POOL_MAX_BYTES,
    MAX_EXPLICIT_SOCKET_BUFFER_BYTES, MAX_PER_CONN_BUFFER_BYTES, MIN_VIABLE_CONCURRENCY,
    NEW_POOLS_TOTAL_MAX_BYTES, QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES,
    QUIC_STREAM_RECEIVE_WINDOW_BYTES, QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES,
    QUIC_UDP_DEFAULT_RECV_BUFFER_BYTES, RESERVE_MARGIN_MIN_BYTES, SOCKET_KERNEL_BOOKKEEPING_FACTOR,
    SPLITHTTP_H2_CLIENT_FLOW_WINDOW_BYTES, SPLITHTTP_H2_SERVER_STREAM_WINDOW_BYTES,
    SPLITHTTP_SHARED_BLOCK_POOL_MAX_BYTES, TLS_SESSION_CACHE_ESTIMATE_BYTES,
    TLS_SESSION_CACHE_MAX_ENTRIES, WS_PER_CONN_BUFFER_BOOKED_BYTES, XDNS_FRAG_WORST_CASE_BYTES,
    XDRIVE_H2_SEND_BUF_PER_CONN_BYTES, XDRIVE_SESSION_WAL_BUFFER_BOOKED_BYTES, XRAY_BUDGET_BYTES,
    XRAY_BUF_POOL_TOTAL_MAX_BYTES, set_effective_handshake_inflight, startup_fixed_floor_bytes,
    startup_fixed_floor_bytes_for, startup_fixed_floor_bytes_for_with_inflight,
};

/// 单项每连接缓冲预算校验（字节；`origin` 指明值的来源，进错误文案）。
///
/// 违例两型：负值（-1 = 无界——铁律③禁排队/无界，Go 同源的显式坑
/// audit4-memory F8）或 > [`MAX_PER_CONN_BUFFER_BYTES`]。
fn check_conn_buffer(value_bytes: i64, origin: &str, violations: &mut Vec<String>) {
    if value_bytes < 0 {
        violations.push(format!(
            "{origin}: per-connection buffer is unbounded ({value_bytes}); \
             bd azcoe 铁律③拒绝无界（MEMORY-BUDGET-256MB.md）"
        ));
    } else if value_bytes > MAX_PER_CONN_BUFFER_BYTES {
        violations.push(format!(
            "{origin}: per-connection buffer {value_bytes}B > budget cap \
             {MAX_PER_CONN_BUFFER_BYTES}B（bd azcoe 铁律③ fail-fast）"
        ));
    }
}

/// streamSettings 的 transport 名（`method` 覆盖 `network`，Go
/// `transport_internet.go:85-88`；本仓单一规范表
/// `xray_common::net::transport::canonical_transport_protocol`）。
fn stream_network(
    ss: Option<&serde_json::Value>,
) -> Option<xray_common::net::transport::TransportProtocol> {
    let name =
        ss.and_then(|v| v.get("method").or_else(|| v.get("network"))).and_then(|v| v.as_str())?;
    xray_common::net::transport::canonical_transport_protocol(name)
}

/// 预算门两栏报告（bd 258qt / pyka7 / nlhht 的口径修正）。
///
/// - [`hard`](Self::hard)：**硬账**——装配期能判定、且真会占的字节（进
///   [`projected`](Self::projected) 判定）。含三项**瞬时上界**（xdns frag 满表、QUIC
///   连接接收窗、TUIC dgram 信箱）：它们超预算只 WARN 不拒启（用户裁决），但必须入账可见 （bd
///   2026-11-08 D-03 / security P2-2 / bd k5pqt）。
/// - [`caps`](Self::caps)：**上限面**——按连接数/端点的上界，装配期零连接 ⇒ 真实占用 0 或受 OS
///   钳制（Linux `rmem_max`），**不并入硬账**，但要 显式打印：**96 MiB 因此不是运行期硬上界**。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BudgetReport {
    /// 硬账合计（字节；与本机档位派生的 [`Self::budget`] 比较）。
    pub projected: usize,
    /// 本机档位派生的总预算（字节；bd sfqlu）。
    pub budget: usize,
    /// 本机可用内存（字节；`XRAY_MEM_LIMIT_MB` 覆盖后）。
    pub available: u64,
    /// 档位短名（`tiny`/`small`/`medium`/`large`）。
    pub tier: &'static str,
    /// 运行期连接数上限（条；触顶由桥 fail-visible 拒绝）。
    pub max_conns: usize,
    /// 硬账逐项（名, 字节）。
    pub hard: Vec<(String, usize)>,
    /// 上限面逐项（名, 上界字节；**不进合计**）。
    pub caps: Vec<(String, usize)>,
    /// 降档说明（`Some` = 预算装不下完整并发，已按能装下的条数封顶但**不拒启**）。
    pub degraded: Option<String>,
    /// 违例（空 = 过门）。
    pub violations: Vec<String>,
}

impl BudgetReport {
    /// 过门。
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.violations.is_empty()
    }

    /// 单行摘要（启动日志 + 错误文案共用）：档位 + 硬账 + 上限面 + 96MiB 的口径声明。
    #[must_use]
    pub fn summary(&self) -> String {
        let hard: Vec<String> =
            self.hard.iter().map(|(name, bytes)| format!("{name} {bytes}B")).collect();
        let caps: Vec<String> =
            self.caps.iter().map(|(name, bytes)| format!("{name} {bytes}B")).collect();
        format!(
            "memory budget: tier {} (available {}B) hard {}B / {}B, max {} conns [{}] ; caps \
             (per-conn/per-endpoint upper bounds, not summed — 96MiB is NOT a runtime hard bound) \
             [{}]",
            self.tier,
            self.available,
            self.projected,
            self.budget,
            self.max_conns,
            hard.join(" + "),
            caps.join(" + "),
        )
    }
}

/// 缺省 xmux/xhttp 连接池上限的**派生链**（bd m2mmm 观测缺口的接线面）。
///
/// 数据源 = `xray_frame::budget::plan` 的**唯一事实源**（[`conn_budget`] / [`ConnBudget`] /
/// [`xmux_pool_cap`]）——本仓不另造派生口径（§3.5.2 禁两份真相源）。
///
/// 数值取**启动快照**（装配期 [`MemoryPlan::cached`] 的探测值）；运行期池上限按实况
/// 内存重算（`xmux_pool_cap(live_available())`，5s TTL，见 splithttp `mux::pool_cap`）
/// ⇒ 启动行是**快照**，运行期数值可微漂（漂移方向恒为「内存变少 ⇒ 上限变低」）。
fn conn_budget_log_line(plan: &xray_frame::budget::plan::MemoryPlan) -> String {
    let cb = xray_frame::budget::plan::conn_budget(plan.available);
    format!(
        "conn budget: xmux/xhttp pool cap {} conns (tier {}, tier cap {}, derived {}, \
         share {}/{}, per-conn {}B, available {}B via {})",
        xray_frame::budget::plan::xmux_pool_cap(plan.available),
        cb.tier.as_str(),
        cb.tier_cap,
        cb.derived,
        cb.share_num,
        cb.share_den,
        cb.per_conn,
        plan.available,
        plan.source,
    )
}

/// xhttp（splithttp）**每连接**账面（字节）= 档位对应服务端 h2 send_buf + hyper 空闲
/// 连接池余量（`MAX_IDLE_PER_HOST` 条 × 每连接估算）。
///
/// 只进 caps 栏（per-conn 上限，**不求和**）。send_buf 的唯一映射源 =
/// [`xray_transport::h2_window::h2_server_max_send_buf_for`]（tiny 8MiB、small 16MiB、
/// medium/large 32MiB）——打印值必须与 transport 实际定窗同源，禁在此另立数字。
fn xhttp_conn_booked_bytes(tier: xray_frame::budget::plan::MemoryTier) -> usize {
    xray_transport::h2_window::h2_server_max_send_buf_for(tier)
        + HYPER_MAX_IDLE_PER_HOST_CONNECTIONS * HYPER_IDLE_CONN_EST_BYTES
}

/// 装配期预算门：产出两栏报告（违例见 [`BudgetReport::violations`]）。
///
/// 校验面（bd sgdwm 扩面 + bd 258qt 口径修正 + bd sfqlu 档位自适应）：
/// 1. 每连接 pipe 软上限（env 缺省档 + policy 各 level `bufferSize`；负值硬拒、 0 放行）；
/// 2. **硬账**：固定底数（池/缓存 + **每监听**握手在途，bd 258qt(a)）+ 最小并发 × pipe 双向 +
///    **显式** `sockopt.receiveBufferSize` 的 UDP 端点账面 （×2 内核记账，bd nlhht）+
///    **瞬时上界三项**（xdns frag 满表、QUIC 连接接收窗、TUIC dgram 信箱；超预算只 WARN 不拒启）——
///    固定面 + 连接面超预算拒启，瞬时面超预算只 WARN（用户裁决 2026-11-07）；
/// 3. **上限面**（不判、只报）：QUIC 缺省 socket（Linux `rmem_max` 钳制 ⇒ 按 16MiB
///    预约会误杀合法配置，bd 258qt(c)）、DoH3 resolver socket（装配期不可数， bd 258qt(d)）、xhttp
///    h2 send_buf（惰性分配，bd pyka7）、桥在途、QUIC 流窗（连接窗内子份额）。
///
/// 预算取自本机档位（[`xray_frame::budget::plan::MemoryPlan::cached`]）；装不下
/// 完整并发时只**降档**（[`BudgetReport::degraded`]），连 1 条都装不下才记违例。
///
/// # 错误
/// `policy` 配置 JSON 坏 → `Err`；违例 → [`BudgetReport::violations`] 非空。
pub fn budget_report(built: &xray_conf::BuiltConfig) -> Result<BudgetReport, String> {
    budget_report_with(built, *xray_frame::budget::plan::MemoryPlan::cached())
}

/// 同 [`budget_report`]，档位计划由调用方注入（单测按档位钉行为）。
pub fn budget_report_with(
    built: &xray_conf::BuiltConfig,
    plan: xray_frame::budget::plan::MemoryPlan,
) -> Result<BudgetReport, String> {
    let mut violations = Vec::new();

    // ── 1) 配置派生面（bd azcoe 原面，口径不变）──
    let env_default = i64::from(xray_features::policy::BufferPolicy::default().connection);
    check_conn_buffer(env_default, "env default buffer", &mut violations);

    let mut max_pipe_bytes = env_default.max(0) as usize;
    for app in &built.apps {
        if app.kind != "policy" {
            continue;
        }
        let cfg: xray_conf::app_config::PolicyConfig = serde_json::from_slice(&app.data)
            .map_err(|e| format!("memory budget gate: invalid policy config: {e}"))?;
        for (lv, level) in &cfg.levels {
            if let Some(kb) = level.buffer_size {
                let bytes = if kb < 0 { -1 } else { i64::from(kb) * 1024 };
                check_conn_buffer(bytes, &format!("policy level {lv} buffer"), &mut violations);
                if bytes > max_pipe_bytes as i64 {
                    max_pipe_bytes = bytes as usize;
                }
            }
        }
    }

    // ── 2) 端点扫描（inbounds + outbounds 的 streamSettings）──
    let mut quic_default = 0usize;
    let mut quic_explicit_booked = 0usize;
    // QUIC 端点总数（显式 + 缺省）：每端点可建 N 条连接，连接窗按连接计（D-03）。
    let mut quic_endpoints = 0usize;
    let mut splithttp = 0usize;
    // xdrive 端点数与其中 h3 分支数（bd yc54c G5）：h3 连接窗入硬账（同 D-03 口径），
    // WAL 会话缓冲面上限面。
    let mut xdrive_endpoints = 0usize;
    let mut xdrive_h3_endpoints = 0usize;
    // masque 端点数（bd anygg G3 / 规划 R14 B4.6）：masque 一体 inbound/outbound 与
    // 纯 transport 形态都带 `network:"masque"` ⇒ 统一按 streamSettings 计数；每条
    // 连接一条 CONNECT-IP 隧道（R15 shortcut），隧道 h2 send_buf 上界入硬账。
    let mut masque_endpoints = 0usize;
    let stream_settings = built
        .inbounds
        .iter()
        .map(|i| i.stream_settings_json.as_ref())
        .chain(built.outbounds.iter().map(|o| o.stream_settings_json.as_ref()));
    for ss in stream_settings {
        match stream_network(ss) {
            Some(xray_common::net::transport::TransportProtocol::Quic) => {
                quic_endpoints += 1;
                match explicit_receive_buffer(ss) {
                    // 显式值 = 运维亲手指定 ⇒ bind 即真占（× 内核 2× 记账）⇒ 硬账。
                    Some(bytes) => {
                        quic_explicit_booked += bytes * SOCKET_KERNEL_BOOKKEEPING_FACTOR;
                    },
                    // 缺省 = 8MiB 只升不降，但 Linux `rmem_max` 钳制 ⇒ 上限面。
                    None => quic_default += 1,
                }
            },
            Some(xray_common::net::transport::TransportProtocol::SplitHttp) => splithttp += 1,
            Some(xray_common::net::transport::TransportProtocol::XDrive) => {
                xdrive_endpoints += 1;
                if xdrive_h3(ss) {
                    xdrive_h3_endpoints += 1;
                }
            },
            Some(xray_common::net::transport::TransportProtocol::Masque) => {
                masque_endpoints += 1;
            },
            _ => {},
        }
    }

    // ── 3) 硬账 + 档位降级（bd sfqlu）──
    // 监听数 = 真正 listen 的入站数（握手闸每 accept 循环一份，bd 258qt(a)）。
    let listeners = built.inbounds.iter().filter(|i| i.port.is_some()).count();
    // 每连接 pipe 占用按两方向计（上/下行各一条 policy pipe，见 MAX_PER_CONN_BUFFER_BYTES doc）。
    let per_conn_pipe = max_pipe_bytes * 2;
    let budget = plan.total_budget;
    // 握手在飞额度**由预算反解**，不再按满载上界（64/监听）预占：
    // 先扣静态面 + 显式 socket + 最小可跑连接面，余额 ÷ 单任务账面 ÷ 监听数
    // = 每监听可用在飞握手数；握手闸按同一值 fail-fast（超限丢弃，不排队）。
    // 2026-11-08 真机实证：176（528MB / 26 监听 / tiny 40MiB）在满载口径下被判
    // 「连 1 条连接都装不下」而拒启；反解后静态面 19MiB + 每监听 ~14 在飞握手即可启动。
    let cores = std::thread::available_parallelism().map_or(1, usize::from);
    let floor_no_hs = startup_fixed_floor_bytes_for_with_inflight(cores, listeners, 0);
    // 握手面**至多占预算 1/4**：它是准入并发上限（超限即丢弃），不该把连接面饿死。
    // 反例（2026-11-08 176 实测）：只按「余额全给握手」反解 ⇒ 26 监听吃走 86.7MiB，
    // 96MiB 预算仍只剩 9 条连接，等于没解决问题。
    let hs_avail = budget
        .saturating_sub(floor_no_hs + quic_explicit_booked + MIN_VIABLE_CONCURRENCY * per_conn_pipe)
        .min(budget / 4);
    // `listeners.max(1)`：0 监听时 floor 不含握手项，该值不参与计算，取 1 避免除零。
    let hs_per_listener =
        (hs_avail / HANDSHAKE_TASK_EST_BYTES / listeners.max(1)).min(HANDSHAKE_INFLIGHT_MAX);
    set_effective_handshake_inflight(hs_per_listener);
    let fixed = startup_fixed_floor_bytes_for(cores, listeners);
    // 固定面与显式 socket 先扣，剩下的才是连接可用额。不足 = 一条满额 pipe 都装不下。
    let for_conns = budget.saturating_sub(fixed + quic_explicit_booked);
    // `bufferSize 0`（Go 合法「不排队」）不占字节 ⇒ 装得下的条数不受限。
    let conns_fit = for_conns.checked_div(per_conn_pipe).unwrap_or(MIN_VIABLE_CONCURRENCY);
    let conns = conns_fit.min(MIN_VIABLE_CONCURRENCY);
    // 运行期连接数上限 = **账本余量口径**（bd 3gxez）：上面算出的 `conns_fit`（预算 −
    // 固定面 − 显式 socket，除以每连接 pipe 双向）就是本配置装得下的条数，直接写进执行点。
    // 档位设计表（13/32/64/170 = 预算/3MiB）**不再当天花板**：它的每连接单价含 2MiB
    // 「在途份额」，而 D-01 已裁定在途是瞬态背压上界（桥字节闸自身兜、只进 caps 栏）⇒
    // 设计表把小内存档压到远低于账本装得下的条数（tiny 13 vs 20），多设备/浏览器并发
    // 即触顶成片拒连（用户感知 = 不稳定）。设计表只剩「未过预算门」时的缺省读数。
    // `XRAY_MAX_CONNS` 仍**只收紧**（用户裁决 2026-11-13：不提供手动放大入口）。
    // **降档值必须到执行点**（bd 2026-11-08 D-02）：桥上 `ConnSlot` 读的正是这里
    // 写入的同一份值；旧状只写 warn 文案，桥仍用档位原值。
    let explicit = xray_frame::budget::plan::explicit_max_conns();
    let max_conns = xray_frame::budget::plan::set_effective_max_conns(
        explicit.map_or(conns_fit, |n| n.min(conns_fit)),
    );

    // ── 3b) 瞬时上界入硬账（bd 2026-11-08 D-03 / security P2-2）──
    // 三项都**由远端/负载推高、装配期不可判定**，但真的会吃掉预算：
    // - xdns frag：每 xdns server 满表 41.2MiB（`frag_n` 由对端片数控制， security P2-2：旧状只进
    //   caps 栏 ⇒ 等于不判，Tiny 40MiB 档静默超账）；
    // - QUIC 连接接收窗：每已建立连接 32MiB，且**无连接级准入闸**（唯一闸是 握手在飞）⇒
    //   入账乘数取「预算余量装得下几条满窗连接」（不是档位并发上限， 那样恒得 10× 超账 ⇒
    //   告警噪音；D-03：旧状全仓零登记）；
    // - TUIC dgram 信箱（bd k5pqt）：每 TUIC 出站一个 per-connection 收包信箱，滞留
    //   条目属主不读取即常驻（字节上界 = `xray_proxy_tuic::udp::DGRAM_INBOX_BYTE_CAP`，
    //   修复前键数上界不封总量、单连接滞留可达 ~300MB）。乘数同 D-03 余量口径。
    // 三者超预算都**只 WARN 不拒启**（用户裁决 2026-11-07）；把它们排斥在
    // `conns_fit` 之外同样是为不把连接面饿死到拒启（frag 单独就超 Tiny 预算）。
    let xdns_servers: usize =
        built.inbounds.iter().map(|i| xdns_mask_count(i.stream_settings_json.as_ref())).sum();
    let frag_booked = xdns_servers * XDNS_FRAG_WORST_CASE_BYTES;
    // QUIC 连接窗：按「本预算**实际装得下几条满窗连接**」记账（不是按档位最大并发——
    // 后者恒得 10× 超账，告警立刻退化成噪音，PM 2026-11-08 再纠偏）。`max(1)` 是
    // 记账口径（至少记 1 条，否则本项为 0 = 不判）；真装不下时会由 projected 超预算
    // 触发告警，文案点明「缺连接级准入闸」这个真问题。
    let quic_conns_fit = budget
        .saturating_sub(fixed + quic_explicit_booked + conns * per_conn_pipe)
        / QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES;
    let quic_conns = if quic_endpoints > 0 { max_conns.min(quic_conns_fit.max(1)) } else { 0 };
    let quic_windows_booked = quic_conns * QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES;
    // TUIC dgram 信箱（bd k5pqt）：常量单一事实源 = tuic 实现（登记簿直引，禁复制值）。
    let tuic_outbounds = built.outbounds.iter().filter(|o| o.entry.kind == "tuic").count();
    let tuic_inbox_fit = budget
        .saturating_sub(fixed + quic_explicit_booked + conns * per_conn_pipe)
        / xray_proxy_tuic::udp::DGRAM_INBOX_BYTE_CAP;
    let tuic_inbox_conns =
        if tuic_outbounds > 0 { tuic_inbox_fit.max(1).min(tuic_outbounds) } else { 0 };
    let tuic_inbox_booked = tuic_inbox_conns * xray_proxy_tuic::udp::DGRAM_INBOX_BYTE_CAP;
    // xdrive h3 连接窗（bd yc54c G5）：xdrive h3 分支的 quinn `TransportConfig`
    // 与 QUIC transport 同源同缺省（`xray_transport_xdrive::h3` transport_config
    // 缺省 = `xray_transport_quic::config::DEFAULT_CONNECTION_RECEIVE_WINDOW`
    // 32MiB）⇒ 复用同一账面常量。乘数同 D-03 余量口径，且从**扣除前序瞬时面**
    // 之后的余量反解（QUIC/xdrive 两种 h3 族并存时不重复记账同一份余量）。
    let xdrive_h3_fit = budget.saturating_sub(
        fixed
            + quic_explicit_booked
            + conns * per_conn_pipe
            + frag_booked
            + quic_windows_booked
            + tuic_inbox_booked,
    ) / QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES;
    let xdrive_h3_conns =
        if xdrive_h3_endpoints > 0 { max_conns.min(xdrive_h3_fit.max(1)) } else { 0 };
    let xdrive_windows_booked = xdrive_h3_conns * QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES;
    // masque 隧道 h2 send_buf（bd anygg G3 / 规划 R14 B4.6）：每条 CONNECT-IP 隧道
    // 一条 h2 连接，发送缓冲上界 16MiB——单一事实源 = `xray_transport::h2_window::
    // H2_MAX_SEND_BUF_SIZE`（masque `h2.rs` 与 splithttp transport 同一 re-export
    // 符号）⇒ 复用登记簿 [`H2_MAX_SEND_BUF_PER_CONN_BYTES`] 同一账面，零新造数字。
    // 乘数同 D-03 余量口径：从扣除前序瞬时面之后的余量反解「装得下几条满载隧道」，
    // 上界 = 运行期连接数上限（R15：每连接一条隧道）；端点数只作开关（= 0 不记账）。
    let masque_fit = budget.saturating_sub(
        fixed
            + quic_explicit_booked
            + conns * per_conn_pipe
            + frag_booked
            + quic_windows_booked
            + tuic_inbox_booked
            + xdrive_windows_booked,
    ) / H2_MAX_SEND_BUF_PER_CONN_BYTES;
    let masque_tunnels = if masque_endpoints > 0 { max_conns.min(masque_fit.max(1)) } else { 0 };
    let masque_send_buf_booked = masque_tunnels * H2_MAX_SEND_BUF_PER_CONN_BYTES;
    // UDP dispatch 会话（bd rmbby）：旧状该面**完全不在预算内**、`MAX_UDP_SESSIONS=4096`
    // 跨档恒定 ⇒ 512MB 档最坏 `4096 × (8KiB + 2×256KiB) ≈ 2GiB` 静默吃穿。
    // 两面分开记（口径见两条常量 doc）：
    // - **常驻** 8KiB/条（池化读缓冲，建会话即占）= 稳态面 ⇒ 按**余量口径**反解本档
    //   装得下的条数（余量 ÷ 常驻字节，上界 = 实现常量），该条数**写进执行点**
    //   （`set_effective_max_udp_sessions`，dispatcher `establish` 读同一份值，超限 fail-visible
    //   拒建）。**禁**按「最坏上界」反解条数：2GiB > 任何档预算 ⇒ 512MB 档只装得下 ~180 条会话 =
    //   并发回退（bd 2026-11-08 D-01 同款教训）。
    // - **瞬态** 2×256KiB duplex（lazy 背压兜底）⇒ caps 栏诚实上界（同
    //   `BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES` 口径），不单独 WARN（恒真 = 噪音）。
    let udp_fit = budget.saturating_sub(
        fixed
            + quic_explicit_booked
            + conns * per_conn_pipe
            + frag_booked
            + quic_windows_booked
            + tuic_inbox_booked
            + xdrive_windows_booked
            + masque_send_buf_booked,
    ) / UDP_SESSION_RESIDENT_BYTES;
    let udp_sessions = xray_frame::budget::plan::set_effective_max_udp_sessions(
        udp_fit.clamp(1, MAX_UDP_SESSIONS),
    );
    let udp_resident_booked = udp_sessions * UDP_SESSION_RESIDENT_BYTES;
    let transient_booked = frag_booked
        + quic_windows_booked
        + tuic_inbox_booked
        + xdrive_windows_booked
        + masque_send_buf_booked;
    let steady_booked = fixed + quic_explicit_booked + conns * per_conn_pipe + udp_resident_booked;
    let projected = steady_booked + transient_booked;
    if conns_fit == 0 {
        violations.push(format!(
            "actual occupancy {steady_booked}B > budget {budget}B even for 1 conn: fixed {fixed}B \
             (pools+caches + {listeners} listeners x {HANDSHAKE_INFLIGHT_MAX} x \
             {HANDSHAKE_TASK_EST_BYTES}B handshake) + explicit udp sockets \
             {quic_explicit_booked}B + 1 conn x {per_conn_pipe}B pipe(2-way); \
             tier {} (bd sfqlu)",
            plan.tier.as_str(),
        ));
    }
    // 告警面（全部走 warn，**不拒启**）：① 连接数降档；② 瞬时上界装不下。
    let mut notes: Vec<String> = Vec::new();
    // 装不下完整并发 ⇒ 降档运行（**不拒启**）：显式告警，让运维看得见少了多少条。
    // 触发两条：① 装不满最小可跑并发；② 生效值低于「档位设计值 / XRAY_MAX_CONNS 显式值」
    // （bd 3gxez 起设计值只是缺省读数，压制它的账本余量必须可见）。
    if conns_fit > 0 && (conns < MIN_VIABLE_CONCURRENCY || max_conns < plan.max_conns) {
        notes.push(format!(
            "内存降档运行（bd sfqlu）：档位 {}（{}，可用 {}B，来源 {}）总预算 {budget}B，\
             固定面 {fixed}B（{listeners} 个监听）+ 显式 socket {quic_explicit_booked}B 后\
             每连接 {per_conn_pipe}B pipe（双向）只装得下 {conns_fit} 条连接\
             （最小可跑 {} 条 / 档位设计值 {} 条）⇒ 本配置连接数上限降为 {max_conns} 条，不拒启",
            plan.tier.as_str(),
            plan.tier.label(),
            plan.available,
            plan.source,
            MIN_VIABLE_CONCURRENCY,
            plan.max_conns,
        ));
    }
    // TUIC 信箱乘数被封顶（装不下全部出站）⇒ **独立 WARN**（bd k5pqt）：账面必须
    // 可见。不能只放在下面「瞬时面超预算」分支里——该分支仅在 projected > budget 时
    // 进，而封顶后 projected 可能仍在预算内，此时「漏记的条数」同样必须告警。
    if tuic_outbounds > tuic_inbox_conns {
        notes.push(format!(
            "TUIC dgram 信箱记账封顶（只 WARN 不拒启，bd k5pqt）：{} 个 tuic 出站 × {}B 字节上界，\
             预算余量只装得下 {tuic_inbox_conns} 个 ⇒ 第 {} 个起的滞留不受预算约束",
            tuic_outbounds,
            xray_proxy_tuic::udp::DGRAM_INBOX_BYTE_CAP,
            tuic_inbox_conns + 1
        ));
    }
    // UDP dispatch 会话上限被预算压低（bd rmbby）⇒ **独立 WARN**：这是**执行点真缩了**
    // 的可行动事件（第 N+1 条会话会拿到 io::Error），不是上面那种「不受预算约束」的
    // 诚实标注 ⇒ 必须让运维在启动日志里看到。常态档位装得下时不发（防噪音）。
    if udp_sessions < MAX_UDP_SESSIONS {
        notes.push(format!(
            "UDP dispatch 会话上限按预算降为 {udp_sessions} 条（bd rmbby，只 WARN 不拒启）：\
             预算余量只装得下 {udp_sessions} 条 × 每会话常驻 {UDP_SESSION_RESIDENT_BYTES}B\
             （实现硬顶 {MAX_UDP_SESSIONS} 条），超限由 establish 拒建\
             （fail-visible io::Error，不静默丢包）"
        ));
    }
    // 瞬时上界（xdns frag / QUIC 连接窗）超预算 = 只 WARN（用户裁决 2026-11-07）。
    if transient_booked > 0 && projected > budget {
        let mut parts: Vec<String> = Vec::new();
        if frag_booked > 0 {
            parts.push(format!(
                "xdns frag 满表 {frag_booked}B（{xdns_servers} 个 server × \
                 {XDNS_FRAG_WORST_CASE_BYTES}B，片数由对端控制）"
            ));
        }
        if quic_conns > 0 {
            parts.push(format!(
                "QUIC 接收窗：预算只装得下 {quic_conns} 条满窗连接（\
                 {QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES}B/连接），且**无连接级准入闸**\
                 （唯一闸是握手在飞）⇒ 第 {} 条起的窗口内存不受预算约束",
                quic_conns + 1
            ));
        }
        if xdrive_h3_conns > 0 {
            parts.push(format!(
                "xdrive h3 接收窗：预算只装得下 {xdrive_h3_conns} 条满窗连接（\
                 {QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES}B/连接，与 QUIC transport \
                 同源同缺省）⇒ 第 {} 条起的窗口内存不受预算约束",
                xdrive_h3_conns + 1
            ));
        }
        if masque_tunnels > 0 {
            parts.push(format!(
                "masque 隧道 h2 send_buf：预算只装得下 {masque_tunnels} 条满载隧道（\
                 {H2_MAX_SEND_BUF_PER_CONN_BYTES}B/隧道）⇒ 第 {} 条起的发送缓冲\
                 不受预算约束",
                masque_tunnels + 1
            ));
        }
        notes.push(format!(
            "瞬时面上界超预算（只 WARN 不拒启，bd 2026-11-08 D-03/security P2-2）：{}；\
             最坏瞬时账面 {projected}B > 预算 {budget}B，常态账面 {steady_booked}B 在预算内",
            parts.join("；")
        ));
    }
    // 满载乘积**过订**：闸是瞬态背压上界（lazy 分配，正常链路远不满），不是每连接
    // 常驻 ⇒ `max_conns × 2 × gate` 与预算是不同量纲，乘积必然超订。**禁静默**
    // （bd 2026-11-08 D-01）：登记成 caps 里的诚实上界 + 一条 WARN；**不**拿它反解
    // 并发数（反解会把四档并发砍到 4/4/4/8 条 = 功能回退，PM 打回）。
    let full_load_product = max_conns * 2 * plan.bridge_gate;
    if full_load_product > budget {
        notes.push(format!(
            "满载乘积过订（bd 2026-11-08 D-01，只 WARN）：{max_conns} 条 × 2 方向 × {}B 闸 = \
             {full_load_product}B，为预算 {budget}B 的 {:.2}× ——闸是**瞬态背压上界**（lazy，正常\
             链路远不满），最坏情形由闸自身兜；**不**按乘积反解并发（否则并发砍到 4 条）",
            plan.bridge_gate,
            full_load_product as f64 / budget as f64,
        ));
    }
    let degraded = (!notes.is_empty()).then(|| notes.join("；"));

    // ── 4) 上限面（打印用；不进 projected）──
    // xhttp 每连接账面按**档位实际生效值**打（send_buf 8MiB@tiny / 16MiB@small /
    // 32MiB@medium|large + 空闲连接池余量）：打印值必须与 transport 侧实际定窗一致。
    let xhttp_conn_booked = xhttp_conn_booked_bytes(plan.tier);
    let caps = vec![
        (
            format!(
                "{quic_default} QUIC x {QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES}B default socket"
            ),
            quic_default * QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES,
        ),
        (
            format!("{splithttp} xhttp x {xhttp_conn_booked}B per-conn h2 send_buf cap"),
            splithttp * xhttp_conn_booked,
        ),
        // bd yc54c G5：xdrive 会话缓冲面上限面（WAL 段缓冲 + h2 send buf，均
        // 惰性/会话级，装配期零会话 ⇒ 不进硬账）。
        (
            format!(
                "{xdrive_endpoints} xdrive x {XDRIVE_SESSION_WAL_BUFFER_BOOKED_BYTES}B \
                 WAL session buffers"
            ),
            xdrive_endpoints * XDRIVE_SESSION_WAL_BUFFER_BOOKED_BYTES,
        ),
        (
            format!(
                "per xdrive h2 conn {XDRIVE_H2_SEND_BUF_PER_CONN_BYTES}B send buf (hyper default)"
            ),
            XDRIVE_H2_SEND_BUF_PER_CONN_BYTES,
        ),
        // bd 55yh7 B4（R14）：masque 单隧道 16MiB send_buf——per-单位上限面保留；
        // 总额账面自 bd anygg G3 起按端点开关 × 余量口径**入硬账**（hard 栏
        // "N masque tunnel h2 send_buf" 项），此处只留防回档登记。
        (
            format!("per masque tunnel {H2_MAX_SEND_BUF_PER_CONN_BYTES}B h2 send_buf cap"),
            H2_MAX_SEND_BUF_PER_CONN_BYTES,
        ),
        (
            format!("per DoH3 resolver {DOH3_SESSION_SOCKET_BOOKED_BYTES}B socket"),
            DOH3_SESSION_SOCKET_BOOKED_BYTES,
        ),
        (
            format!("per conn bridge in-flight {BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES}B cap"),
            BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES,
        ),
        // QUIC 流窗是**连接窗内**的子份额（quinn 按连接窗信用发流信用）⇒ 只登记
        // 防回档，不另记账；真账面是硬账里的连接窗（bd 2026-11-08 D-03）。
        (
            format!(
                "per QUIC stream {QUIC_STREAM_RECEIVE_WINDOW_BYTES}B rx window \
                 (inside conn window, not added)"
            ),
            QUIC_STREAM_RECEIVE_WINDOW_BYTES,
        ),
        // bd sfqlu：档位派生值全部进上限面（运维核对用，不进硬账）。
        (
            format!("bridge byte gate {}B/dir x 2 dirs per conn", plan.bridge_gate),
            2 * plan.bridge_gate,
        ),
        // D-01（PM 2026-11-08 修正）：满载乘积是**诚实的最坏上界**，不是稳态预算
        // ——闸 lazy 分配、正常链路远不满。登记在 caps（运维判据）+ WARN，禁静默。
        (
            format!(
                "worst-case full-load bridge in-flight {full_load_product}B ({max_conns} conns x 2 \
                 dirs x {}B gate; {:.2}x budget — transient backpressure bound, gate enforces)",
                plan.bridge_gate,
                full_load_product as f64 / budget as f64
            ),
            full_load_product,
        ),
        // bd rmbby：UDP 会话的 duplex 面 = **惰性背压兜底**（对端不读才涨到上限）⇒
        // 诚实上界进 caps，不反解会话条数（反解 ⇒ 512MB 档只装得下 ~180 条 = 并发回退）。
        (
            format!(
                "{udp_sessions} udp dispatch sessions x {UDP_SESSION_WORST_CASE_BYTES}B worst \
                 (resident + 2 lazy duplex caps)"
            ),
            udp_sessions * UDP_SESSION_WORST_CASE_BYTES,
        ),
        (format!("max {} conns (tier {})", max_conns, plan.tier.as_str()), max_conns),
    ];

    Ok(BudgetReport {
        projected,
        budget,
        available: plan.available,
        tier: plan.tier.as_str(),
        max_conns,
        hard: vec![
            (format!("fixed floor ({listeners} listeners)"), fixed),
            ("explicit udp sockets".to_string(), quic_explicit_booked),
            (format!("{conns} conns x {per_conn_pipe}B pipe(2-way)"), conns * per_conn_pipe),
            // 瞬时面上界三项：进硬账（可对账），超预算只 WARN（见 degraded）。
            (
                format!("{xdns_servers} xdns frag worst case x {XDNS_FRAG_WORST_CASE_BYTES}B"),
                frag_booked,
            ),
            (
                format!(
                    "{quic_conns} QUIC conn receive window x \
                     {QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES}B"
                ),
                quic_windows_booked,
            ),
            (
                format!(
                    "{tuic_inbox_conns} tuic dgram inbox x {}B",
                    xray_proxy_tuic::udp::DGRAM_INBOX_BYTE_CAP
                ),
                tuic_inbox_booked,
            ),
            (
                format!(
                    "{xdrive_h3_conns} xdrive h3 conn receive window x \
                     {QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES}B"
                ),
                xdrive_windows_booked,
            ),
            (
                format!(
                    "{masque_tunnels} masque tunnel h2 send_buf x {H2_MAX_SEND_BUF_PER_CONN_BYTES}B"
                ),
                masque_send_buf_booked,
            ),
            // UDP dispatch 会话常驻面（bd rmbby）：池化读缓冲，建会话即真占。
            (
                format!(
                    "{udp_sessions} udp dispatch sessions x {UDP_SESSION_RESIDENT_BYTES}B resident"
                ),
                udp_resident_booked,
            ),
        ],
        caps,
        degraded,
        violations,
    })
}

/// streamSettings 的 xdrive h3 派生位（Go `transport_internet.go:93-120` 的
/// `xdriveH3`：`security` = tls（大小写不敏感）且 `tlsSettings.alpn` **恰为**
/// `["h3"]`；bd yc54c G5 用它判 h3 分支的 quinn 连接窗账面）。与
/// `xray_transport_xdrive::config` 的 `is_h3_alpn` 同一 Go 触发键——此处输入是
/// `BuiltConfig` 的原始 stream_settings JSON（xray-conf lint 同款形态），不是
/// dialer 的 security_json，故各持一份薄判定而非共享函数（输入形状不同）。
fn xdrive_h3(ss: Option<&serde_json::Value>) -> bool {
    let security = ss.and_then(|v| v.get("security")).and_then(|s| s.as_str());
    security.is_some_and(|s| s.eq_ignore_ascii_case("tls"))
        && ss
            .and_then(|v| v.get("tlsSettings"))
            .and_then(|t| t.get("alpn"))
            .and_then(|a| a.as_array())
            .is_some_and(|alpn| alpn.len() == 1 && alpn[0].as_str() == Some("h3"))
}

/// streamSettings 里 xdns 服务端 mask 的实例数（`finalmask.udp[{"type":"xdns"}]`）。
///
/// 每个实例一个 [`XDNS_FRAG_WORST_CASE_BYTES`] 面的分片重组器（`ServerState.frag`）
/// ⇒ 账面按份叠加。类型名与 `xray_transport::finalmask::build_udpmask_manager_from_json`
/// 的 match 臂同源（`"xdns"`）。
fn xdns_mask_count(ss: Option<&serde_json::Value>) -> usize {
    ss.and_then(|v| v.get("finalmask"))
        .and_then(|fm| fm.get("udp"))
        .and_then(|udp| udp.as_array())
        .map_or(0, |arr| {
            arr.iter().filter(|e| e.get("type").and_then(|t| t.as_str()) == Some("xdns")).count()
        })
}

/// 端点显式 UDP 接收缓冲（字节；`sockopt.receiveBufferSize`，`0`/缺省 = `None`）。
fn explicit_receive_buffer(ss: Option<&serde_json::Value>) -> Option<usize> {
    let bytes = ss?.get("sockopt")?.get("receiveBufferSize")?.as_i64()?;
    usize::try_from(bytes).ok().filter(|v| *v > 0)
}

/// 装配期预算门：违例逐条列出并拒启（fail-visible）；过门时把两栏摘要打一条 info。
///
/// 降档走 **warn**（启动继续——bd sfqlu 硬约束：不因预算不足直接拒启给用户看），
/// 两档口径：
/// 1. 档位本身低于 96MB 设计点（256MB 小鸡 ⇒ 40MB）—— 一条 warn 说明「降档到 NMB
///    预算」，运维一眼看到为陪跑进程让了多少；
/// 2. 本配置在该预算下装不下最小并发（[`BudgetReport::degraded`]）—— 再一条 warn
///    说明连接数上限被压到多少。
pub fn check_startup_budget(built: &xray_conf::BuiltConfig) -> Result<(), String> {
    check_startup_budget_with(built, *xray_frame::budget::plan::MemoryPlan::cached())
}

/// 同 [`check_startup_budget`]，档位计划由调用方注入（单测按档位钉行为）。
fn check_startup_budget_with(
    built: &xray_conf::BuiltConfig,
    plan: xray_frame::budget::plan::MemoryPlan,
) -> Result<(), String> {
    let report = budget_report_with(built, plan)?;
    if !report.is_ok() {
        return Err(format!("memory budget exceeded: {}", report.violations.join("; ")));
    }
    let log = xray_frame::logging::LogFacade::new("memory_budget", Vec::new());
    log.info(report.summary());
    // 缺省 xmux 连接池上限的**派生链**（bd m2mmm §6 验收 4：字段写对了但没接线
    // ⇒ 运维在真机日志里看不到「池按几条连接封顶」的来源）。
    log.info(conn_budget_log_line(&plan));
    // 96MB = 原设计点（整机 256MB 上的保守分账）；低于它说明本机更小，必须显式告知。
    if report.budget < XRAY_BUDGET_BYTES {
        log.warn(format!(
            "内存降档到 {}MB 预算（可用 {}B，档位 {}）：为系统 + 陪跑进程（sing-box / \
             cloudflared 等）让出内存，本机连接数上限 {} 条（bd sfqlu）",
            report.budget / (1024 * 1024),
            report.available,
            report.tier,
            report.max_conns,
        ));
    }
    if let Some(degraded) = &report.degraded {
        log.warn(degraded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use xray_conf::{BuiltEntry, BuiltInbound, BuiltOutbound};

    use super::*;

    /// 手搓 BuiltConfig（policy app 内联 JSON），供预算门单元测试。
    fn built_with_policy(json: &str) -> xray_conf::BuiltConfig {
        let mut built = xray_conf::BuiltConfig::default();
        built.apps.push(BuiltEntry { kind: "policy".into(), data: json.as_bytes().to_vec() });
        built
    }

    const MIB: u64 = 1024 * 1024;

    /// 原设计点（96MB 预算）的档位计划（bd sfqlu 起预算随机器变 ⇒ 测试须注入）。
    fn plan_96mb() -> xray_frame::budget::plan::MemoryPlan {
        xray_frame::budget::plan::MemoryPlan::from_available(512 * MIB)
    }

    /// 256MB 小鸡档（40MB 预算）。
    fn plan_256mb() -> xray_frame::budget::plan::MemoryPlan {
        xray_frame::budget::plan::MemoryPlan::from_available(256 * MIB)
    }

    /// 四档（256MB / 512MB / 1GB / 大机器）派生出的预算与**执行点**连接数上限必须自洽，
    /// 且生效值出现在报告的 caps 栏里（bd sfqlu 验收 5 · bd 3gxez 口径）。
    ///
    /// 上限口径（bd 3gxez）：`(总预算 − 固定面) / 每连接 pipe(双向)` = 本配置**账本装得下**
    /// 的条数，独立复算后逐档相等。旧断言钉的是「生效值 = 档位设计表 13/32/64/170」——那正是
    /// 缺陷行为本身（设计表把 tiny 压到 13 条 ⇒ 20 并发成片拒连）；现在设计值只是**未过本门**
    /// 时的缺省读数，只能当生效值的下界。并发能力仍不回退（更没按桥闸反解成 4/4/4/8 条）。
    #[test]
    fn tier_plan_drives_budget_and_conn_cap() {
        let cores = std::thread::available_parallelism().map_or(1, usize::from);
        let fixed = xray_frame::budget::startup_fixed_floor_bytes_for(cores, 0);
        let per_conn =
            2 * usize::try_from(xray_features::policy::BufferPolicy::default().connection).unwrap();
        for (available, budget, design_conns) in [
            (256 * MIB, 40 * MIB, 13usize),
            (512 * MIB, 96 * MIB, 32),
            (1024 * MIB, 192 * MIB, 64),
            (16 * 1024 * MIB, 512 * MIB, 170),
        ] {
            let plan = xray_frame::budget::plan::MemoryPlan::from_available(available);
            assert_eq!(plan.max_conns, design_conns, "{available}B 档：未经预算门的缺省读数");
            let report =
                budget_report_with(&xray_conf::BuiltConfig::default(), plan).expect("report");
            assert_eq!(report.budget, budget as usize, "{available}B 档总预算");
            let expect = plan.total_budget.saturating_sub(fixed) / per_conn;
            assert_eq!(report.max_conns, expect, "{available}B 档：生效上限 = 账本余量口径");
            assert!(
                report.max_conns >= design_conns,
                "{available}B 档：账本余量 {} 不得低于档位设计值 {design_conns}",
                report.max_conns
            );
            assert!(report.is_ok(), "{available}B 档缺省配置必须过门：{:?}", report.violations);
            let summary = report.summary();
            assert!(summary.contains(&format!("{budget}B")), "摘要必须带总预算：{summary}");
            assert!(
                report.caps.iter().any(|(n, _)| n.starts_with(&format!("max {expect} conns"))),
                "连接数上限必须进 caps 栏：{:?}",
                report.caps
            );
        }
    }

    /// 256MB 档装不下完整最小并发时**降档不拒启**（用户拍板）：
    /// 4MiB/方向 pipe 下 8 条连接需 64MB > 40MB ⇒ 连接数上限被压到装得下的条数。
    #[test]
    fn tiny_tier_degrades_conns_instead_of_rejecting() {
        let mut built = built_with_policy(r#"{"levels": {"0": {"bufferSize": 4096}}}"#);
        built.inbounds.push(splithttp_inbound("xhttp-in"));
        let plan = plan_256mb();
        let report = budget_report_with(&built, plan).expect("report");
        assert!(report.is_ok(), "256MB 档降档不得拒启：{:?}", report.violations);
        assert!(
            report.projected <= report.budget,
            "降档后账面必须收在预算内：{} > {}",
            report.projected,
            report.budget
        );
        assert!(report.max_conns >= 1, "至少要能跑 1 条连接");
        assert!(
            report.degraded.as_deref().is_some_and(|d| d.contains("内存降档运行")),
            "必须出降档 warn 文案：{:?}",
            report.degraded
        );
    }

    /// bd m2mmm §6 验收 4：生产启动日志里必须能 grep 到**连接数预算派生链**
    /// （档位 / 整机份额 / 每连接占用 / 派生值 / 生效上限 / 来源）——否则运维看到
    /// 「max N conns」却无法反推 xmux 缺省连接池按几条封顶。
    ///
    /// 派生值全部取自 `xray_frame::budget::plan` 的**唯一事实源**
    /// （`conn_budget` / `ConnBudget`）⇒ 与池侧（`xmux_pool_cap`）同源同值。
    #[test]
    fn conn_budget_log_line_exposes_derivation_chain() {
        let plan = plan_96mb();
        let line = conn_budget_log_line(&plan);
        let cb = xray_frame::budget::plan::conn_budget(plan.available);
        assert!(line.contains("conn budget"), "必须点名派生链：{line}");
        assert!(line.contains(&format!("pool cap {} conns", cb.cap)), "必须带生效上限：{line}");
        assert!(line.contains(&format!("tier cap {}", cb.tier_cap)), "必须带档位上限：{line}");
        assert!(line.contains(&format!("derived {}", cb.derived)), "必须带派生值：{line}");
        assert!(
            line.contains(&format!("share {}/{}", cb.share_num, cb.share_den)),
            "必须带整机份额：{line}"
        );
        assert!(line.contains(&format!("per-conn {}B", cb.per_conn)), "必须带每连接占用：{line}");
        assert!(line.contains("available"), "必须带可用内存来源：{line}");
    }

    /// 生效上限必须**等于**池侧同一公式（`xmux_pool_cap`）——两处数值一致 ⇒
    /// 运维在日志里看到的 cap 就是池真正封顶的条数（bd m2mmm 验收 4）。
    #[test]
    fn conn_budget_log_line_cap_matches_pool_cap_formula() {
        for available in [256 * MIB, 512 * MIB, 1024 * MIB, 16 * 1024 * MIB] {
            let plan = xray_frame::budget::plan::MemoryPlan::from_available(available);
            let line = conn_budget_log_line(&plan);
            let expect = xray_frame::budget::plan::xmux_pool_cap(plan.available);
            assert!(
                line.contains(&format!("pool cap {expect} conns")),
                "{available}B 档：日志 cap 必须与池侧公式一致：{line}"
            );
        }
    }

    /// **端到端验收（bd m2mmm §6 验收 4）**：生产启动路径
    /// [`check_startup_budget_with`]（= `start_full` 的预算门入口）**真的把派生链打进
    /// 了日志**——不只是「有个函数能拼出这条串」。
    ///
    /// 抓的是 `xray_frame::logging::LogFacade`（生产日志唯一出口）的真实发射 ⇒ 与运维
    /// 在真机 `grep` 到的内容同源（同一 target / 同一 level / 同一串）。
    #[test]
    fn production_startup_log_contains_conn_budget_chain() {
        #[derive(Clone, Default)]
        struct Capture(Arc<parking_lot::Mutex<Vec<String>>>);
        impl tracing::Subscriber for Capture {
            fn enabled(&self, _meta: &tracing::Metadata<'_>) -> bool {
                true
            }

            fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }

            fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

            fn record_follows_from(&self, _span: &tracing::span::Id, _id: &tracing::span::Id) {}

            fn event(&self, event: &tracing::Event<'_>) {
                struct Msg(String);
                impl tracing::field::Visit for Msg {
                    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                        if field.name() == "message" {
                            self.0.push_str(value);
                        }
                    }

                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        if field.name() == "message" {
                            self.0.push_str(&format!("{value:?}"));
                        }
                    }
                }
                let mut msg = Msg(String::new());
                event.record(&mut msg);
                if !msg.0.is_empty() {
                    self.0.lock().push(msg.0);
                }
            }

            fn enter(&self, _span: &tracing::span::Id) {}

            fn exit(&self, _span: &tracing::span::Id) {}
        }

        let capture = Capture::default();
        tracing::subscriber::with_default(capture.clone(), || {
            // 缺省配置必须过门（否则走不到打日志那一步）。
            check_startup_budget_with(&xray_conf::BuiltConfig::default(), plan_96mb())
                .expect("缺省配置必须过预算门");
        });
        let logs = capture.0.lock().clone();
        let chain = logs
            .iter()
            .find(|m| m.contains("conn budget"))
            .expect("生产启动日志必须含 conn budget 派生链：{logs:?}");
        // 六要素：档位 / 档位上限 / 派生值 / 整机份额 / 每连接占用 / 来源。
        assert!(chain.contains("tier small"), "必须带档位：{chain}");
        assert!(chain.contains("tier cap 32"), "必须带档位上限：{chain}");
        assert!(chain.contains("derived 32"), "必须带派生值：{chain}");
        assert!(chain.contains("share 100663296/536870912"), "必须带整机份额：{chain}");
        assert!(chain.contains("per-conn 3145728B"), "必须带每连接占用：{chain}");
        assert!(chain.contains("via injected"), "必须带来源：{chain}");
        assert!(chain.contains("pool cap 32 conns"), "必须带生效上限：{chain}");
    }

    /// 反例：连 1 条满额 pipe 都装不下 ⇒ 这才是拒启（降档到底线）。
    #[test]
    fn rejects_only_when_not_even_one_conn_fits() {
        let mut built = built_with_policy(r#"{"levels": {"0": {"bufferSize": 4096}}}"#);
        // 4GiB 显式 UDP 账面（×2）= 8GiB ≫ 40MB 档预算。
        built.inbounds.push(quic_inbound_with_recv("quic-in", 4 * 1024 * 1024 * 1024));
        let err = check_startup_budget_with(&built, plan_256mb())
            .expect_err("连 1 条连接都装不下必须拒启");
        assert!(err.contains("even for 1 conn"), "错误必须点名「连 1 条都装不下」：{err}");
        assert!(err.contains("tiny"), "错误必须点名档位：{err}");
    }

    /// E1（bd 2026-11-08 D-01，口径经 PM 修正）：**账本诚实**而非乘积钳制。
    ///
    /// 断言三件事（`--nocapture` 打印四档数值行）：
    /// ① 并发能力保持旧派生量级（13/32/64/170），不被乘积反解砍掉；
    /// ② 满载乘积`max_conns × 2 × gate` 作为**最坏上界**出现在 caps 栏（运维可见）；
    /// ③ 乘积 > 预算时必须有一条 WARN（禁静默），且**不记违例**（不拒启）。
    ///
    /// **不再断言** `max_conns × 2 × gate ≤ budget`：闸是瞬态背压上界，不是每连接
    /// 常驻，那条等式本身是错的模型（PM 2026-11-08 打回）。
    #[test]
    fn full_load_product_is_registered_honestly() {
        for (available, conns) in
            [(256 * MIB, 13usize), (512 * MIB, 32), (1024 * MIB, 64), (16 * 1024 * MIB, 170)]
        {
            let plan = xray_frame::budget::plan::MemoryPlan::from_available(available);
            let report = budget_report_with(&xray_conf::BuiltConfig::default(), plan)
                .expect("缺省配置必须出报告");
            let product = report.max_conns * 2 * plan.bridge_gate;
            println!(
                "tier {} budget {}B gate {}B/dir conns {} (=tier {}) -> caps worst-case {}B ({:.2}x)",
                report.tier,
                report.budget,
                plan.bridge_gate,
                report.max_conns,
                conns,
                product,
                product as f64 / report.budget as f64
            );
            // ① 并发能力不回退：生效上限（bd 3gxez 起 = 账本余量口径）不得低于档位设计值。
            assert!(report.max_conns >= conns, "{} 档并发能力回退了", report.tier);
            // ② 最坏上界必须在 caps 栏可见。
            let (name, value) = report
                .caps
                .iter()
                .find(|(n, _)| n.starts_with("worst-case full-load bridge in-flight"))
                .unwrap_or_else(|| {
                    panic!("{} 档 caps 缺满载上界行：{:?}", report.tier, report.caps)
                });
            assert_eq!(*value, product, "caps 上界值必须等于乘积：{name}");
            // ③ 过订必须 WARN，且不拒启。
            assert!(report.is_ok(), "过订不得拒启：{:?}", report.violations);
            assert!(
                report.degraded.as_deref().is_some_and(|d| d.contains("满载乘积过订")),
                "过订必须 emit WARN（禁静默）：{:?}",
                report.degraded
            );
        }
    }

    /// E2（bd 2026-11-08 D-02）：降档 warn 文案承诺的条数 == 写进执行点的条数。
    ///
    /// 两侧数值：文案里的 `连接数上限降为 N 条` vs `report.max_conns`（后者即
    /// `set_effective_max_conns` 的写入值，桥 `ConnSlot` 读同一份；跨进程读回见
    /// `crates/xray-core/tests/memory_budget_degrade_wiring.rs`）。
    #[test]
    fn degraded_warn_text_matches_effective_conn_limit() {
        let mut built = built_with_policy(r#"{"levels": {"0": {"bufferSize": 4096}}}"#);
        built.inbounds.push(splithttp_inbound("xhttp-in"));
        let report = budget_report_with(&built, plan_256mb()).expect("report");
        let degraded = report.degraded.as_deref().expect("超预算配置必须降档并 warn");
        assert!(
            degraded.contains(&format!("连接数上限降为 {} 条", report.max_conns)),
            "warn 文案的条数必须等于写入执行点的值 {}：{degraded}",
            report.max_conns
        );
    }

    /// E3（bd 2026-11-08 D-03）：QUIC 接收窗入簿（与实现同值）+ **入硬账**
    /// （不是只打日志），乘数 = 预算**实际装得下几条满窗连接**（PM 2026-11-08 纠偏：
    /// 用档位最大并发当乘数会恒得 10× 超账 ⇒ 告警退化成噪音）。
    #[test]
    fn quic_receive_window_ledger_enters_hard_account() {
        use xray_transport_quic::config as qc;
        // 入簿：与实现缺省同值（改实现即红）。
        assert_eq!(
            QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES,
            usize::try_from(qc::DEFAULT_CONNECTION_RECEIVE_WINDOW).expect("窗口常量恒正"),
            "QUIC 连接接收窗账面必须等于实现缺省（bd D-03）"
        );
        assert_eq!(
            QUIC_STREAM_RECEIVE_WINDOW_BYTES,
            usize::try_from(qc::DEFAULT_STREAM_RECEIVE_WINDOW).expect("窗口常量恒正"),
            "QUIC 流接收窗账面必须等于实现缺省"
        );

        for (available, tier_conns) in
            [(256 * MIB, 13usize), (512 * MIB, 32), (1024 * MIB, 64), (16 * 1024 * MIB, 170)]
        {
            let plan = xray_frame::budget::plan::MemoryPlan::from_available(available);
            let mut built = xray_conf::BuiltConfig::default();
            built.inbounds.push(quic_inbound("q1"));
            let report = budget_report_with(&built, plan).expect("report");
            // 并发能力不回退：生效上限（bd 3gxez 起 = 账本余量口径）不得低于档位设计值。
            assert!(report.max_conns >= tier_conns, "{available}B 档并发能力被改动了");

            // 乘数 = min(档位并发, 预算余量装得下的满窗条数)——从报告自身两项硬账
            // 反算（不写字面量）：余量 = 预算 − 固定面 − 常态连接面。
            let read = |pred: &dyn Fn(&str) -> bool| {
                report.hard.iter().find(|(n, _)| pred(n)).map(|(_, b)| *b).unwrap_or(0)
            };
            let fixed = read(&|n| n.starts_with("fixed floor"));
            let conns_pipe = read(&|n| n.contains("conns x") && n.contains("pipe"));
            let explicit = read(&|n| n == "explicit udp sockets");
            let booked = read(&|n| n.contains("QUIC conn receive window x"));
            let fit = report.budget.saturating_sub(fixed + explicit + conns_pipe)
                / QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES;
            println!(
                "tier {} budget {}B max_conns {} quic quic_conns_fit {} -> booked {} conns = {}B",
                report.tier,
                report.budget,
                report.max_conns,
                fit.max(1),
                booked / QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES,
                booked
            );
            assert_eq!(
                booked,
                report.max_conns.min(fit.max(1)) * QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES,
                "{} 档 QUIC 窗账面必须是 min(并发上限, 余量装得下条数) × 32MiB",
                report.tier
            );
            assert_eq!(
                report.hard.iter().map(|(_, b)| b).sum::<usize>(),
                report.projected,
                "硬账逐项之和必须等于合计（QUIC 窗在账内）"
            );
            // 只 WARN 不拒启，且**只有真装不下时才告警**（告警 ↔ 超预算一一对应）。
            assert!(report.is_ok(), "瞬时面超预算不得拒启：{:?}", report.violations);
            let over = report.projected > report.budget;
            let warned = report.degraded.as_deref().is_some_and(|d| d.contains("无连接级准入闸"));
            assert_eq!(
                warned, over,
                "{} 档：账面超预算（{over}）与告警存在（{warned}）必须一一对应：{:?}",
                report.tier, report.degraded
            );
            assert!(
                report.caps.iter().any(|(n, _)| n.contains("QUIC stream")),
                "流窗必须登记在 caps（连接窗内子份额）：{:?}",
                report.caps
            );
        }
    }

    // ── xdrive 入账（bd yc54c G5）─────────────────────────────────────────

    /// xdrive 入站；`h3 = true` 带 `security=tls + alpn ["h3"]`（Go `xdriveH3`
    /// 触发键 ⇒ quinn 连接窗账面），否则 h2/h1 分支（无窗口账面）。
    fn xdrive_inbound(tag: &str, h3: bool) -> BuiltInbound {
        let mut ss = serde_json::json!({
            "network": "xdrive",
            "xdriveSettings": { "service": "local", "remoteFolder": "/tmp/x" },
        });
        if h3 {
            ss["security"] = serde_json::json!("tls");
            ss["tlsSettings"] = serde_json::json!({"alpn": ["h3"]});
        }
        BuiltInbound {
            entry: BuiltEntry { kind: "dokodemo-door".into(), data: b"{}".to_vec() },
            tag: tag.into(),
            port: Some(443),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: Some(ss),
            sniffing_json: None,
        }
    }

    fn xdrive_outbound(tag: &str, h3: bool) -> BuiltOutbound {
        let mut ss = serde_json::json!({
            "network": "xdrive",
            "xdriveSettings": { "service": "local", "remoteFolder": "/tmp/x" },
        });
        if h3 {
            ss["security"] = serde_json::json!("tls");
            ss["tlsSettings"] = serde_json::json!({"alpn": ["h3"]});
        }
        BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
            tag: tag.into(),
            send_through: None,
            stream_settings_json: Some(ss),
            proxy_settings_json: None,
            mux_json: None,
            target_strategy: None,
        }
    }

    /// 账本公式锚（bd yc54c G5）：WAL 会话缓冲 = (1 + 3×8) × 512KiB（实现侧
    /// `params.rs` 缺省常量私有 ⇒ 钉公式与字面值，改实现缺省须两处同步）。
    #[test]
    fn xdrive_wal_buffer_formula_anchor() {
        assert_eq!(XDRIVE_SESSION_WAL_BUFFER_BOOKED_BYTES, (1 + 3 * 8) * 512 * 1024);
        assert_eq!(XDRIVE_SESSION_WAL_BUFFER_BOOKED_BYTES, 13_107_200, "25 × 512KiB 口径锚");
        assert_eq!(XDRIVE_H2_SEND_BUF_PER_CONN_BYTES, 400 * 1024, "hyper 缺省 send buf 估档");
    }

    /// G5 验收：xdrive h3 连接窗**入硬账**（同 D-03 乘数口径）+ WAL/h2 面
    /// 进 caps 栏；`--nocapture` 打印各档位 xdrive 入账值（账面对照）。
    #[test]
    fn xdrive_ledger_enters_hard_account_and_tiers() {
        for (available, tier_conns) in
            [(256 * MIB, 13usize), (512 * MIB, 32), (1024 * MIB, 64), (16 * 1024 * MIB, 170)]
        {
            let plan = xray_frame::budget::plan::MemoryPlan::from_available(available);
            let mut built = xray_conf::BuiltConfig::default();
            built.inbounds.push(xdrive_inbound("xd-in", true));
            built.outbounds.push(xdrive_outbound("xd-out", true));
            let report = budget_report_with(&built, plan).expect("report");
            // 并发能力不回退：生效上限（bd 3gxez 起 = 账本余量口径）不得低于档位设计值。
            assert!(report.max_conns >= tier_conns, "{available}B 档并发能力被改动了");

            let read = |pred: &dyn Fn(&str) -> bool| {
                report.hard.iter().find(|(n, _)| pred(n)).map(|(_, b)| *b).unwrap_or(0)
            };
            let booked = read(&|n| n.contains("xdrive h3 conn receive window x"));
            // 乘数口径与 QUIC 同构：min(并发上限, 扣除前序账面后的余量装得下条数)。
            // 从报告自身反算（不写字面量）：本配置无 quic/xdns/tuic 端点 ⇒
            // 余量 = 预算 − 固定面 − 常态连接面。
            let fixed = read(&|n| n.starts_with("fixed floor"));
            let conns_pipe = read(&|n| n.contains("conns x") && n.contains("pipe"));
            let explicit = read(&|n| n == "explicit udp sockets");
            let fit = report.budget.saturating_sub(fixed + explicit + conns_pipe)
                / QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES;
            let windows = report.max_conns.min(fit.max(1));
            println!(
                "tier {} budget {}B max_conns {} xdrive h3 window booked {} conns = {}B; \
                 caps WAL face 2 x {}B = {}B",
                report.tier,
                report.budget,
                report.max_conns,
                windows,
                booked,
                XDRIVE_SESSION_WAL_BUFFER_BOOKED_BYTES,
                2 * XDRIVE_SESSION_WAL_BUFFER_BOOKED_BYTES,
            );
            assert_eq!(
                booked,
                windows * QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES,
                "{} 档 xdrive h3 窗账面必须是 min(并发上限, 余量装得下条数) × 32MiB",
                report.tier
            );
            assert_eq!(
                report.hard.iter().map(|(_, b)| b).sum::<usize>(),
                report.projected,
                "硬账逐项之和必须等于合计（xdrive 窗在账内）"
            );
            assert!(report.is_ok(), "瞬时面超预算不得拒启：{:?}", report.violations);
            // WAL 会话面 + h2 send buf 面必须进 caps 栏（上限面可见）。
            assert!(
                report.caps.iter().any(|(n, _)| n.contains("xdrive x") && n.contains("WAL")),
                "WAL 会话面必须进 caps：{:?}",
                report.caps
            );
            assert!(
                report
                    .caps
                    .iter()
                    .any(|(n, _)| n.contains("xdrive h2 conn") && n.contains("send buf")),
                "h2 send buf 面必须进 caps：{:?}",
                report.caps
            );
            let over = report.projected > report.budget;
            let warned = report.degraded.as_deref().is_some_and(|d| d.contains("xdrive h3 接收窗"));
            assert_eq!(
                warned, over,
                "{} 档：xdrive 窗超预算（{over}）与告警存在（{warned}）必须一一对应：{:?}",
                report.tier, report.degraded
            );
        }
    }

    /// 非 h3 分支（h2/h1）：无连接窗账面（窗口账面只挂 h3 分支），WAL/h2 caps 面照常。
    #[test]
    fn xdrive_non_h3_has_no_window_ledger() {
        let mut built = xray_conf::BuiltConfig::default();
        built.inbounds.push(xdrive_inbound("xd-in", false));
        let report = budget_report_with(&built, plan_96mb()).expect("report");
        assert!(
            !report.hard.iter().any(|(n, b)| n.contains("xdrive h3 conn receive window") && *b > 0),
            "非 h3 分支不得记非零窗口账：{:?}",
            report.hard
        );
        assert!(
            report.caps.iter().any(|(n, _)| n.contains("WAL")),
            "WAL 面照常进 caps：{:?}",
            report.caps
        );
        assert!(report.is_ok(), "{:?}", report.violations);
    }

    /// E4（security P2-2）：Tiny 档（40MiB）下 xdns frag 满表 41.2MiB 必须**进硬账
    /// 并 emit WARN**，且**不拒启**（用户裁决：预算不足不得拒启）。
    #[test]
    fn xdns_frag_on_tiny_tier_warns_without_rejecting() {
        let mut built = xray_conf::BuiltConfig::default();
        built.inbounds.push(xdns_inbound("xdns-in"));
        let plan = plan_256mb();
        let report = budget_report_with(&built, plan).expect("report");
        let (name, booked) = report
            .hard
            .iter()
            .find(|(n, _)| n.contains("xdns frag"))
            .expect("frag 必须进硬账（旧状只在 caps 栏 = 不判）")
            .clone();
        assert!(name.contains("1 xdns frag"), "账面必须点名 server 数：{name}");
        assert_eq!(booked, XDNS_FRAG_WORST_CASE_BYTES, "单 server 满表 41.2MiB");
        // 告警可见（该文案由 `check_startup_budget` 逐条 log.warn 发出）。
        let degraded = report.degraded.as_deref().unwrap_or_default();
        assert!(
            degraded.contains("xdns frag") && degraded.contains("只 WARN 不拒启"),
            "必须 emit frag 告警且明示不拒启：{degraded:?}"
        );
        assert_eq!(
            report.hard.iter().map(|(_, b)| b).sum::<usize>(),
            report.projected,
            "硬账逐项之和必须等于合计（frag 在账内）"
        );
        assert!(
            report.projected > report.budget,
            "Tiny 40MiB 档装不下 41.2MiB frag 表（账面应超预算）：账面 {}B / 预算 {}B",
            report.projected,
            report.budget
        );
        // 不拒启：gate 返回 Ok（只 WARN）。
        check_startup_budget_with(&built, plan).expect("Tiny + xdns 只 WARN 不拒启");
    }

    /// 瞬时面上界超预算的告警条数 ≥1（frag + QUIC 同时超 ⇒ 各自独立告警）；
    /// 均为 warn 面，`violations` 必须仍空。
    #[test]
    fn transient_over_budget_emits_warns_only() {
        let mut built = xray_conf::BuiltConfig::default();
        built.inbounds.push(xdns_inbound("xdns-in"));
        built.inbounds.push(quic_inbound("quic-in"));
        let report = budget_report_with(&built, plan_256mb()).expect("report");
        assert!(report.violations.is_empty(), "瞬时面超预算不得记违例：{:?}", report.violations);
        let notes = report.degraded.as_deref().unwrap_or_default();
        let warns = notes.matches("只 WARN 不拒启").count();
        assert!(warns >= 1, "至少 1 条 warn（实际 {warns}）：{notes}");
        assert!(notes.contains("xdns frag"), "frag 告警必须在：{notes}");
        assert!(notes.contains("无连接级准入闸"), "QUIC 窗告警（缺准入闸那句）必须在：{notes}");
    }

    fn quic_inbound(tag: &str) -> BuiltInbound {
        BuiltInbound {
            entry: BuiltEntry { kind: "dokodemo-door".into(), data: b"{}".to_vec() },
            tag: tag.into(),
            port: Some(443),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: Some(serde_json::json!({"network": "quic"})),
            sniffing_json: None,
        }
    }

    fn splithttp_inbound(tag: &str) -> BuiltInbound {
        BuiltInbound {
            entry: BuiltEntry { kind: "dokodemo-door".into(), data: b"{}".to_vec() },
            tag: tag.into(),
            port: Some(8080),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: Some(serde_json::json!({"network": "splithttp"})),
            sniffing_json: None,
        }
    }

    /// xdns 服务端入站（`finalmask.udp[{"type":"xdns"}]`，Go `udp/hub.go:61-62`
    /// WrapPacketConnServer 形态；每实例一份 frag 重组器）。
    fn xdns_inbound(tag: &str) -> BuiltInbound {
        BuiltInbound {
            stream_settings_json: Some(serde_json::json!({
                "network": "tcp",
                "finalmask": { "udp": [{ "type": "xdns", "settings": {} }] }
            })),
            ..splithttp_inbound(tag)
        }
    }

    /// QUIC 入站 + **显式** `sockopt.receiveBufferSize`（bd nlhht 的形态）。
    fn quic_inbound_with_recv(tag: &str, bytes: i64) -> BuiltInbound {
        BuiltInbound {
            stream_settings_json: Some(serde_json::json!({
                "network": "quic",
                "sockopt": { "receiveBufferSize": bytes }
            })),
            ..quic_inbound(tag)
        }
    }

    fn xhttp_outbound(tag: &str) -> BuiltOutbound {
        BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
            tag: tag.into(),
            send_through: None,
            stream_settings_json: Some(serde_json::json!({"network": "splithttp"})),
            proxy_settings_json: None,
            mux_json: None,
            target_strategy: None,
        }
    }

    /// TUIC 出站（bd k5pqt）：每个 tuic 出站一个 per-connection dgram 信箱。
    fn tuic_outbound(tag: &str) -> BuiltOutbound {
        BuiltOutbound {
            entry: BuiltEntry { kind: "tuic".into(), data: b"{}".to_vec() },
            tag: tag.into(),
            send_through: None,
            stream_settings_json: None,
            proxy_settings_json: None,
            mux_json: None,
            target_strategy: None,
        }
    }

    /// masque 端点（bd anygg G3）：`network:"masque"` 即一条 CONNECT-IP 隧道面
    /// （一体 inbound/outbound 与纯 transport 形态同形，预算只看 streamSettings）。
    fn masque_outbound(tag: &str) -> BuiltOutbound {
        BuiltOutbound {
            entry: BuiltEntry { kind: "masque".into(), data: b"{}".to_vec() },
            tag: tag.into(),
            send_through: None,
            stream_settings_json: Some(serde_json::json!({"network": "masque"})),
            proxy_settings_json: None,
            mux_json: None,
            target_strategy: None,
        }
    }

    /// bd k5pqt：TUIC dgram 信箱字节上界入账——瞬态面、余量口径（乘数 =
    /// 预算余量装得下的条数，不是档位/出站上限），装不下只 WARN 不拒启。
    #[test]
    fn tuic_dgram_inbox_ledger_books_margin_count() {
        const CAP: usize = xray_proxy_tuic::udp::DGRAM_INBOX_BYTE_CAP;
        // 单一事实源 = tuic 实现（登记簿直引，无副本可漂移）；钉值口径：改实现
        // 值必须同步重审本文件登记算式与 tuic 行为测试（改值即红）。
        assert_eq!(CAP, 8 * 1024 * 1024, "TUIC 信箱字节上界口径钉值（bd k5pqt）");

        // 少量出站（3 个）：96MB 档余量必然装得下 ⇒ 按实际出站数记账。
        let mut built = xray_conf::BuiltConfig::default();
        for i in 0..3 {
            built.outbounds.push(tuic_outbound(&format!("tuic-out-{i}")));
        }
        let report = budget_report_with(&built, plan_96mb()).expect("report");
        let booked = report
            .hard
            .iter()
            .find(|(name, _)| name.contains("tuic dgram inbox"))
            .map_or(0, |(_, bytes)| *bytes);
        assert_eq!(booked, 3 * CAP, "装得下时按实际出站数记账");
        assert!(
            !report.degraded.as_ref().is_some_and(|d| d.contains("TUIC")),
            "装得下不得产生 TUIC WARN：{:?}",
            report.degraded
        );

        // 20 个出站：96MB 档余量上限 = budget/CAP = 12 < 20（结构性保证，与
        // 固定面无关）⇒ 乘数封顶在余量装得下的条数，且 WARN 点名 TUIC 面。
        let mut built = xray_conf::BuiltConfig::default();
        for i in 0..20 {
            built.outbounds.push(tuic_outbound(&format!("tuic-out-{i}")));
        }
        let report = budget_report_with(&built, plan_96mb()).expect("report");
        let booked = report
            .hard
            .iter()
            .find(|(name, _)| name.contains("tuic dgram inbox"))
            .map_or(0, |(_, bytes)| *bytes);
        let fit_max = report.budget / CAP;
        assert!(fit_max < 20, "测试前提：预算装不下全部出站");
        assert!(booked > 0 && booked % CAP == 0, "乘数 ≥ 1（记账口径至少记 1 个）且为上界整数倍");
        assert!(booked / CAP <= fit_max, "乘数必须 ≤ 预算余量装得下的条数（余量口径）");
        assert!(
            report.degraded.as_ref().is_some_and(|d| d.contains("TUIC")),
            "装不下必须 WARN 点名 TUIC 面：{:?}",
            report.degraded
        );
    }

    /// masque 隧道 h2 send_buf 入账（bd anygg G3 / 规划 R14 B4.6）：瞬态面、
    /// 余量口径（乘数 = 预算余量装得下的满载隧道数，上界 = 运行期连接数上限；
    /// 端点数只作开关），装不下只 WARN 不拒启。
    #[test]
    fn masque_send_buf_ledger_books_margin_count() {
        const SEND_BUF: usize = H2_MAX_SEND_BUF_PER_CONN_BYTES;
        // 单一事实源：masque `h2.rs` 消费 `xray_transport::h2_window::
        // H2_MAX_SEND_BUF_SIZE`（与 splithttp 同一 re-export 符号）——登记簿
        // 换值必须同步重审 masque 行为与 splithttp 两侧（改值即红）。
        assert_eq!(
            SEND_BUF,
            xray_transport::h2_window::H2_MAX_SEND_BUF_SIZE,
            "masque 隧道 h2 send_buf 账面与本登记簿不一致（bd anygg G3）"
        );
        assert_eq!(SEND_BUF, 16 * 1024 * 1024, "16MiB/隧道口径锚（规划 R14）");

        // 单端点（1 个 masque outbound）：开关打开 ⇒ 记账 ≥ 1 条满载隧道；
        // 乘数同 QUIC/xdrive 口径 = 运行期连接数上限 ∩ 余量装得下的条数
        // （D-03：端点是开关不是乘数——一条连接一条隧道账面）；装得下 ⇒ 无 masque WARN。
        let mut built = xray_conf::BuiltConfig::default();
        built.outbounds.push(masque_outbound("masque-out"));
        let report = budget_report_with(&built, plan_96mb()).expect("report");
        let booked = report
            .hard
            .iter()
            .find(|(name, _)| name.contains("masque tunnel h2 send_buf"))
            .map_or(0, |(_, bytes)| *bytes);
        let tunnels = booked / SEND_BUF;
        assert_eq!(booked % SEND_BUF, 0, "账面必须是 16MiB 整数倍");
        assert!(
            (1..=report.max_conns).contains(&tunnels),
            "乘数 ∈ [1, 运行期连接数上限]（记账口径 max(1)，上界 max_conns）：tunnels={tunnels}"
        );
        assert_eq!(
            report.hard.iter().map(|(_, b)| b).sum::<usize>(),
            report.projected,
            "hard 栏合计必须等于 projected"
        );
        assert!(
            report.summary().contains("masque tunnel h2 send_buf"),
            "启动 summary 必须可见 masque 项（运维可核）：{}",
            report.summary()
        );
        assert!(
            !report.degraded.as_ref().is_some_and(|d| d.contains("masque")),
            "装得下不得产生 masque WARN：{:?}",
            report.degraded
        );

        // 0 端点 ⇒ 记账 0（开关关闭；hard 栏按既有形态全项列出，0 值即未记账，
        // 同 `"0 QUIC conn receive window"` 先例）。
        let built = xray_conf::BuiltConfig::default();
        let report = budget_report_with(&built, plan_96mb()).expect("report");
        let booked = report
            .hard
            .iter()
            .find(|(name, _)| name.contains("masque tunnel h2 send_buf"))
            .map_or(0, |(_, bytes)| *bytes);
        assert_eq!(booked, 0, "无 masque 端点不得记账：{booked}");

        // 12 端点 + 4MiB pipe（fixture 先例：8 conns × 8MB 双向 = 64MB steady 面）
        // ⇒ masque 余量只剩 ~1 条 ⇒ projected 超预算 ⇒ WARN 点名 masque 面；
        // 乘数封顶在余量装得下的条数（≤ 档位连接上限）。
        let mut built = built_with_policy(r#"{"levels": {"0": {"bufferSize": 4096}}}"#);
        for i in 0..12 {
            built.outbounds.push(masque_outbound(&format!("masque-out-{i}")));
        }
        let report = budget_report_with(&built, plan_96mb()).expect("report");
        let booked = report
            .hard
            .iter()
            .find(|(name, _)| name.contains("masque tunnel h2 send_buf"))
            .map_or(0, |(_, bytes)| *bytes);
        assert_eq!(booked % SEND_BUF, 0, "账面必须是 16MiB 整数倍");
        assert!(
            booked / SEND_BUF <= report.max_conns,
            "乘数上界 = 运行期连接数上限（每连接一条隧道，R15）"
        );
        assert!(
            report.projected > report.budget,
            "测试前提：12 端点撑爆瞬时面（projected {} > budget {}）",
            report.projected,
            report.budget
        );
        assert!(
            report.degraded.as_ref().is_some_and(|d| d.contains("masque")),
            "装不下必须 WARN 点名 masque 面（只 WARN 不拒启）：{:?}",
            report.degraded
        );
        assert!(
            report.is_ok(),
            "瞬时面超预算只 WARN，不得拒启（violations 必须为空）：{:?}",
            report.violations
        );
    }

    #[test]
    fn default_config_without_policy_app_passes() {
        // x86/aarch64 CI 均无 XRAY_BUFSIZE 环境 ⇒ env 缺省 512KB/4KB，过门。
        check_startup_budget(&xray_conf::BuiltConfig::default()).expect("缺省配置必须过预算门");
    }

    #[test]
    fn sane_level_values_pass() {
        // 512KB（x86 缺省等值）与 0（Go 合法：limit 0 = 不排队）都过门。
        let built =
            built_with_policy(r#"{"levels": {"0": {"bufferSize": 512}, "3": {"bufferSize": 0}}}"#);
        check_startup_budget(&built).expect("合法 bufferSize 必须过门");
    }

    #[test]
    fn cap_boundary_value_passes() {
        // 4096 KB = 4MiB = 上界本身：≤ 判定，过门。
        let built = built_with_policy(r#"{"levels": {"0": {"bufferSize": 4096}}}"#);
        check_startup_budget(&built).expect("恰好等于上界必须过门（≤ 判定）");
    }

    #[test]
    fn over_cap_level_is_rejected_and_named() {
        // 256 MiB/方向：96MB 预算下一条连接即超支。
        let built = built_with_policy(r#"{"levels": {"0": {"bufferSize": 262144}}}"#);
        let err = check_startup_budget(&built).expect_err("超上界必须拒");
        assert!(err.contains("memory budget exceeded"), "错误必须点名预算门：{err}");
        assert!(err.contains("policy level 0"), "错误必须点名违例 level：{err}");
        assert!(err.contains("268435456"), "错误必须带换算后的字节值（262144 KB × 1024）：{err}");
    }

    #[test]
    fn negative_level_is_unbounded_violation() {
        let built = built_with_policy(r#"{"levels": {"3": {"bufferSize": -1}}}"#);
        let err = check_startup_budget(&built).expect_err("无界必须拒");
        assert!(err.contains("unbounded"), "错误必须点名无界：{err}");
        assert!(err.contains("policy level 3"), "错误必须点名违例 level：{err}");
    }

    #[test]
    fn multiple_violations_are_listed_together() {
        // 两个 level 同时违例：fail-visible 一次报全，不逐次试错。
        let built = built_with_policy(
            r#"{"levels": {"0": {"bufferSize": -1}, "1": {"bufferSize": 8192}}}"#,
        );
        let err = check_startup_budget(&built).expect_err("双违例必须拒");
        assert!(err.contains("policy level 0"), "{err}");
        assert!(err.contains("policy level 1"), "{err}");
    }

    #[test]
    fn invalid_policy_json_is_reported_not_swallowed() {
        let mut built = xray_conf::BuiltConfig::default();
        built.apps.push(BuiltEntry { kind: "policy".into(), data: b"{not json".to_vec() });
        let err = check_startup_budget(&built).expect_err("坏 JSON 必须显式报错");
        assert!(err.contains("invalid policy config"), "{err}");
    }

    /// audit4-memory F8 语义钉（bd sgdwm 验收 4）：`bufferSize 0` = Go 合法
    /// 「limit 0 不排队」，必须过门；`-1` 才是无界，必须拒。两者分界不许被
    /// 「无界一律硬拒」扩面误伤。
    #[test]
    fn f8_buffer_size_zero_is_legal_but_negative_is_unbounded() {
        let zero = built_with_policy(r#"{"levels": {"0": {"bufferSize": 0}}}"#);
        check_startup_budget(&zero).expect("bufferSize=0（Go 合法不排队）必须过门");
        let neg = built_with_policy(r#"{"levels": {"0": {"bufferSize": -1}}}"#);
        let err = check_startup_budget(&neg).expect_err("bufferSize=-1（无界）必须拒");
        assert!(err.contains("unbounded"), "{err}");
    }

    /// 「配置合法但实际占用超预算」必须拒（bd sgdwm 验收 3，bd nlhht 改口径）：
    /// bufferSize 4MiB 是上界本身（合法），**显式** `receiveBufferSize=64MiB` 的 UDP
    /// 端点账面（64MiB × 2 内核记账 = 128MiB）本身即超 96MiB ⇒ 硬账拒启。
    ///
    /// 旧口径用「1 QUIC 端点按缺省 16MiB 预约」构造违例——bd 258qt(c) 判定那是**误杀**
    /// （Linux `rmem_max` 钳制，端点 socket 缺省只进上限面），故违例样本换成显式值。
    /// bd sfqlu 起预算随机器档位变 ⇒ 本测试注入 96MB 档（原判据的设计点）。
    #[test]
    fn gate_rejects_legal_config_whose_occupancy_exceeds_budget() {
        let mut built = built_with_policy(r#"{"levels": {"0": {"bufferSize": 4096}}}"#);
        built.inbounds.push(quic_inbound_with_recv("quic-in", 64 * 1024 * 1024));
        let err = check_startup_budget_with(&built, plan_96mb())
            .expect_err("配置合法但占用超预算必须拒（bd sgdwm 扩面）");
        assert!(err.contains("actual occupancy"), "错误必须带占用算式：{err}");
        assert!(err.contains("explicit udp sockets"), "错误必须点名显式 socket 面：{err}");
        assert!(err.contains("134217728"), "显式 64MiB × 2 内核记账必须入账：{err}");
        assert!(err.contains("pipe(2-way)"), "错误必须点名 pipe 双向口径：{err}");
    }

    /// bd nlhht：门的账面必须读配置里的 `receiveBufferSize`，不许按缺省 16MiB 记
    /// （旧状：`grep receiveBufferSize` 在门里 0 命中 ⇒ 账面与真实可差 8×）。
    #[test]
    fn explicit_udp_buffer_is_read_from_config() {
        let mut built = xray_conf::BuiltConfig::default();
        // 8 端点 × 1MiB 显式（免确认档）：硬账 = 8 × 1MiB × 2 = 16MiB。
        for i in 0..8 {
            built.inbounds.push(quic_inbound_with_recv(&format!("q{i}"), 1024 * 1024));
        }
        let report = budget_report(&built).expect("report");
        assert!(report.is_ok(), "8 × 1MiB 显式缓冲 + 最小并发应过门：{:?}", report.violations);
        assert!(
            report.hard.iter().any(|(n, b)| n == "explicit udp sockets" && *b == 16 * 1024 * 1024),
            "显式 socket 必须按配置值 ×2 计入硬账：{:?}",
            report.hard
        );
        // 显式端点不再进「缺省 socket」上限面（否则同一笔账算两遍）。
        assert!(
            report.caps.iter().all(|(n, _)| !n.starts_with("8 QUIC x")),
            "显式端点不得同时计入缺省上限面：{:?}",
            report.caps
        );
    }

    /// bd 258qt(c)：**缺省** QUIC 端点 socket 只进上限面，不进硬账——否则 5 端点 =
    /// 107.6MiB 会误杀合法配置（Linux `rmem_max` 缺省把 8MiB 钳到几百 KiB）。
    #[test]
    fn default_quic_sockets_are_caps_not_hard() {
        let mut built = xray_conf::BuiltConfig::default();
        for i in 0..5 {
            built.inbounds.push(quic_inbound(&format!("q{i}")));
        }
        let report = budget_report(&built).expect("report");
        assert!(
            report.is_ok(),
            "5 个缺省 QUIC 端点必须过门（bd 258qt(c)）：{:?}",
            report.violations
        );
        assert!(
            report
                .caps
                .iter()
                .any(|(n, b)| n.starts_with("5 QUIC x") && *b == 5 * 16 * 1024 * 1024),
            "上限面必须列出 5 × 16MiB：{:?}",
            report.caps
        );
        assert!(
            report.hard.iter().filter(|(n, _)| n == "explicit udp sockets").all(|(_, b)| *b == 0),
            "缺省 socket 不得进硬账（账面必须为 0，缺省端点只进上限面）：{:?}",
            report.hard
        );
        // 「96MiB 不是运行期硬上界」必须在摘要里明说（bd pyka7）。
        assert!(
            report.summary().contains("NOT a runtime hard bound"),
            "摘要必须显式声明口径：{}",
            report.summary()
        );
    }

    /// bd 258qt(a)：握手在途**每监听一份**（64 × 55KiB）⇒ 监听多到一定量 + 满额
    /// pipe 会吃掉预算的大头（旧簿按进程记 1 份 × 6KiB，7 监听真额 24MiB 只记 384KiB）。
    ///
    /// bd sfqlu 起这类「装不下完整最小并发」**不再拒启**：降档到装得下的条数并
    /// warn（用户拍板：「预算不足不得直接拒启」）。拒启只剩「连 1 条都装不下」。
    #[test]
    fn many_listeners_with_max_pipe_degrades_conns() {
        let mut built = built_with_policy(r#"{"levels": {"0": {"bufferSize": 4096}}}"#);
        for i in 0..7 {
            built.inbounds.push(splithttp_inbound(&format!("xhttp-in-{i}")));
        }
        let plan = plan_96mb();
        let report = budget_report_with(&built, plan).expect("report");
        assert!(
            report.is_ok(),
            "7 监听 × 4MiB pipe 在 96MB 档只降档不拒启（bd sfqlu）：{:?}",
            report.violations
        );
        let degraded = report.degraded.as_deref().unwrap_or_default();
        assert!(degraded.contains("内存降档运行"), "必须出降档 warn 文案：{degraded:?}");
        assert!(degraded.contains("7 "), "warn 必须点名监听数带来的固定面：{degraded}");
        assert!(
            report.projected <= report.budget,
            "降档后账面必须收在预算内：{} > {}",
            report.projected,
            report.budget
        );
        assert!(
            report.hard.iter().any(|(n, _)| n.contains("pipe(2-way)")),
            "硬账必须点名 pipe 双向口径：{:?}",
            report.hard
        );
    }

    /// 同拓扑（1 QUIC 入站 + 1 xhttp 出站）+ 缺省 pipe：固定 ~19MiB + 端点账面
    /// ~32MiB + 8 × 1MiB pipe ≈ 60MiB ≤ 96MiB ⇒ 过门（防扩面门误伤常规配置）。
    #[test]
    fn gate_accepts_same_topology_within_budget() {
        let mut built = xray_conf::BuiltConfig::default();
        built.inbounds.push(quic_inbound("quic-in"));
        built.outbounds.push(xhttp_outbound("xhttp-out"));
        check_startup_budget(&built).expect("同拓扑缺省 pipe 必须过门");
    }

    /// **真机回归（bd sgdwm，176 生产配置）**：7 个 xhttp 入站 + 缺省 pipe 必须过门。
    /// h2 `send_buf` 是**每连接发送缓冲上限**（仅背压时分配，装配期零连接 ⇒ 真实占用 0），
    /// 若按 listener × 16MiB 预约会算出 120MiB，把合法生产配置**拒启**——
    /// 该形态由 2026-11-07 部署 176 时实际触发（服务起不来，自动回滚）。
    #[test]
    fn many_xhttp_inbounds_do_not_book_h2_cap_per_listener() {
        let mut built = xray_conf::BuiltConfig::default();
        for i in 0..7 {
            built.inbounds.push(splithttp_inbound(&format!("xhttp-in-{i}")));
        }
        check_startup_budget(&built)
            .expect("7 个 xhttp 入站（h2 上限登记不入账）必须过门（176 生产配置回归，bd sgdwm）");
    }

    /// 端点扫描两栏归属（bd 258qt(c)）：2 QUIC + 1 xhttp 走**上限面**（不判），
    /// 4MiB pipe 只动硬账（2 监听 × 握手 + 8 连接 × pipe）。
    #[test]
    fn occupancy_scan_counts_inbound_and_outbound_endpoints() {
        let mut built = xray_conf::BuiltConfig::default();
        built.inbounds.push(quic_inbound("q1"));
        built.inbounds.push(quic_inbound("q2"));
        built.outbounds.push(xhttp_outbound("x1"));
        let report = budget_report(&built).expect("report");
        check_startup_budget(&built).expect("3 端点 + 缺省 pipe 必须过门");
        // 上限面逐项可见（错误文案/日志共用同一 summary）。
        let summary = report.summary();
        assert!(summary.contains("2 QUIC"), "上限面必须点名 QUIC 端点数：{summary}");
        assert!(summary.contains("1 xhttp"), "上限面必须点名 xhttp 端点数：{summary}");
        // 抬到 4MiB pipe：2 监听固定底数（~27MiB）+ 64MiB pipe 仍 < 96MiB ⇒ 过门
        // （pipe 是唯一硬账里的连接面，端点不再是硬账项）。
        built.apps.push(BuiltEntry {
            kind: "policy".into(),
            data: br#"{"levels": {"0": {"bufferSize": 4096}}}"#.to_vec(),
        });
        let report = budget_report(&built).expect("report");
        assert_eq!(report.hard.iter().map(|(_, b)| b).sum::<usize>(), report.projected);
        assert!(
            report
                .hard
                .iter()
                .any(|(n, b)| n.contains("conns x")
                    && *b == MIN_VIABLE_CONCURRENCY * 8 * 1024 * 1024),
            "4MiB pipe 双向必须进硬账：{:?}",
            report.hard
        );
    }

    // ── 登记簿交叉断言（bd sgdwm：从实现处导入对照，改实现值即红）──

    /// 握手在途上限与 gate 实现**同一常量**（bd sgdwm 修正 PM-04 漂移：旧簿 128
    /// vs 实现 64，现簿直接从实现导入）。
    #[test]
    fn handshake_inflight_ledger_matches_gate() {
        assert_eq!(
            HANDSHAKE_INFLIGHT_MAX,
            xray_transport::handshake_gate::MAX_INFLIGHT_HANDSHAKES,
            "握手在途上限与本登记簿不一致：两处同步改（bd sgdwm/PM-04）"
        );
    }

    /// DNS pending 条数闸与 xray-app-dns 实现**同一常量**（bd sgdwm 修正旧簿
    /// 「512KiB 字节」口径错位——实现是 512 条）。
    #[test]
    fn dns_pending_ledger_matches_udp_cap() {
        assert_eq!(
            DNS_PENDING_MAX_ENTRIES,
            xray_app_dns::nameserver::udp::MAX_PENDING_QUERIES,
            "DNS pending 条数上界与本登记簿不一致：两处同步改（bd sgdwm）"
        );
    }

    /// DNS 缓存条数与 xray-app-dns 实现**同一常量**（既有断言，bd azcoe）。
    #[test]
    fn dns_cache_ledger_matches_landed_constant() {
        assert_eq!(
            xray_app_dns::cache_controller::MAX_CACHE_ENTRIES,
            DNS_CACHE_MAX_ENTRIES,
            "xray-app-dns 缓存上界与本登记簿不一致：两处同步改（bd azcoe）"
        );
    }

    /// TLS session cache 条数与 xray-tls 实现**同一常量**（bd sgdwm：实现常量
    /// 已转 pub，旧「私有 const 无法断言」作废）。
    #[test]
    fn tls_session_cache_ledger_matches_impl() {
        assert_eq!(
            TLS_SESSION_CACHE_MAX_ENTRIES,
            xray_tls::tls_session_cache::TLS_SESSION_CACHE_CAPACITY,
            "TLS session cache 条数上界与本登记簿不一致：两处同步改（bd sgdwm）"
        );
    }

    /// xray-buf 分层池进程级预算与实现**同一常量**（bd sgdwm/PM-04「宪法破」的
    /// 主体：8MiB 单列分账）；thread_local 单线程配额 128KiB 一并钉（PM-07
    /// 公式口径的成员）。
    #[test]
    fn xray_buf_pool_ledger_matches_impl() {
        assert_eq!(
            XRAY_BUF_POOL_TOTAL_MAX_BYTES,
            xray_buf::alloc::POOL_BYTE_BUDGET,
            "xray-buf 池进程级预算与本登记簿不一致：两处同步改（bd sgdwm）"
        );
        assert_eq!(xray_buf::alloc::TLS_BYTE_BUDGET, 128 * 1024, "PM-07 公式成员");
    }

    /// splithttp 进程级共享块池与实现**同一常量**（bd sgdwm：pub(super)→pub
    /// 仅可见性，值不动）。
    #[test]
    fn splithttp_block_pool_ledger_matches_impl() {
        assert_eq!(
            SPLITHTTP_SHARED_BLOCK_POOL_MAX_BYTES,
            xray_transport_splithttp::pool_stream::POOL_BYTE_BUDGET,
            "splithttp 块池预算与本登记簿不一致：两处同步改（bd sgdwm）"
        );
    }

    /// hysteria udphop 进程级共享块池与实现**同一算式**（bd ccy5d）：
    /// 簿值 = `POOL_IDLE_CAP`（48 块）× `UDP_BUFFER_SIZE`（4096B，Go `finalmask.UDPSize`）
    /// = 196_608B（bd qetcn 块尺寸 1500→4096 后同额收敛）。
    /// **改任一实现值即红**（块数或块大小变了 ⇒ 账本与 96MB 分账必须同步重审）。
    /// 同时钉「总实算」口径：固定面（含本项）+ 8 连接 × pipe 双向的既有总账
    /// 测试（`ledger_total_stays_within_budget`；u440m 字节闸回退后桥在途为
    /// 登记项不进乘积）随底数抬升自动复算，仍 ≤ 96 MiB。
    #[test]
    fn hysteria_udphop_pool_ledger_matches_impl() {
        use xray_transport_hysteria::udphop as hop;
        assert_eq!(
            HYSTERIA_UDPHOP_SHARED_POOL_MAX_BYTES,
            hop::POOL_IDLE_CAP * hop::UDP_BUFFER_SIZE,
            "hysteria 共享块池预算与本登记簿不一致：两处同步改（bd ccy5d）"
        );
        assert_eq!(HYSTERIA_UDPHOP_SHARED_POOL_MAX_BYTES, 196_608, "48 块 × 4096B 口径锚");
    }

    /// hyper 每 host 空闲**连接数**与实现**同一常量**（bd sgdwm 修正 PM-04：
    /// 旧簿 2MiB 字节口径错位，实现闸是 hyper-util `pool_max_idle_per_host`）。
    #[test]
    fn hyper_idle_ledger_matches_conn_count() {
        assert_eq!(
            HYPER_MAX_IDLE_PER_HOST_CONNECTIONS,
            xray_transport_splithttp::client::MAX_IDLE_PER_HOST,
            "hyper 每 host 空闲连接数与本登记簿不一致：两处同步改（bd sgdwm）"
        );
    }

    /// h2 发送缓冲（真缓冲）与 splithttp 客户端/服务端实现**逐端同一常量**
    /// （客户端 16MiB；服务端按内存档位 8/16/32MiB——映射唯一源见
    /// [`xray_transport::h2_window::h2_server_max_send_buf_for`]；bd sgdwm/PM-05 入簿）；
    /// SETTINGS 流窗/连窗（信用计数器）一并钉住防回档——非内存账面，不计入预算门算式。
    #[test]
    fn h2_send_buf_and_flow_window_ledger_matches_impl() {
        use xray_transport_splithttp::transport as st;
        assert_eq!(
            H2_MAX_SEND_BUF_PER_CONN_BYTES,
            st::H2_MAX_SEND_BUF_SIZE,
            "h2 客户端每连接发送缓冲与本登记簿不一致（bd sgdwm/PM-05）"
        );
        assert_eq!(
            SPLITHTTP_H2_CLIENT_FLOW_WINDOW_BYTES,
            st::H2_INITIAL_STREAM_WINDOW,
            "客户端流窗回档即红（bd wz2b/c9oc）"
        );
        assert_eq!(
            SPLITHTTP_H2_CLIENT_FLOW_WINDOW_BYTES,
            st::H2_INITIAL_CONNECTION_WINDOW,
            "客户端连窗不得低于流窗（bd c9oc F-A）"
        );
        assert_eq!(
            SPLITHTTP_H2_SERVER_STREAM_WINDOW_BYTES,
            st::H2_SERVER_INITIAL_STREAM_WINDOW,
            "服务端流窗 16MiB（bd rjzw2：不得偷抬到客户端 32MiB）"
        );
        assert_eq!(
            SPLITHTTP_H2_CLIENT_FLOW_WINDOW_BYTES,
            st::H2_SERVER_INITIAL_CONNECTION_WINDOW,
            "服务端连窗 32MiB"
        );
        assert_eq!(H2_MAX_SEND_BUF_PER_CONN_BYTES, 16 * 1024 * 1024);
    }

    /// 服务端 h2 send_buf 按**内存档位**三档取值：tiny 8MiB / small 16MiB /
    /// medium/large 32MiB（32MiB 对齐客户端收窗；32MiB 是上限非预约，真实在途 = BDP）。
    /// 四档全断言，禁写字面量散落（期望值由常量派生）。
    #[test]
    fn h2_server_send_buf_follows_memory_tier() {
        use xray_frame::budget::plan::MemoryTier;
        let (tiny, small, large) = (
            xray_transport::h2_window::H2_SERVER_SEND_BUF_TINY_TIER,
            xray_transport::h2_window::H2_SERVER_SEND_BUF_SMALL_TIER,
            xray_transport::h2_window::H2_SERVER_MAX_SEND_BUF_SIZE,
        );
        assert_eq!(tiny, 8 * 1024 * 1024, "tiny 档 8MiB（≤256MB 机器不赌大缓冲）");
        assert_eq!(small, H2_MAX_SEND_BUF_PER_CONN_BYTES, "small 档 = 客户端收窗档 16MiB");
        // 档位单调递增（tiny < small < medium|large）。
        assert!(tiny < small && small < large, "档位 send_buf 必须随档位单调递增");
        for (tier, expect) in [
            (MemoryTier::Tiny, tiny),
            (MemoryTier::Small, small),
            (MemoryTier::Medium, large),
            (MemoryTier::Large, large),
        ] {
            assert_eq!(
                xray_transport::h2_window::h2_server_max_send_buf_for(tier),
                expect,
                "{} 档 send_buf",
                tier.as_str()
            );
            // splithttp 侧（xray-transport-splithttp re-export）同一函数同一值。
            assert_eq!(
                xray_transport_splithttp::transport::h2_server_max_send_buf_for(tier),
                expect,
                "{} 档 send_buf：transport re-export 与唯一映射源不一致",
                tier.as_str()
            );
            // caps 账面 = 档位 send_buf + 空闲连接池余量（打印值随档位变）。
            assert_eq!(
                xhttp_conn_booked_bytes(tier),
                expect + HYPER_MAX_IDLE_PER_HOST_CONNECTIONS * HYPER_IDLE_CONN_EST_BYTES,
                "{} 档 xhttp 每连接账面",
                tier.as_str()
            );
        }
        // 服务端不得低于客户端（下载在飞上限 = min(两端)，低于客户端即自钉）——唯 tiny 档
        // 例外：该档按 8MiB 保守取值（2026-11-13 用户拍板）。
        for tier in [MemoryTier::Medium, MemoryTier::Large] {
            assert!(
                xray_transport::h2_window::h2_server_max_send_buf_for(tier)
                    >= H2_MAX_SEND_BUF_PER_CONN_BYTES,
                "{} 档服务端 send_buf 低于客户端 16MiB",
                tier.as_str()
            );
        }
    }

    /// ws（tungstenite）每连接缓冲与实现**同一构造**（bd sgdwm：读+写 = 64KiB，
    /// bd i37bz 收窄后的口径）。
    #[test]
    fn ws_buffer_ledger_matches_impl() {
        let ws = xray_transport_websocket::config::ws_config();
        assert_eq!(
            ws.read_buffer_size + ws.write_buffer_size,
            WS_PER_CONN_BUFFER_BOOKED_BYTES,
            "ws 每连接帧缓冲账面与本登记簿不一致：两处同步改（bd sgdwm）"
        );
    }

    /// DoH3 会话 socket 账面与 QUIC 端点**同源**（doh3.rs dial 走
    /// bind_udp_endpoint 缺省 8MiB 下限 ×2 内核记账；会话按端点复用，bd 0x4tl）。
    #[test]
    fn doh3_session_socket_ledger_derives_from_quic_booked() {
        assert_eq!(
            DOH3_SESSION_SOCKET_BOOKED_BYTES, QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES,
            "DoH3 会话 socket 账面必须与 QUIC 端点同源（同一 8MiB 下限）"
        );
    }

    /// QUIC/UDP 缺省接收缓冲与 sockopt 侧 parity 下限**同一常量**（bd lidaf ①）：
    /// 缺省行为不动（8 MiB 是 Go quic-go wrapConn parity），只要求两处不漂移。
    #[test]
    fn quic_udp_default_buffer_ledger_matches_sockopt_parity() {
        use xray_transport::sockopt;
        assert_eq!(
            sockopt::QUIC_UDP_MIN_BUFFER,
            QUIC_UDP_DEFAULT_RECV_BUFFER_BYTES,
            "QUIC/UDP 缺省接收缓冲与本登记簿不一致（bd lidaf ①）"
        );
        // 账面口径 = 设定值 × 内核 2× 记账（Windows 无 rmem_max 钳制时真占这么多）。
        assert_eq!(
            QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES,
            QUIC_UDP_DEFAULT_RECV_BUFFER_BYTES * SOCKET_KERNEL_BOOKKEEPING_FACTOR,
            "账面口径必须等于设定值 × 内核记账倍数"
        );
        assert_eq!(SOCKET_KERNEL_BOOKKEEPING_FACTOR, 2, "内核 SO_RCVBUF 记账恒 2×（§96-98）");
    }

    /// socket 显式缓冲上限与 transport 机制面**同一常量**（bd u91se ④）：
    /// 改 transport 闸而不同步登记簿 ⇒ 96 MB 分账失真。
    #[test]
    fn socket_buffer_ledger_matches_transport_gate() {
        use xray_transport::sockopt;
        assert_eq!(
            sockopt::MAX_EXPLICIT_RECEIVE_BUFFER_SIZE,
            MAX_EXPLICIT_SOCKET_BUFFER_BYTES,
            "transport TCP 显式接收缓冲上限与本登记簿不一致（bd u91se ④）"
        );
        // pipe 与 socket 同口径：同一笔 4 MiB 每连接份额（不重复计账）。
        assert_eq!(
            usize::try_from(MAX_PER_CONN_BUFFER_BYTES).expect("4 MiB 恒正"),
            MAX_EXPLICIT_SOCKET_BUFFER_BYTES,
            "socket 显式上限必须与 pipe 每连接份额同口径（4 MiB）"
        );
        // UDP 显式值走同一 4 MiB 免确认档（Trans2：check_explicit_udp_buffer_size）；
        // 其硬顶是 64 MiB 防手滑线，与 TCP 硬顶同源。
        assert_eq!(
            sockopt::SO_RCVBUF_FREE_TIER_MAX,
            MAX_EXPLICIT_SOCKET_BUFFER_BYTES,
            "UDP 显式值免确认档必须与登记簿同值"
        );
        assert_eq!(
            sockopt::MAX_EXPLICIT_UDP_BUFFER_SIZE,
            sockopt::SO_RCVBUF_HARD_MAX,
            "UDP 显式值硬顶必须与 TCP 硬顶同源"
        );
    }

    /// 小池档条款（bd sgdwm 重写 + bd 258qt(a) 再收口）：**进程级**小池/缓存三成员
    /// 合计必须 ≤ 4MiB。握手在途是**每监听**在途任务（64 × 55KiB/监听，随监听数
    /// 线性），随固定底数分账，不入本档（否则单监听就 3.4MiB，两监听必然破 4MiB）。
    #[test]
    fn small_pool_bucket_fits_new_pools_clause() {
        let bucket = DNS_PENDING_EST_BYTES
            + TLS_SESSION_CACHE_ESTIMATE_BYTES
            + HYPER_MAX_IDLE_PER_HOST_CONNECTIONS * HYPER_IDLE_CONN_EST_BYTES;
        assert!(
            bucket <= NEW_POOLS_TOTAL_MAX_BYTES,
            "小池档合计 {bucket}B 超出 NEW_POOLS 档 {}B：条款或成员须同步改（bd sgdwm）",
            NEW_POOLS_TOTAL_MAX_BYTES
        );
    }

    /// 握手在途单任务账面**不得低于**实现侧实测斜率（bd 258qt(a)：
    /// `handshake_gate` 的 `MAX_INFLIGHT_HANDSHAKES` doc 记 54,975B/连接；旧簿写
    /// 6KiB 低 9×）。改实现斜率或改本值须两处同步。
    #[test]
    fn handshake_task_est_matches_impl_measurement() {
        const MEASURED_SLOPE: usize = 54_975;
        // 两个都是常量 ⇒ 用编译期断言（clippy::assertions_on_constants：运行期 assert 对
        // 常量无意义，且编译期就能拦住不一致）。
        const _: () = assert!(
            HANDSHAKE_TASK_EST_BYTES >= MEASURED_SLOPE,
            "握手单任务账面低于实现侧实测斜率：账面必须取实测算术上沿（bd 258qt(a)）"
        );
        const _: () =
            assert!(HANDSHAKE_TASK_EST_BYTES == 55 * 1024, "账面口径 = 实测取整上沿 55KiB");
    }

    /// 固定占用底数 ≤ 预算的固定份额（**8 核 / 1 监听参考机** = 23,724,032B
    /// ≈ 22.6MiB；本断言防固定面悄悄长穿预算的 1/4 —— 超过即须重审分账，不是
    /// 硬顶）。thread_local 项随核数线性、握手项随监听数线性（bd 258qt(a)），
    /// 两者都显式注入 ⇒ 换机器断言不漂移（铁律①）。
    #[test]
    fn fixed_floor_stays_within_quarter_of_budget() {
        let fixed = startup_fixed_floor_bytes_for_with_inflight(8, 1, HANDSHAKE_INFLIGHT_MAX);
        assert_eq!(
            fixed, 23_724_032,
            "8 核/1 监听参考机固定底数变了：成员或估算须重审（bd sgdwm；bd ccy5d 起 \
             含 hysteria 共享块池（bd qetcn 起 48 × 4096B = 196_608B）；bd 258qt(a) 起握手按 \
             55KiB × 监听数）"
        );
        assert!(
            fixed <= XRAY_BUDGET_BYTES / 4,
            "装配期固定占用 {fixed}B 超过预算 1/4（{}B）：池/缓存面须重审（bd sgdwm）",
            XRAY_BUDGET_BYTES / 4
        );
    }

    /// 桥在途登记簿与**条目闸口径**一致（u440m 字节闸回退后）。
    ///
    /// 算式（登记簿 doc 同源）：每方向 mpsc `xray_transport::bridge::PIPE_BUF_CAP`
    /// 条 + 读/写腿手上各 1 = 66 条 × 单条顶格 512KiB × 双方向 = 66 MiB。
    /// 条目因子**从实现常量推导**（D-05：禁簿值自证字面量）——改 PIPE_BUF_CAP
    /// 不改登记簿即红；腿形态/单条顶格口径变更仍须同步改本断言与登记簿 doc。
    /// 行为面另由 `crates/xray-transport/tests/bridge_backpressure_entry_cap.rs`
    /// 钉住（拉取数 65..66）。
    ///
    /// 回退记录（bd u440m）：曾断言 `BRIDGE_BYTE_GATE_PER_DIRECTION_BOOKED_BYTES
    /// == bridge::BRIDGE_BYTE_GATE_PER_DIRECTION_BYTES == 2MiB`（字节闸交叉断言）
    /// 与「桥每连接份额 = pipe 4MiB 同份额不重复计账」——字节闸因高 RTT binding
    /// 回退（RTT 161.6ms ⇒ BDP 2.39–3.56MB > 2MiB ⇒ 闸上限 ≈12.9MB/s，A/B 中位
    /// 比 0.939 −6.1% 超票面 5% 门），两断言随之删除：闸没了，登记它 = 造假。
    #[test]
    fn bridge_backpressure_ledger_matches_impl() {
        // 66 = PIPE_BUF_CAP(64) + 读/写腿手上各 1；512KiB 为单条顶格（readv 8×64KiB
        // / pipe 缺省 connection buffer，见 bridge.rs 背压闸口径注释）
        let entries_per_direction = xray_transport::bridge::PIPE_BUF_CAP + 2;
        assert_eq!(
            BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES,
            entries_per_direction * 512 * 1024 * 2,
            "桥在途满载上界（条目闸口径 N 条 × 512KiB × 双方向）与登记簿不一致：\
             两处同步改（bd u440m 回退后口径；N 从 PIPE_BUF_CAP 推导）"
        );
        // 回退后与 pipe 每连接份额（4MiB）**不再相等**——防「同份额不重复计账」
        // 的旧断言悄悄复活（字节闸已删，桥上界是条目闸口径的独立登记项）。
        assert_ne!(
            BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES,
            usize::try_from(MAX_PER_CONN_BUFFER_BYTES).expect("4 MiB 恒正"),
            "字节闸已回退：桥上界不得再断言 = pipe 4MiB 份额（bd u440m）"
        );
    }

    /// xdns 分片重组器最坏堆账面与实现**同一算式**（bd wpa3o-b）：
    /// 改 frag 任一上限（FRAG_SIZE / FRAG_COUNT / FragEntry 布局）即红——
    /// 账面必须随实现重算，禁单边改。
    #[test]
    fn xdns_frag_ledger_matches_impl() {
        use xray_transport::finalmask::xdns::frag;
        assert_eq!(
            frag::WORST_CASE_BYTES,
            XDNS_FRAG_WORST_CASE_BYTES,
            "xdns 分片重组器最坏堆账面与本登记簿不一致：两处同步改（bd wpa3o-b）"
        );
        // 总实算：固定底数（8 核参考机）+ frag 最坏 ≤ 96MiB。超限即红
        // （票面纪律：超了停下报 PM，禁自行缩 frag 上限或放宽总额）。
        let total = startup_fixed_floor_bytes_for_with_inflight(8, 1, HANDSHAKE_INFLIGHT_MAX)
            + XDNS_FRAG_WORST_CASE_BYTES;
        assert!(
            total <= XRAY_BUDGET_BYTES,
            "frag 入簿后总实算 {total}B 超预算 {}B：停下报 PM 重裁（bd wpa3o-b）",
            XRAY_BUDGET_BYTES
        );
    }

    /// 登记簿**总实算** ≤ 96 MiB：固定面 + 最小并发 × pipe 双向不超总预算
    /// （bd sgdwm/wpa3o-b/u440m 口径延续）。pipe 按 env 缺省档折算
    /// （`BufferPolicy::default().connection`，**字节口径**——check_startup_budget
    /// 的 env 档同源）；8 核参考机（铁律①）。
    ///
    /// **桥在途不进乘积**（u440m 回退后口径）：桥上界是满载瞬态（装配期不可
    /// 判定），只登记不保证（同 xdns frag 口径）——回退前字节闸时代曾以
    /// `+ BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES`（4MiB）入乘积；回退后上界
    /// = 66MiB（条目闸口径，见登记簿 doc 回退记录），继续入乘积 = 造假
    /// （8 × (pipe + 66MiB) ≫ 96MiB，而瞬态本就不该按常驻算）。
    ///
    /// **UDP 会话常驻面进乘积**（bd rmbby）：读缓冲是建会话即占的真常驻
    /// （不是 duplex 那种惰性上界），满 4096 条 = 32MiB 必须在 96MiB 里装得下。
    #[test]
    fn ledger_total_stays_within_budget() {
        let pipe_bytes =
            i64::from(xray_features::policy::BufferPolicy::default().connection).max(0);
        let pipe_per_conn = (pipe_bytes * 2) as usize; // 双方向
        let udp_sessions = MAX_UDP_SESSIONS * UDP_SESSION_RESIDENT_BYTES;
        let total = startup_fixed_floor_bytes_for_with_inflight(8, 1, HANDSHAKE_INFLIGHT_MAX)
            + MIN_VIABLE_CONCURRENCY * pipe_per_conn
            + udp_sessions;
        assert!(
            total <= XRAY_BUDGET_BYTES,
            "总实算 {total}B（固定面 + {} 连接 × pipe 双向 {pipe_per_conn}B + \
             {MAX_UDP_SESSIONS} UDP 会话 × {UDP_SESSION_RESIDENT_BYTES}B）超预算 {}B：\
             分账须重审，禁自行放宽总额",
            MIN_VIABLE_CONCURRENCY,
            XRAY_BUDGET_BYTES
        );
    }

    // ── bd rmbby：UDP dispatch 会话面（三项验收）──

    /// 从两栏取 UDP 会话账面 `(常驻, 最坏上界)`。
    fn udp_session_columns(report: &BudgetReport) -> (usize, usize) {
        let resident = report
            .hard
            .iter()
            .find(|(n, _)| n.contains("udp dispatch sessions"))
            .map(|(_, b)| *b)
            .expect("hard 栏必须登记 UDP 会话常驻面");
        let worst = report
            .caps
            .iter()
            .find(|(n, _)| n.contains("udp dispatch sessions"))
            .map(|(_, b)| *b)
            .expect("caps 栏必须登记 UDP 会话最坏上界");
        (resident, worst)
    }

    /// ① 小内存档（40MiB）过订 ⇒ 会话上限降档 + WARN 一次；账面自洽、不拒启。
    ///
    /// 旧状 `MAX_UDP_SESSIONS=4096` 跨档恒定 ⇒ 40MiB 档把 32MiB 常驻读缓冲
    /// （还没算 duplex）静默吃进预算外。
    #[test]
    fn udp_sessions_degrade_on_tiny_tier() {
        let report =
            budget_report_with(&xray_conf::BuiltConfig::default(), plan_256mb()).expect("report");
        assert!(report.is_ok(), "会话降档不得拒启：{:?}", report.violations);
        let (resident, worst) = udp_session_columns(&report);
        let cap = resident / UDP_SESSION_RESIDENT_BYTES;
        assert!(cap < MAX_UDP_SESSIONS, "40MiB 档装不下 {MAX_UDP_SESSIONS} 条：实得 {cap}");
        assert!(cap >= 1, "至少留 1 条会话");
        let degraded = report.degraded.as_deref().unwrap_or_default();
        assert!(
            degraded.contains(&format!("UDP dispatch 会话上限按预算降为 {cap} 条")),
            "WARN 条数必须等于账面条数 {cap}（禁只写文案不改账面）：{degraded}"
        );
        assert_eq!(
            worst,
            cap * UDP_SESSION_WORST_CASE_BYTES,
            "caps 栏最坏上界 = 条数 × 单会话上界（duplex 不反解条数）"
        );
        assert!(
            report.projected <= report.budget,
            "常驻面必须收在预算内：{} > {}",
            report.projected,
            report.budget
        );
    }

    /// ② 常态档位（96MiB 起）保持实现硬顶且**不告警**——防告警退化成噪音，
    /// 也防「按最坏上界反解」把并发砍到 ~180 条（D-01 同款教训）。
    #[test]
    fn udp_sessions_intact_on_small_and_larger_tiers() {
        for available in [512 * MIB, 1024 * MIB] {
            let plan = xray_frame::budget::plan::MemoryPlan::from_available(available);
            let report =
                budget_report_with(&xray_conf::BuiltConfig::default(), plan).expect("report");
            assert!(report.is_ok(), "{available}B 档不得拒启：{:?}", report.violations);
            let (resident, worst) = udp_session_columns(&report);
            assert_eq!(
                resident / UDP_SESSION_RESIDENT_BYTES,
                MAX_UDP_SESSIONS,
                "{available}B 档会话上限必须保持实现硬顶（并发不回退）"
            );
            assert_eq!(worst, MAX_UDP_SESSIONS * UDP_SESSION_WORST_CASE_BYTES);
            let degraded = report.degraded.as_deref().unwrap_or_default();
            assert!(
                !degraded.contains("UDP dispatch"),
                "{available}B 档装得下 ⇒ 不得出 UDP 告警：{degraded}"
            );
        }
    }

    /// ③ 三联口径自洽（四档全扫）：单会话上界 = 常驻 + 双向 duplex；
    /// 账面 = 条数 × 对应上界；常驻面收在预算内；最坏上界只进 caps。
    // 打印三联表（取证须落数字，同 q1r4q 先例：显式 allow + 理由）。
    #[allow(clippy::print_stdout)]
    #[test]
    fn udp_session_ledger_is_self_consistent_across_tiers() {
        assert_eq!(UDP_SESSION_RESIDENT_BYTES, 8 * 1024, "常驻口径锚 = 池化读缓冲 8KiB");
        assert_eq!(
            UDP_SESSION_WORST_CASE_BYTES,
            UDP_SESSION_RESIDENT_BYTES + 2 * 256 * 1024,
            "单会话最坏上界 = 8KiB 常驻 + 双向 256KiB duplex（改实现常量即红）"
        );
        for available in [256 * MIB, 512 * MIB, 1024 * MIB, 16 * 1024 * MIB] {
            let plan = xray_frame::budget::plan::MemoryPlan::from_available(available);
            let report =
                budget_report_with(&xray_conf::BuiltConfig::default(), plan).expect("report");
            let (resident, worst) = udp_session_columns(&report);
            let cap = resident / UDP_SESSION_RESIDENT_BYTES;
            assert!((1..=MAX_UDP_SESSIONS).contains(&cap), "{available}B 档条数越界：{cap}");
            assert_eq!(
                worst / UDP_SESSION_WORST_CASE_BYTES,
                cap,
                "{available}B 档 caps 栏与 hard 栏条数必须同源"
            );
            assert!(
                report.projected <= report.budget,
                "{available}B 档账面超预算：{} > {}",
                report.projected,
                report.budget
            );
            println!(
                "{} 档（预算 {}B）：上限 {cap} 条 / 常驻 {resident}B / 最坏 {worst}B",
                report.tier, report.budget
            );
        }
    }
}
