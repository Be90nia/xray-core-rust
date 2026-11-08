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
//! 3. 上限面（不判、只打印）：QUIC 缺省 socket（Linux `rmem_max` 钳制 ⇒ 按 16MiB
//!    预约会误杀合法配置）、xhttp h2 send_buf（每连接、惰性分配）、DoH3 resolver
//!    socket（装配期不可数）、桥在途、xdns frag（同 bridge 口径：登记 ≠ 入账）。
//!
//! **内存自适应（bd sfqlu，2026-11-07 用户拍板）**：总预算不再钉 96MB，改由
//! `xray_common::mem_probe::MemoryPlan` 按**探测到的可用内存**分档派生——
//! ≤256MB→40MB / ≤512MB→96MB / ≤1GB→192MB / >1GB→`min(512MB, 可用/4)`。同一份
//! 派生值同时给出桥每方向字节闸与**连接数上限**（`总预算 / 3MiB`，触顶由桥
//! fail-visible 拒绝）。预算装不下时**不拒启**：按装得下的并发数降档并 warn
//! （只有连 1 条连接都装不下才拒）。96MB 仍是 `min` 上沿的默认设计点，故原
//! 「96MiB 不是运行期硬上界」口径不变。

// 登记簿常量单一事实源 = `xray_frame::budget`（ADR-B 拆分）；此处只转出，不复制。
pub use xray_frame::budget::{
    BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES, DNS_CACHE_ESTIMATE_BYTES, DNS_CACHE_MAX_ENTRIES,
    DNS_PENDING_EST_BYTES, DNS_PENDING_MAX_ENTRIES, DNS_SINGLEFLIGHT_UNBOUNDED_NOTE,
    DOH3_SESSION_SOCKET_BOOKED_BYTES, FINALMASK_XMC_POOL_MAX_BYTES, H2_MAX_SEND_BUF_PER_CONN_BYTES,
    HANDSHAKE_INFLIGHT_MAX, HANDSHAKE_TASK_EST_BYTES, HYPER_IDLE_CONN_EST_BYTES,
    HYPER_MAX_IDLE_PER_HOST_CONNECTIONS, HYSTERIA_UDPHOP_SHARED_POOL_MAX_BYTES,
    MAX_EXPLICIT_SOCKET_BUFFER_BYTES, MAX_PER_CONN_BUFFER_BYTES, MIN_VIABLE_CONCURRENCY,
    NEW_POOLS_TOTAL_MAX_BYTES, QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES,
    QUIC_UDP_DEFAULT_RECV_BUFFER_BYTES, RESERVE_MARGIN_MIN_BYTES, SOCKET_KERNEL_BOOKKEEPING_FACTOR,
    SPLITHTTP_ENDPOINT_BOOKED_BYTES, SPLITHTTP_H2_CLIENT_FLOW_WINDOW_BYTES,
    SPLITHTTP_H2_SERVER_STREAM_WINDOW_BYTES, SPLITHTTP_SHARED_BLOCK_POOL_MAX_BYTES,
    TLS_SESSION_CACHE_ESTIMATE_BYTES, TLS_SESSION_CACHE_MAX_ENTRIES,
    WS_PER_CONN_BUFFER_BOOKED_BYTES, XDNS_FRAG_WORST_CASE_BYTES, XRAY_BUDGET_BYTES,
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
///   [`projected`](Self::projected) 判定）。
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

/// 装配期预算门：产出两栏报告（违例见 [`BudgetReport::violations`]）。
///
/// 校验面（bd sgdwm 扩面 + bd 258qt 口径修正 + bd sfqlu 档位自适应）：
/// 1. 每连接 pipe 软上限（env 缺省档 + policy 各 level `bufferSize`；负值硬拒、 0 放行）；
/// 2. **硬账**：固定底数（池/缓存 + **每监听**握手在途，bd 258qt(a)）+ 最小并发 × pipe 双向 +
///    **显式** `sockopt.receiveBufferSize` 的 UDP 端点账面 （×2 内核记账，bd nlhht）；
/// 3. **上限面**（不判、只报）：QUIC 缺省 socket（Linux `rmem_max` 钳制 ⇒ 按 16MiB
///    预约会误杀合法配置，bd 258qt(c)）、DoH3 resolver socket（装配期不可数， bd 258qt(d)）、xhttp
///    h2 send_buf（惰性分配，bd pyka7）、桥在途、xdns frag。
///
/// 预算取自本机档位（[`xray_common::mem_probe::MemoryPlan::cached`]）；装不下
/// 完整并发时只**降档**（[`BudgetReport::degraded`]），连 1 条都装不下才记违例。
///
/// # 错误
/// `policy` 配置 JSON 坏 → `Err`；违例 → [`BudgetReport::violations`] 非空。
pub fn budget_report(built: &xray_conf::BuiltConfig) -> Result<BudgetReport, String> {
    budget_report_with(built, *xray_common::mem_probe::MemoryPlan::cached())
}

/// 同 [`budget_report`]，档位计划由调用方注入（单测按档位钉行为）。
pub fn budget_report_with(
    built: &xray_conf::BuiltConfig,
    plan: xray_common::mem_probe::MemoryPlan,
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
    let mut splithttp = 0usize;
    let stream_settings = built
        .inbounds
        .iter()
        .map(|i| i.stream_settings_json.as_ref())
        .chain(built.outbounds.iter().map(|o| o.stream_settings_json.as_ref()));
    for ss in stream_settings {
        match stream_network(ss) {
            Some(xray_common::net::transport::TransportProtocol::Quic) => {
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
    let projected = fixed + quic_explicit_booked + conns * per_conn_pipe;
    // 运行期连接数上限 = 档位派生值与本配置实际装得下的条数取小。
    let max_conns = plan.max_conns.min(conns_fit);
    if conns_fit == 0 {
        violations.push(format!(
            "actual occupancy {projected}B > budget {budget}B even for 1 conn: fixed {fixed}B \
             (pools+caches + {listeners} listeners x {HANDSHAKE_INFLIGHT_MAX} x \
             {HANDSHAKE_TASK_EST_BYTES}B handshake) + explicit udp sockets \
             {quic_explicit_booked}B + 1 conn x {per_conn_pipe}B pipe(2-way); \
             tier {} (bd sfqlu)",
            plan.tier.as_str(),
        ));
    }
    // 装不下完整并发 ⇒ 降档运行（**不拒启**）：显式告警，让运维看得见少了多少条。
    let degraded = (conns_fit > 0
        && (conns < MIN_VIABLE_CONCURRENCY || max_conns < plan.max_conns))
        .then(|| {
            format!(
                "内存降档运行（bd sfqlu）：档位 {}（{}，可用 {}B，来源 {}）总预算 {budget}B，\
                 固定面 {fixed}B（{listeners} 个监听）+ 显式 socket {quic_explicit_booked}B 后\
                 每连接 {per_conn_pipe}B pipe（双向）只装得下 {conns_fit} 条连接\
                 （最小可跑 {} 条 / 档位上限 {} 条）⇒ 本配置连接数上限降为 {max_conns} 条，不拒启",
                plan.tier.as_str(),
                plan.tier.label(),
                plan.available,
                plan.source,
                MIN_VIABLE_CONCURRENCY,
                plan.max_conns,
            )
        });

    // ── 4) 上限面（打印用；不进 projected）──
    let caps = vec![
        (
            format!(
                "{quic_default} QUIC x {QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES}B default socket"
            ),
            quic_default * QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES,
        ),
        (
            format!(
                "{splithttp} xhttp x {SPLITHTTP_ENDPOINT_BOOKED_BYTES}B per-conn h2 send_buf cap"
            ),
            splithttp * SPLITHTTP_ENDPOINT_BOOKED_BYTES,
        ),
        (
            format!("per DoH3 resolver {DOH3_SESSION_SOCKET_BOOKED_BYTES}B socket"),
            DOH3_SESSION_SOCKET_BOOKED_BYTES,
        ),
        (
            format!("per conn bridge in-flight {BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES}B cap"),
            BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES,
        ),
        (
            format!("per xdns server {XDNS_FRAG_WORST_CASE_BYTES}B frag worst case"),
            XDNS_FRAG_WORST_CASE_BYTES,
        ),
        // bd sfqlu：档位派生值全部进上限面（运维核对用，不进硬账）。
        (
            format!("bridge byte gate {}B/dir x 2 dirs per conn", plan.bridge_gate),
            2 * plan.bridge_gate,
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
        ],
        caps,
        degraded,
        violations,
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
    check_startup_budget_with(built, *xray_common::mem_probe::MemoryPlan::cached())
}

/// 同 [`check_startup_budget`]，档位计划由调用方注入（单测按档位钉行为）。
fn check_startup_budget_with(
    built: &xray_conf::BuiltConfig,
    plan: xray_common::mem_probe::MemoryPlan,
) -> Result<(), String> {
    let report = budget_report_with(built, plan)?;
    if !report.is_ok() {
        return Err(format!("memory budget exceeded: {}", report.violations.join("; ")));
    }
    let log = xray_frame::logging::LogFacade::new("memory_budget", Vec::new());
    log.info(report.summary());
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
    fn plan_96mb() -> xray_common::mem_probe::MemoryPlan {
        xray_common::mem_probe::MemoryPlan::from_available(512 * MIB)
    }

    /// 256MB 小鸡档（40MB 预算）。
    fn plan_256mb() -> xray_common::mem_probe::MemoryPlan {
        xray_common::mem_probe::MemoryPlan::from_available(256 * MIB)
    }

    /// 四档（256MB / 512MB / 1GB / 大机器）派生出的预算与连接数上限必须与档位表一致，
    /// 且派生值全部出现在报告的 caps 栏里（bd sfqlu 验收 5）。
    #[test]
    fn tier_plan_drives_budget_and_conn_cap() {
        for (available, budget, conns) in [
            (256 * MIB, 40 * MIB, 13usize),
            (512 * MIB, 96 * MIB, 32),
            (1024 * MIB, 192 * MIB, 64),
            (16 * 1024 * MIB, 512 * MIB, 170),
        ] {
            let plan = xray_common::mem_probe::MemoryPlan::from_available(available);
            let report =
                budget_report_with(&xray_conf::BuiltConfig::default(), plan).expect("report");
            assert_eq!(report.budget, budget as usize, "{available}B 档总预算");
            assert_eq!(report.max_conns, conns, "{available}B 档连接数上限");
            assert!(report.is_ok(), "{available}B 档缺省配置必须过门：{:?}", report.violations);
            let summary = report.summary();
            assert!(summary.contains(&format!("{budget}B")), "摘要必须带总预算：{summary}");
            assert!(
                report.caps.iter().any(|(n, _)| n.starts_with(&format!("max {conns} conns"))),
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
    /// 簿值 = `POOL_IDLE_CAP`（128 块）× `UDP_BUFFER_SIZE`（1500B）= 192_000B。
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
        assert_eq!(HYSTERIA_UDPHOP_SHARED_POOL_MAX_BYTES, 192_000, "128 块 × 1500B 口径锚");
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

    /// h2 发送缓冲（真缓冲）与 splithttp 客户端/服务端实现**同一常量**
    /// （bd sgdwm/PM-05 入簿）；SETTINGS 流窗/连窗（信用计数器）一并钉住防回档
    /// ——非内存账面，不计入预算门算式。
    #[test]
    fn h2_send_buf_and_flow_window_ledger_matches_impl() {
        use xray_transport_splithttp::transport as st;
        assert_eq!(
            H2_MAX_SEND_BUF_PER_CONN_BYTES,
            st::H2_MAX_SEND_BUF_SIZE,
            "h2 客户端每连接发送缓冲与本登记簿不一致（bd sgdwm/PM-05）"
        );
        assert_eq!(
            st::H2_SERVER_MAX_SEND_BUF_SIZE,
            st::H2_MAX_SEND_BUF_SIZE,
            "服务端 h2 发送缓冲必须与客户端同值（16MiB）"
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

    /// 固定占用底数 ≤ 预算的固定份额（**8 核 / 1 监听参考机** = 23,719,424B
    /// ≈ 22.6MiB；本断言防固定面悄悄长穿预算的 1/4 —— 超过即须重审分账，不是
    /// 硬顶）。thread_local 项随核数线性、握手项随监听数线性（bd 258qt(a)），
    /// 两者都显式注入 ⇒ 换机器断言不漂移（铁律①）。
    #[test]
    fn fixed_floor_stays_within_quarter_of_budget() {
        let fixed = startup_fixed_floor_bytes_for_with_inflight(8, 1, HANDSHAKE_INFLIGHT_MAX);
        assert_eq!(
            fixed, 23_719_424,
            "8 核/1 监听参考机固定底数变了：成员或估算须重审（bd sgdwm；bd ccy5d 起 \
             含 hysteria 共享块池 192_000B；bd 258qt(a) 起握手按 55KiB × 监听数）"
        );
        assert!(
            fixed <= XRAY_BUDGET_BYTES / 4,
            "装配期固定占用 {fixed}B 超过预算 1/4（{}B）：池/缓存面须重审（bd sgdwm）",
            XRAY_BUDGET_BYTES / 4
        );
    }

    /// 桥在途登记簿与**条目闸口径**一致（u440m 字节闸回退后）。
    ///
    /// 算式（登记簿 doc 同源）：每方向 mpsc 64 条 + 读/写腿手上各 1 = 66 条 ×
    /// 单条顶格 512KiB × 双方向 = 66 MiB。改任一因子（条目容量/腿形态/口径）
    /// 须同步改本断言与登记簿 doc，否则红——行为面另由
    /// `crates/xray-transport/tests/bridge_backpressure_entry_cap.rs` 钉住
    /// （拉取数 65..66）。
    ///
    /// 回退记录（bd u440m）：曾断言 `BRIDGE_BYTE_GATE_PER_DIRECTION_BOOKED_BYTES
    /// == bridge::BRIDGE_BYTE_GATE_PER_DIRECTION_BYTES == 2MiB`（字节闸交叉断言）
    /// 与「桥每连接份额 = pipe 4MiB 同份额不重复计账」——字节闸因高 RTT binding
    /// 回退（RTT 161.6ms ⇒ BDP 2.39–3.56MB > 2MiB ⇒ 闸上限 ≈12.9MB/s，A/B 中位
    /// 比 0.939 −6.1% 超票面 5% 门），两断言随之删除：闸没了，登记它 = 造假。
    #[test]
    fn bridge_backpressure_ledger_matches_impl() {
        assert_eq!(
            BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES,
            66 * 512 * 1024 * 2,
            "桥在途满载上界（条目闸口径 66 条 × 512KiB × 双方向）与登记簿不一致：\
             两处同步改（bd u440m 回退后口径）"
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
    #[test]
    fn ledger_total_stays_within_budget() {
        let pipe_bytes =
            i64::from(xray_features::policy::BufferPolicy::default().connection).max(0);
        let pipe_per_conn = (pipe_bytes * 2) as usize; // 双方向
        let total = startup_fixed_floor_bytes_for_with_inflight(8, 1, HANDSHAKE_INFLIGHT_MAX)
            + MIN_VIABLE_CONCURRENCY * pipe_per_conn;
        assert!(
            total <= XRAY_BUDGET_BYTES,
            "总实算 {total}B（固定面 + {} 连接 × pipe 双向 {pipe_per_conn}B）超预算 {}B：\
             分账须重审，禁自行放宽总额",
            MIN_VIABLE_CONCURRENCY,
            XRAY_BUDGET_BYTES
        );
    }
}
