//! 装配面内存预算（bd azcoe · 256MB 小鸡口径）。
//!
//! 用户定调（2026-11-04）：整机 256MB（含 kernel/基础系统 ~60MB + 陪跑进程
//! ~40MB），xray 保守按 **96MB** 设计；约束现在写死进代码，不留「以后再调」。
//! 三条铁律（`reports/audit-2026-11-04/MEMORY-BUDGET-256MB.md`）：
//! ① 上界一律显式常量，禁从 sysinfo/系统内存推导（换机器不改代码）；
//! ② 禁预分配大缓冲；
//! ③ 超限 fail-fast 立即拒启/丢弃，禁排队（排队 = 内存与请求数同涨）。
//!
//! 本模块两部分：
//! - [`check_startup_budget`]：**装配期可校验**的预算门，在 `start_full_dispatched` 入口执行（生产
//!   `start_full` 与 framework `start_full_with_outbound_handlers` 两路共用），违例逐条列出并拒启
//!   （对齐 vaye2/o91s4 的启动期硬错纪律）。
//! - 其余 `pub const`：运行时结构配额**登记簿**——执行点在归属 crate/票（见各 常量
//!   doc），登记防漂移；xray-core 装配面只强校验装配期可知项。

/// 整机 256MB 分账后 xray 的保守预算（96MB；留 24MB 给抖动/page cache）。
pub const XRAY_BUDGET_BYTES: usize = 96 * 1024 * 1024;

/// 每连接 pipe 软上限的硬顶（字节）——**装配期强校验项**。
///
/// 依据：pipe limit 是「单连接可排队字节」的软上限（policy buffer，Go
/// `BufferPolicy.Connection`），x86_64 缺省 512KB、aarch64 缺省 4KB（bd 9utc3）。
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
/// [`xray_transport::sockopt::SO_RCVBUF_FREE_TIER_MAX`]）。
pub const MAX_EXPLICIT_SOCKET_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// QUIC/UDP socket **缺省**接收缓冲（字节/连接）= 8 MiB，**行为不动**（登记项）。
///
/// Go quic-go `wrapConn` 的 `DesiredReceiveBufferSize` parity
/// （`internal/protocol/params.go:5-9`，`sys_conn.go:51-53`）：缺省
/// `receiveBufferSize=0` ⇒ [`xray_transport::sockopt::bind_udp_endpoint`] 的
/// `tune_udp_buffer` 只升不降到本值（Linux 再走 `SO_RCVBUFFORCE`，失败只 warn）。
/// 对拍一致优先于本地优化，故本项只登记 + 披露，不改缺省。
///
/// **Windows 无 `net.core.rmem_max` 钳制** ⇒ 每 socket 真 8 MiB，内核记账 ×2
/// ⇒ 按 [`QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES`]（16 MiB/连接）口径。
/// Linux 受 `net.core.rmem_max` 钳制（stock ≈416 KiB 实际账面）⇒ 8 MiB 只在运维
/// 抬过 `rmem_max` 后成立。TCP 路径缺省为 0（不设，交 OS autotune，bd r5j96）。
pub const QUIC_UDP_DEFAULT_RECV_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// socket 缓冲的**内核记账倍数**：`SO_RCVBUF` 设定值 ×2 才等于内核账面字节
/// （设定值的一半是纯开销，同 `docs/guide-highrtt-sockopt.md` §96-98）。
pub const SOCKET_KERNEL_BOOKKEEPING_FACTOR: usize = 2;

/// QUIC/UDP 缺省接收缓冲的**账面**口径（字节/连接）= 8 MiB × 2 = 16 MiB。
///
/// 256 MB 机型判据：QUIC 连接数 × 本值必须落在 [`XRAY_BUDGET_BYTES`] 内
/// （例：32 个 QUIC 连接 ≈ 512 MiB 账面 ⇒ 已超整机预算）。
pub const QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES: usize =
    QUIC_UDP_DEFAULT_RECV_BUFFER_BYTES * SOCKET_KERNEL_BOOKKEEPING_FACTOR;

/// 握手在途任务并发上限（P0-1 accept 解耦后 per-conn 握手任务数）。
///
/// 128 × ~6KB/任务 ≈ 0.75MB ≤ 1MB 配额。**执行点在 ws/httpupgrade accept 接线
/// （P0-1 任务书，transport crate）**；本登记簿供评审对账，防实现漂移。
pub const HANDSHAKE_INFLIGHT_MAX: usize = 128;

/// DNS pending map 字节预算（0.5MB）。执行点：xray-app-dns（bd 9utc3 第 1 项）。
pub const DNS_PENDING_MAX_BYTES: usize = 512 * 1024;

/// DNS 解析缓存条目上界（**已落地**：xray-app-dns `MAX_CACHE_ENTRIES`）。
/// 16384 键 ≈ 4–5MiB：远高于常规解析工作集，且拦住「TTL 窗内唯一域名数 =
/// 内存」的无界增长（Go 同源无界；Rust 侧按预算收口——有界优于逐字节对拍）。
pub const DNS_CACHE_MAX_ENTRIES: usize = 16_384;

/// TLS session cache 条目上界（**已落地**：xray-tls 128 条 LRU + 24h TTL 双界，
/// ≈ ≤2.5MiB）。该常量在 xray-tls 内为私有 const，故只登记不交叉断言。
pub const TLS_SESSION_CACHE_MAX_ENTRIES: usize = 128;

/// finalmask xmc manager 池字节上界（≤4MB）。执行点：finalmask 池接线票。
pub const FINALMASK_XMC_POOL_MAX_BYTES: usize = 4 * 1024 * 1024;

/// hyper 每主机 idle 连接缓冲字节上界（≤2MB）。执行点：xray-transport-splithttp
/// （bd cgmcj）。
pub const HYPER_MAX_IDLE_PER_HOST_BYTES: usize = 2 * 1024 * 1024;

/// 本轮新增池/缓存合计硬顶（4MB）。逐池 byte 上界的分账执行点见上各项 + bd f516k。
pub const NEW_POOLS_TOTAL_MAX_BYTES: usize = 4 * 1024 * 1024;

/// 总盘预留余量下限（整机 256MB 口径运维判据：256 − 系统 ~60 − 陪跑 ~40 −
/// xray ~96 ≈ 60MB，票面判据取 ≥50MB）。上线由 PM 亲核实测 RSS，非代码强校验。
pub const RESERVE_MARGIN_MIN_BYTES: usize = 50 * 1024 * 1024;

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

/// 装配期预算门：校验配置派生的内存面，违例逐条列出（fail-visible 拒启）。
///
/// 当前校验面 = 每连接 pipe 软上限的取值来源：
/// - env 缺省档（`xray.ray.buffer.size` / `XRAY_RAY_BUFFER_SIZE` / `XRAY_BUFSIZE` →
///   `BufferPolicy::default`，level 未配 bufferSize 时的生效值）；
/// - policy app 各 level 的 `bufferSize`（KB 单位；负值 = 无界，Go ×1024 转字节）。
pub fn check_startup_budget(built: &xray_conf::BuiltConfig) -> Result<(), String> {
    let mut violations = Vec::new();

    let env_default = i64::from(xray_features::policy::BufferPolicy::default().connection);
    check_conn_buffer(env_default, "env default buffer", &mut violations);

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
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(format!("memory budget exceeded: {}", violations.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use xray_conf::BuiltEntry;

    use super::*;

    /// 手搓 BuiltConfig（policy app 内联 JSON），供预算门单元测试。
    fn built_with_policy(json: &str) -> xray_conf::BuiltConfig {
        let mut built = xray_conf::BuiltConfig::default();
        built.apps.push(BuiltEntry { kind: "policy".into(), data: json.as_bytes().to_vec() });
        built
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

    /// 登记簿与已落地实现对账：xray-app-dns 缓存上界改动必须同步本登记簿。
    #[test]
    fn dns_cache_ledger_matches_landed_constant() {
        assert_eq!(
            xray_app_dns::cache_controller::MAX_CACHE_ENTRIES,
            DNS_CACHE_MAX_ENTRIES,
            "xray-app-dns 缓存上界与本登记簿不一致：两处同步改（bd azcoe）"
        );
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
}
