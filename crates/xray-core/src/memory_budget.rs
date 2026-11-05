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
}
