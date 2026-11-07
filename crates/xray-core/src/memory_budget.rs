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
//! （对齐 vaye2/o91s4 的启动期硬错纪律）。校验面（bd sgdwm 扩面）：
//! 1. 配置派生值：env 缺省档 + policy 各 level `bufferSize`（KB；负值 = 无界 ⇒ 硬拒，Go 同源坑
//!    audit4-memory F8；本仓装配期硬拒负值 ⇒ 96MB 门下不存在「Go 同源
//!    无界」活口，**无界一律硬拒零豁免**；0 = Go 合法「limit 0 不排队」，必须放行）；
//! 2. 实际占用面：进程级池/缓存固定占用（[`startup_fixed_floor_bytes`]）、QUIC 每 listener 的 UDP
//!    socket 接收缓冲（bind 即真实分配）、预算内最小并发乘以每连接 pipe 占用——配置合法但 合计超
//!    [`XRAY_BUDGET_BYTES`] 同样拒启。 xhttp 的 h2 send_buf
//!    是**每连接发送缓冲上限**（仅背压时分配，装配期 0 占用），按 「上限 ≠
//!    预约」统一口径**登记不入账**（同 bridge 在途 / xdns frag / DNS singleflight）； 真机依据见
//!    `check_startup_budget` 内注释（bd sgdwm）。

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
    XRAY_BUF_POOL_TOTAL_MAX_BYTES, startup_fixed_floor_bytes, startup_fixed_floor_bytes_for,
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

/// 装配期预算门：校验「配置派生值 + 实际占用面」，违例逐条列出（fail-visible 拒启）。
///
/// 校验面（bd sgdwm 扩面后）：
/// 1. 每连接 pipe 软上限的取值来源：env 缺省档（`xray.ray.buffer.size` / `XRAY_RAY_BUFFER_SIZE` /
///    `XRAY_BUFSIZE` → `BufferPolicy::default`，level 未配 bufferSize 时的生效值）+ policy app 各
///    level 的 `bufferSize`（KB 单位； 负值 = 无界硬拒；0 = Go 合法「不排队」放行）。
/// 2. 实际占用面：[`startup_fixed_floor_bytes`]（进程级池/缓存）加上 QUIC 每 listener 的 UDP socket
///    接收缓冲（扫 inbounds/outbounds 的 streamSettings transport 名；bind 即真实分配）， 再加
///    [`MIN_VIABLE_CONCURRENCY`] × 最大 pipe 档 × 2 方向，合计超 [`XRAY_BUDGET_BYTES`]
///    即拒——「配置合法但实际占用超预算」的组合同样过不了门。
///
/// **xhttp 的 h2 send_buf 登记不入账（bd sgdwm 真机暴露）**：它是**每连接发送缓冲上限**，
/// 只在背压时按需分配，装配期零连接 ⇒ 真实占用 0。若按 listener × 16MiB 预约，176 生产配置
/// （7 个 xhttp 入站）会算出 120MiB 而**拒绝启动合法配置**；故按「上限 ≠ 预约」统一口径
/// （同 bridge 在途 / xdns frag / DNS singleflight）只登记并在错误文案中点名，不计入实算。
///
/// **桥在途不入门（jcnjb③ 决策，登记≠入账口径）**：桥在途上界登记在
/// [`BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES`]（条目闸口径 66MiB/连接缺省档；
/// u440m 字节闸曾钉 4MiB，真机 A/B 中位比 0.939 −6.1% 超票面 5% 门已回退——
/// 与 pipe 的 4MiB 每连接份额**不再是同一份额**，登记簿 doc 有回退记录），
/// 但它是**满载瞬态**（写端堵塞 + 读端持续产的瞬态形态，装配期零连接 ⇒ 占用 0，
/// 连接数本身装配期不可判定）⇒ 不并入「连接数 × 档位」扫描，也不进总实算
/// 断言乘积（同 xdns frag 口径）；总实算（固定面 + 8 连接 × pipe 双向 ≤ 96MiB）
/// 钉在 tests `ledger_total_stays_within_budget`——份额常量漂移即红。
pub fn check_startup_budget(built: &xray_conf::BuiltConfig) -> Result<(), String> {
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

    // ── 2) 实际占用面（bd sgdwm 扩面）──
    let mut quic_endpoints = 0usize;
    let mut splithttp_endpoints = 0usize;
    let stream_settings = built
        .inbounds
        .iter()
        .map(|i| i.stream_settings_json.as_ref())
        .chain(built.outbounds.iter().map(|o| o.stream_settings_json.as_ref()));
    for ss in stream_settings {
        match stream_network(ss) {
            Some(xray_common::net::transport::TransportProtocol::Quic) => quic_endpoints += 1,
            Some(xray_common::net::transport::TransportProtocol::SplitHttp) => {
                splithttp_endpoints += 1;
            },
            _ => {},
        }
    }

    let fixed = startup_fixed_floor_bytes();
    // QUIC 的 UDP socket 接收缓冲是**每 listener 的真实分配**（bind 即占，内核含 2× 记账）⇒ 入账。
    let endpoint_booked = quic_endpoints * QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES;
    // h2 send_buf（xhttp）是**每连接的发送缓冲上限**，只在背压时按需分配，装配期零连接 ⇒ 0 占用。
    // 按「上限 ≠ 预约」统一口径（同 bridge 在途 / xdns frag / DNS singleflight）**登记不入账**。
    // 真机依据（bd sgdwm）：176 生产配置有 7 个 xhttp 入站，若按 listener × 16MiB 预约会算出
    // 120MiB ⇒ 合法配置被拒启；而实际常驻远低于该上限。端点与容量仍在错误文案中点名。
    let registered_only = splithttp_endpoints * SPLITHTTP_ENDPOINT_BOOKED_BYTES;
    // 每连接 pipe 占用按两方向计（上/下行各一条 policy pipe，见 MAX_PER_CONN_BUFFER_BYTES doc）。
    let per_conn_pipe = max_pipe_bytes * 2;
    // 桥在途不入门：满载瞬态（装配期零连接，连接数不可判定；jcnjb③；总实算
    // 钉在 tests ledger_total_stays_within_budget）。条目闸口径上界见登记簿
    // BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES（u440m 字节闸已回退）。
    let projected = fixed + endpoint_booked + MIN_VIABLE_CONCURRENCY * per_conn_pipe;
    if projected > XRAY_BUDGET_BYTES {
        violations.push(format!(
            "actual occupancy {projected}B > budget {}B: fixed {fixed}B (pools+caches) \
             + endpoints {endpoint_booked}B ({quic_endpoints} QUIC x {}B socket booked) \
             + {MIN_VIABLE_CONCURRENCY} conns x {per_conn_pipe}B pipe(2-way) \
             [registered-only, not summed: {splithttp_endpoints} xhttp x {SPLITHTTP_ENDPOINT_BOOKED_BYTES}B \
             = {registered_only}B h2 send_buf cap — allocated only under backpressure]",
            XRAY_BUDGET_BYTES, QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES,
        ));
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(format!("memory budget exceeded: {}", violations.join("; ")))
    }
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

    /// 「配置合法但实际占用超预算」必须拒（bd sgdwm 验收 3）：
    /// bufferSize 4MiB 是上界本身（合法），1 个 QUIC 端点 + 8 条满额 pipe 双向
    /// 的占用面合计 > 96MiB ⇒ 扩面门必须点名算式拒启。
    #[test]
    fn gate_rejects_legal_config_whose_occupancy_exceeds_budget() {
        let mut built = built_with_policy(r#"{"levels": {"0": {"bufferSize": 4096}}}"#);
        built.inbounds.push(quic_inbound("quic-in"));
        let err =
            check_startup_budget(&built).expect_err("配置合法但占用超预算必须拒（bd sgdwm 扩面）");
        assert!(err.contains("actual occupancy"), "错误必须带占用算式：{err}");
        assert!(err.contains("1 QUIC"), "错误必须点名 QUIC 端点数：{err}");
        assert!(err.contains("pipe(2-way)"), "错误必须点名 pipe 双向口径：{err}");
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

    /// 扩面门取「最大显式 level」做 pipe 底数：显式 4MiB 比缺省 512KiB 大 ⇒
    /// 可行性算式按 4MiB（与上条拒例同一算式路径，防只按 env 缺省漏算）。
    #[test]
    fn occupancy_scan_counts_inbound_and_outbound_endpoints() {
        let mut built = xray_conf::BuiltConfig::default();
        built.inbounds.push(quic_inbound("q1"));
        built.inbounds.push(quic_inbound("q2"));
        built.outbounds.push(xhttp_outbound("x1"));
        // 3 端点账面 = 2×16MiB + 1×(16MiB+400KiB)；缺省 pipe 下合计 < 96MiB。
        check_startup_budget(&built).expect("3 端点 + 缺省 pipe 必须过门");
        // 抬到 4MiB pipe ⇒ 可行性破线，错误里 QUIC=2、xhttp=1 逐一可见。
        built.apps.push(BuiltEntry {
            kind: "policy".into(),
            data: br#"{"levels": {"0": {"bufferSize": 4096}}}"#.to_vec(),
        });
        let err = check_startup_budget(&built).expect_err("4MiB pipe + 3 端点必须破线");
        assert!(err.contains("2 QUIC"), "{err}");
        assert!(err.contains("1 xhttp"), "{err}");
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

    /// 小池档条款（bd sgdwm 重写后的 NEW_POOLS 语义）：四成员合计必须 ≤ 4MiB。
    /// 大池（xray-buf/splithttp）与 DNS 缓存、finalmask xmc 池单列分账，不入本档。
    #[test]
    fn small_pool_bucket_fits_new_pools_clause() {
        let bucket = HANDSHAKE_INFLIGHT_MAX * HANDSHAKE_TASK_EST_BYTES
            + DNS_PENDING_EST_BYTES
            + TLS_SESSION_CACHE_ESTIMATE_BYTES
            + HYPER_MAX_IDLE_PER_HOST_CONNECTIONS * HYPER_IDLE_CONN_EST_BYTES;
        assert!(
            bucket <= NEW_POOLS_TOTAL_MAX_BYTES,
            "小池档合计 {bucket}B 超出 NEW_POOLS 档 {}B：条款或成员须同步改（bd sgdwm）",
            NEW_POOLS_TOTAL_MAX_BYTES
        );
    }

    /// 固定占用底数 ≤ 预算的固定份额（**按 8 核参考机折算** ~19.6MiB；本断言防
    /// 固定面悄悄长穿预算的 1/4 —— 超过即须重审分账，不是硬顶；thread_local
    /// 项随核数线性，换机器断言不漂移，铁律①）。
    #[test]
    fn fixed_floor_stays_within_quarter_of_budget() {
        let fixed = startup_fixed_floor_bytes_for(8);
        assert_eq!(
            fixed, 20_508_160,
            "8 核参考机固定底数变了：成员或估算须重审（bd sgdwm；bd ccy5d 起 \
             含 hysteria 共享块池 192_000B）"
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
        let total = startup_fixed_floor_bytes_for(8) + XDNS_FRAG_WORST_CASE_BYTES;
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
        let total = startup_fixed_floor_bytes_for(8) + MIN_VIABLE_CONCURRENCY * pipe_per_conn;
        assert!(
            total <= XRAY_BUDGET_BYTES,
            "总实算 {total}B（固定面 + {} 连接 × pipe 双向 {pipe_per_conn}B）超预算 {}B：\
             分账须重审，禁自行放宽总额",
            MIN_VIABLE_CONCURRENCY,
            XRAY_BUDGET_BYTES
        );
    }
}
