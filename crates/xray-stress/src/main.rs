#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr)]
// 压测 harness：stdout 结构化进度行即产品接口（采样/判定报告消费方为脚本）
//! xray-stress：Xray-core-rust 压测 harness 入口。
//!
//! 十二场景矩阵（全部 loopback、真实协议栈）：
//! - s1 短连接风暴：vless+REALITY 链路，连接生命周期内存回环
//! - s2 长连接大流量：同链路持续泵随机数据，稳态吞吐衰减曲线
//! - s3 QUIC 重连循环：hysteria2 0-RTT dial→roundtrip→drop 回环
//! - s4 混合：mKCP（UDP 路径）短连接 + 长连接叠加
//! - s5-s12 协议链扩展：vmess+ws / trojan+grpc / ss+tcp / tuic v5 / anytls / vless+xhttp(auto) /
//!   http 代理 / vmess+xhttp H3（QUIC 承载）， 每场景独立 start_full 双实例，短连接风暴复用 s1
//!   worker 语义
//!
//! 长跑启动命令见 run_stress.ps1 / run_stress.sh（保守/标准/激进三档）。

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use clap::Parser;
use xray_stress::{
    error::{Result, StressError},
    quic_loop,
    report::StatsHandle,
    sampler::{Sampler, checkpoint_interval},
    scenarios as sc, topology,
};

#[derive(Parser, Debug)]
#[command(name = "xray-stress", about = "Xray-core-rust stress harness")]
struct Args {
    /// 运行时长（秒）。
    #[arg(long, default_value_t = 600)]
    duration: u64,
    /// S1 短连接并发档位。
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    /// 场景集，逗号分隔：s1..s12 或 all。
    #[arg(long, default_value = "s1,s2,s3,s4")]
    scenarios: String,
    /// 采样间隔（秒）。
    #[arg(long, default_value_t = 30)]
    sample_interval: u64,
    /// 输出目录（metrics.csv + summary.md）。
    #[arg(long, default_value = "stress-out")]
    out_dir: std::path::PathBuf,
    /// 泄漏判定阈值：RSS 线性增长超过基线的 X %/h 记 SUSPECT。
    #[arg(long, default_value_t = 5.0)]
    leak_threshold: f64,
    /// S2 长连接条数。
    #[arg(long, default_value_t = 4)]
    s2_conns: usize,
    /// S1/S4 短连接每轮间隔（毫秒）。Windows 动态端口预算内建连节流。
    #[arg(long, default_value_t = 150)]
    s1_delay_ms: u64,
    /// 负载停止后的观察窗（秒），0=关。基础设施（服务端实例）保留运行，
    /// 采样行标 `__drain__`：connIdle 300s 固有堆积会回落/企稳，真泄漏不落——
    /// 供 tools/check_stress_leak.py 区分两者。窗口须 > 300s（connIdle）。
    #[arg(long, default_value_t = 0)]
    drain_secs: u64,
}

#[allow(
    clippy::disallowed_methods,
    reason = "压测 run_id 需要真实挂钟（跨进程/跨机对账的唯一键；mock 钟会撞名）；本 crate 是独立 bin，无 ctx.clock() 注入面亦未接 compat::clock → 待压测工具接 Clock 端口后迁"
)]
fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
    topology::ensure_crypto_provider();

    let run_id = format!(
        "stress-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );
    let scenarios = parse_scenarios(&args.scenarios)?;
    let duration = Duration::from_secs(args.duration);
    let interval = Duration::from_secs(args.sample_interval);
    println!(
        "[xray-stress] run={run_id} duration={}s concurrency={} s2_conns={} scenarios={:?} drain={}s out={}",
        args.duration,
        args.concurrency,
        args.s2_conns,
        scenarios,
        args.drain_secs,
        args.out_dir.display()
    );

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(run(args, run_id, scenarios, duration, interval))?;
    runtime.shutdown_timeout(Duration::from_secs(3));
    Ok(())
}

async fn run(
    args: Args,
    run_id: String,
    scenarios: Vec<Scenario>,
    duration: Duration,
    interval: Duration,
) -> Result<()> {
    let failures = Failures::default();
    #[allow(clippy::disallowed_methods, reason = "压测 run 时钟锚点；Clock 端口注入待 bd 39hko")]
    let deadline = Instant::now() + duration;
    // 看门狗兜底（真机 CI 实证：concurrency=32 时 tokio 定时器饿死 ⇒ deadline 永不检查）。
    // grace 120s：留够负载收工（30s）+ 首轮探针的余量。
    #[allow(clippy::disallowed_methods, reason = "压测 run 时钟锚点；Clock 端口注入待 bd 39hko")]
    let watchdog = Watchdog::arm(deadline + Duration::from_secs(120), || {
        println!("[xray-stress] watchdog: run exceeded duration, terminating");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        // 非零退出：挂死 run 必须让 CI 失败（exit(0) 会让后续门禁把挂死读成成功，
        // 压测路径评审 F2）。3 = watchdog 专用码，区别于 load/探针失败。
        std::process::exit(3);
    });
    let mut stats: Vec<StatsHandle> = Vec::new();
    // 负载 worker 与基础设施（协议链服务实例）分池：drain 观察窗停负载、
    // 保留 infra，让服务端 idle 连接按 connIdle 语义自然回收。
    let mut load = tokio::task::JoinSet::new();
    let mut infra = tokio::task::JoinSet::new();

    // --- 拓扑装配（按场景需要起实例） ---
    let echo_port = topology::start_echo().await.port();
    let need_socks_link = scenarios.contains(&Scenario::S1) || scenarios.contains(&Scenario::S2);
    let socks_port = if need_socks_link {
        let (port, sh, ch) = topology::start_reality_link(echo_port).await?;
        spawn_infra(&mut infra, "reality infra", sh.into_iter().chain(ch), &failures);
        topology::probe_socks_roundtrip(port, echo_port).await?;
        println!(
            "[xray-stress] reality link ready: socks=127.0.0.1:{port} echo=127.0.0.1:{echo_port}"
        );
        Some(port)
    } else {
        None
    };
    let kcp_socks_port = if scenarios.contains(&Scenario::S4) {
        let (port, sh, ch) = topology::start_kcp_link(echo_port).await?;
        spawn_infra(&mut infra, "kcp infra", sh.into_iter().chain(ch), &failures);
        topology::probe_socks_roundtrip(port, echo_port).await?;
        println!("[xray-stress] kcp link ready: socks=127.0.0.1:{port}");
        Some(port)
    } else {
        None
    };
    let quic_addr = if scenarios.contains(&Scenario::S3) {
        let addr = quic_loop::start_quic_echo_server().await?;
        println!("[xray-stress] quic echo server ready: udp/{addr}");
        Some(addr)
    } else {
        None
    };

    // s5-s12：每场景独立协议链（表驱动装配 + 首连探针）
    let mut protocol_links: Vec<(Scenario, u16)> = Vec::new();
    for &(sc, name) in PROTOCOL_SCENARIOS {
        if !scenarios.contains(&sc) {
            continue;
        }
        let (port, sh, ch) = sc.start_link(echo_port).await?;
        spawn_infra(&mut infra, name, sh.into_iter().chain(ch), &failures);
        // 60s 预算：覆盖 QUIC 系握手失败浮现（quinn 对端拒接经 idle timeout ~30s）
        tokio::time::timeout(
            Duration::from_secs(60),
            topology::probe_socks_roundtrip(port, echo_port),
        )
        .await
        .map_err(|_| StressError::ProbeTimeout { name: name.to_string() })??;
        println!("[xray-stress] {name} link ready: socks=127.0.0.1:{port}");
        protocol_links.push((sc, port));
    }

    // --- 场景 spawn ---
    if let Some(port) = socks_port {
        if scenarios.contains(&Scenario::S1) {
            let h = StatsHandle::new("s1-short");
            stats.push(h.clone());
            load.spawn(sc::s1_short_burst(
                port,
                echo_port,
                args.concurrency,
                deadline,
                h,
                args.s1_delay_ms,
            ));
        }
        if scenarios.contains(&Scenario::S2) {
            let h = StatsHandle::new("s2-long");
            stats.push(h.clone());
            load.spawn(sc::s2_long_flow(port, echo_port, args.s2_conns, deadline, h));
        }
    }
    if let Some(addr) = quic_addr {
        let h = StatsHandle::new("s3-quic");
        stats.push(h.clone());
        load.spawn(quic_loop::s3_quic_reconnect_loop(addr, deadline, h));
    }
    if let (Some(port), true) = (kcp_socks_port, scenarios.contains(&Scenario::S4)) {
        let h = StatsHandle::new("s4-mixed-kcp");
        stats.push(h.clone());
        let short = (args.concurrency / 4).max(2);
        let long = (args.s2_conns / 2).max(1);
        load.spawn(sc::s4_mixed(port, echo_port, short, long, deadline, h, args.s1_delay_ms));
    }
    for &(sc, port) in &protocol_links {
        let h = StatsHandle::new(sc.stats_name());
        stats.push(h.clone());
        load.spawn(sc::s1_short_burst(
            port,
            echo_port,
            args.concurrency,
            deadline,
            h,
            args.s1_delay_ms,
        ));
    }
    println!("[xray-stress] {} scenario task groups running", stats.len());

    // --- 采样循环 ---
    let mut sampler = Sampler::new(&run_id, &args.out_dir, stats, checkpoint_interval(duration))?;
    let label = format!("scenarios={scenarios:?}");
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        #[allow(
            clippy::disallowed_methods,
            reason = "压测 run 时钟锚点；Clock 端口注入待 bd 39hko"
        )]
        let elapsed = duration.as_secs_f64() - (deadline - Instant::now()).as_secs_f64();
        if let Err(e) = sampler.sample_once(elapsed, interval, false) {
            eprintln!("[xray-stress] sampler error: {e}");
        }
        match sampler.maybe_checkpoint(duration, args.leak_threshold, &label) {
            Ok(true) => println!("[xray-stress] checkpoint written"),
            Ok(false) => {},
            Err(e) => eprintln!("[xray-stress] checkpoint error: {e}"),
        }
        #[allow(
            clippy::disallowed_methods,
            reason = "压测 run 时钟锚点；Clock 端口注入待 bd 39hko"
        )]
        if Instant::now() >= deadline {
            break;
        }
    }

    // --- 收尾：停负载（在途 roundtrip 落地），infra 保留供 drain 观察窗 ---
    // load 任务各自在 deadline 收工；30s 未收工 = 挂死证据（F-9），记失败位而非只打印。
    let stop = tokio::time::timeout(
        Duration::from_secs(30),
        drain_join(&mut load, "load worker", &failures),
    );
    if stop.await.is_err() {
        failures.record("load stop", &"timeout 30s, load workers hung");
        load.abort_all();
    }

    // drain 观察窗：负载已停、服务端实例存活，idle 连接按 connIdle 语义回收。
    // 固有堆积（如 s12 H3 connIdle 300s 窗口）→ RSS 回落/企稳；真泄漏 → 不落。
    // 行标 `__drain__`，由 tools/check_stress_leak.py 判定。
    if args.drain_secs > 0 {
        println!(
            "[xray-stress] drain window: {}s (idle-connection reclaim observation)",
            args.drain_secs
        );
        #[allow(
            clippy::disallowed_methods,
            reason = "压测 drain 观察窗时钟锚点；Clock 端口注入待 bd 39hko"
        )]
        let drain_end = Instant::now() + Duration::from_secs(args.drain_secs);
        // drain 窗自己的兜底：drain_secs + 60s（到点仍不退出 = 同样饿死）
        watchdog.extend_to(drain_end + Duration::from_secs(60));
        #[allow(
            clippy::disallowed_methods,
            reason = "压测 drain 观察窗时钟锚点；Clock 端口注入待 bd 39hko"
        )]
        let load_end = Instant::now();
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let elapsed = duration.as_secs_f64() + load_end.elapsed().as_secs_f64();
            if let Err(e) = sampler.sample_once(elapsed, interval, true) {
                eprintln!("[xray-stress] sampler error: {e}");
            }
            #[allow(
                clippy::disallowed_methods,
                reason = "压测 drain 观察窗时钟锚点；Clock 端口注入待 bd 39hko"
            )]
            if Instant::now() >= drain_end {
                break;
            }
        }
    }

    // --- 结束态功能探针（F-9）：进程退出码只证明没崩，不证明功能还活着。
    // drain 结束后每条已建链路再走一轮真实 roundtrip，任一条失败即整 run 失败。
    let mut links: Vec<(&str, u16)> = Vec::new();
    if let Some(port) = socks_port {
        links.push(("s1-s2-reality", port));
    }
    if let Some(port) = kcp_socks_port {
        links.push(("s4-kcp", port));
    }
    for &(sc, port) in &protocol_links {
        links.push((sc.stats_name(), port));
    }
    // 收尾段兜底：每条链路 30s 探针预算 + 余量（探针自身超时会记账，这里只管不退出的情形）
    #[allow(clippy::disallowed_methods, reason = "压测 run 时钟锚点；Clock 端口注入待 bd 39hko")]
    let probe_budget = Instant::now() + Duration::from_secs(30 * (links.len() as u64 + 2) + 120);
    watchdog.extend_to(probe_budget);
    if let Err(e) = probe_links(&links, echo_port).await {
        failures.record("end-state probe", &e);
    }
    if let Some(addr) = quic_addr {
        match tokio::time::timeout(Duration::from_secs(30), quic_loop::probe_quic_roundtrip(addr))
            .await
        {
            Ok(Ok(())) => println!("[xray-stress] end-state probe ok: s3-quic (udp/{addr})"),
            Ok(Err(e)) => failures.record("end-state probe s3-quic", &e),
            Err(_) => failures.record("end-state probe s3-quic", &"timeout 30s"),
        }
    }

    let rest = tokio::time::timeout(
        Duration::from_secs(10),
        drain_join(&mut infra, "infra task", &failures),
    );
    if rest.await.is_err() {
        // 服务端 serve 任务本就长活，10s 未收工是正常路径（下面 abort 收尾），不算失败。
        println!("[xray-stress] drain timeout, aborting stragglers");
        infra.abort_all();
    }

    let path = sampler.write_final_summary(duration, args.leak_threshold, &label)?;
    let rss = &sampler.samples_rss;
    println!(
        "[xray-stress] done. rss first={:.1}MB last={:.1}MB peak={:.1}MB; samples={}",
        rss.first().map_or(0.0, |s| s.1),
        rss.last().map_or(0.0, |s| s.1),
        rss.iter().map(|s| s.1).fold(f64::MIN, f64::max),
        rss.len(),
    );
    if let Some(v) = xray_stress::report::judge_leak(rss, args.leak_threshold) {
        if v.suspect {
            println!(
                "[xray-stress] WARNING: leak SUSPECT — slope {:.2} MB/h ({:.2} %/h > {:.1} %/h)",
                v.slope_mb_per_h, v.slope_pct_per_h, args.leak_threshold
            );
        }
    }
    println!("[xray-stress] summary: {}", path.display());
    let failed = failures.count();
    if failed > 0 {
        return Err(StressError::RunFailed { count: failed });
    }
    Ok(())
}

/// 任务失败账本（审计 F-26）：infra / 负载任务的 panic、JoinError、收工超时一律
/// 记数与 log，run 结束返回 Err。禁 `let _ = h.await` 式静默吞掉——
/// 那是 5h 长跑最隐蔽的假绿来源。
#[derive(Clone, Default)]
struct Failures(Arc<AtomicU64>);

impl Failures {
    fn record(&self, what: &str, detail: &dyn std::fmt::Display) {
        self.0.fetch_add(1, Ordering::Relaxed);
        tracing::error!("[xray-stress] {what} failed: {detail}");
    }

    fn count(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// infra 任务入池：panic/JoinError 记进失败账本（不再静默停摆）。
fn spawn_infra(
    set: &mut tokio::task::JoinSet<()>,
    label: &'static str,
    handles: impl IntoIterator<Item = tokio::task::JoinHandle<()>>,
    failures: &Failures,
) {
    for h in handles {
        let failures = failures.clone();
        set.spawn(async move {
            if let Err(e) = h.await {
                failures.record(label, &e);
            }
        });
    }
}

/// 收工一组任务，panic/取消一律记进失败账本（F-26）。
async fn drain_join(set: &mut tokio::task::JoinSet<()>, what: &str, failures: &Failures) {
    while let Some(res) = set.join_next().await {
        if let Err(e) = res {
            failures.record(what, &e);
        }
    }
}

/// 看门狗：tokio 定时器被饿死时的唯一退出保证。
///
/// 全速 loopback 负载（如 `--concurrency 32` = 192 worker）会让 tokio worker
/// 永不 park ⇒ timer wheel 不推进 ⇒ `tick.tick().await` / `sleep` / deadline
/// 检查全部失效，run 永不退出（真机 CI 实证：5 平台在 Run stress 后 2h40m+
/// 不退出）。本线程用 `std::thread::sleep`（不依赖 tokio 运行时）兜底。
///
/// 触发目标可延长但不可提前（负载段 → drain 段 → 收尾段）。
struct Watchdog(Arc<parking_lot::Mutex<Instant>>);

impl Watchdog {
    /// 起线程；`on_fire` 在目标到点且未被延长时调用一次。
    #[allow(
        clippy::disallowed_methods,
        reason = "看门狗必须是 OS 线程 + 真实 sleep：tokio 定时器正是被饿死的那个（全速 loopback 下 worker 不 park），走 tokio 就会一起失效"
    )]
    fn arm(target: Instant, on_fire: impl FnOnce() + Send + 'static) -> Self {
        let shared = Arc::new(parking_lot::Mutex::new(target));
        let slot = shared.clone();
        std::thread::spawn(move || {
            loop {
                let now = Instant::now();
                let target = *slot.lock();
                if now >= target {
                    on_fire();
                    return;
                }
                std::thread::sleep(target - now);
            }
        });
        Self(shared)
    }

    /// 把触发点往后推（只允许延长，避免收尾段被提前砍）。
    fn extend_to(&self, target: Instant) {
        let mut cur = self.0.lock();
        if target > *cur {
            *cur = target;
        }
    }
}

/// 结束态探针：每条已建链路各跑一轮真实 SOCKS roundtrip（审计 F-9：
/// 进程活着 ≠ 功能活着，任务级挂死必须判负）。
async fn probe_links(links: &[(&str, u16)], echo_port: u16) -> Result<()> {
    for (name, port) in links {
        tokio::time::timeout(
            Duration::from_secs(30),
            topology::probe_socks_roundtrip(*port, echo_port),
        )
        .await
        .map_err(|_| StressError::Probe(format!("{name} end-state probe timeout (30s)")))??;
        println!("[xray-stress] end-state probe ok: {name} (socks=127.0.0.1:{port})");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Scenario {
    S1,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
    S9,
    S10,
    S11,
    S12,
}

/// s5-s12：每个场景一条独立协议链（短连接风暴 worker 复用 s1 语义）。
const PROTOCOL_SCENARIOS: &[(Scenario, &str)] = &[
    (Scenario::S5, "s5-vmess-ws"),
    (Scenario::S6, "s6-trojan-grpc"),
    (Scenario::S7, "s7-ss-tcp"),
    (Scenario::S8, "s8-tuic"),
    (Scenario::S9, "s9-anytls"),
    (Scenario::S10, "s10-vless-xhttp"),
    (Scenario::S11, "s11-http-proxy"),
    (Scenario::S12, "s12-vmess-h3"),
];

impl Scenario {
    /// s5-s12 → 对应协议链启动器（start_full 双实例）。
    async fn start_link(self, echo_port: u16) -> Result<topology::LinkHandles> {
        match self {
            Scenario::S5 => topology::start_vmess_ws_link(echo_port).await,
            Scenario::S6 => topology::start_trojan_grpc_link(echo_port).await,
            Scenario::S7 => topology::start_ss_link(echo_port).await,
            Scenario::S8 => topology::start_tuic_link(echo_port).await,
            Scenario::S9 => topology::start_anytls_link(echo_port).await,
            Scenario::S10 => topology::start_splithttp_link(echo_port).await,
            Scenario::S11 => topology::start_http_link(echo_port).await,
            Scenario::S12 => topology::start_vmess_h3_link(echo_port).await,
            _ => Err(StressError::Scenario("s1-s4 links are provisioned separately".into())),
        }
    }

    fn stats_name(self) -> &'static str {
        PROTOCOL_SCENARIOS.iter().find(|(s, _)| *s == self).map(|(_, n)| *n).unwrap_or("unknown")
    }
}

fn parse_scenarios(s: &str) -> Result<Vec<Scenario>> {
    let mut out = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        out.push(match part.to_ascii_lowercase().as_str() {
            "s1" => Scenario::S1,
            "s2" => Scenario::S2,
            "s3" => Scenario::S3,
            "s4" => Scenario::S4,
            "s5" => Scenario::S5,
            "s6" => Scenario::S6,
            "s7" => Scenario::S7,
            "s8" => Scenario::S8,
            "s9" => Scenario::S9,
            "s10" => Scenario::S10,
            "s11" => Scenario::S11,
            "s12" => Scenario::S12,
            "all" => {
                return Ok(vec![
                    Scenario::S1,
                    Scenario::S2,
                    Scenario::S3,
                    Scenario::S4,
                    Scenario::S5,
                    Scenario::S6,
                    Scenario::S7,
                    Scenario::S8,
                    Scenario::S9,
                    Scenario::S10,
                    Scenario::S11,
                    Scenario::S12,
                ]);
            },
            other => {
                return Err(StressError::Scenario(format!(
                    "unknown scenario: {other} (expect s1..s12|all)"
                )));
            },
        });
    }
    if out.is_empty() {
        return Err(StressError::Scenario("empty --scenarios".into()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn end_state_probe_fails_on_dead_link() {
        // 已释放端口 = 链路已死（accept 泵停摆 / 进程僵死的最小复现形态）
        let dead = topology::pick_free_port().await;
        let err = probe_links(&[("dead-link", dead)], 9).await.unwrap_err();
        assert!(matches!(err, StressError::Probe(_)), "unexpected: {err:?}");
    }

    #[tokio::test]
    async fn panicked_task_records_failure() {
        // F-26 验收：任务 panic ⇒ JoinError ⇒ 失败账本计数 > 0 ⇒ run 返回 Err(RunFailed)
        let failures = Failures::default();
        let mut set = tokio::task::JoinSet::new();
        set.spawn(async { panic!("boom") });
        drain_join(&mut set, "test task", &failures).await;
        assert_eq!(failures.count(), 1, "panic 必须进失败账本");
    }

    /// 看门狗必须在目标到点后触发（不依赖 tokio 运行时——本测试没有 runtime）。
    #[test]
    #[allow(clippy::disallowed_methods, reason = "测试计时锚点")]
    fn watchdog_fires_after_target() {
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = fired.clone();
        let _wd = Watchdog::arm(Instant::now() + Duration::from_millis(50), move || {
            flag.store(true, Ordering::Relaxed);
        });
        std::thread::sleep(Duration::from_millis(400));
        assert!(fired.load(Ordering::Relaxed), "到点必须触发");
    }

    /// 延长后不得提前触发（drain / 收尾段要靠这条不被砍）。
    #[test]
    #[allow(clippy::disallowed_methods, reason = "测试计时锚点")]
    fn watchdog_extension_defers_fire() {
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = fired.clone();
        let base = Instant::now();
        let wd = Watchdog::arm(base + Duration::from_millis(50), move || {
            flag.store(true, Ordering::Relaxed);
        });
        wd.extend_to(base + Duration::from_millis(500));
        std::thread::sleep(Duration::from_millis(200));
        assert!(!fired.load(Ordering::Relaxed), "延长后不得在旧目标点触发");
        std::thread::sleep(Duration::from_millis(600));
        assert!(fired.load(Ordering::Relaxed), "新目标点必须触发");
    }

    /// 只允许往后退：传更早的目标不得缩短（否则收尾段可能被负载段的旧目标砍掉）。
    #[test]
    #[allow(clippy::disallowed_methods, reason = "测试计时锚点")]
    fn watchdog_extension_never_shortens() {
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = fired.clone();
        let base = Instant::now();
        let wd = Watchdog::arm(base + Duration::from_millis(300), move || {
            flag.store(true, Ordering::Relaxed);
        });
        wd.extend_to(base + Duration::from_millis(10));
        std::thread::sleep(Duration::from_millis(150));
        assert!(!fired.load(Ordering::Relaxed), "更早的目标不得提前触发");
    }
}
