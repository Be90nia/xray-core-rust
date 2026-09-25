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

use std::time::{Duration, Instant};

use clap::Parser;
use xray_stress::{quic_loop, report::StatsHandle, sampler::Sampler, scenarios as sc, topology};

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

fn main() -> anyhow::Result<()> {
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
) -> anyhow::Result<()> {
    let deadline = Instant::now() + duration;
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
        for h in sh.into_iter().chain(ch) {
            infra.spawn(async move {
                let _ = h.await;
            });
        }
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
        for h in sh.into_iter().chain(ch) {
            infra.spawn(async move {
                let _ = h.await;
            });
        }
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
        for h in sh.into_iter().chain(ch) {
            infra.spawn(async move {
                let _ = h.await;
            });
        }
        // 60s 预算：覆盖 QUIC 系握手失败浮现（quinn 对端拒接经 idle timeout ~30s）
        tokio::time::timeout(
            Duration::from_secs(60),
            topology::probe_socks_roundtrip(port, echo_port),
        )
        .await
        .map_err(|_| anyhow::anyhow!("{name} link probe timeout (60s)"))??;
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
    for (sc, port) in protocol_links {
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
    let mut sampler = Sampler::new(&run_id, &args.out_dir, stats, Duration::from_secs(21_600))?;
    let label = format!("scenarios={scenarios:?}");
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let elapsed = duration.as_secs_f64() - (deadline - Instant::now()).as_secs_f64();
        if let Err(e) = sampler.sample_once(elapsed, interval, false) {
            eprintln!("[xray-stress] sampler error: {e}");
        }
        match sampler.maybe_checkpoint(duration, args.leak_threshold, &label) {
            Ok(true) => println!("[xray-stress] checkpoint written"),
            Ok(false) => {},
            Err(e) => eprintln!("[xray-stress] checkpoint error: {e}"),
        }
        if Instant::now() >= deadline {
            break;
        }
    }

    // --- 收尾：停负载（在途 roundtrip 落地），infra 保留供 drain 观察窗 ---
    let stop = tokio::time::timeout(Duration::from_secs(30), async {
        while load.join_next().await.is_some() {}
    });
    if stop.await.is_err() {
        println!("[xray-stress] load stop timeout, aborting workers");
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
        let drain_end = Instant::now() + Duration::from_secs(args.drain_secs);
        let load_end = Instant::now();
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let elapsed = duration.as_secs_f64() + load_end.elapsed().as_secs_f64();
            if let Err(e) = sampler.sample_once(elapsed, interval, true) {
                eprintln!("[xray-stress] sampler error: {e}");
            }
            if Instant::now() >= drain_end {
                break;
            }
        }
    }

    let rest = tokio::time::timeout(Duration::from_secs(10), async {
        while infra.join_next().await.is_some() {}
    });
    if rest.await.is_err() {
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
    async fn start_link(self, echo_port: u16) -> anyhow::Result<topology::LinkHandles> {
        match self {
            Scenario::S5 => topology::start_vmess_ws_link(echo_port).await,
            Scenario::S6 => topology::start_trojan_grpc_link(echo_port).await,
            Scenario::S7 => topology::start_ss_link(echo_port).await,
            Scenario::S8 => topology::start_tuic_link(echo_port).await,
            Scenario::S9 => topology::start_anytls_link(echo_port).await,
            Scenario::S10 => topology::start_splithttp_link(echo_port).await,
            Scenario::S11 => topology::start_http_link(echo_port).await,
            Scenario::S12 => topology::start_vmess_h3_link(echo_port).await,
            _ => anyhow::bail!("s1-s4 links are provisioned separately"),
        }
    }

    fn stats_name(self) -> &'static str {
        PROTOCOL_SCENARIOS.iter().find(|(s, _)| *s == self).map(|(_, n)| *n).unwrap_or("unknown")
    }
}

fn parse_scenarios(s: &str) -> anyhow::Result<Vec<Scenario>> {
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
            other => anyhow::bail!("unknown scenario: {other} (expect s1..s12|all)"),
        });
    }
    if out.is_empty() {
        anyhow::bail!("empty --scenarios");
    }
    Ok(out)
}
