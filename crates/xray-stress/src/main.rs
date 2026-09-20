//! xray-stress：Xray-core-rust 压测 harness 入口。
//!
//! 四场景矩阵（全部 loopback、真实协议栈）：
//! - s1 短连接风暴：vless+REALITY 链路，连接生命周期内存回环
//! - s2 长连接大流量：同链路持续泵随机数据，稳态吞吐衰减曲线
//! - s3 QUIC 重连循环：hysteria2 0-RTT dial→roundtrip→drop 回环
//! - s4 混合：mKCP（UDP 路径）短连接 + 长连接叠加
//!
//! 长跑启动命令见 run_stress.ps1 / run_stress.sh（保守/标准/激进三档）。

use std::time::{Duration, Instant};

use clap::Parser;
use xray_stress::quic_loop;
use xray_stress::report::StatsHandle;
use xray_stress::sampler::Sampler;
use xray_stress::scenarios as sc;
use xray_stress::topology;

#[derive(Parser, Debug)]
#[command(name = "xray-stress", about = "Xray-core-rust stress harness")]
struct Args {
    /// 运行时长（秒）。
    #[arg(long, default_value_t = 600)]
    duration: u64,
    /// S1 短连接并发档位。
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    /// 场景集，逗号分隔：s1,s2,s3,s4 或 all。
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
        "[xray-stress] run={run_id} duration={}s concurrency={} s2_conns={} scenarios={:?} out={}",
        args.duration,
        args.concurrency,
        args.s2_conns,
        scenarios,
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
    let mut tasks = tokio::task::JoinSet::new();

    // --- 拓扑装配（按场景需要起实例） ---
    let echo_port = topology::start_echo().await.port();
    let need_socks_link = scenarios.contains(&Scenario::S1) || scenarios.contains(&Scenario::S2);
    let socks_port = if need_socks_link {
        let (port, sh, ch) = topology::start_reality_link(echo_port).await?;
        for h in sh.into_iter().chain(ch) {
            tasks.spawn(async move {
                let _ = h.await;
            });
        }
        topology::probe_socks_roundtrip(port, echo_port).await?;
        println!("[xray-stress] reality link ready: socks=127.0.0.1:{port} echo=127.0.0.1:{echo_port}");
        Some(port)
    } else {
        None
    };
    let kcp_socks_port = if scenarios.contains(&Scenario::S4) {
        let (port, sh, ch) = topology::start_kcp_link(echo_port).await?;
        for h in sh.into_iter().chain(ch) {
            tasks.spawn(async move {
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

    // --- 场景 spawn ---
    if let Some(port) = socks_port {
        if scenarios.contains(&Scenario::S1) {
            let h = StatsHandle::new("s1-short");
            stats.push(h.clone());
            tasks.spawn(sc::s1_short_burst(
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
            tasks.spawn(sc::s2_long_flow(port, echo_port, args.s2_conns, deadline, h));
        }
    }
    if let Some(addr) = quic_addr {
        let h = StatsHandle::new("s3-quic");
        stats.push(h.clone());
        tasks.spawn(quic_loop::s3_quic_reconnect_loop(addr, deadline, h));
    }
    if let (Some(port), true) = (kcp_socks_port, scenarios.contains(&Scenario::S4)) {
        let h = StatsHandle::new("s4-mixed-kcp");
        stats.push(h.clone());
        let short = (args.concurrency / 4).max(2);
        let long = (args.s2_conns / 2).max(1);
        tasks.spawn(sc::s4_mixed(
            port,
            echo_port,
            short,
            long,
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
        if let Err(e) = sampler.sample_once(elapsed, interval) {
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

    // --- 收尾：等在途 roundtrip 落地，超时强杀 ---
    let drain = tokio::time::timeout(Duration::from_secs(10), async {
        while tasks.join_next().await.is_some() {}
    });
    if drain.await.is_err() {
        println!("[xray-stress] drain timeout, aborting stragglers");
        tasks.abort_all();
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
}

fn parse_scenarios(s: &str) -> anyhow::Result<Vec<Scenario>> {
    let mut out = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        out.push(match part.to_ascii_lowercase().as_str() {
            "s1" => Scenario::S1,
            "s2" => Scenario::S2,
            "s3" => Scenario::S3,
            "s4" => Scenario::S4,
            "all" => return Ok(vec![Scenario::S1, Scenario::S2, Scenario::S3, Scenario::S4]),
            other => anyhow::bail!("unknown scenario: {other} (expect s1|s2|s3|s4|all)"),
        });
    }
    if out.is_empty() {
        anyhow::bail!("empty --scenarios");
    }
    Ok(out)
}
