//! P3-1 S2 长跑取证（B2 T2.1）：生产 `dispatch_link` 每笔落的选择记录
//! `(dest, tag, chosen_handler_tag)` 与 xray-frame 查表（S3 目标面
//! `xray_frame::dispatch::lookup`）逐条比对，差异率必须为 0。
//!
//! **本驱动面的独特价值 = 查表面对拍**：生产 in-vivo 对照器（`record_in_vivo`，
//! B4 前置已接线）比的是「旧臂本体 vs S0 提取半边」，同源 ⇒ 只检臂漂移；
//! 而查表登记按 `TypeId` 键，生产 `Arc<dyn DispatchHandler>` 无法还原具体型
//! （见报告 G2），故「真实记录 vs `xray_frame::dispatch::lookup`」这一对照
//! 只能在测试驱动面做（本文件）。
//!
//! 计数口径：`dual_write::sample_count()`/`diff_count()` 是**全局**计数器，
//! 现已同时包含生产 in-vivo 样本与本驱动面的回放样本 ⇒ 本文件用 `st.samples`
//! （回放侧自计）核对记录丢失，全局增量只作参照打印。
//!
//! 负载：`DW_CONCURRENCY` 并发 worker 循环建链（pipe 双工 + 4KB 往返回显），
//! 覆盖 forced 命中 / 路由命中 / 路由未命中 / 默认出站四条选择出口。
//!
//! 运行（默认 3 轮 × 30 分钟）：
//! `cargo test --release -p xray-app-dispatcher --features dispatcher-dual-write \
//!   --test dual_write_longrun -- --ignored --nocapture`
//! 环境变量：`DW_ROUNDS`（默认 3）、`DW_ROUND_MINUTES`（默认 30）、
//! `DW_CONCURRENCY`（默认 24）。
#![cfg(feature = "dispatcher-dual-write")]

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use xray_app_dispatcher::{
    DefaultDispatcher, DispatchHandler, OutboundHandlerManager, RoutingContext, RoutingRouter,
    SimpleOhm,
    default::{PinFuture, Route, SniffingRequest, dual_write},
};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_frame::{
    PluginContext,
    contract_assert::contract_test_context,
    dispatch::{HandlerCapability, Lookup, lookup},
};

/// 回显累计字节（流量总量取证）。
static BYTES: AtomicU64 = AtomicU64::new(0);
/// 已发起的 dispatch 次数（对照记录环容量，检记录丢失）。
static DISPATCHED: AtomicU64 = AtomicU64::new(0);
/// 仪器自检用（`DW_INJECT_DIFF=<tag>`）：对该请求 tag 故意给出错误的新路结果，
/// 用于 red-green 验证「差异真的会被记到」（否则 0 差异可能是仪器哑了）。
static INJECT_DIFF: std::sync::OnceLock<String> = std::sync::OnceLock::new();
/// 分支覆盖计数（forced / 路由 / 无路由默认）与未命中记录数。
static K_FORCED: AtomicU64 = AtomicU64::new(0);
static K_ROUTED: AtomicU64 = AtomicU64::new(0);
static K_PLAIN: AtomicU64 = AtomicU64::new(0);

/// 回显 handler：读 link 上行 → 原样写回下行，直到上行 EOF。
async fn echo_loop(link: xray_transport::link::Link) {
    use xray_buf::io::{Reader as _, Writer as _};
    let mut r = link.reader;
    let mut w = link.writer;
    loop {
        match r.read_multi_buffer().await {
            Ok(mb) if !mb.is_empty() => {
                let n = mb.len() as u64;
                if w.write_multi_buffer(mb).await.is_err() {
                    break;
                }
                BYTES.fetch_add(n, Ordering::Relaxed);
            },
            // 空 buffer = 上行 EOF；Err = 链路断。
            _ => break,
        }
    }
    w.shutdown();
}

macro_rules! echo_handlers {
    ($($ty:ident => $tag:literal),* $(,)?) => {
        $(
            #[derive(Debug)]
            struct $ty;
            impl DispatchHandler for $ty {
                fn tag(&self) -> &str { $tag }
                fn dispatch(&self, _dest: &Destination, link: xray_transport::link::Link) -> PinFuture<()> {
                    Box::pin(echo_loop(link))
                }
            }
        )*
    };
}

echo_handlers! {
    H0 => "t0", H1 => "t1", H2 => "t2", H3 => "t3",
    H4 => "t4", H5 => "t5", H6 => "t6", H7 => "t7",
    Hd => "t-default",
    MissProbe => "t-miss",
}

const TAGS: [&str; 8] = ["t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7"];
const MISS_TAG: &str = "t-miss";

/// 路由面：9/10 命中轮转 tag，1/10 返回未登记 tag（路由未命中出口）。
#[derive(Debug)]
struct CycleRouter {
    n: AtomicUsize,
}

impl RoutingRouter for CycleRouter {
    fn pick_route(
        &self,
        _ctx: &dyn RoutingContext,
    ) -> Result<Route, xray_app_dispatcher::DispatcherError> {
        let i = self.n.fetch_add(1, Ordering::Relaxed);
        Ok(Route::new(if i % 10 == 9 { MISS_TAG } else { TAGS[i % TAGS.len()] }))
    }
}

fn build_ohm() -> Arc<SimpleOhm> {
    let ohm = SimpleOhm::new();
    ohm.add("t0", Arc::new(H0));
    ohm.add("t1", Arc::new(H1));
    ohm.add("t2", Arc::new(H2));
    ohm.add("t3", Arc::new(H3));
    ohm.add("t4", Arc::new(H4));
    ohm.add("t5", Arc::new(H5));
    ohm.add("t6", Arc::new(H6));
    ohm.add("t7", Arc::new(H7));
    ohm.set_default(Arc::new(Hd));
    Arc::new(ohm)
}

/// 查表侧世界：8 个 tag 各自由独立型背书（`lookup` 登记表按 `TypeId` 键，
/// 一型只承载一个 tag——两 tag 同型在该面不可表达，见报告 G2）。
fn build_ctx() -> PluginContext {
    let mut ctx = contract_test_context("dual-write-longrun");
    ctx.register_handler(Arc::new(H0)).expect("register H0");
    ctx.register_handler(Arc::new(H1)).expect("register H1");
    ctx.register_handler(Arc::new(H2)).expect("register H2");
    ctx.register_handler(Arc::new(H3)).expect("register H3");
    ctx.register_handler(Arc::new(H4)).expect("register H4");
    ctx.register_handler(Arc::new(H5)).expect("register H5");
    ctx.register_handler(Arc::new(H6)).expect("register H6");
    ctx.register_handler(Arc::new(H7)).expect("register H7");
    ctx
}

fn lookup_one<T: DispatchHandler + 'static>(ctx: &PluginContext, tag: &str) -> Option<String> {
    match lookup::<T>(ctx, HandlerCapability::of::<T>(tag)) {
        Lookup::Found(h) => Some(h.tag().to_string()),
        Lookup::Missing { .. } => None,
    }
}

/// 新路（S3 目标面）对同一请求 tag 的选择结果。
fn new_choice(ctx: &PluginContext, tag: &str) -> Option<String> {
    if INJECT_DIFF.get().is_some_and(|t| t == tag) {
        return Some("t-injected-diff".to_string());
    }
    match tag {
        "t0" => lookup_one::<H0>(ctx, tag),
        "t1" => lookup_one::<H1>(ctx, tag),
        "t2" => lookup_one::<H2>(ctx, tag),
        "t3" => lookup_one::<H3>(ctx, tag),
        "t4" => lookup_one::<H4>(ctx, tag),
        "t5" => lookup_one::<H5>(ctx, tag),
        "t6" => lookup_one::<H6>(ctx, tag),
        "t7" => lookup_one::<H7>(ctx, tag),
        _ => lookup_one::<MissProbe>(ctx, tag),
    }
}

#[derive(Default)]
struct RoundStats {
    samples: u64,
    local_diffs: u64,
    default_records: u64,
    miss_records: u64,
    diff_samples: Vec<String>,
}

/// 排干记录环并与查表面逐条比对（差异走 `compare_sample` 计数 + error 留痕）。
fn drain_and_compare(ctx: &PluginContext, st: &mut RoundStats) {
    for rec in dual_write::take_records() {
        let Some(tag) = rec.tag.as_deref() else {
            // tag=None = 默认出站分支：默认选择是 dispatcher 策略半边，不是查表键，
            // 两侧同源无对照意义——单列计数，不计入差异样本。
            st.default_records += 1;
            continue;
        };
        let new = new_choice(ctx, tag);
        st.samples += 1;
        if rec.chosen_handler_tag.is_none() {
            st.miss_records += 1;
        }
        if dual_write::compare_sample(tag, rec.chosen_handler_tag.as_deref(), new.as_deref()) {
            st.local_diffs += 1;
            if st.diff_samples.len() < 20 {
                st.diff_samples.push(format!("{rec:?} new={new:?}"));
            }
        }
    }
}

async fn worker(
    id: usize,
    routed: Arc<DefaultDispatcher>,
    plain: Arc<DefaultDispatcher>,
    stop: Arc<AtomicBool>,
    delay: Duration,
    bypass: bool,
) {
    let payload = [0x5au8; 4096];
    let mut i = 0usize;
    while !stop.load(Ordering::Relaxed) {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let kind = (i + id * 7) % 100;
        let (up_r, up_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let link = xray_transport::link::Link::new(Box::new(up_r), Box::new(dn_w));
        let dest = Destination::new(
            Address::new_domain(format!("dw-{id}-{i}.longrun.test")),
            Port::new(443),
            Network::TCP,
        );
        if bypass {
            // 归因对照：绕开 dispatcher（不落记录、不 spawn 分发任务），只跑
            // 「pipe + 回显 handler」同一流量形态，用于区分内存增长归属。
            tokio::spawn(echo_loop(link));
        } else {
            // 60% forced 命中 / 25% 路由（含 1/10 未命中） / 15% 默认出站。
            let (d, forced) = if kind < 60 {
                K_FORCED.fetch_add(1, Ordering::Relaxed);
                (routed.as_ref(), Some(TAGS[kind % TAGS.len()]))
            } else if kind < 85 {
                K_ROUTED.fetch_add(1, Ordering::Relaxed);
                (routed.as_ref(), None)
            } else {
                K_PLAIN.fetch_add(1, Ordering::Relaxed);
                (plain.as_ref(), None)
            };
            if d.dispatch_link(&dest, link, &SniffingRequest::default(), None, forced).is_err() {
                i += 1;
                continue;
            }
        }
        DISPATCHED.fetch_add(1, Ordering::Relaxed);
        let mut w = up_w;
        let mut mb = xray_buf::multi::MultiBuffer::new();
        mb.merge_bytes(&payload);
        if w.write_multi_buffer(mb).await.is_err() {
            i += 1;
            continue;
        }
        drop(w); // 上行 EOF → 回显 handler 收尾
        let mut r = dn_r;
        // 未命中分支链路被 shutdown：2s 上界防挂死（命中分支毫秒级返回）。
        let _ = tokio::time::timeout(Duration::from_secs(2), r.read_multi_buffer()).await;
        i += 1;
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "长跑取证（轮数×时长由 DW_* 环境变量控制），手动触发"]
async fn dual_write_invivo_longrun() {
    let rounds = env_usize("DW_ROUNDS", 3);
    let minutes = env_usize("DW_ROUND_MINUTES", 30);
    let concurrency = env_usize("DW_CONCURRENCY", 16);
    let delay = Duration::from_micros(env_usize("DW_DELAY_MICROS", 2000) as u64);
    let instrument_check = match std::env::var("DW_INJECT_DIFF") {
        Ok(t) => {
            let _ = INJECT_DIFF.set(t);
            true
        },
        Err(_) => false,
    };
    let bypass = std::env::var("DW_BYPASS_DISPATCH").is_ok();

    let ohm = build_ohm();
    let mut routed = DefaultDispatcher::new();
    routed.init(
        &xray_app_dispatcher::Config::default(),
        Arc::clone(&ohm) as Arc<dyn OutboundHandlerManager>,
        Some(Arc::new(CycleRouter { n: AtomicUsize::new(0) })),
        xray_features::policy::Policy::default(),
        None,
    );
    let mut plain = DefaultDispatcher::new();
    plain.init(
        &xray_app_dispatcher::Config::default(),
        Arc::clone(&ohm) as Arc<dyn OutboundHandlerManager>,
        None,
        xray_features::policy::Policy::default(),
        None,
    );
    let routed = Arc::new(routed);
    let plain = Arc::new(plain);
    let ctx = build_ctx();

    println!(
        "[longrun] rounds={rounds} minutes/round={minutes} concurrency={concurrency} \
         delay_us={} bypass_dispatch={bypass} handlers=8+default",
        delay.as_micros()
    );

    let mut failures = Vec::new();
    for round in 1..=rounds {
        let base_samples = dual_write::sample_count();
        let base_diffs = dual_write::diff_count();
        let base_bytes = BYTES.load(Ordering::Relaxed);
        let base_dispatched = DISPATCHED.load(Ordering::Relaxed);
        let base_kf = K_FORCED.load(Ordering::Relaxed);
        let base_kr = K_ROUTED.load(Ordering::Relaxed);
        let base_kp = K_PLAIN.load(Ordering::Relaxed);
        let started = Instant::now();

        let stop = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(concurrency);
        for id in 0..concurrency {
            workers.push(tokio::spawn(worker(
                id,
                Arc::clone(&routed),
                Arc::clone(&plain),
                Arc::clone(&stop),
                delay,
                bypass,
            )));
        }

        // 记录环上限 10k：逐 100ms 排干比对（否则环溢出丢最旧，样本数与实际
        // dispatch 数脱节）。每 60s 打一行进度（挂死可见）。
        let mut st = RoundStats::default();
        let ticks = minutes * 600;
        for tick in 1..=ticks {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drain_and_compare(&ctx, &mut st);
            if tick % 600 == 0 {
                println!(
                    "[longrun] round {round} t+{}s dispatched_delta={} samples={} diffs={} \
                     bytes_delta={}",
                    tick / 10,
                    DISPATCHED.load(Ordering::Relaxed) - base_dispatched,
                    dual_write::sample_count() - base_samples,
                    dual_write::diff_count() - base_diffs,
                    BYTES.load(Ordering::Relaxed) - base_bytes,
                );
            }
        }

        stop.store(true, Ordering::Relaxed);
        for h in workers {
            let _ = h.await;
        }

        drain_and_compare(&ctx, &mut st);
        let samples = dual_write::sample_count() - base_samples;
        let diffs = dual_write::diff_count() - base_diffs;
        let bytes = BYTES.load(Ordering::Relaxed) - base_bytes;
        let dispatched = DISPATCHED.load(Ordering::Relaxed) - base_dispatched;
        let seen = st.samples + st.default_records;
        let lost = dispatched.saturating_sub(seen);
        println!(
            "ROUND {round} wall_s={} dispatched={dispatched} seen={seen} records_lost={lost} \
             samples={samples} diffs={diffs} local_diffs={} default_records={} miss_records={} \
             traffic_mb={:.1}",
            started.elapsed().as_secs(),
            st.local_diffs,
            st.default_records,
            st.miss_records,
            bytes as f64 / (1024.0 * 1024.0),
        );
        println!(
            "BRANCHES {round} forced={} routed={} plain={}",
            K_FORCED.load(Ordering::Relaxed) - base_kf,
            K_ROUTED.load(Ordering::Relaxed) - base_kr,
            K_PLAIN.load(Ordering::Relaxed) - base_kp,
        );
        for s in &st.diff_samples {
            println!("[longrun] DIFF round {round}: {s}");
        }
        if bypass {
            // 归因模式：只测「pipe + 回显」内存形态，不产出对照样本。
        } else if samples == 0 {
            failures.push(format!("round {round}: 零样本（对照面未跑到 = 证据无效）"));
        }
        if bypass {
            // 归因模式无记录环消费者，跳过丢失/差异断言。
        } else if instrument_check {
            // red 自检：注入差异后必须真的被记到，否则 0 差异不可信。
            if diffs == 0 && st.local_diffs == 0 {
                failures.push(format!("round {round}: 注入差异未被检出（仪器失效）"));
            }
        } else {
            if diffs != 0 || st.local_diffs != 0 {
                failures.push(format!("round {round}: diffs={diffs} local={}", st.local_diffs));
            }
            if lost * 100 > dispatched.max(1) {
                failures.push(format!(
                    "round {round}: 记录丢失 {lost}/{dispatched} > 1%（排干跟不上）"
                ));
            }
        }
    }

    let total_diffs = dual_write::diff_count();
    let total_samples = dual_write::sample_count();
    println!(
        "[longrun] totals samples={total_samples} diffs={total_diffs} \
         instrument_check={instrument_check}"
    );
    assert!(failures.is_empty(), "长跑失败：{failures:?}");
    if bypass {
        println!("[longrun] BYPASS 归因模式完成（不产出对照样本）");
    } else if instrument_check {
        println!("[longrun] INSTRUMENT CHECK OK：注入差异被检出（样本面非哑）");
    } else {
        println!("[longrun] PARITY OK：{rounds} 轮差异率 0");
    }
}
