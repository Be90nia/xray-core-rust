//! readv/拷贝热路径高并发基准（性能批：splice/readv 收益的高并发数据补证）
//!
//! 拓扑：真实 TCP loopback——不用 tokio `io::duplex`（DuplexStream 未覆写
//! `poll_read_vectored`，ReadVReader 会退化为顺序单缓冲读，readv 语义失真）。
//! N 并发连接 × 每流 512KB：写端 task 循环 `write_all` 泵数据，读端 task 经
//! 生产同款分派 `xray_buf::io::new_readv_reader` 消费，criterion 计总吞吐。
//!
//! 对照组经进程级 env 闸门切换（`xray.buf.readv`）：
//! - `enable` → ReadVReader（readv 聚合读，一次 syscall 填多缓冲）
//! - `disable` → SingleReader（单缓冲拷贝路径，Go 无 readv 时等价物）
//!
//! CI 接入位（可选、不阻塞）：.github/workflows 新增 ubuntu job 跑
//! `cargo bench -p xray-benchmarks --bench readv_bench`。splice 高并发 PPS
//! 为 Linux-only 语义，本地 Windows 无法验证，骨架见文件尾 cfg(linux) mod。

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, tcp::OwnedWriteHalf},
};
use xray_buf::{
    io::{Reader, new_readv_reader},
    readv::reload_env_settings,
};

const PER_STREAM_BYTES: usize = 512 * 1024;
const CHUNK: usize = 64 * 1024;

/// 切换 readv env 闸门（进程级 AtomicBool，需显式 reload）。
fn set_gate(enable: bool) {
    // bench 进程独占 env，set_var 安全
    unsafe {
        std::env::set_var("xray.buf.readv", if enable { "enable" } else { "disable" });
    }
    reload_env_settings();
}

/// 写端：泵 `total` 字节后 drop（半关闭 → 读端见 EOF）。
/// 读满即停时对端可能已 drop，BrokenPipe 属预期。
async fn pump(mut w: OwnedWriteHalf, mut total: usize) {
    let chunk = [0xABu8; CHUNK];
    while total > 0 {
        let n = chunk.len().min(total);
        if w.write_all(&chunk[..n]).await.is_err() {
            break;
        }
        total -= n;
    }
}

/// 读端：经生产分派消费 `expected` 字节，返回实收字节数。
async fn drain(mut r: Box<dyn Reader>, expected: usize) -> usize {
    let mut got = 0;
    while got < expected {
        let mb = match r.read_multi_buffer().await {
            Ok(mb) => mb,
            Err(_) => break,
        };
        if mb.is_empty() {
            break;
        }
        got += mb.len();
    }
    got
}

/// 单次迭代：建 N 对 loopback 连接，读写双侧全并发，返回总字节数。
/// 连接在迭代内建立：loopback 建连为 µs 级，相对 4MB 传输占比可忽略，
/// 换取迭代间状态干净（无跨迭代残留数据）。
async fn run_once(n_streams: usize) -> usize {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");

    let mut pump_handles = Vec::with_capacity(n_streams);
    let mut drain_handles = Vec::with_capacity(n_streams);
    for _ in 0..n_streams {
        let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let client = client.expect("connect loopback");
        let (server, _) = server.expect("accept loopback");

        let (_, cw) = client.into_split();
        let (sr, _) = server.into_split();
        pump_handles.push(tokio::spawn(pump(cw, PER_STREAM_BYTES)));
        // 生产同款分派：闸门 on → ReadVReader，off → SingleReader
        drain_handles.push(tokio::spawn(drain(new_readv_reader(sr), PER_STREAM_BYTES)));
    }

    let mut total = 0;
    for h in drain_handles {
        total += h.await.expect("drain task");
    }
    for h in pump_handles {
        let _ = h.await;
    }
    total
}

/// 跑一组并发流基准：`gate_on` 切闸门，`n_streams` 并发 × [`PER_STREAM_BYTES`]。
fn bench_streams(c: &mut Criterion, gate_on: bool, n_streams: usize) {
    let rt =
        tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
    set_gate(gate_on);

    let group_name = if gate_on { "readv_hotpath" } else { "copy_hotpath" };
    let mut g = c.benchmark_group(group_name);
    g.throughput(Throughput::Bytes((PER_STREAM_BYTES * n_streams) as u64));
    g.bench_with_input(BenchmarkId::from_parameter(n_streams), &n_streams, |b, &n| {
        b.iter(|| {
            let total = rt.block_on(run_once(n));
            black_box(total);
        });
    });
    g.finish();
}

fn bench_readv_1stream(c: &mut Criterion) {
    bench_streams(c, true, 1);
}
fn bench_readv_8streams(c: &mut Criterion) {
    bench_streams(c, true, 8);
}
fn bench_copy_1stream(c: &mut Criterion) {
    bench_streams(c, false, 1);
}
fn bench_copy_8streams(c: &mut Criterion) {
    bench_streams(c, false, 8);
}

criterion_group!(
    benches,
    bench_copy_1stream,
    bench_copy_8streams,
    bench_readv_1stream,
    bench_readv_8streams,
);
criterion_main!(benches);

// ========== splice(2) 高并发 PPS 骨架（未验：Linux-only，Windows 本地无法测） ==========
//
// 测法（CI ubuntu 落地时实现）：pipe2 + splice(sockfd→pipefd→sockfd) 零拷贝循环，
// 拓扑同上 N 并发连接；指标 = splice 调用次数/秒（PPS）与 MB/s，对照 readv 组。
// 依赖：benches 需增 libc（cfg(target_os = "linux") 门控），本仓库 benches 刻意
// 不引新依赖，故骨架不实现 FFI。
//
// CI job 注释位：ubuntu runner
//   cargo bench -p xray-benchmarks --bench readv_bench -- --filter splice
// 可选、不阻塞主 CI 门禁。
#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn bench_splice_pps_skeleton() {
    // 骨架占位：不注册进 criterion_group（避免 CI 侧执行 panic），
    // 由 CI ubuntu 按上方注释位实现 splice FFI 后挂载。本地未验。
    unimplemented!("splice PPS 骨架：CI ubuntu 补测，本地 Windows 未验")
}
