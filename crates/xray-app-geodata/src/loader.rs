//! 启动期 geodata 线程池化加载入口（xray-frame 契约任务书 P1-2 互喂试点）。
//!
//! 把启动期 CPU 密集的 dat 文件扫描 + protobuf 解码搬进 udf
//! [`PooledThreadPool`]（worker 内借缓冲 → 跑 → RAII 还），替代裸
//! `std::thread::spawn`。**硬边界**（契约明列）：只迁启动期文件加载 + 解码、
//! 启动期规则集构建、低频后台更新；数据面 IO / 握手热路径 / 持 socket 的
//! 任务一律禁入。
//!
//! 解码语义零改动：全部原样调用 [`xray_geodata::loader`] 既有公开函数
//! （[`find_geo_ip`] / [`find_geo_site`]），本文件不含任何 wire/格式逻辑。
//!
//! # 依赖形态（继承派生纪律）
//!
//! 池件直接白拿 udf：[`PooledThreadPool::new`] 组装
//! `MemoryPool`（缓冲）× `ThreadPool`（worker）+ 借用超时；本 crate 不复制
//! 任何池逻辑，只做编排（任务构造 / 提交 / 串行收集）。

use std::{
    io::Read,
    path::Path,
    sync::{Arc, mpsc},
    time::Duration,
};

use skeleton_infra::{
    memgov::MemoryPool,
    pool::{RejectedTask, ThreadPool, ThreadPoolTuning},
    pooled_thread_pool::PooledThreadPool,
};
use xray_geodata::{
    GeoIp, GeoSite,
    loader::{LoaderError, find_geo_ip, find_geo_site},
};

use crate::{
    config::GeodataAsset,
    downloader::AssetDownloader,
    error::GeodataError,
    swap::{self, Stage},
};

// PM 拍板（拍板清单 §2 P1-2.1）：固定默认值 + env 覆盖，不按核数动态取——
// 动态取值削弱可复现性，调参走 env 显式行为。
const DEFAULT_CORE: usize = 2;
const DEFAULT_MAX: usize = 2;
const DEFAULT_QUEUE_CAP: usize = 8;
const DEFAULT_BORROW_TIMEOUT_MS: usize = 10_000;

/// 池参数 env 覆盖项：worker 保活数。
pub const ENV_CORE: &str = "XRAY_GEODATA_POOL_CORE";
/// 池参数 env 覆盖项：worker 上限（同时决定内存池缓冲上限）。
pub const ENV_MAX: &str = "XRAY_GEODATA_POOL_MAX";
/// 池参数 env 覆盖项：中央队列容量（溢出走 RejectedTask 退还，不 panic）。
pub const ENV_QUEUE_CAP: &str = "XRAY_GEODATA_POOL_QUEUE_CAP";
/// 池参数 env 覆盖项：worker 借缓冲超时（毫秒）。
pub const ENV_BORROW_TIMEOUT_MS: &str = "XRAY_GEODATA_POOL_BORROW_TIMEOUT_MS";

/// 池参数（`core` 保活 / `max` worker 上限 / `queue_cap` 排队上限 / 借用超时）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PoolParams {
    core: usize,
    max: usize,
    queue_cap: usize,
    borrow_timeout: Duration,
}

/// 纯解析：env 覆盖 → 参数 + 告警（不碰真实环境，测试注入闭包）。
/// 非法/退化值（0、core>max）记告警并回落默认/修正——启动配置打错字不应
/// fail-fast 炸进程，但也不能静默吞掉。
fn parse_overrides(get: impl Fn(&str) -> Option<String>) -> (PoolParams, Vec<String>) {
    let mut warnings = Vec::new();
    let num = |name: &str, default: usize, warnings: &mut Vec<String>| -> usize {
        match get(name) {
            None => default,
            Some(raw) => match raw.trim().parse::<usize>() {
                Ok(v) if v > 0 => v,
                _ => {
                    warnings
                        .push(format!("invalid {name}={raw:?}; falling back to default {default}"));
                    default
                },
            },
        }
    };
    let core = num(ENV_CORE, DEFAULT_CORE, &mut warnings);
    let max = num(ENV_MAX, DEFAULT_MAX, &mut warnings);
    let queue_cap = num(ENV_QUEUE_CAP, DEFAULT_QUEUE_CAP, &mut warnings);
    let borrow_ms = num(ENV_BORROW_TIMEOUT_MS, DEFAULT_BORROW_TIMEOUT_MS, &mut warnings);
    let mut params = PoolParams {
        core,
        max,
        queue_cap,
        borrow_timeout: Duration::from_millis(borrow_ms as u64),
    };
    if params.core > params.max {
        warnings.push(format!(
            "{ENV_CORE}={} > {ENV_MAX}={}; clamping core to max",
            params.core, params.max
        ));
        params.core = params.max;
    }
    (params, warnings)
}

/// 互喂池：worker 内借缓冲 → 跑 → RAII 还。
///
/// 构造参数逐项对应 udf 真实签名：
/// - `PooledThreadPool::new(mem, threads, borrow_timeout)`
///   （`crates/udf-frame/skeleton-infra/src/pooled_thread_pool.rs`）
/// - `ThreadPool::new(ThreadPoolTuning)`（同目录 `pool.rs`）
/// - `ThreadPoolTuning::new(core, max, queue_cap)`（同上）
pub struct GeodataLoadPool {
    pool: PooledThreadPool<Vec<u8>, fn() -> Vec<u8>>,
}

impl GeodataLoadPool {
    /// 组装互喂池。非法参数（0 值 / `core > max`）由 udf 构造期 fail-fast
    /// panic（恒不合法 = 调用方 bug，同 udf 纪律）。
    ///
    /// 内存池上限 = `max`：每 worker 至多持 1 块缓冲，恒不借空
    /// （`borrow_rejected` 只在误用时才可能非零）。
    pub fn new(core: usize, max: usize, queue_cap: usize, borrow_timeout: Duration) -> Self {
        let mem = Arc::new(MemoryPool::<Vec<u8>>::new(max, max, Vec::new));
        let threads = ThreadPool::new(ThreadPoolTuning::new(core, max, queue_cap));
        Self { pool: PooledThreadPool::new(mem, threads, borrow_timeout) }
    }

    /// 固定默认值 + env 覆盖装配（PM 拍板 §2 P1-2.1）。非法 env 值记
    /// `tracing::warn` 后回落默认，不 panic。
    pub fn from_env() -> Self {
        let (params, warnings) = parse_overrides(|k| std::env::var(k).ok());
        for w in &warnings {
            tracing::warn!("{w}");
        }
        Self::new(params.core, params.max, params.queue_cap, params.borrow_timeout)
    }

    /// 提交一个加载任务（worker 内借缓冲 → 跑 → RAII 还）。
    /// 返回 `Err(RejectedTask)` = 提交侧拒绝（队列满/shutdown），任务原样退还，
    /// 不 panic。
    pub fn submit(
        &self,
        f: impl FnOnce(&mut Vec<u8>) + Send + 'static,
    ) -> Result<(), RejectedTask> {
        self.pool.submit(f)
    }

    /// 借空拒绝计数（读侧；与提交侧 rejected 独立）。
    pub fn borrow_rejected(&self) -> u64 {
        self.pool.borrow_rejected()
    }

    /// 线程池管理面（resize / metrics / shutdown+join / 审计订阅）。
    pub fn threads(&self) -> &ThreadPool {
        self.pool.threads()
    }

    /// 内存池管理面（metrics / 直接借还）。
    pub fn mem_pool(&self) -> &MemoryPool<Vec<u8>, fn() -> Vec<u8>> {
        self.pool.mem_pool()
    }

    /// 停机面：停止接收新任务 → 排空已入队任务 → 等 worker 退役
    /// （契约坑约束 5：后台任务必托管）。幂等。
    pub fn shutdown_join(&self) {
        self.pool.threads().shutdown();
        self.pool.threads().join();
    }

    /// 并行加载一批 (kind, file, code) 请求：全部提交（worker 内读 dat 文件
    /// 进借来的缓冲 → 原样调用 xray-geodata 解码）→ **串行收集**。
    ///
    /// - 提交侧队列满 = 该请求在本线程内联执行（CallerRuns 等价，有界不 panic）；
    /// - 单请求失败（文件缺/解码坏）不影响其他请求，按请求序返回各自结果。
    pub fn load_parallel(
        &self,
        datadir: &Path,
        reqs: &[LoadRequest],
    ) -> Vec<Result<LoadedEntry, LoaderError>> {
        let (tx, rx) = mpsc::channel();
        let mut queued = 0usize;
        let mut inline: Vec<(usize, Result<LoadedEntry, LoaderError>)> = Vec::new();
        for (idx, req) in reqs.iter().enumerate() {
            let submitted = self.submit({
                let tx = tx.clone();
                let datadir = datadir.to_path_buf();
                let req = req.clone();
                move |buf: &mut Vec<u8>| {
                    let _ = tx.send((idx, run_load(&datadir, &req, buf)));
                }
            });
            match submitted {
                Ok(()) => queued += 1,
                Err(_) => {
                    // RejectedTask 已退还（此处置即不执行池内副本）：
                    // CallerRuns 等价，本线程自带 scratch 内联补位。
                    let mut scratch = Vec::new();
                    inline.push((idx, run_load(datadir, req, &mut scratch)));
                },
            }
        }
        drop(tx);
        let mut slots: Vec<Option<_>> = (0..reqs.len()).map(|_| None).collect();
        for _ in 0..queued {
            if let Ok((idx, r)) = rx.recv() {
                slots[idx] = Some(r);
            }
        }
        for (idx, r) in inline {
            slots[idx] = Some(r);
        }
        slots.into_iter().map(|s| s.expect("every request produced a result")).collect()
    }
}

/// 加载判型（Go 语义 `loadIP` / `loadSite` 的显式选择面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadKind {
    /// geoip 条目 → [`LoadedEntry::Ip`]。
    Ip,
    /// geosite 条目 → [`LoadedEntry::Site`]。
    Site,
}

/// 一条启动期加载请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadRequest {
    pub kind: LoadKind,
    /// dat 文件名（如 `geoip.dat`），相对 `datadir`。
    pub file: String,
    /// 国家/地区代码（如 `CN`）。
    pub code: String,
}

/// 加载结果（判型同请求 kind）。
#[derive(Debug)]
pub enum LoadedEntry {
    Ip(GeoIp),
    Site(GeoSite),
}

/// 单条加载：读 dat 文件字节进（借来的）缓冲 → 原样调用 xray-geodata 内存解码。
/// `buf` 由 PooledThreadPool worker 借出（RAII 自动还）或调用线程自带 scratch。
fn run_load(
    datadir: &Path,
    req: &LoadRequest,
    buf: &mut Vec<u8>,
) -> Result<LoadedEntry, LoaderError> {
    buf.clear();
    let mut f = std::fs::File::open(datadir.join(&req.file))?;
    f.read_to_end(buf)?;
    match req.kind {
        LoadKind::Ip => find_geo_ip(buf, &req.code).map(LoadedEntry::Ip),
        LoadKind::Site => find_geo_site(buf, &req.code).map(LoadedEntry::Site),
    }
}

/// 「并行下载 + 串行 swap」的下载半边（PM 拍板 §2 P1-2.2）：每个 asset 一个
/// 池任务（写各自 temp 文件），全部完成后由调用方走**串行**
/// [`crate::swap::swap_all`]——`swap_all` 的顺序交换与失败回滚原样不动。
/// 任一 asset 失败 → clean 已成功 stage 并返回首个（按 asset 序）错误，
/// 语义对齐串行 [`crate::downloader::download_assets`]。
pub fn download_assets_parallel(
    pool: &GeodataLoadPool,
    downloader: Arc<dyn AssetDownloader>,
    assets: &[GeodataAsset],
) -> Result<Vec<Stage>, GeodataError> {
    let (tx, rx) = mpsc::channel();
    let mut queued = 0usize;
    let mut inline: Vec<(usize, Result<Stage, GeodataError>)> = Vec::new();
    for (idx, asset) in assets.iter().enumerate() {
        let submitted = pool.submit({
            let tx = tx.clone();
            let downloader = Arc::clone(&downloader);
            let asset = asset.clone();
            move |_buf: &mut Vec<u8>| {
                // 下载走流式落盘，借来的缓冲闲置即还（factory 为空 Vec，零成本）。
                let _ = tx.send((idx, download_stage(downloader.as_ref(), &asset)));
            }
        });
        match submitted {
            Ok(()) => queued += 1,
            Err(_) => {
                let r = download_stage(downloader.as_ref(), asset);
                inline.push((idx, r));
            },
        }
    }
    drop(tx);
    let mut slots: Vec<Option<_>> = (0..assets.len()).map(|_| None).collect();
    for _ in 0..queued {
        if let Ok((idx, r)) = rx.recv() {
            slots[idx] = Some(r);
        }
    }
    for (idx, r) in inline {
        slots[idx] = Some(r);
    }
    let mut staged: Vec<Stage> = Vec::with_capacity(assets.len());
    for (idx, slot) in slots.into_iter().enumerate() {
        match slot.expect("every asset produced a result") {
            Ok(stage) => staged.push(stage),
            Err(e) => {
                swap::clean(&staged);
                return Err(GeodataError::Other(
                    format!("asset[{}] {:?}: {e}", idx, assets[idx].file).into(),
                ));
            },
        }
    }
    Ok(staged)
}

/// 池任务体：镜像 `downloader::download_one`（私有，本文件不可改彼）——
/// resolve target → 建临时文件 → `download_to` → Stage；失败清 temp。
fn download_stage(
    downloader: &dyn AssetDownloader,
    asset: &GeodataAsset,
) -> Result<Stage, GeodataError> {
    let target = downloader.resolve_target(&asset.file)?;
    let (_file, temp) = swap::temp_file(&target, ".tmp")?;
    drop(_file); // path 模式：下载 trait 自管 fd
    if let Err(e) = downloader.download_to(&asset.url, &temp) {
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }
    Ok(Stage { target, temp })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use prost::Message;
    use xray_geodata::{Cidr, Domain, GeoIpList, GeoSiteList};

    use super::*;

    fn unique_dir(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "xray-app-geodata-loader-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// 合成 geoip.dat：`codes.len()` 条目 × 每条 `cidrs` 个网段（确定性的扫描负载）。
    fn make_geoip_dat(codes: usize, cidrs: usize) -> Vec<u8> {
        let mut list = GeoIpList::new();
        for c in 0..codes {
            let code = format!("c{c:03}");
            let mut entry = xray_geodata::GeoIp::new(&code);
            for k in 0..cidrs {
                let o = ((c * 7 + k * 13) % 251) as u8;
                entry = entry.with_cidr(Cidr::new(vec![10, o, o, o], 24));
            }
            list = list.with_entry(entry);
        }
        list.encode_to_vec()
    }

    fn make_geosite_dat(codes: usize, domains: usize) -> Vec<u8> {
        let mut list = GeoSiteList::new();
        for c in 0..codes {
            let code = format!("c{c:03}");
            let mut entry = xray_geodata::GeoSite::new(&code);
            for k in 0..domains {
                entry = entry.with_domain(Domain::domain(&format!("d{c:03}-{k:03}.example")));
            }
            list = list.with_entry(entry);
        }
        list.encode_to_vec()
    }

    fn fixture_dir(label: &str, codes: usize, cidrs: usize, domains: usize) -> PathBuf {
        let dir = unique_dir(label);
        std::fs::write(dir.join("geoip.dat"), make_geoip_dat(codes, cidrs)).unwrap();
        std::fs::write(dir.join("geosite.dat"), make_geosite_dat(codes, domains)).unwrap();
        dir
    }

    fn reqs_per_file(codes: usize, per_file: usize) -> Vec<LoadRequest> {
        (0..per_file)
            .flat_map(|i| {
                let code = format!("c{:03}", i * (codes / per_file));
                [
                    LoadRequest {
                        kind: LoadKind::Ip,
                        file: "geoip.dat".into(),
                        code: code.clone(),
                    },
                    LoadRequest { kind: LoadKind::Site, file: "geosite.dat".into(), code },
                ]
            })
            .collect()
    }

    #[test]
    fn parse_overrides_defaults_and_invalid_fallback() {
        let (p, warnings) = parse_overrides(|_| None);
        assert_eq!(p.core, 2);
        assert_eq!(p.max, 2);
        assert_eq!(p.queue_cap, 8);
        assert_eq!(p.borrow_timeout, Duration::from_millis(10_000));
        assert!(warnings.is_empty());

        let (p, warnings) = parse_overrides(|k| {
            Some(match k {
                ENV_CORE => "0".into(),         // 退化值 → 默认 + 告警
                ENV_MAX => "abc".into(),        // 非数字 → 默认 + 告警
                ENV_QUEUE_CAP => " 16 ".into(), // 容忍空白
                ENV_BORROW_TIMEOUT_MS => "500".into(),
                _ => return None,
            })
        });
        assert_eq!((p.core, p.max, p.queue_cap), (2, 2, 16));
        assert_eq!(p.borrow_timeout, Duration::from_millis(500));
        assert_eq!(warnings.len(), 2, "0 与非数字各记一条: {warnings:?}");

        // core > max → clamp 修正 + 告警
        let (p, warnings) = parse_overrides(|k| {
            Some(match k {
                ENV_CORE => "4".into(),
                ENV_MAX => "2".into(),
                _ => return None,
            })
        });
        assert_eq!(p.core, 2);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn load_parallel_balances_borrow_and_return() {
        let dir = fixture_dir("balance", 8, 40, 40);
        let pool = GeodataLoadPool::new(2, 2, 8, Duration::from_secs(10));
        let reqs = reqs_per_file(8, 4);
        let results = pool.load_parallel(&dir, &reqs);
        assert_eq!(results.len(), reqs.len());
        for (i, r) in results.iter().enumerate() {
            let entry = r.as_ref().unwrap_or_else(|e| panic!("req[{i}] failed: {e:?}"));
            match (&reqs[i].kind, entry) {
                (LoadKind::Ip, LoadedEntry::Ip(ip)) => assert_eq!(ip.code, reqs[i].code),
                (LoadKind::Site, LoadedEntry::Site(site)) => {
                    assert_eq!(site.code, reqs[i].code)
                },
                (kind, entry) => panic!("kind mismatch: {kind:?} vs {entry:?}"),
            }
        }
        // ① 提交 N 个任务后 borrow_rejected()==0 且借还计数归零（RAII 归还）。
        pool.shutdown_join();
        assert_eq!(pool.borrow_rejected(), 0);
        let m = pool.mem_pool().metrics();
        assert_eq!(m.core.borrowed, 0, "buffers must all be returned");
        assert_eq!(m.core.idle, m.core.max, "all buffers back in pool");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn task_panic_does_not_poison_pool_or_leak_buffer() {
        // ② 单任务 panic 不影响其他任务，RAII 归还仍发生（udf 侧已钉 guard
        // unwind 路径；此处验证编排层可用性不回退）。
        let dir = fixture_dir("panic", 4, 20, 20);
        let pool = GeodataLoadPool::new(1, 1, 8, Duration::from_secs(10));
        let (tx, rx) = mpsc::channel();
        for i in 0..3 {
            let tx = tx.clone();
            let dir2 = dir.clone();
            pool.submit(move |buf: &mut Vec<u8>| {
                let req = LoadRequest {
                    kind: LoadKind::Ip,
                    file: "geoip.dat".into(),
                    code: format!("c{i:03}"),
                };
                let _ = tx.send(run_load(&dir2, &req, buf));
            })
            .unwrap();
        }
        pool.submit(move |_buf| panic!("deliberate task panic")).unwrap();
        drop(tx);
        let mut oks = 0;
        while let Ok(r) = rx.recv() {
            assert!(r.is_ok());
            oks += 1;
        }
        assert_eq!(oks, 3);
        // 池仍可用（shutdown 之前提交）
        let (tx2, rx2) = mpsc::channel();
        pool.submit(move |buf| {
            let _ = tx2.send(buf.capacity());
        })
        .expect("pool must stay usable after a task panic");
        pool.shutdown_join();
        assert_eq!(pool.borrow_rejected(), 0);
        let m = pool.mem_pool().metrics();
        assert_eq!(m.core.borrowed, 0, "panic task must still return its buffer");
        assert_eq!(m.core.idle, m.core.max);
        assert!(rx2.recv().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn queue_overflow_rejects_with_refundable_task() {
        // ④ 并发提交有界：queue_cap 溢出 → RejectedTask 退还，不 panic；
        // 退还任务可取回执行（Abort 语义）。
        let pool = GeodataLoadPool::new(1, 1, 1, Duration::from_secs(10));
        let (started_tx, started_rx) = mpsc::channel();
        let (ack_tx, ack_rx) = mpsc::channel::<()>();
        pool.submit(move |_buf| {
            let _ = started_tx.send(());
            let _ = ack_rx.recv(); // 钉住唯一 worker
        })
        .unwrap();
        started_rx.recv_timeout(Duration::from_secs(5)).expect("first task must claim the worker");

        let (done_tx, done_rx) = mpsc::channel();
        let queued_tx = done_tx.clone();
        // 占满 queue_cap=1
        pool.submit(move |_buf| {
            let _ = queued_tx.send("queued");
        })
        .unwrap();
        // 溢出提交 → Err(RejectedTask)，任务退还
        let rejected = pool
            .submit(move |_buf| {
                let _ = done_tx.send("refunded-inline");
            })
            .expect_err("queue_cap=1 + busy worker must reject");
        let recovered = rejected.into_task();

        drop(ack_tx);
        pool.shutdown_join();
        assert_eq!(done_rx.recv(), Ok("queued"));
        assert_eq!(pool.borrow_rejected(), 0);
        recovered(); // 退还任务由调用方处置：内联执行仍有效
        assert_eq!(done_rx.recv(), Ok("refunded-inline"));
        let m = pool.mem_pool().metrics();
        assert_eq!(m.core.borrowed, 0);
        assert_eq!(m.core.idle, m.core.max);
    }

    #[test]
    fn download_assets_parallel_mirrors_serial_semantics() {
        let dir = unique_dir("dl");
        let pool = GeodataLoadPool::new(2, 2, 8, Duration::from_secs(10));
        let dl: Arc<dyn AssetDownloader> = Arc::new(CountingDownloader { root: dir.clone() });
        let assets = vec![
            GeodataAsset { url: "u1".into(), file: "a.dat".into() },
            GeodataAsset { url: "u2".into(), file: "b.dat".into() },
        ];
        let staged = download_assets_parallel(&pool, Arc::clone(&dl), &assets).unwrap();
        assert_eq!(staged.len(), 2);
        for s in &staged {
            assert!(s.temp.exists());
        }
        // 失败 asset → clean 本轮已成功 stage + 返回按 asset 序的首个错误
        //（独立目录，断言失败轮零残留）
        let dir2 = unique_dir("dl-fail");
        let dl2: Arc<dyn AssetDownloader> = Arc::new(CountingDownloader { root: dir2.clone() });
        let bad = vec![
            GeodataAsset { url: "u1".into(), file: "a.dat".into() },
            GeodataAsset { url: "boom".into(), file: "bad.dat".into() },
        ];
        let err = download_assets_parallel(&pool, dl2, &bad).unwrap_err();
        assert!(err.to_string().contains("bad.dat"), "{err}");
        let leftovers: Vec<_> = std::fs::read_dir(&dir2)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "tmp"))
            .collect();
        assert!(leftovers.is_empty(), "failed run must clean staged temps: {leftovers:?}");
        pool.shutdown_join();
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    /// 测试下载器：写 url 内容到 temp；url 含 "boom" 则失败。
    struct CountingDownloader {
        root: PathBuf,
    }
    impl AssetDownloader for CountingDownloader {
        fn download_to(&self, url: &str, temp: &Path) -> Result<(), GeodataError> {
            if url.contains("boom") {
                return Err(GeodataError::Other("boom asset".into()));
            }
            std::fs::write(temp, url.as_bytes()).unwrap();
            Ok(())
        }

        fn resolve_target(&self, file: &str) -> Result<PathBuf, GeodataError> {
            Ok(self.root.join(file))
        }
    }
}
