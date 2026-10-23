//! P1-2 验收：启动期 geodata 加载走 PooledThreadPool。
//!
//! ③ 启动期耗时对比（串行基线 vs 池化，≥3 轮取中位数，断言**不得更慢**：
//! 池化中位数 ≤ 串行 × 1.05）；合成数据、零网络。①借还配平 / ②panic 隔离 /
//! ④有界提交 的单测面在 `src/loader.rs` `#[cfg(test)]`，此处以真实 dat 文件
//! 端到端复证。

use std::{
    path::{Path, PathBuf},
    sync::mpsc,
    time::{Duration, Instant},
};

use prost::Message;
use xray_app_geodata::{
    GeodataLoadPool, LoadKind, LoadRequest, LoadedEntry, download_assets_parallel,
};
use xray_geodata::{
    Cidr, Domain, GeoIp, GeoIpList, GeoSite, GeoSiteList,
    loader::{LoaderError, find_geo_ip, find_geo_site},
};

// ── 合成 fixture（确定性负载：codes × entries，扫描+解码均为真实工作） ──

fn make_geoip_dat(codes: usize, cidrs: usize) -> Vec<u8> {
    let mut list = GeoIpList::new();
    for c in 0..codes {
        let code = format!("c{c:03}");
        let mut entry = GeoIp::new(&code);
        for k in 0..cidrs {
            let o = ((c * 11 + k * 17) % 251) as u8;
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
        let mut entry = GeoSite::new(&code);
        for k in 0..domains {
            entry = entry.with_domain(Domain::domain(&format!("d{c:03}-{k:03}.example")));
        }
        list = list.with_entry(entry);
    }
    list.encode_to_vec()
}

fn unique_dir(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "xray-app-geodata-parallel-load-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

const CODES: usize = 96;
const ENTRIES: usize = 220;
const PER_FILE: usize = 12;

fn fixture_dir(label: &str) -> PathBuf {
    let dir = unique_dir(label);
    std::fs::write(dir.join("geoip.dat"), make_geoip_dat(CODES, ENTRIES)).unwrap();
    std::fs::write(dir.join("geosite.dat"), make_geosite_dat(CODES, ENTRIES)).unwrap();
    dir
}

fn reqs() -> Vec<LoadRequest> {
    (0..PER_FILE)
        .flat_map(|i| {
            let code = format!("c{:03}", i * (CODES / PER_FILE));
            [
                LoadRequest { kind: LoadKind::Ip, file: "geoip.dat".into(), code: code.clone() },
                LoadRequest { kind: LoadKind::Site, file: "geosite.dat".into(), code },
            ]
        })
        .collect()
}

// ── 串行基线：同一解码路径原样调用（文件读 → find_* 内存解码） ──

fn run_serial(datadir: &Path, reqs: &[LoadRequest]) -> Vec<Result<LoadedEntry, LoaderError>> {
    reqs.iter()
        .map(|req| {
            let bytes = std::fs::read(datadir.join(&req.file))?;
            match req.kind {
                LoadKind::Ip => find_geo_ip(&bytes, &req.code).map(LoadedEntry::Ip),
                LoadKind::Site => find_geo_site(&bytes, &req.code).map(LoadedEntry::Site),
            }
        })
        .collect()
}

fn median(durs: &mut [Duration]) -> Duration {
    durs.sort();
    durs[durs.len() / 2]
}

#[test]
fn pooled_startup_load_is_not_slower_than_serial() {
    let dir = fixture_dir("perf");
    let reqs = reqs();
    let pool = GeodataLoadPool::new(2, 2, 32, Duration::from_secs(10));

    let timed_serial = |reqs: &[LoadRequest]| -> Duration {
        let t0 = Instant::now();
        let rs = run_serial(&dir, reqs);
        let elapsed = t0.elapsed();
        assert_eq!(rs.len(), reqs.len());
        for r in &rs {
            r.as_ref().expect("serial load must succeed");
        }
        elapsed
    };
    let timed_pooled = |pool: &GeodataLoadPool, reqs: &[LoadRequest]| -> Duration {
        let t0 = Instant::now();
        let rs = pool.load_parallel(&dir, reqs);
        let elapsed = t0.elapsed();
        assert_eq!(rs.len(), reqs.len());
        for r in &rs {
            r.as_ref().expect("pooled load must succeed");
        }
        elapsed
    };

    // 预热轮（FS 缓存），不计入
    timed_serial(&reqs);
    timed_pooled(&pool, &reqs);

    // 交替 3 轮取中位数，降低窗口漂移影响
    let mut serial = Vec::new();
    let mut pooled = Vec::new();
    for _ in 0..3 {
        serial.push(timed_serial(&reqs));
        pooled.push(timed_pooled(&pool, &reqs));
    }
    let (s_med, p_med) = (median(&mut serial), median(&mut pooled));
    println!("serial median: {s_med:?}, pooled median: {p_med:?}");
    // ③ 断言：不得更慢（容忍 5% 抖动）
    assert!(
        p_med.as_nanos() * 100 <= s_med.as_nanos() * 105,
        "pooled ({p_med:?}) must not be slower than serial ({s_med:?}) x 1.05"
    );

    pool.shutdown_join();
    assert_eq!(pool.borrow_rejected(), 0);
    let m = pool.mem_pool().metrics();
    assert_eq!(m.core.borrowed, 0);
    assert_eq!(m.core.idle, m.core.max);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parallel_load_end_to_end_balance_and_panic_isolation() {
    // ①②在真实 dat 文件上复证：全部结果正确 + panic 任务不拖垮批次、不漏缓冲。
    let dir = fixture_dir("e2e");
    let pool = GeodataLoadPool::new(2, 2, 32, Duration::from_secs(10));
    let reqs = reqs();
    let results = pool.load_parallel(&dir, &reqs);
    assert_eq!(results.len(), reqs.len());
    for (i, r) in results.iter().enumerate() {
        let entry = r.as_ref().unwrap_or_else(|e| panic!("req[{i}] failed: {e:?}"));
        match (&reqs[i].kind, entry) {
            (LoadKind::Ip, LoadedEntry::Ip(ip)) => assert_eq!(ip.code, reqs[i].code),
            (LoadKind::Site, LoadedEntry::Site(site)) => assert_eq!(site.code, reqs[i].code),
            (kind, entry) => panic!("kind mismatch: {kind:?} vs {entry:?}"),
        }
    }

    // 混入 panic 任务：其余任务不受影响，缓冲仍 RAII 归还
    let (tx, rx) = mpsc::channel();
    for i in 0..4 {
        let tx = tx.clone();
        let dir2 = dir.clone();
        pool.submit(move |buf: &mut Vec<u8>| {
            // 与 run_load 同构（私有不可达）：读文件进借来的缓冲再解码
            buf.clear();
            let read = std::fs::File::open(dir2.join("geoip.dat")).and_then(|mut f| {
                use std::io::Read;
                f.read_to_end(buf)
            });
            let req = LoadRequest {
                kind: LoadKind::Ip,
                file: "geoip.dat".into(),
                code: format!("c{i:03}"),
            };
            let ok = read.is_ok() && xray_geodata::loader::find_geo_ip(buf, &req.code).is_ok();
            let _ = tx.send(ok);
        })
        .unwrap();
    }
    pool.submit(move |_buf| panic!("deliberate panic among loaders")).unwrap();
    drop(tx);
    let mut oks = 0;
    while let Ok(ok) = rx.recv() {
        assert!(ok);
        oks += 1;
    }
    assert_eq!(oks, 4);

    pool.shutdown_join();
    assert_eq!(pool.borrow_rejected(), 0);
    let m = pool.mem_pool().metrics();
    assert_eq!(m.core.borrowed, 0, "panic task must not leak its buffer");
    assert_eq!(m.core.idle, m.core.max);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bounded_submit_overflow_returns_rejected_task_without_panic() {
    // ④ queue_cap 溢出路径：Err(RejectedTask) 退还（不 panic），池排空后照常工作。
    let dir = fixture_dir("overflow");
    let pool = GeodataLoadPool::new(1, 1, 2, Duration::from_secs(10));
    let reqs = reqs();
    // 先阻塞唯一 worker，制造确定性溢出
    let (started_tx, started_rx) = mpsc::channel();
    let (ack_tx, ack_rx) = mpsc::channel::<()>();
    pool.submit(move |_buf| {
        let _ = started_tx.send(());
        let _ = ack_rx.recv();
    })
    .unwrap();
    started_rx.recv_timeout(Duration::from_secs(5)).expect("worker claimed blocker");

    let mut rejected = 0;
    let mut recovered: Vec<skeleton_infra::pool::RejectedTask> = Vec::new();
    for req in &reqs {
        let req = req.clone();
        match pool.submit(move |buf: &mut Vec<u8>| {
            let _ = xray_geodata::loader::find_geo_ip(buf, &req.code);
        }) {
            Ok(()) => {},
            Err(task) => {
                rejected += 1;
                recovered.push(task);
            },
        }
    }
    assert!(rejected > 0, "PER_FILE*2={} > queue_cap=2 must overflow", reqs.len());
    assert_eq!(rejected, recovered.len());

    drop(ack_tx);
    pool.shutdown_join();
    // 排空期间被排队的任务正常完成；退还任务由调用方处置（此处取回即弃）
    for task in recovered {
        drop(task.into_task());
    }
    assert_eq!(pool.borrow_rejected(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parallel_download_plus_serial_swap_shape() {
    // 拍板 §2 P1-2.2：并行下载产出 Stage 列表，串行 swap_all 原样消费（不改动）。
    use std::{collections::HashMap, sync::Arc};

    use xray_app_geodata::{AssetDownloader, GeodataAsset, swap};

    struct FakeDownloader {
        root: PathBuf,
        payloads: HashMap<String, Vec<u8>>,
    }
    impl AssetDownloader for FakeDownloader {
        fn download_to(
            &self,
            url: &str,
            temp: &Path,
        ) -> Result<(), xray_app_geodata::GeodataError> {
            let payload = self.payloads.get(url).ok_or_else(|| {
                xray_app_geodata::GeodataError::Other(format!("boom: {url}").into())
            })?;
            std::fs::write(temp, payload).unwrap();
            Ok(())
        }

        fn resolve_target(&self, file: &str) -> Result<PathBuf, xray_app_geodata::GeodataError> {
            Ok(self.root.join(file))
        }
    }

    let dir = unique_dir("dlswap");
    let pool = GeodataLoadPool::new(2, 2, 8, Duration::from_secs(10));
    let dl: Arc<dyn AssetDownloader> = Arc::new(FakeDownloader {
        root: dir.clone(),
        payloads: HashMap::from([
            ("geoip-src".to_string(), make_geoip_dat(CODES, ENTRIES)),
            ("geosite-src".to_string(), make_geosite_dat(CODES, ENTRIES)),
        ]),
    });
    let assets = vec![
        GeodataAsset { url: "geoip-src".into(), file: "geoip.dat".into() },
        GeodataAsset { url: "geosite-src".into(), file: "geosite.dat".into() },
    ];
    // 并行下载半边
    let staged =
        download_assets_parallel(&pool, Arc::clone(&dl), &assets).expect("downloads succeed");
    assert_eq!(staged.len(), 2);
    // 串行 swap 半边（swap_all 原样调用，语义零改动）
    let tx = swap::swap_all(&staged).expect("swap_all succeeds");
    assert!(dir.join("geoip.dat").exists());
    assert!(dir.join("geosite.dat").exists());
    tx.commit().expect("commit succeeds");
    // 下载结果可直接被池化加载消费（闭环）
    let results = pool.load_parallel(&dir, &reqs());
    assert!(results.iter().all(|r| r.is_ok()));

    pool.shutdown_join();
    let _ = std::fs::remove_dir_all(&dir);
}
