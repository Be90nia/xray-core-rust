//! 真机 WFP 验证（**需管理员**）：安装 → 快照 → 卸载 → 复查。
//!
//! 用途：验证 `xray-proxy-tun::wfp::sys` 的 FFI 全链路（引擎打开 / 事务 / 子层 /
//! 各类过滤条件 / 提交 / 关闭即删）在真实 Windows 上跑通。
//!
//! ## 安全
//!
//! 默认用**哑 LUID**（不存在的接口）→ 过滤条件永不命中 → 对本机流量**零影响**。
//! 只有显式传 `--real-luid <n>` 才会绑定真实接口（那时才会真的拦流量）。
//!
//! ## 用法
//!
//! ```bat
//! cargo build --example wfp_live -p xray-proxy-tun
//! target\debug\examples\wfp_live.exe <日志路径> [--real-luid <n>]
//! ```
//!
//! 需管理员：UAC 提权运行（`Start-Process -Verb RunAs`）。

#![allow(
    clippy::disallowed_macros,
    reason = "手工诊断 example：进度直印 stderr 是其唯一输出通道（非生产代码路径）"
)]
// wfp 是 Windows 专有：以下 helper 仅 Windows main 消费，非 Windows stub 单元不参与编译。
#[cfg(target_os = "windows")]
use std::{fs::File, io::Write, process::Command};

/// 日志写入器（带 flush，便于提权进程运行时外部读取）。
#[cfg(target_os = "windows")]
struct Log(File);

#[cfg(target_os = "windows")]
impl Log {
    fn new(path: &str) -> Self {
        let f = File::create(path).expect("create log file");
        Self(f)
    }

    fn line(&mut self, s: &str) {
        writeln!(self.0, "{s}").expect("write log");
        self.0.flush().expect("flush log");
    }
}

/// 统计 `netsh wfp show filters` 输出里出现我们过滤器显示名的次数。
#[cfg(target_os = "windows")]
fn count_our_filters() -> (usize, usize) {
    let out = Command::new("netsh").args(["wfp", "show", "filters"]).output();
    let Ok(out) = out else {
        return (0, 0);
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let ours = text.lines().filter(|l| l.contains("Xray TUN")).count();
    let total = text.lines().filter(|l| l.contains("Filter")).count();
    (ours, total)
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("wfp_live is Windows-only");
}

#[cfg(target_os = "windows")]
fn main() {
    let mut args = std::env::args().skip(1);
    let log_path =
        args.next().unwrap_or_else(|| "reports/night-run-2026-10-20/tmp/wfp_live.log".to_string());
    let mut real_luid: Option<u64> = None;
    while let Some(a) = args.next() {
        if a == "--real-luid" {
            real_luid = args.next().and_then(|v| v.parse().ok());
        }
    }

    let mut log = Log::new(&log_path);
    log.line("== WFP live check start ==");

    let (before_ours, before_total) = count_our_filters();
    log.line(&format!("netsh filters: ours={before_ours} total={before_total}"));

    // 哑 LUID：条件永不命中（除非显式给了真实 LUID）。
    let luid = real_luid.unwrap_or(0x1122_3344_5566_7788);
    log.line(&format!("tun luid = 0x{luid:016x} (real={})", real_luid.is_some()));

    // dns/ipv4/ipv6 三类全开 → 覆盖全部条件类型（appid blob / 端口 u16 / LUID u64 /
    // 安全描述符 blob / u8 / u32 / addr16）。
    let guard = match xray_proxy_tun::wfp::sys::install_with_luid(luid, true, true, true) {
        Ok(g) => {
            log.line("install: OK (engine+transaction+sublayer+filters committed)");
            g
        },
        Err(e) => {
            log.line(&format!("install: FAILED: {e}"));
            log.line("== done (failed) ==");
            std::process::exit(1);
        },
    };

    let (after_ours, after_total) = count_our_filters();
    log.line(&format!("netsh filters after install: ours={after_ours} total={after_total}"));

    log.line("holding filters for 3s ...");
    std::thread::sleep(std::time::Duration::from_secs(3));

    drop(guard);
    log.line("drop guard: engine closed (dynamic session -> filters removed)");

    let (removed_ours, removed_total) = count_our_filters();
    log.line(&format!("netsh filters after drop: ours={removed_ours} total={removed_total}"));
    log.line(&format!(
        "RESULT: installed_visible={} removed_visible={} (both should be 0 if netsh prints display names)",
        after_ours, removed_ours
    ));
    log.line("== WFP live check done ==");
}
