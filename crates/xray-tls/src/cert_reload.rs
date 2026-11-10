//! 服务端证书热重载（Go `setupOcspTicker` 的非 OCSP 面）。
//!
//! # Go 事实（`D:/Project/Xray-core/transport/internet/tls/config.go:104-136`）
//! - 周期 = **3600 s 常量**（`:110` `hotReloadCertInterval := uint64(3600)`）；条目 `ocspStapling >
//!   0` 时改用该秒数——本仓该字段直接拒启（bd mvmwu），故恒 3600 s。
//! - 变更判定 = **读回来的内容字符串比对**（`:126`），**不看 mtime**。
//! - 读失败 ⇒ `LogErrorInner` 后 `return`（`:117-124`）：旧证书原位保留，但该条目的重读
//!   **永久停止**。本仓改为「失败保留旧证书 + 下个周期继续重试」——运维换文件换到一半、
//!   权限临时丢失都能自愈，且失败必有 warn。
//! - `oneTimeLoading=true` 的条目不 spawn ticker（`:105-107`）；内联证书天然如此。
//!
//! # 托管（CLAUDE.md §3.5.6 ①类）
//! 周期任务不是裸 `tokio::spawn`：它住在 [`ComponentScope`] 账本里，`drain` 即 abort 在途
//! 睡眠任务。装配点 [`start`] 没有 scope 入参（`build_server_config` 有 5 个生产调用点：
//! xray-core inbound + grpc/httpupgrade/hysteria/quic 运输层，签名不可改），故用进程级账本
//! [`PROCESS_SCOPE`]——与 Go 的 goroutine 同寿命，进程内所有入站共享一份。需要组件级范围时
//! 直接调 [`spawn_reload_task`] 传自己的 scope。
//!
//! 定时器为何不用 udf `std_ext::scheduler::Scheduler`：它的生命周期挂在自带工作线程上，
//! 任务不归 [`ComponentScope`] 账本 ⇒ **双份停机账本**（§3.5.6 明禁）。本件在托管任务内
//! 用 `tokio::time::sleep` 轮次推进，随托管任务一起被 abort。

use std::{
    io,
    path::PathBuf,
    sync::{Arc, LazyLock},
    time::Duration,
};

use xray_frame::{hot_slot::HotSlot, scope::ComponentScope};

use crate::server_config::{CertSnapshot, NamedCertKey, named_cert_key_from_files};

/// Go 缺省周期：`transport/internet/tls/config.go:110`（3600 s）。
pub(crate) const DEFAULT_RELOAD_INTERVAL: Duration = Duration::from_secs(3600);

/// 单张服务端证书的重读源。
#[derive(Debug, Clone)]
pub(crate) enum CertEntrySpec {
    /// `certificateFile` + `keyFile`：每个周期重新读盘。
    File { certificate: PathBuf, key: PathBuf },
    /// 内联 PEM / `oneTimeLoading=true`：只在装配期读一次，重载时原样保留。
    Static(NamedCertKey),
}

/// 进程级托管账本（见模块文档「托管」）。
static PROCESS_SCOPE: LazyLock<ComponentScope> =
    LazyLock::new(|| ComponentScope::new("xray_tls::cert_reload"));

/// 重读全部 file 源并整体替换快照。
///
/// 任一源失败 ⇒ `Err` 且**快照不动**（旧证书继续服务）。返回 `Ok(true)` = 内容有变化
/// 已替换；`Ok(false)` = 与当前快照逐张相同（Go `:126` 的内容比对语义）。
pub(crate) fn reload_once(
    slot: &HotSlot<CertSnapshot>,
    specs: &[CertEntrySpec],
) -> io::Result<bool> {
    let mut entries = Vec::with_capacity(specs.len());
    for spec in specs {
        entries.push(match spec {
            CertEntrySpec::Static(entry) => entry.clone(),
            CertEntrySpec::File { certificate, key } => {
                named_cert_key_from_files(certificate, key)?
            },
        });
    }
    let current = slot.current();
    if same_cert_chains(&entries, current.entries()) {
        return Ok(false);
    }
    slot.replace(Arc::new(CertSnapshot::new(entries, current.reject_unknown())));
    Ok(true)
}

/// 逐张比对证书链（叶子 + 中间证书全等才算未变；链变更也要换）。
fn same_cert_chains(a: &[NamedCertKey], b: &[NamedCertKey]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.key.cert == y.key.cert)
}

/// 周期重读任务（托管在 `scope` 内；`scope.drain` 即 abort 睡眠中的任务）。
///
/// # Errors
/// scope 已关闸（停机期拒发）→ `Err`，调用方据此留痕。
pub(crate) fn spawn_reload_task(
    scope: &ComponentScope,
    slot: Arc<HotSlot<CertSnapshot>>,
    specs: Vec<CertEntrySpec>,
    interval: Duration,
) -> io::Result<()> {
    // period 0 会让循环空转（busy spin）；调用方给的都是常量或测试短周期。
    let period = interval.max(Duration::from_millis(1));
    scope
        .spawn(async move {
            loop {
                // 先睡一个周期（对齐 Go `time.NewTicker` 的首次触发时机）；重读本身是
                // 同步短操作，漂移 = 一次读盘耗时。进程被挂起后不会补发积压 tick。
                tokio::time::sleep(period).await;
                match reload_once(&slot, &specs) {
                    Ok(true) => tracing::info!(
                        target: "xray_tls::cert_reload",
                        "server certificate reloaded from disk"
                    ),
                    // 内容未变：Go 同样静默（只有变化才重新装入）。
                    Ok(false) => {},
                    // 重载失败绝不打挂服务：旧证书继续用，下个周期自动重试。
                    Err(e) => tracing::warn!(
                        target: "xray_tls::cert_reload",
                        error = %e,
                        "server certificate reload failed; keeping the previously loaded certificate"
                    ),
                }
            }
        })
        .map(|_| ())
        // 拒发语义（闸已关）只透传文案：`ScopeClosed` 类型在 xray-frame 是私有的。
        .map_err(|_| io::Error::other("certificate reload task rejected: component scope closed"))
}

/// 装配期入口：存在 file 形态条目时启动进程级重读任务。
///
/// 无 tokio runtime（同步上下文/单元测试）时跳过：不能裸造 runtime，也不该让配置
/// 构建失败——证书就是装配期读到的那份，与无热重载时行为一致。
pub(crate) fn start(slot: Arc<HotSlot<CertSnapshot>>, specs: Vec<CertEntrySpec>) {
    if !specs.iter().any(|s| matches!(s, CertEntrySpec::File { .. })) {
        return;
    }
    if tokio::runtime::Handle::try_current().is_err() {
        tracing::debug!(
            target: "xray_tls::cert_reload",
            "no tokio runtime at build time: server certificate hot reload disabled"
        );
        return;
    }
    if let Err(e) = spawn_reload_task(&PROCESS_SCOPE, slot, specs, DEFAULT_RELOAD_INTERVAL) {
        tracing::warn!(
            target: "xray_tls::cert_reload",
            error = %e,
            "certificate hot reload task rejected: certificate stays at its startup value"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::certificate::generate_self_signed_cert;

    /// workspace 外的临时目录（进程 id + tag 隔离，跑完即删）。
    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("xray-tls-reload-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_pair(dir: &Path, cert_pem: &str, key_pem: &str) {
        std::fs::write(dir.join("cert.pem"), cert_pem).unwrap();
        std::fs::write(dir.join("key.pem"), key_pem).unwrap();
    }

    /// 装配期快照 + 重读源（同 `build_named_cert_keys` 的 file 分支）。
    fn setup(dir: &Path) -> (CertSnapshot, Vec<CertEntrySpec>) {
        let spec =
            CertEntrySpec::File { certificate: dir.join("cert.pem"), key: dir.join("key.pem") };
        let entry = named_cert_key_from_files(&dir.join("cert.pem"), &dir.join("key.pem")).unwrap();
        (CertSnapshot::new(vec![entry], false), vec![spec])
    }

    fn leaf(slot: &HotSlot<CertSnapshot>) -> Vec<u8> {
        slot.with(|s| s.entries()[0].key.cert[0].as_ref().to_vec())
    }

    #[test]
    fn reload_picks_up_rewritten_files() {
        let dir = temp_dir("pickup");
        let (cert1, key1) = generate_self_signed_cert(&["localhost"]).unwrap();
        write_pair(&dir, &cert1, &key1);
        let (snapshot, specs) = setup(&dir);
        let before = snapshot.entries()[0].key.cert[0].as_ref().to_vec();
        let slot = HotSlot::new(Arc::new(snapshot));

        // 文件未换：内容一致 ⇒ 不替换
        assert!(!reload_once(&slot, &specs).unwrap());
        assert_eq!(leaf(&slot), before);

        let (cert2, key2) = generate_self_signed_cert(&["localhost"]).unwrap();
        write_pair(&dir, &cert2, &key2);
        assert!(reload_once(&slot, &specs).unwrap(), "换证书必须判定为已变更");
        assert_ne!(leaf(&slot), before, "快照必须换成新证书");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reload_failure_keeps_previous_certificate() {
        let dir = temp_dir("corrupt");
        let (cert1, key1) = generate_self_signed_cert(&["localhost"]).unwrap();
        write_pair(&dir, &cert1, &key1);
        let (snapshot, specs) = setup(&dir);
        let before = snapshot.entries()[0].key.cert[0].as_ref().to_vec();
        let slot = HotSlot::new(Arc::new(snapshot));

        // 最常见的运维失误：换了证书没换私钥 ⇒ 配对校验必须拦住（旧证书继续服务）
        let (other_cert, _other_key) = generate_self_signed_cert(&["localhost"]).unwrap();
        std::fs::write(dir.join("cert.pem"), &other_cert).unwrap();
        let err = reload_once(&slot, &specs).unwrap_err();
        assert!(err.to_string().contains("mismatch"), "证书/私钥必须配对: {err}");
        assert_eq!(leaf(&slot), before, "配对失败必须保留旧证书");

        write_pair(&dir, &cert1, &key1);
        std::fs::write(dir.join("cert.pem"), b"not a pem").unwrap();
        let err = reload_once(&slot, &specs).unwrap_err();
        assert!(
            err.to_string().contains("no PEM certificate block"),
            "解析失败需带定位信息: {err}"
        );
        assert_eq!(leaf(&slot), before, "重载失败必须保留旧证书");

        std::fs::write(dir.join("cert.pem"), b"-----BEGIN CERTIFICATE-----\nzz\n").unwrap();
        assert!(reload_once(&slot, &specs).is_err());
        assert_eq!(leaf(&slot), before, "PEM 损坏也必须保留旧证书");

        std::fs::remove_file(dir.join("cert.pem")).unwrap();
        assert!(reload_once(&slot, &specs).is_err());
        assert_eq!(leaf(&slot), before, "文件消失也必须保留旧证书");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 托管的周期任务随 scope 排空退出（§3.5.6 ①类：`in_flight() == 0`）。
    #[tokio::test]
    async fn reload_task_exits_when_scope_drained() {
        let scope = ComponentScope::new("xray_tls::cert_reload_test");
        let slot = Arc::new(HotSlot::new(Arc::new(CertSnapshot::new(Vec::new(), false))));
        spawn_reload_task(&scope, slot, Vec::new(), Duration::from_millis(20)).unwrap();
        assert_eq!(scope.in_flight(), 1);

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(scope.in_flight(), 1, "周期任务在 scope 关闭前必须持续存活");

        let report = scope.drain(Duration::from_secs(5)).await;
        assert_eq!(report.timed_out, 0, "睡眠中的周期任务必须可被 abort");
        assert_eq!(scope.in_flight(), 0);
    }
}
