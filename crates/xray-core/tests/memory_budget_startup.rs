//! bd azcoe：装配期内存预算门——超预算配置必须**拒启**（fail-visible）。
//!
//! 验收面：`start_full`（默认可执行文件的启动链路，run.rs:262）对超出
//! [`xray_core::memory_budget::MAX_PER_CONN_BUFFER_BYTES`] 或无界（-1）的
//! per-connection buffer 配置，在装配任何实例/监听器之前返回点名违例项的错误。

use xray_conf::{BuiltConfig, BuiltEntry};
use xray_core::functions::start_full;

/// policy level bufferSize（KB）= 256 MiB/方向：96MB 预算下一条连接即超支。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_full_rejects_overbudget_per_conn_buffer() {
    let mut built = BuiltConfig::default();
    built.apps.push(BuiltEntry {
        kind: "policy".into(),
        data: br#"{"levels": {"0": {"bufferSize": 262144}}}"#.to_vec(),
    });

    let err = match start_full(&built).await {
        Ok(_) => panic!("超预算配置必须拒启（bd azcoe 铁律③ fail-fast）"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("memory budget exceeded"), "错误必须点名预算门：{msg}");
    assert!(msg.contains("policy level 0"), "错误必须点名违例 level：{msg}");
}

/// bufferSize = -1（无界，Go 同源显式坑 audit4-memory F8）必须拒启。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_full_rejects_unbounded_per_conn_buffer() {
    let mut built = BuiltConfig::default();
    built.apps.push(BuiltEntry {
        kind: "policy".into(),
        data: br#"{"levels": {"3": {"bufferSize": -1}}}"#.to_vec(),
    });

    let err = match start_full(&built).await {
        Ok(_) => panic!("无界 per-connection buffer 必须拒启（bd azcoe 铁律③）"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("memory budget exceeded"), "错误必须点名预算门：{msg}");
    assert!(msg.contains("unbounded"), "错误必须点名无界：{msg}");
}

/// 合法配置（缺省 policy + 常规 bufferSize）必须过门——防预算门误伤正常启动。
/// 完整的正常启动面由既有 e2e（start_full socks→freedom 等）持续覆盖。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_full_accepts_sane_per_conn_buffer() {
    let mut built = BuiltConfig::default();
    built.apps.push(BuiltEntry {
        kind: "policy".into(),
        data: br#"{"levels": {"0": {"bufferSize": 512}}}"#.to_vec(),
    });

    let (_, _ohm, handles) =
        start_full(&built).await.expect("合法 bufferSize（512KB = x86 缺省）必须过预算门");
    assert!(handles.is_empty(), "无 inbound 配置 ⇒ 无监听任务");
}
