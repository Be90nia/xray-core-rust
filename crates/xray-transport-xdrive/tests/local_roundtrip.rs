//! `local` 后端端到端行为锚（规划 §6 门 B1）：
//! 1. dial→serve（真注册面/真配置面）→1MiB 双向逐字节相等→双侧关闭→ streams/<sid> 被 collector
//!    回收；
//! 2. Windows `ERROR_SHARING_VIOLATION` 读重试真机用例（Go 556767e4 语义）。

use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::mpsc,
};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_transport::{
    connection::Connection, dialer::StreamSettings, listener_registry::ConnHandler,
};
use xray_transport_xdrive::{LocalStorage, dial, serve, storage::Storage};

fn temp_root(tag: &str) -> String {
    std::env::temp_dir()
        .join(format!("xdrive-roundtrip-{}-{tag}", std::process::id()))
        .to_string_lossy()
        .into_owned()
}

/// 最小 xdrive 出站/入站配置（B0 放开后的 streamSettings 直通形态）：
/// local 后端 + 小段/快轮询/短 TTL（collector 收口判据秒级可观测）。
fn test_settings(root: &str) -> StreamSettings {
    StreamSettings::from_json(Some(&serde_json::json!({
        "network": "xdrive",
        "xdriveSettings": {
            "service": "local",
            "remoteFolder": root,
            "segmentBytes": 65536,
            "flushIntervalMs": 5,
            "pollIntervalMs": 5,
            "maxPollIntervalMs": 50,
            "sessionTtlSeconds": 1,
            "concurrency": 8
        }
    })))
}

/// 用例 1：dial→serve→1MiB 双向逐字节相等→collector 回收 streams/<sid>。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_roundtrip_1mib_and_collector_reclaim() {
    let root = temp_root("e2e");
    let storage: Arc<dyn Storage> = Arc::new(LocalStorage::new(&root).unwrap());
    let settings = test_settings(&root);

    // serve（生产入口）：accept 到的连接进 channel。
    let (conn_tx, mut conn_rx) = mpsc::channel::<Box<dyn Connection>>(4);
    let handler: ConnHandler = Arc::new(move |conn| {
        // 满载即随 drop 走兜底关闭序（测试面单会话，通道容量恒够）。
        let _ = conn_tx.try_send(conn);
    });
    let listener =
        serve("127.0.0.1:0".parse().unwrap(), settings.clone(), Default::default(), handler)
            .await
            .unwrap();
    assert_eq!(
        listener.local_addr().unwrap().to_string(),
        "127.0.0.1:0",
        "local_addr must echo the configured addr (no real bind)"
    );

    // 出站侧：真 dial（配置解析 + announce 投递 + WAL Conn）。
    let dest = Destination::new(Address::new_domain("xdrive.test"), Port::new(443), Network::TCP);
    let mut client = dial(&dest, &Default::default(), &settings).await.unwrap();

    // 入站侧 accept（announce → claim → Conn 交付）。
    let mut server = tokio::time::timeout(Duration::from_secs(10), conn_rx.recv())
        .await
        .expect("listener must accept the announced session in time")
        .expect("handler channel closed");

    // 1MiB 上行：客户端写 → 服务端读，逐字节相等。
    let payload: Vec<u8> = (0..1024 * 1024usize).map(|i| (i * 7 % 251) as u8).collect();
    client.write_all(&payload).await.unwrap();
    let mut received = vec![0u8; payload.len()];
    server.read_exact(&mut received).await.unwrap();
    assert_eq!(received, payload, "1MiB uplink must arrive byte-equal");

    // 1MiB 下行：服务端回写 → 客户端读。
    server.write_all(&received).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload, "1MiB downlink must arrive byte-equal");

    // 双侧关闭（Go Close 序：冲净 + `.end` → 对端 EOF）。
    client.shutdown().await.unwrap();
    server.shutdown().await.unwrap();

    // streams/<sid> 被 collector 回收：TTL 1s + collect 间隔 0.5s + 首见等待，
    // 给 8s 余量轮询 streams 目录直到空。
    let mut reclaimed = false;
    for _ in 0..80 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if storage.list("streams").await.unwrap().is_empty() {
            reclaimed = true;
            break;
        }
    }
    assert!(reclaimed, "collector must reclaim streams/ after both conns closed");

    listener.close().unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

// ── Windows 共享冲突读重试（真机） ───────────────────────────────────────────

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn windows_sharing_violation_read_retries() {
    use std::os::windows::fs::OpenOptionsExt;

    let root = temp_root("sharing");
    let storage = LocalStorage::new(&root).unwrap();
    let name = "streams/sv/c2s/000000000.seg";
    storage.put(name, b"segment-payload").await.unwrap();

    // 复现 Go 556767e4 的冲突方向：把柄方持 DELETE 访问权且不与 DELETE 共享
    //（access = GENERIC_WRITE|DELETE；share = READ|WRITE）——std 读方请求
    // FILE_SHARE_DELETE，在该把柄下 open 撞 ERROR_SHARING_VIOLATION(32)。
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const DELETE: u32 = 0x0001_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    let full = std::path::Path::new(&root).join("streams/sv/c2s/000000000.seg");
    let holder = std::fs::OpenOptions::new()
        .write(true)
        .access_mode(GENERIC_WRITE | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&full)
        .unwrap();

    // 300ms 后释放把柄（重试窗 2s 内），get 的重试环须骑过冲突拿到数据。
    let releaser = tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(300));
        drop(holder);
    });
    let data = storage.get(name).await.expect("retry loop must ride out the violation");
    assert_eq!(data, b"segment-payload");
    assert!(releaser.await.is_ok(), "releaser must not panic");

    let _ = std::fs::remove_dir_all(&root);
}

/// 非 Windows：无重试环的直读路径——缺失 → NotFound 哨兵（编译冒烟）。
#[cfg(not(windows))]
#[tokio::test]
async fn plain_read_maps_missing_to_not_found() {
    use std::io;

    let root = temp_root("plain");
    let storage = LocalStorage::new(&root).unwrap();
    let err = storage.get("streams/none/000000000.seg").await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
    let _ = std::fs::remove_dir_all(&root);
}
