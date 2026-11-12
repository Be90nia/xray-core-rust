//! `google-drive` 后端**真实云**活体测试（bd yc54c G2——B4「真实云未验」缺口的收口件）。
//!
//! 双闸门控（两道都过才真跑）：
//! - `#[ignore]`：需要真实凭据，默认 `cargo test` 不碰；
//! - `XDRIVE_DRIVE_*` 环境变量：缺任一 ⇒ 打印缺失清单后 SKIP 返回。
//!
//! 凭据获取步骤 / 运行命令 / 预期输出：`docs/guides/xdrive-real-backend-checklist.md`。
//!
//! 脱敏纪律（用户硬约束）：凭据只经环境变量注入，绝不写入日志/断言消息/git——
//! 输出只含前 6 位脱敏前缀。对象随机命名、跑完即删；断言中途失败时打印对象名，
//! 便于在 Drive 文件夹里手工清理残件。
//!
//! 复跑：
//! ```text
//! XDRIVE_DRIVE_CLIENT_ID=… XDRIVE_DRIVE_CLIENT_SECRET=… \
//!   XDRIVE_DRIVE_REFRESH_TOKEN=… XDRIVE_DRIVE_FOLDER_ID=… \
//!   cargo test -p xray-transport-xdrive --test drive_live -- --ignored --nocapture
//! ```

use std::{
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use xray_frame::compat::clock;
use xray_transport::dialer::StreamSettings;
use xray_transport_xdrive::{
    Config, DriveStorage,
    storage::{Storage, is_not_found},
};

const ENV_KEYS: [&str; 4] = [
    "XDRIVE_DRIVE_CLIENT_ID",
    "XDRIVE_DRIVE_CLIENT_SECRET",
    "XDRIVE_DRIVE_REFRESH_TOKEN",
    "XDRIVE_DRIVE_FOLDER_ID",
];

/// 单步护栏超时：后端内部已有重试/退避，外层只防整测挂死。
const OP_TIMEOUT: Duration = Duration::from_secs(300);

/// 前 6 位脱敏。
fn mask(v: &str) -> String {
    format!("{}…", v.chars().take(6).collect::<String>())
}

/// 缺任一 env → 打印缺失清单并返回 `None`（调用方 SKIP）。
fn env_or_skip() -> Option<[String; 4]> {
    let missing: Vec<&str> =
        ENV_KEYS.iter().copied().filter(|k| std::env::var(k).is_err()).collect();
    if !missing.is_empty() {
        eprintln!(
            "SKIP：缺少环境变量 {missing:?}——凭据获取见 docs/guides/xdrive-real-backend-checklist.md"
        );
        return None;
    }
    Some(ENV_KEYS.map(|k| std::env::var(k).unwrap_or_default()))
}

/// 1MiB 伪随机载荷（xorshift64*；确定性、零新依赖，随机性压平中间层缓存/去重）。
fn payload_1mib() -> Vec<u8> {
    let mut s = 0x9E37_79B9_7F4A_7C15u64 ^ (std::process::id() as u64).wrapping_mul(0x2545_F491);
    let mut v = Vec::with_capacity(1024 * 1024);
    for _ in 0..1024 * 1024 {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        v.push((s >> 24) as u8);
    }
    v
}

/// 直连生产端点：TLS（rustls 内置 webpki 根，验真 Google 证书）+ ALPN h2。
/// 会话级小段/快轮询加速 1MiB 往返与失败暴露。
fn live_settings(secrets: &[String; 3], folder: &str) -> StreamSettings {
    StreamSettings::from_json(Some(&serde_json::json!({
        "network": "xdrive",
        "security": "tls",
        "tlsSettings": {"serverName": "www.googleapis.com", "alpn": ["h2"]},
        "xdriveSettings": {
            "service": "google-drive",
            "remoteFolder": folder,
            "secrets": secrets,
            "segmentBytes": 262144,
            "pollIntervalMs": 5,
            "maxPollIntervalMs": 50,
        },
    })))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需真实凭据：见 docs/guides/xdrive-real-backend-checklist.md（XDRIVE_DRIVE_* 环境变量）"]
async fn drive_roundtrip_1mib() {
    let Some([client_id, client_secret, refresh_token, folder]) = env_or_skip() else {
        return;
    };
    eprintln!(
        "Drive 活体：client_id={} client_secret={} refresh_token={} folder={}",
        mask(&client_id),
        mask(&client_secret),
        mask(&refresh_token),
        mask(&folder),
    );

    let settings = live_settings(&[client_id, client_secret, refresh_token], &folder);
    let config = Config::from_settings(&settings).expect("config from settings");
    let storage: Arc<dyn Storage> =
        Arc::new(DriveStorage::new(&settings, &config).expect("DriveStorage"));

    let base = format!(
        "live-{}-{}",
        clock().now_system().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        std::process::id(),
    );
    let name = format!("xdrive-live/{base}.seg");
    let payload = payload_1mib();
    eprintln!("对象名：{name}（断言失败时请手工删除该残件）");

    let outcome = roundtrip(storage.as_ref(), &name, &payload).await;
    // 失败也清理：不给用户云端留垃圾对象（成功路径已在 roundtrip 内删除）。
    if outcome.is_err() {
        let _ = tokio::time::timeout(OP_TIMEOUT, storage.delete(&name)).await;
    }
    outcome.expect("1MiB roundtrip");
}

/// put → get（1MiB 逐字节）→ list 含对象 → delete → get NotFound。
async fn roundtrip(storage: &dyn Storage, name: &str, payload: &[u8]) -> std::io::Result<()> {
    tokio::time::timeout(OP_TIMEOUT, async {
        storage.put(name, payload).await?;
        let got = storage.get(name).await?;
        assert_eq!(got.len(), payload.len(), "get 长度不一致");
        assert!(got == payload, "1MiB 往返内容不一致");

        let (dir, file) = name.rsplit_once('/').unwrap_or(("", name));
        let entries = storage.list(dir).await?;
        assert!(
            entries.iter().any(|e| e.name == file),
            "list({dir}) 缺少 {file}，实得 {:?}",
            entries.iter().map(|e| &e.name).collect::<Vec<_>>(),
        );

        storage.delete(name).await?;
        match storage.get(name).await {
            Err(e) if is_not_found(&e) => Ok(()),
            other => panic!("delete 后 get 应 NotFound，实得 {other:?}"),
        }
    })
    .await
    .map_err(|_| {
        std::io::Error::other(format!("roundtrip 超过 {OP_TIMEOUT:?}（网络或凭据问题）"))
    })?
}
