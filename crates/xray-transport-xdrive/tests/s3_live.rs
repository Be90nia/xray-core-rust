//! `s3` 后端**真实云**活体测试（bd yc54c G2——SigV4/分页/对象布局对真实 S3 服务的锚）。
//!
//! 双闸门控（两道都过才真跑）：
//! - `#[ignore]`：需要真实凭据，默认 `cargo test` 不碰；
//! - `XDRIVE_S3_*` 环境变量：缺必填任一 ⇒ 打印缺失清单后 SKIP 返回。
//!
//! env（必填）：`XDRIVE_S3_ENDPOINT`（含 `https://`，如 `https://s3.us-east-1.amazonaws.com`）、
//! `XDRIVE_S3_REGION`、`XDRIVE_S3_BUCKET`、`XDRIVE_S3_ACCESS_KEY`、`XDRIVE_S3_SECRET_KEY`；
//! 可选：`XDRIVE_S3_SESSION_TOKEN`（临时凭据第三元）、`XDRIVE_S3_PATH_STYLE`
//! （`false` = virtual-hosted，缺省 true）。
//!
//! 凭据获取步骤 / 运行命令 / 预期输出：`docs/guides/xdrive-real-backend-checklist.md`。
//! `tests/s3_real_backend.rs` 是 moto（本机 mock S3）锚，本文件是**真实云**锚，互不替代。
//!
//! 脱敏纪律（用户硬约束）：凭据只经环境变量注入，绝不写入日志/断言消息/git——
//! 输出只含前 6 位脱敏前缀。对象随机命名、跑完即删；断言中途失败时打印对象名。
//!
//! 复跑：
//! ```text
//! XDRIVE_S3_ENDPOINT=… XDRIVE_S3_REGION=… XDRIVE_S3_BUCKET=… \
//!   XDRIVE_S3_ACCESS_KEY=… XDRIVE_S3_SECRET_KEY=… \
//!   cargo test -p xray-transport-xdrive --test s3_live -- --ignored --nocapture
//! ```

use std::{
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use xray_frame::compat::clock;
use xray_transport::dialer::StreamSettings;
use xray_transport_xdrive::{
    Config,
    s3::S3Storage,
    storage::{Storage, is_not_found},
};

const REQUIRED_KEYS: [&str; 5] = [
    "XDRIVE_S3_ENDPOINT",
    "XDRIVE_S3_REGION",
    "XDRIVE_S3_BUCKET",
    "XDRIVE_S3_ACCESS_KEY",
    "XDRIVE_S3_SECRET_KEY",
];

/// 单步护栏超时：后端内部已有重试/退避，外层只防整测挂死。
const OP_TIMEOUT: Duration = Duration::from_secs(300);

/// 前 6 位脱敏。
fn mask(v: &str) -> String {
    format!("{}…", v.chars().take(6).collect::<String>())
}

/// 缺任一必填 env → 打印缺失清单并返回 `None`（调用方 SKIP）。
fn required_env() -> Option<[String; 5]> {
    let missing: Vec<&str> =
        REQUIRED_KEYS.iter().copied().filter(|k| std::env::var(k).is_err()).collect();
    if !missing.is_empty() {
        eprintln!(
            "SKIP：缺少环境变量 {missing:?}——凭据获取见 docs/guides/xdrive-real-backend-checklist.md"
        );
        return None;
    }
    Some(REQUIRED_KEYS.map(|k| std::env::var(k).unwrap_or_default()))
}

/// 1MiB 伪随机载荷（xorshift64*；确定性、零新依赖）。
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

/// endpoint 的 host（去 scheme/path；validate 会拒 credentials/query/fragment 形态）。
fn host_of(endpoint: &str) -> &str {
    let rest = endpoint.split_once("://").map_or(endpoint, |(_, r)| r);
    rest.split('/').next().unwrap_or(rest)
}

/// endpoint 为 `http://`（本机 MinIO/moto 类）时不加 TLS；`https://` 加 TLS + ALPN h2。
fn live_settings(
    endpoint: &str,
    region: &str,
    bucket: &str,
    path_style: bool,
    secrets: &[String],
) -> StreamSettings {
    let host = host_of(endpoint);
    let mut settings = serde_json::json!({
        "network": "xdrive",
        "xdriveSettings": {
            "service": "s3",
            "remoteFolder": "xdrive-live",
            "secrets": secrets,
            "segmentBytes": 262144,
            "pollIntervalMs": 5,
            "maxPollIntervalMs": 50,
            "s3": {"endpoint": endpoint, "region": region, "bucket": bucket, "pathStyle": path_style},
        },
    });
    if endpoint.starts_with("https://") {
        settings["security"] = serde_json::json!("tls");
        settings["tlsSettings"] = serde_json::json!({"serverName": host, "alpn": ["h2"]});
    }
    StreamSettings::from_json(Some(&settings))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需真实凭据：见 docs/guides/xdrive-real-backend-checklist.md（XDRIVE_S3_* 环境变量）"]
async fn s3_roundtrip_1mib() {
    let Some([endpoint, region, bucket, access_key, secret_key]) = required_env() else {
        return;
    };
    let token = std::env::var("XDRIVE_S3_SESSION_TOKEN").unwrap_or_default();
    let path_style =
        std::env::var("XDRIVE_S3_PATH_STYLE").is_ok_and(|v| !v.eq_ignore_ascii_case("false"));
    eprintln!(
        "S3 活体：endpoint={endpoint} region={region} bucket={bucket} path_style={path_style} \
         access_key={} secret_key={} session_token={}",
        mask(&access_key),
        mask(&secret_key),
        mask(&token),
    );

    let mut secrets = vec![access_key, secret_key];
    if !token.is_empty() {
        secrets.push(token);
    }
    let settings = live_settings(&endpoint, &region, &bucket, path_style, &secrets);
    let config = Config::from_settings(&settings).expect("config from settings");
    let storage: Arc<dyn Storage> =
        Arc::new(S3Storage::new(&settings, &config).expect("S3Storage"));

    let base = format!(
        "live-{}-{}",
        clock().now_system().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        std::process::id(),
    );
    let name = format!("xdrive-live/{base}.seg");
    let payload = payload_1mib();
    eprintln!("对象名：{name}（断言失败时请手工删除该残件）");

    let outcome = roundtrip(storage.as_ref(), &name, &payload).await;
    // 失败也清理：不给用户桶里留垃圾对象（成功路径已在 roundtrip 内删除）。
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
