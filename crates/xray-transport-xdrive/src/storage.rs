//! `Storage` 契约 + 构造分派 + 共享实例表。对应 Go `storage.go`。
//!
//! 归属（规划 §4.1）：对象名布局是 xdrive 的 wire 契约 → 协议方向件留本 crate。
//! [`SlotStore`] 是 B5 环形槽位的 trait 形态（Go `slotStore`）；B1 仅落形态与
//! 判定位，Drive 实现 B4 落、环形槽方法 B5 填。

use std::{collections::HashMap, io, sync::Arc};

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::{config::Config, local::LocalStorage};

/// 临时件命名前缀：resolve 拒写、list 滤除（Go `tempPrefix`；Put 的临时件与
/// fsx 崩溃残留隔离于对象命名空间之外）。
pub const TEMP_PREFIX: &str = ".xdrive-tmp-";

/// 单条 list 结果（Go `Entry`）。`inline` 只有槽位/announce 内联载荷才有值；
/// local 后端恒 `None`。
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub inline: Option<Vec<u8>>,
}

/// 对象存储后端契约（Go `Storage` 接口）。
///
/// 取消语义：Go 每方法带 ctx；Rust 侧取消由任务层的 scope 令牌表达（存储操作
/// 本身是短临界区，后端内部再处理各自的重试/预算——B2+ 云后端）。
#[async_trait]
pub trait Storage: Send + Sync {
    async fn put(&self, name: &str, data: &[u8]) -> io::Result<()>;

    /// 缺失 → [`ErrorKind::NotFound`](std::io::ErrorKind)（对齐 Go `errNotFound`
    /// 哨兵；调用方用 [`is_not_found`] 判定）。
    async fn get(&self, name: &str) -> io::Result<Vec<u8>>;

    async fn delete(&self, name: &str) -> io::Result<()>;

    /// 列出 prefix 一级目录下的条目（名不含路径；Go `os.ReadDir` 单级语义，
    /// 名称按字典序）。
    async fn list(&self, prefix: &str) -> io::Result<Vec<Entry>>;

    async fn close(&self) -> io::Result<()>;

    /// 会话视图（Go `sessionStorage`）：云后端返回绑定 XMUX 连接池的会话存储
    /// （模板/token/缓存共享，连接面独立、`close` 归还池记账）；local 无连接
    /// 面 → `None`（原样返回）。
    fn session(&self) -> Option<Arc<dyn Storage>> {
        None
    }

    /// 槽位能力判定位（Go `storage.(slotStore)` 类型断言的等价口）。
    /// 仅 google-drive（B4）返回 `Some`。
    fn as_slot_store(&self) -> Option<&dyn SlotStore> {
        None
    }
}

/// 环形槽位存储契约（Go `slotStore`）。B5 填 `makeRing`/`setSlot`/`getSlot`；
/// B1 只落 trait 形态供 `Params::for_storage` 判定。
pub trait SlotStore: Send + Sync {}

/// 「对象不存在」哨兵（Go `errNotFound`）。
pub fn not_found() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "object not found")
}

/// 是否「对象不存在」（Go `err == errNotFound` 判定）。
#[must_use]
pub fn is_not_found(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
}

/// 按流设置构造后端（Go `newStorage`）。
///
/// `local` 直建；`template` 经共享实例表去重（Go `sharedStorage`）——dial/serve
/// 同配置共享同一后端与 XMUX 连接池；`s3`/`google-drive` 随 B3/B4 接入。
pub fn new_storage(
    settings: &xray_transport::dialer::StreamSettings,
) -> io::Result<Arc<dyn Storage>> {
    // Go `testStorageFactory`：测试替换后端工厂（生产恒 None）。
    let factory = TEST_FACTORY.read().clone();
    if let Some(factory) = factory {
        return factory(settings);
    }
    let config = Config::from_settings(settings)?;
    match config.service.as_str() {
        "local" => Ok(Arc::new(LocalStorage::new(&config.remote_folder)?)),
        "google-drive" | "Google Drive" => shared_storage(Some(settings), &config, || {
            Ok(Arc::new(crate::drive::DriveStorage::new(settings, &config)?))
        }),
        "template" => shared_storage(Some(settings), &config, || {
            Ok(Arc::new(crate::template::TemplateStorage::new(settings, &config)?))
        }),
        // s3 分派臂：XdriveB3 移交（bd hjtlk B3；构造在 S3Storage::new 内 fail-visible）。
        "s3" => shared_storage(Some(settings), &config, || {
            Ok(Arc::new(crate::s3::S3Storage::new(settings, &config)?))
        }),
        other => Err(io::Error::other(format!("unsupported service: {other}"))),
    }
}

// ── 测试替换工厂（Go `testStorageFactory`）────────────────────────────────
//
// Go：`atomic.Pointer[func(config) (Storage, error)]`，nil in production。Rust 面
// 以进程级 RwLock<Option<Arc<dyn Fn>>> 承载；仅集成测试注入（dial/serve →
// new_storage 的入口替换），`reset_test_storage_factory` 收尾恢复。

type TestStorageFactory = Arc<
    dyn Fn(&xray_transport::dialer::StreamSettings) -> io::Result<Arc<dyn Storage>> + Send + Sync,
>;

static TEST_FACTORY: std::sync::LazyLock<parking_lot::RwLock<Option<TestStorageFactory>>> =
    std::sync::LazyLock::new(|| parking_lot::RwLock::new(None));

/// 注册测试替换工厂（Go `testStorageFactory.Store` 的等价面；仅测试注入）。
#[doc(hidden)]
pub fn set_test_storage_factory(factory: TestStorageFactory) {
    *TEST_FACTORY.write() = Some(factory);
}

/// 撤销测试替换工厂（Go 测试 cleanup 恢复 nil 的等价面）。
#[doc(hidden)]
pub fn reset_test_storage_factory() {
    *TEST_FACTORY.write() = None;
}

/// 会话存储（Go `sessionStorage`）：云后端返回会话视图（走 XMUX 连接池），
/// 其余原样返回（Dial 每会话、Listener 每接受连接各取一次）。
#[must_use]
pub fn session_storage(storage: Arc<dyn Storage>) -> Arc<dyn Storage> {
    storage.session().unwrap_or(storage)
}

// ── 共享实例表（Go `shared`/`sharedStorage`/`shareKey`/`resetSharedStorage`）──
//
// 云后端按 share_key 进程级去重（token/连接复用）：B2 起 `template` 分派臂消费
// （`new_storage`），dial 与 serve 同配置共享同一后端实例与 XMUX 连接池。

static SHARED: std::sync::LazyLock<parking_lot::Mutex<HashMap<String, Arc<dyn Storage>>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

/// 共享实例去重键（Go `shareKey`）：service/remoteFolder/s3 三元/secrets/
/// security 类型/destination 以 `\0` 连接后 sha256 hex（禁 FNV/XXH——非加密摘要
/// 做凭据键会引入可碰撞面）。
#[must_use]
pub fn share_key(
    settings: Option<&xray_transport::dialer::StreamSettings>,
    config: &Config,
) -> String {
    let mut parts: Vec<String> = vec![config.service.clone(), config.remote_folder.clone()];
    if let Some(s3) = config.s3.as_ref() {
        // s3 子对象 B3 才强类型化；去重键按 Go 字段直读（缺省空串 + region 缺省）。
        let get = |k: &str| s3.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let path_style = s3.get("pathStyle").and_then(|v| v.as_bool()).unwrap_or(false);
        parts.push(get("endpoint"));
        parts.push(if get("region").is_empty() { "us-east-1".to_string() } else { get("region") });
        parts.push(get("bucket"));
        parts.push(if path_style { "path-style" } else { "virtual-hosted-style" }.to_string());
    }
    parts.extend(config.secrets.iter().cloned());
    if let Some(settings) = settings {
        parts.push(settings.security.clone());
        if let Some((address, port)) = settings.fronting.as_ref() {
            parts.push(format!("{address}:{port}"));
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(parts.join("\x00"));
    let sum = hasher.finalize();
    std_ext::encode::hex_encode(&sum, std_ext::encode::HexCase::Lower)
}

/// 进程级共享实例获取（Go `sharedStorage`）：命中即复用，未命中 build 后入表。
pub fn shared_storage(
    settings: Option<&xray_transport::dialer::StreamSettings>,
    config: &Config,
    build: impl FnOnce() -> io::Result<Arc<dyn Storage>>,
) -> io::Result<Arc<dyn Storage>> {
    let key = share_key(settings, config);
    let mut table = SHARED.lock();
    if let Some(storage) = table.get(&key) {
        return Ok(Arc::clone(storage));
    }
    let storage = build()?;
    table.insert(key, Arc::clone(&storage));
    Ok(storage)
}

/// 清空共享实例表（Go `resetSharedStorage`；测试隔离用）。
pub fn reset_shared_storage() {
    SHARED.lock().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(service: &str, folder: &str) -> Config {
        Config {
            service: service.to_string(),
            remote_folder: folder.to_string(),
            ..Config::default()
        }
    }

    #[test]
    fn share_key_distinguishes_service_and_folder() {
        let a = share_key(None, &config("local", "/tmp/a"));
        let b = share_key(None, &config("local", "/tmp/b"));
        let c = share_key(None, &config("s3", "/tmp/a"));
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn share_key_covers_secrets_and_security() {
        let mut with_secret = config("local", "/x");
        with_secret.secrets = vec!["tok".to_string()];
        let base = share_key(None, &config("local", "/x"));
        let sec = share_key(None, &with_secret);
        let mut settings = xray_transport::dialer::StreamSettings::tcp();
        settings.security = "tls".to_string();
        let tls = share_key(Some(&settings), &config("local", "/x"));
        assert_ne!(base, sec);
        assert_ne!(base, tls);
    }

    #[test]
    fn shared_storage_reuses_instance() {
        reset_shared_storage();
        let root = std::env::temp_dir().join(format!("xdrive-shared-{}", std::process::id()));
        let c = config("local", root.to_string_lossy().as_ref());
        let first = shared_storage(None, &c, || Ok(Arc::new(LocalStorage::new(&c.remote_folder)?)))
            .unwrap();
        let second =
            shared_storage(None, &c, || panic!("build must not run for a cached key")).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        reset_shared_storage();
        let _ = std::fs::remove_dir_all(root);
    }
}
