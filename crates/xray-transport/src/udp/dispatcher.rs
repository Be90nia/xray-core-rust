//! # UDP Dispatcher — per-destination NAT 连接跟踪
//!
//! 对应 Go `transport/internet/udp/dispatcher.go`。
//!
//! ## 架构
//!
//! - `ConnEntry` — 单个 UDP NAT 会话（source→dest 映射 + 最后活动时间）
//! - `UdpDispatcher` — 管理所有 ConnEntry，1分钟超时清理
//!
//! Go 的 `Dispatcher` 为每个 (source, destination) 对维护一个 `connEntry`，
//! 包含出站连接和最后活动时间。无活动的 entry 在 1 分钟后被清理。

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{sync::Mutex, task::JoinHandle};

/// UDP NAT 会话超时（对应 Go `udp.Dispatcher.cleanupInterval = 1min`）。
const UDP_NAT_TIMEOUT: Duration = Duration::from_secs(60);

/// 清理检查间隔。
const CLEANUP_INTERVAL: Duration = Duration::from_secs(15);

/// 最大并发 NAT 条目数。
const MAX_NAT_ENTRIES: usize = 4096;

/// NAT 会话 key：(source, destination)。
type NatKey = (SocketAddr, SocketAddr);

// ===== ConnEntry =====

/// 单个 UDP NAT 会话。对应 Go `udp.connEntry`。
///
/// 每个 (source, destination) 对对应一个 ConnEntry，
/// 记录最后活动时间用于超时清理。
pub struct ConnEntry {
    /// 最后活动时间。
    last_activity: Instant,
    /// 出站目标地址。
    destination: SocketAddr,
    /// 来源地址。
    source: SocketAddr,
}

impl ConnEntry {
    /// 创建新的 NAT 会话。
    pub fn new(source: SocketAddr, destination: SocketAddr) -> Self {
        Self { last_activity: Instant::now(), destination, source }
    }

    /// 更新最后活动时间。
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// 是否已过期。
    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > UDP_NAT_TIMEOUT
    }

    /// 来源地址。
    pub fn source(&self) -> SocketAddr {
        self.source
    }

    /// 目标地址。
    pub fn destination(&self) -> SocketAddr {
        self.destination
    }

    /// 最后活动时间。
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }
}

// ===== UdpDispatcher =====

/// UDP NAT Dispatcher。对应 Go `udp.Dispatcher`。
///
/// 管理 per-destination 的 UDP 会话，1分钟超时自动清理。
pub struct UdpDispatcher {
    /// NAT 表：(source, destination) → ConnEntry。
    entries: Arc<Mutex<HashMap<NatKey, ConnEntry>>>,
    /// 清理 task handle。
    cleanup_handle: Option<JoinHandle<()>>,
}

impl UdpDispatcher {
    /// 创建新的 UDP Dispatcher。
    pub fn new() -> Self {
        let entries: Arc<Mutex<HashMap<NatKey, ConnEntry>>> = Arc::new(Mutex::new(HashMap::new()));

        // 启动清理 task。
        let entries_clone = Arc::clone(&entries);
        let handle = tokio::spawn(async move {
            Self::cleanup_loop(entries_clone).await;
        });

        Self { entries, cleanup_handle: Some(handle) }
    }

    /// 注册或刷新一个 NAT 会话。
    ///
    /// 如果 (source, destination) 已存在，更新 last_activity。
    /// 如果不存在，创建新 entry（超容量时返回错误）。
    pub async fn register(&self, source: SocketAddr, destination: SocketAddr) -> io::Result<()> {
        let key = (source, destination);
        let mut entries = self.entries.lock().await;

        if let Some(entry) = entries.get_mut(&key) {
            entry.touch();
            return Ok(());
        }

        // 容量检查。
        if entries.len() >= MAX_NAT_ENTRIES {
            // 先清理过期条目腾出空间。
            let before = entries.len();
            entries.retain(|_, e| !e.is_expired());
            let removed = before - entries.len();
            tracing::debug!(
                before,
                removed,
                after = entries.len(),
                "UDP NAT table full, cleaned expired entries"
            );

            if entries.len() >= MAX_NAT_ENTRIES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("UDP NAT table full ({MAX_NAT_ENTRIES})"),
                ));
            }
        }

        entries.insert(key, ConnEntry::new(source, destination));
        Ok(())
    }

    /// 刷新指定 NAT 会话的活动时间。
    ///
    /// 收到来自该会话的数据时调用。不存在时静默忽略。
    pub async fn touch(&self, source: SocketAddr, destination: SocketAddr) {
        let key = (source, destination);
        let mut entries = self.entries.lock().await;
        if let Some(entry) = entries.get_mut(&key) {
            entry.touch();
        }
    }

    /// 移除指定 NAT 会话。
    pub async fn remove(&self, source: SocketAddr, destination: SocketAddr) {
        let key = (source, destination);
        self.entries.lock().await.remove(&key);
    }

    /// 获取当前 NAT 条目数。
    pub async fn len(&self) -> usize {
        self.entries.lock().await.len()
    }

    /// NAT 表是否为空。
    pub async fn is_empty(&self) -> bool {
        self.entries.lock().await.is_empty()
    }

    /// 查找指定 (source, destination) 的 NAT 会话。
    pub async fn get(&self, source: SocketAddr, destination: SocketAddr) -> Option<SocketAddr> {
        let key = (source, destination);
        let entries = self.entries.lock().await;
        entries.get(&key).map(|e| e.destination)
    }

    /// 清理所有过期条目。返回清理的数量。
    pub async fn cleanup_expired(&self) -> usize {
        let mut entries = self.entries.lock().await;
        let before = entries.len();
        entries.retain(|_, e| !e.is_expired());
        before - entries.len()
    }

    /// 关闭 Dispatcher，停止清理 task。
    pub fn close(&mut self) {
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
        }
    }

    /// 清理循环。
    async fn cleanup_loop(entries: Arc<Mutex<HashMap<NatKey, ConnEntry>>>) {
        loop {
            tokio::time::sleep(CLEANUP_INTERVAL).await;

            let mut guard = entries.lock().await;
            let before = guard.len();
            guard.retain(|_, e| !e.is_expired());
            let removed = before - guard.len();

            if removed > 0 {
                tracing::debug!(
                    before,
                    removed,
                    after = guard.len(),
                    "UDP NAT cleanup: removed expired entries"
                );
            }
        }
    }
}

impl Default for UdpDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for UdpDispatcher {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_creates_entry() {
        let dispatcher = UdpDispatcher::new();
        let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:80".parse().unwrap();

        dispatcher.register(src, dst).await.unwrap();
        assert_eq!(dispatcher.len().await, 1);

        let found = dispatcher.get(src, dst).await;
        assert_eq!(found, Some(dst));
    }

    #[tokio::test]
    async fn register_refreshes_existing() {
        let dispatcher = UdpDispatcher::new();
        let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:80".parse().unwrap();

        dispatcher.register(src, dst).await.unwrap();
        dispatcher.register(src, dst).await.unwrap(); // 刷新
        assert_eq!(dispatcher.len().await, 1); // 仍然是1个
    }

    #[tokio::test]
    async fn touch_updates_activity() {
        let dispatcher = UdpDispatcher::new();
        let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:80".parse().unwrap();

        dispatcher.register(src, dst).await.unwrap();

        // touch 不存在的 key 不会 panic。
        let other: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        dispatcher.touch(other, dst).await;

        // touch 存在的 key 更新活动时间。
        dispatcher.touch(src, dst).await;
        assert_eq!(dispatcher.len().await, 1);
    }

    #[tokio::test]
    async fn remove_deletes_entry() {
        let dispatcher = UdpDispatcher::new();
        let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:80".parse().unwrap();

        dispatcher.register(src, dst).await.unwrap();
        dispatcher.remove(src, dst).await;
        assert_eq!(dispatcher.len().await, 0);
    }

    #[tokio::test]
    async fn expired_entries_cleaned() {
        let dispatcher = UdpDispatcher::new();
        let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:80".parse().unwrap();

        // 手动插入一个已过期的 entry。
        {
            let mut entries = dispatcher.entries.lock().await;
            let mut expired_entry = ConnEntry::new(src, dst);
            // 设置 last_activity 为 2 分钟前（超过 60s 超时）。
            expired_entry.last_activity = Instant::now() - Duration::from_secs(120);
            entries.insert((src, dst), expired_entry);
        }

        assert_eq!(dispatcher.len().await, 1);
        let removed = dispatcher.cleanup_expired().await;
        assert_eq!(removed, 1);
        assert_eq!(dispatcher.len().await, 0);
    }

    #[tokio::test]
    async fn active_entries_not_cleaned() {
        let dispatcher = UdpDispatcher::new();
        let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:80".parse().unwrap();

        dispatcher.register(src, dst).await.unwrap();
        let removed = dispatcher.cleanup_expired().await;
        assert_eq!(removed, 0);
        assert_eq!(dispatcher.len().await, 1);
    }

    #[tokio::test]
    async fn capacity_limit_enforced() {
        let dispatcher = UdpDispatcher::new();

        // 填满到容量。
        for i in 0..MAX_NAT_ENTRIES {
            let src: SocketAddr = format!("127.0.0.1:{i}").parse().unwrap();
            let dst: SocketAddr = "127.0.0.1:80".parse().unwrap();
            dispatcher.register(src, dst).await.unwrap();
        }

        // 下一个应该失败（因为都是新的、未过期的 entry）。
        let src: SocketAddr = "127.0.0.2:1".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let result = dispatcher.register(src, dst).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn close_stops_cleanup_task() {
        let mut dispatcher = UdpDispatcher::new();
        assert!(dispatcher.cleanup_handle.is_some());
        dispatcher.close();
        assert!(dispatcher.cleanup_handle.is_none());
    }
}
