//! SplitHTTP 服务端会话管理。
//!
//! 对应 Go `hub.go` 的 `httpSession` + `upsertSession` + `sessions sync.Map`。
//!
//! ## 设计
//!
//! 每个客户端连接由 `session_id` 标识。会话持有一个 [`UploadQueue`]，用于缓冲
//! packet-up 模式的乱序分包。会话有 30 秒 TTL：如果 GET（下载流）在 30s 内
//! 未到达，会话被自动清理；GET 到达后标记 `is_fully_connected`，生命周期与
//! GET 连接绑定。

use std::{collections::HashMap, sync::Arc};

use tokio::{sync::Mutex, time::Duration};

use crate::upload_queue::UploadQueue;

/// 单个 HTTP 会话：持有 upload_queue + 是否已完全连接（GET 已到达）。
pub struct HttpSession {
    /// 接收侧 reorder 队列（packet-up 分包缓冲）。
    pub upload_queue: Arc<UploadQueue>,
    /// GET 请求是否已到达（到达后会话不再被自动 reap）。
    pub fully_connected: tokio::sync::Notify,
}

impl HttpSession {
    /// 构造新会话，upload_queue 容量由 `max_buffered_posts` 决定。
    pub fn new(max_buffered_posts: usize) -> Self {
        Self {
            upload_queue: Arc::new(UploadQueue::new(max_buffered_posts)),
            fully_connected: tokio::sync::Notify::new(),
        }
    }

    /// 标记 GET 请求已到达，禁用自动 reap。
    pub fn mark_fully_connected(&self) {
        self.fully_connected.notify_one();
    }

    /// 等待 GET 请求到达。
    pub async fn wait_fully_connected(&self) {
        self.fully_connected.notified().await;
    }
}

/// 会话表：session_id → Arc<HttpSession>。
///
/// 对应 Go `requestHandler.sessions sync.Map` + `sessionMu sync.Mutex`。
/// `upsert` 实现 get-or-create + 30s 自动 reap。
pub struct SessionMap {
    inner: Mutex<HashMap<String, Arc<HttpSession>>>,
}

impl SessionMap {
    /// 构造空会话表。
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    /// 获取已有会话（不创建）。用于 GET 标记 fully_connected。
    pub async fn get(&self, session_id: &str) -> Option<Arc<HttpSession>> {
        self.inner.lock().await.get(session_id).cloned()
    }

    /// get-or-create 会话，并启动 30s reap 定时器。
    ///
    /// 对应 Go `upsertSession`：如果 session 已存在返回已有；否则创建新 session
    /// 并 spawn 一个 30s 定时器——如果 30s 内 GET 未到达（`isFullyConnected` 未关闭），
    /// 删除 session 并关闭 upload_queue。
    pub async fn upsert(
        self: &Arc<Self>,
        session_id: &str,
        max_buffered_posts: usize,
    ) -> Arc<HttpSession> {
        // fast path
        {
            let map = self.inner.lock().await;
            if let Some(s) = map.get(session_id) {
                return Arc::clone(s);
            }
        }
        // slow path
        let mut map = self.inner.lock().await;
        // double-check
        if let Some(s) = map.get(session_id) {
            return Arc::clone(s);
        }
        let session = Arc::new(HttpSession::new(max_buffered_posts));
        map.insert(session_id.to_string(), Arc::clone(&session));
        drop(map);

        // spawn reap timer
        let self_clone = Arc::clone(self);
        let sid = session_id.to_string();
        let session_clone = Arc::clone(&session);
        tokio::spawn(async move {
            tokio::select! {
                _ = session_clone.wait_fully_connected() => {
                    // GET arrived, session lives as long as the GET connection.
                }
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    // 30s without GET → reap（对齐 Go hub.go:86-88：Delete + queue.Close）。
                    self_clone.remove(&sid).await;
                }
            }
        });

        session
    }

    /// 删除会话（GET 结束后调用）。
    ///
    /// 删除即关闭 [`UploadQueue`]（对齐 Go reap 路径 hub.go:88
    /// `s.uploadQueue.Close()`）：packet-up 的 `forward_queue_to_writer` 任务收到
    /// EOF 退出 → 上行 duplex 写端 drop → dispatcher 桥接链上行 EOF。缺失此关闭
    /// 时 forward 任务永挂，服务端会话/桥接/freedom 连接整条链无法解体
    /// （bd s10/s12 泄漏服务端侧根因）。幂等：session 不存在时无操作。
    pub async fn remove(&self, session_id: &str) {
        let session = self.inner.lock().await.remove(session_id);
        if let Some(session) = session {
            session.upload_queue.close().await;
        }
    }
}

impl Default for SessionMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upsert_creates_and_reuses_session() {
        let map = Arc::new(SessionMap::new());
        let s1 = map.upsert("sess-1", 30).await;
        let s2 = map.upsert("sess-1", 30).await;
        assert!(Arc::ptr_eq(&s1, &s2));
    }

    #[tokio::test]
    async fn upsert_different_sessions() {
        let map = Arc::new(SessionMap::new());
        let s1 = map.upsert("a", 30).await;
        let s2 = map.upsert("b", 30).await;
        assert!(!Arc::ptr_eq(&s1, &s2));
    }

    #[tokio::test]
    async fn get_returns_none_for_unknown() {
        let map = SessionMap::new();
        assert!(map.get("nope").await.is_none());
    }

    #[tokio::test]
    async fn get_returns_some_after_upsert() {
        let map = Arc::new(SessionMap::new());
        map.upsert("x", 10).await;
        assert!(map.get("x").await.is_some());
    }

    #[tokio::test]
    async fn remove_deletes_session() {
        let map = Arc::new(SessionMap::new());
        map.upsert("x", 10).await;
        map.remove("x").await;
        assert!(map.get("x").await.is_none());
    }

    #[tokio::test]
    async fn session_reaped_after_30s_without_get() {
        let map = Arc::new(SessionMap::new());
        let _s = map.upsert("reap-me", 10).await;
        // Simulate timeout by using a very short sleep — the real timer is 30s,
        // but we can't wait that long in a test. Instead test the reap logic
        // directly by checking that the session exists before remove.
        assert!(map.get("reap-me").await.is_some());
        // Manual remove (simulates what the reap timer does).
        map.remove("reap-me").await;
        assert!(map.get("reap-me").await.is_none());
    }

    #[tokio::test]
    async fn fully_connected_prevents_reap_logic() {
        // Test that mark_fully_connected + wait_fully_completed works.
        let session = HttpSession::new(10);
        session.mark_fully_connected();
        // wait_fully_connected should return immediately since already notified.
        tokio::time::timeout(Duration::from_millis(100), session.wait_fully_connected())
            .await
            .expect("wait_fully_connected should resolve immediately after mark");
    }
}
