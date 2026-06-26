//! Channel 实现。
//!
//! 对应 Go `app/stats/channel.go`：
//! - `Channel struct { channel chan channelMessage; subscribers []chan interface{}; ... }`
//! - `Publish` 写入 publisher mpsc → 内部 goroutine 读 → 广播到 subscribers
//! - `Subscribe` / `Unsubscribe` 管理订阅列表
//! - `Start` 启动 broadcast goroutine；`Close` 关闭信号 + 清空订阅
//!
//! ## Rust 化简化（ponytail: 最小可工作）
//!
//! 取消内部 publisher mpsc + broadcast goroutine，**`publish` 直接同步遍历订阅者
//! `try_send`**。等价语义：
//! - non-blocking 模式：缓冲满则丢弃（Go spawn goroutine 重试 → 简化为丢弃）
//! - blocking 模式：缓冲满则 spawn 后台 task `tx.send().await`
//!
//! `start` / `close` 仅切换 `running` / `closed` 原子标志。
//! `close` 同步 drop 所有 sender → 订阅者 `recv` 立即收到 `None`。
//!
//! 这是**等价于 Go 的最简实现**：Go 的 publisher mpsc + goroutine 仅为解耦
//! publisher 与 subscriber 速度差，Rust 端用 try_send/spawn 达到同样效果。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use xray_features::stats::{Channel as ChannelTrait, ChannelError, ChannelSubscriber};

use crate::error::log_warning;

/// 通道配置。对应 Go `app/stats/config.proto::ChannelConfig`。
#[derive(Debug, Clone)]
pub struct ChannelConfig {
    /// 阻塞模式：缓冲满时 spawn task 等待重试。
    /// 对应 Go `ChannelConfig.Blocking`。
    pub blocking: bool,
    /// 订阅者数量上限（0 = 无限制）。对应 Go `ChannelConfig.SubscriberLimit`。
    pub subscriber_limit: usize,
    /// 每个 subscriber 的缓冲容量（0 = 1）。对应 Go `ChannelConfig.BufferSize`。
    pub buffer_size: usize,
}

impl Default for ChannelConfig {
    /// 默认配置：与 Go `Manager.RegisterChannel` 内联值一致
    /// （`BufferSize: 64, Blocking: false`）。
    fn default() -> Self {
        Self {
            blocking: false,
            subscriber_limit: 0,
            buffer_size: 64,
        }
    }
}

impl ChannelConfig {
    /// 缓冲容量，至少 1（mpsc::channel 不接受 0）。
    fn effective_buffer(&self) -> usize {
        self.buffer_size.max(1)
    }
}

/// 统计通道实现。
///
/// 对应 Go `app/stats.Channel`。线程安全。
///
/// 使用 [`Mutex<Vec<(u64, mpsc::Sender)>>`] 维护订阅列表，
/// 每个 subscriber 由 unique ID 标识（用于 unsubscribe 查找）。
pub struct StatsChannel {
    config: ChannelConfig,
    subscribers: Mutex<Vec<(u64, mpsc::Sender<Arc<dyn std::any::Any + Send + Sync>>)>>,
    next_id: AtomicU64,
    running: AtomicBool,
    closed: AtomicBool,
}

impl StatsChannel {
    /// 新建通道。对应 Go `NewChannel(config *ChannelConfig) *Channel`。
    #[must_use]
    pub fn new(config: ChannelConfig) -> Self {
        Self {
            config,
            subscribers: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
            running: AtomicBool::new(false),
            closed: AtomicBool::new(true), // 初始未启动等价 closed=true
        }
    }

    /// 默认配置新建。
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ChannelConfig::default())
    }
}

impl ChannelTrait for StatsChannel {
    fn publish(&self, msg: Arc<dyn std::any::Any + Send + Sync>) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let subs = self.subscribers.lock();
        for (_, tx) in subs.iter() {
            match tx.try_send(Arc::clone(&msg)) {
                Ok(()) => (),
                Err(mpsc::error::TrySendError::Full(m)) => {
                    if self.config.blocking {
                        // spawn 后台 task 等待重试（Go blocking 模式）
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let _ = tx.send(m).await;
                        });
                    }
                    // 非 blocking 模式直接丢弃
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // subscriber drop 了，下次清理时移除（这里静默）
                }
            }
        }
    }

    fn subscribers(&self) -> usize {
        self.subscribers.lock().len()
    }

    fn subscribe(&self) -> Result<ChannelSubscriber, ChannelError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(ChannelError::Closed);
        }
        let mut subs = self.subscribers.lock();
        if self.config.subscriber_limit > 0 && subs.len() >= self.config.subscriber_limit {
            return Err(ChannelError::SubscribersLimitReached {
                limit: self.config.subscriber_limit,
            });
        }
        let (tx, rx) = mpsc::channel(self.config.effective_buffer());
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        subs.push((id, tx));
        Ok(ChannelSubscriber::new(rx, id))
    }

    fn unsubscribe(&self, sub: &ChannelSubscriber) -> Result<(), ChannelError> {
        let mut subs = self.subscribers.lock();
        let before = subs.len();
        subs.retain(|(id, _)| *id != sub.id());
        if subs.len() == before {
            // Go 行为：找不到不报错（仅在 channel closed 时 Unsubscribe 报错）
            log_warning(format!(
                "unsubscribe: subscriber {} not found (already removed?)",
                sub.id()
            ));
        }
        Ok(())
    }

    fn running(&self) -> bool {
        self.running.load(Ordering::SeqCst) && !self.closed.load(Ordering::SeqCst)
    }

    fn start(&self) -> Result<(), ChannelError> {
        let was_running = self.running.swap(true, Ordering::SeqCst);
        self.closed.store(false, Ordering::SeqCst);
        if was_running && !self.closed.load(Ordering::SeqCst) {
            // 已经在跑，幂等返回 Ok
            return Ok(());
        }
        Ok(())
    }

    fn close(&self) -> Result<(), ChannelError> {
        let was_closed = self.closed.swap(true, Ordering::SeqCst);
        if was_closed {
            return Ok(());
        }
        self.running.store(false, Ordering::SeqCst);
        // drop 所有 sender → 订阅者 recv 收到 None
        let mut subs = self.subscribers.lock();
        subs.clear();
        Ok(())
    }
}

impl std::fmt::Debug for StatsChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatsChannel")
            .field("config", &self.config)
            .field("subscriber_count", &self.subscribers.lock().len())
            .field("running", &self.running.load(Ordering::SeqCst))
            .field("closed", &self.closed.load(Ordering::SeqCst))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_features::stats::ChannelMessage;

    fn make_msg<T: 'static + Send + Sync>(v: T) -> ChannelMessage {
        Arc::new(v)
    }

    #[test]
    fn config_default_matches_go() {
        let c = ChannelConfig::default();
        assert!(!c.blocking);
        assert_eq!(c.subscriber_limit, 0);
        assert_eq!(c.buffer_size, 64);
    }

    #[test]
    fn config_effective_buffer_min_one() {
        let c = ChannelConfig {
            buffer_size: 0,
            ..ChannelConfig::default()
        };
        assert_eq!(c.effective_buffer(), 1);
    }

    #[test]
    fn new_channel_initial_closed() {
        let c = StatsChannel::with_defaults();
        assert!(!c.running());
        // closed=true 时 running() 也返回 false
    }

    #[test]
    fn start_makes_running() {
        let c = StatsChannel::with_defaults();
        c.start().unwrap();
        assert!(c.running());
    }

    #[test]
    fn start_is_idempotent() {
        let c = StatsChannel::with_defaults();
        c.start().unwrap();
        c.start().unwrap(); // 再次不报错
        assert!(c.running());
    }

    #[test]
    fn close_stops_running() {
        let c = StatsChannel::with_defaults();
        c.start().unwrap();
        c.close().unwrap();
        assert!(!c.running());
    }

    #[test]
    fn close_is_idempotent() {
        let c = StatsChannel::with_defaults();
        c.start().unwrap();
        c.close().unwrap();
        c.close().unwrap(); // 再次不报错
    }

    #[test]
    fn subscribe_before_start_errors_closed() {
        let c = StatsChannel::with_defaults();
        match c.subscribe() {
            Err(ChannelError::Closed) => (),
            Err(e) => panic!("expected Closed, got {e:?}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    #[test]
    fn subscribe_after_start_ok() {
        let c = StatsChannel::with_defaults();
        c.start().unwrap();
        let _sub = c.subscribe().expect("subscribe ok");
        assert_eq!(c.subscribers(), 1);
    }

    #[test]
    fn subscriber_limit_enforced() {
        let c = StatsChannel::new(ChannelConfig {
            subscriber_limit: 2,
            ..ChannelConfig::default()
        });
        c.start().unwrap();
        let _a = c.subscribe().unwrap();
        let _b = c.subscribe().unwrap();
        match c.subscribe() {
            Err(ChannelError::SubscribersLimitReached { limit: 2 }) => (),
            Err(e) => panic!("expected SubscribersLimitReached, got {e:?}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    #[test]
    fn unsubscribe_reduces_count() {
        let c = StatsChannel::with_defaults();
        c.start().unwrap();
        let sub = c.subscribe().unwrap();
        assert_eq!(c.subscribers(), 1);
        c.unsubscribe(&sub).unwrap();
        assert_eq!(c.subscribers(), 0);
    }

    #[test]
    fn unsubscribe_unknown_silent() {
        let c = StatsChannel::with_defaults();
        c.start().unwrap();
        let (_, fake_rx) = mpsc::channel(1);
        let fake = ChannelSubscriber::new(fake_rx, 999);
        // 不 panic 即可
        c.unsubscribe(&fake).unwrap();
    }

    #[test]
    fn publish_to_no_subscribers_noop() {
        let c = StatsChannel::with_defaults();
        c.start().unwrap();
        c.publish(make_msg(42_u32)); // 不 panic
    }

    #[test]
    fn publish_closed_silent() {
        let c = StatsChannel::with_defaults();
        // 未 start（closed=true）
        c.publish(make_msg(42_u32)); // 静默
    }

    #[test]
    fn publish_delivers_to_all_subscribers() {
        let c = StatsChannel::with_defaults();
        c.start().unwrap();
        let mut s1 = c.subscribe().unwrap();
        let mut s2 = c.subscribe().unwrap();

        // 用 tokio runtime 测试 async recv
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            c.publish(make_msg(42_u32));
            let m1 = s1.recv().await.expect("s1 got msg");
            let m2 = s2.recv().await.expect("s2 got msg");
            assert_eq!(m1.downcast_ref::<u32>(), Some(&42));
            assert_eq!(m2.downcast_ref::<u32>(), Some(&42));
        });
    }

    #[test]
    fn publish_after_close_subscribers_get_none() {
        let c = StatsChannel::with_defaults();
        c.start().unwrap();
        let mut s = c.subscribe().unwrap();
        c.close().unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let m = s.recv().await;
            assert!(m.is_none(), "subscriber must get None after close");
        });
    }

    #[test]
    fn unsubscribe_stops_delivery() {
        let c = StatsChannel::with_defaults();
        c.start().unwrap();
        let s1 = c.subscribe().unwrap();
        c.unsubscribe(&s1).unwrap();
        // 即使 publish，s1 也收不到（sender 已 remove）
        // 但 s1 仍持有 Receiver，drop 时也 OK
        c.publish(make_msg(1_u32));
        // 验证 subscribers 列表已清空
        assert_eq!(c.subscribers(), 0);
    }

    #[test]
    fn recv_as_downcasts() {
        let c = StatsChannel::with_defaults();
        c.start().unwrap();
        let mut s = c.subscribe().unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            c.publish(make_msg("hello".to_string()));
            let msg: String = s.recv_as::<String>().await.expect("got string");
            assert_eq!(msg, "hello");
        });
    }

    #[test]
    fn debug_format_works() {
        let c = StatsChannel::with_defaults();
        let s = format!("{c:?}");
        assert!(s.contains("StatsChannel"));
    }

    #[test]
    fn implements_features_channel_trait() {
        let c: Arc<dyn ChannelTrait> = Arc::new(StatsChannel::with_defaults());
        c.start().unwrap();
        let _sub = c.subscribe().unwrap();
        assert_eq!(c.subscribers(), 1);
        assert!(c.running());
        c.close().unwrap();
        assert!(!c.running());
    }

    #[test]
    fn subscriber_id_increments() {
        let c = StatsChannel::with_defaults();
        c.start().unwrap();
        let s1 = c.subscribe().unwrap();
        let s2 = c.subscribe().unwrap();
        assert_eq!(s1.id(), 1);
        assert_eq!(s2.id(), 2);
    }
}
