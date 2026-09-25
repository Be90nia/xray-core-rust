//! Channel 实现。
//!
//! 对应 Go `app/stats/channel.go`：
//! - `Channel struct { channel chan channelMessage; subscribers []chan interface{}; ... }`
//! - `Publish` 写入 publisher mpsc → 内部 goroutine 读 → 广播到 subscribers
//! - `Subscribe` / `Unsubscribe` 管理订阅列表
//! - `Start` 启动 broadcast goroutine；`Close` 关闭信号 + 清空订阅
//!
//! ## Rust 化实现（对齐 Go channel.go 形态，票 qx37）
//!
//! `publish` 将消息写入**有界内部队列**（容量 = buffer_size），由 `start` 时
//! spawn 的**单一 worker task** 逐条 fan-out 到订阅者：
//! - blocking 模式：worker `send().await` 阻塞送达（Go `pub.broadcast`）
//! - 非 blocking 模式：worker `try_send`，满即丢（Go default 分支）
//!
//! 发布端 `try_send` 满即丢，绝不 per-message spawn——订阅者消费慢时堆积
//! 以内部队列容量为上界（Go 内部 chan 同款语义）。
//!
//! `close` drop 内部队列 sender（worker `recv` 返回 None 退出）+ 清空订阅。

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use parking_lot::Mutex;
use tokio::sync::mpsc;
use xray_features::stats::{
    Channel as ChannelTrait, ChannelError, ChannelMessage, ChannelSubscriber,
};

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
        Self { blocking: false, subscriber_limit: 0, buffer_size: 64 }
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
    /// 与 worker task 共享（Arc：闭包需 'static）。
    subscribers: Arc<Mutex<Vec<(u64, mpsc::Sender<ChannelMessage>)>>>,
    /// 单 worker fan-out 的发布入口。`start` 时创建，`close` 时 drop
    /// （worker `recv` 返回 None 退出）。
    worker_tx: Mutex<Option<mpsc::Sender<ChannelMessage>>>,
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
            subscribers: Arc::new(Mutex::new(Vec::new())),
            worker_tx: Mutex::new(None),
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

    /// 确保单 worker 已 spawn。惰性：`tokio::spawn` 需要 runtime 上下文，
    /// 无 runtime 的同步调用方（如纯同步单测直接 `new` + `start`）跳过——
    /// 此时 publish 的消息直接丢弃，与 Go channel 未 Start 不投递一致。
    fn ensure_worker(&self) {
        let mut worker = self.worker_tx.lock();
        if worker.is_some() {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let (tx, mut rx) = mpsc::channel::<ChannelMessage>(self.config.effective_buffer());
        let subscribers = Arc::clone(&self.subscribers);
        let blocking = self.config.blocking;
        rt.spawn(async move {
            // 锁不跨 await：每条消息先快照订阅者列表再逐个投递。
            while let Some(msg) = rx.recv().await {
                let subs: Vec<mpsc::Sender<ChannelMessage>> =
                    { subscribers.lock().iter().map(|(_, tx)| tx.clone()).collect() };
                for tx in subs {
                    if blocking {
                        let _ = tx.send(Arc::clone(&msg)).await;
                    } else {
                        // 非 blocking：满即丢（与 Go default 分支一致）
                        let _ = tx.try_send(Arc::clone(&msg));
                    }
                }
            }
        });
        *worker = Some(tx);
    }
}

impl ChannelTrait for StatsChannel {
    fn publish(&self, msg: ChannelMessage) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        // 单 worker fan-out（Go channel.go broadcast goroutine）：发布端只入
        // 有界内部队列，满即丢——绝不 per-message spawn（票 qx37）。
        self.ensure_worker();
        if let Some(tx) = self.worker_tx.lock().as_ref() {
            let _ = tx.try_send(msg);
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
        // 有 runtime 上下文则立即建 worker；无 runtime 由 publish 惰性补建
        self.ensure_worker();
        Ok(())
    }

    fn close(&self) -> Result<(), ChannelError> {
        let was_closed = self.closed.swap(true, Ordering::SeqCst);
        if was_closed {
            return Ok(());
        }
        self.running.store(false, Ordering::SeqCst);
        // 停止单 worker：drop 发布入口 → worker recv 返回 None 退出
        self.worker_tx.lock().take();
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
    use xray_features::stats::ChannelMessage;

    use super::*;

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
        let c = ChannelConfig { buffer_size: 0, ..ChannelConfig::default() };
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
        let c =
            StatsChannel::new(ChannelConfig { subscriber_limit: 2, ..ChannelConfig::default() });
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
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
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

        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
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

        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
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

    /// 票 qx37：blocking 模式满载不堆积——订阅者不消费时连发 1000 条，
    /// 发布端始终同步返回（try_send 满即丢，无 per-message spawn），
    /// 订阅者最终收到的条数以内部队列容量为上界（≈3 条，绝非 1000）。
    #[test]
    fn blocking_full_load_bounded_no_task_pileup() {
        let c = StatsChannel::new(ChannelConfig {
            blocking: true,
            buffer_size: 1,
            ..ChannelConfig::default()
        });
        c.start().unwrap();
        let mut sub = c.subscribe().unwrap();

        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        rt.block_on(async {
            for i in 0..1000_u32 {
                c.publish(make_msg(i));
                // 偶尔让 worker 前进，模拟真实发布节奏
                if i % 50 == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
            // drain：确认有界
            let mut got = 0usize;
            loop {
                match tokio::time::timeout(std::time::Duration::from_millis(50), sub.recv()).await {
                    Ok(Some(_)) => got += 1,
                    _ => break,
                }
            }
            assert!(got >= 1, "at least the buffered messages must be delivered");
            assert!(got <= 5, "bounded fan-out must not pile up 1000 messages, got {got}");
        });
    }

    /// 票 qx37：close 后 worker 退出（worker_tx 清空），重启后 publish
    /// 重建 worker 并恢复投递。
    #[test]
    fn close_stops_worker_and_restart_recreates_it() {
        let c = StatsChannel::with_defaults();
        c.start().unwrap();
        c.close().unwrap();
        assert!(c.worker_tx.lock().is_none(), "close must drop worker entry");

        // 重启后恢复投递（worker 由 runtime 内的 publish 惰性重建）
        c.start().unwrap();
        let mut sub = c.subscribe().unwrap();
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        rt.block_on(async {
            c.publish(make_msg(7_u32));
            let m = tokio::time::timeout(std::time::Duration::from_millis(500), sub.recv())
                .await
                .expect("delivery after restart");
            assert_eq!(m.unwrap().downcast_ref::<u32>(), Some(&7));
        });
    }
}
