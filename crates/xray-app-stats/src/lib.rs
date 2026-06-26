//! xray-app-stats：统计应用服务（流量计数 / 在线 IP / pub-sub 通道）。
//!
//! 对应 Go `app/stats/`：
//! - `counter.go` → [`counter::Counter`]（AtomicI64，对应 `atomic.AddInt64/SwapInt64`）
//! - `online_map.go` → [`online_map::OnlineMap`]（refcount + 跳过 localhost）
//! - `channel.go` → [`channel::StatsChannel`]（mpsc + Vec 订阅者，简化版无内部 goroutine）
//! - `stats.go` → [`manager::Manager`]（`RwLock<HashMap>`，含 Start/Close）
//! - `command/command.go` → [`command::DefaultStatsService`]（编排 + trait，gRPC 注册留给上层）
//! - `features/stats/stats.go` 接口层（[`xray_features::stats`]）已重写对齐 Go
//!
//! ## IO 边界范围（与 P4-4 proxyman 一致策略）
//!
//! - **业务核心**：Counter/OnlineMap/Channel/Manager 实现，完全独立可测
//! - **gRPC server 注册留 trait**：[`command::StatsService`] trait + [`command::DefaultStatsService`]
//!   编排类，不引入 tonic（由 `xray-app-commander` 注册）
//! - **SysStatsProvider 注入**：Rust 无 `runtime.MemStats` 等价，留 trait 由上层注入
//!   jemalloc / tokio 统计实现（[`command::DefaultSysStatsProvider`] 仅填 uptime）
//!
//! ## 关键决策
//!
//! 1. **修正 features/stats.rs**：早期简化版 Counter::add/set 不返回旧值且缺
//!    OnlineMap/Channel；重写对齐 Go 语义。`xray-app-dispatcher` 的 `Arc<dyn Counter>`
//!    兼容（add 调用忽略返回值）
//! 2. **Channel 简化**：去掉 Go publisher mpsc + broadcast goroutine 双层结构，
//!    `publish` 直接同步遍历订阅者 `try_send`（blocking 模式失败时 spawn 重试 task）。
//!    等价语义，更少抽象。
//! 3. **Manager 的 Start/Close 独立暴露**（不在 features::stats::Manager trait 中）：
//!    Go 通过 features.Feature 嵌入，Rust 端 Manager trait 不含 Start/Close，
//!    由本 crate Manager 结构体额外提供方法
//! 4. **ChannelSubscriber 在 features 层定义**：所有 Channel 实现共用同一订阅句柄类型，
//!    含 `mpsc::Receiver<ChannelMessage>` + ID

pub mod channel;
pub mod command;
pub mod counter;
pub mod error;
pub mod manager;
pub mod online_map;

// Re-export 主要公共类型
pub use channel::{ChannelConfig, StatsChannel};
pub use command::{
    DefaultStatsService, DefaultSysStatsProvider, GetAllOnlineUsersResponse, GetStatsRequest,
    GetStatsResponse, GetStatsOnlineIpListResponse, GetUsersStatsRequest, GetUsersStatsResponse,
    OnlineIpEntry, QueryStatsRequest, QueryStatsResponse, Stat, StatsCommandError, StatsService,
    SysStats, SysStatsProvider, UserStat,
};
pub use counter::Counter;
pub use error::StatsError;
pub use manager::Manager;
pub use online_map::OnlineMap;

// features 层 trait 透出
pub use xray_features::stats::{
    get_or_register_channel, get_or_register_counter, get_or_register_online_map,
    subscribe_runnable_channel, unsubscribe_closable_channel, Channel, ChannelError,
    ChannelMessage, ChannelSubscriber, Counter as CounterTrait, Manager as ManagerTrait,
    ManagerError, NoopManager, OnlineMap as OnlineMapTrait,
};
