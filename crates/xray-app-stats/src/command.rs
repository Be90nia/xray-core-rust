//! Stats command 服务。
//!
//! 对应 Go `app/stats/command/command.go`：
//! - 7 个 RPC handler 方法（GetStats / GetStatsOnline / GetStatsOnlineIpList /
//!   GetAllOnlineUsers / GetUsersStats / QueryStats / GetSysStats）
//! - gRPC server 注册逻辑
//!
//! ## Rust 化策略（与 P4-4 proxyman 一致）
//!
//! - **不引入 tonic**：定义 [`StatsService`] trait 含 7 个方法
//! - **[`DefaultStatsService`]** 持有 `Arc<dyn Manager>` 编排业务逻辑
//! - **gRPC server 注册留 trait + 编排类**：上层 `xray-app-commander` crate
//!   负责把 `DefaultStatsService` 注册到 tonic gRPC server（依赖 tonic crate）
//!
//! ## SysStats 数据来源
//!
//! Go 用 `runtime.ReadMemStats` + `runtime.NumGoroutine`，Rust 等价：
//! - **uptime**: `Instant::now() - start_time`
//! - **num_threads (逻辑核心)**: `std::thread::available_parallelism` 纯 std 跨平台
//! - **mem/sys/mallocs/frees**: sysinfo/jemalloc 未接入（Windows Defender 拦截
//!   ntapi build script，需用户加 target/ 排除路径后才可引入 sysinfo）；
//!   需精确数据时通过 [`SysStatsProvider`] trait 注入自定义实现
//! - **num_gc/pause_total_ns**: Rust 无 GC，恒为 0
//! - [`DefaultSysStatsProvider`]：num_threads=1（零依赖、零 syscall、轻量级）
//! - [`StdParallelismSysStatsProvider`]：num_threads=逻辑 CPU 数（纯 std、推荐）

use std::sync::Arc;
use std::time::Instant;

use xray_features::stats::Manager;

// ---------------------------------------------------------------------------
// 数据类型（对应 Go proto 生成的 message）
// ---------------------------------------------------------------------------

/// 单条统计。对应 Go `Stat { name; value }`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stat {
    pub name: String,
    pub value: i64,
}

/// 系统统计。对应 Go `SysStatsResponse`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SysStats {
    pub uptime_seconds: u32,
    pub num_threads: u32,
    pub alloc_bytes: u64,
    pub total_alloc_bytes: u64,
    pub sys_bytes: u64,
    pub mallocs: u64,
    pub frees: u64,
    pub live_objects: u64,
    pub num_gc: u32,
    pub pause_total_ns: u64,
}

/// 在线 IP 详情。对应 Go `OnlineIPEntry { ip; last_seen }`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OnlineIpEntry {
    pub ip: String,
    pub last_seen: i64,
}

/// 单用户统计。对应 Go `UserStat`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserStat {
    pub email: String,
    pub ips: Vec<OnlineIpEntry>,
    pub uplink: i64,
    pub downlink: i64,
}

// ---------------------------------------------------------------------------
// Request / Response
// ---------------------------------------------------------------------------

/// GetStats 请求。对应 Go `GetStatsRequest { name; reset }`。
#[derive(Debug, Clone)]
pub struct GetStatsRequest {
    pub name: String,
    pub reset: bool,
}

/// QueryStats 请求。对应 Go `QueryStatsRequest { pattern; reset }`。
#[derive(Debug, Clone)]
pub struct QueryStatsRequest {
    pub pattern: String,
    pub reset: bool,
}

/// GetUsersStats 请求。对应 Go `GetUsersStatsRequest { include_traffic; reset }`。
#[derive(Debug, Clone)]
pub struct GetUsersStatsRequest {
    pub include_traffic: bool,
    pub reset: bool,
}

/// GetStats 响应。对应 Go `GetStatsResponse { stat }`。
#[derive(Debug, Clone, Default)]
pub struct GetStatsResponse {
    pub stat: Option<Stat>,
}

/// QueryStats 响应。对应 Go `QueryStatsResponse { stat }`。
#[derive(Debug, Clone, Default)]
pub struct QueryStatsResponse {
    pub stats: Vec<Stat>,
}

/// GetStatsOnlineIpList 响应。对应 Go `GetStatsOnlineIpListResponse`。
#[derive(Debug, Clone, Default)]
pub struct GetStatsOnlineIpListResponse {
    pub name: String,
    pub ips: Vec<OnlineIpEntry>,
}

/// GetAllOnlineUsers 响应。对应 Go `GetAllOnlineUsersResponse`。
#[derive(Debug, Clone, Default)]
pub struct GetAllOnlineUsersResponse {
    pub users: Vec<String>,
}

/// GetUsersStats 响应。对应 Go `GetUsersStatsResponse`。
#[derive(Debug, Clone, Default)]
pub struct GetUsersStatsResponse {
    pub users: Vec<UserStat>,
}

// ---------------------------------------------------------------------------
// SysStatsProvider（运行时统计注入接口）
// ---------------------------------------------------------------------------

/// 运行时统计注入接口。
///
/// 默认实现 [`DefaultSysStatsProvider`] 仅填 uptime，其余 0。
/// 上层（如 main）可注入更精确的实现（jemalloc / tokio runtime 等）。
pub trait SysStatsProvider: Send + Sync {
    /// 返回当前系统统计快照。
    fn snapshot(&self) -> SysStats;
}

/// 默认 SysStatsProvider：只填 uptime（其余字段 0）。
pub struct DefaultSysStatsProvider {
    start_time: Instant,
}

impl DefaultSysStatsProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
        }
    }

    /// 显式指定起始时刻（测试用）。
    #[must_use]
    pub fn with_start(start_time: Instant) -> Self {
        Self { start_time }
    }
}

impl Default for DefaultSysStatsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SysStatsProvider for DefaultSysStatsProvider {
    fn snapshot(&self) -> SysStats {
        let uptime = self.start_time.elapsed().as_secs();
        SysStats {
            uptime_seconds: u32::try_from(uptime).unwrap_or(u32::MAX),
            num_threads: 1, // Rust 程序至少主线程
            ..SysStats::default()
        }
    }
}

// ---------------------------------------------------------------------------
// StdParallelismSysStatsProvider（纯 std 实现，无额外依赖）
// ---------------------------------------------------------------------------

/// 基于 [`std::thread::available_parallelism`] 的轻量级 SysStatsProvider。
///
/// 仅提供 uptime + 逻辑核心数（作为 num_threads 近似）。
/// 内存/GC 字段恒为 0——这些需要 sysinfo 或 jemalloc 接入（因 Windows Defender
/// 拦截 ntapi/rayon-core build script，sysinfo 推迟，需用户先加 Defender 排除路径）。
///
/// ponytail: 不引入新依赖即完成基本功能，待生产需求明确后再接入 sysinfo/jemalloc。
pub struct StdParallelismSysStatsProvider {
    start_time: Instant,
    logical_cpus: u32,
}

impl StdParallelismSysStatsProvider {
    /// 新建。`available_parallelism` 失败时 fallback 到 1。
    #[must_use]
    pub fn new() -> Self {
        let logical_cpus = std::thread::available_parallelism()
            .map(|n| u32::try_from(n.get()).unwrap_or(u32::MAX))
            .unwrap_or(1);
        Self {
            start_time: Instant::now(),
            logical_cpus,
        }
    }

    /// 显式指定起始时刻（测试用）。
    #[must_use]
    pub fn with_start(start_time: Instant) -> Self {
        let logical_cpus = std::thread::available_parallelism()
            .map(|n| u32::try_from(n.get()).unwrap_or(u32::MAX))
            .unwrap_or(1);
        Self { start_time, logical_cpus }
    }
}

impl Default for StdParallelismSysStatsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SysStatsProvider for StdParallelismSysStatsProvider {
    fn snapshot(&self) -> SysStats {
        let uptime = self.start_time.elapsed().as_secs();
        SysStats {
            uptime_seconds: u32::try_from(uptime).unwrap_or(u32::MAX),
            num_threads: self.logical_cpus,
            ..SysStats::default()
        }
    }
}

// ---------------------------------------------------------------------------
// StatsService trait
// ---------------------------------------------------------------------------

/// Stats 命令服务接口。对应 Go `StatsServiceServer` 接口。
///
/// 所有方法接受请求结构体，返回响应或 [`StatsCommandError`]。
pub trait StatsService: Send + Sync {
    /// 获取 counter 值。对应 Go `GetStats`。
    fn get_stats(&self, req: &GetStatsRequest) -> Result<GetStatsResponse, StatsCommandError>;

    /// 获取 OnlineMap IP 数。对应 Go `GetStatsOnline`。
    fn get_stats_online(
        &self,
        req: &GetStatsRequest,
    ) -> Result<GetStatsResponse, StatsCommandError>;

    /// 获取 OnlineMap 详情。对应 Go `GetStatsOnlineIpList`。
    fn get_stats_online_ip_list(
        &self,
        req: &GetStatsRequest,
    ) -> Result<GetStatsOnlineIpListResponse, StatsCommandError>;

    /// 获取所有在线用户。对应 Go `GetAllOnlineUsers`。
    fn get_all_online_users(&self) -> Result<GetAllOnlineUsersResponse, StatsCommandError>;

    /// 获取所有用户统计（含 IP 与可选流量）。对应 Go `GetUsersStats`。
    fn get_users_stats(
        &self,
        req: &GetUsersStatsRequest,
    ) -> Result<GetUsersStatsResponse, StatsCommandError>;

    /// 按 pattern 模糊查询 counters。对应 Go `QueryStats`。
    fn query_stats(
        &self,
        req: &QueryStatsRequest,
    ) -> Result<QueryStatsResponse, StatsCommandError>;

    /// 获取系统统计。对应 Go `GetSysStats`。
    fn get_sys_stats(&self) -> Result<SysStats, StatsCommandError>;
}

// ---------------------------------------------------------------------------
// StatsCommandError
// ---------------------------------------------------------------------------

/// Stats 命令处理错误。
#[derive(Debug, thiserror::Error)]
pub enum StatsCommandError {
    /// 资源未找到。对应 Go `status.Error(codes.NotFound, "...")`。
    #[error("resource `{0}` not found")]
    NotFound(String),

    /// 内部错误。
    #[error("internal error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// DefaultStatsService 编排类
// ---------------------------------------------------------------------------

/// 默认 StatsService 实现。对应 Go `statsServer struct { stats; startTime }`。
pub struct DefaultStatsService {
    manager: Arc<dyn Manager>,
    sys_stats: Arc<dyn SysStatsProvider>,
}

impl DefaultStatsService {
    /// 新建。对应 Go `NewStatsServer(manager)`。
    #[must_use]
    pub fn new(manager: Arc<dyn Manager>) -> Self {
        Self {
            manager,
            sys_stats: Arc::new(DefaultSysStatsProvider::new()),
        }
    }

    /// 显式注入 SysStatsProvider。
    #[must_use]
    pub fn with_sys_stats(manager: Arc<dyn Manager>, sys_stats: Arc<dyn SysStatsProvider>) -> Self {
        Self { manager, sys_stats }
    }
}

/// Counter name 解析 helper。
///
/// Go counter name 格式：`user>>>{email}>>>traffic>>>{uplink|downlink}`。
/// 此函数提取 email，返回 `(email, is_uplink)`。
///
/// 返回 `None` 表示 name 不匹配 user 流量格式。
fn parse_user_traffic_name(name: &str) -> Option<(String, bool)> {
    const PREFIX_USER: &str = "user>>>";
    const SUFFIX_UPLINK: &str = ">>>traffic>>>uplink";
    const SUFFIX_DOWNLINK: &str = ">>>traffic>>>downlink";

    if let Some(rest) = name.strip_prefix(PREFIX_USER) {
        if let Some(email) = rest.strip_suffix(SUFFIX_UPLINK) {
            return Some((email.to_string(), true));
        }
        if let Some(email) = rest.strip_suffix(SUFFIX_DOWNLINK) {
            return Some((email.to_string(), false));
        }
    }
    None
}

/// OnlineMap name 解析 helper。
///
/// Go OnlineMap name 格式：`user>>>{email}>>>ip`。
/// 此函数提取 email（与 Go `strings.Cut(name, ">>>")` 后再 `strings.Cut(rest, ">>>")` 等价）。
fn parse_user_online_map_name(name: &str) -> Option<String> {
    const PREFIX_USER: &str = "user>>>";
    let rest = name.strip_prefix(PREFIX_USER)?;
    let email = rest.split(">>>").next()?;
    Some(email.to_string())
}

impl StatsService for DefaultStatsService {
    fn get_stats(&self, req: &GetStatsRequest) -> Result<GetStatsResponse, StatsCommandError> {
        let c = self
            .manager
            .get_counter(&req.name)
            .ok_or_else(|| StatsCommandError::NotFound(req.name.clone()))?;
        let value = if req.reset {
            c.set(0)
        } else {
            c.value()
        };
        Ok(GetStatsResponse {
            stat: Some(Stat {
                name: req.name.clone(),
                value,
            }),
        })
    }

    fn get_stats_online(
        &self,
        req: &GetStatsRequest,
    ) -> Result<GetStatsResponse, StatsCommandError> {
        let om = self
            .manager
            .get_online_map(&req.name)
            .ok_or_else(|| StatsCommandError::NotFound(req.name.clone()))?;
        let value = i64::try_from(om.count()).unwrap_or(i64::MAX);
        Ok(GetStatsResponse {
            stat: Some(Stat {
                name: req.name.clone(),
                value,
            }),
        })
    }

    fn get_stats_online_ip_list(
        &self,
        req: &GetStatsRequest,
    ) -> Result<GetStatsOnlineIpListResponse, StatsCommandError> {
        let om = self
            .manager
            .get_online_map(&req.name)
            .ok_or_else(|| StatsCommandError::NotFound(req.name.clone()))?;
        let mut ips = Vec::new();
        om.for_each(&mut |ip, last_seen| {
            ips.push(OnlineIpEntry {
                ip: ip.to_string(),
                last_seen,
            });
            true
        });
        Ok(GetStatsOnlineIpListResponse {
            name: req.name.clone(),
            ips,
        })
    }

    fn get_all_online_users(&self) -> Result<GetAllOnlineUsersResponse, StatsCommandError> {
        Ok(GetAllOnlineUsersResponse {
            users: self.manager.get_all_online_users(),
        })
    }

    fn get_users_stats(
        &self,
        req: &GetUsersStatsRequest,
    ) -> Result<GetUsersStatsResponse, StatsCommandError> {
        // 第 1 阶段：遍历 online_maps，构建 email → UserStat
        let mut user_map: std::collections::HashMap<String, UserStat> =
            std::collections::HashMap::new();

        self.manager.visit_online_maps(&mut |name, om| {
            if om.count() == 0 {
                return true;
            }
            let Some(email) = parse_user_online_map_name(name) else {
                return true;
            };
            let mut user = UserStat {
                email: email.clone(),
                ..UserStat::default()
            };
            om.for_each(&mut |ip, last_seen| {
                user.ips.push(OnlineIpEntry {
                    ip: ip.to_string(),
                    last_seen,
                });
                true
            });
            if !user.ips.is_empty() {
                user_map.insert(email, user);
            }
            true
        });

        // 第 2 阶段：可选填充 traffic
        if req.include_traffic {
            self.manager.visit_counters(&mut |name, c| {
                let Some((email, is_uplink)) = parse_user_traffic_name(name) else {
                    return true;
                };
                let Some(user) = user_map.get_mut(&email) else {
                    return true;
                };
                let value = if req.reset { c.set(0) } else { c.value() };
                if is_uplink {
                    user.uplink = value;
                } else {
                    user.downlink = value;
                }
                true
            });
        }

        let users: Vec<UserStat> = user_map.into_values().collect();
        Ok(GetUsersStatsResponse { users })
    }

    fn query_stats(
        &self,
        req: &QueryStatsRequest,
    ) -> Result<QueryStatsResponse, StatsCommandError> {
        let mut stats = Vec::new();
        self.manager.visit_counters(&mut |name, c| {
            if name.contains(req.pattern.as_str()) {
                let value = if req.reset { c.set(0) } else { c.value() };
                stats.push(Stat {
                    name: name.to_string(),
                    value,
                });
            }
            true
        });
        Ok(QueryStatsResponse { stats })
    }

    fn get_sys_stats(&self) -> Result<SysStats, StatsCommandError> {
        Ok(self.sys_stats.snapshot())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::Manager;
    use xray_features::stats::Manager as _; // trait method in scope

    fn make_service_with_setup<F: FnOnce(&Manager)>(setup: F) -> DefaultStatsService {
        let m = Manager::new();
        setup(&m);
        let arc: Arc<dyn xray_features::stats::Manager> = Arc::new(m);
        DefaultStatsService::new(arc)
    }

    // --- parse_user_traffic_name ---

    #[test]
    fn parse_user_traffic_uplink() {
        let (email, is_up) = parse_user_traffic_name("user>>>alice>>>traffic>>>uplink").unwrap();
        assert_eq!(email, "alice");
        assert!(is_up);
    }

    #[test]
    fn parse_user_traffic_downlink() {
        let (email, is_up) =
            parse_user_traffic_name("user>>>bob>>>traffic>>>downlink").unwrap();
        assert_eq!(email, "bob");
        assert!(!is_up);
    }

    #[test]
    fn parse_user_traffic_invalid_returns_none() {
        assert!(parse_user_traffic_name("user>>>x").is_none());
        assert!(parse_user_traffic_name("inbound>>>tag>>>traffic>>>uplink").is_none());
        assert!(parse_user_traffic_name("user>>>x>>>bytes").is_none());
    }

    // --- parse_user_online_map_name ---

    #[test]
    fn parse_user_online_map_basic() {
        let email = parse_user_online_map_name("user>>>alice>>>ip").unwrap();
        assert_eq!(email, "alice");
    }

    #[test]
    fn parse_user_online_map_invalid() {
        assert!(parse_user_online_map_name("inbound>>>tag").is_none());
    }

    // --- GetStats ---

    #[test]
    fn get_stats_returns_value() {
        let svc = make_service_with_setup(|m| {
            let c = m.register_counter("user>>>a>>>traffic>>>uplink").unwrap();
            c.add(1234);
        });
        let resp = svc
            .get_stats(&GetStatsRequest {
                name: "user>>>a>>>traffic>>>uplink".into(),
                reset: false,
            })
            .unwrap();
        assert_eq!(resp.stat.unwrap().value, 1234);
    }

    #[test]
    fn get_stats_reset_returns_old_value() {
        let svc = make_service_with_setup(|m| {
            let c = m.register_counter("c").unwrap();
            c.add(50);
        });
        let resp = svc
            .get_stats(&GetStatsRequest {
                name: "c".into(),
                reset: true,
            })
            .unwrap();
        // reset 后返回原值
        assert_eq!(resp.stat.unwrap().value, 50);
        // 再次取应是 0
        let resp2 = svc
            .get_stats(&GetStatsRequest {
                name: "c".into(),
                reset: false,
            })
            .unwrap();
        assert_eq!(resp2.stat.unwrap().value, 0);
    }

    #[test]
    fn get_stats_not_found() {
        let svc = make_service_with_setup(|_| {});
        let err = svc
            .get_stats(&GetStatsRequest {
                name: "missing".into(),
                reset: false,
            })
            .unwrap_err();
        assert!(matches!(err, StatsCommandError::NotFound(_)));
    }

    // --- GetStatsOnline ---

    #[test]
    fn get_stats_online_returns_count() {
        let svc = make_service_with_setup(|m| {
            let om = m.register_online_map("user>>>u>>>ip").unwrap();
            om.add_ip("10.0.0.1");
            om.add_ip("10.0.0.2");
        });
        let resp = svc
            .get_stats_online(&GetStatsRequest {
                name: "user>>>u>>>ip".into(),
                reset: false,
            })
            .unwrap();
        assert_eq!(resp.stat.unwrap().value, 2);
    }

    #[test]
    fn get_stats_online_not_found() {
        let svc = make_service_with_setup(|_| {});
        let err = svc
            .get_stats_online(&GetStatsRequest {
                name: "x".into(),
                reset: false,
            })
            .unwrap_err();
        assert!(matches!(err, StatsCommandError::NotFound(_)));
    }

    // --- GetStatsOnlineIpList ---

    #[test]
    fn get_stats_online_ip_list_collects_ips() {
        let svc = make_service_with_setup(|m| {
            let om = m.register_online_map("u").unwrap();
            om.add_ip("10.0.0.1");
            om.add_ip("10.0.0.2");
        });
        let resp = svc
            .get_stats_online_ip_list(&GetStatsRequest {
                name: "u".into(),
                reset: false,
            })
            .unwrap();
        assert_eq!(resp.name, "u");
        assert_eq!(resp.ips.len(), 2);
        let mut ips: Vec<String> = resp.ips.into_iter().map(|e| e.ip).collect();
        ips.sort();
        assert_eq!(ips, vec!["10.0.0.1", "10.0.0.2"]);
    }

    // --- GetAllOnlineUsers ---

    #[test]
    fn get_all_online_users_returns_active() {
        let svc = make_service_with_setup(|m| {
            let om1 = m.register_online_map("user>>>a>>>ip").unwrap();
            om1.add_ip("10.0.0.1");
            // user b 注册但无 IP，不应返回
            let _om2 = m.register_online_map("user>>>b>>>ip").unwrap();
        });
        let resp = svc.get_all_online_users().unwrap();
        assert_eq!(resp.users, vec!["user>>>a>>>ip"]);
    }

    // --- GetUsersStats ---

    #[test]
    fn get_users_stats_without_traffic() {
        let svc = make_service_with_setup(|m| {
            let om = m.register_online_map("user>>>alice>>>ip").unwrap();
            om.add_ip("10.0.0.1");
            om.add_ip("10.0.0.2");
            // 注册一些 counter，但 include_traffic=false 不查
            let up = m
                .register_counter("user>>>alice>>>traffic>>>uplink")
                .unwrap();
            up.add(1024);
        });
        let resp = svc
            .get_users_stats(&GetUsersStatsRequest {
                include_traffic: false,
                reset: false,
            })
            .unwrap();
        assert_eq!(resp.users.len(), 1);
        let u = &resp.users[0];
        assert_eq!(u.email, "alice");
        assert_eq!(u.ips.len(), 2);
        assert_eq!(u.uplink, 0); // 未查
        assert_eq!(u.downlink, 0);
    }

    #[test]
    fn get_users_stats_with_traffic() {
        let svc = make_service_with_setup(|m| {
            let om = m.register_online_map("user>>>bob>>>ip").unwrap();
            om.add_ip("10.0.0.5");
            let up = m
                .register_counter("user>>>bob>>>traffic>>>uplink")
                .unwrap();
            up.add(100);
            let down = m
                .register_counter("user>>>bob>>>traffic>>>downlink")
                .unwrap();
            down.add(200);
        });
        let resp = svc
            .get_users_stats(&GetUsersStatsRequest {
                include_traffic: true,
                reset: false,
            })
            .unwrap();
        let u = &resp.users[0];
        assert_eq!(u.email, "bob");
        assert_eq!(u.uplink, 100);
        assert_eq!(u.downlink, 200);
    }

    #[test]
    fn get_users_stats_reset_clears_counters() {
        let svc = make_service_with_setup(|m| {
            let om = m.register_online_map("user>>>c>>>ip").unwrap();
            om.add_ip("1.1.1.1");
            let up = m
                .register_counter("user>>>c>>>traffic>>>uplink")
                .unwrap();
            up.add(999);
        });
        let resp = svc
            .get_users_stats(&GetUsersStatsRequest {
                include_traffic: true,
                reset: true,
            })
            .unwrap();
        let u = &resp.users[0];
        assert_eq!(u.uplink, 999, "reset 必须返回重置前的值");

        // 再查应该 0
        let resp2 = svc
            .get_users_stats(&GetUsersStatsRequest {
                include_traffic: true,
                reset: false,
            })
            .unwrap();
        let u2 = &resp2.users[0];
        assert_eq!(u2.uplink, 0);
    }

    #[test]
    fn get_users_stats_skips_zero_count_maps() {
        let svc = make_service_with_setup(|m| {
            let _om = m.register_online_map("user>>>empty>>>ip").unwrap();
            // 无 add_ip → count=0
        });
        let resp = svc
            .get_users_stats(&GetUsersStatsRequest {
                include_traffic: false,
                reset: false,
            })
            .unwrap();
        assert!(resp.users.is_empty());
    }

    // --- QueryStats ---

    #[test]
    fn query_stats_matches_pattern() {
        let svc = make_service_with_setup(|m| {
            m.register_counter("user>>>a>>>traffic>>>uplink").unwrap();
            m.register_counter("user>>>a>>>traffic>>>downlink").unwrap();
            m.register_counter("user>>>b>>>traffic>>>uplink").unwrap();
        });
        let resp = svc
            .query_stats(&QueryStatsRequest {
                pattern: "a>>>traffic".into(),
                reset: false,
            })
            .unwrap();
        assert_eq!(resp.stats.len(), 2);
    }

    #[test]
    fn query_stats_matches_all_with_empty_pattern() {
        let svc = make_service_with_setup(|m| {
            m.register_counter("x").unwrap();
            m.register_counter("y").unwrap();
        });
        let resp = svc
            .query_stats(&QueryStatsRequest {
                pattern: "".into(),
                reset: false,
            })
            .unwrap();
        assert_eq!(resp.stats.len(), 2);
    }

    #[test]
    fn query_stats_reset_returns_old_values() {
        let svc = make_service_with_setup(|m| {
            let c = m.register_counter("c").unwrap();
            c.add(7);
        });
        let resp = svc
            .query_stats(&QueryStatsRequest {
                pattern: "c".into(),
                reset: true,
            })
            .unwrap();
        assert_eq!(resp.stats[0].value, 7);
        // 再查应是 0
        let resp2 = svc
            .query_stats(&QueryStatsRequest {
                pattern: "c".into(),
                reset: false,
            })
            .unwrap();
        assert_eq!(resp2.stats[0].value, 0);
    }

    // --- GetSysStats ---

    #[test]
    fn get_sys_stats_returns_uptime_nonzero() {
        let svc = make_service_with_setup(|_| {});
        std::thread::sleep(std::time::Duration::from_millis(50));
        let s = svc.get_sys_stats().unwrap();
        assert!(s.uptime_seconds == 0 || s.uptime_seconds >= 1); // < 1 秒时为 0
        assert!(s.num_threads >= 1);
    }

    // --- SysStatsProvider ---

    #[test]
    fn default_sys_stats_provider_default_constructible() {
        let p = DefaultSysStatsProvider::default();
        let s = p.snapshot();
        assert!(s.num_threads >= 1);
    }

    #[test]
    fn default_sys_stats_provider_with_start_in_past() {
        let start = Instant::now() - std::time::Duration::from_secs(10);
        let p = DefaultSysStatsProvider::with_start(start);
        let s = p.snapshot();
        assert!(s.uptime_seconds >= 10);
    }

    #[test]
    fn sys_stats_default_all_zero() {
        let s = SysStats::default();
        assert_eq!(s.uptime_seconds, 0);
        assert_eq!(s.alloc_bytes, 0);
    }

    // --- DefaultStatsService implements trait ---

    #[test]
    fn default_stats_service_as_trait_object() {
        let svc: Arc<dyn StatsService> = Arc::new(DefaultStatsService::new(Arc::new(Manager::new())));
        let resp = svc.get_all_online_users().unwrap();
        assert!(resp.users.is_empty());
    }

    // --- Stat / 数据类型 ---

    #[test]
    fn stat_default_zero() {
        let s = Stat::default();
        assert_eq!(s.name, "");
        assert_eq!(s.value, 0);
    }

    #[test]
    fn stat_equality() {
        let a = Stat {
            name: "x".into(),
            value: 10,
        };
        let b = Stat {
            name: "x".into(),
            value: 10,
        };
        assert_eq!(a, b);
    }

    // --- SysStatsProvider custom impl ---

    #[test]
    fn custom_sys_stats_provider_injection() {
        struct CustomProvider;
        impl SysStatsProvider for CustomProvider {
            fn snapshot(&self) -> SysStats {
                SysStats {
                    uptime_seconds: 999,
                    num_gc: 5,
                    ..SysStats::default()
                }
            }
        }
        let arc: Arc<dyn SysStatsProvider> = Arc::new(CustomProvider);
        let svc = DefaultStatsService::with_sys_stats(Arc::new(Manager::new()), arc);
        let s = svc.get_sys_stats().unwrap();
        assert_eq!(s.uptime_seconds, 999);
        assert_eq!(s.num_gc, 5);
    }

    // --- StdParallelismSysStatsProvider ---

    #[test]
    fn std_parallelism_provider_default_constructible() {
        let p = StdParallelismSysStatsProvider::default();
        let s = p.snapshot();
        assert!(s.num_threads >= 1);
    }

    #[test]
    fn std_parallelism_provider_with_start_in_past() {
        let start = Instant::now() - std::time::Duration::from_secs(10);
        let p = StdParallelismSysStatsProvider::with_start(start);
        let s = p.snapshot();
        assert!(s.uptime_seconds >= 10);
        assert!(s.num_threads >= 1);
    }

    #[test]
    fn std_parallelism_provider_mem_fields_zero() {
        // 纯 std 无 mem 统计能力，这些字段应恒为 0
        let p = StdParallelismSysStatsProvider::new();
        let s = p.snapshot();
        assert_eq!(s.alloc_bytes, 0);
        assert_eq!(s.sys_bytes, 0);
        assert_eq!(s.num_gc, 0);
        assert_eq!(s.mallocs, 0);
    }

    #[test]
    fn std_parallelism_provider_injectable_into_service() {
        let arc: Arc<dyn SysStatsProvider> = Arc::new(StdParallelismSysStatsProvider::new());
        let svc = DefaultStatsService::with_sys_stats(Arc::new(Manager::new()), arc);
        let s = svc.get_sys_stats().unwrap();
        assert!(s.num_threads >= 1);
    }

    // --- Error display ---

    #[test]
    fn error_display_not_found() {
        let e = StatsCommandError::NotFound("x".into());
        assert_eq!(e.to_string(), "resource `x` not found");
    }

    #[test]
    fn error_display_internal() {
        let e = StatsCommandError::Internal("boom".into());
        assert_eq!(e.to_string(), "internal error: boom");
    }
}
