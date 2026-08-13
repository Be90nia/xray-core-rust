//! VLESS outbound 反向代理监控器（Bridge 端）。
//!
//! 对应 Go `proxy/vless/outbound/outbound.go` 的反向代理 bridge 监控逻辑。
//!
//! 在 Xray 反向代理架构中，Bridge（NAT 后客户端）的 VLESS outbound 周期性
//! 地向 Portal 建立 `command=Rvs`（destination `v1.rvs.cool`）的连接，维持
//! 反向隧道。监控器（`ReverseMonitor`）跟踪活跃连接数，当活跃数低于目标
//! 时决策是否建立新隧道。
//!
//! 本模块是纯逻辑 + 线程安全状态（`Mutex<Vec<…>>`），实际的 IO（建立
//! 连接）由上层 dispatcher 注入。`start()` 返回初始需要建立的连接数。

use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;

use crate::error::{Result, VlessError};

/// 单条反向隧道连接的状态。
#[derive(Debug, Clone)]
pub struct ReverseConnState {
    /// 连接是否活跃（已建立但未关闭）。
    pub active: bool,
    /// 建立时间（用于判断隧道是否过期）。
    pub established_at: Instant,
}

impl ReverseConnState {
    /// 创建一条活跃连接状态。
    #[must_use]
    pub fn new() -> Self {
        Self {
            active: true,
            established_at: Instant::now(),
        }
    }
}

impl Default for ReverseConnState {
    fn default() -> Self {
        Self::new()
    }
}

/// Bridge 端 reverse 监控器。
///
/// 维护目标活跃连接数（`target_conns`），跟踪当前活跃连接列表。
/// `start()` 触发初始连接建立；`pending_dials()` 返回还需建立的连接数。
///
/// 对应 Go outbound Handler 中 reverse 配置的监控 goroutine：
/// 定期检查 `len(active) < target`，不足则发起新的 Rvs 拨号。
#[derive(Debug)]
pub struct ReverseMonitor {
    /// 目标 outbound tag（Portal 标识）。
    pub tag: String,
    /// 目标活跃连接数（尽力维持）。
    pub target_conns: u32,
    inner: Arc<Mutex<Vec<ReverseConnState>>>,
}

impl Clone for ReverseMonitor {
    fn clone(&self) -> Self {
        Self {
            tag: self.tag.clone(),
            target_conns: self.target_conns,
            inner: Arc::clone(&self.inner),
        }
    }
}

impl ReverseMonitor {
    /// 创建监控器。
    ///
    /// `target_conns` 对应 Go 端反向代理维持的并行隧道数（通常为 1～数条）。
    #[must_use]
    pub fn new(tag: impl Into<String>, target_conns: u32) -> Self {
        Self {
            tag: tag.into(),
            target_conns,
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// 启动监控：返回初始需要建立的连接数。
    ///
    /// 对应 Go `Handler.Start()` 中初始化 reverse 监控的逻辑。
    /// 实际连接建立由调用方执行（需 Dialer + IO），本方法只返回缺口。
    #[must_use]
    pub fn start(&self) -> u32 {
        self.pending_dials()
    }

    /// 记录一条新连接已建立。
    pub fn on_conn_established(&self) {
        self.inner.lock().push(ReverseConnState::new());
    }

    /// 记录一条连接已关闭（标记为非活跃）。
    ///
    /// # Errors
    /// 没有活跃连接时返回 [`VlessError::Other`]。
    pub fn on_conn_closed(&self) -> Result<()> {
        let mut conns = self.inner.lock();
        // 从末尾往前找第一条活跃连接，标记关闭
        for c in conns.iter_mut().rev() {
            if c.active {
                c.active = false;
                return Ok(());
            }
        }
        Err(VlessError::Other(
            "no active reverse connection to close".into(),
        ))
    }

    /// 清理已关闭的连接记录（GC），返回清理数。
    pub fn gc_closed(&self) -> usize {
        let mut conns = self.inner.lock();
        let before = conns.len();
        conns.retain(|c| c.active);
        before - conns.len()
    }

    /// 当前活跃连接数。
    #[must_use]
    pub fn active_count(&self) -> u32 {
        self.inner.lock().iter().filter(|c| c.active).count() as u32
    }

    /// 还需建立的连接数 = target_conns - active_count（下限 0）。
    #[must_use]
    pub fn pending_dials(&self) -> u32 {
        self.target_conns.saturating_sub(self.active_count())
    }

    /// 是否需要建立新连接。
    #[must_use]
    pub fn needs_dial(&self) -> bool {
        self.pending_dials() > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_returns_target_when_empty() {
        let mon = ReverseMonitor::new("portal", 2);
        assert_eq!(mon.start(), 2);
        assert!(mon.needs_dial());
    }

    #[test]
    fn pending_decreases_as_conns_established() {
        let mon = ReverseMonitor::new("portal", 2);
        assert_eq!(mon.pending_dials(), 2);

        mon.on_conn_established();
        assert_eq!(mon.pending_dials(), 1);
        assert_eq!(mon.active_count(), 1);

        mon.on_conn_established();
        assert_eq!(mon.pending_dials(), 0);
        assert!(!mon.needs_dial());
    }

    #[test]
    fn close_reopens_deficit() {
        let mon = ReverseMonitor::new("portal", 1);
        mon.on_conn_established();
        assert_eq!(mon.pending_dials(), 0);

        mon.on_conn_closed().unwrap();
        assert_eq!(mon.active_count(), 0);
        assert_eq!(mon.pending_dials(), 1);
        assert!(mon.needs_dial());
    }

    #[test]
    fn close_with_no_active_errors() {
        let mon = ReverseMonitor::new("portal", 1);
        let err = mon.on_conn_closed().unwrap_err();
        assert!(matches!(&err, VlessError::Other(m) if m.contains("no active")));
    }

    #[test]
    fn gc_cleans_closed() {
        let mon = ReverseMonitor::new("portal", 3);
        mon.on_conn_established();
        mon.on_conn_established();
        mon.on_conn_established();
        mon.on_conn_closed().unwrap();
        mon.on_conn_closed().unwrap();

        assert_eq!(mon.active_count(), 1);
        assert_eq!(mon.gc_closed(), 2);
        assert_eq!(mon.active_count(), 1);
    }

    #[test]
    fn saturating_sub_no_underflow() {
        let mon = ReverseMonitor::new("portal", 1);
        mon.on_conn_established();
        mon.on_conn_established(); // 超出 target
        assert_eq!(mon.pending_dials(), 0);
    }

    #[test]
    fn clone_shares_state() {
        let mon = ReverseMonitor::new("portal", 1);
        let mon2 = mon.clone();
        mon.on_conn_established();
        assert_eq!(mon2.active_count(), 1);
    }

    #[test]
    fn target_zero_never_dials() {
        let mon = ReverseMonitor::new("portal", 0);
        assert_eq!(mon.start(), 0);
        assert!(!mon.needs_dial());
    }
}
