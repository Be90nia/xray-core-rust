//! Bridge + Portal trait stub。
//!
//! 对应 Go `app/reverse/bridge.go` + `portal.go`。
//! 因 mux/pipe/signal.ActivityTimer 在 Rust 端尚未翻译，这里仅暴露 trait + 编排 stub，
//! 实际 worker 创建/连接管理由后续 Phase 完成。

use std::sync::Arc;

use crate::config::{BridgeConfig, PortalConfig};
use crate::error::ReverseError;
use crate::picker::{PickerWorker, StaticMuxPicker};

/// Bridge factory trait：构造一个 bridge。
///
/// 对应 Go `NewBridge(config, dispatcher)`。
pub trait BridgeFactory: Send + Sync {
    type Bridge: Bridge;

    fn create(&self, config: &BridgeConfig) -> Result<Self::Bridge, ReverseError>;
}

/// Bridge trait：暴露 Start/Close + worker 数量查询。
pub trait Bridge: Send + Sync {
    fn start(&self) -> Result<(), ReverseError>;
    fn close(&self) -> Result<(), ReverseError>;
    fn worker_count(&self) -> usize;
    fn tag(&self) -> &str;
    fn domain(&self) -> &str;
}

/// Portal factory trait：构造一个 portal。
pub trait PortalFactory: Send + Sync {
    type Portal: Portal;

    fn create(&self, config: &PortalConfig) -> Result<Self::Portal, ReverseError>;
}

/// Portal trait：暴露 Start/Close + picker 查询。
pub trait Portal: Send + Sync {
    fn start(&self) -> Result<(), ReverseError>;
    fn close(&self) -> Result<(), ReverseError>;
    fn tag(&self) -> &str;
    fn domain(&self) -> &str;
}

/// 配置校验 helper：tag/domain 非空。
pub fn validate_bridge_config(c: &BridgeConfig) -> Result<(), ReverseError> {
    if c.tag.is_empty() {
        return Err(ReverseError::BridgeTagEmpty);
    }
    if c.domain.is_empty() {
        return Err(ReverseError::BridgeDomainEmpty);
    }
    Ok(())
}

/// 配置校验 helper：tag/domain 非空。
pub fn validate_portal_config(c: &PortalConfig) -> Result<(), ReverseError> {
    if c.tag.is_empty() {
        return Err(ReverseError::PortalTagEmpty);
    }
    if c.domain.is_empty() {
        return Err(ReverseError::PortalDomainEmpty);
    }
    Ok(())
}

/// 判断 dest domain 是否等于 given domain（对应 Go `isDomain`）。
pub fn is_domain(dest_domain: Option<&str>, expected: &str) -> bool {
    match dest_domain {
        Some(d) => d == expected,
        None => false,
    }
}

/// 判断 dest domain 是否是内部 reverse 域名。
pub fn is_internal_domain(dest_domain: Option<&str>) -> bool {
    is_domain(dest_domain, crate::config::INTERNAL_DOMAIN)
}

/// Bridge 创建 monitor 决策：是否需要新 worker。
///
/// 对应 Go `Bridge.monitor`：worker=0 或 平均 conn > 16 时建新 worker。
pub fn should_create_bridge_worker(worker_count: usize, total_connections: u32) -> bool {
    if worker_count == 0 {
        return true;
    }
    let avg = total_connections / worker_count as u32;
    avg > 16
}

/// Portal picker 选择辅助：从 picker 中选最少连接的 worker。
///
/// 返回 picker snapshot 中的 index。
pub fn pick_portal_worker<W: PickerWorker>(
    picker: &StaticMuxPicker<W>,
) -> Result<usize, ReverseError> {
    picker.pick_available_index()
}

/// 重新导出 Arc<dyn Bridge> / Arc<dyn Portal> 类型别名。
pub type SharedBridge = Arc<dyn Bridge>;
pub type SharedPortal = Arc<dyn Portal>;

// ===========================================================================
// 生产实体（RuntimeBridge / RuntimePortal / LinkDispatch）
//
// 对应 Go `app/reverse/bridge.go`（Bridge 编排：monitor 2s + worker 清理）
// 与 `app/reverse/portal.go`（Portal 编排：picker + outbound 注册）。
// ===========================================================================

use tokio::sync::watch;
use std::time::Duration;

use xray_common::net::destination::Destination;

use crate::worker::{BridgeWorker, PortalWorker};

/// Bridge monitor 周期（Go `bridge.go:44` Interval: 2s）。
pub const BRIDGE_MONITOR_INTERVAL: Duration = Duration::from_secs(2);

/// Portal picker 清理周期（Go `portal.go:149` Interval: 30s）。
pub const PICKER_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

/// 等待停止信号（close 发 true 或 sender 被 drop/摘除）。
async fn wait_stop(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// 真实 dispatcher 抽象（Go `routing.Dispatcher` + ctx inbound tag）。
///
/// 生产实现：[`DefaultDispatcherAdapter`]（包 `DefaultDispatcher::dispatch`，
/// inbound_tag 参数等价 Go `session.ContextWithInbound`）。
#[async_trait::async_trait]
pub trait LinkDispatch: Send + Sync {
    /// 返回式 dispatch（Go `routing.Dispatcher.Dispatch(ctx, dest) (*Link, error)`）。
    async fn dispatch(
        &self,
        dest: &Destination,
        inbound_tag: Option<&str>,
    ) -> Result<xray_transport::link::Link, ReverseError>;

    /// 消费式 dispatch（Go `routing.Dispatcher.DispatchLink`）。
    async fn dispatch_link(
        &self,
        dest: &Destination,
        link: xray_transport::link::Link,
        inbound_tag: Option<&str>,
    ) -> Result<(), ReverseError>;

    /// Reverse-mux bridge 侧带帧内 source/local 的消费式 dispatch（txno④；
    /// Go server.go:166-174 覆写 ctx inbound 的 Source/Local 后 DispatchLink）。
    /// 默认丢弃元数据等价 [`Self::dispatch_link`]。
    async fn dispatch_link_inbound(
        &self,
        dest: &Destination,
        link: xray_transport::link::Link,
        inbound_tag: Option<&str>,
        source: Option<&Destination>,
        local: Option<&Destination>,
    ) -> Result<(), ReverseError> {
        let _ = (source, local);
        self.dispatch_link(dest, link, inbound_tag).await
    }
}

/// 生产适配器：`DefaultDispatcher` → [`LinkDispatch`]。
pub struct DefaultDispatcherAdapter(pub std::sync::Arc<xray_app_dispatcher::DefaultDispatcher>);

#[async_trait::async_trait]
impl LinkDispatch for DefaultDispatcherAdapter {
    async fn dispatch(
        &self,
        dest: &Destination,
        inbound_tag: Option<&str>,
    ) -> Result<xray_transport::link::Link, ReverseError> {
        self.0
            .dispatch(
                dest,
                &xray_app_dispatcher::default::SniffingRequest::default(),
                inbound_tag,
                None,
            )
            .map_err(|e| ReverseError::CreateBridgeWorker(e.to_string()))
    }

    async fn dispatch_link(
        &self,
        dest: &Destination,
        link: xray_transport::link::Link,
        inbound_tag: Option<&str>,
    ) -> Result<(), ReverseError> {
        self.0
            .dispatch_link(
                dest,
                link,
                &xray_app_dispatcher::default::SniffingRequest::default(),
                inbound_tag.map(|tag| xray_app_dispatcher::default::AccessContext {
                    inbound_tag: tag.to_string(),
                    ..Default::default()
                }),
                None,
            )
            .map_err(|e| ReverseError::CreateBridgeWorker(e.to_string()))
    }

    async fn dispatch_link_inbound(
        &self,
        dest: &Destination,
        link: xray_transport::link::Link,
        inbound_tag: Option<&str>,
        source: Option<&Destination>,
        local: Option<&Destination>,
    ) -> Result<(), ReverseError> {
        // AccessContext.from/local 为 "ip:port" 形态（与入站协议层 peer 一致；
        // SourceIpMatcher/Access log 依赖该形态——Destination Display 的
        // "network:addr:port" 形态会让 dispatcher 的 parse_from_ip 失效）。
        // Go server.go:166-174：reverse 帧内 Source/Local 覆写 ctx inbound——
        // bridge 侧本地出站（路由规则/Access 日志）看到真实客户端源。
        let meta = |d: Option<&Destination>| {
            d.map(|x| format!("{}:{}", x.address(), x.port().value()))
                .unwrap_or_default()
        };
        self.0
            .dispatch_link(
                dest,
                link,
                &xray_app_dispatcher::default::SniffingRequest::default(),
                Some(xray_app_dispatcher::default::AccessContext {
                    inbound_tag: inbound_tag.unwrap_or_default().to_string(),
                    from: meta(source),
                    local: meta(local),
                    ..Default::default()
                }),
                None,
            )
            .map_err(|e| ReverseError::CreateBridgeWorker(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// RuntimeBridge
// ---------------------------------------------------------------------------

/// Bridge 编排：周期 monitor 维护 BridgeWorker 池。
///
/// 对应 Go `Bridge`（bridge.go:20-99）：
/// - `monitor`（2s）：清理非活跃 worker；worker=0 或平均连接 > 16 时新建
/// - `Start`/`Close`：启停 monitor 周期任务
pub struct RuntimeBridge {
    dispatcher: std::sync::Arc<dyn LinkDispatch>,
    tag: String,
    domain: String,
    workers: std::sync::Arc<parking_lot::Mutex<Vec<std::sync::Arc<BridgeWorker>>>>,
    /// monitor 停止信号（close 发 true 并摘除 sender；重启建新信道——旧循环
    /// 盯旧信道必然退出，close/start 往返不会叠加 monitor 循环）。
    stop_tx: parking_lot::Mutex<Option<watch::Sender<bool>>>,
}

impl RuntimeBridge {
    /// 对应 Go `NewBridge`（bridge.go:29-47）。
    pub fn new(
        config: &BridgeConfig,
        dispatcher: std::sync::Arc<dyn LinkDispatch>,
    ) -> Result<Self, ReverseError> {
        validate_bridge_config(config)?;
        Ok(Self {
            dispatcher,
            tag: config.tag.clone(),
            domain: config.domain.clone(),
            workers: std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            stop_tx: parking_lot::Mutex::new(None),
        })
    }

    /// monitor 一轮（Go `Bridge.monitor`，bridge.go:68-91）。
    async fn monitor_step(
        dispatcher: &std::sync::Arc<dyn LinkDispatch>,
        domain: &str,
        tag: &str,
        workers: &std::sync::Arc<parking_lot::Mutex<Vec<std::sync::Arc<BridgeWorker>>>>,
    ) -> Result<(), ReverseError> {
        // cleanup（bridge.go:49-66）：保留 IsActive worker。
        // Go 对 Closed worker 调 Timer.SetTimeout(0)——terminate=worker.Close 已
        // 关闭，为幂等 no-op，此处等价省略。
        workers.lock().retain(|w| w.is_active());

        // 快照后逐个 await（parking_lot guard 不可跨 await）
        let active: Vec<std::sync::Arc<BridgeWorker>> = workers
            .lock()
            .iter()
            .filter(|w| w.is_active())
            .cloned()
            .collect();
        let mut num_connections = 0u32;
        let num_worker = active.len() as u32;
        for w in &active {
            num_connections += w.connections().await;
        }

        if should_create_bridge_worker(num_worker as usize, num_connections) {
            match BridgeWorker::new(domain, tag, std::sync::Arc::clone(dispatcher)).await {
                Ok(w) => workers.lock().push(w),
                Err(e) => {
                    // Go bridge.go:83-86：LogWarning + return nil（不中断 monitor）
                    crate::error::at_warning(&e);
                }
            }
        }
        Ok(())
    }
}

impl Bridge for RuntimeBridge {
    fn start(&self) -> Result<(), ReverseError> {
        let mut guard = self.stop_tx.lock();
        if guard.is_some() {
            return Ok(()); // monitor 已在跑
        }
        let (stop_tx, mut stop_rx) = watch::channel(false);
        *guard = Some(stop_tx);
        drop(guard);
        let dispatcher = std::sync::Arc::clone(&self.dispatcher);
        let domain = self.domain.clone();
        let tag = self.tag.clone();
        let workers = std::sync::Arc::clone(&self.workers);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(BRIDGE_MONITOR_INTERVAL) => {}
                    _ = wait_stop(&mut stop_rx) => break,
                }
                if Self::monitor_step(&dispatcher, &domain, &tag, &workers)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(())
    }

    fn close(&self) -> Result<(), ReverseError> {
        // Go `Bridge.Close` = monitorTask.Close()（worker 交由各自 timer 收尾）
        if let Some(tx) = self.stop_tx.lock().take() {
            let _ = tx.send(true);
        }
        Ok(())
    }

    fn worker_count(&self) -> usize {
        self.workers.lock().len()
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn domain(&self) -> &str {
        &self.domain
    }
}

// ---------------------------------------------------------------------------
// RuntimePortal
// ---------------------------------------------------------------------------

/// Portal 编排：picker + outbound 注册。
///
/// 对应 Go `Portal`（portal.go:23-101）：
/// - `Start`：`ohm.AddHandler(tag, &Outbound{...})`；`Close`：RemoveHandler
/// - `HandleConnection`（经 [`crate::outbound::PortalOutbound`]）：目标域命中 →
///   建 ClientWorker+PortalWorker；否则 picker 选 worker dispatch
pub struct RuntimePortal {
    registrar: std::sync::Arc<dyn crate::outbound::OutboundRegistrar>,
    tag: String,
    domain: String,
    picker: std::sync::Arc<StaticMuxPicker<std::sync::Arc<PortalWorker>>>,
    /// picker 清理循环停止信号（语义同 [`RuntimeBridge::stop_tx`]）。
    stop_tx: parking_lot::Mutex<Option<watch::Sender<bool>>>,
}

impl RuntimePortal {
    /// 对应 Go `NewPortal`（portal.go:31-54）。
    pub fn new(
        config: &PortalConfig,
        registrar: std::sync::Arc<dyn crate::outbound::OutboundRegistrar>,
    ) -> Result<Self, ReverseError> {
        validate_portal_config(config)?;
        Ok(Self {
            registrar,
            tag: config.tag.clone(),
            domain: config.domain.clone(),
            picker: std::sync::Arc::new(StaticMuxPicker::new()),
            stop_tx: parking_lot::Mutex::new(None),
        })
    }

    pub fn picker(&self) -> &std::sync::Arc<StaticMuxPicker<std::sync::Arc<PortalWorker>>> {
        &self.picker
    }
}

impl Portal for RuntimePortal {
    fn start(&self) -> Result<(), ReverseError> {
        let mut guard = self.stop_tx.lock();
        if guard.is_some() {
            return Ok(()); // 已在跑
        }
        // Go portal.go:56-61：AddHandler；picker 30s cleanup（portal.go:145-152）
        self.registrar.add_handler(
            &self.tag,
            std::sync::Arc::new(crate::outbound::PortalOutbound::new(
                self.tag.clone(),
                std::sync::Arc::clone(&self.picker),
                self.domain.clone(),
            )),
        )?;
        let (stop_tx, mut stop_rx) = watch::channel(false);
        *guard = Some(stop_tx);
        drop(guard);
        let picker = std::sync::Arc::clone(&self.picker);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(PICKER_CLEANUP_INTERVAL) => {}
                    _ = wait_stop(&mut stop_rx) => break,
                }
                picker.cleanup();
            }
        });
        Ok(())
    }

    fn close(&self) -> Result<(), ReverseError> {
        if let Some(tx) = self.stop_tx.lock().take() {
            let _ = tx.send(true);
        }
        self.registrar.remove_handler(&self.tag)
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn domain(&self) -> &str {
        &self.domain
    }
}

/// Portal worker 的 [`PickerWorker`](crate::picker::PickerWorker) 转发（Arc 容器）。
impl crate::picker::PickerWorker for std::sync::Arc<PortalWorker> {
    fn is_full(&self) -> bool {
        (**self).is_full()
    }

    fn is_closed(&self) -> bool {
        (**self).is_closed()
    }

    fn is_draining(&self) -> bool {
        (**self).is_draining()
    }

    fn active_connections(&self) -> u32 {
        (**self).active_connections()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_bridge_rejects_empty_tag() {
        let c = BridgeConfig {
            tag: "".into(),
            domain: "d".into(),
        };
        assert!(matches!(
            validate_bridge_config(&c),
            Err(ReverseError::BridgeTagEmpty)
        ));
    }

    #[test]
    fn validate_bridge_rejects_empty_domain() {
        let c = BridgeConfig {
            tag: "t".into(),
            domain: "".into(),
        };
        assert!(matches!(
            validate_bridge_config(&c),
            Err(ReverseError::BridgeDomainEmpty)
        ));
    }

    #[test]
    fn validate_bridge_accepts_valid() {
        let c = BridgeConfig {
            tag: "t".into(),
            domain: "d".into(),
        };
        assert!(validate_bridge_config(&c).is_ok());
    }

    #[test]
    fn validate_portal_rejects_empty_tag() {
        let c = PortalConfig {
            tag: "".into(),
            domain: "d".into(),
        };
        assert!(matches!(
            validate_portal_config(&c),
            Err(ReverseError::PortalTagEmpty)
        ));
    }

    #[test]
    fn validate_portal_rejects_empty_domain() {
        let c = PortalConfig {
            tag: "t".into(),
            domain: "".into(),
        };
        assert!(matches!(
            validate_portal_config(&c),
            Err(ReverseError::PortalDomainEmpty)
        ));
    }

    #[test]
    fn is_domain_matches() {
        assert!(is_domain(Some("reverse"), "reverse"));
    }

    #[test]
    fn is_domain_mismatch() {
        assert!(!is_domain(Some("other"), "reverse"));
    }

    #[test]
    fn is_domain_none() {
        assert!(!is_domain(None, "reverse"));
    }

    #[test]
    fn is_internal_domain_recognizes() {
        assert!(is_internal_domain(Some("reverse")));
        assert!(!is_internal_domain(Some("other")));
        assert!(!is_internal_domain(None));
    }

    #[test]
    fn should_create_when_zero_workers() {
        assert!(should_create_bridge_worker(0, 0));
    }

    #[test]
    fn should_create_when_avg_above_threshold() {
        // 1 worker, 17 connections → avg 17 > 16
        assert!(should_create_bridge_worker(1, 17));
    }

    #[test]
    fn should_not_create_when_avg_at_or_below_threshold() {
        // 2 workers, 32 connections → avg 16 (== 16, not > 16)
        assert!(!should_create_bridge_worker(2, 32));
        // 2 workers, 30 connections → avg 15
        assert!(!should_create_bridge_worker(2, 30));
    }
}
