//! Portal/Bridge worker 纯决策逻辑。
//!
//! 对应 Go `portal.go` 的 `PortalWorker.heartbeat` 决策部分 +
//! `bridge.go` 的 `BridgeWorker.IsActive` 状态判断。
//! 实际 IO（pipe 读写、timer、mux client）由后续 Phase 接入。

use crate::config::ControlState;
use crate::error::ReverseError;

/// Portal worker 进入 drain 状态的总连接数阈值。
/// 对应 Go `portal.go` 的 `w.client.TotalConnections() > 256`。
pub const DRAIN_THRESHOLD: u32 = 256;

/// Heartbeat counter 模数。
/// 对应 Go `portal.go` 的 `w.counter = (w.counter + 1) % 5`。
pub const HEARTBEAT_COUNTER_MOD: u8 = 5;

/// Portal worker heartbeat 决策结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatDecision {
    /// 本次 heartbeat 是否应进入 drain（total_connections 超阈值）。
    pub should_drain: bool,
    /// 是否应发送 Control 消息（draining 或 counter == 1）。
    pub should_send: bool,
    /// 更新后的 counter 值。
    pub new_counter: u8,
    /// Control 消息的 state 字段。
    pub control_state: ControlState,
}

/// Portal worker 状态快照（heartbeat 决策输入）。
///
/// 对应 Go `PortalWorker` 在 heartbeat 时刻读取的字段集合。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortalWorkerState {
    /// worker 是否已关闭。
    pub closed: bool,
    /// 是否已进入 drain 状态。
    pub already_draining: bool,
    /// writer 是否存在（Go 中 `w.writer != nil`）。
    pub writer_present: bool,
    /// 当前总连接数。
    pub total_connections: u32,
    /// 当前 heartbeat counter。
    pub counter: u8,
}

/// Portal worker heartbeat 决策（对应 Go `PortalWorker.heartbeat` 的纯逻辑部分）。
///
/// 预检查（与 Go 一致）：
/// - `closed` → `Err(WorkerStopped)`
/// - `already_draining || !writer_present` → `Err(AlreadyDisposed)`
///
/// 决策：
/// - `total_connections > DRAIN_THRESHOLD` → 本次进入 drain
/// - `counter = (counter + 1) % HEARTBEAT_COUNTER_MOD`
/// - `should_drain || counter == 1` → 发送 Control
pub fn portal_heartbeat_decision(
    state: &PortalWorkerState,
) -> Result<HeartbeatDecision, ReverseError> {
    if state.closed {
        return Err(ReverseError::WorkerStopped);
    }
    if state.already_draining || !state.writer_present {
        return Err(ReverseError::AlreadyDisposed);
    }

    let should_drain = state.total_connections > DRAIN_THRESHOLD;
    let new_counter = (state.counter + 1) % HEARTBEAT_COUNTER_MOD;
    let should_send = should_drain || new_counter == 1;
    let control_state = if should_drain {
        ControlState::Drain
    } else {
        ControlState::Active
    };

    Ok(HeartbeatDecision {
        should_drain,
        should_send,
        new_counter,
        control_state,
    })
}

/// Bridge worker 是否活跃（对应 Go `BridgeWorker.IsActive`）。
///
/// `state == Active && !worker_closed`
#[must_use]
pub fn bridge_worker_is_active(state: ControlState, worker_closed: bool) -> bool {
    matches!(state, ControlState::Active) && !worker_closed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(closed: bool, draining: bool, writer: bool, conn: u32, counter: u8) -> PortalWorkerState {
        PortalWorkerState {
            closed,
            already_draining: draining,
            writer_present: writer,
            total_connections: conn,
            counter,
        }
    }

    // --- portal_heartbeat_decision ---

    #[test]
    fn heartbeat_closed_returns_worker_stopped() {
        let err = portal_heartbeat_decision(&state(true, false, true, 0, 0)).unwrap_err();
        assert!(matches!(err, ReverseError::WorkerStopped));
    }

    #[test]
    fn heartbeat_already_draining_returns_disposed() {
        let err = portal_heartbeat_decision(&state(false, true, true, 0, 0)).unwrap_err();
        assert!(matches!(err, ReverseError::AlreadyDisposed));
    }

    #[test]
    fn heartbeat_no_writer_returns_disposed() {
        let err = portal_heartbeat_decision(&state(false, false, false, 0, 0)).unwrap_err();
        assert!(matches!(err, ReverseError::AlreadyDisposed));
    }

    #[test]
    fn heartbeat_below_threshold_no_drain() {
        let d = portal_heartbeat_decision(&state(false, false, true, 100, 0)).unwrap();
        assert!(!d.should_drain);
        assert_eq!(d.control_state, ControlState::Active);
    }

    #[test]
    fn heartbeat_at_threshold_no_drain() {
        // 256 is NOT > 256, so no drain
        let d = portal_heartbeat_decision(&state(false, false, true, DRAIN_THRESHOLD, 0)).unwrap();
        assert!(!d.should_drain);
        assert_eq!(d.control_state, ControlState::Active);
    }

    #[test]
    fn heartbeat_above_threshold_drains() {
        let d = portal_heartbeat_decision(&state(false, false, true, DRAIN_THRESHOLD + 1, 0)).unwrap();
        assert!(d.should_drain);
        assert_eq!(d.control_state, ControlState::Drain);
    }

    #[test]
    fn heartbeat_counter_wraps_mod5() {
        // counter 4 → (4+1)%5 = 0
        let d = portal_heartbeat_decision(&state(false, false, true, 0, 4)).unwrap();
        assert_eq!(d.new_counter, 0);
        // counter 0 → (0+1)%5 = 1
        let d = portal_heartbeat_decision(&state(false, false, true, 0, 0)).unwrap();
        assert_eq!(d.new_counter, 1);
        // counter 3 → (3+1)%5 = 4
        let d = portal_heartbeat_decision(&state(false, false, true, 0, 3)).unwrap();
        assert_eq!(d.new_counter, 4);
    }

    #[test]
    fn heartbeat_sends_when_counter_is_1() {
        // counter 0 → new_counter 1 → should_send = true (even without drain)
        let d = portal_heartbeat_decision(&state(false, false, true, 0, 0)).unwrap();
        assert!(d.should_send);
    }

    #[test]
    fn heartbeat_does_not_send_when_counter_not_1_and_no_drain() {
        // counter 1 → new_counter 2, no drain → should_send = false
        let d = portal_heartbeat_decision(&state(false, false, true, 0, 1)).unwrap();
        assert!(!d.should_send);
    }

    #[test]
    fn heartbeat_drain_always_sends() {
        // Even if counter is not 1, drain forces send
        let d = portal_heartbeat_decision(&state(false, false, true, DRAIN_THRESHOLD + 1, 1)).unwrap();
        assert!(d.should_drain);
        assert!(d.should_send);
    }

    #[test]
    fn heartbeat_full_cycle() {
        // Simulate 5 heartbeats: only counter==1 and drain should send
        let mut counter = 0u8;
        let mut send_count = 0;
        for _ in 0..5 {
            let st = state(false, false, true, 10, counter);
            let d = portal_heartbeat_decision(&st).unwrap();
            if d.should_send {
                send_count += 1;
            }
            counter = d.new_counter;
        }
        // In 5 iterations, counter cycles 1,2,3,4,0 — only counter==1 sends once
        assert_eq!(send_count, 1);
    }

    // --- bridge_worker_is_active ---

    #[test]
    fn bridge_active_when_active_state_and_not_closed() {
        assert!(bridge_worker_is_active(ControlState::Active, false));
    }

    #[test]
    fn bridge_inactive_when_drain_state() {
        assert!(!bridge_worker_is_active(ControlState::Drain, false));
    }

    #[test]
    fn bridge_inactive_when_closed() {
        assert!(!bridge_worker_is_active(ControlState::Active, true));
    }

    #[test]
    fn bridge_inactive_when_drain_and_closed() {
        assert!(!bridge_worker_is_active(ControlState::Drain, true));
    }

    #[test]
    fn drain_threshold_constant() {
        assert_eq!(DRAIN_THRESHOLD, 256);
    }

    #[test]
    fn heartbeat_counter_mod_constant() {
        assert_eq!(HEARTBEAT_COUNTER_MOD, 5);
    }
}
