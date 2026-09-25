//! KCP 连接 6 态状态机（对应 Go `connection.go` 的 `State` 类型）。
//!
//! 状态转移图（Go 注释）：
//!
//! ```text
//! StateActive (0)
//!     │ local close   │ peer close    │ peer terminate
//!     ▼               ▼               ▼
//! StateReadyToClose  StatePeerClosed  StatePeerTerminating
//!     │ peer close       │ local close
//!     ▼                  ▼
//! StateTerminating ◄────┐
//!     │ timeout 8s
//!     ▼
//! StateTerminated (5)   ← 最终态
//! ```

use std::fmt;

/// 连接状态（i32 表示，对应 Go `type State int32`；使用 atomic 操作）。
///
/// 数值与 Go 完全对齐（prost build 时 `State` 为自由 i32 类型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum State {
    /// 连接活跃（初始态）。
    Active = 0,
    /// 本端已关闭（local close）。
    ReadyToClose = 1,
    /// 对端已关闭（peer close）。
    PeerClosed = 2,
    /// 本端开始终止（即将销毁）。
    Terminating = 3,
    /// 对端开始终止。
    PeerTerminating = 4,
    /// 已终止（最终态，资源可释放）。
    Terminated = 5,
}

impl State {
    /// 从 i32 原子值恢复（对应 Go `State(atomic.LoadInt32(...))`）。
    ///
    /// 未知值返回 `None`（与 Go 不一致 —— Go 直接强转；Rust 更稳健）。
    #[must_use]
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Active),
            1 => Some(Self::ReadyToClose),
            2 => Some(Self::PeerClosed),
            3 => Some(Self::Terminating),
            4 => Some(Self::PeerTerminating),
            5 => Some(Self::Terminated),
            _ => None,
        }
    }

    /// 当前状态是否为候选之一（对应 Go `State.Is(states...)`）。
    #[must_use]
    pub fn is(self, candidates: &[State]) -> bool {
        candidates.iter().any(|&s| s == self)
    }

    /// 是否为「已经本端关闭」状态（ReadyToClose / Terminating / Terminated）。
    ///
    /// 对应 Go `Read` / `ReadMultiBuffer` 中 `c.State().Is(StateReadyToClose,
    /// StateTerminating, StateTerminated)` 的判定。
    #[must_use]
    pub fn is_locally_closed(self) -> bool {
        matches!(self, Self::ReadyToClose | Self::Terminating | Self::Terminated)
    }

    /// 是否已彻底结束（最终态）。
    #[must_use]
    pub fn is_terminated(self) -> bool {
        matches!(self, Self::Terminated)
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Active => "Active",
            Self::ReadyToClose => "ReadyToClose",
            Self::PeerClosed => "PeerClosed",
            Self::Terminating => "Terminating",
            Self::PeerTerminating => "PeerTerminating",
            Self::Terminated => "Terminated",
        })
    }
}

/// Active 状态常量（语义化构造，常用场景）。
pub const STATE_ACTIVE: State = State::Active;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_i32_round_trip() {
        for v in 0..=5 {
            let s = State::from_i32(v).unwrap_or_else(|| panic!("v={v}"));
            assert_eq!(s as i32, v);
        }
    }

    #[test]
    fn from_i32_unknown_returns_none() {
        assert_eq!(State::from_i32(-1), None);
        assert_eq!(State::from_i32(6), None);
        assert_eq!(State::from_i32(100), None);
    }

    #[test]
    fn is_predicate_matches() {
        assert!(State::Active.is(&[State::Active]));
        assert!(State::Active.is(&[State::ReadyToClose, State::Active]));
        assert!(!State::Active.is(&[State::Terminated]));
        assert!(!State::Active.is(&[])); // 空候选表永远 false
    }

    #[test]
    fn is_locally_closed_covers_three_variants() {
        assert!(State::ReadyToClose.is_locally_closed());
        assert!(State::Terminating.is_locally_closed());
        assert!(State::Terminated.is_locally_closed());
        assert!(!State::Active.is_locally_closed());
        assert!(!State::PeerClosed.is_locally_closed());
        assert!(!State::PeerTerminating.is_locally_closed());
    }

    #[test]
    fn display_matches_go_string() {
        assert_eq!(State::Active.to_string(), "Active");
        assert_eq!(State::PeerClosed.to_string(), "PeerClosed");
        assert_eq!(State::PeerTerminating.to_string(), "PeerTerminating");
    }
}
