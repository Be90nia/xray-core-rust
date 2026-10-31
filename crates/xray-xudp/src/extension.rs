//! XUDP extension handling for Mux integration.
//!
//! Provides XUDP session management and Mux extension types.

use std::time::{Duration, Instant};

/// XUDP session status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XudpStatus {
    /// Session is being initialized.
    Initializing = 0,
    /// Session is active.
    Active = 1,
    /// Session is expiring.
    Expiring = 2,
}

impl From<u64> for XudpStatus {
    fn from(v: u64) -> Self {
        match v {
            0 => XudpStatus::Initializing,
            1 => XudpStatus::Active,
            2 => XudpStatus::Expiring,
            _ => XudpStatus::Initializing,
        }
    }
}

impl From<XudpStatus> for u64 {
    fn from(s: XudpStatus) -> Self {
        s as u64
    }
}

/// XUDP session associated with a Mux session.
#[derive(Debug)]
pub struct XudpSession {
    /// 8-byte Global ID.
    pub global_id: [u8; 8],
    /// Current status.
    pub status: XudpStatus,
    /// Expiration time.
    pub expire: Instant,
}

#[allow(
    clippy::disallowed_methods,
    reason = "XUDP 会话 TTL 判定；XudpSession 为纯协议结构无 ctx 注入面（713x6 台账：结构性不可达→出口已就位 xray-frame::compat::clock，待迁）"
)]
impl XudpSession {
    /// Create a new XUDP session with the given Global ID.
    pub fn new(global_id: [u8; 8]) -> Self {
        Self {
            global_id,
            status: XudpStatus::Initializing,
            expire: Instant::now() + Duration::from_secs(60),
        }
    }

    /// Check if the session has expired.
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expire
    }

    /// Activate the session.
    pub fn activate(&mut self) {
        self.status = XudpStatus::Active;
    }

    /// Mark the session as expiring.
    pub fn expire_session(&mut self) {
        self.status = XudpStatus::Expiring;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xudp_status_conversions() {
        assert_eq!(XudpStatus::from(0u64), XudpStatus::Initializing);
        assert_eq!(XudpStatus::from(1u64), XudpStatus::Active);
        assert_eq!(XudpStatus::from(2u64), XudpStatus::Expiring);
        assert_eq!(u64::from(XudpStatus::Initializing), 0);
        assert_eq!(u64::from(XudpStatus::Active), 1);
        assert_eq!(u64::from(XudpStatus::Expiring), 2);
    }

    #[test]
    fn test_xudp_session_new() {
        let id = [1u8; 8];
        let session = XudpSession::new(id);
        assert_eq!(session.global_id, id);
        assert_eq!(session.status, XudpStatus::Initializing);
        assert!(!session.is_expired());
    }

    #[test]
    fn test_xudp_session_activate() {
        let id = [1u8; 8];
        let mut session = XudpSession::new(id);
        session.activate();
        assert_eq!(session.status, XudpStatus::Active);
    }

    #[test]
    fn test_xudp_session_expire() {
        let id = [1u8; 8];
        let mut session = XudpSession::new(id);
        session.expire_session();
        assert_eq!(session.status, XudpStatus::Expiring);
    }

    #[test]
    fn test_xudp_session_expired() {
        let id = [1u8; 8];
        let mut session = XudpSession::new(id);
        session.expire = Instant::now() - Duration::from_secs(1);
        assert!(session.is_expired());
    }
}
