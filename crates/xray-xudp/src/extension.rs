//! XUDP extension handling for Mux integration.
//!
//! Provides XUDP session management and Mux extension types.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

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

/// Global XUDP session manager.
///
/// Manages XUDP sessions across Mux connections.
/// Periodically cleans up expired sessions.
pub struct XudpManager {
    sessions: Mutex<HashMap<[u8; 8], XudpSession>>,
}

impl XudpManager {
    /// Create a new XUDP manager.
    pub fn new() -> Self {
        Self { sessions: Mutex::new(HashMap::new()) }
    }

    /// Get or create an XUDP session for the given Global ID.
    pub fn get_or_create(&self, global_id: [u8; 8]) -> XudpStatus {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(session) = sessions.get_mut(&global_id) {
            if session.is_expired() {
                session.status = XudpStatus::Initializing;
                session.expire = Instant::now() + Duration::from_secs(60);
            }
            session.status
        } else {
            let session = XudpSession::new(global_id);
            let status = session.status;
            sessions.insert(global_id, session);
            status
        }
    }

    /// Remove an XUDP session.
    pub fn remove(&self, global_id: &[u8; 8]) -> bool {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.remove(global_id).is_some()
    }

    /// Clean up expired sessions.
    pub fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let before = sessions.len();
        sessions.retain(|_, session| !session.is_expired());
        before - sessions.len()
    }

    /// Return the number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Check if there are no sessions.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for XudpManager {
    fn default() -> Self {
        Self::new()
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
    fn test_xudp_manager_new() {
        let mgr = XudpManager::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn test_xudp_manager_get_or_create() {
        let mgr = XudpManager::new();
        let id = [42u8; 8];
        let status = mgr.get_or_create(id);
        assert_eq!(status, XudpStatus::Initializing);
        assert_eq!(mgr.len(), 1);
        // Second call returns existing
        let status2 = mgr.get_or_create(id);
        assert_eq!(status2, XudpStatus::Initializing);
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn test_xudp_manager_remove() {
        let mgr = XudpManager::new();
        let id = [42u8; 8];
        mgr.get_or_create(id);
        assert!(mgr.remove(&id));
        assert!(mgr.is_empty());
        assert!(!mgr.remove(&id)); // already removed
    }

    #[test]
    fn test_xudp_manager_cleanup() {
        let mgr = XudpManager::new();
        let id1 = [1u8; 8];
        let id2 = [2u8; 8];
        mgr.get_or_create(id1);
        mgr.get_or_create(id2);
        assert_eq!(mgr.len(), 2);
        // None expired yet
        let removed = mgr.cleanup_expired();
        assert_eq!(removed, 0);
        assert_eq!(mgr.len(), 2);
    }

    #[test]
    fn test_xudp_manager_default() {
        let mgr = XudpManager::default();
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_xudp_session_expired() {
        let id = [1u8; 8];
        let mut session = XudpSession::new(id);
        session.expire = Instant::now() - Duration::from_secs(1);
        assert!(session.is_expired());
    }
}
