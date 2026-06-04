//! 网络类型定义
//!
//! 对应 Go 版本 `common/net/network.go`，定义网络协议枚举类型。

use serde::{Deserialize, Serialize};

/// 网络协议类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Network {
    TCP,
    UDP,
    Unix,
}

impl Network {
    /// 返回协议的字符串表示。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TCP => "tcp",
            Self::UDP => "udp",
            Self::Unix => "unix",
        }
    }

    /// 从字符串解析网络协议。
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Some(Self::TCP),
            "udp" => Some(Self::UDP),
            "unix" => Some(Self::Unix),
            _ => None,
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_str() {
        assert_eq!(Network::TCP.as_str(), "tcp");
        assert_eq!(Network::UDP.as_str(), "udp");
        assert_eq!(Network::Unix.as_str(), "unix");
    }

    #[test]
    fn test_from_str() {
        assert_eq!(Network::from_str("tcp"), Some(Network::TCP));
        assert_eq!(Network::from_str("udp"), Some(Network::UDP));
        assert_eq!(Network::from_str("unix"), Some(Network::Unix));
        assert_eq!(Network::from_str("TCP"), Some(Network::TCP));
        assert_eq!(Network::from_str("unknown"), None);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Network::TCP), "tcp");
        assert_eq!(format!("{}", Network::UDP), "udp");
        assert_eq!(format!("{}", Network::Unix), "unix");
    }

    #[test]
    fn test_equality() {
        assert_eq!(Network::TCP, Network::TCP);
        assert_ne!(Network::TCP, Network::UDP);
    }

    #[test]
    fn test_copy() {
        let a = Network::TCP;
        let b = a;
        assert_eq!(a, b);
    }
}
