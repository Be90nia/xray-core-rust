//! 网络端口类型定义
//!
//! 对应 Go 版本 `common/net/port.go`，定义端口、端口范围和端口列表类型。

use serde::{Deserialize, Serialize};

/// 网络端口号（0-65535）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Port(u16);

impl Port {
    /// 最大端口号。
    pub const MAX: Port = Port(65535);
    /// 最小端口号。
    pub const MIN: Port = Port(0);

    /// 创建新的端口号。
    #[must_use]
    pub fn new(port: u16) -> Self {
        Self(port)
    }

    /// 获取端口号的数值。
    #[must_use]
    pub fn value(&self) -> u16 {
        self.0
    }

    /// 检查端口号是否在有效用户范围内（> 0）。
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.0 > 0
    }
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u16> for Port {
    fn from(port: u16) -> Self {
        Self(port)
    }
}

impl From<Port> for u16 {
    fn from(port: Port) -> Self {
        port.0
    }
}

/// 端口范围 [from, to]，包含两端。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortRange {
    from: Port,
    to: Port,
}

impl PortRange {
    /// 创建新的端口范围。
    #[must_use]
    pub fn new(from: Port, to: Port) -> Self {
        Self { from, to }
    }

    /// 获取起始端口。
    #[must_use]
    pub fn from_port(&self) -> Port {
        self.from
    }

    /// 获取结束端口。
    #[must_use]
    pub fn to_port(&self) -> Port {
        self.to
    }

    /// 检查给定端口是否在此范围内。
    #[must_use]
    pub fn contains(&self, port: Port) -> bool {
        port >= self.from && port <= self.to
    }
}

impl std::fmt::Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.from, self.to)
    }
}

/// 内存端口范围，用于 protobuf 消息的端口范围表示。
///
/// 对应 Go 版本的 `MemoryPortRange`，语义与 `PortRange` 相同，
/// 但提供独立的类型以区分 proto 层和使用层。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemoryPortRange(PortRange);

impl MemoryPortRange {
    /// 从端口范围创建。
    #[must_use]
    pub fn new(from: Port, to: Port) -> Self {
        Self(PortRange::new(from, to))
    }

    /// 从 `PortRange` 创建。
    #[must_use]
    pub fn from_range(range: PortRange) -> Self {
        Self(range)
    }

    /// 获取起始端口。
    #[must_use]
    pub fn from_port(&self) -> Port {
        self.0.from_port()
    }

    /// 获取结束端口。
    #[must_use]
    pub fn to_port(&self) -> Port {
        self.0.to_port()
    }

    /// 检查给定端口是否在此范围内。
    #[must_use]
    pub fn contains(&self, port: Port) -> bool {
        self.0.contains(port)
    }

    /// 获取内部 `PortRange` 的引用。
    #[must_use]
    pub fn as_range(&self) -> &PortRange {
        &self.0
    }

    /// 消费自身，返回内部 `PortRange`。
    #[must_use]
    pub fn into_range(self) -> PortRange {
        self.0
    }
}

impl std::fmt::Display for MemoryPortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// 端口列表，包含多个端口范围。
///
/// 对应 Go 版本的 `MemoryPortList`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryPortList {
    ranges: Vec<PortRange>,
}

impl MemoryPortList {
    /// 从端口范围列表创建。
    #[must_use]
    pub fn new(ranges: Vec<PortRange>) -> Self {
        Self { ranges }
    }

    /// 创建空的端口列表。
    #[must_use]
    pub fn empty() -> Self {
        Self { ranges: Vec::new() }
    }

    /// 获取端口范围列表的引用。
    #[must_use]
    pub fn ranges(&self) -> &[PortRange] {
        &self.ranges
    }

    /// 检查给定端口是否在任一范围内。
    #[must_use]
    pub fn contains(&self, port: Port) -> bool {
        self.ranges.iter().any(|r| r.contains(port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_new() {
        let port = Port::new(80);
        assert_eq!(port.value(), 80);
    }

    #[test]
    fn test_port_constants() {
        assert_eq!(Port::MIN.value(), 0);
        assert_eq!(Port::MAX.value(), 65535);
    }

    #[test]
    fn test_port_is_valid() {
        assert!(!Port::new(0).is_valid());
        assert!(Port::new(1).is_valid());
        assert!(Port::new(80).is_valid());
        assert!(Port::new(65535).is_valid());
    }

    #[test]
    fn test_port_display() {
        assert_eq!(format!("{}", Port::new(443)), "443");
    }

    #[test]
    fn test_port_from_u16() {
        let port: Port = 8080u16.into();
        assert_eq!(port.value(), 8080);
    }

    #[test]
    fn test_port_into_u16() {
        let port = Port::new(443);
        let val: u16 = port.into();
        assert_eq!(val, 443);
    }

    #[test]
    fn test_port_ordering() {
        assert!(Port::new(80) < Port::new(443));
        assert!(Port::new(443) > Port::new(80));
        assert_eq!(Port::new(80), Port::new(80));
    }

    #[test]
    fn test_port_range_new() {
        let range = PortRange::new(Port::new(80), Port::new(443));
        assert_eq!(range.from_port(), Port::new(80));
        assert_eq!(range.to_port(), Port::new(443));
    }

    #[test]
    fn test_port_range_contains() {
        let range = PortRange::new(Port::new(80), Port::new(443));
        assert!(range.contains(Port::new(80)));
        assert!(range.contains(Port::new(443)));
        assert!(range.contains(Port::new(200)));
        assert!(!range.contains(Port::new(79)));
        assert!(!range.contains(Port::new(444)));
    }

    #[test]
    fn test_port_range_display() {
        let range = PortRange::new(Port::new(80), Port::new(443));
        assert_eq!(format!("{range}"), "80-443");
    }

    #[test]
    fn test_memory_port_range_new() {
        let mpr = MemoryPortRange::new(Port::new(100), Port::new(200));
        assert_eq!(mpr.from_port(), Port::new(100));
        assert_eq!(mpr.to_port(), Port::new(200));
    }

    #[test]
    fn test_memory_port_range_from_range() {
        let range = PortRange::new(Port::new(1), Port::new(10));
        let mpr = MemoryPortRange::from_range(range);
        assert_eq!(mpr.as_range(), &PortRange::new(Port::new(1), Port::new(10)));
    }

    #[test]
    fn test_memory_port_range_contains() {
        let mpr = MemoryPortRange::new(Port::new(80), Port::new(443));
        assert!(mpr.contains(Port::new(80)));
        assert!(!mpr.contains(Port::new(79)));
    }

    #[test]
    fn test_memory_port_range_into_range() {
        let mpr = MemoryPortRange::new(Port::new(1), Port::new(100));
        let range = mpr.into_range();
        assert_eq!(range.from_port(), Port::new(1));
        assert_eq!(range.to_port(), Port::new(100));
    }

    #[test]
    fn test_memory_port_range_display() {
        let mpr = MemoryPortRange::new(Port::new(80), Port::new(443));
        assert_eq!(format!("{mpr}"), "80-443");
    }

    #[test]
    fn test_memory_port_list_new() {
        let list = MemoryPortList::new(vec![
            PortRange::new(Port::new(80), Port::new(80)),
            PortRange::new(Port::new(443), Port::new(443)),
        ]);
        assert_eq!(list.ranges().len(), 2);
    }

    #[test]
    fn test_memory_port_list_empty() {
        let list = MemoryPortList::empty();
        assert!(list.ranges().is_empty());
        assert!(!list.contains(Port::new(80)));
    }

    #[test]
    fn test_memory_port_list_contains() {
        let list = MemoryPortList::new(vec![
            PortRange::new(Port::new(80), Port::new(80)),
            PortRange::new(Port::new(443), Port::new(445)),
        ]);
        assert!(list.contains(Port::new(80)));
        assert!(!list.contains(Port::new(81)));
        assert!(list.contains(Port::new(443)));
        assert!(list.contains(Port::new(444)));
        assert!(list.contains(Port::new(445)));
        assert!(!list.contains(Port::new(446)));
    }

    #[test]
    fn test_serde_roundtrip_port() {
        let port = Port::new(8080);
        let json = serde_json::to_string(&port).expect("serialize");
        let deserialized: Port = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(port, deserialized);
    }

    #[test]
    fn test_serde_roundtrip_port_range() {
        let range = PortRange::new(Port::new(80), Port::new(443));
        let json = serde_json::to_string(&range).expect("serialize");
        let deserialized: PortRange = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(range, deserialized);
    }

    #[test]
    fn test_serde_roundtrip_memory_port_list() {
        let list = MemoryPortList::new(vec![
            PortRange::new(Port::new(22), Port::new(22)),
            PortRange::new(Port::new(80), Port::new(443)),
        ]);
        let json = serde_json::to_string(&list).expect("serialize");
        let deserialized: MemoryPortList = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(list, deserialized);
    }
}
