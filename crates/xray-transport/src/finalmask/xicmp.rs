//! # D10: xICMP 伪装
//!
//! 对应 Go `transport/internet/finalmask/xicmp/`。
//!
//! 把代理流量伪装成 ICMP echo（ping）——payload 编码在 ICMP 包的 data 字段。
//!
//! ## TODO rpn-future
//!
//! - 实现 ICMP echo 包装（payload → ICMP data）
//! - 实现 ICMP echo 解包
//! - 实现 raw socket 收发（需 CAP_NET_RAW）

/// xICMP 配置。
#[derive(Debug, Clone)]
pub struct XicmpConfig {
    /// 伪装的源 IP。
    pub source_ip: Option<std::net::Ipv4Addr>,
    /// 伪装的目标 IP。
    pub target_ip: Option<std::net::Ipv4Addr>,
    /// ICMP identifier（通常为 PID）。
    pub identifier: u16,
    /// 每包最大 payload（字节，ICMP data 通常 ≤ 1472）。
    pub max_payload_per_packet: usize,
}

impl Default for XicmpConfig {
    fn default() -> Self {
        Self {
            source_ip: None,
            target_ip: None,
            identifier: 0,
            max_payload_per_packet: 1472,
        }
    }
}

/// xICMP session（stub）。
pub struct XicmpSession {
    config: XicmpConfig,
    sequence: std::sync::atomic::AtomicU16,
}

impl XicmpSession {
    #[must_use]
    pub fn new(config: XicmpConfig) -> Self {
        Self {
            config,
            sequence: std::sync::atomic::AtomicU16::new(0),
        }
    }

    /// 构造一个 ICMP echo 包（stub：仅返回 data 部分）。
    ///
    /// TODO rpn-future: 构造完整 ICMP header（type=8 + code=0 + checksum + id + seq + data）。
    pub fn build_echo(&self, payload: &[u8]) -> Vec<u8> {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut packet = Vec::with_capacity(8 + payload.len());
        // ICMP header stub
        packet.push(8); // type = Echo Request
        packet.push(0); // code
        packet.extend_from_slice(&[0u8, 0u8]); // checksum (stub)
        packet.extend_from_slice(&self.config.identifier.to_be_bytes());
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_increments_sequence() {
        let sess = XicmpSession::new(XicmpConfig::default());
        let p1 = sess.build_echo(b"a");
        let p2 = sess.build_echo(b"b");
        // sequence 字段在 offset 6..8
        let s1 = u16::from_be_bytes([p1[6], p1[7]]);
        let s2 = u16::from_be_bytes([p2[6], p2[7]]);
        assert_eq!(s2, s1 + 1);
    }
}
