//! UDP-over-TCP（UoT v2）帧 —— anytls 生态的 UDP 承载约定。
//!
//! 规范来源 `github.com/SagerNet/sing/common/uot`（anytls / sing-box / mihomo 共用）：
//!
//! 1. 客户端以 **magic 目标** `sp.v2.udp-over-tcp.arpa` 建 TCP 会话（端口 0）；
//! 2. 会话首帧 = `Request`：`[1B isConnect][SOCKS5 addr]`（标准 ATYP 1/3/4）；
//! 3. 之后每个数据报：`isConnect=true` 时 `[2B BE len][payload]`（目标固定为 Request
//!    里的目标）；`isConnect=false` 时每包前再带 `[1B atyp{0=IPv4,1=IPv6,2=Fqdn}][addr][2B
//!    len][payload]`。
//!
//! 本仓实现 **isConnect=true** 单目标形态（与 Xray 的「一线程一目标」UDP 模型
//! 一致）；`isConnect=false`（每包自带目标，cone 语义）在服务端显式拒绝并记日志
//! —— 静默按单目标处理会错投到首包目标。
//!
//! 帧本体（第 3 条）的编解码**只有一份实现**：`xray_app_dispatcher::udp_session::
//! XudpWireConn`（link 的 XUDP 帧 ↔ wire `[2B len][payload]`），客户端
//! [`crate::dispatcher::make_dial_fn`] 与服务端 `server::serve_uot_session` 共用它。
//! 本模块只管 magic 目标探测与 `Request` 编解码——两侧各写一份帧实现正是
//! bd b5e77 的线格式漂移根因。

use crate::{
    error::{AnytlsError, Result},
    socks::SocksAddr,
};

/// UoT v2 magic 目标域名。
pub const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
/// UoT v1 兼容 magic 目标域名（同一 framing，仅探测用）。
pub const LEGACY_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";

/// 目标域名是否是 UoT magic（任一版本）。
#[must_use]
pub fn is_magic(host: &str) -> bool {
    host == MAGIC_ADDRESS || host == LEGACY_MAGIC_ADDRESS
}

/// 编码 `Request`：`[1B isConnect][SOCKS5 addr]`。
pub fn encode_request(is_connect: bool, dest: &SocksAddr) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(32);
    out.push(u8::from(is_connect));
    out.extend_from_slice(&dest.encode()?);
    Ok(out)
}

/// 解析 `Request`。`Ok(None)` = 字节不足（调用方继续读）。
pub fn decode_request(buf: &[u8]) -> Result<Option<(bool, SocksAddr, usize)>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    // [1B isConnect][1B atyp]...
    let need = match buf[1] {
        // atyp IPv4：1 + 4 + 2
        0x01 => 1 + 1 + 4 + 2,
        // atyp IPv6：1 + 1 + 16 + 2
        0x04 => 1 + 1 + 16 + 2,
        // atyp 域名：1 + 1 + 1(len) + len + 2
        0x03 => {
            if buf.len() < 3 {
                return Ok(None);
            }
            1 + 1 + 1 + usize::from(buf[2]) + 2
        },
        other => {
            return Err(AnytlsError::InvalidSocksAddr(format!("uot: unknown atyp {other}")));
        },
    };
    if buf.len() < need {
        return Ok(None);
    }
    let (dest, used) = SocksAddr::decode(&buf[1..])?;
    let is_connect = buf[0] != 0;
    Ok(Some((is_connect, dest, 1 + used)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip_ipv4() {
        let dest = SocksAddr::ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8), 53);
        let bytes = encode_request(true, &dest).unwrap();
        assert_eq!(bytes[0], 1, "isConnect 前缀");
        assert_eq!(bytes[1], 0x01, "atyp IPv4");
        let (is_connect, got, used) = decode_request(&bytes).unwrap().expect("complete");
        assert!(is_connect);
        assert_eq!(got, dest);
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn request_roundtrip_domain() {
        let dest = SocksAddr::domain("example.com", 443);
        let bytes = encode_request(false, &dest).unwrap();
        let (is_connect, got, used) = decode_request(&bytes).unwrap().expect("complete");
        assert!(!is_connect);
        assert_eq!(got, dest);
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn request_incomplete_returns_none() {
        let dest = SocksAddr::domain("abcd.example", 53);
        let bytes = encode_request(true, &dest).unwrap();
        for cut in 0..bytes.len() {
            assert!(decode_request(&bytes[..cut]).unwrap().is_none(), "cut={cut} must be None");
        }
        assert!(decode_request(&bytes).unwrap().is_some());
    }

    #[test]
    fn magic_address_detection() {
        assert!(is_magic("sp.v2.udp-over-tcp.arpa"));
        assert!(is_magic("sp.udp-over-tcp.arpa"));
        assert!(!is_magic("example.com"));
    }
}
