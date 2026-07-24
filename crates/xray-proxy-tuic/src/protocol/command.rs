//! TUIC v5 命令类型（VER + TYPE + 负载）。
//!
//! 切片1 范围：Authenticate（认证）、Connect（TCP relay）、Heartbeat、Dissociate。
//! 切片2 待办：Packet（UDP relay + 分片）。

use bytes::{Buf, BufMut};

use super::address::Address;
use crate::error::{Result, TuicError};

/// 协议版本号（固定 0x05）。
pub const VERSION: u8 = 0x05;

/// 命令类型码。
pub mod type_code {
    /// 认证：UUID(16) + TOKEN(32)，经 uni stream 发送。
    pub const AUTHENTICATE: u8 = 0x00;
    /// TCP 连接：Address，经 bi stream 发送。
    pub const CONNECT: u8 = 0x01;
    /// UDP 包：ASSOC_ID(2) + PKT_ID(2) + FRAG_TOTAL(1) + FRAG_ID(1) + SIZE(2) + ADDR。
    pub const PACKET: u8 = 0x02;
    /// 关闭 UDP 关联：ASSOC_ID(2)。
    pub const DISSOCIATE: u8 = 0x03;
    /// 心跳：空负载。
    pub const HEARTBEAT: u8 = 0x04;
}

/// TOKEN 长度（TLS keying material exporter 输出 32 字节）。
pub const TOKEN_LEN: usize = 32;

/// TUIC 命令枚举。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Authenticate（仅切片1 用于客户端发送）。
    Authenticate {
        uuid_bytes: [u8; 16],
        token: [u8; TOKEN_LEN],
    },
    /// Connect（TCP relay 切片1 核心）。
    Connect(Address),
    /// Dissociate（关闭 UDP 关联，预留）。
    Dissociate { assoc_id: u16 },
    /// Heartbeat（保活）。
    Heartbeat,
}

impl Command {
    /// 命令类型码。
    #[must_use]
    pub fn type_code(&self) -> u8 {
        match self {
            Self::Authenticate { .. } => type_code::AUTHENTICATE,
            Self::Connect(_) => type_code::CONNECT,
            Self::Dissociate { .. } => type_code::DISSOCIATE,
            Self::Heartbeat => type_code::HEARTBEAT,
        }
    }

    /// 序列化为字节流（VER + TYPE + 负载）。
    ///
    /// 用于发送到 uni/bi stream 开头。Packet 命令不在此实现（切片2）。
    pub fn write_to<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(VERSION);
        buf.put_u8(self.type_code());
        match self {
            Self::Authenticate { uuid_bytes, token } => {
                buf.put_slice(uuid_bytes);
                buf.put_slice(token);
            }
            Self::Connect(addr) => addr.write_to(buf),
            Self::Dissociate { assoc_id } => buf.put_u16(*assoc_id),
            Self::Heartbeat => {}
        }
    }

    /// 序列化所需字节数。
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        // VER + TYPE
        let header = 2;
        let payload = match self {
            Self::Authenticate { uuid_bytes, token } => uuid_bytes.len() + token.len(),
            Self::Connect(addr) => addr.encoded_len(),
            Self::Dissociate { .. } => 2,
            Self::Heartbeat => 0,
        };
        header + payload
    }

    /// 从 [`Buf`] 解析（不含 VER，调用方先消费 VER 字节并校验）。
    ///
    /// `type_byte` 为已读出的 TYPE 字节。
    pub fn read_payload<B: Buf>(type_byte: u8, buf: &mut B) -> Result<Self> {
        match type_byte {
            type_code::AUTHENTICATE => {
                let need = 16 + TOKEN_LEN;
                if buf.remaining() < need {
                    return Err(TuicError::UnexpectedEof("authenticate payload"));
                }
                let mut uuid_bytes = [0u8; 16];
                buf.copy_to_slice(&mut uuid_bytes);
                let mut token = [0u8; TOKEN_LEN];
                buf.copy_to_slice(&mut token);
                Ok(Self::Authenticate { uuid_bytes, token })
            }
            type_code::CONNECT => {
                let addr = Address::read_from(buf)?;
                Ok(Self::Connect(addr))
            }
            type_code::DISSOCIATE => {
                if buf.remaining() < 2 {
                    return Err(TuicError::UnexpectedEof("dissociate assoc_id"));
                }
                Ok(Self::Dissociate {
                    assoc_id: buf.get_u16(),
                })
            }
            type_code::HEARTBEAT => Ok(Self::Heartbeat),
            other => Err(TuicError::UnknownCommandType(other)),
        }
    }
}

/// 从 stream 开头读出并校验版本与类型码，返回 (TYPE 字节, 剩余 buf 引用)。
///
/// 实际使用：调用方从 quinn stream 读出字节后用此函数解析。
pub fn parse_header<B: Buf>(buf: &mut B) -> Result<u8> {
    if buf.remaining() < 2 {
        return Err(TuicError::UnexpectedEof("ver+type"));
    }
    let ver = buf.get_u8();
    if ver != VERSION {
        return Err(TuicError::InvalidVersion(ver));
    }
    Ok(buf.get_u8())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::address::Address;
    use std::net::Ipv4Addr;

    fn roundtrip(cmd: &Command) {
        let mut buf = Vec::with_capacity(cmd.encoded_len());
        cmd.write_to(&mut buf);
        assert_eq!(buf.len(), cmd.encoded_len());
        let mut cursor = &buf[..];
        let type_byte = parse_header(&mut cursor).unwrap();
        let parsed = Command::read_payload(type_byte, &mut cursor).unwrap();
        assert_eq!(*cmd, parsed);
    }

    #[test]
    fn authenticate_roundtrip() {
        let cmd = Command::Authenticate {
            uuid_bytes: [0xab; 16],
            token: [0xcd; TOKEN_LEN],
        };
        roundtrip(&cmd);
    }

    #[test]
    fn connect_ipv4_roundtrip() {
        let cmd = Command::Connect(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4), 80));
        roundtrip(&cmd);
    }

    #[test]
    fn connect_domain_roundtrip() {
        let cmd = Command::Connect(Address::Domain("www.google.com".into(), 443));
        roundtrip(&cmd);
    }

    #[test]
    fn dissociate_roundtrip() {
        roundtrip(&Command::Dissociate { assoc_id: 1234 });
    }

    #[test]
    fn heartbeat_roundtrip() {
        roundtrip(&Command::Heartbeat);
    }

    #[test]
    fn heartbeat_is_minimal() {
        let cmd = Command::Heartbeat;
        assert_eq!(cmd.encoded_len(), 2); // 仅 VER + TYPE
    }

    #[test]
    fn invalid_version_rejected() {
        let mut buf = vec![0x04, type_code::HEARTBEAT];
        let mut cursor = &buf[..];
        let err = parse_header(&mut cursor).unwrap_err();
        assert!(matches!(err, TuicError::InvalidVersion(0x04)));
        buf[0] = 0xff;
    }

    #[test]
    fn unknown_type_rejected() {
        let buf = vec![VERSION, 0x99];
        let mut cursor = &buf[..];
        let type_byte = parse_header(&mut cursor).unwrap();
        let err = Command::read_payload(type_byte, &mut cursor).unwrap_err();
        assert!(matches!(err, TuicError::UnknownCommandType(0x99)));
    }
}
