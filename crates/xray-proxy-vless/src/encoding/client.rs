//! VLESS 客户端编解码（出站方向）。
//!
//! 对应 Go 版本 `proxy/vless/encoding/encoding.go` 中的 `EncodeRequestHeader`
//! 和 `DecodeResponseHeader`。

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use xray_common::net::address::Address;
use xray_common::uuid::UUID;
use xray_proto::xray::proxy::vless::encoding::Addons;

use crate::encoding::{encode_header_addons, write_address_port, VlessCommand};
use crate::error::{Result, VlessError};

/// 编码并发送请求头到 `writer`。
///
/// 对应 Go 的 `EncodeRequestHeader`。布局见 [`crate::encoding`] 模块文档。
///
/// - `user_uuid`：用户 UUID 引用（16 字节原始表示）。
/// - `command`：TCP/UDP/Mux/Rvs。
/// - `address` / `port`：仅 TCP/UDP 必填，Mux/Rvs 必填 `None`。
pub async fn encode_request_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    version: u8,
    user_uuid: &UUID,
    command: VlessCommand,
    address: Option<&Address>,
    port: Option<u16>,
    addons: &Addons,
) -> Result<()> {
    // 校验：TCP/UDP 必须传 address+port；Mux/Rvs 必须不传
    if command.needs_address() {
        if address.is_none() || port.is_none() {
            return Err(VlessError::InvalidRequestAddress);
        }
    } else if address.is_some() || port.is_some() {
        // Mux/Rvs 携带固定域名，调用方不应传 address+port
        return Err(VlessError::Other(
            "Mux/Rvs command should not carry address/port".into(),
        ));
    }

    let mut buf = Vec::with_capacity(64);

    // 1B version
    buf.push(version);

    // 16B user id（UUID 原始字节）
    buf.extend_from_slice(user_uuid.as_bytes());

    // addons
    encode_header_addons(&mut buf, addons)?;

    // 1B command
    buf.push(command.as_u8());

    // TCP/UDP: port + addr
    if let (Some(addr), Some(p)) = (address, port) {
        write_address_port(&mut buf, addr, p);
    }

    writer.write_all(&buf).await.map_err(VlessError::Io)?;
    Ok(())
}

/// 解码响应头：薄包装 [`crate::encoding::decode_response_header`]。
///
/// 对应 Go 的 `DecodeResponseHeader`。返回响应 addons，版本不匹配返回错误。
pub async fn decode_response_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected_version: u8,
) -> Result<Addons> {
    crate::encoding::decode_response_header(reader, expected_version).await
}

// ---------------------------------------------------------------------------
// 单元测试（对应 Go 的 encoding_test.go）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::server::decode_request_header;
    use crate::encoding::VERSION;
    use crate::encoding::empty_addons;
    use crate::validator::{MemoryUser, MemoryValidator, Validator};
    use crate::MemoryAccount;
    use std::io::Cursor;
    use xray_common::net::address::Address;
    use xray_common::uuid::UUID;

    fn make_user_and_validator() -> (UUID, MemoryValidator) {
        let uuid = UUID::new();
        let user = MemoryUser {
            level: 0,
            email: "test@example.com".to_string(),
            account: MemoryAccount::from_proto_account(&xray_proto::xray::proxy::vless::Account {
                    id: uuid.to_string(),
                    ..Default::default()
                },
            )
            .unwrap(),
        };
        let v = MemoryValidator::new();
        v.add(user).unwrap();
        (uuid, v)
    }

    #[tokio::test]
    async fn test_request_serialization_tcp_domain() {
        // 对照 Go TestRequestSerialization: TCP + Domain
        let (uuid, validator) = make_user_and_validator();

        let mut buf = Vec::new();
        let addons = empty_addons();
        let addr = Address::Domain("www.example.com".to_string());
        encode_request_header(
            &mut buf,
            VERSION,
            &uuid,
            VlessCommand::Tcp,
            Some(&addr),
            Some(443),
            &addons,
        )
        .await
        .unwrap();

        let mut cursor = Cursor::new(buf);
        let mut first: Option<Vec<u8>> = None;
        let decoded = decode_request_header(false, &mut first, &mut cursor, &validator)
            .await
            .unwrap();

        assert_eq!(decoded.version, VERSION);
        assert_eq!(decoded.command, VlessCommand::Tcp);
        assert_eq!(decoded.port, Some(443));
        let got_addr = decoded.address.expect("address should be present");
        assert!(got_addr.is_domain());
        assert_eq!(got_addr.as_domain(), Some("www.example.com"));
    }

    #[tokio::test]
    async fn test_request_serialization_mux() {
        // 对照 Go TestMuxRequest: Mux command 不写 addr/port
        let (uuid, validator) = make_user_and_validator();

        let mut buf = Vec::new();
        let addons = empty_addons();
        encode_request_header(
            &mut buf,
            VERSION,
            &uuid,
            VlessCommand::Mux,
            None,
            None,
            &addons,
        )
        .await
        .unwrap();

        let mut cursor = Cursor::new(buf);
        let mut first: Option<Vec<u8>> = None;
        let decoded = decode_request_header(false, &mut first, &mut cursor, &validator)
            .await
            .unwrap();

        assert_eq!(decoded.command, VlessCommand::Mux);
        let got_addr = decoded.address.expect("mux address should be set");
        assert_eq!(got_addr.as_domain(), Some("v1.mux.cool"));
        assert_eq!(decoded.port, None);
    }

    #[tokio::test]
    async fn test_request_invalid_command() {
        // 对照 Go TestInvalidRequest: command=100 在 decode 时拒绝
        let (uuid, validator) = make_user_and_validator();

        let mut buf = Vec::new();
        buf.push(VERSION);
        buf.extend_from_slice(uuid.as_bytes());
        buf.push(0); // addons len = 0
        buf.push(100); // 非法 command

        let mut cursor = Cursor::new(buf);
        let mut first: Option<Vec<u8>> = None;
        let err = decode_request_header(false, &mut first, &mut cursor, &validator)
            .await
            .unwrap_err();
        match err {
            VlessError::InvalidRequestCommand(_) => {}
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_request_unknown_user_rejected() {
        let uuid_unknown = UUID::new();

        let mut buf = Vec::new();
        let addons = empty_addons();
        let addr = Address::Domain("www.example.com".to_string());
        encode_request_header(
            &mut buf,
            VERSION,
            &uuid_unknown,
            VlessCommand::Tcp,
            Some(&addr),
            Some(443),
            &addons,
        )
        .await
        .unwrap();

        let validator = MemoryValidator::new(); // 空
        let mut cursor = Cursor::new(buf);
        let mut first: Option<Vec<u8>> = None;
        let err = decode_request_header(false, &mut first, &mut cursor, &validator)
            .await
            .unwrap_err();
        match err {
            VlessError::UserNotFound(_) => {}
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_encode_response_header_round_trip() {
        let mut buf = Vec::new();
        let addons = empty_addons();
        crate::encoding::encode_response_header(&mut buf, VERSION, &addons)
            .await
            .unwrap();

        let mut cursor = Cursor::new(buf);
        let got = decode_response_header(&mut cursor, VERSION).await.unwrap();
        assert_eq!(got.flow, addons.flow);
    }
}
