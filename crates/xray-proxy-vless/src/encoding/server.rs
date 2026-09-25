//! VLESS 服务端编解码（入站方向）。
//!
//! 对应 Go 版本 `proxy/vless/encoding/encoding.go` 中的 `DecodeRequestHeader`
//! 和 `EncodeResponseHeader`。

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use xray_common::net::address::Address;
use xray_proto::xray::proxy::vless::encoding::Addons;

use crate::{
    encoding::{VERSION, VlessCommand, decode_header_addons, empty_addons, read_address_port},
    error::{Result, VlessError},
    validator::{MemoryUser, Validator},
};

/// 解码后的请求头。
#[derive(Debug, Clone)]
pub struct DecodedRequest {
    /// 协议版本（目前仅 0）。
    pub version: u8,
    /// 用户 ID 原始 16 字节（解码得到的，**未做 ProcessUUID**）。
    pub user_id: [u8; 16],
    /// 命令类型。
    pub command: VlessCommand,
    /// 目标地址。`Mux`/`Rvs` 时是固定域名 `v1.mux.cool`/`v1.rvs.cool`。
    pub address: Option<Address>,
    /// 目标端口。`Mux`/`Rvs` 时为 `None`。
    pub port: Option<u16>,
    /// Addons。
    pub addons: Addons,
    /// 校验通过后找到的用户（含 `MemoryAccount`）。
    pub user: Option<MemoryUser>,
}

impl Default for DecodedRequest {
    fn default() -> Self {
        Self {
            version: VERSION,
            user_id: [0u8; 16],
            command: VlessCommand::Tcp,
            address: None,
            port: None,
            addons: empty_addons(),
            user: None,
        }
    }
}

/// 解码请求头。
///
/// 对应 Go 的 `DecodeRequestHeader`。
///
/// - `isfb`：是否从 `first` 缓冲读取 `version + UUID`（17 字节，性能优化路径）。
///   - `true`：`first` 必须为 `Some` 且至少 17 字节，函数会消费前 17 字节。
///   - `false`：所有数据从 `reader` 顺序读。
/// - `first`：`isfb=true` 时使用，调用方预读的字节缓冲。
/// - `reader`：除首 17 字节外的输入源（`isfb=false` 时是唯一输入源）。
/// - `validator`：用于校验 UUID 并返回 `MemoryUser`。
pub async fn decode_request_header<R: AsyncRead + Unpin>(
    isfb: bool,
    first: &mut Option<Vec<u8>>,
    reader: &mut R,
    validator: &dyn Validator,
) -> Result<DecodedRequest> {
    let mut decoded = DecodedRequest::default();

    // ---- 1. version + UUID（17 字节，可能来自 first 或 reader）----
    if isfb {
        let first_buf = first
            .as_mut()
            .ok_or_else(|| VlessError::Other("isfb=true but first buffer is None".into()))?;
        if first_buf.len() < 17 {
            return Err(VlessError::Other(
                "first buffer too short for isfb (need 17 bytes)".into(),
            ));
        }
        decoded.version = first_buf[0];
        decoded.user_id.copy_from_slice(&first_buf[1..17]);
        // 消费掉 17 字节
        first_buf.drain(0..17);
    } else {
        let mut ver_buf = [0u8; 1];
        reader.read_exact(&mut ver_buf).await.map_err(VlessError::Io)?;
        decoded.version = ver_buf[0];

        let mut id_buf = [0u8; 16];
        reader.read_exact(&mut id_buf).await.map_err(VlessError::Io)?;
        decoded.user_id = id_buf;
    }

    // ---- 2. 校验 version ----
    if decoded.version != VERSION {
        return Err(VlessError::InvalidRequestVersion(decoded.version));
    }

    // ---- 3. 查找用户 ----
    let user_uuid = xray_common::uuid::UUID::from_bytes(decoded.user_id);
    if let Some(user) = validator.get(&user_uuid) {
        decoded.user = Some(user);
    } else {
        return Err(VlessError::UserNotFound(user_uuid.to_string()));
    }

    // ---- 4. addons（始终从 reader 读）----
    decoded.addons = decode_header_addons(reader).await?;

    // ---- 5. command (1B) ----
    let mut cmd_buf = [0u8; 1];
    reader.read_exact(&mut cmd_buf).await.map_err(VlessError::Io)?;
    let command =
        VlessCommand::from_u8(cmd_buf[0]).ok_or(VlessError::InvalidRequestCommand(cmd_buf[0]))?;
    decoded.command = command;

    // ---- 6. 根据 command 决定地址 ----
    match command {
        VlessCommand::Mux => {
            decoded.address =
                Some(Address::Domain(VlessCommand::Mux.fixed_domain().unwrap().to_string()));
        },
        VlessCommand::Rvs => {
            decoded.address =
                Some(Address::Domain(VlessCommand::Rvs.fixed_domain().unwrap().to_string()));
        },
        VlessCommand::Tcp | VlessCommand::Udp => {
            let (addr, port) = read_address_port(reader).await?;
            decoded.address = Some(addr);
            decoded.port = Some(port.value());
        },
    }

    Ok(decoded)
}

/// 编码响应头：薄包装 [`crate::encoding::encode_response_header`]。
pub async fn encode_response_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    version: u8,
    response_addons: &Addons,
) -> Result<()> {
    crate::encoding::encode_response_header(writer, version, response_addons).await
}

// ---------------------------------------------------------------------------
// 单元测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use xray_common::{net::address::Address, uuid::UUID};

    use super::*;
    use crate::{
        MemoryAccount,
        encoding::{client::encode_request_header, empty_addons},
        validator::{MemoryUser, MemoryValidator, Validator},
    };

    fn make_user_and_validator() -> (UUID, MemoryValidator) {
        let uuid = UUID::new();
        let user = MemoryUser {
            level: 0,
            email: "test@example.com".to_string(),
            account: MemoryAccount::from_proto_account(&xray_proto::xray::proxy::vless::Account {
                id: uuid.to_string(),
                ..Default::default()
            })
            .unwrap(),
        };
        let v = MemoryValidator::new();
        v.add(user).unwrap();
        (uuid, v)
    }

    #[tokio::test]
    async fn test_decode_tcp_request() {
        let (uuid, validator) = make_user_and_validator();

        let mut buf = Vec::new();
        let addr = Address::Domain("www.example.com".to_string());
        let addons = empty_addons();
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
        let decoded =
            decode_request_header(false, &mut first, &mut cursor, &validator).await.unwrap();

        assert_eq!(decoded.version, VERSION);
        assert_eq!(decoded.command, VlessCommand::Tcp);
        assert_eq!(decoded.port, Some(443));
        let got_addr = decoded.address.unwrap();
        assert_eq!(got_addr.as_domain(), Some("www.example.com"));
        assert!(decoded.user.is_some());
    }

    #[tokio::test]
    async fn test_decode_udp_request_ipv4() {
        let (uuid, validator) = make_user_and_validator();

        let mut buf = Vec::new();
        let addr = Address::IPv4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let addons = empty_addons();
        encode_request_header(
            &mut buf,
            VERSION,
            &uuid,
            VlessCommand::Udp,
            Some(&addr),
            Some(53),
            &addons,
        )
        .await
        .unwrap();

        let mut cursor = Cursor::new(buf);
        let mut first: Option<Vec<u8>> = None;
        let decoded =
            decode_request_header(false, &mut first, &mut cursor, &validator).await.unwrap();

        assert_eq!(decoded.command, VlessCommand::Udp);
        assert_eq!(decoded.port, Some(53));
        let got_addr = decoded.address.unwrap();
        assert!(got_addr.is_ipv4());
        assert_eq!(got_addr.ipv4_bytes(), Some([8, 8, 8, 8]));
    }

    #[tokio::test]
    async fn test_decode_mux_request() {
        let (uuid, validator) = make_user_and_validator();

        let mut buf = Vec::new();
        let addons = empty_addons();
        encode_request_header(&mut buf, VERSION, &uuid, VlessCommand::Mux, None, None, &addons)
            .await
            .unwrap();

        let mut cursor = Cursor::new(buf);
        let mut first: Option<Vec<u8>> = None;
        let decoded =
            decode_request_header(false, &mut first, &mut cursor, &validator).await.unwrap();

        assert_eq!(decoded.command, VlessCommand::Mux);
        assert_eq!(decoded.port, None);
        let got_addr = decoded.address.unwrap();
        assert_eq!(got_addr.as_domain(), Some("v1.mux.cool"));
    }

    #[tokio::test]
    async fn test_decode_rvs_request() {
        let (uuid, validator) = make_user_and_validator();

        let mut buf = Vec::new();
        let addons = empty_addons();
        encode_request_header(&mut buf, VERSION, &uuid, VlessCommand::Rvs, None, None, &addons)
            .await
            .unwrap();

        let mut cursor = Cursor::new(buf);
        let mut first: Option<Vec<u8>> = None;
        let decoded =
            decode_request_header(false, &mut first, &mut cursor, &validator).await.unwrap();

        assert_eq!(decoded.command, VlessCommand::Rvs);
        let got_addr = decoded.address.unwrap();
        assert_eq!(got_addr.as_domain(), Some("v1.rvs.cool"));
    }

    #[tokio::test]
    async fn test_decode_with_isfb_first_buffer() {
        let (uuid, validator) = make_user_and_validator();

        let mut full_buf = Vec::new();
        let addr = Address::Domain("isfb.test".to_string());
        let addons = empty_addons();
        encode_request_header(
            &mut full_buf,
            VERSION,
            &uuid,
            VlessCommand::Tcp,
            Some(&addr),
            Some(80),
            &addons,
        )
        .await
        .unwrap();

        // 切分：前 17 字节进 first，其余进 reader
        let mut first = Some(full_buf[..17].to_vec());
        let mut cursor = Cursor::new(full_buf[17..].to_vec());

        let decoded =
            decode_request_header(true, &mut first, &mut cursor, &validator).await.unwrap();

        assert_eq!(decoded.version, VERSION);
        assert_eq!(decoded.command, VlessCommand::Tcp);
        assert_eq!(decoded.port, Some(80));
        let got_addr = decoded.address.unwrap();
        assert_eq!(got_addr.as_domain(), Some("isfb.test"));

        let remaining = first.unwrap();
        assert!(remaining.is_empty(), "first should be drained");
    }

    #[tokio::test]
    async fn test_decode_isfb_too_short_rejected() {
        let validator = MemoryValidator::new();
        let mut first = Some(vec![0u8; 5]);
        let mut cursor = Cursor::new(Vec::new());
        let err =
            decode_request_header(true, &mut first, &mut cursor, &validator).await.unwrap_err();
        match err {
            VlessError::Other(msg) => assert!(msg.contains("too short")),
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_decode_isfb_missing_first() {
        let validator = MemoryValidator::new();
        let mut first = None;
        let mut cursor = Cursor::new(Vec::new());
        let err =
            decode_request_header(true, &mut first, &mut cursor, &validator).await.unwrap_err();
        match err {
            VlessError::Other(msg) => assert!(msg.contains("None")),
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_decode_invalid_version_rejected() {
        let (uuid, validator) = make_user_and_validator();

        let mut buf = Vec::new();
        buf.push(1);
        buf.extend_from_slice(uuid.as_bytes());

        let mut cursor = Cursor::new(buf);
        let mut first: Option<Vec<u8>> = None;
        let err =
            decode_request_header(false, &mut first, &mut cursor, &validator).await.unwrap_err();
        match err {
            VlessError::InvalidRequestVersion(_) => {},
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_encode_response_round_trip() {
        let mut buf = Vec::new();
        let addons = empty_addons();
        encode_response_header(&mut buf, VERSION, &addons).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let got = crate::encoding::decode_response_header(&mut cursor, VERSION).await.unwrap();
        assert_eq!(got.flow, addons.flow);
    }
}
