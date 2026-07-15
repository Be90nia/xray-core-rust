//! VLESS inbound server：accept TCP → decode_request_header → Destination → dispatch。
//!
//! 对应 Go `app/proxyman/inbound/always.go::handle_connection` +
//! `proxy/vless/inbound/inbound.go::Process`。最小端到端切片：
//! TCP accept → decode_request_header → DecodedRequest → Destination →
//! `DispatchHandler::dispatch(dest, link)`。
//!
//! 不含：TLS 包装（raw TCP）、fallback 路由、UDP/Mux/Rvs 处理（warn 跳过）。

use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use xray_app_dispatcher::default::SimpleOhm;
use xray_app_dispatcher::OutboundHandlerManager;
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_transport::link::Link;

use crate::encoding::server::{decode_request_header, encode_response_header};
use crate::encoding::{empty_addons, VlessCommand, VERSION};
use crate::validator::Validator;

/// VLESS inbound 服务入口。
///
/// 绑定 `listener` 监听，每个连接 spawn 独立 task：
/// 1. `decode_request_header` 解析 VLESS 请求头（含 UUID 校验）
/// 2. TCP 命令的 address+port → `Destination`；UDP/Mux/Rvs warn 跳过
/// 3. 发送 VLESS 响应头（version + empty addons）
/// 4. `tokio::io::split` → `Link` → `ohm` default handler `dispatch(dest, link)`
///
/// # 参数
/// - `listener`：已绑定的 TCP listener
/// - `ohm`：出站管理器（至少有 default handler）
/// - `validator`：VLESS 用户 validator（UUID → MemoryUser）
///
/// # 错误
/// accept 循环自身错误返回；单个连接错误只 log 不中断循环。
pub async fn serve_vless(
    listener: TcpListener,
    ohm: Arc<SimpleOhm>,
    validator: Arc<dyn Validator>,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;

    tracing::info!(
        addr = %listener.local_addr()?,
        "vless inbound listening"
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "vless accept failed");
                continue;
            }
        };

        let handler = Arc::clone(&handler);
        let validator = Arc::clone(&validator);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &handler, &validator).await {
                tracing::debug!(error = %e, "vless connection ended with error");
            }
        });

        let _ = peer;
    }
}

/// 处理单个 VLESS 连接：decode → dispatch。
async fn handle_connection(
    stream: TcpStream,
    handler: &Arc<dyn xray_app_dispatcher::DispatchHandler>,
    validator: &Arc<dyn Validator>,
) -> std::io::Result<()> {
    let mut stream = stream;

    // 1. decode VLESS request header（isfb=false，全部从 stream 读）
    let mut first: Option<Vec<u8>> = None;
    let decoded = decode_request_header(false, &mut first, &mut stream, validator.as_ref())
        .await
        .map_err(|e| std::io::Error::other(format!("vless decode: {e}")))?;

    // 2. 只处理 TCP；UDP/Mux/Rvs 先 warn 跳过
    if decoded.command != VlessCommand::Tcp {
        tracing::warn!(
            command = ?decoded.command,
            "vless non-TCP command not yet supported, closing connection"
        );
        return Ok(());
    }

    let address = decoded
        .address
        .ok_or_else(|| std::io::Error::other("vless decode: missing address for TCP command"))?;
    let port = decoded
        .port
        .ok_or_else(|| std::io::Error::other("vless decode: missing port for TCP command"))?;
    let dest = Destination::new(address, Port::new(port), Network::TCP);

    // 3. 发送 VLESS 响应头（version + empty addons），客户端收到后开始数据流
    encode_response_header(&mut stream, VERSION, &empty_addons())
        .await
        .map_err(|e| std::io::Error::other(format!("vless encode response: {e}")))?;

    // 4. split → Link → dispatch（dispatch 内部拨号 + bridge，消耗 link）
    // ponytail: tokio::io::split 返回的 ReadHalf/WriteHalf 是 'static + Send，
    // new_reader/new_writer 接受 AsyncRead/AsyncWrite + Unpin + Send + 'static。
    let (read_half, write_half) = tokio::io::split(stream);
    let link = Link::new(new_reader(read_half), new_writer(write_half));
    let _ = handler.dispatch(&dest, link).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::client::{decode_response_header, encode_request_header};
    use crate::validator::{MemoryUser, MemoryValidator};
    use crate::MemoryAccount;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use xray_app_dispatcher::default::DialBridge;
    use xray_common::net::address::Address;
    use xray_common::uuid::UUID;
    use xray_proxy_freedom::make_freedom_dial_fn;

    /// 构造测试用 validator + 已注册用户的 UUID。
    fn make_validator_with_user() -> (UUID, Arc<dyn Validator>) {
        let uuid = UUID::new();
        let user = MemoryUser {
            level: 0,
            email: "test@example.com".to_string(),
            account: MemoryAccount::from_proto_account(
                &xray_proto::xray::proxy::vless::Account {
                    id: uuid.to_string(),
                    ..Default::default()
                },
            )
            .unwrap(),
        };
        let v = MemoryValidator::new();
        v.add(user).unwrap();
        (uuid, Arc::new(v))
    }

    /// 端到端：VLESS client → VLESS inbound → freedom outbound → echo server。
    #[tokio::test]
    async fn vless_inbound_to_freedom_outbound_e2e() {
        // 1. echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // 2. dispatcher：freedom outbound → SimpleOhm default
        let ohm = Arc::new(SimpleOhm::new());
        let dial_fn = make_freedom_dial_fn();
        let bridge = Arc::new(DialBridge::new("freedom", dial_fn))
            as Arc<dyn xray_app_dispatcher::DispatchHandler>;
        ohm.set_default(bridge);

        // 3. validator + serve_vless
        let (uuid, validator) = make_validator_with_user();
        let vless_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_addr = vless_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        let validator_clone = Arc::clone(&validator);
        tokio::spawn(async move {
            let _ = serve_vless(vless_listener, ohm_clone, validator_clone).await;
        });

        // 4. VLESS client：connect → encode request → decode response → echo round-trip
        let mut client = tokio::net::TcpStream::connect(vless_addr)
            .await
            .unwrap();
        let addons = empty_addons();
        let dest_addr = Address::from_ipv4_bytes([127, 0, 0, 1]);
        encode_request_header(
            &mut client,
            VERSION,
            &uuid,
            VlessCommand::Tcp,
            Some(&dest_addr),
            Some(echo_port),
            &addons,
        )
        .await
        .unwrap();

        // 读响应头（version + addons），客户端消费后才能发数据
        let _resp_addons = decode_response_header(&mut client, VERSION)
            .await
            .unwrap();

        // 5. 发数据 + 读 echo
        let payload = b"hello vless proxy!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "should receive echo through vless proxy");
    }

    /// 无效用户（validator 中不存在）→ 连接被关闭，client 收到 EOF 或 decode 错误。
    #[tokio::test]
    async fn vless_inbound_rejects_unknown_user() {
        let ohm = Arc::new(SimpleOhm::new());
        let dial_fn = make_freedom_dial_fn();
        ohm.set_default(Arc::new(DialBridge::new("freedom", dial_fn))
            as Arc<dyn xray_app_dispatcher::DispatchHandler>);

        // 空 validator（无任何用户）
        let validator: Arc<dyn Validator> = Arc::new(MemoryValidator::new());
        let vless_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_addr = vless_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        let validator_clone = Arc::clone(&validator);
        tokio::spawn(async move {
            let _ = serve_vless(vless_listener, ohm_clone, validator_clone).await;
        });

        // client 用一个随机的（未注册的）UUID
        let unknown_uuid = UUID::new();
        let mut client = tokio::net::TcpStream::connect(vless_addr)
            .await
            .unwrap();
        let addons = empty_addons();
        let dest_addr = Address::from_ipv4_bytes([127, 0, 0, 1]);
        encode_request_header(
            &mut client,
            VERSION,
            &unknown_uuid,
            VlessCommand::Tcp,
            Some(&dest_addr),
            Some(80),
            &addons,
        )
        .await
        .unwrap();

        // server 因 UserNotFound 关闭连接 → client 读响应得到 EOF 或连接重置
        let mut buf = [0u8; 16];
        let result = client.read(&mut buf).await;
        match result {
            Ok(0) => {} // clean EOF
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => {}
            other => panic!("expected EOF or connection reset, got {other:?}"),
        }
    }
}
