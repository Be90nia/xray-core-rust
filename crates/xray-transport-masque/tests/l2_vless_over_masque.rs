//! bd anygg G2 L2：`network: "masque"` 作入站传输承载 VLESS 的真实字节往返
//! （走 transport listener 注册表真实现，非 proxy 直挂）。
//!
//! 拓扑（单进程双入站，全生产链）：
//! - **masque proxy 入站**（`xray_proxy_masque::server::serve`，端口 A）——装配即 注册进程级共享
//!   users 闸（G2 委托源）；dispatch = 计数 canary（内桥 freedom →
//!   echo），本用例流量不应触达——触达即证明走了 proxy 直挂而非 transport listener（负面判别力）。
//! - **VLESS 入站**（transport listener 注册表形态：`listen_tcp` 按 `network: "masque"` 查表 →
//!   真实现 gate 委托 + `HandlerAcceptor` 裸流桥）—— ConnHandler = 生产 vless
//!   `handle_connection_with_fallback`（dispatch → freedom → 本地 TCP echo）。
//! - **客户端** = 生产 `make_vless_dial_fn`（vless over masque transport； masqueSettings user/pass
//!   → Basic 认证头）。
//!
//! 断言：①正确 masque 凭据 + 正确 UUID → 真实字节 64KiB 往返逐字节比对；②
//! 错误 masque 密码 → 拨号失败（共享 users 闸 401 委托生效）；③错误 UUID →
//! 隧道建立后协议层拒绝（transport 放行 ≠ 免认证）；④proxy canary == 0（流量
//! 未走 proxy 直挂）+ echo 接受计数 ≥ 1（观察手段看得见）。
//!
//! 共享闸注记：三个用例同进程内共享 `serve()` 注册槽（首个生效）——各用例凭据
//! 恒同（常量），无行为差。
#![allow(clippy::disallowed_methods)] // 测试基建 spawn（坑约束 #5）

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use xray_app_dispatcher::{
    DispatchHandler,
    default::{DialBridge, PinFuture},
};
use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_frame::scope::ComponentScope;
use xray_proxy_freedom::{FreedomDispatchBridge, make_freedom_dial_fn};
use xray_proxy_masque::server::{MasqueServer, parse_server_settings, serve};
use xray_proxy_vless::{
    MemoryAccount, MemoryUser, MemoryValidator, Validator, VlessInboundOptions,
    VlessOutboundConfig, handle_connection_with_fallback, make_vless_dial_fn,
};
use xray_transport::{
    connection::Connection,
    dialer::StreamSettings,
    listener_registry::{ConnHandler, TransportListener},
    sockopt::SocketOptions,
};

/// masque 传输层凭据（共享 users 闸 = proxy 入站的 users 表，serve() 注册）。
const MASQUE_USER: &str = "g2@example.com";
const MASQUE_PASS: &str = "g2-pass";
/// VLESS 协议层凭据（入站 validator 注册的同一 UUID）。
const VLESS_UUID: &str = "b8a1d0e2-3c4f-4a5b-8c9d-0e1f2a3b4c5d";
/// 错误 UUID（transport 层放行后协议层必须拒绝）。
const WRONG_UUID: &str = "11111111-2222-4333-8444-555555555555";

/// L2 真实字节门槛（对齐 b5_e2e 的 L2 判据量级：逐字节比对非 mock 数据）。
const L2_BYTES: usize = 64 * 1024;

/// 服务端实例序号（temp 目录唯一化）。
static SERVER_SEQ: AtomicUsize = AtomicUsize::new(0);

// ===== 共享 harness =====

struct CertGuard {
    tmp: PathBuf,
    pin: String,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl Drop for CertGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

fn make_cert(tag: &str) -> CertGuard {
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let cert = params.self_signed(&key_pair).expect("self signed");
    let pin = xray_tls::pin::generate_cert_hash_hex(cert.der());

    let tmp = std::env::temp_dir().join(format!(
        "masque-g2-l2-{}-{}-{}",
        tag.replace('/', "_"),
        std::process::id(),
        SERVER_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&tmp).expect("mkdir");
    let cert_path = tmp.join("cert.pem");
    let key_path = tmp.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
    CertGuard { tmp, pin, cert_path, key_path }
}

/// 本地 TCP echo 监听器（被拨号即计数 + 逐字节回显）。
async fn echo_listener() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let addr = listener.local_addr().expect("echo addr");
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);
    // 测试基建任务（spawn 三分类②）：canary 监听，随用例生命周期。
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        },
                    }
                }
            });
        }
    });
    (addr, accepts)
}

/// 计数 canary dispatch：内桥 freedom → echo。流量一旦触达 proxy 直挂路径，
/// 计数必 > 0（用例断言其停在 0 = 走的是 transport listener）。
#[derive(Debug)]
struct CanaryDispatch {
    calls: Arc<AtomicUsize>,
    inner: Arc<dyn DispatchHandler>,
}

impl DispatchHandler for CanaryDispatch {
    fn tag(&self) -> &str {
        "g2-proxy-canary"
    }

    fn dispatch(&self, dest: &Destination, link: xray_transport::link::Link) -> PinFuture<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.dispatch(dest, link)
    }
}

/// L2 环境句柄：masque proxy 入站（users 源 + canary）+ VLESS transport 入站 +
/// echo 监听器。Drop = 全量收口。
struct L2Env {
    proxy_listener: Box<dyn TransportListener>,
    proxy_server: Arc<MasqueServer>,
    vless_listener: Box<dyn TransportListener>,
    cert: CertGuard,
    echo_addr: SocketAddr,
    echo_accepts: Arc<AtomicUsize>,
    proxy_dispatch_calls: Arc<AtomicUsize>,
    vless_port: u16,
}

impl Drop for L2Env {
    fn drop(&mut self) {
        self.proxy_server.close();
        let _ = self.proxy_listener.close();
        let _ = self.vless_listener.close();
    }
}

async fn bind_free_port() -> SocketAddr {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind probe");
    probe.local_addr().expect("probe addr")
}

fn server_tls_stream(cert: &CertGuard) -> StreamSettings {
    StreamSettings {
        protocol: "masque".into(),
        security: "tls".into(),
        security_json: Some(serde_json::json!({
            "alpn": ["h2"],
            "certificates": [{
                "certificateFile": cert.cert_path.display().to_string(),
                "keyFile": cert.key_path.display().to_string(),
            }],
        })),
        ..StreamSettings::tcp()
    }
}

/// 起 L2 环境（两个入站 + echo）。共享 users 闸由 proxy serve() 注册。
async fn setup_l2() -> L2Env {
    // 1) echo 监听器（freedom 真拨号目标）。
    let (echo_addr, echo_accepts) = echo_listener().await;

    // 2) masque proxy 入站（users 源；dispatch = canary 内桥 freedom → echo）。
    let cert = make_cert("proxy-in");
    let proxy_addr = bind_free_port().await;
    let proxy_settings = parse_server_settings(&serde_json::json!({
        "users": [{ "email": MASQUE_USER, "pass": MASQUE_PASS }],
        "address": ["198.18.0.1/15"],
    }))
    .expect("proxy server settings");
    let proxy_calls = Arc::new(AtomicUsize::new(0));
    let proxy_dispatch: Arc<dyn DispatchHandler> = Arc::new(CanaryDispatch {
        calls: Arc::clone(&proxy_calls),
        inner: Arc::new(FreedomDispatchBridge::from_bridge(
            Arc::new(xray_frame::PluginContext::for_plugin("g2-freedom")),
            Arc::new(DialBridge::new("g2-freedom-out", make_freedom_dial_fn())),
        )),
    });
    let (proxy_listener, proxy_server) = serve(
        proxy_addr,
        "g2-proxy-in",
        proxy_settings,
        proxy_dispatch,
        ComponentScope::new("g2-proxy-in"),
        server_tls_stream(&cert),
        SocketOptions::default(),
    )
    .await
    .expect("serve masque proxy");
    let proxy_port = proxy_listener.local_addr().expect("proxy local addr").port();

    // 3) VLESS 入站（transport listener 注册表形态——生产 spawn_transport_listener_inbound
    //    同款：listen_tcp 按 network=masque 查表）。
    xray_transport_masque::register::register_dialer().expect("register masque dialer");
    xray_transport_masque::register::register_listener().expect("register masque listener");

    let vless_validator: Arc<dyn xray_proxy_vless::Validator> = {
        let proto = xray_proto::xray::proxy::vless::Account {
            id: VLESS_UUID.to_string(),
            ..Default::default()
        };
        let account = MemoryAccount::from_proto_account(&proto).expect("vless account");
        let validator = MemoryValidator::new();
        validator.add(MemoryUser::new("g2-vless@local", 0, account)).expect("add vless user");
        Arc::new(validator)
    };
    let vless_dispatch: Arc<dyn DispatchHandler> =
        Arc::new(DialBridge::new("g2-vless-freedom-out", make_freedom_dial_fn()));

    let vless_bind = bind_free_port().await;
    let arm_scope = Arc::new(ComponentScope::new("g2-vless-arm"));
    let plugin_ctx = Arc::new(xray_frame::PluginContext::for_plugin("g2-vless"));
    let dispatch_for_conn = Arc::clone(&vless_dispatch);
    let validator_for_conn = Arc::clone(&vless_validator);
    let bind = vless_bind;
    let on_conn: ConnHandler = Arc::new(move |conn: Box<dyn Connection>| {
        let dispatch = Arc::clone(&dispatch_for_conn);
        let validator = Arc::clone(&validator_for_conn);
        let ctx = Arc::clone(&plugin_ctx);
        let scope = Arc::clone(&arm_scope);
        // transport 解包层丢失地址时用 bind 地址兜底（inbound.rs 同款）。
        let peer = conn.remote_addr().ok().flatten().unwrap_or(bind);
        let local = conn.local_addr().ok().flatten().unwrap_or(bind);
        // §3.5.6 ①类：连接任务归本 inbound 的 arm scope；闸关后 spawn 失败 =
        // conn 随闭包 drop（对端读 EOF，生产 vless_transport_on_conn 同结局）。
        let _ = scope.spawn(async move {
            if let Err(e) = handle_connection_with_fallback(
                conn,
                &dispatch,
                &validator,
                None,
                peer,
                local,
                String::new(),
                String::new(),
                Some(VlessInboundOptions::default()),
                None,
                &ctx,
            )
            .await
            {
                eprintln!("[g2-l2] vless conn error: {e}");
            }
        });
    });
    let vless_listener = xray_transport::listener_registry::listen_tcp(
        vless_bind,
        server_tls_stream(&cert),
        SocketOptions::default(),
        on_conn,
    )
    .await
    .expect("listen vless over masque transport");
    let vless_port = vless_listener.local_addr().expect("vless local addr").port();
    assert_ne!(proxy_port, vless_port, "two inbounds must bind distinct ports");

    L2Env {
        proxy_listener,
        proxy_server,
        vless_listener,
        cert,
        echo_addr,
        echo_accepts,
        proxy_dispatch_calls: proxy_calls,
        vless_port,
    }
}

/// 生产 vless 客户端拨号（masque transport + Basic 凭据 + UUID）。
async fn vless_dial(
    env: &L2Env,
    pass: &str,
    uuid: &str,
    target: Destination,
) -> Result<Box<dyn Connection>, String> {
    let client = VlessOutboundConfig::new(
        xray_common::uuid::UUID::parse(uuid).expect("client uuid"),
        Address::ipv4(Ipv4Addr::LOCALHOST),
        Port::new(env.vless_port),
    )
    .with_stream_settings(Some(StreamSettings {
        protocol: "masque".into(),
        security: "tls".into(),
        security_json: Some(serde_json::json!({
            "serverName": "localhost",
            "alpn": ["h2"],
            "pinnedPeerCertSha256": env.cert.pin,
        })),
        transport_json: Some(serde_json::json!({ "user": MASQUE_USER, "pass": pass })),
        ..StreamSettings::tcp()
    }));
    make_vless_dial_fn(Arc::new(client))(&target).await
}

fn local_target(port: u16) -> Destination {
    Destination::tcp(Address::ipv4(Ipv4Addr::LOCALHOST), Port::new(port))
}

/// L2 确定性 payload（字节 = 偏移低 8 位；与 b5 l2_body 同款设计）。
fn l2_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i & 0xff) as u8).collect()
}

// ===== 用例 1：真实字节往返（G2 主验收） =====

/// 正确 masque 凭据 + 正确 UUID → 64KiB 真实字节经
/// vless 客户端 → masque transport listener（gate 委托 + 隧道裸流桥）→
/// vless 服务端 → freedom → echo 全链逐字节往返；proxy 直挂 canary 停在 0。
#[tokio::test]
async fn vless_over_masque_transport_roundtrip() {
    let env = setup_l2().await;
    let target = local_target(env.echo_addr.port());

    let mut conn =
        vless_dial(&env, MASQUE_PASS, VLESS_UUID, target.clone()).await.expect("vless dial");

    let payload = l2_payload(L2_BYTES);
    conn.write_all(&payload).await.expect("write payload");
    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got).await.expect("read echo");
    assert_eq!(got, payload, "echoed bytes must match the sent pattern byte-for-byte");

    // 收敛窗：dispatch/freedom 拨号与计数留确定性余量。
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        env.proxy_dispatch_calls.load(Ordering::SeqCst),
        0,
        "traffic must flow through the transport listener, not the proxy path"
    );
    assert!(
        env.echo_accepts.load(Ordering::SeqCst) >= 1,
        "echo listener must have accepted at least one connection (canary visibility)"
    );
}

// ===== 用例 2：masque 层委托认证 401（G2 gate 委托面） =====

/// 错误 masque 密码 → 共享 users 闸 401（认证委托生效；CONNECT-IP 升级被拒，
/// vless 拨号在 transport 层失败——vless 握手从未开始）。
#[tokio::test]
async fn wrong_masque_pass_rejected_by_shared_gate() {
    let env = setup_l2().await;
    let target = local_target(env.echo_addr.port());

    let result = vless_dial(&env, "WRONG-PASS", VLESS_UUID, target).await;
    assert!(result.is_err(), "wrong masque pass must fail the delegated gate");
    assert_eq!(
        env.proxy_dispatch_calls.load(Ordering::SeqCst),
        0,
        "rejected traffic must not reach any dispatch"
    );
}

// ===== 用例 3：协议层自认证仍在（transport 放行 ≠ 免认证） =====

/// 正确 masque 凭据 + 错误 UUID → transport 层放行（Go hub.go:53 无 transport
/// 认证形态），但 vless 服务端 UUID 校验拒绝 → 隧道关闭，读面 EOF 且无回显。
#[tokio::test]
async fn wrong_vless_uuid_rejected_by_protocol_layer() {
    let env = setup_l2().await;
    let target = local_target(env.echo_addr.port());

    match vless_dial(&env, MASQUE_PASS, WRONG_UUID, target).await {
        // transport 层即拒绝（未来语义收紧）也视为通过。
        Err(_) => {},
        Ok(mut conn) => {
            let payload = l2_payload(L2_BYTES);
            conn.write_all(&payload).await.expect("write into tunnel");
            let mut got = vec![0u8; payload.len()];
            let read =
                tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut got)).await;
            match read {
                Err(_) => panic!("read must not hang; server should close on auth failure"),
                Ok(Err(_)) => {}, // EOF/连接关闭 = 协议层拒绝 surfaced
                Ok(Ok(_)) => panic!("server must not echo for an unauthenticated uuid"),
            }
        },
    }
    assert_eq!(
        env.proxy_dispatch_calls.load(Ordering::SeqCst),
        0,
        "rejected traffic must not reach any dispatch"
    );
}
