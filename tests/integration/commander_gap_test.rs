//! G-11 commander 五命令真实-server 集成（bd jezb 接线后）。
//!
//! bd jezb 前：`start_full` 未给 Commander 注入 proxyman HandlerService，
//! inbound/alter 四命令经真实 gRPC 恒返回 `UNIMPLEMENTED(... requires proxyman
//! HandlerService (not injected))`，本文件把该缺口钉成契约断言。
//!
//! bd jezb 后：`start_full` 注入 `ApiHandlerService`（inbound 域接真实
//! `InboundRuntime`）+ proxyman command trait 改为 async（AddInbound 要真实 bind
//! listener，bind 失败原样上抛）。断言按 Go 语义改写：
//! - AddInbound：新 tag 可连、可列，重复 tag → AlreadyExists，bind 失败 → 上抛；
//! - RemoveInbound：端口不再接受连接、列表移除，重复删 → NotFound；
//! - ListInbounds：tags / 完整 config（proxy/receiver type_url）两态；
//! - AlterInbound：AddUser/RemoveUser 对 ss 用户面生效，非 UserManager 入站 →
//!   FailedPrecondition，未知 tag → NotFound，未知操作类型 → 明确报错。
//!
//! GetStats 由 bd dnw3 接线，保持全链路绿断言。

use std::{sync::Arc, time::Duration};

use prost::Message as _;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tonic::{Request, transport::Channel};
use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound, app_config::ApiConfig};
use xray_core::functions::start_full;
use xray_proto::xray::{
    app::{
        proxyman::command::{
            AddInboundRequest, AddUserOperation, AlterInboundRequest, GetInboundUserRequest,
            ListInboundsRequest, RemoveInboundRequest, RemoveUserOperation,
            handler_service_client::HandlerServiceClient,
        },
        stats::command::{GetStatsRequest, stats_service_client::StatsServiceClient},
    },
    common::{protocol::User, serial::TypedMessage},
    core::InboundHandlerConfig,
};

/// policy system 四门（Go app/policy 的 System.Stats 同语义）：开启后
/// inbound/outbound 按 tag 的 traffic counter 才会被注册（wiring sm80① 门控）。
const POLICY_SYSTEM_STATS: &[u8] =
    br#"{"system":{"statsInboundUplink":true,"statsInboundDownlink":true,"statsOutboundUplink":true,"statsOutboundDownlink":true}}"#;

/// 起好的真实实例（Drop 时不强杀：测试末尾显式 `abort`）。
struct ApiInstance {
    api: String,
    /// dokodemo → echo 入站端口（`with_traffic_path`）。
    dok_port: Option<u16>,
    /// shadowsocks legacy 入站端口（`with_ss_inbound`）。
    ss_port: Option<u16>,
    instance: Arc<xray_core::Instance>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl ApiInstance {
    fn abort(self) {
        for h in self.handles {
            h.abort();
        }
    }
}

/// bind :0 取空闲端口再释放。
async fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// echo 服务器：回环回写（入站的真实目标）。
async fn spawn_echo() -> u16 {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = echo.accept().await else { break };
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
    port
}

/// freedom outbound（default 兜底；显式放行回环）。
fn freedom_default() -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry {
            kind: "freedom".into(),
            data: br#"{"finalRules":[{"action":"allow","network":"tcp,udp","ip":["127.0.0.0/8","::1/128"]}]}"#
                .to_vec(),
        },
        tag: "direct".into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

/// dokodemo inbound（rewrite → 目标地址，转发到 echo）。
fn dokodemo_inbound(tag: &str, port: u16, echo_port: u16) -> BuiltInbound {
    BuiltInbound {
        entry: BuiltEntry {
            kind: "dokodemo".into(),
            data: format!(r#"{{"address":"127.0.0.1","port":{echo_port}}}"#).into_bytes(),
        },
        tag: tag.into(),
        port: Some(port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

/// shadowsocks legacy 入站（单配置用户 `cfg@ss`，gRPC AlterInbound 在其上加/删）。
fn ss_inbound(port: u16) -> BuiltInbound {
    BuiltInbound {
        entry: BuiltEntry {
            kind: "shadowsocks".into(),
            data: br#"{"method":"aes-128-gcm","users":[{"method":"aes-128-gcm","password":"pw-cfg","email":"cfg@ss"}]}"#
                .to_vec(),
        },
        tag: "ss-in".into(),
        port: Some(port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

/// 起真实实例：api app（HandlerService+StatsService）+ policy system stats 门 +
/// freedom default；按开关追加 dokodemo → echo 与 shadowsocks 入站。
async fn start_api_instance(with_traffic_path: bool, with_ss_inbound: bool) -> ApiInstance {
    // pick_free_port 是 bind-then-drop 的 TOCTOU：并行测试可能在 drop 与真正 bind
    // 之间抢走端口（Windows os error 10048）。整体重建配置重试几次即可，
    // 无需改生产装配；非端口类错误立即上抛，不允许被重试掩盖。
    let mut last = String::new();
    for _ in 0..5 {
        match start_api_instance_once(with_traffic_path, with_ss_inbound).await {
            Ok(v) => return v,
            Err(e) => {
                let dbg = format!("{e:?}");
                if !dbg.contains("10048") && !dbg.contains("address in use") {
                    panic!("start_full failed (not a port race): {dbg}");
                }
                last = dbg;
            },
        }
    }
    panic!("start_full kept hitting address-in-use after 5 attempts: {last}");
}

async fn start_api_instance_once(
    with_traffic_path: bool,
    with_ss_inbound: bool,
) -> Result<ApiInstance, String> {
    let api_addr = format!("127.0.0.1:{}", pick_free_port().await);

    let mut built = BuiltConfig::default();
    built.apps.push(BuiltEntry { kind: "policy".into(), data: POLICY_SYSTEM_STATS.to_vec() });
    built.apps.push(BuiltEntry {
        kind: "api".into(),
        data: serde_json::to_vec(&ApiConfig {
            // Go api.go:23-25 `API tag can't be empty.`：tag 必填。
            tag: Some("api".to_string()),
            listen: Some(api_addr.clone()),
            services: Some(vec!["HandlerService".to_string(), "StatsService".to_string()]),
        })
        .map_err(|e| e.to_string())?,
    });
    let mut dok_port = None;
    if with_traffic_path {
        let echo_port = spawn_echo().await;
        let port = pick_free_port().await;
        built.inbounds.push(dokodemo_inbound("dok-in", port, echo_port));
        dok_port = Some(port);
    }
    let mut ss_port = None;
    if with_ss_inbound {
        let port = pick_free_port().await;
        built.inbounds.push(ss_inbound(port));
        ss_port = Some(port);
    }
    built.outbounds.push(freedom_default());
    let (instance, _ohm, handles) = start_full(&built).await.map_err(|e| format!("{e:?}"))?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(ApiInstance { api: api_addr, dok_port, ss_port, instance, handles })
}

/// 连接 commander gRPC（等待 server bind 就绪，最多 ~3s；与 commander_api_test.rs
/// 同款重试）。
async fn connect(addr: &str) -> Channel {
    let mut last = None;
    for _ in 0..30 {
        match tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect_timeout(Duration::from_secs(1))
            .connect()
            .await
        {
            Ok(ch) => return ch,
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("failed to connect commander gRPC at {addr}: {last:?}");
}

/// proxy_settings TypedMessage（value = settings JSON，与 CLI `api add-inbound` 同约定）。
fn proxy_settings(kind: &str, settings: serde_json::Value) -> TypedMessage {
    TypedMessage {
        r#type: format!("xray.proxy.{kind}.Config"),
        value: serde_json::to_vec(&settings).unwrap(),
    }
}

/// receiver_settings TypedMessage（listen/port JSON）。
fn receiver_settings(port: u16) -> TypedMessage {
    TypedMessage {
        r#type: "xray.app.proxyman.ReceiverConfig".into(),
        value: serde_json::to_vec(&serde_json::json!({"listen":"127.0.0.1","port":port})).unwrap(),
    }
}

/// AddUserOperation 的 TypedMessage（value = protobuf 编码，与 CLI `api add-user` 同）。
fn add_user_op(email: &str, method: &str, password: &str) -> TypedMessage {
    let account = TypedMessage {
        r#type: "xray.proxy.shadowsocks.Account".into(),
        value: serde_json::to_vec(
            &serde_json::json!({"method": method, "password": password, "email": email}),
        )
        .unwrap(),
    };
    let op = AddUserOperation {
        user: Some(User { level: 0, email: email.into(), account: Some(account) }),
    };
    TypedMessage {
        r#type: "xray.app.proxyman.command.AddUserOperation".into(),
        value: op.encode_to_vec(),
    }
}

/// RemoveUserOperation 的 TypedMessage。
fn remove_user_op(email: &str) -> TypedMessage {
    TypedMessage {
        r#type: "xray.app.proxyman.command.RemoveUserOperation".into(),
        value: RemoveUserOperation { email: email.into() }.encode_to_vec(),
    }
}

async fn inbound_tags(handler: &mut HandlerServiceClient<Channel>) -> Vec<String> {
    handler
        .list_inbounds(Request::new(ListInboundsRequest { is_only_tags: true }))
        .await
        .expect("ListInbounds 应成功（bd jezb 后已接线）")
        .into_inner()
        .inbounds
        .into_iter()
        .map(|i| i.tag)
        .collect()
}

// =========================================================================
// StatsService.GetStats（生产已接线 → 全链路绿断言）
// =========================================================================

/// 真实流量后经 gRPC GetStats 查询四个 tag counter（inbound/outbound × up/down）
/// 均非零；未注册名字返回错误（Go ErrNotFound 语义）。
#[tokio::test]
async fn get_stats_over_real_server_after_traffic() {
    let t = start_api_instance(true, false).await;
    let dok_port = t.dok_port.expect("traffic path must include dokodemo inbound");

    // 真实流量：payload 经 dokodemo → freedom → echo 回环。
    let payload = b"stats e2e traffic through dispatcher!";
    let mut client = TcpStream::connect(("127.0.0.1", dok_port)).await.unwrap();
    client.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut got))
        .await
        .expect("echo roundtrip 超时")
        .unwrap();
    assert_eq!(&got, payload);

    let mut stats = StatsServiceClient::new(connect(&t.api).await);
    for name in [
        "inbound>>>dok-in>>>traffic>>>uplink",
        "inbound>>>dok-in>>>traffic>>>downlink",
        "outbound>>>direct>>>traffic>>>uplink",
        "outbound>>>direct>>>traffic>>>downlink",
    ] {
        let resp = stats
            .get_stats(Request::new(GetStatsRequest { name: name.to_string(), reset: false }))
            .await
            .unwrap_or_else(|e| panic!("GetStats({name}) 应成功: {e:?}"));
        let stat = resp.into_inner().stat.unwrap_or_else(|| panic!("GetStats({name}) 缺 stat"));
        assert!(stat.value > 0, "counter {name} 应非零，实际 {}", stat.value);
    }

    // 未注册 counter → 错误（Go stats.ErrNotFound 语义，不虚构 0 值）。
    let missing = stats
        .get_stats(Request::new(GetStatsRequest {
            name: "inbound>>>never-registered>>>traffic>>>uplink".to_string(),
            reset: false,
        }))
        .await;
    assert!(missing.is_err(), "未注册 counter 应报错而非返回 0");

    t.abort();
}

// =========================================================================
// AddInbound / RemoveInbound / ListInbounds / AlterInbound（Go 语义）
// =========================================================================

/// AddInbound：新入站真实监听（连过去 echo 通）、可列出、重复 tag → AlreadyExists、
/// bind 冲突 → 错误上抛（不静默成功）。
#[tokio::test]
async fn add_inbound_starts_real_listener_and_serves() {
    let t = start_api_instance(false, false).await;
    let echo_port = spawn_echo().await;
    let port = pick_free_port().await;
    let mut handler = HandlerServiceClient::new(connect(&t.api).await);

    let cfg = InboundHandlerConfig {
        tag: "api-added-in".into(),
        receiver_settings: Some(receiver_settings(port)),
        proxy_settings: Some(proxy_settings(
            "dokodemo",
            serde_json::json!({"address": "127.0.0.1", "port": echo_port}),
        )),
    };
    handler
        .add_inbound(Request::new(AddInboundRequest { inbound: Some(cfg.clone()) }))
        .await
        .expect("AddInbound 应成功（bd jezb 后已接线）");

    // 真实监听：payload 经新入站 → dokodemo → freedom → echo 回环。
    let payload = b"gRPC AddInbound e2e traffic";
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    sock.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut got))
        .await
        .expect("新增入站 echo roundtrip 超时")
        .unwrap();
    assert_eq!(&got, payload);

    // 列表含新 tag（Go：AddInbound 后 ihm 立即可查）。
    assert!(
        inbound_tags(&mut handler).await.iter().any(|tag| tag == "api-added-in"),
        "ListInbounds 应包含新增 tag"
    );

    // 重复 tag → AlreadyExists（Go "existing tag found" 语义）。
    let dup = handler
        .add_inbound(Request::new(AddInboundRequest { inbound: Some(cfg) }))
        .await
        .unwrap_err();
    assert_eq!(dup.code(), tonic::Code::AlreadyExists, "重复 tag 应 AlreadyExists: {dup:?}");

    // 端口被占（echo 已 bind 该端口）→ bind 失败原样上抛，不静默成功。
    let busy = handler
        .add_inbound(Request::new(AddInboundRequest {
            inbound: Some(InboundHandlerConfig {
                tag: "api-busy-in".into(),
                receiver_settings: Some(receiver_settings(echo_port)),
                proxy_settings: Some(proxy_settings(
                    "dokodemo",
                    serde_json::json!({"address": "127.0.0.1", "port": echo_port}),
                )),
            }),
        }))
        .await
        .unwrap_err();
    assert!(
        busy.message().contains("listen socket"),
        "bind 失败应带 listen socket 上下文上抛，实际: {}",
        busy.message()
    );
    assert!(
        !inbound_tags(&mut handler).await.iter().any(|tag| tag == "api-busy-in"),
        "bind 失败不应留下已登记 tag"
    );

    // 缺 proxy_settings → 明确报错（不静默成功）。
    let no_proxy = handler
        .add_inbound(Request::new(AddInboundRequest {
            inbound: Some(InboundHandlerConfig {
                tag: "api-no-proxy".into(),
                ..Default::default()
            }),
        }))
        .await
        .unwrap_err();
    assert!(
        no_proxy.message().contains("proxy_settings"),
        "缺 proxy_settings 应报明确错误，实际: {}",
        no_proxy.message()
    );

    t.abort();
}

/// RemoveInbound：端口立即停止接受连接、列表移除、重复删 → NotFound。
#[tokio::test]
async fn remove_inbound_stops_listener() {
    let t = start_api_instance(true, false).await;
    let dok_port = t.dok_port.expect("traffic path must include dokodemo inbound");
    let mut handler = HandlerServiceClient::new(connect(&t.api).await);

    handler
        .remove_inbound(Request::new(RemoveInboundRequest { tag: "dok-in".into() }))
        .await
        .expect("RemoveInbound 应成功");
    assert!(
        !inbound_tags(&mut handler).await.iter().any(|tag| tag == "dok-in"),
        "移除后 ListInbounds 不应再含该 tag"
    );

    // 运行时状态真变：原端口不再接受连接（取消令牌已停 accept loop）。
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(TcpStream::connect(("127.0.0.1", dok_port)).await.is_err(), "移除后入站不应再接受连接");

    // 重复删 → NotFound（Go HandlerNotFound）。
    let gone = handler
        .remove_inbound(Request::new(RemoveInboundRequest { tag: "dok-in".into() }))
        .await
        .unwrap_err();
    assert_eq!(gone.code(), tonic::Code::NotFound, "未知 tag 应 NotFound: {gone:?}");

    t.abort();
}

/// ListInbounds：tags 态只回 tag；完整态回 proxy/receiver type_url。
#[tokio::test]
async fn list_inbounds_reports_running_configs() {
    let t = start_api_instance(true, false).await;
    let mut handler = HandlerServiceClient::new(connect(&t.api).await);

    let full = handler
        .list_inbounds(Request::new(ListInboundsRequest { is_only_tags: false }))
        .await
        .expect("ListInbounds 应成功")
        .into_inner();
    let cfg = full
        .inbounds
        .iter()
        .find(|i| i.tag == "dok-in")
        .expect("ListInbounds 应含配置期 dokodemo 入站");
    assert_eq!(
        cfg.proxy_settings.as_ref().map(|m| m.r#type.as_str()),
        Some("xray.proxy.dokodemo.Config"),
        "proxy_settings type_url 应对齐 Go 注册名"
    );
    assert_eq!(
        cfg.receiver_settings.as_ref().map(|m| m.r#type.as_str()),
        Some("xray.app.proxyman.ReceiverConfig"),
        "receiver_settings type_url 应对齐 Go 注册名"
    );

    let tags_only = handler
        .list_inbounds(Request::new(ListInboundsRequest { is_only_tags: true }))
        .await
        .unwrap()
        .into_inner();
    assert!(!tags_only.inbounds.is_empty());
    assert!(
        tags_only
            .inbounds
            .iter()
            .all(|i| i.proxy_settings.is_none() && i.receiver_settings.is_none()),
        "is_only_tags=true 时不应回填 settings"
    );

    t.abort();
}

/// AlterInbound：AddUser/RemoveUser 对 ss 用户面真实生效；非 UserManager 入站 →
/// FailedPrecondition；未知 tag → NotFound；未知操作类型 → 明确报错。
#[tokio::test]
async fn alter_inbound_add_and_remove_user() {
    let t = start_api_instance(true, true).await;
    assert!(t.ss_port.is_some(), "ss inbound 应已启动");
    let mut handler = HandlerServiceClient::new(connect(&t.api).await);

    // 配置期用户面可见（ss validator 与 serve loop 共享 Arc）。
    let initial = handler
        .get_inbound_users(Request::new(GetInboundUserRequest {
            tag: "ss-in".into(),
            email: String::new(),
        }))
        .await
        .expect("GetInboundUsers 应成功")
        .into_inner();
    assert_eq!(initial.users.len(), 1, "配置期应有 1 个用户: {initial:?}");
    assert_eq!(initial.users[0].email, "cfg@ss");

    // AddUser → 用户表 +1（Go AddUserOperation）。
    handler
        .alter_inbound(Request::new(AlterInboundRequest {
            tag: "ss-in".into(),
            operation: Some(add_user_op("added@ss", "aes-128-gcm", "pw-added")),
        }))
        .await
        .expect("AlterInbound(AddUser) 应成功");
    let after_add = handler
        .get_inbound_users(Request::new(GetInboundUserRequest {
            tag: "ss-in".into(),
            email: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(after_add.users.len(), 2, "AddUser 后应 2 个用户: {after_add:?}");
    assert!(after_add.users.iter().any(|u| u.email == "added@ss"));

    // RemoveUser → 用户表 -1（Go RemoveUserOperation）。
    handler
        .alter_inbound(Request::new(AlterInboundRequest {
            tag: "ss-in".into(),
            operation: Some(remove_user_op("added@ss")),
        }))
        .await
        .expect("AlterInbound(RemoveUser) 应成功");
    let after_remove = handler
        .get_inbound_users(Request::new(GetInboundUserRequest {
            tag: "ss-in".into(),
            email: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(after_remove.users.len(), 1, "RemoveUser 后应回到 1 个用户: {after_remove:?}");

    // 非 UserManager 入站（dokodemo）→ FailedPrecondition（Go 类型断言失败语义）。
    let not_um = handler
        .alter_inbound(Request::new(AlterInboundRequest {
            tag: "dok-in".into(),
            operation: Some(add_user_op("x@dok", "aes-128-gcm", "pw")),
        }))
        .await
        .unwrap_err();
    assert_eq!(
        not_um.code(),
        tonic::Code::FailedPrecondition,
        "非 UserManager 入站应 FailedPrecondition: {not_um:?}"
    );

    // 未知 tag → NotFound（Go HandlerNotFound）。
    let ghost = handler
        .alter_inbound(Request::new(AlterInboundRequest {
            tag: "ghost-in".into(),
            operation: Some(add_user_op("x@ghost", "aes-128-gcm", "pw")),
        }))
        .await
        .unwrap_err();
    assert_eq!(ghost.code(), tonic::Code::NotFound, "未知 tag 应 NotFound: {ghost:?}");

    // 未知操作类型 → 明确报错（不 panic、不静默）。
    let bogus = handler
        .alter_inbound(Request::new(AlterInboundRequest {
            tag: "ss-in".into(),
            operation: Some(TypedMessage {
                r#type: "xray.app.proxyman.command.BogusOperation".into(),
                value: Vec::new(),
            }),
        }))
        .await
        .unwrap_err();
    assert!(
        bogus.message().contains("unsupported inbound operation type"),
        "未知操作类型应报明确错误，实际: {}",
        bogus.message()
    );

    // 用户面改动不影响实例存活（LogFeature 仍在 instance 注册表内）。
    assert!(t.instance.get_feature::<xray_app_log::LogFeature>().is_some());
    t.abort();
}
