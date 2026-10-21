//! G-11 commander 五命令真实-server 集成（dofk 缺口；现有 commander_api_test.rs
//! 只覆盖 AddOutbound/RemoveOutbound/RestartLogger/Reflection）。
//!
//! 补五命令：AddInbound / RemoveInbound / ListInbounds /
//! AlterInbound(AddUser+RemoveUser) / StatsService.GetStats——全部经
//! `start_full` 起的真实实例 + 真实 tonic gRPC 客户端（对齐 Go
//! testing/scenarios 的 InitializeServerConfigs + core.NewClient 形态）。
//!
//! 生产事实（撰写时，bd 票级缺口）：`start_full` 只向 Commander 注入
//! OutboundRuntime + StatsService + LoggerService；**proxyman HandlerService
//! 未接线**（`Commander::set_handler_service` 无生产调用方）。因此 inbound/alter
//! 四命令经真实 gRPC 返回 `UNIMPLEMENTED("... requires proxyman HandlerService
//! (not injected)")`。这四条测试把当前生产契约钉成断言：产品接线 proxyman 后
//! 自动翻红，提示按 Go 语义更新断言。GetStats 生产已接线（bd dnw3），全链路绿断言。
//!
//! Go 对照差异（finding，详见报告）：Go 的 HandlerService.AddInbound 等 10 op
//! 全部可用；Rust 生产面 inbound 域命令未接线。

use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tonic::{Request, Status, transport::Channel};
use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound, app_config::ApiConfig};
use xray_core::functions::start_full;
use xray_proto::xray::{
    app::{
        proxyman::command::{
            AddInboundRequest, AlterInboundRequest, ListInboundsRequest, RemoveInboundRequest,
            handler_service_client::HandlerServiceClient,
        },
        stats::command::{GetStatsRequest, stats_service_client::StatsServiceClient},
    },
    common::serial::TypedMessage,
    core::InboundHandlerConfig,
};

/// policy system 四门（Go app/policy 的 System.Stats 同语义）：开启后
/// inbound/outbound 按 tag 的 traffic counter 才会被注册（wiring sm80① 门控）。
const POLICY_SYSTEM_STATS: &[u8] =
    br#"{"system":{"statsInboundUplink":true,"statsInboundDownlink":true,"statsOutboundUplink":true,"statsOutboundDownlink":true}}"#;

/// bind :0 取空闲端口再释放。
async fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
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

/// 起真实实例：api app（HandlerService+StatsService）+ policy system stats 门 +
/// dokodemo inbound（rewrite → echo）+ freedom。返回 (api 地址, dok 端口, instance,
/// handles)。纯 API 断言的测试走 `dok_port=None` 路径（无 inbound）。
async fn start_api_instance(
    with_traffic_path: bool,
) -> (String, Option<u16>, Arc<xray_core::Instance>, Vec<tokio::task::JoinHandle<()>>) {
    let api_port = pick_free_port().await;
    let api_addr = format!("127.0.0.1:{api_port}");

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
        .unwrap(),
    });
    if with_traffic_path {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
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
        let dok_port = pick_free_port().await;
        built.inbounds.push(BuiltInbound {
            entry: BuiltEntry {
                kind: "dokodemo".into(),
                data: format!(r#"{{"address":"127.0.0.1","port":{echo_port}}}"#).into_bytes(),
            },
            tag: "dok-in".into(),
            port: Some(dok_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        });
        built.outbounds.push(freedom_default());
        let (_instance, _ohm, handles) = start_full(&built).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        return (api_addr, Some(dok_port), _instance, handles);
    }
    built.outbounds.push(freedom_default());
    let (instance, _ohm, handles) = start_full(&built).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    (api_addr, None, instance, handles)
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

/// 断言 gRPC 状态 = UNIMPLEMENTED 且报文指向 proxyman HandlerService 未注入
/// （当前生产契约；接线后自动翻红提醒更新为 Go 语义断言）。
fn assert_unimplemented_gap(stage: &str, err: Status) {
    assert_eq!(
        err.code(),
        tonic::Code::Unimplemented,
        "{stage}: 生产未接线 proxyman HandlerService 时应返回 UNIMPLEMENTED"
    );
    let msg = err.message();
    assert!(
        msg.contains("requires proxyman HandlerService"),
        "{stage}: 报文应指向 proxyman HandlerService 缺注入，实际: {msg}"
    );
}

// =========================================================================
// StatsService.GetStats（生产已接线 → 全链路绿断言）
// =========================================================================

/// 真实流量后经 gRPC GetStats 查询四个 tag counter（inbound/outbound × up/down）
/// 均非零；未注册名字返回错误（Go ErrNotFound 语义）。
#[tokio::test]
async fn get_stats_over_real_server_after_traffic() {
    let (api_addr, dok_port, _instance, handles) = start_api_instance(true).await;
    let dok_port = dok_port.expect("traffic path must include dokodemo inbound");

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

    let mut stats = StatsServiceClient::new(connect(&api_addr).await);
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

    for h in handles {
        h.abort();
    }
}

// =========================================================================
// AddInbound / RemoveInbound / ListInbounds / AlterInbound（生产缺口契约）
// =========================================================================

/// AddInbound：生产面 UNIMPLEMENTED（proxyman HandlerService 未注入）。
#[tokio::test]
async fn add_inbound_unimplemented_on_real_server() {
    let (api_addr, _, _instance, handles) = start_api_instance(false).await;
    let mut handler = HandlerServiceClient::new(connect(&api_addr).await);
    let err = handler
        .add_inbound(Request::new(AddInboundRequest {
            inbound: Some(InboundHandlerConfig { tag: "api-added-in".into(), ..Default::default() }),
        }))
        .await
        .unwrap_err();
    assert_unimplemented_gap("AddInbound", err);
    for h in handles {
        h.abort();
    }
}

/// RemoveInbound：生产面 UNIMPLEMENTED。
#[tokio::test]
async fn remove_inbound_unimplemented_on_real_server() {
    let (api_addr, _, _instance, handles) = start_api_instance(false).await;
    let mut handler = HandlerServiceClient::new(connect(&api_addr).await);
    let err = handler
        .remove_inbound(Request::new(RemoveInboundRequest { tag: "dok-in".into() }))
        .await
        .unwrap_err();
    assert_unimplemented_gap("RemoveInbound", err);
    for h in handles {
        h.abort();
    }
}

/// ListInbounds：生产面 UNIMPLEMENTED。
#[tokio::test]
async fn list_inbounds_unimplemented_on_real_server() {
    let (api_addr, _, _instance, handles) = start_api_instance(false).await;
    let mut handler = HandlerServiceClient::new(connect(&api_addr).await);
    let err = handler
        .list_inbounds(Request::new(ListInboundsRequest { is_only_tags: false }))
        .await
        .unwrap_err();
    assert_unimplemented_gap("ListInbounds", err);
    for h in handles {
        h.abort();
    }
}

/// AlterInbound（AddUser + RemoveUser 两操作）：生产面 UNIMPLEMENTED。
/// 操作载荷按 Go `AlterInboundRequest{tag, operation: TypedMessage}` 形态构造，
/// type URL 对齐 Go proxyman command 操作注册名（命令在 decode 前即被拒，
/// value 留空不影响契约断言）。
#[tokio::test]
async fn alter_inbound_adduser_and_removeuser_unimplemented_on_real_server() {
    let (api_addr, _, _instance, handles) = start_api_instance(false).await;
    let mut handler = HandlerServiceClient::new(connect(&api_addr).await);

    let add_user = AlterInboundRequest {
        tag: "dok-in".into(),
        operation: Some(TypedMessage {
            r#type: "xray.app.proxyman.command.AddUserOperation".into(),
            value: Vec::new(),
        }),
    };
    let err = handler.alter_inbound(Request::new(add_user)).await.unwrap_err();
    assert_unimplemented_gap("AlterInbound(AddUser)", err);

    let remove_user = AlterInboundRequest {
        tag: "dok-in".into(),
        operation: Some(TypedMessage {
            r#type: "xray.app.proxyman.command.RemoveUserOperation".into(),
            value: Vec::new(),
        }),
    };
    let err = handler.alter_inbound(Request::new(remove_user)).await.unwrap_err();
    assert_unimplemented_gap("AlterInbound(RemoveUser)", err);

    for h in handles {
        h.abort();
    }
}
