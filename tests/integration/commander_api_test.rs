//! Commander gRPC API e2e 测试（bd ze3+bg7）。
//!
//! 全链路：BuiltConfig（api app + freedom outbound）→ `start_full` →
//! Instance + SimpleOhm + commander gRPC server → 真实 tonic 客户端调用：
//! - AddOutbound/RemoveOutbound/ListOutbounds → 断言操作的是 **生产 SimpleOhm** （`start_full`
//!   返回的同一个 ohm），而非 commander 内部 stub registry
//! - RestartLogger → 真实 LogInstance.restart
//! - gRPC reflection → list services 可发现已注册服务

use std::{sync::Arc, time::Duration};

use tokio::net::TcpListener;
use tonic::{Request, transport::Channel};
/// 反射客户端（tonic-reflection 0.14：类型在 `pb::v1alpha` 下）。
use tonic_reflection::pb::v1alpha::server_reflection_client::ServerReflectionClient;
use tonic_reflection::pb::v1alpha::{
    ServerReflectionRequest, server_reflection_request::MessageRequest,
    server_reflection_response::MessageResponse,
};
use xray_app_dispatcher::OutboundHandlerManager;
use xray_conf::{BuiltConfig, BuiltEntry, BuiltOutbound, app_config::ApiConfig};
use xray_core::functions::start_full;
use xray_proto::xray::{
    app::{
        log::command::{RestartLoggerRequest, logger_service_client::LoggerServiceClient},
        proxyman::command::{
            AddOutboundRequest, ListOutboundsRequest, RemoveOutboundRequest,
            handler_service_client::HandlerServiceClient,
        },
    },
    common::serial::TypedMessage,
    core::OutboundHandlerConfig,
};

/// 构造与 CLI（api_exec::build_typed_message）一致编码的 AddOutbound 请求。
fn add_outbound_request(tag: &str, protocol: &str, settings: &str) -> AddOutboundRequest {
    AddOutboundRequest {
        outbound: Some(OutboundHandlerConfig {
            tag: tag.to_string(),
            sender_settings: Some(TypedMessage {
                r#type: "xray.app.proxyman.outbound".to_string(),
                value: b"{}".to_vec(),
            }),
            proxy_settings: Some(TypedMessage {
                r#type: format!("xray.proxy.{protocol}.Config"),
                value: settings.as_bytes().to_vec(),
            }),
            expire: 0,
            comment: String::new(),
        }),
    }
}

/// 起一个完整实例（api app 监听随机端口 + freedom default outbound），
/// 返回（ohm、api 地址、instance）。
async fn start_with_api()
-> (Arc<xray_app_dispatcher::default::SimpleOhm>, String, Arc<xray_core::Instance>) {
    // 随机端口：先 bind :0 拿端口号再释放（与 e2e_test.rs 的端口分配惯例一致）。
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let api_addr = format!("127.0.0.1:{port}");

    let api_cfg = ApiConfig {
        tag: None,
        listen: Some(api_addr.clone()),
        services: Some(vec![
            "HandlerService".to_string(),
            "LoggerService".to_string(),
            "ReflectionService".to_string(),
        ]),
    };
    let built = BuiltConfig {
        apps: vec![BuiltEntry {
            kind: "api".to_string(),
            data: serde_json::to_vec(&api_cfg).unwrap(),
        }],
        inbounds: vec![],
        outbounds: vec![BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".to_string(), data: b"{}".to_vec() },
            tag: "direct".to_string(),
            send_through: None,
            stream_settings_json: None,
            proxy_settings_json: None,
            mux_json: None,
            target_strategy: None,
        }],
    };

    let (instance, ohm, _handles) = start_full(&built).await.unwrap();
    (ohm, api_addr, instance)
}

/// 连接 commander gRPC（等待 server bind 就绪，最多 ~3s）。
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

#[tokio::test]
async fn add_remove_outbound_hits_real_ohm() {
    let (ohm, addr, _instance) = start_with_api().await;
    let channel = connect(&addr).await;
    let mut handler = HandlerServiceClient::new(channel);

    // AddOutbound(freedom) → 生产 ohm 可查到（bg7 核心断言）
    handler
        .add_outbound(Request::new(add_outbound_request("api-added", "freedom", "{}")))
        .await
        .unwrap();
    assert!(
        ohm.get_handler("api-added").is_some(),
        "AddOutbound must register into the real SimpleOhm"
    );

    // 重复 tag → AlreadyExists（Go "existing tag found" 语义）
    let dup = handler
        .add_outbound(Request::new(add_outbound_request("api-added", "freedom", "{}")))
        .await;
    assert!(dup.is_err());
    assert_eq!(dup.unwrap_err().code(), tonic::Code::AlreadyExists);

    // ListOutbounds 含静态 direct + 动态 api-added
    let listed =
        handler.list_outbounds(Request::new(ListOutboundsRequest {})).await.unwrap().into_inner();
    let tags: Vec<&str> = listed.outbounds.iter().map(|o| o.tag.as_str()).collect();
    assert!(tags.contains(&"direct"));
    assert!(tags.contains(&"api-added"));

    // RemoveOutbound → 生产 ohm 中消失；再删 → NotFound
    handler
        .remove_outbound(Request::new(RemoveOutboundRequest { tag: "api-added".to_string() }))
        .await
        .unwrap();
    assert!(ohm.get_handler("api-added").is_none());
    let gone = handler
        .remove_outbound(Request::new(RemoveOutboundRequest { tag: "api-added".to_string() }))
        .await;
    assert_eq!(gone.unwrap_err().code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn restart_logger_hits_real_log_instance() {
    let (_ohm, addr, instance) = start_with_api().await;
    let channel = connect(&addr).await;
    let mut logger = LoggerServiceClient::new(channel);

    // RestartLogger → 真实 DefaultLogService → LogInstance::restart（close+start）
    logger.restart_logger(Request::new(RestartLoggerRequest {})).await.unwrap();

    // restart 后 LogInstance 仍 active（close 失败或 start 失败都会变 inactive）
    let log_feature =
        instance.get_feature::<xray_app_log::LogFeature>().expect("LogFeature must be registered");
    assert!(log_feature.instance().is_active(), "LogInstance must stay active after RestartLogger");
}

#[tokio::test]
async fn reflection_lists_commander_services() {
    let (_ohm, addr, _instance) = start_with_api().await;
    let channel = connect(&addr).await;
    let mut reflection = ServerReflectionClient::new(channel);

    // bidi stream：发一条 ListServices("*")，收第一条响应
    let request_stream = futures::stream::iter(vec![ServerReflectionRequest {
        host: String::new(),
        message_request: Some(MessageRequest::ListServices("*".to_string())),
    }]);
    let mut resp = reflection.server_reflection_info(request_stream).await.unwrap().into_inner();
    let msg = resp.message().await.unwrap().expect("reflection response");

    let names: Vec<String> = match msg.message_response {
        Some(MessageResponse::ListServicesResponse(list)) => {
            list.service.into_iter().map(|s| s.name).collect()
        },
        other => panic!("expected ListServicesResponse, got {other:?}"),
    };
    assert!(
        names.iter().any(|n| n == "xray.app.proxyman.command.HandlerService"),
        "HandlerService missing from reflection list: {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "xray.app.log.command.LoggerService"),
        "LoggerService missing from reflection list: {names:?}"
    );
}

/// bd xim8 修复验证：reflection 仅 opt-in。未在 `services` 中声明 `ReflectionService`
/// 时，gRPC server **不暴露** reflection — `ServerReflectionInfo` 调用返回
/// Unimplemented/Empty（grpcurl 匿名枚举不可达）。对应 Go `infra/conf/api.go:30`
/// `"reflectionservice"` 关键字语义。
#[tokio::test]
async fn reflection_disabled_when_not_opted_in() {
    // api cfg：无 ReflectionService
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let api_addr = format!("127.0.0.1:{port}");

    let api_cfg = ApiConfig {
        tag: None,
        listen: Some(api_addr.clone()),
        services: Some(vec![
            "HandlerService".to_string(),
            "LoggerService".to_string(),
            // 注意：未声明 ReflectionService → reflection 必须禁用
        ]),
    };
    let built = BuiltConfig {
        apps: vec![BuiltEntry {
            kind: "api".to_string(),
            data: serde_json::to_vec(&api_cfg).unwrap(),
        }],
        inbounds: vec![],
        outbounds: vec![BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".to_string(), data: b"{}".to_vec() },
            tag: "direct".to_string(),
            send_through: None,
            stream_settings_json: None,
            proxy_settings_json: None,
            mux_json: None,
            target_strategy: None,
        }],
    };
    let (_instance, _ohm, _handles) = match xray_core::functions::start_full(&built).await {
        Ok(v) => v,
        Err(e) => panic!("start_full failed: {e}"),
    };
    let channel = connect(&api_addr).await;
    let mut reflection = ServerReflectionClient::new(channel);

    // 尝试 ListServices — opt-out 时服务端无 reflection handler，应返回
    // tonic::Status(Code::Unimplemented) 或 Empty。
    let request_stream = futures::stream::iter(vec![ServerReflectionRequest {
        host: String::new(),
        message_request: Some(MessageRequest::ListServices("*".to_string())),
    }]);
    let result = reflection.server_reflection_info(request_stream).await;
    // 任一形式都表示 reflection 已禁用：
    // - bidi 第一次 recv 即收到 Unimplemented
    // - 或 channel 报 unknown service
    match result {
        Err(status) => {
            // bidi 错误（最常见）：server reflection 未注册 → Unimplemented
            assert!(
                status.code() == tonic::Code::Unimplemented
                    || status.code() == tonic::Code::Unknown,
                "expected Unimplemented/Unknown when reflection disabled, got {:?}",
                status
            );
        },
        Ok(resp) => {
            // 极少见：bidi 返回 Ok 但流立即 Empty → 也算禁用
            let mut stream = resp.into_inner();
            let msg = stream.message().await;
            match msg {
                Ok(Some(mr)) => {
                    // 服务端不应返回 ListServicesResponse — 只可能 ErrorInfo 或 empty
                    if let Some(MessageResponse::ListServicesResponse(list)) = mr.message_response {
                        panic!(
                            "reflection must be disabled, but got {} services",
                            list.service.len()
                        );
                    }
                },
                Ok(None) => { /* 空流 = 禁用 OK */ },
                Err(status) => {
                    // message() 收到 Unimplemented
                    assert!(
                        status.code() == tonic::Code::Unimplemented
                            || status.code() == tonic::Code::Unknown,
                        "expected Unimplemented/Unknown when reflection disabled, got {:?}",
                        status
                    );
                },
            }
        },
    }
}
