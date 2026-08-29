//! # API 命令 execute 函数
//!
//! 通过 gRPC 调用 commander API。Go 全部 23 个子命令已在 Rust 端接通真实 RPC
//! （proxyman / stats / router / logger service client + HandlerService 用户管理）。
//!
//! 实现层仅做：参数反序列化 + gRPC request 构造 + RPC 调用 + 响应打印。
//! 后端业务逻辑（commaner gRPC server）由 `xray-core` 端的 gRPC server 提供。

use std::io::Read;


use tonic::Request;

use xray_proto::xray::app::log::command::RestartLoggerRequest;
use xray_proto::xray::app::proxyman::command::{
    AddInboundRequest, AddOutboundRequest, AddUserOperation, AlterInboundRequest,
    GetInboundUserRequest, ListInboundsRequest, ListOutboundsRequest, RemoveInboundRequest,
    RemoveOutboundRequest, RemoveUserOperation,
};
use xray_proto::xray::app::router::command::{
    AddRuleRequest, GetBalancerInfoRequest, ListRuleRequest, OverrideBalancerTargetRequest,
    RemoveRuleRequest,
};
use xray_proto::xray::app::stats::command::{
    GetAllOnlineUsersRequest, GetStatsRequest, GetUsersStatsRequest, QueryStatsRequest,
    SysStatsRequest,
};
use xray_proto::xray::common::serial::TypedMessage;
use xray_proto::xray::core::{InboundHandlerConfig, OutboundHandlerConfig};

use crate::commands::api_client::ApiClient;
use crate::error::CliError;

use super::api_args::*;

/// 读取配置参数（文件路径、`stdin:`、或 HTTP URL）。
fn load_config(arg: &str) -> Result<Vec<u8>, CliError> {
    if arg == "stdin:" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| CliError::InvalidArgument(format!("failed to read stdin: {e}")))?;
        Ok(buf)
    } else {
        std::fs::read(arg).map_err(|e| CliError::InvalidArgument(format!("failed to read {arg}: {e}")))
    }
}

/// 从 JSON 配置文件构建入站 HandlerConfig 列表。
///
/// 对应 Go `serial.DecodeJSONConfig` + `InboundConfigs.Build()` 的简化版：
/// 解析 JSON 配置 → 提取 inbounds → 转为 proto `InboundHandlerConfig`。
fn build_inbound_configs(json_data: &[u8]) -> Result<Vec<InboundHandlerConfig>, CliError> {
    let config: serde_json::Value = serde_json::from_slice(json_data)
        .map_err(|e| CliError::InvalidArgument(format!("failed to parse JSON config: {e}")))?;

    let inbounds = config
        .get("inbounds")
        .or_else(|| config.get("inbound"))
        .and_then(|v| v.as_array());

    let Some(inbounds) = inbounds else {
        return Err(CliError::InvalidArgument("no inbounds found in config".into()));
    };

    let mut result = Vec::new();
    for ib in inbounds {
        let tag = ib.get("tag").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let protocol = ib.get("protocol").and_then(|v| v.as_str()).unwrap_or("");

        // proxy_settings：inbound 的 settings 内容
        let proxy_settings = build_typed_message(protocol, ib.get("settings"));

        // receiver_settings：inbound 的 streamSettings + port + listen 等
        let receiver_settings = build_typed_message(
            "xray.app.proxyman.inbound",
            Some(&serde_json::Value::Object({
                let mut map = serde_json::Map::new();
                if let Some(v) = ib.get("port") { map.insert("port".into(), v.clone()); }
                if let Some(v) = ib.get("listen") { map.insert("listen".into(), v.clone()); }
                if let Some(v) = ib.get("streamSettings") { map.insert("streamSettings".into(), v.clone()); }
                if let Some(v) = ib.get("sniffing") { map.insert("sniffing".into(), v.clone()); }
                map
            })),
        );

        result.push(InboundHandlerConfig {
            tag,
            receiver_settings: Some(receiver_settings),
            proxy_settings: Some(proxy_settings),
        });
    }

    Ok(result)
}

/// 从 JSON 配置文件构建出站 HandlerConfig 列表。
fn build_outbound_configs(json_data: &[u8]) -> Result<Vec<OutboundHandlerConfig>, CliError> {
    let config: serde_json::Value = serde_json::from_slice(json_data)
        .map_err(|e| CliError::InvalidArgument(format!("failed to parse JSON config: {e}")))?;

    let outbounds = config
        .get("outbounds")
        .or_else(|| config.get("outbound"))
        .and_then(|v| v.as_array());

    let Some(outbounds) = outbounds else {
        return Err(CliError::InvalidArgument("no outbounds found in config".into()));
    };

    let mut result = Vec::new();
    for ob in outbounds {
        let tag = ob.get("tag").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let protocol = ob.get("protocol").and_then(|v| v.as_str()).unwrap_or("");

        let proxy_settings = build_typed_message(protocol, ob.get("settings"));
        let sender_settings = build_typed_message(
            "xray.app.proxyman.outbound",
            Some(&serde_json::Value::Object({
                let mut map = serde_json::Map::new();
                if let Some(v) = ob.get("sendThrough") { map.insert("sendThrough".into(), v.clone()); }
                if let Some(v) = ob.get("streamSettings") { map.insert("streamSettings".into(), v.clone()); }
                map
            })),
        );

        result.push(OutboundHandlerConfig {
            tag,
            sender_settings: Some(sender_settings),
            proxy_settings: Some(proxy_settings),
            expire: 0,
            comment: String::new(),
        });
    }

    Ok(result)
}

/// 构建 TypedMessage：type_url 为协议名对应的全限定类型，value 为 JSON 编码。
fn build_typed_message(type_name: &str, settings: Option<&serde_json::Value>) -> TypedMessage {
    // Go 端 type_url 格式为 "xray.proxy.PROTOCOL.Config" 或 "xray.app.proxyman.inbound.Config"
    let type_url = if type_name.contains('.') {
        type_name.to_string()
    } else {
        format!("xray.proxy.{type_name}.Config")
    };

    let value = settings
        .map(|v| serde_json::to_vec(v).unwrap_or_default())
        .unwrap_or_default();

    TypedMessage { r#type: type_url, value }
}

/// 构建 AddRule 的 TypedMessage（路由规则）。
fn build_rule_typed_message(json_data: &[u8]) -> Result<TypedMessage, CliError> {
    let config: serde_json::Value = serde_json::from_slice(json_data)
        .map_err(|e| CliError::InvalidArgument(format!("failed to parse JSON config: {e}")))?;

    let routing = config.get("routing").ok_or_else(|| {
        CliError::InvalidArgument("config did not have \"routing\" field".into())
    })?;

    Ok(TypedMessage {
        r#type: "xray.app.router.RoutingConfig".to_string(),
        value: serde_json::to_vec(routing).unwrap_or_default(),
    })
}

/// 打印 gRPC 响应。proto 消息不实现 serde::Serialize，用 Debug 输出。
fn print_response<T: std::fmt::Debug>(resp: &T, _json_output: bool) {
    // ponytail: proto 消息无 serde derive，用 Debug 格式输出；后续可加 prost serde feature 改进
    println!("{resp:#?}");
}

// ---------------------------------------------------------------------------
// 已接通 gRPC 的 8 个命令
// ---------------------------------------------------------------------------

/// add-inbound：读取配置 → 构建 AddInboundRequest → gRPC 调用。
pub async fn execute_add_inbound(args: &AddInboundArgs) -> Result<(), CliError> {
    let data = load_config(&args.config)?;
    let inbounds = build_inbound_configs(&data)?;

    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut handler = client.handler_client();

    for ib in inbounds {
        let tag = ib.tag.clone();
        let req = Request::new(AddInboundRequest { inbound: Some(ib) });
        handler
            .add_inbound(req)
            .await
            .map_err(|e| CliError::ApiRequestFailed(format!("failed to add inbound '{tag}': {e}")))?;
        println!("added inbound: {tag}");
    }

    Ok(())
}

/// remove-inbound：发送 RemoveInboundRequest。
pub async fn execute_remove_inbound(args: &RemoveInboundArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut handler = client.handler_client();

    let req = Request::new(RemoveInboundRequest { tag: args.tag.clone() });
    handler
        .remove_inbound(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to remove inbound: {e}")))?;

    println!("removed inbound: {}", args.tag);
    Ok(())
}

/// add-outbound：读取配置 → 构建 AddOutboundRequest → gRPC 调用。
pub async fn execute_add_outbound(args: &AddOutboundArgs) -> Result<(), CliError> {
    let data = load_config(&args.config)?;
    let outbounds = build_outbound_configs(&data)?;

    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut handler = client.handler_client();

    for ob in outbounds {
        let tag = ob.tag.clone();
        let req = Request::new(AddOutboundRequest { outbound: Some(ob) });
        handler
            .add_outbound(req)
            .await
            .map_err(|e| CliError::ApiRequestFailed(format!("failed to add outbound '{tag}': {e}")))?;
        println!("added outbound: {tag}");
    }

    Ok(())
}

/// remove-outbound：发送 RemoveOutboundRequest。
pub async fn execute_remove_outbound(args: &RemoveOutboundArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut handler = client.handler_client();

    let req = Request::new(RemoveOutboundRequest { tag: args.tag.clone() });
    handler
        .remove_outbound(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to remove outbound: {e}")))?;

    println!("removed outbound: {}", args.tag);
    Ok(())
}

/// add-rule：读取配置 → 构建 AddRuleRequest → gRPC 调用。
pub async fn execute_add_rule(args: &AddRuleArgs) -> Result<(), CliError> {
    let data = load_config(&args.config)?;
    let config = build_rule_typed_message(&data)?;

    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut routing = client.routing_client();

    let req = Request::new(AddRuleRequest {
        config: Some(config),
        should_append: args.append,
    });
    routing
        .add_rule(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to add rule: {e}")))?;

    println!("added rule");
    Ok(())
}

/// remove-rule：发送 RemoveRuleRequest。
pub async fn execute_remove_rule(args: &RemoveRuleArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut routing = client.routing_client();

    for rule_tag in &args.rule_tags {
        let req = Request::new(RemoveRuleRequest {
            rule_tag: rule_tag.clone(),
        });
        routing
            .remove_rule(req)
            .await
            .map_err(|e| CliError::ApiRequestFailed(format!("failed to remove rule '{rule_tag}': {e}")))?;
        println!("removed rule: {rule_tag}");
    }

    Ok(())
}

/// stats：发送 GetStatsRequest。
pub async fn execute_stats(args: &StatsArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut stats = client.stats_client();

    let req = Request::new(GetStatsRequest {
        name: args.name.clone(),
        reset: args.reset,
    });
    let resp = stats
        .get_stats(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to get stats: {e}")))?;

    print_response(&resp.into_inner(), args.api.json);
    Ok(())
}

/// stats-query：发送 QueryStatsRequest。
pub async fn execute_stats_query(args: &StatsQueryArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut stats = client.stats_client();

    let req = Request::new(QueryStatsRequest {
        pattern: args.pattern.clone(),
        reset: args.reset,
    });
    let resp = stats
        .query_stats(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to query stats: {e}")))?;

    print_response(&resp.into_inner(), args.api.json);
    Ok(())
}
// ---------------------------------------------------------------------------
// 接通 gRPC 的剩余 15 个命令
// ---------------------------------------------------------------------------

/// list-inbounds：发送 ListInboundsRequest { is_only_tags }。
pub async fn execute_list_inbounds(args: &ListInboundsArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut handler = client.handler_client();

    let req = Request::new(ListInboundsRequest {
        is_only_tags: args.only_tags,
    });
    let resp = handler
        .list_inbounds(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to list inbounds: {e}")))?;

    print_response(&resp.into_inner(), args.api.json);
    Ok(())
}

/// list-outbounds：发送 ListOutboundsRequest {}。
pub async fn execute_list_outbounds(args: &ListOutboundsArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut handler = client.handler_client();

    let req = Request::new(ListOutboundsRequest {});
    let resp = handler
        .list_outbounds(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to list outbounds: {e}")))?;

    print_response(&resp.into_inner(), args.api.json);
    Ok(())
}

/// list-rules：发送 ListRuleRequest {}。
pub async fn execute_list_rules(args: &ListRulesArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut routing = client.routing_client();

    let req = Request::new(ListRuleRequest {});
    let resp = routing
        .list_rule(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to list rules: {e}")))?;

    print_response(&resp.into_inner(), args.api.json);
    Ok(())
}

/// sys-stats：发送 SysStatsRequest {}。
pub async fn execute_sys_stats(args: &SysStatsArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut stats = client.stats_client();

    let req = Request::new(SysStatsRequest {});
    let resp = stats
        .get_sys_stats(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to get sys stats: {e}")))?;

    print_response(&resp.into_inner(), args.api.json);
    Ok(())
}

/// restart-logger：发送 RestartLoggerRequest {} 到 LoggerService。
pub async fn execute_restart_logger(args: &RestartLoggerArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut logger = client.logger_client();

    let req = Request::new(RestartLoggerRequest {});
    logger
        .restart_logger(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to restart logger: {e}")))?;

    println!("logger restarted");
    Ok(())
}

/// add-user：循环配置文件 → 提取 inbound 用户 → AlterInbound(AddUserOperation)。
///
/// 对应 Go `inbound_user_add.go::executeAddInboundUsers` + `extractInboundUsers`：
/// 配置文件为标准 xray config JSON，每个 inbound 的 `settings.clients` (vmess) /
/// `settings.clients` (vless/trojan) / `settings.users` (ss) 作为用户来源。
pub async fn execute_add_user(args: &AddUserArgs) -> Result<(), CliError> {
    let data = load_config(&args.config)?;
    let inbounds = build_inbound_configs(&data)?;

    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut handler = client.handler_client();

    let mut success = 0;
    for ib in &inbounds {
        let tag = ib.tag.clone();
        if tag.is_empty() {
            continue;
        }
        let users = extract_users_from_inbound(ib);
        if users.is_empty() {
            continue;
        }
        for user in users {
            if user.email.is_empty() {
                continue;
            }
            let op = AddUserOperation { user: Some(user) };
            let typed = TypedMessage {
                r#type: "xray.app.proxyman.command.AddUserOperation".to_string(),
                value: prost::Message::encode_to_vec(&op),
            };
            let req = Request::new(AlterInboundRequest {
                tag: tag.clone(),
                operation: Some(typed),
            });
            match handler.alter_inbound(req).await {
                Ok(_) => {
                    println!("add user: ok");
                    success += 1;
                }
                Err(e) => {
                    println!("add user error: {e}");
                }
            }
        }
    }
    println!("Added {success} user(s) in total.");
    Ok(())
}

/// remove-user：对每个 email 调用 AlterInbound(RemoveUserOperation { email })。
pub async fn execute_remove_user(args: &RemoveUserArgs) -> Result<(), CliError> {
    if args.tag.is_empty() {
        return Err(CliError::InvalidArgument("inbound tag not specified".into()));
    }

    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut handler = client.handler_client();

    let mut success = 0;
    for email in &args.emails {
        println!("remove user: {email}");
        let op = RemoveUserOperation { email: email.clone() };
        let typed = TypedMessage {
            r#type: "xray.app.proxyman.command.RemoveUserOperation".to_string(),
            value: prost::Message::encode_to_vec(&op),
        };
        let req = Request::new(AlterInboundRequest {
            tag: args.tag.clone(),
            operation: Some(typed),
        });
        match handler.alter_inbound(req).await {
            Ok(_) => success += 1,
            Err(e) => println!("remove user error: {e}"),
        }
    }
    println!("Removed {success} user(s) in total.");
    Ok(())
}

/// inbound-user：发送 GetInboundUserRequest { tag, email }。
pub async fn execute_inbound_user(args: &InboundUserArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut handler = client.handler_client();

    let req = Request::new(GetInboundUserRequest {
        tag: args.tag.clone(),
        email: args.email.clone(),
    });
    let resp = handler
        .get_inbound_users(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to get inbound user: {e}")))?;

    print_response(&resp.into_inner(), args.api.json);
    Ok(())
}

/// inbound-user-count：发送 GetInboundUserRequest { tag }（email 留空）。
pub async fn execute_inbound_user_count(args: &InboundUserCountArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut handler = client.handler_client();

    let req = Request::new(GetInboundUserRequest {
        tag: args.tag.clone(),
        email: String::new(),
    });
    let resp = handler
        .get_inbound_users_count(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to get inbound user count: {e}")))?;

    print_response(&resp.into_inner(), args.api.json);
    Ok(())
}

/// balancer-info：发送 GetBalancerInfoRequest { tag }。
pub async fn execute_balancer_info(args: &BalancerInfoArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut routing = client.routing_client();

    let req = Request::new(GetBalancerInfoRequest {
        tag: args.balancer.clone(),
    });
    let resp = routing
        .get_balancer_info(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to get balancer info: {e}")))?;

    print_response(&resp.into_inner(), args.api.json);
    Ok(())
}

/// balancer-override：发送 OverrideBalancerTargetRequest { balancer_tag, target }。
/// `--remove` 模式：target 留空（清空覆盖）。
pub async fn execute_balancer_override(args: &BalancerOverrideArgs) -> Result<(), CliError> {
    if args.balancer.is_empty() {
        return Err(CliError::InvalidArgument("balancer tag not specified".into()));
    }

    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut routing = client.routing_client();

    let target = if args.remove { String::new() } else { args.target.clone() };
    let req = Request::new(OverrideBalancerTargetRequest {
        balancer_tag: args.balancer.clone(),
        target,
    });
    routing
        .override_balancer_target(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to override balancer: {e}")))?;

    Ok(())
}

/// source-ip-block：构造 RoutingConfig（ruleTag + inboundTag + outboundTag + source ips），
/// 若 `--reset` 先 RemoveRule，再 AddRule(append=true)。
pub async fn execute_source_ip_block(args: &SourceIpBlockArgs) -> Result<(), CliError> {
    if args.ips.is_empty() {
        return Err(CliError::InvalidArgument("no IPs provided".into()));
    }

    // 构造与 Go 等价的 RoutingConfig JSON
    let inbound_tag: Vec<String> = args.inbound.iter().cloned().collect();
    let routing_json = serde_json::json!({
        "routing": {
            "rules": [{
                "ruleTag": args.rule_tag,
                "inboundTag": inbound_tag,
                "outboundTag": args.outbound.as_deref().unwrap_or("blocked"),
                "source": args.ips,
            }]
        }
    });

    let config = serde_json::to_vec(&routing_json).unwrap_or_default();
    let typed = TypedMessage {
        r#type: "xray.app.router.RoutingConfig".to_string(),
        value: config,
    };

    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut routing = client.routing_client();

    if args.reset {
        let rm_req = Request::new(RemoveRuleRequest {
            rule_tag: args.rule_tag.clone(),
        });
        let rm_resp = routing
            .remove_rule(rm_req)
            .await
            .map_err(|e| CliError::ApiRequestFailed(format!("failed to remove rule: {e}")))?;
        print_response(&rm_resp.into_inner(), args.api.json);
    }

    let req = Request::new(AddRuleRequest {
        config: Some(typed),
        should_append: true,
    });
    let resp = routing
        .add_rule(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to add rule: {e}")))?;

    print_response(&resp.into_inner(), args.api.json);
    Ok(())
}

/// stats-online：发送 GetStatsRequest { name: "user>>>EMAIL>>>online", reset: false }。
pub async fn execute_stats_online(args: &StatsOnlineArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut stats = client.stats_client();

    let stat_name = format!("user>>>{}>>>online", args.email);
    let req = Request::new(GetStatsRequest {
        name: stat_name,
        reset: false,
    });
    let resp = stats
        .get_stats_online(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to get stats: {e}")))?;

    print_response(&resp.into_inner(), args.api.json);
    Ok(())
}

/// online-ip-list：`--all` 模式 → GetUsersStatsRequest；否则 GetStatsRequest。
pub async fn execute_online_ip_list(args: &OnlineIpListArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut stats = client.stats_client();

    if args.all {
        if args.email.is_some() {
            return Err(CliError::InvalidArgument(
                "-all and -email are mutually exclusive".into(),
            ));
        }
        let req = Request::new(GetUsersStatsRequest {
            include_traffic: args.include_traffic,
            reset: args.reset,
        });
        let resp = stats
            .get_users_stats(req)
            .await
            .map_err(|e| CliError::ApiRequestFailed(format!("failed to get users stats: {e}")))?;
        print_response(&resp.into_inner(), args.api.json);
    } else {
        let email = args
            .email
            .as_deref()
            .ok_or_else(|| CliError::InvalidArgument("either -all or -email required".into()))?;
        let stat_name = format!("user>>>{email}>>>online");
        let req = Request::new(GetStatsRequest {
            name: stat_name,
            reset: false,
        });
        let resp = stats
            .get_stats_online_ip_list(req)
            .await
            .map_err(|e| {
                CliError::ApiRequestFailed(format!("failed to get online ip list: {e}"))
            })?;
        print_response(&resp.into_inner(), args.api.json);
    }
    Ok(())
}

/// online-users：发送 GetAllOnlineUsersRequest {}。
pub async fn execute_online_users(args: &OnlineUsersArgs) -> Result<(), CliError> {
    let client = ApiClient::connect(&args.api.server, args.api.timeout).await?;
    let mut stats = client.stats_client();

    let req = Request::new(GetAllOnlineUsersRequest {});
    let resp = stats
        .get_all_online_users(req)
        .await
        .map_err(|e| CliError::ApiRequestFailed(format!("failed to get online users: {e}")))?;

    print_response(&resp.into_inner(), args.api.json);
    Ok(())
}

// ---------------------------------------------------------------------------
// add-user 辅助：从 JSON 配置提取 (tag, Vec<User>)。
// ---------------------------------------------------------------------------

/// 从标准 xray config JSON 提取每个 inbound 的用户列表。
///
/// 对应 Go `extractInboundUsers` + 各协议的 `Build()`：支持 vmess / vless / trojan / ss /
/// ss2022。每个用户构造 proto `User { level, email, account: TypedMessage }`。
fn extract_users_from_inbound(ib: &InboundHandlerConfig) -> Vec<xray_proto::xray::common::protocol::User> {
    let Some(proxy) = &ib.proxy_settings else { return Vec::new() };
    // proxy.value 是 settings JSON 编码字节；根据 protocol 字段决定字段路径。
    let settings: serde_json::Value = match serde_json::from_slice(&proxy.value) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    // vmess/vless/trojan: settings.clients[] = { id, email, level }
    // ss/ss2022:        settings.users[]   = { email, level, password, method?, cipher? }
    let candidates: &[(&str, &str)] = &[
        ("vmess", "clients"),
        ("vless", "clients"),
        ("trojan", "clients"),
        ("shadowsocks", "users"),
        ("shadowsocks_2022", "users"),
    ];
    let mut users = Vec::new();
    for (proto, field) in candidates {
        if !proxy.r#type.contains(proto) {
            continue;
        }
        let Some(arr) = settings.get(*field).and_then(|v| v.as_array()) else {
            continue;
        };
        for entry in arr {
            let email = entry
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let level = entry
                .get("level")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let account_json = serde_json::to_vec(entry).unwrap_or_default();
            let account = TypedMessage {
                r#type: format!("xray.proxy.{proto}.Account"),
                value: account_json,
            };
            users.push(xray_proto::xray::common::protocol::User {
                level,
                email,
                account: Some(account),
            });
        }
    }
    users
}

/// 单元测试：验证协议字段路径与 User 构造。
#[cfg(test)]
mod tests {
    use super::*;

    fn inbound_with_settings(proto: &str, settings_json: serde_json::Value) -> InboundHandlerConfig {
        let value = serde_json::to_vec(&settings_json).unwrap();
        InboundHandlerConfig {
            tag: "vless-in".into(),
            receiver_settings: None,
            proxy_settings: Some(TypedMessage {
                r#type: format!("xray.proxy.{proto}.Config"),
                value,
            }),
        }
    }

    #[test]
    fn extract_vless_users_builds_user_with_account() {
        let ib = inbound_with_settings(
            "vless",
            serde_json::json!({
                "clients": [
                    {"id": "uuid-1", "email": "a@x", "level": 1},
                    {"id": "uuid-2", "email": "b@x"}
                ]
            }),
        );
        let users = extract_users_from_inbound(&ib);
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].email, "a@x");
        assert_eq!(users[0].level, 1);
        assert!(users[0].account.is_some());
        let acc = users[0].account.as_ref().unwrap();
        assert!(acc.r#type.contains("vless"));
    }

    #[test]
    fn extract_vmess_users_uses_clients_field() {
        let ib = inbound_with_settings(
            "vmess",
            serde_json::json!({
                "clients": [{"id": "u", "email": "v@x", "level": 0}]
            }),
        );
        let users = extract_users_from_inbound(&ib);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].email, "v@x");
    }

    #[test]
    fn extract_ss_users_uses_users_field() {
        let ib = inbound_with_settings(
            "shadowsocks",
            serde_json::json!({
                "users": [{"email": "ss@x", "password": "p", "method": "aes-256-gcm", "level": 0}]
            }),
        );
        let users = extract_users_from_inbound(&ib);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].email, "ss@x");
    }

    #[test]
    fn extract_unknown_proto_returns_empty() {
        let ib = inbound_with_settings("socks", serde_json::json!({"foo": "bar"}));
        assert!(extract_users_from_inbound(&ib).is_empty());
    }

    #[test]
    fn extract_missing_proxy_settings_returns_empty() {
        let ib = InboundHandlerConfig {
            tag: "x".into(),
            receiver_settings: None,
            proxy_settings: None,
        };
        assert!(extract_users_from_inbound(&ib).is_empty());
    }

    #[test]
    fn extract_invalid_json_returns_empty() {
        let ib = InboundHandlerConfig {
            tag: "x".into(),
            receiver_settings: None,
            proxy_settings: Some(TypedMessage {
                r#type: "xray.proxy.vmess.Config".into(),
                value: vec![0xff, 0xfe],
            }),
        };
        assert!(extract_users_from_inbound(&ib).is_empty());
    }
}
