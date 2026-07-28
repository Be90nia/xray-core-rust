//! # API 命令 execute 函数
//!
//! 通过 gRPC 调用 commander API。8 个核心命令已接通真实 RPC，
//! 其余命令仍返回 [`CliError::Unimplemented`]。

use std::io::Read;

use tonic::Request;

use xray_proto::xray::app::proxyman::command::{
    AddInboundRequest, AddOutboundRequest, RemoveInboundRequest, RemoveOutboundRequest,
};
use xray_proto::xray::app::router::command::{AddRuleRequest, RemoveRuleRequest};
use xray_proto::xray::app::stats::command::{GetStatsRequest, QueryStatsRequest};
use xray_proto::xray::common::serial::TypedMessage;
use xray_proto::xray::core::{InboundHandlerConfig, OutboundHandlerConfig};

use crate::commands::api_client::ApiClient;
use crate::error::CliError;

use super::api_args::*;

/// 生成返回 Unimplemented 的函数体。
macro_rules! api_stub {
    ($args:expr, $what:expr) => {
        {
            let _ = &$args;
            Err(CliError::Unimplemented { what: $what })
        }
    };
}

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
// 仍为 stub 的命令（待后续切片接通）
// ---------------------------------------------------------------------------

/// list-inbounds execute。
pub async fn execute_list_inbounds(args: &ListInboundsArgs) -> Result<(), CliError> {
    api_stub!(args.only_tags, "api list-inbounds: gRPC client not yet wired")
}

/// list-outbounds execute。
pub async fn execute_list_outbounds(args: &ListOutboundsArgs) -> Result<(), CliError> {
    api_stub!(args.only_tags, "api list-outbounds: gRPC client not yet wired")
}

/// list-rules execute。
pub async fn execute_list_rules(args: &ListRulesArgs) -> Result<(), CliError> {
    api_stub!(args.api.server, "api list-rules: gRPC client not yet wired")
}

/// sys-stats execute。
pub async fn execute_sys_stats(args: &SysStatsArgs) -> Result<(), CliError> {
    api_stub!(args.api.server, "api sys-stats: gRPC client not yet wired")
}

/// restart-logger execute。
pub async fn execute_restart_logger(args: &RestartLoggerArgs) -> Result<(), CliError> {
    api_stub!(args.api.server, "api restart-logger: gRPC client not yet wired")
}

/// add-user execute。
pub async fn execute_add_user(args: &AddUserArgs) -> Result<(), CliError> {
    api_stub!(args.config, "api add-user: gRPC client not yet wired")
}

/// remove-user execute。
pub async fn execute_remove_user(args: &RemoveUserArgs) -> Result<(), CliError> {
    api_stub!(args.emails, "api remove-user: gRPC client not yet wired")
}

/// inbound-user execute。
pub async fn execute_inbound_user(args: &InboundUserArgs) -> Result<(), CliError> {
    api_stub!(args.email, "api inbound-user: gRPC client not yet wired")
}

/// inbound-user-count execute。
pub async fn execute_inbound_user_count(args: &InboundUserCountArgs) -> Result<(), CliError> {
    api_stub!(args.tag, "api inbound-user-count: gRPC client not yet wired")
}

/// balancer-info execute。
pub async fn execute_balancer_info(args: &BalancerInfoArgs) -> Result<(), CliError> {
    api_stub!(args.balancer, "api balancer-info: gRPC client not yet wired")
}

/// balancer-override execute。
pub async fn execute_balancer_override(args: &BalancerOverrideArgs) -> Result<(), CliError> {
    api_stub!(args.remove, "api balancer-override: gRPC client not yet wired")
}

/// source-ip-block execute。
pub async fn execute_source_ip_block(args: &SourceIpBlockArgs) -> Result<(), CliError> {
    api_stub!(args.ips, "api source-ip-block: gRPC client not yet wired")
}

/// stats-online execute。
pub async fn execute_stats_online(args: &StatsOnlineArgs) -> Result<(), CliError> {
    api_stub!(args.email, "api stats-online: gRPC client not yet wired")
}

/// online-ip-list execute。
pub async fn execute_online_ip_list(args: &OnlineIpListArgs) -> Result<(), CliError> {
    api_stub!(args.all, "api online-ip-list: gRPC client not yet wired")
}

/// online-users execute。
pub async fn execute_online_users(args: &OnlineUsersArgs) -> Result<(), CliError> {
    api_stub!(args.api.server, "api online-users: gRPC client not yet wired")
}
