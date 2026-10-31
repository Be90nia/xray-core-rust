//! v26 反向代理装配（bd nip4p）：VLESS Reverse Proxy 的 bridge/portal 编排接线。
//!
//! Go v26 已移除 legacy `reverse` app 配置（`infra/conf/xray.go` 对顶层
//! `reverse` 走 `PrintRemovedFeatureError`），唯一的反向形态 = VLESS Reverse
//! Proxy，两侧 tag 都来自 VLESS settings 的 `reverse.tag`：
//!
//! - **bridge 侧** = 出站 user 的 `reverse.tag`（`proxy/vless/outbound/outbound.go:98-127`： vless
//!   出站自建 `Reverse`，2s monitor 经路由拨 portal 域名 `v1.rvs.cool`）；
//! - **portal 侧** = 入站 user 的 `reverse.tag`（`proxy/vless/inbound/inbound.go:191-215`：
//!   `GetReverse` 按 tag 把 portal handler 登记进出站表）。
//!
//! 编排件由 `xray-app-reverse` 提供（[`RuntimeBridge`] = monitor + worker 池，
//! [`RuntimePortal`] = picker + `PortalOutbound` 注册），本模块只做**装配**：
//! 从 [`BuiltConfig`] 派生 [`ReverseConfig`] → `ReverseFeature` + `set_deps` +
//! `add_feature`，由 `Instance::start` 启动（bridge 先行、portal 随后，与 Go
//! `Reverse.Init` 同序）。缺少 deps 或 portal 注册失败即 `StartFailed`
//! （Go `core.RequireFeatures` 失败同样硬错）。
//!
//! [`RuntimeBridge`]: xray_app_reverse::RuntimeBridge
//! [`RuntimePortal`]: xray_app_reverse::RuntimePortal

use std::{collections::BTreeSet, sync::Arc};

use xray_app_dispatcher::default::{DefaultDispatcher, SimpleOhm};
use xray_app_reverse::{
    BridgeConfig, DefaultDispatcherAdapter, PortalConfig, ReverseConfig, ReverseFeature,
    SimpleOhmRegistrar,
};
use xray_conf::BuiltConfig;

use crate::{CoreFunctionError, instance::Instance};

/// VLESS 出站 settings → bridge tag。
///
/// 读法与 [`crate::outbound::parse_vless_config`] 同源（`vnext[0].users[0].reverse.tag`）：
/// 出站侧反向注册表就由那里建，两处必须同一取法，否则 bridge 拨出去的
/// `command=Rvs` 与监听侧判据会脱节。
#[must_use]
pub(crate) fn vless_outbound_reverse_tags(data: &[u8]) -> Vec<String> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else {
        return Vec::new();
    };
    let user = v
        .get("vnext")
        .and_then(|x| x.as_array())
        .and_then(|a| a.first())
        .and_then(|x| x.get("users"))
        .and_then(|u| u.as_array())
        .and_then(|a| a.first());
    user.and_then(reverse_tag_of).into_iter().collect()
}

/// VLESS 入站 settings → portal tag 列表（去重排序）。
///
/// `clients` 键在场（非 null）即完全覆盖 `users` 别名——与
/// [`crate::inbound::build_vless_validator`] 的取法一致。
#[must_use]
pub(crate) fn vless_inbound_reverse_tags(data: &[u8]) -> Vec<String> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else {
        return Vec::new();
    };
    let clients = v
        .get("clients")
        .filter(|c| !c.is_null())
        .or_else(|| v.get("users"))
        .and_then(|c| c.as_array());
    let Some(clients) = clients else {
        return Vec::new();
    };
    clients.iter().filter_map(reverse_tag_of).collect::<BTreeSet<_>>().into_iter().collect()
}

/// `{"reverse": {"tag": "..."}}` → tag（空 tag 不视为反向）。
fn reverse_tag_of(v: &serde_json::Value) -> Option<String> {
    v.get("reverse")
        .and_then(|r| r.get("tag"))
        .and_then(|t| t.as_str())
        .filter(|t| !t.is_empty())
        .map(String::from)
}

/// 从 [`BuiltConfig`] 派生反向编排配置：出站 reverse.tag → bridge，入站 user
/// reverse.tag → portal。
///
/// domain 恒 `v1.rvs.cool`（`xray_proxy_vless::RVS_DOMAIN`：VLESS Rvs carrier 的
/// 固定目的地，也即 portal 侧 `PortalConfig::new` 的缺省 domain）。**不是**
/// `xray_app_reverse::INTERNAL_DOMAIN`——后者是 mux 内部的控制流目的地
/// （`"reverse"`），配成它会让 carrier 拨号落空（实测：bridge 会去 DNS 解析
/// `reverse`）。
#[must_use]
pub(crate) fn derive_reverse_config(built: &BuiltConfig) -> ReverseConfig {
    let domain = || xray_proxy_vless::RVS_DOMAIN.to_string();
    let bridge_tags: BTreeSet<String> = built
        .outbounds
        .iter()
        .filter(|ob| ob.entry.kind == "vless")
        .flat_map(|ob| vless_outbound_reverse_tags(&ob.entry.data))
        .collect();
    let portal_tags: BTreeSet<String> = built
        .inbounds
        .iter()
        .filter(|ib| ib.entry.kind == "vless")
        .flat_map(|ib| vless_inbound_reverse_tags(&ib.entry.data))
        .collect();
    ReverseConfig {
        bridges: bridge_tags
            .into_iter()
            .map(|tag| BridgeConfig { tag, domain: domain() })
            .collect(),
        portals: portal_tags
            .into_iter()
            .map(|tag| PortalConfig { tag, domain: domain() })
            .collect(),
    }
}

/// 装配反向编排（等同 Go：vless 出站 `Init` 自建 reverse bridge，vless 入站
/// `GetReverse` 登记 portal handler）。
///
/// 无反向 tag → 零动作（不建 feature，不产生任何运行时开销）。
/// 必须在 `Instance::start` 之前调用：portal handler 要在入站开始收 Rvs 之前
/// 登记进出站表（`Instance::start` 先于 `spawn_inbounds`）。
pub(crate) fn install_vless_reverse(
    instance: &mut Instance,
    built: &BuiltConfig,
    ohm: &Arc<SimpleOhm>,
    dispatcher: &Arc<DefaultDispatcher>,
) -> Result<(), CoreFunctionError> {
    let config = derive_reverse_config(built);
    if config.bridges.is_empty() && config.portals.is_empty() {
        return Ok(());
    }
    let bridges = config.bridges.len();
    let portals = config.portals.len();
    let feature = Arc::new(ReverseFeature::new(config));
    // 对应 Go `core.RequireFeatures(routing.Dispatcher, outbound.Manager)`：
    // dispatcher 拨 carrier，ohm 承载 portal outbound handler。
    feature.set_deps(
        Arc::new(DefaultDispatcherAdapter(Arc::clone(dispatcher))),
        Arc::new(SimpleOhmRegistrar(Arc::clone(ohm))),
    );
    instance.add_feature(feature).map_err(|e| {
        CoreFunctionError::InstanceInit(format!("reverse feature registration: {e}"))
    })?;
    tracing::info!(bridges, portals, "reverse (VLESS Reverse Proxy) assembly installed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_reverse_tag_from_vnext_user() {
        let data = serde_json::to_vec(&serde_json::json!({
            "vnext": [{
                "address": "portal.example.com",
                "port": 443,
                "users": [{ "id": "66ad4540-b58c-4ad2-9926-ea63445a9b57",
                            "reverse": { "tag": "rvs-tag" } }],
            }],
        }))
        .unwrap();
        assert_eq!(vless_outbound_reverse_tags(&data), vec!["rvs-tag".to_string()]);
    }

    #[test]
    fn outbound_reverse_absent_yields_empty() {
        let data = br#"{"vnext":[{"address":"a","port":1,"users":[{"id":"x"}]}]}"#;
        assert!(vless_outbound_reverse_tags(data).is_empty());
        // 空 tag 不算反向（Go `reverse.tag` 空 = 未配置）
        let blank =
            br#"{"vnext":[{"address":"a","port":1,"users":[{"id":"x","reverse":{"tag":""}}]}]}"#;
        assert!(vless_outbound_reverse_tags(blank).is_empty());
        assert!(vless_outbound_reverse_tags(b"not json").is_empty());
    }

    #[test]
    fn inbound_reverse_tags_dedup_and_users_alias() {
        let data = serde_json::to_vec(&serde_json::json!({
            "clients": [
                { "id": "a", "reverse": { "tag": "p1" } },
                { "id": "b", "reverse": { "tag": "p1" } },
                { "id": "c", "reverse": { "tag": "p2" } },
                { "id": "d" },
            ],
        }))
        .unwrap();
        assert_eq!(vless_inbound_reverse_tags(&data), vec!["p1".to_string(), "p2".to_string()]);
        let alias = br#"{"users":[{"id":"a","reverse":{"tag":"p3"}}]}"#;
        assert_eq!(vless_inbound_reverse_tags(alias), vec!["p3".to_string()]);
        // clients 为空数组时完全覆盖 users 别名（Go vless.go:46-48）
        let cover = br#"{"clients":[],"users":[{"id":"a","reverse":{"tag":"p4"}}]}"#;
        assert!(vless_inbound_reverse_tags(cover).is_empty());
    }

    #[test]
    fn derive_config_splits_bridge_and_portal_tags() {
        use xray_conf::{BuiltEntry, BuiltInbound, BuiltOutbound};
        let ob_data = br#"{"vnext":[{"address":"a","port":1,"users":[{"id":"x","reverse":{"tag":"bridge1"}}]}]}"#;
        let ib_data = br#"{"clients":[{"id":"y","reverse":{"tag":"portal1"}}]}"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "vless".into(), data: ob_data.to_vec() },
            tag: "rvs-out".into(),
            send_through: None,
            stream_settings_json: None,
            proxy_settings_json: None,
            mux_json: None,
            target_strategy: None,
        });
        built.inbounds.push(BuiltInbound {
            entry: BuiltEntry { kind: "vless".into(), data: ib_data.to_vec() },
            tag: "portal-in".into(),
            port: Some(443),
            listen: None,
            stream_settings_json: None,
            sniffing_json: None,
        });
        // 非 vless 协议不参与派生
        built.outbounds.push(BuiltOutbound {
            entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
            tag: "direct".into(),
            send_through: None,
            stream_settings_json: None,
            proxy_settings_json: None,
            mux_json: None,
            target_strategy: None,
        });
        let cfg = derive_reverse_config(&built);
        assert_eq!(cfg.bridges.len(), 1);
        assert_eq!(cfg.bridges[0].tag, "bridge1");
        assert_eq!(cfg.bridges[0].domain, xray_proxy_vless::RVS_DOMAIN);
        assert_eq!(cfg.portals.len(), 1);
        assert_eq!(cfg.portals[0].tag, "portal1");
    }
}
