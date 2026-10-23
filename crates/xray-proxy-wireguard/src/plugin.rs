//! WireGuard 协议插件（P2 批次·重栈收尾档，统一迁移契约模板 A1–A12）。
//!
//! 五层映射：
//! - **L1**：[`WireguardPlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 [`PluginContext`] 取——build 期 `ctx.section()` 读 per-plugin 段（缺段
//!   fail-fast，坑约束 7 装配半边）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep/Instant）。
//! - **L4**：`assert_plugin_contract!(WireguardPlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 / 私钥缺失 / 密钥非 hex/base64 / reserved 非 3 字节 / port u16 溢出 →
//!   build `Err` → 整链 fail-visible（tests/plugin_contract.rs 装配负向）。
//!
//! wire 零改动（WG-TUN-FROZEN）：`wireguard.rs` / `tunnel.rs` / `netstack.rs` /
//! `driver.rs` / `peer.rs` / `users.rs` / `dispatcher.rs` / `outbound.rs` /
//! `inbound.rs` —— boringtun + smoltcp 重栈数据面一行不动；入站行为仍走
//! [`WireguardInboundHandler`]（既有 `InboundHandler` 实现原样复用，插件只负责
//! 配置注入与构建，构建接缝 = [`WireguardInboundHandler::new`]）。
//! `integration_wireguard_dataplane` 是红线级回归（本单验收必跑）。
//!
//! udf 判定（A7，非通用件）：WG 加解密与用户态网络栈装配是协议方向件——按
//! CLAUDE.md §3.5.3「带领域方向的件不进 udf-frame」，留主仓最近消费方；
//! 无提炼候选。

use std::sync::{Arc, OnceLock};

use xray_app_dispatcher::DispatchHandler;
use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContext, PluginContract, PluginDep, PluginError,
};

use crate::{
    config::{DeviceConfig, PeerConfig},
    inbound::WireguardInboundHandler,
};

/// 通用条款适用子集（wireguard 12 条全适用：peer 公钥/mac 认证失败 → [`WgError`]
/// 分类 → 1；WG Noise 握手存在（boringtun 内聚）→ 2 适用，运行时 deadline 接线
/// 属实例面（数据面冻结范围）随 P3 收口；netstack 会话 conn_id → 3；xray-buf
/// io 面 → 4；driver/accept/relay task 托管 → 5；close = join abort → 6；build
/// 段路由 → 7；[`WgError`] 分类 + panic 不逃逸 IO 线程 → 8；netstack 队列有界
/// （`WG_UDP_QUEUE_CAP` 等）→ 9；tracing → 10；私钥/PSK 掩码 → 11；热路径
/// 冻结 → 12）。
static WG_CLAUSES: &[ClauseId] = &[
    ClauseId::AuthErrorClassified,
    ClauseId::HandshakeDeadline,
    ClauseId::ConnIdPresent,
    ClauseId::PoolDiscipline,
    ClauseId::SpawnManaged,
    ClauseId::StopRegistered,
    ClauseId::ConfigSectionOnly,
    ClauseId::ErrorClassifiedNoPanicEscape,
    ClauseId::BoundedResources,
    ClauseId::LogDiscipline,
    ClauseId::SecretMasking,
    ClauseId::HotPathFreeze,
];

/// 协议专属条款（差异表 §2.2 第 14 行 + 本单派单契约：数据面冻结红线）。
static WG_EXTRA: &[(&str, &str)] = &[(
    "WG-TUN-FROZEN",
    "WG 数据面（boringtun+smoltcp 重栈）一行不改；integration_wireguard_dataplane 是红线级回归",
)];

static WG_CONTRACT: PluginContract =
    PluginContract { clauses: WG_CLAUSES, extra: WG_EXTRA, not_applicable: &[] };

static WG_LIFECYCLE: WireguardLifecycle = WireguardLifecycle;

/// build 产物：设备配置（同规 xray-core `parse_wireguard_config`）+ 入站 UDP
/// 监听端口（段级 `port`，缺省 51820）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardBuiltConfig {
    /// WG 设备（服务端形态，`is_client = false`）。
    pub device: DeviceConfig,
    /// 入站 UDP 监听端口。
    pub listen_port: u16,
}

/// WireGuard 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`inbounds[]/outbounds[]` 内
/// `protocol == "wireguard"` 的元素）解析 `settings` + 段级 `port` →
/// [`WireguardBuiltConfig`] 并持有；入站 handler 经
/// [`inbound_handler`](WireguardPlugin::inbound_handler) 由插件产出（tag 与
/// dispatcher handler 属实例注册期信息，不在 build 期定）。
#[derive(Debug, Default)]
pub struct WireguardPlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）。
    config: OnceLock<WireguardBuiltConfig>,
}

impl WireguardPlugin {
    /// build 产物观察面；build 前调用 → `Err`（fail-visible）。
    pub fn built_config(&self) -> Result<&WireguardBuiltConfig, PluginError> {
        self.config.get().ok_or_else(|| {
            PluginError::Other("wireguard plugin not built yet (build must run first)".into())
        })
    }

    /// 插件产出：入站 handler（`InboundHandler` 实现与行为不变，
    /// [`WireguardInboundHandler::new`] 即构建接缝——inbound.rs 零 diff）。
    pub async fn inbound_handler(
        &self,
        tag: &str,
        dispatch: Arc<dyn DispatchHandler>,
    ) -> Result<WireguardInboundHandler, PluginError> {
        let cfg = self.built_config()?;
        WireguardInboundHandler::new(tag, &cfg.device, cfg.listen_port, dispatch)
            .await
            .map_err(|e| PluginError::Other(Box::new(e)))
    }
}

impl Plugin for WireguardPlugin {
    fn name(&self) -> &'static str {
        "wireguard"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &WG_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &WG_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let config = parse_wireguard_section(ctx.section()?)?;
        self.config.set(config).map_err(|_| {
            PluginError::Other("wireguard plugin built twice (assembly bug)".into())
        })?;
        Ok(())
    }
}

/// WireGuard 生命周期三相：插件级无在途异步任务 / 无外部资源，三相直通。
/// 连接级 driver task（WG 协议 pump + netstack poll + accept loop）的托管
/// （坑约束 5/6 运行时半边）属 [`WireguardInboundHandler`] 实例面（既有行为，
/// close = join abort；FxScope/ShutdownCoordinator 接线随 P3 入口收口统一迁移）。
/// 数据面 pump/netstack 本体在 WG-TUN-FROZEN 冻结范围内，禁在此层包装。
pub struct WireguardLifecycle;

impl Lifecycle for WireguardLifecycle {
    fn init(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        Ok(())
    }

    fn start(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        Ok(())
    }

    fn stop(&self) -> Result<(), PluginError> {
        Ok(())
    }
}

/// per-plugin 段 → [`WireguardBuiltConfig`]。
///
/// 同规 xray-core `outbound.rs::parse_wireguard_config`（权威生产解析）+
/// `inbound.rs::parse_wireguard_inbound_config`（段级 `port`：缺省 51820，
/// u16 溢出显式拒绝禁饱和）。与 xray-core 解析面的收敛属 P3 入口收口，此处
/// 不回头改 core。
fn parse_wireguard_section(
    section: &serde_json::Value,
) -> Result<WireguardBuiltConfig, PluginError> {
    let settings = section.get("settings").unwrap_or(section);
    let device = parse_device_settings(settings)
        .map_err(|e| PluginError::Other(format!("wireguard: {e}").into()))?;
    let port = section.get("port").and_then(|x| x.as_u64()).unwrap_or(51820);
    let listen_port = u16::try_from(port)
        .map_err(|_| PluginError::Other("wireguard: inbound port out of u16 range".into()))?;
    Ok(WireguardBuiltConfig { device, listen_port })
}

/// settings JSON → [`DeviceConfig`]。逐字段同规 xray-core
/// `parse_wireguard_config`（Go `infra/conf/wireguard.go:17-68`）；`numWorkers`/
/// `noKernelTun`/`users` 不在 JSON settings 面，保持 proto 缺省（core 解析
/// 同构 `..Default::default()`，票 o7ns D2）。
fn parse_device_settings(v: &serde_json::Value) -> std::result::Result<DeviceConfig, String> {
    let secret_key = wg_get(v, "secretKey", "secret_key")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing secretKey".to_string())?;
    let secret_key = parse_wireguard_key(secret_key)?;
    let mut peers = Vec::new();
    if let Some(arr) = v.get("peers").and_then(|x| x.as_array()) {
        for p in arr {
            let public_key = wg_get(p, "publicKey", "public_key")
                .and_then(|x| x.as_str())
                .ok_or_else(|| "missing peer publicKey".to_string())?;
            let public_key = parse_wireguard_key(public_key)?;
            let endpoint = p
                .get("endpoint")
                .and_then(|x| x.as_str())
                .ok_or_else(|| "missing peer endpoint".to_string())?;
            // Go wireguard.go:39-44：空 PreSharedKey → 无 PSK。
            let pre_shared_key =
                match wg_get(p, "preSharedKey", "pre_shared_key").and_then(|x| x.as_str()) {
                    Some(s) if !s.is_empty() => parse_wireguard_key(s)?,
                    _ => String::new(),
                };
            // Go wireguard.go:47-49：KeepAlive(uint32) 非零 → 十进制字符串承载
            // （票 o7ns D1 string 语义）；0/缺省 → 空串=禁用。
            let keep_alive = wg_get(p, "keepAlive", "keep_alive")
                .and_then(|x| x.as_u64())
                .map(|n| u32::try_from(n).map_err(|_| "keepAlive out of u32 range".to_string()))
                .transpose()?
                .filter(|n| *n != 0)
                .map_or_else(String::new, |n| n.to_string());
            // Go wireguard.go:50-54 AllowedIPs；字段缺失 → 全路由双栈
            // （bd 7v0k①）；显式空数组尊重为空。
            let allowed_ips =
                match wg_get(p, "allowedIPs", "allowed_ips").and_then(|x| x.as_array()) {
                    Some(a) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
                    None => vec!["0.0.0.0/0".to_string(), "::0/0".to_string()],
                };
            // Go wireguard.go:24-25 per-user Level/Email（server 模式 users 载荷）。
            let level = wg_get(p, "level", "level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let email =
                wg_get(p, "email", "email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            peers.push(PeerConfig {
                public_key,
                endpoint: endpoint.to_string(),
                pre_shared_key,
                keep_alive,
                allowed_ips,
                level,
                email,
            });
        }
    }
    // Go wireguard.go:75-79：address 缺省 → bogon 双栈（bd 7v0k①）。
    let endpoint = v
        .get("address")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_else(|| vec!["10.0.0.1".to_string(), "fd59:7153:2388:b5fd::1".to_string()]);
    // Go wireguard.go:106-110：MTU 0 → 消费侧 effective_mtu() 回落 1420。
    let mtu = v
        .get("mtu")
        .and_then(|x| x.as_i64())
        .map(|n| i32::try_from(n).map_err(|_| "mtu out of i32 range".to_string()))
        .transpose()?
        .unwrap_or(0);
    // Go wireguard.go:112-115："reserved" 应为空或恰好 3 字节。
    let reserved = v
        .get("reserved")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .map(|x| {
                    x.as_u64()
                        .and_then(|n| u8::try_from(n).ok())
                        .ok_or_else(|| "reserved must be a byte array".to_string())
                })
                .collect::<std::result::Result<Vec<u8>, String>>()
        })
        .transpose()?
        .unwrap_or_default();
    if !reserved.is_empty() && reserved.len() != 3 {
        return Err(r#""reserved" should be empty or 3 bytes"#.to_string());
    }
    // Go efc9e6da 删除 domainStrategy：存量配置警告后忽略（PM 拍板保翻先例）。
    if let Some(s) = wg_get(v, "domainStrategy", "domain_strategy").and_then(|x| x.as_str()) {
        if !s.is_empty() {
            tracing::warn!(
                "wireguard plugin: domainStrategy is deprecated and ignored (removed upstream, \
                 efc9e6da); domain targets resolve via tunnel DNS"
            );
        }
    }
    // Go c7e569b0：remoteDNS（隧道内 DNS 服务器列表；["local"] 已废弃回落默认
    // 隧道 DNS，语义在消费侧）。
    let dns = wg_get(v, "remoteDNS", "remote_dns")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<String>>())
        .unwrap_or_default();
    Ok(DeviceConfig { secret_key, peers, endpoint, mtu, reserved, dns, ..Default::default() })
}

/// camelCase 主键（Go infra/conf wireguard.go:17-68 JSON tag）缺失时读
/// snake_case 别名（同规 xray-core `wg_get`）。
fn wg_get<'a>(v: &'a serde_json::Value, camel: &str, snake: &str) -> Option<&'a serde_json::Value> {
    v.get(camel).or_else(|| v.get(snake))
}

/// Go infra/conf/wireguard.go:148-174 `ParseWireGuardKey`：64 字符 hex 原样
/// 通过；否则按 base64（含 `+`/`/` 用标准表，否则 URL 表，容忍单个尾部 `=`）
/// 解码为小写 hex（同规 xray-core `parse_wireguard_key`，bd ttni）。
fn parse_wireguard_key(s: &str) -> std::result::Result<String, String> {
    use base64::Engine as _;
    if s.is_empty() {
        return Err("key must not be empty".to_string());
    }
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(s.to_string());
    }
    let trimmed = s.strip_suffix('=').unwrap_or(s);
    let decoded = if trimmed.contains('+') || trimmed.contains('/') {
        base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed)
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed)
    }
    .map_err(|e| format!("failed to deserialize key: {e}"))?;
    Ok(decoded.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn hex_key(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    #[test]
    fn section_defaults_match_core() {
        let cfg = parse_wireguard_section(&json!({ "settings": { "secretKey": hex_key(0x11) } }))
            .expect("minimal server section");
        assert_eq!(cfg.listen_port, 51820, "port 缺省 51820（core inbound 同规）");
        assert!(cfg.device.peers.is_empty(), "peers 缺失 → 空（bd 7v0k③ 允许空启动）");
        assert_eq!(
            cfg.device.endpoint,
            vec!["10.0.0.1".to_string(), "fd59:7153:2388:b5fd::1".to_string()],
            "address 缺省 bogon 双栈"
        );
        assert_eq!(cfg.device.mtu, 0, "MTU 0 → 消费侧回落 1420");
        assert_eq!(cfg.device.effective_mtu(), 1420);
        assert!(cfg.device.dns.is_empty() && !cfg.device.is_client);
    }

    #[test]
    fn section_base64_keys_normalize_to_hex() {
        use base64::Engine as _;
        let secret = base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]);
        let pub_key = base64::engine::general_purpose::STANDARD.encode([0x22u8; 32]);
        let cfg = parse_wireguard_section(&json!({
            "settings": {
                "secretKey": secret,
                "peers": [{ "publicKey": pub_key, "endpoint": "203.0.113.7:51820" }]
            }
        }))
        .expect("base64 keys");
        assert_eq!(cfg.device.secret_key, "11".repeat(32), "base64 secret 归一为小写 hex");
        assert_eq!(cfg.device.peers[0].public_key, "22".repeat(32));
        assert_eq!(cfg.device.peers[0].pre_shared_key, "", "PSK 缺省 → 空串");
        assert_eq!(
            cfg.device.peers[0].allowed_ips,
            vec!["0.0.0.0/0".to_string(), "::0/0".to_string()],
            "allowedIPs 字段缺失 → 全路由双栈"
        );
    }

    #[test]
    fn section_keepalive_and_list_constraints() {
        let cfg = parse_wireguard_section(&json!({
            "settings": {
                "secretKey": hex_key(0x11),
                "peers": [{
                    "publicKey": hex_key(0x22),
                    "endpoint": "203.0.113.7:51820",
                    "keepAlive": 25,
                    "allowedIPs": ["10.0.0.0/8"],
                    "preSharedKey": hex_key(0x33),
                    "email": "u1@example.com",
                    "level": 2
                }],
                "reserved": [2, 5, 1]
            },
            "port": 18443
        }))
        .expect("full section");
        let peer = &cfg.device.peers[0];
        assert_eq!(peer.keep_alive, "25", "KeepAlive → 十进制字符串（票 o7ns D1）");
        assert_eq!(peer.allowed_ips, vec!["10.0.0.0/8".to_string()], "显式列表尊重");
        assert_eq!(peer.pre_shared_key, "33".repeat(32));
        assert_eq!((peer.level, peer.email.as_str()), (2, "u1@example.com"));
        assert_eq!(cfg.device.reserved, vec![2, 5, 1]);
        assert_eq!(cfg.listen_port, 18443, "段级 port 显式");
    }

    #[test]
    fn section_negatives_fail_visible() {
        let err =
            parse_wireguard_section(&json!({ "settings": {} })).expect_err("missing secretKey");
        assert!(err.to_string().contains("secretKey"), "{err}");

        let err = parse_wireguard_section(&json!({
            "settings": { "secretKey": hex_key(0x11), "reserved": [1, 2] }
        }))
        .expect_err("reserved 非 3 字节");
        assert!(err.to_string().contains("reserved"), "{err}");

        let err = parse_wireguard_section(&json!({
            "settings": { "secretKey": hex_key(0x11) }, "port": 70000
        }))
        .expect_err("port u16 溢出");
        assert!(err.to_string().contains("u16"), "{err}");

        let err = parse_wireguard_section(&json!({
            "settings": { "secretKey": "not a key!!" }
        }))
        .expect_err("密钥非 hex/base64");
        assert!(err.to_string().contains("key"), "{err}");
    }
}
