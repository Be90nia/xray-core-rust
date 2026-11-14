//! Freedom 配置与规则匹配。
//!
//! 对应 Go `proxy/freedom/freedom.go` + `config.proto`。
//!
//! ## 协议本质
//!
//! Freedom 出站代理直接连接目标地址（不走任何上游代理），是 Xray 的"直连"出口。
//! 配置层支持：
//!
//! - **DomainStrategy**：DNS 解析策略（AS_IS / USE_IP / USE_IP4 / USE_IP6 / USE_IP46 / USE_IP64）
//! - **DestinationOverride**：强制覆盖目标地址（用于透明代理重定向）
//!   - 配置键 `redirect`：Go 键，`"host:port"` 字符串（`infra/conf/freedom.go:23`）
//!   - 兼容键 `destinationOverride`：本仓扩展，Go 不认，仅 `redirect` 缺省时生效
//! - **Fragment**：TCP 分片（绕过 SNI 审查）
//! - **Noise**：填充噪声（绕过流量分析）
//! - **FinalRules**：最终规则（Allow/Block 匹配 network + port + IP 规则：CIDR / `geoip:` / `ext:`
//!   / `ext-ip:`，支持 `!` 反向）
//!
//! 默认规则：`defaultBlockPrivateRule`（阻止 RFC 1918 私有地址 + 保留段）+
//! `defaultBlockAllRule`（阻止所有，用于 vless-reverse）。
//!
//! ## 切片边界（P6-5 切片1）
//!
//! 实现配置层 + FinalRule 逻辑匹配（network + port + IP CIDR）+ 默认 CIDR 常量。
//! IP 匹配通过 `xray_geodata::matcher::ip` 实现：普通 CIDR 走 `HeuristicIPMatcher`，
//! `geoip:` 等资产规则在**构造期**经 `IpRegistry`（`IP_REG`）解析并在 `reload()` 时热更。
//! 默认 `defaultBlockPrivateRule` 使用 [`DEFAULT_BLOCK_PRIVATE_CIDRS`] 构建的
//! 缓存 matcher（[`private_ip_matcher`]）。Handler/Process/dial 见 `handler.rs`。

/// DNS 解析策略。对应 Go `proxy/freedom/config.proto` DomainStrategy。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(i32)]
pub enum DomainStrategy {
    /// AS_IS: 直接拨号，让 OS 解析域名（默认）
    #[default]
    AsIs = 0,
    /// USE_IP: 解析域名到 IP（IPv4 或 IPv6）
    UseIP = 1,
    /// USE_IP4: 解析域名到 IPv4
    UseIPv4 = 2,
    /// USE_IP6: 解析域名到 IPv6
    UseIPv6 = 3,
    /// USE_IP46: 优先 IPv4，回退 IPv6
    UseIPv4v6 = 4,
    /// USE_IP64: 优先 IPv6，回退 IPv4
    UseIPv6v4 = 5,
    /// FORCE_IP: 解析失败即失败（IPv4 或 IPv6）
    ForceIP = 6,
    /// FORCE_IP4: 强制 IPv4，解析失败即失败
    ForceIPv4 = 7,
    /// FORCE_IP6: 强制 IPv6，解析失败即失败
    ForceIPv6 = 8,
    /// FORCE_IP46: 强制 IPv4，回退 IPv6
    ForceIPv4v6 = 9,
    /// FORCE_IP64: 强制 IPv6，回退 IPv4
    ForceIPv6v4 = 10,
}

impl DomainStrategy {
    #[must_use]
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::UseIP,
            2 => Self::UseIPv4,
            3 => Self::UseIPv6,
            4 => Self::UseIPv4v6,
            5 => Self::UseIPv6v4,
            6 => Self::ForceIP,
            7 => Self::ForceIPv4,
            8 => Self::ForceIPv6,
            9 => Self::ForceIPv4v6,
            10 => Self::ForceIPv6v4,
            _ => Self::AsIs,
        }
    }

    /// Go `transport/internet/config.go` strategy 表：`[mode, prefer, fallback]`。
    ///
    /// mode：0=AsIs，1=Use，2=Force；prefer/fallback：0=任意，4=IPv4，6=IPv6。
    #[must_use]
    pub fn strategy_table(self) -> [u8; 3] {
        match self {
            Self::AsIs => [0, 0, 0],
            Self::UseIP => [1, 0, 0],
            Self::UseIPv4 => [1, 4, 0],
            Self::UseIPv6 => [1, 6, 0],
            Self::UseIPv4v6 => [1, 4, 6],
            Self::UseIPv6v4 => [1, 6, 4],
            Self::ForceIP => [2, 0, 0],
            Self::ForceIPv4 => [2, 4, 0],
            Self::ForceIPv6 => [2, 6, 0],
            Self::ForceIPv4v6 => [2, 4, 6],
            Self::ForceIPv6v4 => [2, 6, 4],
        }
    }

    /// 解析失败时是否必须报错（Go `ForceIP()`：`strategy[s][0] == 2`）。
    #[must_use]
    pub fn force_ip(self) -> bool {
        self.strategy_table()[0] == 2
    }

    /// 是否带解析策略（Go `HasStrategy()`：`strategy[s][0] != 0`）。
    #[must_use]
    pub fn has_strategy(self) -> bool {
        self.strategy_table()[0] != 0
    }

    /// 优先 IPv4（Go `PreferIP4()`，config.go:110-116）。
    ///
    /// `prefer == 0`（AsIs/UseIP/ForceIP）→ true：Go 视为"两个家族都可"。
    #[must_use]
    pub fn prefer_ipv4(self) -> bool {
        let p = self.strategy_table()[1];
        p == 4 || p == 0
    }

    /// 优先 IPv6（Go `PreferIP6()`，config.go:114-116）。
    ///
    /// `prefer == 0`（AsIs/UseIP/ForceIP）→ true：Go 视为"两个家族都可"。
    #[must_use]
    pub fn prefer_ipv6(self) -> bool {
        let p = self.strategy_table()[1];
        p == 6 || p == 0
    }

    /// 有回退家族（Go `HasFallback()`）。
    #[must_use]
    pub fn has_fallback(self) -> bool {
        self.strategy_table()[2] != 0
    }

    /// 回退到 IPv4（Go `FallbackIP4()`）。
    #[must_use]
    pub fn fallback_ipv4(self) -> bool {
        self.strategy_table()[2] == 4
    }

    /// 回退到 IPv6（Go `FallbackIP6()`）。
    #[must_use]
    pub fn fallback_ipv6(self) -> bool {
        self.strategy_table()[2] == 6
    }

    /// 是否需要 DNS 解析
    #[must_use]
    pub fn needs_resolution(self) -> bool {
        self.has_strategy()
    }

    /// 解析后是否只接受 IPv4
    #[must_use]
    pub fn ipv4_only(self) -> bool {
        self.prefer_ipv4() && !self.has_fallback()
    }

    /// 解析后是否只接受 IPv6
    #[must_use]
    pub fn ipv6_only(self) -> bool {
        self.prefer_ipv6() && !self.has_fallback()
    }
}

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::{Arc, LazyLock},
};

use xray_common::net::{
    address::Address,
    destination::Destination,
    network::Network,
    port::{MemoryPortList, Port, PortRange},
};
use xray_geodata::matcher::ip::{HeuristicIPMatcher, IP_REG, IPMatcher, IpRegistry};
use xray_proto::xray::common::geodata::ip_rule;

use crate::error::{FreedomError, Result};

/// RuleAction 枚举。对应 proto `RuleAction`。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(i32)]
pub enum RuleAction {
    #[default]
    Allow = 0,
    Block = 1,
}

impl RuleAction {
    #[must_use]
    pub fn from_proto_value(v: i32) -> Self {
        match v {
            1 => Self::Block,
            _ => Self::Allow,
        }
    }

    #[must_use]
    pub fn to_proto_value(self) -> i32 {
        self as i32
    }
}

/// 数值范围。对应 proto `Range`。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Range {
    pub min: u64,
    pub max: u64,
}

/// 目标地址覆盖。对应 proto `DestinationOverride`。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DestinationOverride {
    pub server: Option<xray_proto::xray::common::protocol::ServerEndpoint>,
}

impl DestinationOverride {
    /// 从 `destinationOverride` 键解析（**非 Go 键**，本仓兼容扩展）。
    ///
    /// 形态：`{"server": {"address": "1.2.3.4" | "example.com", "port": 443}}`。
    /// 无 `server` 键返回 `None`。键名取自 proto 字段 `destination_override`；
    /// Go 的 JSON 配置层只有 `redirect` 字符串（`infra/conf/freedom.go:23`），
    /// 不认此键——Go 用户的配置必须走 [`Self::from_redirect`]。
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        let server = v.get("server")?;
        let address = server.get("address").and_then(|a| a.as_str()).map(|s| {
            xray_proto::xray::common::net::IpOrDomain {
                address: Some(address_str_to_ip_or_domain(s)),
            }
        });
        let port = server.get("port").and_then(|p| p.as_u64()).unwrap_or(0) as u32;
        Some(Self {
            server: Some(xray_proto::xray::common::protocol::ServerEndpoint {
                address,
                port,
                user: None,
            }),
        })
    }

    /// Go `redirect` 键（`infra/conf/freedom.go:166-180`）：`"host:port"` 字符串。
    ///
    /// 语义 = Go `net.SplitHostPort` + `xnet.PortFromString`：host 非空则改写地址
    /// （IP 或域名），port 恒改写；host 空（`":443"`）只改写端口。任一解析失败
    /// Go 在 `Build` 期拒启（`invalid redirect address/port`），此处同形报错。
    ///
    /// # Errors
    /// 缺端口 / 裸 IPv6（多冒号）/ 缺 `]` / 非十进制端口 / 端口 > 65535。
    pub fn from_redirect(redirect: &str) -> Result<Self> {
        let (host, port_str) = split_host_port(redirect)
            .map_err(|e| invalid(format!("invalid redirect address: {redirect}: {e}")))?;
        let port = parse_redirect_port(port_str)
            .map_err(|e| invalid(format!("invalid redirect port: {redirect}: {e}")))?;
        let address = if host.is_empty() {
            None
        } else {
            Some(xray_proto::xray::common::net::IpOrDomain {
                address: Some(address_str_to_ip_or_domain(host)),
            })
        };
        Ok(Self {
            server: Some(xray_proto::xray::common::protocol::ServerEndpoint {
                address,
                port,
                user: None,
            }),
        })
    }

    /// freedom settings 解析入口：Go 键 `redirect` 优先，本仓扩展
    /// `destinationOverride` 兜底（Go 只有 `redirect`，故两者并存时取 `redirect`）。
    ///
    /// `redirect` 缺失 / `null` / 空串 = 未配置（Go `len(c.Redirect) > 0`）；
    /// 非字符串形态 Go 解码即失败，此处同样拒启。
    ///
    /// # Errors
    /// `redirect` 非法（见 [`Self::from_redirect`]）或类型不是字符串。
    pub fn from_settings(settings: &serde_json::Value) -> Result<Option<Self>> {
        let extension = || settings.get("destinationOverride").and_then(Self::from_json);
        match settings.get("redirect") {
            None | Some(serde_json::Value::Null) => Ok(extension()),
            Some(serde_json::Value::String(s)) if s.is_empty() => Ok(extension()),
            Some(serde_json::Value::String(s)) => Self::from_redirect(s).map(Some),
            Some(other) => Err(invalid(format!(
                "invalid redirect address: {other}: expected \"host:port\" string"
            ))),
        }
    }
}

/// Go `net.SplitHostPort`：`"host:port"` / `":port"` / `"[::1]:port"`；
/// 缺端口、裸 IPv6（多冒号）、缺 `]` 一律报错（Go 侧即 `Build` 拒启）。
fn split_host_port(s: &str) -> std::result::Result<(&str, &str), &'static str> {
    if let Some(rest) = s.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return Err("missing ']' in address");
        };
        return match tail.strip_prefix(':') {
            Some(port) => Ok((host, port)),
            None => Err("missing port in address"),
        };
    }
    let mut parts = s.rsplitn(2, ':');
    let (Some(port), Some(host)) = (parts.next(), parts.next()) else {
        return Err("missing port in address");
    };
    if host.contains(':') {
        return Err("too many colons in address");
    }
    Ok((host, port))
}

/// Go `xnet.PortFromString`（`common/net/port.go:30-35`）：十进制、无符号、≤ 65535。
fn parse_redirect_port(s: &str) -> std::result::Result<u32, &'static str> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid port range");
    }
    let port = s.parse::<u32>().map_err(|_| "invalid port range")?;
    if port > 65535 {
        return Err("port is not a valid port");
    }
    Ok(port)
}

/// TCP 分片配置。对应 proto `Fragment`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fragment {
    pub packets_from: u64,
    pub packets_to: u64,
    pub length_min: u64,
    pub length_max: u64,
    pub interval_min: u64,
    pub interval_max: u64,
    pub max_split_min: u64,
    pub max_split_max: u64,
}

/// 噪声配置。对应 proto `Noise`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Noise {
    pub length_min: u64,
    pub length_max: u64,
    pub delay_min: u64,
    pub delay_max: u64,
    pub packet: Vec<u8>,
    pub apply_to: String,
}

/// 配置无效（带 Go 对齐文案）。
fn invalid(msg: impl Into<String>) -> FreedomError {
    FreedomError::InvalidConfig(msg.into())
}

/// 方言键的数值直取（历史形态 `lengthMin`/`lengthMax` 等）。
fn dialect(v: &serde_json::Value, k: &str) -> u64 {
    v.get(k).and_then(|x| x.as_u64()).unwrap_or(0)
}

/// Go `ParseRangeString`（infra/conf/common.go:355-390）：`"10"` / `"10-20"` /
/// `"-1919--810"`（负号开头按第二个连字符切分）/ `""`→`(0,0)` / 非法 `None`。
fn parse_range_string(s: &str) -> Option<(i64, i64)> {
    if let Ok(v) = s.parse::<i64>() {
        return Some((v, v));
    }
    if s.is_empty() {
        return Some((0, 0));
    }
    let pair = match s.strip_prefix('-') {
        Some(rest) => rest.split_once('-').map(|(a, b)| (format!("-{a}"), b.to_string())),
        None => s.split_once('-').map(|(a, b)| (a.to_string(), b.to_string())),
    };
    let (left, right) = pair?;
    Some((left.parse().ok()?, right.parse().ok()?))
}

/// Go `Int32Range` 键（infra/conf/common.go:315-332）：`"1-2"` 字符串或纯整数。
///
/// Go 允许负值作哨兵，但 fragment/noises 的用量全为非负——此处硬错，否则负值
/// 会 cast 成巨大 `u64`，分片/噪声静默退化成「一次发完」。
fn json_range(v: &serde_json::Value) -> Result<(u64, u64)> {
    match v {
        serde_json::Value::String(s) => range_from_str(s),
        serde_json::Value::Number(n) => {
            let x = n.as_i64().ok_or_else(|| invalid("Invalid integer range: not an integer"))?;
            non_negative(x, x)
        },
        _ => Err(invalid(
            "Invalid integer range, expected either string of form \"1-2\" or plain integer.",
        )),
    }
}

/// `ParseRangeString` 的字符串形态 + 非负校验。
fn range_from_str(s: &str) -> Result<(u64, u64)> {
    let (from, to) = parse_range_string(s.trim()).ok_or_else(|| {
        invalid(format!(
            "Invalid integer range, expected either string of form \"1-2\" or plain integer: {s}"
        ))
    })?;
    non_negative(from, to)
}

fn non_negative(from: i64, to: i64) -> Result<(u64, u64)> {
    match (u64::try_from(from), u64::try_from(to)) {
        (Ok(a), Ok(b)) => Ok((a, b)),
        _ => Err(invalid("Invalid integer range: negative value")),
    }
}

/// Go `fragment.packets`（freedom.go:93-116）：`"tlshello"`→`(0,1)`、`""`/缺键
/// →`(0,0)`（全包分片）、区间字符串、方言纯整数。
fn packets_range(v: Option<&serde_json::Value>) -> Result<(u64, u64)> {
    match v {
        None => Ok((0, 0)),
        Some(serde_json::Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "tlshello" => Ok((0, 1)),
            "" => Ok((0, 0)),
            other => {
                let (from, to) = range_from_str(other)?;
                if from == 0 {
                    return Err(invalid("PacketsFrom can't be 0"));
                }
                Ok((from, to))
            },
        },
        Some(serde_json::Value::Number(n)) => {
            let x = n
                .as_u64()
                .ok_or_else(|| invalid("Invalid PacketsFrom: expected non-negative integer"))?;
            Ok((x, x))
        },
        Some(_) => Err(invalid("Invalid PacketsFrom: expected string or integer")),
    }
}

impl Fragment {
    /// 解析 freedom `fragment` 子对象（Go `infra/conf/freedom.go:92-142` Build）。
    ///
    /// Go 键形（`packets`/`length`/`interval`/`maxSplit`）为权威；缺 `length`
    /// 时回退本仓历史方言（`lengthMin`/`lengthMax` 数值直给，`interval` 可缺省）。
    /// 两个消费方（xray-core 生产解析与 framework 插件段解析）共用本实现。
    pub fn from_json(v: &serde_json::Value) -> Result<Self> {
        let (packets_from, packets_to) = packets_range(v.get("packets"))?;
        let Some(length) = v.get("length") else {
            let (length_min, length_max) = (dialect(v, "lengthMin"), dialect(v, "lengthMax"));
            if length_min == 0 {
                return Err(invalid("Length can't be empty"));
            }
            return Ok(Self {
                packets_from,
                packets_to,
                length_min,
                length_max,
                interval_min: dialect(v, "intervalMin"),
                interval_max: dialect(v, "intervalMax"),
                max_split_min: dialect(v, "maxSplitMin"),
                max_split_max: dialect(v, "maxSplitMax"),
            });
        };
        let (length_min, length_max) = json_range(length)?;
        if length_min == 0 {
            return Err(invalid("LengthMin can't be 0"));
        }
        let interval = v.get("interval").ok_or_else(|| invalid("Interval can't be empty"))?;
        let (interval_min, interval_max) = json_range(interval)?;
        let (max_split_min, max_split_max) = match v.get("maxSplit") {
            Some(m) => json_range(m)?,
            None => (0, 0),
        };
        Ok(Self {
            packets_from,
            packets_to,
            length_min,
            length_max,
            interval_min,
            interval_max,
            max_split_min,
            max_split_max,
        })
    }
}

impl Noise {
    /// 解析单个 freedom `noises[]` 元素（Go `infra/conf/freedom.go:217-262`
    /// `ParseNoise`）：`type` ∈ {rand,str,hex,base64}，`delay` 为 Int32Range，
    /// `applyTo` ∈ {ip,ipv4,ipv6}（含 ""/"all" → "ip"）。
    ///
    /// 无 `type` 键 = 本仓历史方言：`packet:"rand"` 或给了 `lengthMin/Max` 时按
    /// rand 取长度区间，否则按字面字节；`delay` 可用 `delayMin/delayMax`。
    pub fn from_json(v: &serde_json::Value) -> Result<Self> {
        let ty = v.get("type").and_then(|x| x.as_str()).unwrap_or("").to_ascii_lowercase();
        let packet_raw = v.get("packet").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let (length_min, length_max, packet) = match ty.as_str() {
            "rand" => {
                let (a, b) = range_from_str(&packet_raw)
                    .map_err(|_| invalid(format!("invalid value for rand Length: {packet_raw}")))?;
                if a == 0 {
                    return Err(invalid("rand lengthMin or lengthMax cannot be 0"));
                }
                (a, b, Vec::new())
            },
            "str" => (0, 0, packet_raw.into_bytes()),
            "hex" => (
                0,
                0,
                hex::decode(&packet_raw)
                    .map_err(|e| invalid(format!("Invalid hex string: {e}")))?,
            ),
            "base64" => (0, 0, decode_base64(&packet_raw)?),
            "" => {
                let (a, b) = (dialect(v, "lengthMin"), dialect(v, "lengthMax"));
                if packet_raw == "rand" || a != 0 || b != 0 {
                    (a, b, Vec::new())
                } else {
                    (0, 0, packet_raw.into_bytes())
                }
            },
            other => {
                return Err(invalid(format!(
                    "Invalid packet, only rand/str/hex/base64 are supported: {other}"
                )));
            },
        };
        let (delay_min, delay_max) = match v.get("delay") {
            Some(d) => json_range(d)?,
            None => (dialect(v, "delayMin"), dialect(v, "delayMax")),
        };
        let apply_to = match v
            .get("applyTo")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "ip" | "all" => "ip",
            "ipv4" => "ipv4",
            "ipv6" => "ipv6",
            other => {
                return Err(invalid(format!(
                    "Invalid applyTo, only ip/ipv4/ipv6 are supported: {other}"
                )));
            },
        };
        Ok(Self {
            length_min,
            length_max,
            delay_min,
            delay_max,
            packet,
            apply_to: apply_to.to_string(),
        })
    }
}

/// Go `base64.RawURLEncoding` + `+`→`-`/`/`→`_`/`=` 去除（freedom.go:242-247）。
fn decode_base64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let cleaned = s.replace('+', "-").replace('/', "_").replace('=', "");
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cleaned)
        .map_err(|e| invalid(format!("Invalid base64 string: {e}")))
}

/// 最终规则配置。对应 proto `FinalRuleConfig`。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FinalRuleConfig {
    pub action: RuleAction,
    /// 允许的网络类型（proto repeated enum → `Vec<i32>`）。
    pub networks: Vec<i32>,
    pub port_list: Option<xray_proto::xray::common::net::PortList>,
    /// IP 规则（prost repeated message）：Custom CIDR 或 Geoip（`file:code` 资产引用）。
    pub ip: Vec<xray_proto::xray::common::geodata::IpRule>,
    /// 阻断延时（proto `Range delay`，仅 block 规则有值）。
    pub delay: Option<Range>,
    /// 阻断期日志级别（proto `optional log.Severity`，仅 block 规则有值）。
    pub log_level: Option<i32>,
}

impl FinalRuleConfig {
    /// 从 freedom settings JSON 解析（Go `infra/conf/freedom.go:46-54`
    /// `FreedomFinalRuleConfig` + `Build` :252-320）。
    ///
    /// 形态：`{"action": "block", "network": "tcp,udp", "port": "443,80-90",
    /// "ip": ["10.0.0.0/8", "geoip:cn"], "delay": "30-90" | {"from":30,"to":90},
    /// "logLevel": "warning"}`；`blockDelay` 为弃用别名（优先于 `delay`）。
    ///
    /// `ip` 规则在此处即查资产（Go `ParseIPRules` 的 `checkFile`）：`geoip:` /
    /// `ext:` / `ext-ip:` 的文件缺失或代号不存在 ⇒ 拒启。
    pub fn from_json(v: &serde_json::Value) -> Result<Self> {
        Self::from_json_with_datadir(v, &xray_common::platform::get_asset_dir())
    }

    /// [`FinalRuleConfig::from_json`] 的显式资产目录形态（测试 / 非默认资产目录部署）。
    pub fn from_json_with_datadir(v: &serde_json::Value, datadir: &Path) -> Result<Self> {
        let action = match v
            .get("action")
            .and_then(|a| a.as_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "allow" => RuleAction::Allow,
            "block" => RuleAction::Block,
            other => {
                return Err(crate::error::FreedomError::InvalidConfig(format!(
                    "unknown finalRule action: {other}"
                )));
            },
        };
        let networks = v.get("network").map(json_network_list).unwrap_or_default();
        // bd 5w5z0：port/ip 的非法项必须**硬错**（Go 在解码期 `PortRange.UnmarshalJSON`
        // / `geodata.ParseIPRules` 就报错）。旧实现逐项 `continue`/`filter_map(ok)`
        // 丢弃，丢空后 `port_list=None` / `ip=None` = **匹配所有**——一条笔误
        // （`ip:["not-an-ip"]`、`port:"18500,bad"`）把规则从"精确"翻转成"全阻断"。
        let port_list = match v.get("port") {
            Some(p) if !p.is_null() => Some(json_port_list(p).map_err(|e| {
                crate::error::FreedomError::InvalidConfig(format!("finalRule port: {e}"))
            })?),
            _ => None,
        };
        let ip = match v.get("ip") {
            Some(ip) if !ip.is_null() => json_ip_rules(ip, datadir).map_err(|e| {
                crate::error::FreedomError::InvalidConfig(format!("finalRule ip: {e}"))
            })?,
            _ => Vec::new(),
        };
        // Go :286-288：`blockDelay` 弃用别名，非 nil 时覆盖 `delay`（`c.Delay = c.BlockDelay`）。
        let mut delay = match v.get("delay") {
            Some(d) => json_int32_range(d).map_err(|e| invalid(format!("finalRule delay: {e}")))?,
            None => None,
        };
        let legacy_delay = match v.get("blockDelay") {
            Some(d) => {
                json_int32_range(d).map_err(|e| invalid(format!("finalRule blockDelay: {e}")))?
            },
            None => None,
        };
        if let Some(d) = legacy_delay {
            crate::FREEDOM_LOG
                .warn("freedom: \"finalRules.blockDelay\" is deprecated, use \"finalRules.delay\"");
            delay = Some(d);
        }
        let log_level_str = match v.get("logLevel") {
            None | Some(serde_json::Value::Null) => "",
            Some(serde_json::Value::String(s)) => s.as_str(),
            Some(_) => {
                return Err(invalid("finalRule logLevel must be a string"));
            },
        };
        // Go :290-293：allow 规则带 delay/logLevel 直接报错（不是忽略）。
        if action != RuleAction::Block {
            if delay.is_some() || !log_level_str.is_empty() {
                return Err(invalid("delay and logLevel are only supported for block finalRules"));
            }
            return Ok(Self { action, networks, port_list, ip, delay: None, log_level: None });
        }
        Ok(Self {
            action,
            networks,
            port_list,
            ip,
            delay,
            log_level: Some(parse_log_level(log_level_str)?),
        })
    }
}

/// Go `infra/conf/freedom.go:302-317`：`logLevel` 值域 → proto `Severity`。
/// 缺省/`"info"` = Info（Go 恒给 block 规则一个非 nil 指针）。
fn parse_log_level(s: &str) -> Result<i32> {
    use xray_proto::xray::common::log::Severity;
    match s.to_ascii_lowercase().as_str() {
        "" | "info" => Ok(Severity::Info as i32),
        "none" => Ok(Severity::Unknown as i32),
        "debug" => Ok(Severity::Debug as i32),
        "warning" => Ok(Severity::Warning as i32),
        "error" => Ok(Severity::Error as i32),
        other => Err(invalid(format!("unknown finalRules.logLevel: {other}"))),
    }
}

/// 地址字符串 → proto `IpOrDomain` oneof（先试 IPv4，再 IPv6，否则域名）。
fn address_str_to_ip_or_domain(s: &str) -> xray_proto::xray::common::net::ip_or_domain::Address {
    use xray_proto::xray::common::net::ip_or_domain::Address as IoD;
    if let Ok(v4) = s.parse::<Ipv4Addr>() {
        IoD::Ip(v4.octets().to_vec())
    } else if let Ok(v6) = s.parse::<Ipv6Addr>() {
        IoD::Ip(v6.octets().to_vec())
    } else {
        IoD::Domain(s.to_string())
    }
}

/// Go `NetworkList`：`"tcp,udp"` 字符串或字符串数组 → proto `Network` i32 列表。
fn json_network_list(v: &serde_json::Value) -> Vec<i32> {
    let tokens: Vec<String> = match v {
        serde_json::Value::String(s) => s.split(',').map(|t| t.trim().to_string()).collect(),
        serde_json::Value::Array(a) => {
            a.iter().map(|x| x.as_str().unwrap_or_default().trim().to_string()).collect()
        },
        // 类型不符（数组/字符串都不是）：Go 解码期硬错；此处退化为 Unknown
        // （永不命中），绝不退化成空表（空表 = 匹配全部）。
        _ => vec![String::new()],
    };
    tokens
        .into_iter()
        // 未知 token 按 Go `Network.Build`（infra/conf/common.go:79-90）映射
        // `Unknown`（索引 0，永不命中 TCP/UDP）。**不得丢弃**：丢空后
        // `networks` 为空 → `FinalRule::build` 走 ALL_NETWORKS，规则从"永不命中"
        // 翻成"匹配全部网络"（bd 5w5z0）。
        .map(|t| match t.to_ascii_lowercase().as_str() {
            "tcp" => xray_proto::xray::common::net::Network::Tcp as i32,
            "udp" => xray_proto::xray::common::net::Network::Udp as i32,
            "unix" => xray_proto::xray::common::net::Network::Unix as i32,
            _ => xray_proto::xray::common::net::Network::Unknown as i32,
        })
        .collect()
}

/// Go `PortList`：`"443,80-90"` 字符串 / 数字数组 / 混合数组 → proto `PortList`。
///
/// 每个条目都必须解析成功（Go `PortRange.UnmarshalJSON` 对非法端口范围直接
/// 报错 → 配置拒启）。旧实现 `continue` 丢项，丢空后返回 `None` = **匹配所有
/// 端口**（bd 5w5z0）。
fn json_port_list(
    v: &serde_json::Value,
) -> std::result::Result<xray_proto::xray::common::net::PortList, String> {
    let items: Vec<String> = match v {
        serde_json::Value::String(s) => s.split(',').map(|t| t.trim().to_string()).collect(),
        serde_json::Value::Array(a) => a
            .iter()
            .map(|x| match x {
                serde_json::Value::String(s) => Ok(s.trim().to_string()),
                serde_json::Value::Number(n) => Ok(n.to_string()),
                _ => Err(format!("port entry is not a string or number: {x}")),
            })
            .collect::<std::result::Result<Vec<_>, _>>()?,
        serde_json::Value::Number(n) => vec![n.to_string()],
        other => return Err(format!("port list must be a string, number or array: {other}")),
    };
    let mut range = Vec::new();
    for item in items {
        let (from, to) = parse_port_range_str(&item)
            .filter(|(_, to)| *to <= u32::from(u16::MAX))
            .ok_or_else(|| format!("invalid port range: {item}"))?;
        range.push(xray_proto::xray::common::net::PortRange { from, to });
    }
    Ok(xray_proto::xray::common::net::PortList { range })
}

/// `"443"` / `"80-90"` → (from, to)。解析失败返回 `None`。
fn parse_port_range_str(s: &str) -> Option<(u32, u32)> {
    match s.split_once('-') {
        Some((a, b)) => {
            let from: u32 = a.trim().parse().ok()?;
            let to: u32 = b.trim().parse().ok()?;
            (from <= to).then_some((from, to))
        },
        None => s.trim().parse::<u32>().ok().map(|p| (p, p)),
    }
}

/// Go `StringList` IP 规则：`["10.0.0.0/8", "geoip:cn", "!ext:custom.dat:XX"]` →
/// proto `IpRule` 列表。
///
/// 逐条走 [`xray_geodata::rule_parser::parse_ip_rules`]（= Go `geodata.ParseIPRules`
/// 同构）：`geoip:X` 展开成 `ext:geoip.dat:X`、`ext:`/`ext-ip:` 直取 `file:code`、
/// 外层 `!` 与 code 内 `!` XOR 成 `reverse_match`、当场 `check_file` 校验资产与代号。
///
/// 每个条目都必须可解析（Go 对非法 IP / 非法前缀 / 资产缺失直接报错 → 拒启）。
/// 旧实现 `filter_map(ok)` 丢项，丢空后 `ip = None` = **匹配所有**地址——
/// `ip:["not-an-ip"]` 会把一条精确规则翻转成全阻断（bd 5w5z0）。
/// 错误带规则原文（Go `illegal ip rule: <rule>` 同形），资产缺失时原文即含文件名。
fn json_ip_rules(
    v: &serde_json::Value,
    datadir: &Path,
) -> std::result::Result<Vec<xray_proto::xray::common::geodata::IpRule>, String> {
    let items: Vec<String> = match v {
        serde_json::Value::String(s) => s.split(',').map(|t| t.trim().to_string()).collect(),
        serde_json::Value::Array(a) => a
            .iter()
            .map(|x| {
                x.as_str()
                    .map(|s| s.trim().to_string())
                    .ok_or_else(|| format!("ip rule entry is not a string: {x}"))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?,
        other => return Err(format!("ip rules must be a string or array: {other}")),
    };
    let mut out = Vec::with_capacity(items.len());
    for raw in items {
        let parsed = xray_geodata::rule_parser::parse_ip_rules(std::slice::from_ref(&raw), datadir)
            .map_err(|e| match e {
                // 资产类失败（文件不存在/代号缺失）带上资产目录：`io::Error` 自身
                // 不含路径（Go 的 `os.Open` 错误含），缺了就没法定位找哪个目录。
                xray_geodata::rule_parser::RuleParserError::FileCheckFailed(_)
                | xray_geodata::rule_parser::RuleParserError::Io(_) => {
                    format!("illegal ip rule `{raw}` (asset dir {}): {e}", datadir.display())
                },
                e => format!("illegal ip rule `{raw}`: {e}"),
            })?;
        out.extend(parsed.into_iter().map(geodata_ip_rule_to_proto));
    }
    Ok(out)
}

/// `xray_geodata::pb::IpRule` → proto `IpRule`（`xray.common.geodata`）。
///
/// 两个 crate 各自生成同名不同类型（Go 只有一份 proto，无此转换），字段级复制。
fn geodata_ip_rule_to_proto(
    rule: xray_geodata::pb::IpRule,
) -> xray_proto::xray::common::geodata::IpRule {
    use xray_geodata::pb;
    let value = match rule.value {
        None => None,
        Some(pb::ip_rule::Value::Custom(c)) => {
            Some(ip_rule::Value::Custom(xray_proto::xray::common::geodata::CidrRule {
                cidr: c.cidr.map(|cidr| xray_proto::xray::common::geodata::Cidr {
                    ip: cidr.ip,
                    prefix: cidr.prefix,
                }),
                reverse_match: c.reverse_match,
            }))
        },
        Some(pb::ip_rule::Value::Geoip(g)) => {
            Some(ip_rule::Value::Geoip(xray_proto::xray::common::geodata::GeoIpRule {
                file: g.file,
                code: g.code,
                reverse_match: g.reverse_match,
            }))
        },
    };
    xray_proto::xray::common::geodata::IpRule { value }
}

/// proto `IpRule` → `xray_geodata::pb::IpRule`（[`IpRegistry::build_ip_matcher`] 入参）。
///
/// 字段级复制，不做资产展开：`Geoip` 变体保持 `file:code` 形态交给注册表在
/// 构造期解析——这样 `IP_REG.reload()` 能按各自 rules 重建（Go `DynamicIPMatcher.rules` 同）。
fn to_geodata_ip_rules(
    rules: &[xray_proto::xray::common::geodata::IpRule],
) -> Vec<xray_geodata::pb::IpRule> {
    use xray_geodata::pb;
    rules
        .iter()
        .map(|r| pb::IpRule {
            value: match r.value.as_ref() {
                None => None,
                Some(ip_rule::Value::Custom(c)) => Some(pb::ip_rule::Value::Custom(pb::CidrRule {
                    cidr: c
                        .cidr
                        .as_ref()
                        .map(|cidr| pb::Cidr { ip: cidr.ip.clone(), prefix: cidr.prefix }),
                    reverse_match: c.reverse_match,
                })),
                Some(ip_rule::Value::Geoip(g)) => Some(pb::ip_rule::Value::Geoip(pb::GeoIpRule {
                    file: g.file.clone(),
                    code: g.code.clone(),
                    reverse_match: g.reverse_match,
                })),
            },
        })
        .collect()
}

/// Go `Int32Range`（`infra/conf/common.go:316-349`）：`"30-90"` / `30` / `""` → `Range`，
/// 且 `From > To` 时交换（`ensureOrder`）；非法形态**硬错**（Go 解码期即报错）。
/// `{"from":a,"to":b}` 是本仓既有方言（Go 无此形态），保留兼容。
fn json_int32_range(v: &serde_json::Value) -> Result<Option<Range>> {
    let (a, b) = match v {
        serde_json::Value::Null => return Ok(None),
        serde_json::Value::Number(n) => {
            let x = n.as_i64().ok_or_else(|| invalid("invalid integer range"))?;
            (x, x)
        },
        serde_json::Value::String(s) if s.is_empty() => (0, 0),
        serde_json::Value::String(s) => match s.split_once('-') {
            Some((a, b)) => match (a.trim().parse::<i64>(), b.trim().parse::<i64>()) {
                (Ok(a), Ok(b)) => (a, b),
                _ => return Err(invalid(format!("invalid range string: {s}"))),
            },
            // Go `ParseRangeString`：裸数字等同 [n, n]
            None => match s.trim().parse::<i64>() {
                Ok(n) => (n, n),
                Err(_) => return Err(invalid(format!("invalid range string: {s}"))),
            },
        },
        serde_json::Value::Object(o) => (
            o.get("from").and_then(serde_json::Value::as_i64).unwrap_or(0),
            o.get("to").and_then(serde_json::Value::as_i64).unwrap_or(0),
        ),
        _ => return Err(invalid("invalid integer range, expected string or plain integer")),
    };
    let (min, max) = if a > b { (b, a) } else { (a, b) };
    Ok(Some(Range { min: min.max(0) as u64, max: max.max(0) as u64 }))
}

/// Freedom 主配置。对应 proto `xray.proxy.freedom.Config`。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Config {
    /// DNS 解析策略（proto enum → i32）。
    pub domain_strategy: i32,
    pub destination_override: Option<DestinationOverride>,
    pub user_level: u32,
    pub fragment: Option<Fragment>,
    pub proxy_protocol: u32,
    pub noises: Vec<Noise>,
    pub final_rules: Vec<FinalRuleConfig>,
}

impl Config {
    /// 从 prost Config 构造。
    pub fn from_proto(p: xray_proto::xray::proxy::freedom::Config) -> Result<Self> {
        Ok(Self {
            domain_strategy: p.domain_strategy,
            destination_override: p
                .destination_override
                .map(|d| DestinationOverride { server: d.server }),
            user_level: p.user_level,
            fragment: p.fragment.map(|f| Fragment {
                packets_from: f.packets_from,
                packets_to: f.packets_to,
                length_min: f.length_min,
                length_max: f.length_max,
                interval_min: f.interval_min,
                interval_max: f.interval_max,
                max_split_min: f.max_split_min,
                max_split_max: f.max_split_max,
            }),
            proxy_protocol: p.proxy_protocol,
            noises: p
                .noises
                .into_iter()
                .map(|n| Noise {
                    length_min: n.length_min,
                    length_max: n.length_max,
                    delay_min: n.delay_min,
                    delay_max: n.delay_max,
                    packet: n.packet,
                    apply_to: n.apply_to,
                })
                .collect(),
            final_rules: p
                .final_rules
                .into_iter()
                .map(|r| FinalRuleConfig {
                    action: RuleAction::from_proto_value(r.action),
                    networks: r.networks,
                    port_list: r.port_list,
                    ip: r.ip,
                    delay: r.delay.map(|b| Range { min: b.min, max: b.max }),
                    log_level: r.log_level,
                })
                .collect(),
        })
    }

    /// 转换为 prost Config。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::proxy::freedom::Config {
        xray_proto::xray::proxy::freedom::Config {
            domain_strategy: self.domain_strategy,
            destination_override: self.destination_override.as_ref().map(|d| {
                xray_proto::xray::proxy::freedom::DestinationOverride { server: d.server.clone() }
            }),
            user_level: self.user_level,
            fragment: self.fragment.as_ref().map(|f| xray_proto::xray::proxy::freedom::Fragment {
                packets_from: f.packets_from,
                packets_to: f.packets_to,
                length_min: f.length_min,
                length_max: f.length_max,
                interval_min: f.interval_min,
                interval_max: f.interval_max,
                max_split_min: f.max_split_min,
                max_split_max: f.max_split_max,
            }),
            proxy_protocol: self.proxy_protocol,
            noises: self
                .noises
                .iter()
                .map(|n| xray_proto::xray::proxy::freedom::Noise {
                    length_min: n.length_min,
                    length_max: n.length_max,
                    delay_min: n.delay_min,
                    delay_max: n.delay_max,
                    packet: n.packet.clone(),
                    apply_to: n.apply_to.clone(),
                })
                .collect(),
            final_rules: self
                .final_rules
                .iter()
                .map(|r| xray_proto::xray::proxy::freedom::FinalRuleConfig {
                    action: r.action.to_proto_value(),
                    networks: r.networks.clone(),
                    port_list: r.port_list.clone(),
                    ip: r.ip.clone(),
                    delay: r.delay.map(|b| xray_proto::xray::proxy::freedom::Range {
                        min: b.min,
                        max: b.max,
                    }),
                    log_level: r.log_level,
                })
                .collect(),
        }
    }
}

/// 运行时最终规则（从 FinalRuleConfig 构建）。对应 Go `FinalRule` struct。
impl std::fmt::Debug for FinalRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinalRule")
            .field("action", &self.action)
            .field("network", &self.network)
            .field("port", &self.port.is_some())
            .field("has_ip_matcher", &self.ip.is_some())
            .field("delay", &self.delay)
            .field("log_level", &self.log_level)
            .finish()
    }
}

pub struct FinalRule {
    pub action: RuleAction,
    /// 允许的网络类型（bool 数组索引 0=TCP 1=UDP 等，与 Go `[8]bool` 一致）。
    pub network: [bool; 8],
    /// 端口列表（None 表示匹配所有端口）。对应 Go `matchPort` 的 `len==0` 语义。
    pub port: Option<MemoryPortList>,
    /// IP CIDR 匹配器（None 表示无 IP 限制 → 匹配所有地址）。
    pub ip: Option<Arc<dyn IPMatcher>>,
    /// 阻断延时；None = 默认 [30, 90] 秒。对应 Go `FinalRule.delay`。
    pub delay: Option<Range>,
    /// 阻断期日志级别（proto `Severity` 值）；None = Info。对应 Go `FinalRule.logLevel`。
    pub log_level: Option<i32>,
}

impl Clone for FinalRule {
    fn clone(&self) -> Self {
        Self {
            action: self.action,
            network: self.network,
            port: self.port.clone(),
            ip: self.ip.clone(),
            delay: self.delay,
            log_level: self.log_level,
        }
    }
}

/// 默认允许所有网络（与 Go `allNetworks` 一致）。
pub const ALL_NETWORKS: [bool; 8] = [true; 8];

/// 默认阻止私有地址的 CIDR 列表——逐条抄自 Go `common/geodata/consts.go:9-72`
/// （`geodata.GetPrivateIPMatcher()` 的表，`defaultBlockPrivateRule` 用它）。
///
/// 分组与注释一一对应 Go 源；Go 中被注释掉的条目在此同样注释保留
/// （`// "192.0.0.0/24"` 等），便于下轮对拍。
pub const DEFAULT_BLOCK_PRIVATE_CIDRS: &[&str] = &[
    // https://www.iana.org/assignments/iana-ipv4-special-registry
    "0.0.0.0/8",      // "This network"
    "0.0.0.0/32",     // "This host on this network"
    "10.0.0.0/8",     // Private-Use
    "100.64.0.0/10",  // Shared Address Space
    "127.0.0.0/8",    // Loopback
    "169.254.0.0/16", // Link Local
    "172.16.0.0/12",  // Private-Use
    // "192.0.0.0/24",   // IETF Protocol Assignments
    "192.0.0.0/29",   // IPv4 Service Continuity Prefix
    "192.0.0.8/32",   // IPv4 dummy address
    "192.0.0.9/32",   // Port Control Protocol Anycast
    "192.0.0.10/32",  // Traversal Using Relays around NAT Anycast
    "192.0.0.170/32", // NAT64/DNS64 Discovery
    "192.0.0.171/32", // NAT64/DNS64 Discovery
    "192.0.2.0/24",   // Documentation (TEST-NET-1)
    // "192.31.196.0/24",    // AS112-v4
    "192.52.193.0/24", // AMT
    // "192.88.99.0/24",  // Deprecated (6to4 Relay Anycast)
    "192.88.99.2/32", // 6a44-relay anycast address
    "192.168.0.0/16", // Private-Use
    // "192.175.48.0/24",    // Direct Delegation AS112 Service
    "198.18.0.0/15",      // Benchmarking
    "198.51.100.0/24",    // Documentation (TEST-NET-2)
    "203.0.113.0/24",     // Documentation (TEST-NET-3)
    "240.0.0.0/4",        // Reserved
    "255.255.255.255/32", // Limited Broadcast
    // https://www.iana.org/assignments/multicast-addresses
    "224.0.0.0/4",
    // https://www.iana.org/assignments/iana-ipv6-special-registry
    "::1/128", // Loopback Address
    "::/128",  // Unspecified Address
    // "::ffff:0:0/96",     // IPv4-mapped Address
    "64:ff9b::/96",   // IPv4-IPv6 Translat.
    "64:ff9b:1::/48", // IPv4-IPv6 Translat.
    "100::/64",       // Discard-Only Address Block
    "100:0:0:1::/64", // Dummy IPv6 Prefix
    // "2001::/23",      // IETF Protocol Assignments
    "2001::/32",     // TEREDO
    "2001:1::1/128", // Port Control Protocol Anycast
    "2001:1::2/128", // Traversal Using Relays around NAT Anycast
    "2001:1::3/128", // DNS-SD Service Registration Protocol Anycast
    "2001:2::/48",   // Benchmarking
    "2001:3::/32",   // AMT
    // "2001:4:112::/48", // AS112-v6
    // "2001:10::/28",    // Deprecated (previously ORCHID)
    "2001:20::/28",  // ORCHIDv2
    "2001:30::/28",  // Drone Remote ID Protocol Entity Tags (DETs) Prefix
    "2001:db8::/32", // Documentation
    "2002::/16",     // 6to4
    // "2620:4f:8000::/48", // Direct Delegation AS112 Service
    "3fff::/20", // Documentation
    "5f00::/16", // Segment Routing (SRv6) SIDs
    "fc00::/7",  // Unique-Local
    "fe80::/10", // Link-Local Unicast
    // https://www.iana.org/assignments/ipv6-multicast-addresses
    "ff00::/8",
];

impl FinalRule {
    /// 从 FinalRuleConfig 构造运行时规则。对应 Go `buildFinalRule`。
    ///
    /// `ip` 规则经全局 [`IP_REG`] 构建：`geoip:` / `ext:` / `ext-ip:` 的资产在
    /// **构造期**读入并登记，`IP_REG.reload()` 可热更（Go `geodata.IPReg.BuildIPMatcher`
    /// 同）。资产缺失 ⇒ `Err` 拒启，不静默退空集。
    pub fn build(config: &FinalRuleConfig) -> Result<Self> {
        Self::build_with_registry(&IP_REG, config)
    }

    /// [`FinalRule::build`] 的显式注册表形态（测试 / 非默认资产目录部署）。
    pub fn build_with_registry(registry: &IpRegistry, config: &FinalRuleConfig) -> Result<Self> {
        let network = if config.networks.is_empty() {
            ALL_NETWORKS
        } else {
            let mut net = [false; 8];
            for &n in &config.networks {
                let idx = n as usize;
                if idx < 8 {
                    net[idx] = true;
                }
            }
            net
        };

        let port = config.port_list.as_ref().map(to_mem_port_list);

        Ok(Self {
            action: config.action,
            network,
            port,
            ip: build_ip_matcher_from_rules(registry, &config.ip)?,
            delay: config.delay,
            log_level: config.log_level,
        })
    }

    /// 构造默认规则。对应 Go `init()` 中的 `defaultBlockPrivateRule` /
    /// `defaultBlockAllRule`，以及 `getDefaultFinalRule` 的选择结果。
    ///
    /// - [`DefaultRuleType::BlockPrivate`]：action=Block，network=all，ip=私有 CIDR matcher。
    /// - [`DefaultRuleType::BlockAll`]：action=Block，network=all，ip=None（匹配所有）。
    ///
    /// 两者的 `log_level` 都是 Warning（Go `freedom.go:78-90` 显式
    /// `log.Severity_Warning.Enum()`）。
    #[must_use]
    pub fn build_default_rule(kind: DefaultRuleType) -> Self {
        let log_level = Some(xray_proto::xray::common::log::Severity::Warning as i32);
        match kind {
            DefaultRuleType::BlockPrivate => Self {
                action: RuleAction::Block,
                network: ALL_NETWORKS,
                port: None,
                ip: Some(private_ip_matcher()),
                delay: None,
                log_level,
            },
            DefaultRuleType::BlockAll => Self {
                action: RuleAction::Block,
                network: ALL_NETWORKS,
                port: None,
                ip: None,
                delay: None,
                log_level,
            },
        }
    }

    /// 网络类型是否匹配。对应 Go `matchNetwork`。
    #[must_use]
    pub fn match_network(&self, network_index: usize) -> bool {
        if network_index >= 8 {
            return false;
        }
        self.network[network_index]
    }

    /// 端口是否匹配。None 表示匹配所有端口。对应 Go `matchPort`。
    #[must_use]
    pub fn match_port(&self, port: u16) -> bool {
        match &self.port {
            None => true,
            Some(list) => list.contains(Port::new(port)),
        }
    }

    /// IP 是否匹配。None ip matcher 表示匹配所有。对应 Go `matchIP`。
    ///
    /// `ip` 为 `None`（域名目标，但规则有 IP 限制）时返回 `false`——
    /// 与 Go `addr != nil && addr.Family().IsIP()` 一致。
    #[must_use]
    pub fn match_ip(&self, ip: Option<IpAddr>) -> bool {
        match (&self.ip, ip) {
            (None, _) => true,
            (Some(m), Some(addr)) => m.match_ip(addr),
            (Some(_), None) => false,
        }
    }

    /// 完整匹配。对应 Go `Apply`。
    #[must_use]
    pub fn apply(&self, network_index: usize, port: u16, ip: Option<IpAddr>) -> bool {
        if !self.match_network(network_index) {
            return false;
        }
        if !self.match_port(port) {
            return false;
        }
        self.match_ip(ip)
    }
}

/// 把 proto `PortList` 转为 `MemoryPortList`。对应 Go `net.PortListFromProto`。
fn to_mem_port_list(pl: &xray_proto::xray::common::net::PortList) -> MemoryPortList {
    let ranges: Vec<PortRange> = pl
        .range
        .iter()
        .map(|r| PortRange::new(Port::new(r.from as u16), Port::new(r.to as u16)))
        .collect();
    MemoryPortList::new(ranges)
}

/// 从 proto `IpRule` 列表构建 IP matcher。对应 Go `freedom.go:126-131`
/// （`geodata.IPReg.BuildIPMatcher(config.Ip)`）。
///
/// 空规则 ⇒ `None`（= 匹配所有地址，Go 同：`len(config.Ip) > 0` 才建 matcher）。
/// 正/负极性分组、同组 CIDR 合并、`geoip` 资产在构造期解析，全在注册表内部
/// （`build_optimized_ip_matcher` 语义）—— 旧实现在此只取 Custom 变体、
/// 丢掉 reverse 分组（bd 5w5z0 同族），并对 geoip 硬错。
fn build_ip_matcher_from_rules(
    registry: &IpRegistry,
    rules: &[xray_proto::xray::common::geodata::IpRule],
) -> Result<Option<Arc<dyn IPMatcher>>> {
    if rules.is_empty() {
        return Ok(None);
    }
    let matcher = registry
        .build_ip_matcher(&to_geodata_ip_rules(rules))
        .map_err(|e| FreedomError::InvalidConfig(format!("finalRule ip: {e}")))?;
    Ok(Some(matcher))
}

/// 缓存的私有 IP matcher（从 [`DEFAULT_BLOCK_PRIVATE_CIDRS`] 构建）。
///
/// 对应 Go `geodata.GetPrivateIPMatcher()`——进程级单例，惰性构建一次。
#[must_use]
pub fn private_ip_matcher() -> Arc<dyn IPMatcher> {
    static MATCHER: LazyLock<Arc<dyn IPMatcher>> = LazyLock::new(|| {
        let cidrs: Vec<xray_geodata::pb::Cidr> = DEFAULT_BLOCK_PRIVATE_CIDRS
            .iter()
            .filter_map(|s| xray_geodata::rule_parser::parse_cidr(s).ok())
            .collect();
        Arc::new(HeuristicIPMatcher::from_cidrs(&cidrs))
    });
    MATCHER.clone()
}

/// 根据入站协议名返回默认 final rule 类型。
///
/// 对应 Go `getDefaultFinalRule`：
/// - `"vless-reverse"` → 阻止所有
/// - `"vless"` / `"vmess"` / `"trojan"` / `"hysteria"` / `"wireguard"` / `"masque"` /
///   `"shadowsocks*"` → 阻止私有
/// - 其他 → None（不应用默认规则）
#[must_use]
pub fn get_default_rule_type(inbound_name: &str) -> Option<DefaultRuleType> {
    match inbound_name {
        "vless-reverse" => Some(DefaultRuleType::BlockAll),
        "vless" | "vmess" | "trojan" | "hysteria" | "wireguard" | "masque" => {
            Some(DefaultRuleType::BlockPrivate)
        },
        other if other.starts_with("shadowsocks") => Some(DefaultRuleType::BlockPrivate),
        _ => None,
    }
}

/// 默认规则类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultRuleType {
    /// 阻止 RFC 1918 私有地址（DEFAULT_BLOCK_PRIVATE_CIDRS）。
    BlockPrivate,
    /// 阻止所有地址。
    BlockAll,
}

/// 原生 `Network` → proto 值索引。对应 Go `int(network)`（Tcp=2/Udp=3/Unix=4）。
///
/// `FinalRule::build` 用 proto 值填 `network` 数组，匹配侧必须用同一索引口径。
#[must_use]
pub fn network_index(network: Network) -> usize {
    match network {
        Network::TCP => 2,
        Network::UDP => 3,
        Network::Unix => 4,
    }
}

/// 首个命中的规则（配置规则优先，其次默认规则）。对应 Go `matchFinalRule` :187-197。
#[must_use]
pub fn match_final_rules(
    rules: &[FinalRule],
    default_rule: Option<&FinalRule>,
    dest: &Destination,
) -> Option<FinalRule> {
    let idx = network_index(dest.network());
    let port = dest.port().value();
    let ip = dest.address().ip();
    for rule in rules {
        if rule.apply(idx, port, ip) {
            return Some(rule.clone());
        }
    }
    if let Some(dr) = default_rule {
        if dr.apply(idx, port, ip) {
            return Some(dr.clone());
        }
    }
    None
}

/// 命中 Block 规则与否（Go :335-339 的 `rule.action == Block` 判定）。
#[must_use]
pub fn is_blocked_by_rules(
    rules: &[FinalRule],
    default_rule: Option<&FinalRule>,
    dest: &Destination,
) -> bool {
    match_final_rules(rules, default_rule, dest).is_some_and(|r| r.action == RuleAction::Block)
}

/// finalRule Block 预检的域名解析（Go v26.9.9 `Process` :294-329，#6058）。
///
/// 返回全部候选 IP 供逐 IP 匹配（Go :304-329 任一 IP 命中 Block 即阻断）；
/// 空表 = 解析失败/无结果，调用方按「无法预检」继续拨号（Go :298-299/:315-318
/// 记日志继续，dial 层可再解析）。仅 `ForceIP` 策略解析失败返回 Err（Go
/// :300-302 断链重试）。
///
/// # Errors
/// 仅 `strategy.force_ip()` 且 `LookupForIP` 失败时返回错误。
pub async fn resolve_ips_for_rules(
    domain: &str,
    port: u16,
    strategy: xray_transport::sockopt::DomainStrategy,
) -> std::io::Result<Vec<IpAddr>> {
    if strategy.has_strategy() {
        return match xray_transport::system_dialer::lookup_for_ip(domain, strategy, None).await {
            Ok(ips) => Ok(ips),
            Err(e) => {
                if strategy.force_ip() {
                    Err(e)
                } else {
                    crate::FREEDOM_LOG.debug(format!(
                        "freedom: LookupForIP failed, skip finalRule pre-check domain={domain} error={e}"
                    ));
                    Ok(Vec::new())
                }
            },
        };
    }
    // Go :315-318：系统 resolver（AsIs）；失败记日志、空表继续
    match tokio::net::lookup_host((domain, port)).await {
        Ok(addrs) => Ok(addrs.map(|sa| sa.ip()).collect()),
        Err(e) => {
            crate::FREEDOM_LOG.debug(format!(
                "freedom: system resolve failed, skip finalRule pre-check domain={domain} error={e}"
            ));
            Ok(Vec::new())
        },
    }
}

/// 目标地址替换为解析出的 IP（端口/网络保留）。finalRule 逐 IP 预检
/// （dispatcher/handler）与 UDP 逐帧改写（udp.rs）共用。
#[must_use]
pub fn destination_with_ip(dest: &Destination, ip: IpAddr) -> Destination {
    let address = match ip {
        IpAddr::V4(v4) => Address::IPv4(v4),
        IpAddr::V6(v6) => Address::IPv6(v6),
    };
    Destination::new(address, dest.port(), dest.network())
}

/// 目标改写：Go `Process` :269-279 + `isValidAddress` :240-247。
///
/// `server.address` 有效（非 AnyIP/AnyIPv6）时改写地址；`server.port != 0` 时改写端口。
#[must_use]
pub fn apply_destination_override(
    dest: &Destination,
    ov: Option<&DestinationOverride>,
) -> Destination {
    let Some(server) = ov.and_then(|o| o.server.as_ref()) else {
        return dest.clone();
    };
    let mut address = dest.address().clone();
    if let Some(new_addr) = server.address.as_ref().and_then(ip_or_domain_to_address) {
        if is_valid_override_address(&new_addr) {
            address = new_addr;
        }
    }
    let port = if server.port != 0 { Port::new(server.port as u16) } else { dest.port() };
    Destination::new(address, port, dest.network())
}

/// Go `isValidAddress` :240-247——排除 AnyIP（0.0.0.0）与 AnyIPv6（::）。
fn is_valid_override_address(addr: &Address) -> bool {
    match addr {
        Address::IPv4(v4) => !v4.is_unspecified(),
        Address::IPv6(v6) => !v6.is_unspecified(),
        Address::Domain(_) => true,
    }
}

/// proto `IpOrDomain` → 原生 `Address`。IP 字节数非 4/16 返回 `None`。
#[allow(clippy::incompatible_msrv)] // std from_octets 1.91 stable，晚于 workspace MSRV 声明
fn ip_or_domain_to_address(iod: &xray_proto::xray::common::net::IpOrDomain) -> Option<Address> {
    use xray_proto::xray::common::net::ip_or_domain::Address as IoD;
    match iod.address.as_ref()? {
        IoD::Ip(bytes) => match bytes.as_slice() {
            [a, b, c, d] => Some(Address::IPv4(Ipv4Addr::new(*a, *b, *c, *d))),
            b16 => Some(Address::IPv6(Ipv6Addr::from_octets(b16.try_into().ok()?))),
        },
        IoD::Domain(d) => Some(Address::Domain(d.clone())),
    }
}

/// 黑洞：drain 上游输入直到 `block_delay(rule)` 超时，随后关闭下游。
///
/// 对应 Go `Process` blockedDest 分支 :352-366——不拨号，慢速丢弃防探测。
pub(crate) async fn blackhole_link(link: xray_transport::link::Link, tag: &str, rule: &FinalRule) {
    let delay = block_delay(rule);
    log_blocked(
        rule,
        format!(
            "freedom: target blocked by final rule, blackholing connection tag={tag} delay={delay:?}"
        ),
    );
    let xray_transport::link::Link { mut reader, writer } = link;
    // EOF 语义与 udp pump 一致：Err 或 Ok(空 buffer) 都视为对端关闭
    let drain = async {
        loop {
            match reader.read_multi_buffer().await {
                Ok(mb) if !mb.is_empty() => continue,
                _ => break,
            }
        }
    };
    tokio::select! {
        _ = drain => {}
        _ = tokio::time::sleep(delay) => {}
    }
    writer.shutdown();
}

/// 按规则 `log_level` 发射阻断日志。对应 Go `FinalRule.log`（:234-250）：
/// 未设级别 = Info；`Unknown`（`"none"`）在 Go 的 switch 里无分支 ⇒ 不打日志。
fn log_blocked(rule: &FinalRule, message: String) {
    use xray_proto::xray::common::log::Severity;
    match rule.log_level.and_then(|v| Severity::try_from(v).ok()) {
        None | Some(Severity::Info) => crate::FREEDOM_LOG.info(message),
        Some(Severity::Warning) => crate::FREEDOM_LOG.warn(message),
        Some(Severity::Error) => crate::FREEDOM_LOG.error(message),
        Some(Severity::Debug) => crate::FREEDOM_LOG.debug(message),
        Some(Severity::Unknown) => {},
    }
}

/// 计算阻断延时。对应 Go `Handler.blockDelay` :226-238。
///
/// 默认 [30, 90] 秒；`rule.delay` 可覆盖。`dice.Roll(span+1)` → [0, span]。
#[must_use]
pub fn block_delay(rule: &FinalRule) -> std::time::Duration {
    let (min, max) = match rule.delay {
        Some(r) => (r.min, r.max),
        None => (30, 90),
    };
    let span = max.abs_diff(min);
    let roll = rand::random_range(0..=span);
    std::time::Duration::from_secs(min + roll)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== bd 5w5z0：finalRules 静默丢项 → 语义翻转（丢空 = 匹配所有） =====

    /// port / ip 的非法项必须硬错（Go 解码期 `PortRange.UnmarshalJSON` /
    /// `geodata.ParseIPRules` 硬错）。旧实现逐项丢弃，丢空后 `None` = 匹配所有
    /// → `ip:["not-an-ip"]` 把精确规则翻转成全阻断（E1 实证：全流量黑洞、零日志）。
    #[test]
    fn final_rule_rejects_invalid_port_and_ip() {
        let e = FinalRuleConfig::from_json(&serde_json::json!({
            "action": "block", "ip": ["not-an-ip"]
        }))
        .unwrap_err();
        assert!(e.to_string().contains("illegal ip rule `not-an-ip`"), "{e}");

        let e = FinalRuleConfig::from_json(&serde_json::json!({
            "action": "block", "port": "18500,bad-port"
        }))
        .unwrap_err();
        assert!(e.to_string().contains("invalid port range"), "{e}");

        // geoip/ext 规则在解析期查资产（Go `ParseIPRules` 的 `checkFile`）：
        // 资产缺失/代号不存在 ⇒ 拒启（不得静默丢空 = 匹配所有）。用空目录注入保证
        // 与机器上是否装了 geoip.dat 无关。
        let empty = tmp_dir("freedom_no_asset");
        let e = FinalRuleConfig::from_json_with_datadir(
            &serde_json::json!({"action": "block", "ip": ["geoip:cn"]}),
            &empty,
        )
        .unwrap_err();
        assert!(
            e.to_string().contains("geoip:cn") && e.to_string().contains("asset dir"),
            "错误须点名规则与资产目录: {e}"
        );
        let e = FinalRuleConfig::from_json_with_datadir(
            &serde_json::json!({"action": "block", "ip": ["ext-ip:custom.dat:XX"]}),
            &empty,
        )
        .unwrap_err();
        assert!(e.to_string().contains("custom.dat"), "错误须含文件名: {e}");

        // 合法配置照常（不误报）
        let c = FinalRuleConfig::from_json(&serde_json::json!({
            "action": "allow", "port": "443,80-90", "ip": ["10.0.0.0/8"], "network": "tcp,udp"
        }))
        .expect("valid rule parses");
        assert_eq!(c.ip.len(), 1);
        assert_eq!(c.networks.len(), 2);
        assert!(c.port_list.is_some());
    }

    /// 未知 network token → `Network::Unknown`（Go `Network.Build` 同款，永不命中），
    /// **不得**丢空变成 ALL_NETWORKS。
    #[test]
    fn final_rule_unknown_network_never_widens() {
        let c = FinalRuleConfig::from_json(&serde_json::json!({
            "action": "block", "network": "tpc"
        }))
        .expect("parse");
        let rule = FinalRule::build(&c).expect("build");
        assert!(!rule.match_network(1), "TCP 不得被未知 token 命中");
        assert!(!rule.match_network(2), "UDP 不得被未知 token 命中");
    }

    /// 合成 `geoip.dat`（`GeoIpList{ entry: [{code, cidr}] }` 的 prost 编码，与真实
    /// 资产同形；写 `xray.geodata` 包 = `xray-geodata` 的 loader 读的那份）。
    fn write_geoip_dat(dir: &std::path::Path, code: &str, cidrs: &[(Vec<u8>, u32)]) {
        use prost::Message as _;
        let mut entry = xray_geodata::pb::GeoIp::new(code);
        entry.cidr = cidrs
            .iter()
            .map(|(ip, prefix)| xray_geodata::pb::Cidr::new(ip.clone(), *prefix))
            .collect();
        let list = xray_geodata::pb::GeoIpList::new().with_entry(entry);
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join(xray_geodata::rule_parser::DEFAULT_GEOIP_DAT),
            list.encode_to_vec(),
        )
        .unwrap();
    }

    fn tmp_dir(label: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("xray_freedom_{label}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `geoip:` 规则必须在**构造期**从资产解析并参与匹配（旧实现该变体硬错拒启）。
    #[test]
    fn final_rule_geoip_rule_matches_asset_ips() {
        let dir = tmp_dir("geoip_hit");
        write_geoip_dat(&dir, "PRIVATE", &[(vec![10, 0, 0, 0], 8), (vec![172, 16, 0, 0], 12)]);

        let cfg = FinalRuleConfig::from_json_with_datadir(
            &serde_json::json!({"action": "block", "ip": ["geoip:private"]}),
            &dir,
        )
        .expect("geoip rule parses when asset present");
        match cfg.ip[0].value.as_ref() {
            Some(ip_rule::Value::Geoip(g)) => {
                assert_eq!((g.file.as_str(), g.code.as_str()), ("geoip.dat", "PRIVATE"));
                assert!(!g.reverse_match);
            },
            other => panic!("expected Geoip rule, got {other:?}"),
        }

        let rule = FinalRule::build_with_registry(&IpRegistry::with_datadir(dir.clone()), &cfg)
            .expect("build");
        assert!(rule.apply(0, 80, Some("10.1.2.3".parse().unwrap())), "资产内 IP 命中");
        assert!(rule.apply(0, 80, Some("172.20.0.1".parse().unwrap())), "资产内 IP 命中");
        assert!(!rule.apply(0, 80, Some("8.8.8.8".parse().unwrap())), "资产外 IP 不命中");
    }

    /// `!geoip:` = 同组整组取反（Go `buildOptimizedIPMatcher` 的 neg 分组）：
    /// 资产内不命中、资产外命中。`ext-ip:` 前缀与 `geoip:` 同构。
    #[test]
    fn final_rule_reversed_geoip_and_ext_ip_prefix() {
        let dir = tmp_dir("geoip_rev");
        write_geoip_dat(&dir, "PRIVATE", &[(vec![10, 0, 0, 0], 8)]);
        let registry = IpRegistry::with_datadir(dir.clone());

        for rule in ["!geoip:private", "!ext-ip:geoip.dat:private", "ext:geoip.dat:!PRIVATE"] {
            let cfg = FinalRuleConfig::from_json_with_datadir(
                &serde_json::json!({"action": "allow", "ip": [rule]}),
                &dir,
            )
            .unwrap_or_else(|e| panic!("{rule}: {e}"));
            let built = FinalRule::build_with_registry(&registry, &cfg).expect("build");
            assert!(!built.match_ip(Some("10.1.2.3".parse().unwrap())), "{rule}: 组内不命中");
            assert!(built.match_ip(Some("8.8.8.8".parse().unwrap())), "{rule}: 组外命中");
        }
    }

    /// CIDR 的 `!` 反向必须生效（旧实现 parse 期就对 `!` 硬错，`reverse_match` 恒 false）。
    ///
    /// Go 语义 = pos/neg **各建一个子 matcher，最后取并集**（`HeuristicMultiIPMatcher`
    /// = `any()`），不是集合差：`!x` 单独出现 = "除 x 外全部"，与正向组混合时
    /// 排除项不能削减正向组（`ip_matcher.go:951-1013`）。
    #[test]
    fn final_rule_negated_cidr_reverses_group() {
        let cfg = FinalRuleConfig::from_json(&serde_json::json!({
            "action": "block", "ip": ["!192.168.1.0/24"]
        }))
        .expect("parse");
        match cfg.ip[0].value.as_ref() {
            Some(ip_rule::Value::Custom(c)) => assert!(c.reverse_match, "`!` 必须置 reverse_match"),
            other => panic!("expected Custom rule, got {other:?}"),
        }
        let rule = FinalRule::build(&cfg).expect("build");
        assert!(!rule.match_ip(Some("192.168.1.5".parse().unwrap())), "组内不命中");
        assert!(rule.match_ip(Some("8.8.8.8".parse().unwrap())), "组外取反命中");
    }

    /// 构造期读资产失败 ⇒ `Err`（Go `BuildIPMatcher` 同，不静默退空集 = 全放行）。
    #[test]
    fn final_rule_geoip_missing_asset_refuses_to_build() {
        let empty = tmp_dir("geoip_missing");
        let cfg = FinalRuleConfig {
            action: RuleAction::Block,
            ip: vec![xray_proto::xray::common::geodata::IpRule {
                value: Some(ip_rule::Value::Geoip(xray_proto::xray::common::geodata::GeoIpRule {
                    file: String::new(),
                    code: "cn".into(),
                    reverse_match: false,
                })),
            }],
            ..Default::default()
        };
        let e = FinalRule::build_with_registry(&IpRegistry::with_datadir(empty), &cfg)
            .expect_err("missing asset must fail the build");
        assert!(e.to_string().contains("geoip"), "{e}");
    }

    // ===== fragment / noises JSON 解析（Go infra/conf/freedom.go） =====

    #[test]
    fn fragment_go_keys_tlshello_and_range() {
        let f = Fragment::from_json(&serde_json::json!({
            "packets": "tlshello", "length": "100-200", "interval": "10-20"
        }))
        .expect("go 键形");
        assert_eq!((f.packets_from, f.packets_to), (0, 1), "tlshello");
        assert_eq!((f.length_min, f.length_max), (100, 200));
        assert_eq!((f.interval_min, f.interval_max), (10, 20));
        assert_eq!((f.max_split_min, f.max_split_max), (0, 0), "maxSplit 可缺省");

        let f = Fragment::from_json(&serde_json::json!({
            "packets": "1-3", "length": "10-20", "interval": "1-2", "maxSplit": 2
        }))
        .expect("区间键形");
        assert_eq!((f.packets_from, f.packets_to), (1, 3));
        assert_eq!((f.max_split_min, f.max_split_max), (2, 2));
    }

    #[test]
    fn fragment_go_keys_errors_match_go() {
        let e = Fragment::from_json(&serde_json::json!({"packets": "1-3", "interval": "1-2"}))
            .unwrap_err();
        assert!(e.to_string().contains("Length can't be empty"), "{e}");

        let e = Fragment::from_json(&serde_json::json!({"packets": "1-3", "length": "10-20"}))
            .unwrap_err();
        assert!(e.to_string().contains("Interval can't be empty"), "{e}");

        let e = Fragment::from_json(
            &serde_json::json!({"packets": "0-3", "length": "1-2", "interval": 1}),
        )
        .unwrap_err();
        assert!(e.to_string().contains("PacketsFrom can't be 0"), "{e}");
    }

    #[test]
    fn fragment_dialect_keys_still_parse() {
        // 存量方言（lengthMin/lengthMax 直给，interval 可缺省）。
        let f = Fragment::from_json(&serde_json::json!({"lengthMin": 10, "lengthMax": 20}))
            .expect("方言键形");
        assert_eq!((f.packets_from, f.packets_to), (0, 0), "全包分片");
        assert_eq!((f.length_min, f.length_max), (10, 20));
        assert_eq!((f.interval_min, f.interval_max), (0, 0));
    }

    #[test]
    fn noise_four_types_and_apply_to() {
        let n = Noise::from_json(&serde_json::json!({"type": "rand", "packet": "10-20"}))
            .expect("rand");
        assert_eq!((n.length_min, n.length_max), (10, 20));
        assert!(n.packet.is_empty());
        assert_eq!(n.apply_to, "ip", "缺省 applyTo = ip");

        let n =
            Noise::from_json(&serde_json::json!({"type": "str", "packet": " AA "})).expect("str");
        assert_eq!(n.packet, b"AA", "packet 两端空白按 Go TrimSpace 去掉");

        let n =
            Noise::from_json(&serde_json::json!({"type": "hex", "packet": "0aff"})).expect("hex");
        assert_eq!(n.packet, vec![0x0a, 0xff]);

        let n = Noise::from_json(&serde_json::json!({"type": "base64", "packet": "-_8"}))
            .expect("base64");
        assert_eq!(n.packet, vec![0xfb, 0xff]);

        let n = Noise::from_json(&serde_json::json!({
            "type": "str", "packet": "AA", "delay": "400-500", "applyTo": "IPv6"
        }))
        .expect("delay + applyTo");
        assert_eq!((n.delay_min, n.delay_max), (400, 500));
        assert_eq!(n.apply_to, "ipv6");

        let e = Noise::from_json(&serde_json::json!({"type": "bogus", "packet": "x"})).unwrap_err();
        assert!(e.to_string().contains("only rand/str/hex/base64"), "{e}");
        let e =
            Noise::from_json(&serde_json::json!({"type": "str", "applyTo": "ipv5"})).unwrap_err();
        assert!(e.to_string().contains("only ip/ipv4/ipv6"), "{e}");
    }

    #[test]
    fn noise_dialect_keys_still_parse() {
        let n =
            Noise::from_json(&serde_json::json!({"packet": "rand", "delayMin": 1})).expect("方言");
        assert!(n.packet.is_empty());
        assert_eq!(n.delay_min, 1);
    }

    // ===== RuleAction =====

    #[test]
    fn rule_action_roundtrip() {
        assert_eq!(RuleAction::from_proto_value(0), RuleAction::Allow);
        assert_eq!(RuleAction::from_proto_value(1), RuleAction::Block);
        assert_eq!(RuleAction::Allow.to_proto_value(), 0);
        assert_eq!(RuleAction::Block.to_proto_value(), 1);
    }

    // ===== DomainStrategy FORCE_* (v2q) =====

    #[test]
    fn domain_strategy_force_variants_from_i32() {
        // Go transport/internet/config.pb.go: DomainStrategy_FORCE_IP=6..FORCE_IP64=10
        assert_eq!(DomainStrategy::from_i32(6), DomainStrategy::ForceIP);
        assert_eq!(DomainStrategy::from_i32(7), DomainStrategy::ForceIPv4);
        assert_eq!(DomainStrategy::from_i32(8), DomainStrategy::ForceIPv6);
        assert_eq!(DomainStrategy::from_i32(9), DomainStrategy::ForceIPv4v6);
        assert_eq!(DomainStrategy::from_i32(10), DomainStrategy::ForceIPv6v4);
        assert_eq!(DomainStrategy::ForceIP as i32, 6);
        assert_eq!(DomainStrategy::ForceIPv6v4 as i32, 10);
    }

    /// Go config.go `strategy` 表第 0 列 == 2 → ForceIP()。
    #[test]
    fn domain_strategy_force_ip_flag() {
        for s in [
            DomainStrategy::AsIs,
            DomainStrategy::UseIP,
            DomainStrategy::UseIPv4,
            DomainStrategy::UseIPv6,
            DomainStrategy::UseIPv4v6,
            DomainStrategy::UseIPv6v4,
        ] {
            assert!(!s.force_ip(), "{s:?} is not force");
        }
        for s in [
            DomainStrategy::ForceIP,
            DomainStrategy::ForceIPv4,
            DomainStrategy::ForceIPv6,
            DomainStrategy::ForceIPv4v6,
            DomainStrategy::ForceIPv6v4,
        ] {
            assert!(s.force_ip(), "{s:?} is force");
            assert!(s.has_strategy(), "{s:?} has strategy");
        }
    }

    /// Go LookupForIP 的家族选择：PreferIP4/6 + FallbackIP4/6。
    #[test]
    fn domain_strategy_family_preference() {
        use DomainStrategy::*;
        // (strategy, prefer4, prefer6, fb4, fb6)
        // 注：Go config.go:110-116 — prefer=0（both）时 PreferIP4/6 都为 true。
        // strategy 表：UseIP/ForceIP 的 prefer 列 = 0 → prefer4=prefer6=true。
        let cases = [
            (UseIP, true, true, false, false),
            (UseIPv4, true, false, false, false),
            (UseIPv6, false, true, false, false),
            (UseIPv4v6, true, false, false, true),
            (UseIPv6v4, false, true, true, false),
            (ForceIP, true, true, false, false),
            (ForceIPv4, true, false, false, false),
            (ForceIPv6, false, true, false, false),
            (ForceIPv4v6, true, false, false, true),
            (ForceIPv6v4, false, true, true, false),
        ];
        for (s, p4, p6, f4, f6) in cases {
            assert_eq!(s.prefer_ipv4(), p4, "{s:?}.prefer_ipv4");
            assert_eq!(s.prefer_ipv6(), p6, "{s:?}.prefer_ipv6");
            assert_eq!(s.fallback_ipv4(), f4, "{s:?}.fallback_ipv4");
            assert_eq!(s.fallback_ipv6(), f6, "{s:?}.fallback_ipv6");
            assert_eq!(s.has_fallback(), f4 || f6, "{s:?}.has_fallback");
        }
        assert!(!AsIs.has_strategy());
    }

    /// Go config.go:110-116 PreferIP4()/PreferIP6()：prefer=0 时两个家族都视为优先。
    /// 与 `domain_strategy_family_preference` 中 UseIP/ForceIP 行同一断言，但显式
    /// 标"both"分组，对齐 Go 文档行为（bd 3ln）。
    #[test]
    fn domain_strategy_prefer_zero_means_both() {
        use DomainStrategy::*;
        // prefer=0（UseIP / ForceIP / AsIs）：v4/v6 均视为"优先"。
        for s in [UseIP, ForceIP] {
            assert!(s.prefer_ipv4(), "{s:?} prefer=0 → prefer_ipv4 true");
            assert!(s.prefer_ipv6(), "{s:?} prefer=0 → prefer_ipv6 true");
        }
        // AsIs：prefer=0 但 handler 层早退（has_strategy==false），不影响拨号过滤。
        // 测试仅验证方法语义（==0 时双 true），不约束 AsIs 在拨号层行为。
        assert!(AsIs.prefer_ipv4());
        assert!(AsIs.prefer_ipv6());
        // prefer=4 单边
        assert!(UseIPv4.prefer_ipv4() && !UseIPv4.prefer_ipv6());
        // prefer=6 单边
        assert!(!UseIPv6.prefer_ipv4() && UseIPv6.prefer_ipv6());
    }

    // ===== FinalRule::build =====

    #[test]
    fn build_rule_empty_networks_allows_all() {
        let cfg =
            FinalRuleConfig { action: RuleAction::Block, networks: vec![], ..Default::default() };
        let rule = FinalRule::build(&cfg).unwrap();
        assert!(rule.network.iter().all(|&v| v));
    }

    #[test]
    fn build_rule_specific_networks() {
        let cfg = FinalRuleConfig {
            action: RuleAction::Allow,
            networks: vec![0, 1], // TCP + UDP
            ..Default::default()
        };
        let rule = FinalRule::build(&cfg).unwrap();
        assert!(rule.network[0]); // TCP
        assert!(rule.network[1]); // UDP
        assert!(!rule.network[2]); // 其他
    }

    // ===== FinalRule::match_network =====

    #[test]
    fn match_network_in_range() {
        let rule = FinalRule {
            action: RuleAction::Allow,
            network: [true, false, false, false, false, false, false, false],
            port: None,
            ip: None,
            delay: None,
            log_level: None,
        };
        assert!(rule.match_network(0)); // TCP
        assert!(!rule.match_network(1)); // UDP
        assert!(!rule.match_network(99)); // 越界
    }

    // ===== FinalRule::match_port =====

    #[test]
    fn match_port_none_matches_all() {
        let rule = FinalRule {
            action: RuleAction::Allow,
            network: ALL_NETWORKS,
            port: None,
            ip: None,
            delay: None,
            log_level: None,
        };
        assert!(rule.match_port(80));
        assert!(rule.match_port(443));
    }

    #[test]
    fn match_port_list_restricts() {
        let rule = FinalRule {
            action: RuleAction::Allow,
            network: ALL_NETWORKS,
            port: Some(MemoryPortList::new(vec![PortRange::new(Port::new(80), Port::new(80))])),
            ip: None,
            delay: None,
            log_level: None,
        };
        assert!(rule.match_port(80));
        assert!(!rule.match_port(443));
    }

    // ===== FinalRule::match_ip / apply =====

    #[test]
    fn match_ip_none_matches_all_addresses() {
        let rule = FinalRule {
            action: RuleAction::Allow,
            network: ALL_NETWORKS,
            port: None,
            ip: None,
            delay: None,
            log_level: None,
        };
        assert!(rule.match_ip(Some("8.8.8.8".parse().unwrap())));
        assert!(rule.match_ip(Some("::1".parse().unwrap())));
        assert!(rule.match_ip(None)); // 无 IP 限制时域名也匹配
    }

    #[test]
    fn apply_full_match_no_ip_restriction() {
        let rule = FinalRule {
            action: RuleAction::Allow,
            network: [true, true, false, false, false, false, false, false],
            port: None,
            ip: None,
            delay: None,
            log_level: None,
        };
        assert!(rule.apply(0, 80, Some("1.2.3.4".parse().unwrap()))); // TCP:80
        assert!(rule.apply(1, 443, Some("1.2.3.4".parse().unwrap()))); // UDP:443
        assert!(!rule.apply(2, 80, Some("1.2.3.4".parse().unwrap()))); // 网络 2 不允许
    }

    // ===== build_default_rule / private IP blocking =====

    #[test]
    fn build_default_rule_block_private_blocks_rfc1918() {
        let rule = FinalRule::build_default_rule(DefaultRuleType::BlockPrivate);
        assert_eq!(rule.action, RuleAction::Block);
        assert!(rule.network.iter().all(|&v| v));
        // TCP:80
        let priv4: Option<IpAddr> = Some("10.0.0.1".parse().unwrap());
        assert!(rule.apply(0, 80, priv4), "10.0.0.1 should be blocked");
        assert!(
            rule.apply(0, 80, Some("192.168.1.1".parse().unwrap())),
            "192.168.1.1 should be blocked"
        );
        assert!(
            rule.apply(0, 80, Some("172.16.5.4".parse().unwrap())),
            "172.16.5.4 should be blocked"
        );
        assert!(
            rule.apply(0, 80, Some("127.0.0.1".parse().unwrap())),
            "127.0.0.1 should be blocked"
        );
        assert!(
            rule.apply(0, 80, Some("169.254.1.1".parse().unwrap())),
            "169.254.1.1 link-local should be blocked"
        );
        assert!(rule.apply(0, 80, Some("::1".parse().unwrap())), "::1 should be blocked");
    }

    #[test]
    fn build_default_rule_block_private_allows_public() {
        let rule = FinalRule::build_default_rule(DefaultRuleType::BlockPrivate);
        assert!(
            !rule.apply(0, 80, Some("8.8.8.8".parse().unwrap())),
            "8.8.8.8 should NOT be blocked"
        );
        assert!(
            !rule.apply(0, 443, Some("1.1.1.1".parse().unwrap())),
            "1.1.1.1 should NOT be blocked"
        );
        assert!(
            !rule.apply(0, 80, Some("2001:4860:4860::8888".parse().unwrap())),
            "public IPv6 should NOT be blocked"
        );
    }

    #[test]
    fn build_default_rule_block_all_blocks_everything() {
        let rule = FinalRule::build_default_rule(DefaultRuleType::BlockAll);
        assert_eq!(rule.action, RuleAction::Block);
        assert!(rule.ip.is_none(), "BlockAll has no IP matcher → matches all");
        assert!(rule.apply(0, 80, Some("8.8.8.8".parse().unwrap())));
        assert!(rule.apply(0, 80, Some("10.0.0.1".parse().unwrap())));
        assert!(rule.apply(0, 80, None), "BlockAll matches even non-IP");
    }

    #[test]
    fn config_rule_with_custom_cidr_blocks_matching_ip() {
        // 用户配置：Allow 除 8.8.8.0/24 外的所有 → 用 Block 规则覆盖。
        use xray_proto::xray::common::geodata::{Cidr, CidrRule, IpRule};
        let cfg = FinalRuleConfig {
            action: RuleAction::Block,
            networks: vec![],
            ip: vec![IpRule {
                value: Some(ip_rule::Value::Custom(CidrRule {
                    cidr: Some(Cidr { ip: vec![8, 8, 8, 0], prefix: 24 }),
                    reverse_match: false,
                })),
            }],
            ..Default::default()
        };
        let rule = FinalRule::build(&cfg).unwrap();
        assert!(rule.ip.is_some(), "custom CIDR rule builds a matcher");
        assert!(rule.apply(0, 80, Some("8.8.8.8".parse().unwrap())), "8.8.8.8 matches");
        assert!(!rule.apply(0, 80, Some("1.2.3.4".parse().unwrap())), "1.2.3.4 no match");
    }

    // ===== get_default_rule_type =====

    #[test]
    fn default_rule_for_known_protocols() {
        assert_eq!(get_default_rule_type("vless-reverse"), Some(DefaultRuleType::BlockAll));
        assert_eq!(get_default_rule_type("vless"), Some(DefaultRuleType::BlockPrivate));
        assert_eq!(get_default_rule_type("vmess"), Some(DefaultRuleType::BlockPrivate));
        assert_eq!(get_default_rule_type("trojan"), Some(DefaultRuleType::BlockPrivate));
        assert_eq!(get_default_rule_type("hysteria"), Some(DefaultRuleType::BlockPrivate));
        assert_eq!(get_default_rule_type("wireguard"), Some(DefaultRuleType::BlockPrivate));
        // bd uixeu：Go 26.11.9 `getDefaultFinalRule` 的 masque 分支
        assert_eq!(get_default_rule_type("masque"), Some(DefaultRuleType::BlockPrivate));
        assert_eq!(
            get_default_rule_type("shadowsocks-aes-256-gcm"),
            Some(DefaultRuleType::BlockPrivate)
        );
    }

    #[test]
    fn default_rule_for_unknown_protocol_is_none() {
        assert_eq!(get_default_rule_type("socks"), None);
        assert_eq!(get_default_rule_type("http"), None);
        assert_eq!(get_default_rule_type(""), None);
    }

    // ===== bd mwdf1：私有地址表对齐 Go common/geodata/consts.go =====

    /// 表内容与 Go 26.11.9 `consts.go:9-72` 逐条一致：条数 + 新增项 + 已删项。
    #[test]
    fn default_block_private_cidrs_match_go_table() {
        // Go 表 44 条有效项（注释掉的 8 条不计）
        assert_eq!(DEFAULT_BLOCK_PRIVATE_CIDRS.len(), 44, "{DEFAULT_BLOCK_PRIVATE_CIDRS:?}");
        for added in [
            "0.0.0.0/32",
            "192.0.0.0/29",
            "192.0.0.171/32",
            "240.0.0.0/4",
            "255.255.255.255/32",
            "64:ff9b:1::/48",
            "100:0:0:1::/64",
            "2001:30::/28",
            "2002::/16",
            "3fff::/20",
            "5f00::/16",
        ] {
            assert!(DEFAULT_BLOCK_PRIVATE_CIDRS.contains(&added), "missing {added}");
        }
        for removed in ["192.0.0.0/24", "192.88.99.0/24", "224.0.0.0/3", "::/127"] {
            assert!(!DEFAULT_BLOCK_PRIVATE_CIDRS.contains(&removed), "stale {removed}");
        }
    }

    /// `private_ip_matcher` 用 `filter_map` 建 matcher——任何一条解析失败会被**静默丢弃**
    /// （等于悄悄缩小阻止面）。逐条校验可解析。
    #[test]
    fn default_block_private_cidrs_all_parse() {
        for s in DEFAULT_BLOCK_PRIVATE_CIDRS {
            assert!(
                xray_geodata::rule_parser::parse_cidr(s).is_ok(),
                "unparseable default CIDR {s} (silently dropped by private_ip_matcher)"
            );
        }
    }

    /// 新表的实际命中面：新增段被拦、Go 已删段不再连带拦截。
    #[test]
    fn default_block_private_matcher_matches_go_table() {
        let rule = FinalRule::build_default_rule(DefaultRuleType::BlockPrivate);
        let blocked: &[&str] = &[
            "10.1.2.3",
            "192.0.0.3",       // 192.0.0.0/29
            "192.0.0.9",       // Port Control Protocol Anycast
            "192.0.2.1",       // TEST-NET-1
            "224.0.0.1",       // multicast
            "240.1.2.3",       // Reserved（新增）
            "255.255.255.255", // Limited Broadcast（新增）
            "::",
            "::1",
            "2001:db8::1",
            "2002::1",    // 6to4（新增）
            "3fff::1",    // Documentation（新增）
            "64:ff9b::1", // IPv4-IPv6 Translat.
        ];
        for ip in blocked {
            assert!(rule.apply(0, 80, Some(ip.parse().unwrap())), "{ip} must be blocked");
        }
        let allowed: &[&str] = &[
            "8.8.8.8",
            "1.1.1.1",
            "192.0.0.17", // 旧表 192.0.0.0/24 连带拦，Go 新表不收
            "::2",        // 旧表 ::/127 连带拦，Go 新表只收 :: 与 ::1
            "2001:4860:4860::8888",
            "2606:4700::1111",
        ];
        for ip in allowed {
            assert!(!rule.apply(0, 80, Some(ip.parse().unwrap())), "{ip} must be allowed");
        }
    }

    #[test]
    fn all_networks_constant() {
        assert!(ALL_NETWORKS.iter().all(|&v| v));
    }

    // ===== proto roundtrip =====

    #[test]
    fn proto_roundtrip_minimal() {
        let cfg = Config { user_level: 3, ..Default::default() };
        let proto = cfg.to_proto();
        let cfg2 = Config::from_proto(proto).unwrap();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn proto_roundtrip_with_fragment() {
        let cfg = Config {
            fragment: Some(Fragment {
                packets_from: 1,
                packets_to: 100,
                length_min: 100,
                length_max: 500,
                interval_min: 0,
                interval_max: 10,
                max_split_min: 2,
                max_split_max: 8,
            }),
            ..Default::default()
        };
        let proto = cfg.to_proto();
        let cfg2 = Config::from_proto(proto).unwrap();
        assert_eq!(cfg, cfg2);
    }

    // ===== destinationOverride 消费（Go :269-279 + isValidAddress）=====

    /// 本仓扩展键 `destinationOverride.server.{address,port}` 生效：改写地址与端口。
    #[test]
    fn destination_override_extension_keys_rewrite_target() {
        let ov = DestinationOverride::from_json(&serde_json::json!(
            {"server": {"address": "9.9.9.9", "port": 1080}}
        ))
        .expect("extension keys");
        let dest = Destination::tcp(Address::Domain("example.com".into()), Port::new(5900));
        let rewritten = apply_destination_override(&dest, Some(&ov));
        assert_eq!(rewritten.address(), &Address::IPv4("9.9.9.9".parse().unwrap()));
        assert_eq!(rewritten.port().value(), 1080);
        // 网络类型保持
        assert!(rewritten.is_tcp());
    }

    /// AnyIP（0.0.0.0 / ::）无效：地址不改写；port 0 不改写端口。
    #[test]
    fn destination_override_skips_anyip_and_zero_port() {
        let ov = DestinationOverride::from_json(&serde_json::json!(
            {"server": {"address": "0.0.0.0", "port": 0}}
        ))
        .expect("json");
        let dest = Destination::udp(Address::IPv4("8.8.8.8".parse().unwrap()), Port::new(53));
        let rewritten = apply_destination_override(&dest, Some(&ov));
        assert_eq!(rewritten, dest, "AnyIP + port 0 must not rewrite");
        // IPv6 Any
        let ov6 = DestinationOverride::from_json(&serde_json::json!(
            {"server": {"address": "::", "port": 1234}}
        ))
        .expect("json");
        let rewritten6 = apply_destination_override(&dest, Some(&ov6));
        assert_eq!(rewritten6.address(), dest.address(), ":: must not rewrite address");
        assert_eq!(rewritten6.port().value(), 1234, "valid port still applies");
    }

    /// 旧 Rust 方言（无 destinationOverride 键）→ None，不改写。
    #[test]
    fn destination_override_absent_is_identity() {
        let dest = Destination::tcp(Address::Domain("example.com".into()), Port::new(443));
        assert_eq!(apply_destination_override(&dest, None), dest);
    }

    // ===== redirect（Go `infra/conf/freedom.go:23,166-180`）=====

    /// `"host:port"` → 地址 + 端口都改写；`":port"` 只改写端口（Go 允许空 host）。
    #[test]
    fn redirect_parses_go_host_port_string() {
        let dest = Destination::tcp(Address::Domain("example.com".into()), Port::new(443));
        let ov = DestinationOverride::from_redirect("9.9.9.9:1080").expect("host:port");
        let rewritten = apply_destination_override(&dest, Some(&ov));
        assert_eq!(rewritten.address(), &Address::IPv4("9.9.9.9".parse().unwrap()));
        assert_eq!(rewritten.port().value(), 1080);

        // 空 host：Go `if len(host) > 0` 才赋 Address ⇒ 仅端口改写
        let port_only = DestinationOverride::from_redirect(":8080").expect("port only");
        let rewritten = apply_destination_override(&dest, Some(&port_only));
        assert_eq!(rewritten.address(), dest.address());
        assert_eq!(rewritten.port().value(), 8080);

        // IPv6 带括号（Go SplitHostPort 剥括号 + ParseAddress）
        let v6 = DestinationOverride::from_redirect("[::1]:1080").expect("ipv6");
        assert_eq!(
            apply_destination_override(&dest, Some(&v6)).address(),
            &Address::IPv6("::1".parse().unwrap())
        );
    }

    /// Go `Build` 拒启形态：缺端口 / 多冒号 / 空端口 / 非数字端口 / 超范围 / 缺 `]`。
    #[test]
    fn redirect_rejects_invalid_go_forms() {
        for bad in ["1.2.3.4", "::1:443", "host:", "host:http", "host:70000", "[::1]"] {
            let err = DestinationOverride::from_redirect(bad).expect_err(bad);
            assert!(err.to_string().contains("invalid redirect"), "{bad} → {err}");
        }
    }

    /// 双键并存：Go 键 `redirect` 优先；扩展键单独存在时仍生效（旧配置不失效）。
    #[test]
    fn redirect_wins_over_extension_key() {
        let both = serde_json::json!({
            "redirect": "1.1.1.1:8443",
            "destinationOverride": {"server": {"address": "9.9.9.9", "port": 1080}}
        });
        let ov = DestinationOverride::from_settings(&both).unwrap().expect("override");
        let dest = Destination::tcp(Address::Domain("example.com".into()), Port::new(443));
        let rewritten = apply_destination_override(&dest, Some(&ov));
        assert_eq!(rewritten.address(), &Address::IPv4("1.1.1.1".parse().unwrap()));
        assert_eq!(rewritten.port().value(), 8443, "Go 键 redirect 优先");

        // 只有扩展键 → 生效（兼容保留）
        let ext = serde_json::json!({
            "destinationOverride": {"server": {"address": "9.9.9.9", "port": 1080}}
        });
        let ov = DestinationOverride::from_settings(&ext).unwrap().expect("override");
        assert_eq!(apply_destination_override(&dest, Some(&ov)).port().value(), 1080);

        // 两者皆无 / redirect 空串 / null → 未配置
        for settings in [
            serde_json::json!({}),
            serde_json::json!({"redirect": ""}),
            serde_json::json!({"redirect": null}),
        ] {
            assert!(DestinationOverride::from_settings(&settings).unwrap().is_none(), "{settings}");
        }

        // redirect 非字符串 → 拒启（Go 解码 string 字段即失败）
        let bad = serde_json::json!({"redirect": {"server": {"port": 1}}});
        assert!(DestinationOverride::from_settings(&bad).is_err());
    }

    // ===== FinalRuleConfig JSON（Go FreedomFinalRuleConfig + Build）=====

    #[test]
    fn final_rule_from_json_full_fields() {
        let cfg = FinalRuleConfig::from_json(&serde_json::json!({
            "action": "block",
            "network": "tcp,udp",
            "port": "53,80-90",
            "ip": ["10.0.0.0/8", "192.168.1.1"],
            "delay": "30-90"
        }))
        .unwrap();
        assert_eq!(cfg.action, RuleAction::Block);
        assert_eq!(cfg.networks.len(), 2);
        let rule = FinalRule::build(&cfg).unwrap();
        // 10.x UDP 53 → 命中
        assert!(rule.apply(network_index(Network::UDP), 53, Some("10.1.2.3".parse().unwrap())));
        // 8.8.8.8 → 不在 IP 段 → 不命中
        assert!(!rule.apply(network_index(Network::UDP), 53, Some("8.8.8.8".parse().unwrap())));
        // 裸 IP → /32；端口不在列表 → 不命中
        assert!(!rule.apply(
            network_index(Network::TCP),
            443,
            Some("192.168.1.1".parse().unwrap())
        ));
        // delay 解析
        assert_eq!(cfg.delay.map(|r| (r.min, r.max)), Some((30, 90)));
        // 未写 logLevel 的 block 规则 → Info（Go 恒给非 nil 指针）
        assert_eq!(cfg.log_level, Some(xray_proto::xray::common::log::Severity::Info as i32));
    }

    /// 单条 IP 规则 JSON → 运行时规则。
    fn ip_rule_from_json(ip: &str) -> FinalRule {
        let cfg = FinalRuleConfig::from_json(&serde_json::json!({"action": "allow", "ip": [ip]}))
            .expect("valid final rule json");
        FinalRule::build(&cfg).expect("valid final rule")
    }

    /// bd 6g7k：CIDR 前缀边界表（含 /0 与主机位非零的归一化）。
    #[test]
    fn json_ip_rule_prefix_table() {
        // (规则, 目标 IP, 期望命中)
        let cases: &[(&str, &str, bool)] = &[
            ("0.0.0.0/0", "8.8.8.8", true),
            ("0.0.0.0/0", "0.0.0.0", true),
            ("0.0.0.0/0", "255.255.255.255", true),
            ("0.0.0.1/0", "192.0.2.1", true), // 主机位非零 + /0
            ("0.0.0.0/1", "127.0.0.1", true),
            ("0.0.0.0/1", "128.0.0.0", false),
            ("10.0.0.0/8", "10.255.255.255", true),
            ("10.0.0.0/8", "11.0.0.0", false),
            ("192.168.1.5/24", "192.168.1.200", true), // 非对齐地址 → 掩码归一化
            ("192.168.1.5/24", "192.168.2.1", false),
            ("192.168.1.5/24", "192.168.0.255", false),
            ("192.168.1.4/31", "192.168.1.5", true),
            ("192.168.1.4/31", "192.168.1.6", false),
            ("192.168.1.5", "192.168.1.5", true), // 裸 IP → /32
            ("192.168.1.5", "192.168.1.4", false),
            ("0.0.0.0/31", "0.0.0.1", true),
            ("0.0.0.0/32", "0.0.0.1", false),
            ("::/0", "2001:db8::1", true),
            ("::/0", "::1", true),
            ("::1/0", "2001:db8::5", true), // 非对齐 + v6 /0
            ("2001:db8::/32", "2001:db8:ffff::1", true),
            ("2001:db8::5/32", "2001:db8::1", true), // 非对齐 v6 → 掩码归一化
            ("2001:db8::/32", "2001:db9::1", false),
            ("2001:db8::1/127", "2001:db8::1", true),
            ("2001:db8::1/127", "2001:db8::3", false),
            ("2001:db8::1", "2001:db8::1", true), // 裸 v6 → /128
            ("2001:db8::1", "2001:db8::2", false),
        ];
        for &(rule_str, ip_str, expected) in cases {
            let rule = ip_rule_from_json(rule_str);
            let ip: IpAddr = ip_str.parse().expect("valid test ip");
            assert_eq!(rule.match_ip(Some(ip)), expected, "rule={rule_str} ip={ip_str}");
        }
    }

    /// /0 只覆盖本协议族：v4 /0 不命中 IPv6，v6 /0 不命中 IPv4。
    #[test]
    fn json_ip_rule_zero_prefix_stays_in_family() {
        assert!(!ip_rule_from_json("0.0.0.0/0").match_ip(Some("2001:db8::1".parse().unwrap())));
        assert!(!ip_rule_from_json("::/0").match_ip(Some("8.8.8.8".parse().unwrap())));
    }

    /// 逗号字符串形态（Go StringList）同样保留 /0：v4+v6 混合集合两族全放行。
    #[test]
    fn json_ip_rule_zero_prefix_string_list_mixed_families() {
        let cfg = FinalRuleConfig::from_json(
            &serde_json::json!({"action": "allow", "ip": "0.0.0.0/0, ::/0"}),
        )
        .unwrap();
        let rule = FinalRule::build(&cfg).unwrap();
        assert!(rule.match_ip(Some("8.8.8.8".parse().unwrap())));
        assert!(rule.match_ip(Some("2001:db8::1".parse().unwrap())));
    }

    /// 配置级：`finalRules: [{action: allow, ip: [0.0.0.0/0]}]` 覆盖默认 BlockPrivate。
    #[test]
    fn allow_zero_prefix_overrides_default_block_private() {
        let rule = ip_rule_from_json("0.0.0.0/0");
        let default = FinalRule::build_default_rule(DefaultRuleType::BlockPrivate);
        let dest = Destination::tcp(Address::IPv4("10.1.2.3".parse().unwrap()), Port::new(80));
        let matched = match_final_rules(std::slice::from_ref(&rule), Some(&default), &dest);
        assert_eq!(matched.map(|r| r.action), Some(RuleAction::Allow));
    }

    /// Go `infra/conf/freedom.go:290-293`：`delay` / `logLevel` 只对 block 规则生效，
    /// 出现在 allow 规则里是**配置错误**（不是忽略）。
    #[test]
    fn final_rule_allow_with_delay_or_log_level_is_error() {
        for rule in [
            serde_json::json!({"action": "allow", "delay": {"from": 5, "to": 9}}),
            // 弃用别名同样受限（Go 先 `c.Delay = c.BlockDelay` 再校验 action）
            serde_json::json!({"action": "allow", "blockDelay": {"from": 5, "to": 9}}),
            serde_json::json!({"action": "allow", "logLevel": "warning"}),
        ] {
            let e = FinalRuleConfig::from_json(&rule).unwrap_err();
            assert!(
                e.to_string().contains("only supported for block finalRules"),
                "unexpected error for {rule}: {e}"
            );
        }
        // allow 规则空 logLevel（Go 判 `!= ""`）不算设置
        let cfg =
            FinalRuleConfig::from_json(&serde_json::json!({"action": "allow", "logLevel": ""}))
                .expect("empty logLevel on allow rule is accepted");
        assert_eq!(cfg.action, RuleAction::Allow);
        assert_eq!((cfg.delay, cfg.log_level), (None, None));
        // 无 network 限制 = 全网络
        let rule = FinalRule::build(&cfg).unwrap();
        assert!(rule.match_network(network_index(Network::TCP)));
        assert!(rule.match_network(network_index(Network::UDP)));
    }

    // ===== bd uixeu：finalRules 的 delay / blockDelay / logLevel =====

    /// `delay` 为新键、`blockDelay` 为弃用别名；两者取值一致，同时出现时别名优先
    /// （Go `c.Delay = c.BlockDelay`）。
    #[test]
    fn final_rule_delay_and_block_delay_alias_equivalent() {
        let new = FinalRuleConfig::from_json(
            &serde_json::json!({"action": "block", "delay": {"from": 5, "to": 9}}),
        )
        .unwrap();
        let legacy = FinalRuleConfig::from_json(
            &serde_json::json!({"action": "block", "blockDelay": {"from": 5, "to": 9}}),
        )
        .unwrap();
        assert_eq!(new, legacy);
        assert_eq!(new.delay.map(|r| (r.min, r.max)), Some((5, 9)));

        // 同时出现 → blockDelay 覆盖 delay
        let both = FinalRuleConfig::from_json(&serde_json::json!({
            "action": "block",
            "delay": {"from": 5, "to": 9},
            "blockDelay": {"from": 10, "to": 20}
        }))
        .unwrap();
        assert_eq!(both.delay.map(|r| (r.min, r.max)), Some((10, 20)));

        // 运行时延时取自 delay（random roll 落在 [min, max] 闭区间）
        let rule = FinalRule::build(&both).unwrap();
        assert_eq!(rule.delay.map(|r| (r.min, r.max)), Some((10, 20)));
        for _ in 0..16 {
            let d = block_delay(&rule).as_secs();
            assert!((10..=20).contains(&d), "delay out of range: {d}");
        }

        // Go `Int32Range` 三形态：交换顺序 / 裸数字 / 非法硬错
        let swapped =
            FinalRuleConfig::from_json(&serde_json::json!({"action": "block", "delay": "90-30"}))
                .unwrap();
        assert_eq!(swapped.delay.map(|r| (r.min, r.max)), Some((30, 90)));
        let plain = FinalRuleConfig::from_json(&serde_json::json!({"action": "block", "delay": 5}))
            .unwrap();
        assert_eq!(plain.delay.map(|r| (r.min, r.max)), Some((5, 5)));
        assert!(
            FinalRuleConfig::from_json(&serde_json::json!({"action": "block", "delay": "abc"}))
                .is_err()
        );
    }

    /// `logLevel` 值域对齐 Go `freedom.go:302-317`；未知值硬错。
    #[test]
    fn final_rule_log_level_values_match_go() {
        use xray_proto::xray::common::log::Severity;
        let cases: &[(&str, Option<Severity>)] = &[
            ("", Some(Severity::Info)),
            ("info", Some(Severity::Info)),
            ("INFO", Some(Severity::Info)),
            ("none", Some(Severity::Unknown)),
            ("debug", Some(Severity::Debug)),
            ("warning", Some(Severity::Warning)),
            ("error", Some(Severity::Error)),
        ];
        for &(s, want) in cases {
            let cfg =
                FinalRuleConfig::from_json(&serde_json::json!({"action": "block", "logLevel": s}))
                    .unwrap_or_else(|e| panic!("logLevel={s}: {e}"));
            assert_eq!(cfg.log_level, want.map(|v| v as i32), "logLevel={s}");
        }
        let e = FinalRuleConfig::from_json(
            &serde_json::json!({"action": "block", "logLevel": "verbose"}),
        )
        .unwrap_err();
        assert!(e.to_string().contains("unknown finalRules.logLevel"), "{e}");
    }

    /// unset 级别 = Info、`none` = 不打日志（Go `FinalRule.log` 的 switch 无 Unknown 分支）。
    #[test]
    fn block_log_level_selects_severity() {
        use xray_proto::xray::common::log::Severity;
        let rule = FinalRule::build_default_rule(DefaultRuleType::BlockPrivate);
        assert_eq!(rule.log_level, Some(Severity::Warning as i32), "默认规则记 Warning");
        let configured = FinalRule::build(
            &FinalRuleConfig::from_json(
                &serde_json::json!({"action": "block", "logLevel": "none"}),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(configured.log_level, Some(Severity::Unknown as i32));
    }

    #[test]
    fn final_rule_unknown_action_is_error() {
        assert!(FinalRuleConfig::from_json(&serde_json::json!({"action": "drop"})).is_err());
        assert!(FinalRuleConfig::from_json(&serde_json::json!({})).is_err());
    }

    // ===== 索引口径（proto 值 Tcp=2/Udp=3）=====

    #[test]
    fn network_index_uses_proto_values() {
        assert_eq!(network_index(Network::TCP), 2);
        assert_eq!(network_index(Network::UDP), 3);
        assert_eq!(network_index(Network::Unix), 4);
    }
}
