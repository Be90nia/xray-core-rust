//! # Stream memory settings（对应 Go `transport/internet/memory_settings.go`）
//!
//! 集中描述 outbound/inbound 一次 dial/listen 所需的全部流设置：
//!
//! - 协议名（tcp / ws / grpc / ...）+ 安全层名（none / tls / reality）
//! - **TCP/UDP mask manager 配置块**（对应 Go `TcpmaskManager` / `UdpmaskManager`，
//!   当前阶段只持有 JSON-shaped entries，未实例化 manager 对象——运行时接线由各
//!   transport crate 负责）
//! - **QuicParams 配置块**（对应 Go `QuicParamsConfig` JSON 形态，
//!   `infra/conf/transport_internet.go:620-635`）
//! - **DownloadSettings 配置块**（splithttp 高级特性，下载流的嵌套 StreamConfig）
//!
//! ## 范围
//!
//! - 仅配置块定义 + JSON 解析。
//! - 不实例化真实 manager（`TcpmaskManager { tcpmasks: Vec<Box<dyn Tcpmask>> }` 等）
//!   ——运行时接线由各 transport crate 在自己的 dialer/listener 路径上做。
//! - proto 类型（`xray_proto::xray::transport::internet::StreamConfig`）本模块不直接
//!   依赖（`xray-transport` 当前无 `xray-proto` 依赖；引入是 YAGNI，按需后期再加）。
//!
//! ## Go 对照（file:line 锚点）
//!
//! - `transport/internet/memory_settings.go:9-20`：`MemoryStreamConfig` 结构
//! - `transport/internet/memory_settings.go:23-83`：`ToMemoryStreamConfig`
//! - `transport/internet/config.proto:44-65`：`StreamConfig` proto
//! - `transport/internet/config.proto:67-87`：`UdpHop` / `QuicParams` proto
//! - `infra/conf/transport_internet.go:620-635`：`QuicParamsConfig` JSON 字段
//! - `infra/conf/transport_internet.go:1977-1981`：`FinalMask{tcp, udp, quicParams}`
//! - `infra/conf/transport_internet.go:2138-2242`：Build() 装配 4 块的语义

use std::io;

/// 单条 mask 描述（对应 Go `infra/conf.Mask{Type, Settings}`）。
///
/// 与 Go `[]TypedMessage` 的差别：Rust 端全程 JSON，没有 protobuf 序列化，
/// 故保留 `{type, settings}` 二元结构而不引入 `serial.TypedMessage`。
#[derive(Debug, Clone, Default)]
pub struct MaskEntry {
    /// mask 类型名（`"mkcp-legacy"` / `"xdns"` / `"salamander"` / ...）。
    pub mask_type: String,
    /// mask 私有配置 JSON。
    pub settings: Option<serde_json::Value>,
}

/// TCP mask 链配置（对应 Go `FinalMask.Tcp []Mask` + `TcpmaskManager`）。
///
/// 非-goal：本结构只承载已解析的 entries，不构造 `Vec<Box<dyn Tcpmask>>`。
#[derive(Debug, Clone, Default)]
pub struct TcpmaskManagerConfig {
    pub masks: Vec<MaskEntry>,
}

/// UDP mask 链配置（对应 Go `FinalMask.Udp []Mask` + `UdpmaskManager`）。
///
/// 非-goal：本结构只承载已解析的 entries，不构造 `Vec<Box<dyn Udpmask>>`。
#[derive(Debug, Clone, Default)]
pub struct UdpmaskManagerConfig {
    pub masks: Vec<MaskEntry>,
}

/// UDP 跳端口 + 区间配置（对应 Go `QuicParamsConfig.UdpHop` JSON）。
///
/// Go 字段是 `UdpHop { Ports []uint32, IntervalMin int64, IntervalMax int64 }`，
/// JSON 形态 ports 是 list/range，interval 是 `{from, to}`。本结构保留 JSON
/// 形状而非 proto 形状，方便后续 to_proto() 一站式转换。
#[derive(Debug, Clone, Default)]
pub struct UdpHopConfig {
    pub ports: Vec<u32>,
    pub interval_min: i64,
    pub interval_max: i64,
}

/// QUIC 流参数配置块（对应 Go `QuicParamsConfig` JSON 形态）。
///
/// 字段集合与 `infra/conf/transport_internet.go:620-635` 一致；缺省字段为
/// `Default` 的零值。校验（>= 16384、timeout 区间等）由 Build() 在 conf 层
/// 处理，本模块宽容解析——与现有 `xray-transport/src/dialer.rs::from_json`
/// 风格一致。
#[derive(Debug, Clone, Default)]
pub struct QuicParamsConfig {
    pub congestion: String,
    pub debug: bool,
    pub bbr_profile: String,
    /// 上行带宽字符串（`"100 mbps"` 等），带宽解析在 conf 层做；
    /// 本结构保留原始字符串供下游解析。
    pub brutal_up: String,
    pub brutal_down: String,
    /// Brutal 丢包补偿开关（Go `transport_finalmask.go:999` json `brutalDisableLossCompensation`；
    /// splithttp/hysteria dialer `UseBrutal` 第三参消费）。
    pub brutal_disable_loss_compensation: bool,
    pub udp_hop: UdpHopConfig,
    pub init_stream_receive_window: u64,
    pub max_stream_receive_window: u64,
    pub init_connection_receive_window: u64,
    pub max_connection_receive_window: u64,
    pub max_idle_timeout: i64,
    pub keep_alive_period: i64,
    pub disable_path_mtu_discovery: bool,
    pub max_incoming_streams: i64,
}

/// DownloadSettings 配置块（对应 Go `splithttp.Config.DownloadSettings`）。
///
/// 下载流的嵌套 `StreamConfig`：当 splithttp 用 `stream-up` 模式时，
/// 会有一个独立的 StreamConfig 描述下载流。本结构递归引用
/// [`MemoryStreamConfig`]，与 Go `MemoryStreamConfig.DownloadSettings` 同构。
#[derive(Debug, Clone, Default)]
pub struct DownloadSettingsConfig {
    pub inner: Box<MemoryStreamConfig>,
}

/// 流的内存形态（对应 Go `transport/internet.MemoryStreamConfig`）。
///
/// 集中描述 outbound/inbound 一次 dial/listen 所需的全部上下文；
/// 与 [`crate::dialer::StreamSettings`] 的差别：后者是 JSON-shaped 配置原语
/// （每个 transport crate 自己 `serde_json::from_value` 强转），本结构是
/// 已经过 Go `ToMemoryStreamConfig` 等价物解析的 memory 形态。
#[derive(Debug, Clone, Default)]
pub struct MemoryStreamConfig {
    pub protocol_name: String,
    pub security_type: String,
    pub tcpmask_manager: Option<TcpmaskManagerConfig>,
    pub udpmask_manager: Option<UdpmaskManagerConfig>,
    pub quic_params: Option<QuicParamsConfig>,
    pub download_settings: Option<DownloadSettingsConfig>,
}

/// JSON → [`MemoryStreamConfig`] 转换器（对应 Go `ToMemoryStreamConfig`）。
///
/// `json = None` → 返回 `protocol_name = "tcp"` 的默认 config（与 Go `nil` 输入
/// 等价：dialer.go:51 `ToMemoryStreamConfig(nil)`）。
///
/// # Errors
///
/// - `InvalidInput`：JSON 不是 object、字段类型不匹配。
///
/// # 范围
///
/// 仅解析 4 配置块（`tcp[]` / `udp[]` / `quicParams` / `downloadSettings`）。
/// `protocol_name` / `security_type` 来自顶层 `network` / `security` 字段，
/// 与 `StreamSettings::from_json` 字段约定一致（dialer.rs:139-140）。
pub fn to_memory_stream_config(json: Option<&serde_json::Value>) -> io::Result<MemoryStreamConfig> {
    let Some(v) = json else {
        return Ok(MemoryStreamConfig { protocol_name: "tcp".to_string(), ..Default::default() });
    };
    let obj = v.as_object().ok_or_else(|| invalid("streamSettings: expected an object"))?;
    let protocol_name = obj.get("network").and_then(|n| n.as_str()).unwrap_or("tcp").to_string();
    let security_type = obj.get("security").and_then(|s| s.as_str()).unwrap_or("").to_string();
    let finalmask = obj.get("finalmask");
    let tcpmask_manager = parse_tcpmask_manager(finalmask.and_then(|f| f.get("tcp")))?;
    let udpmask_manager = parse_udpmask_manager(finalmask.and_then(|f| f.get("udp")))?;
    let quic_params = parse_quic_params_config(finalmask.and_then(|f| f.get("quicParams")))?;
    let download_settings = parse_download_settings(obj.get("downloadSettings"))?;
    Ok(MemoryStreamConfig {
        protocol_name,
        security_type,
        tcpmask_manager,
        udpmask_manager,
        quic_params,
        download_settings,
    })
}

fn parse_tcpmask_manager(v: Option<&serde_json::Value>) -> io::Result<Option<TcpmaskManagerConfig>> {
    let Some(arr) = v.and_then(|v| v.as_array()) else { return Ok(None) };
    let mut masks = Vec::with_capacity(arr.len());
    for entry in arr {
        masks.push(parse_mask_entry(entry)?);
    }
    Ok(Some(TcpmaskManagerConfig { masks }))
}

fn parse_udpmask_manager(v: Option<&serde_json::Value>) -> io::Result<Option<UdpmaskManagerConfig>> {
    let Some(arr) = v.and_then(|v| v.as_array()) else { return Ok(None) };
    let mut masks = Vec::with_capacity(arr.len());
    for entry in arr {
        masks.push(parse_mask_entry(entry)?);
    }
    Ok(Some(UdpmaskManagerConfig { masks }))
}

fn parse_mask_entry(v: &serde_json::Value) -> io::Result<MaskEntry> {
    let obj = v.as_object().ok_or_else(|| invalid("mask: expected an object"))?;
    let mask_type = obj.get("type").and_then(|t| t.as_str())
        .ok_or_else(|| invalid("mask: missing `type`"))?.to_string();
    let settings = obj.get("settings").cloned();
    Ok(MaskEntry { mask_type, settings })
}

/// 解析 `finalmask.quicParams` JSON 节点（宽容解析，校验由下游 CC 接线做，
/// 对齐 Go `infra/conf` Build() 语义的调用点在 splithttp H3 dialer / hysteria）。
pub fn parse_quic_params_config(
    v: Option<&serde_json::Value>,
) -> io::Result<Option<QuicParamsConfig>> {
    let Some(obj) = v else { return Ok(None) };
    let obj = obj.as_object().ok_or_else(|| invalid("quicParams: expected an object"))?;
    let get_str = |k: &str| obj.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let get_u64 = |k: &str| obj.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
    let get_i64 = |k: &str| obj.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
    let get_bool = |k: &str| obj.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    let udp_hop = parse_udp_hop(obj.get("udpHop"))?;
    Ok(Some(QuicParamsConfig {
        congestion: get_str("congestion"),
        debug: get_bool("debug"),
        bbr_profile: get_str("bbrProfile"),
        brutal_up: get_str("brutalUp"),
        brutal_down: get_str("brutalDown"),
        brutal_disable_loss_compensation: get_bool("brutalDisableLossCompensation"),
        udp_hop,
        init_stream_receive_window: get_u64("initStreamReceiveWindow"),
        max_stream_receive_window: get_u64("maxStreamReceiveWindow"),
        init_connection_receive_window: get_u64("initConnectionReceiveWindow"),
        max_connection_receive_window: get_u64("maxConnectionReceiveWindow"),
        max_idle_timeout: get_i64("maxIdleTimeout"),
        keep_alive_period: get_i64("keepAlivePeriod"),
        disable_path_mtu_discovery: get_bool("disablePathMtuDiscovery"),
        max_incoming_streams: get_i64("maxIncomingStreams"),
    }))
}

fn parse_udp_hop(v: Option<&serde_json::Value>) -> io::Result<UdpHopConfig> {
    let Some(obj) = v else { return Ok(UdpHopConfig::default()) };
    let obj = obj.as_object().ok_or_else(|| invalid("udpHop: expected an object"))?;
    // ports: list/range → flatten to Vec<u32>（Go PortList.Build().Ports()）
    let ports = match obj.get("ports") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(v) => parse_port_list(v)?,
    };
    // interval: {from, to} → (i64, i64)
    let (interval_min, interval_max) = parse_int32_range(obj.get("interval"))
        .unwrap_or((0, 0));
    Ok(UdpHopConfig { ports, interval_min, interval_max })
}
fn parse_port_list(v: &serde_json::Value) -> io::Result<Vec<u32>> {
    // Go PortList 形态：string `"443,8000-8002"`（common.go:243-275），
    // 内部 items 是 int 单端口或 "from-to" 区间，"," 分隔。
    // 也支持 JSON number（单端口速记）/ array（向后兼容）。
    let mut out = Vec::new();
    if let Some(s) = v.as_str() {
        for item in s.split(',') {
            let t = item.trim();
            if t.is_empty() { continue; }
            if let Some(idx) = t.find('-') {
                let from_s = &t[..idx];
                let to_s = &t[idx + 1..];
                let from: u32 = from_s.parse().map_err(|_| invalid(format!("ports: invalid range start {from_s:?}")))?;
                let to: u32 = to_s.parse().map_err(|_| invalid(format!("ports: invalid range end {to_s:?}")))?;
                if from > to { return Err(invalid(format!("ports: range start > end ({from}>{to})"))); }
                for p in from..=to {
                    out.push(p);
                }
            } else {
                let p: u32 = t.parse().map_err(|_| invalid(format!("ports: invalid port {t:?}")))?;
                out.push(p);
            }
        }
        return Ok(out);
    }
    if let Some(n) = v.as_u64() {
        if n > u32::MAX as u64 { return Err(invalid("ports: out of u32 range")); }
        return Ok(vec![n as u32]);
    }
    let arr = v.as_array().ok_or_else(|| invalid("ports: expected string, number, or array"))?;
    for item in arr {
        match item {
            serde_json::Value::Number(n) => {
                let p = n.as_u64().ok_or_else(|| invalid("ports: not a u32"))?;
                if p > u32::MAX as u64 { return Err(invalid("ports: out of u32 range")); }
                out.push(p as u32);
            }
            serde_json::Value::Object(_) => {
                let (from, to) = parse_int32_range(Some(item))?;
                if from < 0 || to < 0 || from > u32::MAX as i64 || to > u32::MAX as i64 {
                    return Err(invalid("ports: range out of u32 range"));
                }
                for p in from.max(0) as u32..=to.max(0) as u32 {
                    out.push(p);
                }
            }
            _ => return Err(invalid("ports: expected number or {from,to} object")),
        }
    }
    Ok(out)
}

fn parse_int32_range(v: Option<&serde_json::Value>) -> io::Result<(i64, i64)> {
    let Some(v) = v else { return Ok((0, 0)) };
    match v {
        serde_json::Value::Number(n) => {
            let x = n.as_i64().ok_or_else(|| invalid("range: not an i64"))?;
            Ok((x, x))
        }
        serde_json::Value::Object(o) => {
            let from = o.get("from").and_then(|v| v.as_i64()).unwrap_or(0);
            let to = o.get("to").and_then(|v| v.as_i64()).unwrap_or(from);
            Ok((from, to))
        }
        serde_json::Value::Null => Ok((0, 0)),
        _ => Err(invalid("range: expected number or {from,to} object")),
    }
}

fn parse_download_settings(v: Option<&serde_json::Value>) -> io::Result<Option<DownloadSettingsConfig>> {
    let Some(inner) = v else { return Ok(None) };
    let inner = to_memory_stream_config(Some(inner))?;
    Ok(Some(DownloadSettingsConfig { inner: Box::new(inner) }))
}

fn invalid(msg: impl AsRef<str>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.as_ref().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ===== 默认值 =====

    #[test]
    fn default_none_yields_tcp_no_security() {
        let m = to_memory_stream_config(None).expect("None -> default");
        assert_eq!(m.protocol_name, "tcp");
        assert_eq!(m.security_type, "");
        assert!(m.tcpmask_manager.is_none());
        assert!(m.udpmask_manager.is_none());
        assert!(m.quic_params.is_none());
        assert!(m.download_settings.is_none());
    }

    #[test]
    fn default_empty_object_yields_tcp_no_security() {
        let m = to_memory_stream_config(Some(&json!({}))).expect("empty obj -> default");
        assert_eq!(m.protocol_name, "tcp");
        assert_eq!(m.security_type, "");
        assert!(m.tcpmask_manager.is_none());
    }

    #[test]
    fn default_protocol_security_from_top_level() {
        let m = to_memory_stream_config(Some(&json!({
            "network": "splithttp",
            "security": "reality"
        }))).expect("ok");
        assert_eq!(m.protocol_name, "splithttp");
        assert_eq!(m.security_type, "reality");
    }

    // ===== TcpmaskManager 解析（bd 44s 第 1 块）=====

    #[test]
    fn tcpmask_manager_parses_array() {
        let m = to_memory_stream_config(Some(&json!({
            "finalmask": {
                "tcp": [
                    { "type": "mkcp-legacy", "settings": { "header": "dns", "value": "x.com" } },
                    { "type": "xdns" }
                ]
            }
        }))).expect("ok");
        let tm = m.tcpmask_manager.expect("tcpmask_manager");
        assert_eq!(tm.masks.len(), 2);
        assert_eq!(tm.masks[0].mask_type, "mkcp-legacy");
        assert_eq!(tm.masks[0].settings.as_ref().unwrap().get("header").unwrap(), "dns");
        assert_eq!(tm.masks[1].mask_type, "xdns");
        assert!(tm.masks[1].settings.is_none());
    }

    #[test]
    fn tcpmask_manager_absent_yields_none() {
        let m = to_memory_stream_config(Some(&json!({}))).unwrap();
        assert!(m.tcpmask_manager.is_none());
        let m = to_memory_stream_config(Some(&json!({"finalmask": {}}))).unwrap();
        assert!(m.tcpmask_manager.is_none());
        let m = to_memory_stream_config(Some(&json!({"finalmask": {"tcp": []}}))).unwrap();
        assert!(m.tcpmask_manager.is_some_and(|t| t.masks.is_empty()));
    }

    // ===== UdpmaskManager 解析（bd 44s 第 2 块）=====

    #[test]
    fn udpmask_manager_parses_array() {
        let m = to_memory_stream_config(Some(&json!({
            "finalmask": {
                "udp": [
                    { "type": "salamander", "settings": { "key": "abc" } }
                ]
            }
        }))).expect("ok");
        let um = m.udpmask_manager.expect("udpmask_manager");
        assert_eq!(um.masks.len(), 1);
        assert_eq!(um.masks[0].mask_type, "salamander");
        assert_eq!(um.masks[0].settings.as_ref().unwrap().get("key").unwrap(), "abc");
    }

    #[test]
    fn udpmask_manager_absent_yields_none() {
        let m = to_memory_stream_config(Some(&json!({}))).unwrap();
        assert!(m.udpmask_manager.is_none());
    }

    // ===== QuicParams 解析（bd 44s 第 3 块）=====

    #[test]
    fn quic_params_parses_all_fields() {
        let m = to_memory_stream_config(Some(&json!({
            "finalmask": {
                "quicParams": {
                    "congestion": "Brutal",
                    "debug": true,
                    "bbrProfile": "Aggressive",
                    "brutalUp": "100 mbps",
                    "brutalDown": "50 mbps",
                    "brutalDisableLossCompensation": true,
                    "udpHop": {
                        "ports": "443,8000-8002",
                        "interval": { "from": 10, "to": 30 }
                    },
                    "initStreamReceiveWindow": 16384,
                    "maxStreamReceiveWindow": 32768,
                    "initConnectionReceiveWindow": 49152,
                    "maxConnectionReceiveWindow": 65536,
                    "maxIdleTimeout": 30,
                    "keepAlivePeriod": 10,
                    "disablePathMtuDiscovery": true,
                    "maxIncomingStreams": 64
                }
            }
        }))).expect("ok");
        let q = m.quic_params.expect("quic_params");
        assert_eq!(q.congestion, "Brutal");
        assert!(q.debug);
        assert_eq!(q.bbr_profile, "Aggressive");
        assert_eq!(q.brutal_up, "100 mbps");
        assert_eq!(q.brutal_down, "50 mbps");
        // Go transport_finalmask.go:999 json `brutalDisableLossCompensation`
        assert!(q.brutal_disable_loss_compensation);
        assert_eq!(q.udp_hop.ports, vec![443, 8000, 8001, 8002]);
        assert_eq!(q.udp_hop.interval_min, 10);
        assert_eq!(q.udp_hop.interval_max, 30);
        assert_eq!(q.init_stream_receive_window, 16384);
        assert_eq!(q.max_stream_receive_window, 32768);
        assert_eq!(q.init_connection_receive_window, 49152);
        assert_eq!(q.max_connection_receive_window, 65536);
        assert_eq!(q.max_idle_timeout, 30);
        assert_eq!(q.keep_alive_period, 10);
        assert!(q.disable_path_mtu_discovery);
        assert_eq!(q.max_incoming_streams, 64);
    }

    #[test]
    fn quic_params_defaults_when_absent() {
        let m = to_memory_stream_config(Some(&json!({}))).unwrap();
        assert!(m.quic_params.is_none());
        let m = to_memory_stream_config(Some(&json!({"finalmask": {}}))).unwrap();
        assert!(m.quic_params.is_none());
        // 空对象 → 全 default（congestion="" 等）
        let m = to_memory_stream_config(Some(&json!({"finalmask": {"quicParams": {}}}))).unwrap();
        let q = m.quic_params.unwrap();
        assert_eq!(q.congestion, "");
        assert!(!q.debug);
        assert_eq!(q.udp_hop.ports, Vec::<u32>::new());
        assert_eq!(q.init_stream_receive_window, 0);
    }

    #[test]
    fn quic_params_udp_hop_with_only_ports() {
        let m = to_memory_stream_config(Some(&json!({
            "finalmask": {"quicParams": {"udpHop": {"ports": [443]}}}
        }))).unwrap();
        let q = m.quic_params.unwrap();
        assert_eq!(q.udp_hop.ports, vec![443]);
        assert_eq!(q.udp_hop.interval_min, 0);
        assert_eq!(q.udp_hop.interval_max, 0);
    }

    // ===== DownloadSettings 解析（bd 44s 第 4 块）=====

    #[test]
    fn download_settings_parses_nested_stream_config() {
        let m = to_memory_stream_config(Some(&json!({
            "network": "splithttp",
            "security": "tls",
            "downloadSettings": {
                "network": "splithttp",
                "security": "none",
                "finalmask": {
                    "udp": [
                        { "type": "salamander", "settings": { "key": "k" } }
                    ]
                }
            }
        }))).expect("ok");
        let dl = m.download_settings.expect("download_settings");
        assert_eq!(dl.inner.protocol_name, "splithttp");
        assert_eq!(dl.inner.security_type, "none");
        let um = dl.inner.udpmask_manager.as_ref().expect("inner udpmask_manager");
        assert_eq!(um.masks.len(), 1);
        assert_eq!(um.masks[0].mask_type, "salamander");
    }

    #[test]
    fn download_settings_absent_yields_none() {
        let m = to_memory_stream_config(Some(&json!({}))).unwrap();
        assert!(m.download_settings.is_none());
    }

    // ===== 错误路径 =====

    #[test]
    fn non_object_top_level_returns_error() {
        let v = json!("not-an-object");
        let r = to_memory_stream_config(Some(&v));
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn mask_entry_missing_type_returns_error() {
        let v = json!({"finalmask": {"tcp": [{"settings": {}}]}});
        let r = to_memory_stream_config(Some(&v));
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn quic_params_non_object_returns_error() {
        let v = json!({"finalmask": {"quicParams": "bad"}});
        let r = to_memory_stream_config(Some(&v));
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
}