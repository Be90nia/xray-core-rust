//! QUIC 传输配置。
//!
//! 对应 Go `transport/internet/quic/config.go::Config`。
//! 解析安全层（TLS）所需的字段 + 拥塞控制（`congestion`）。

use std::{io, sync::Arc};

/// 缺省流接收窗（bd wz2b W4：quinn 缺省流收窗 1.25MB STREAM_RWND 高 BDP 钉
/// 1.25MB/RTT@169ms≈7.4MB/s；缺省显式 16MB，与 h2 族同值）。
const DEFAULT_STREAM_RECEIVE_WINDOW: u64 = 16 * 1024 * 1024;
/// 缺省连接接收窗（与 splithttp/grpc h2 连接窗同值）。
const DEFAULT_CONNECTION_RECEIVE_WINDOW: u64 = 32 * 1024 * 1024;
/// 缺省空闲超时（毫秒）。Go `transport/internet/quic/dialer.go`（v26 移除前）硬编码
/// `MaxIdleTimeout: 300s`——quinn 缺省 30s 会把长空闲会话早抬重付握手。
const DEFAULT_MAX_IDLE_TIMEOUT_MS: u64 = 300_000;

/// QUIC 配置。
///
/// Go 端字段对照：
/// - `header` / `key`：obfuscation（未实现，quinn 不支持 header obfuscation）
/// - `security` / `tlsSettings`：通过 `StreamSettings.security_json` 承载，本结构不重复存储
/// - `congestion`：拥塞控制算法字面值（Go `infra/conf/transport_internet.go:245-253`）：
///   `""`/`"brutal"`/`"reno"`/`"bbr"` 合法；`"force-brutal"` 需 brutalUp>0（本层
///   无该字段，恒报错）；未知值硬错（文案同 Go）
/// - `keepAlive`：QUIC keepalive 周期（与 Go `keep_alive` 同义；quinn 端叫 keep_alive_period）
/// - `initialStreamReceiveWindow` / `maxStreamReceiveWindow`：流接收窗口两级 （quinn 单固定窗口 →
///   取 max 对齐 Go Initial/Max 稳态）
/// - `initialConnectionReceiveWindow` / `maxConnectionReceiveWindow`：连接级窗口
/// - `maxIdleTimeout` / `keepAlivePeriod`：秒（quinn 内部 ms，乘 1000）
/// - `disablePathMtuDiscovery`：true 禁用 PMTUD
/// - `maxIncomingStreams`：最大并发入站双向流（-1 = 不设上限）
/// - `initialMtu`：初始 MTU（0 = quinn 缺省 1200；bd ut95o B7 试验项）
/// - `disableSendFairness`：true 关闭同优先级流间发送公平调度（bd ut95o B7 试验项）
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicConfig {
    /// 是否启用 keep-alive（对应 Go `keep_alive`，默认 false）。
    pub keep_alive: bool,
    /// 拥塞控制算法（对应 Go `QuicParams.congestion`，解析期小写归一）。
    ///
    /// `"bbr"` → quinn BBR；`"reno"` → quinn NewReno；`""`/`"brutal"` → CUBIC
    /// （brutal 发送器仅 hysteria 路径有真实现，本 crate 落 CUBIC 登记）。未知值解析期报错。
    pub congestion: String,
    /// 流接收窗口（字节）。qeyo：quinn 单固定窗口取 max(initial, max) 对齐 Go 稳态。
    /// 0 = 缺省显式 16MB（bd wz2b W4；原 quinn 默认 1.25MB STREAM_RWND 高 BDP 钉）。
    pub stream_receive_window: u64,
    /// 连接级接收窗口（字节）。qeyo：同上。0 = 缺省显式 32MB（bd wz2b W4）。
    pub connection_receive_window: u64,
    /// 最大空闲超时（毫秒；0 = 缺省 300s，对齐 Go quic dialer 硬编码值）。
    pub max_idle_timeout_ms: u64,
    /// keep-alive 周期（毫秒；0 = 禁用）。
    pub keep_alive_period_ms: u64,
    /// true 禁用 PMTUD（Go 默认非 Linux/Win/Mac = true）。
    pub disable_path_mtu_discovery: bool,
    /// 最大并发入站双向流（-1 = 不设上限 → quinn::VarInt::MAX）。
    pub max_incoming_streams: i64,
    /// true 禁用 UDP 发送 GSO（Go `QuicParams.disableGSO`，默认 false = 启用）。
    pub disable_gso: bool,
    /// 初始 MTU（`quicSettings.initialMtu`，字节；bd ut95o B7 试验项）。0 = 不设，
    /// 沿用 quinn 缺省 1200；显式值须 ≥1200（quinn setter 内部静默 `.max(1200)` 钳制，
    /// 解析层提前硬错防配置笔误静默失效）与 ≤65535（quinn `u16` 上限）。抬初始 MTU
    /// 可缩短高 BDP 路径的慢启动爬坡；路径 MTU 探测（默认启用）发现黑洞后自动回退。
    pub initial_mtu: u16,
    /// true 关闭同优先级流间发送公平调度（`quicSettings.disableSendFairness`，
    /// bd ut95o B7 试验项）。quinn 缺省 `send_fairness: true` = 轮转调度；tuic/hysteria
    /// 类 relay 场景每连接大量小流，关闭后按写入顺序发送，降低分片与协议开销。
    pub disable_send_fairness: bool,
}

impl QuicConfig {
    /// 从 `quicSettings` JSON 解析。
    ///
    /// `None` 或非 object 返回 [`QuicConfig::default`]（非 object 返回 Err）。
    ///
    /// # Errors
    /// JSON 非 object → [`InvalidData`](io::ErrorKind::InvalidData)。
    pub fn from_json(json: Option<&serde_json::Value>) -> io::Result<Self> {
        let Some(v) = json else {
            return Ok(Self::default());
        };
        let Some(obj) = v.as_object() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "quicSettings must be a JSON object",
            ));
        };
        let keep_alive = obj.get("keepAlive").and_then(|x| x.as_bool()).unwrap_or(false);
        // congestion 字面值校验（Go infra/conf/transport_internet.go:245-253）：小写归一，
        // ""/brutal/reno/bbr 合法直通；force-brutal 需 QuicParams.brutalUp>0——本层
        // （quicSettings）无 brutalUp 字段，忠实映射 Go up==0 分支恒报错；未知值硬错。
        let congestion =
            obj.get("congestion").and_then(|x| x.as_str()).unwrap_or("").to_ascii_lowercase();
        match congestion.as_str() {
            "" | "brutal" | "reno" | "bbr" => {},
            "force-brutal" => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "force-brutal requires up"));
            },
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unknown congestion control: {congestion}, valid values: reno, bbr, brutal, force-brutal"
                    ),
                ));
            },
        }
        // qeyo：finalmask.quicParams 也可承载窗口/idle/keepalive 字段（与 hysteria crate 同源
        // QuicParamsConfig 解析——finalmask 路径走 memory_settings.rs::parse_quic_params_config，
        // 直接 quicSettings 路径走这里）。两个入口字段名一致。
        // quicSettings 直接路径：用户内联在 quicConfig.settings 内。
        let get_u64 = |k: &str| obj.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        let get_i64 = |k: &str| obj.get(k).and_then(|v| v.as_i64()).unwrap_or(-1);
        let get_bool = |k: &str| obj.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
        // 两级窗口取 max（quinn 单固定窗口对齐 Go 稳态）。
        let init_stream = get_u64("initStreamReceiveWindow");
        let max_stream = get_u64("maxStreamReceiveWindow");
        let stream_win = init_stream.max(max_stream);
        let init_conn = get_u64("initConnectionReceiveWindow");
        let max_conn = get_u64("maxConnectionReceiveWindow");
        let conn_win = init_conn.max(max_conn);
        // maxIdleTimeout 秒 → 毫秒（0 = 不设 → quinn 默认 30s）
        let max_idle = get_u64("maxIdleTimeout");
        let max_idle_ms = if max_idle == 0 { 0 } else { max_idle * 1000 };
        // keepAlivePeriod 秒 → 毫秒
        let keep_period = get_u64("keepAlivePeriod");
        let keep_period_ms = if keep_period == 0 { 0 } else { keep_period * 1000 };
        // bd ut95o B7：initialMtu（0 = quinn 缺省 1200，不设）；显式值硬校验
        // 1200..=65535——quinn setter 内部 `.max(1200)` 静默钳制，这里 fail-visible
        // 拒绝笔误值而非让配置静默失效。
        let initial_mtu_raw = get_u64("initialMtu");
        let initial_mtu = if initial_mtu_raw == 0 {
            0
        } else {
            u16::try_from(initial_mtu_raw)
                .ok()
                .filter(|v| *v >= 1200)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "initialMtu must be 0 (quinn default) or within 1200..=65535, got {initial_mtu_raw}"
                        ),
                    )
                })?
        };
        Ok(Self {
            keep_alive,
            congestion,
            stream_receive_window: stream_win,
            connection_receive_window: conn_win,
            max_idle_timeout_ms: max_idle_ms,
            keep_alive_period_ms: keep_period_ms,
            disable_path_mtu_discovery: get_bool("disablePathMtuDiscovery"),
            max_incoming_streams: get_i64("maxIncomingStreams"),
            disable_gso: get_bool("disableGSO"),
            initial_mtu,
            disable_send_fairness: get_bool("disableSendFairness"),
        })
    }

    /// 构建 quinn `TransportConfig`（qeyo：完整 6 字段 + 拥塞控制）。
    ///
    /// `"bbr"` → quinn BBR；`"reno"` → quinn NewReno；`""`/`"brutal"` → CUBIC
    /// （解析层已保证字面值合法；`Default` 的 `""` 落 CUBIC 即 quinn 默认）。
    #[must_use]
    pub fn build_transport_config(&self) -> quinn::TransportConfig {
        let mut t = quinn::TransportConfig::default();
        // qeyo：流量控制窗口（Go Initial+Max → quinn 单固定窗口取 max 对齐稳态）。
        // bd wz2b W4：0（quicSettings 缺省）原不设 → quinn 缺省流收窗 1.25MB 高 BDP
        // 钉死；缺省显式 16MB 流窗/32MB 连接窗，用户显式配置仍优先。
        let stream_win = if self.stream_receive_window > 0 {
            self.stream_receive_window
        } else {
            DEFAULT_STREAM_RECEIVE_WINDOW
        };
        let conn_win = if self.connection_receive_window > 0 {
            self.connection_receive_window
        } else {
            DEFAULT_CONNECTION_RECEIVE_WINDOW
        };
        if let Ok(v) = quinn::VarInt::try_from(stream_win) {
            t.stream_receive_window(v);
        }
        if let Ok(v) = quinn::VarInt::try_from(conn_win) {
            t.receive_window(v);
        }
        // 空闲超时（bd zru2：0 = 缺省 300s，对齐 Go quic dialer 硬编码
        // `MaxIdleTimeout: 300s`；quinn 缺省仅 30s。显式配置仍优先）
        let idle_ms = if self.max_idle_timeout_ms > 0 {
            self.max_idle_timeout_ms
        } else {
            DEFAULT_MAX_IDLE_TIMEOUT_MS
        };
        if let Ok(v) = quinn::VarInt::try_from(idle_ms) {
            t.max_idle_timeout(Some(quinn::IdleTimeout::from(v)));
        }
        // keep-alive 周期（与 hysteria crate 同源字段；与 keep_alive bool 字段等价）
        if self.keep_alive_period_ms > 0 {
            t.keep_alive_interval(Some(std::time::Duration::from_millis(
                self.keep_alive_period_ms,
            )));
        }
        // PMTUD：true → 禁用
        if self.disable_path_mtu_discovery {
            t.mtu_discovery_config(None);
        }
        // 最大并发入站双向流
        if self.max_incoming_streams >= 0 {
            if let Ok(v) = quinn::VarInt::try_from(self.max_incoming_streams as u64) {
                t.max_concurrent_bidi_streams(v);
            } else {
                t.max_concurrent_bidi_streams(quinn::VarInt::MAX);
            }
        }
        // bd ut95o B7：初始 MTU opt-in（0 = 缺省不设，quinn 默认 1200）
        if self.initial_mtu > 0 {
            t.initial_mtu(self.initial_mtu);
        }
        // bd ut95o B7：发送公平调度 opt-out（缺省不设，quinn 默认 true）；
        // tuic/hysteria 类每连接大量小流的 relay 场景关闭后按写入顺序发送。
        if self.disable_send_fairness {
            t.send_fairness(false);
        }
        match self.congestion.to_ascii_lowercase().as_str() {
            "bbr" => {
                t.congestion_controller_factory(Arc::new(
                    quinn_proto::congestion::BbrConfig::default(),
                ));
            },
            // 解析层已保证字面值合法；`Default` 构造的 "" 落 CUBIC（quinn 默认）。
            // "brutal" 在本 crate 无 BrutalSender（hysteria crate 专属），落 CUBIC 登记。
            "reno" => {
                t.congestion_controller_factory(Arc::new(
                    quinn_proto::congestion::NewRenoConfig::default(),
                ));
            },
            _ => {
                t.congestion_controller_factory(Arc::new(
                    quinn_proto::congestion::CubicConfig::default(),
                ));
            },
        }
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_returns_default() {
        let cfg = QuicConfig::from_json(None).unwrap();
        assert_eq!(cfg, QuicConfig::default());
        assert!(!cfg.keep_alive);
        assert!(cfg.congestion.is_empty());
    }

    #[test]
    fn keep_alive_parsed() {
        let v: serde_json::Value = serde_json::from_str(r#"{"keepAlive":true}"#).unwrap();
        let cfg = QuicConfig::from_json(Some(&v)).unwrap();
        assert!(cfg.keep_alive);
    }

    #[test]
    fn congestion_parsed() {
        let v: serde_json::Value = serde_json::from_str(r#"{"congestion":"bbr"}"#).unwrap();
        let cfg = QuicConfig::from_json(Some(&v)).unwrap();
        assert_eq!(cfg.congestion, "bbr");
    }

    #[test]
    fn congestion_go_literal_set_accepted() {
        for lit in ["brutal", "reno", "bbr", "BRUTAL", "Reno"] {
            // Go ToLower 后严格匹配（无 trim）——仅验证合法字面值与大小写归一；
            // 带空格串属未知值，走硬错分支（见下方 rejected 测试）。
            // " Reno " 类带空格串 Go 侧硬错（ToLower 无 trim），归入 rejected 语义。
            let v: serde_json::Value =
                serde_json::from_str(&format!(r#"{{"congestion":"{lit}"}}"#)).unwrap();
            let cfg = QuicConfig::from_json(Some(&v)).unwrap();
            assert_eq!(cfg.congestion, lit.to_ascii_lowercase());
        }
    }

    #[test]
    fn congestion_unknown_rejected_go_parity() {
        // Go 合法集合无 "cubic"/"new_reno"/其他——硬错且文案一致（transport_internet.go:253）。
        for lit in ["cubic", "new_reno", "NewReno", "whatever", " Reno "] {
            let v: serde_json::Value =
                serde_json::from_str(&format!(r#"{{"congestion":"{lit}"}}"#)).unwrap();
            let err = QuicConfig::from_json(Some(&v)).unwrap_err();
            assert!(
                err.to_string().contains("unknown congestion control"),
                "literal {lit:?} should fail with Go message, got: {err}"
            );
        }
    }

    #[test]
    fn congestion_force_brutal_requires_up() {
        // 本层无 brutalUp 字段 → 恒等价 Go up==0 分支（transport_internet.go:249-250）。
        let v: serde_json::Value =
            serde_json::from_str(r#"{"congestion":"force-brutal"}"#).unwrap();
        let err = QuicConfig::from_json(Some(&v)).unwrap_err();
        assert_eq!(err.to_string(), "force-brutal requires up");
    }

    #[test]
    fn non_object_returns_err() {
        let v: serde_json::Value = serde_json::from_str(r#""not-an-object""#).unwrap();
        let r = QuicConfig::from_json(Some(&v));
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn empty_object_uses_defaults() {
        let v: serde_json::Value = serde_json::from_str(r#"{}"#).unwrap();
        let cfg = QuicConfig::from_json(Some(&v)).unwrap();
        assert!(!cfg.keep_alive);
        assert!(cfg.congestion.is_empty());
    }

    #[test]
    fn disable_gso_parsed() {
        // Go QuicParams.disableGSO（config.proto:81）：缺省 false = GSO 启用。
        let v: serde_json::Value = serde_json::from_str(r#"{"disableGSO":true}"#).unwrap();
        let cfg = QuicConfig::from_json(Some(&v)).unwrap();
        assert!(cfg.disable_gso);
        let v: serde_json::Value = serde_json::from_str(r#"{}"#).unwrap();
        let cfg = QuicConfig::from_json(Some(&v)).unwrap();
        assert!(!cfg.disable_gso);
    }

    #[test]
    fn build_transport_config_bbr() {
        let cfg = QuicConfig { congestion: "bbr".into(), ..Default::default() };
        // 不 panic 即可——quinn TransportConfig 内部不暴露已设的 congestion 类型
        let _t = cfg.build_transport_config();
    }

    #[test]
    fn build_transport_config_default_is_cubic() {
        let cfg = QuicConfig::default();
        let _t = cfg.build_transport_config();
    }

    #[test]
    fn build_transport_config_case_insensitive() {
        let cfg = QuicConfig { congestion: "BBR".into(), ..Default::default() };
        let _t = cfg.build_transport_config();
    }

    /// bd zru2：缺省 idle 300s（Go quic dialer 硬编码 `MaxIdleTimeout: 300s`），
    /// 显式配置仍优先。quinn `TransportConfig` 无 getter——用 Debug 输出回读字段。
    #[test]
    fn build_transport_config_default_idle_timeout_300s() {
        let dbg = format!("{:?}", QuicConfig::default().build_transport_config());
        assert!(dbg.contains("max_idle_timeout: Some(300000)"), "{dbg}");

        let cfg = QuicConfig { max_idle_timeout_ms: 60_000, ..Default::default() };
        let dbg = format!("{:?}", cfg.build_transport_config());
        assert!(dbg.contains("max_idle_timeout: Some(60000)"), "{dbg}");
    }

    /// bd ut95o B7：缺省值不变——initial_mtu=0 / disable_send_fairness=false 均
    /// 不触发 setter，quinn 缺省（initial_mtu 1200 / send_fairness true）原样保留。
    #[test]
    fn b7_defaults_unchanged() {
        for cfg in [
            QuicConfig::default(),
            QuicConfig::from_json(None).unwrap(),
            QuicConfig::from_json(Some(&serde_json::json!({}))).unwrap(),
        ] {
            assert_eq!(cfg.initial_mtu, 0);
            assert!(!cfg.disable_send_fairness);
            let dbg = format!("{:?}", cfg.build_transport_config());
            assert!(dbg.contains("initial_mtu: 1200"), "{dbg}");
            assert!(dbg.contains("send_fairness: true"), "{dbg}");
        }
    }

    /// bd ut95o B7：initialMtu opt-in 生效（1452 = 1500−28 常见以太网可行值）。
    #[test]
    fn b7_initial_mtu_opt_in() {
        let v = serde_json::json!({"initialMtu": 1452});
        let cfg = QuicConfig::from_json(Some(&v)).unwrap();
        assert_eq!(cfg.initial_mtu, 1452);
        let dbg = format!("{:?}", cfg.build_transport_config());
        assert!(dbg.contains("initial_mtu: 1452"), "{dbg}");
    }

    /// bd ut95o B7：initialMtu 非法值硬错（fail-visible，不静默钳到 quinn 缺省）。
    #[test]
    fn b7_initial_mtu_rejects_invalid() {
        for bad in [900u64, 70_000] {
            let v = serde_json::json!({ "initialMtu": bad });
            let err = QuicConfig::from_json(Some(&v)).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(err.to_string().contains("initialMtu must be 0"), "got: {err}");
        }
    }

    /// bd ut95o B7：disableSendFairness opt-in 生效（quinn send_fairness 翻 false）。
    #[test]
    fn b7_send_fairness_opt_out() {
        let v = serde_json::json!({"disableSendFairness": true});
        let cfg = QuicConfig::from_json(Some(&v)).unwrap();
        assert!(cfg.disable_send_fairness);
        let dbg = format!("{:?}", cfg.build_transport_config());
        assert!(dbg.contains("send_fairness: false"), "{dbg}");
    }
}
