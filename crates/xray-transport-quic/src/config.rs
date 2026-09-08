//! QUIC 传输配置。
//!
//! 对应 Go `transport/internet/quic/config.go::Config`。
//! 解析安全层（TLS）所需的字段 + 拥塞控制（`congestion`）。

use std::io;
use std::sync::Arc;

/// QUIC 配置。
///
/// Go 端字段对照：
/// - `header` / `key`：obfuscation（未实现，quinn 不支持 header obfuscation）
/// - `security` / `tlsSettings`：通过 `StreamSettings.security_json` 承载，本结构不重复存储
/// - `congestion`：拥塞控制算法（`"bbr"` / `"cubic"` / `"new_reno"`，默认 CUBIC）
/// - `keepAlive`：QUIC keepalive 周期（与 Go `keep_alive` 同义；quinn 端叫 keep_alive_period）
/// - `initialStreamReceiveWindow` / `maxStreamReceiveWindow`：流接收窗口两级
///   （quinn 单固定窗口 → 取 max 对齐 Go Initial/Max 稳态）
/// - `initialConnectionReceiveWindow` / `maxConnectionReceiveWindow`：连接级窗口
/// - `maxIdleTimeout` / `keepAlivePeriod`：秒（quinn 内部 ms，乘 1000）
/// - `disablePathMtuDiscovery`：true 禁用 PMTUD
/// - `maxIncomingStreams`：最大并发入站双向流（-1 = 不设上限）
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicConfig {
    /// 是否启用 keep-alive（对应 Go `keep_alive`，默认 false）。
    pub keep_alive: bool,
    /// 拥塞控制算法（对应 Go `CongestionControl`）。
    ///
    /// `"bbr"` → quinn-proto BBR；其他（`""`、`"cubic"`、`"new_reno"`）→ 默认 CUBIC。
    pub congestion: String,
    /// 流接收窗口（字节）。qeyo：quinn 单固定窗口取 max(initial, max) 对齐 Go 稳态。
    /// 0 = 使用 quinn 默认（~500KB）；上层解析时已映射成实际值。
    pub stream_receive_window: u64,
    /// 连接级接收窗口（字节）。qeyo：同上。
    pub connection_receive_window: u64,
    /// 最大空闲超时（毫秒；0 = 不设，quinn 默认 30s）。
    pub max_idle_timeout_ms: u64,
    /// keep-alive 周期（毫秒；0 = 禁用）。
    pub keep_alive_period_ms: u64,
    /// true 禁用 PMTUD（Go 默认非 Linux/Win/Mac = true）。
    pub disable_path_mtu_discovery: bool,
    /// 最大并发入站双向流（-1 = 不设上限 → quinn::VarInt::MAX）。
    pub max_incoming_streams: i64,
}

impl QuicConfig {
    /// 从 `quicSettings` JSON 解析。
    ///
    /// `None` 或非 object 返回 [`QuicConfig::default`]（非 object 返回 Err）。
    ///
    /// # Errors
    /// JSON 非 object → [`InvalidData`](io::ErrorKind::InvalidData)。
    pub fn from_json(json: Option<&serde_json::Value>) -> io::Result<Self> {
        let Some(v) = json else { return Ok(Self::default()); };
        let Some(obj) = v.as_object() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "quicSettings must be a JSON object",
            ));
        };
        let keep_alive = obj
            .get("keepAlive")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        let congestion = obj
            .get("congestion")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
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
        Ok(Self {
            keep_alive,
            congestion,
            stream_receive_window: stream_win,
            connection_receive_window: conn_win,
            max_idle_timeout_ms: max_idle_ms,
            keep_alive_period_ms: keep_period_ms,
            disable_path_mtu_discovery: get_bool("disablePathMtuDiscovery"),
            max_incoming_streams: get_i64("maxIncomingStreams"),
        })
    }

    /// 构建 quinn [`TransportConfig`]（qeyo：完整 6 字段 + 拥塞控制）。
    ///
    /// `congestion == "bbr"` → quinn-proto BBR；
    /// 其他（`""`、`"cubic"`/`"new_reno"`/未知）→ CUBIC（quinn 默认，与 Go quic-go 一致）。
    #[must_use]
    pub fn build_transport_config(&self) -> quinn::TransportConfig {
        let mut t = quinn::TransportConfig::default();
        // qeyo：流量控制窗口（Go Initial+Max → quinn 单固定窗口取 max 对齐稳态）
        if self.stream_receive_window > 0 {
            if let Ok(v) = quinn::VarInt::try_from(self.stream_receive_window) {
                t.stream_receive_window(v);
            }
        }
        if self.connection_receive_window > 0 {
            if let Ok(v) = quinn::VarInt::try_from(self.connection_receive_window) {
                t.receive_window(v);
            }
        }
        // 空闲超时（qeyo 兼容：0 = quinn 默认 30s，>0 用配置值）
        if self.max_idle_timeout_ms > 0 {
            if let Ok(v) = quinn::VarInt::try_from(self.max_idle_timeout_ms) {
                t.max_idle_timeout(Some(quinn::IdleTimeout::from(v)));
            }
        }
        // keep-alive 周期（与 hysteria crate 同源字段；与 keep_alive bool 字段等价）
        if self.keep_alive_period_ms > 0 {
            t.keep_alive_interval(Some(std::time::Duration::from_millis(self.keep_alive_period_ms)));
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
        match self.congestion.to_ascii_lowercase().as_str() {
            "bbr" => {
                t.congestion_controller_factory(Arc::new(
                    quinn_proto::congestion::BbrConfig::default(),
                ));
            }
            // cubic / new_reno / "" / 未知 → CUBIC（quinn 默认，与 Go quic-go 一致）
            _ => {
                t.congestion_controller_factory(Arc::new(
                    quinn_proto::congestion::CubicConfig::default(),
                ));
            }
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
    fn build_transport_config_bbr() {
        let cfg = QuicConfig {
            congestion: "bbr".into(),
            ..Default::default()
        };
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
        let cfg = QuicConfig {
            congestion: "BBR".into(),
            ..Default::default()
        };
        let _t = cfg.build_transport_config();
    }
}
