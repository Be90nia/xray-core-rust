//! `streamSettings.finalmask.quicParams` JSON 解析 + 校验。
//!
//! 对应 Go `infra/conf/transport_internet.go`：
//! - `QuicParamsConfig`（:620-635）—— JSON 字段；
//! - `StreamConfig.Build` quicParams 段（:2153-2240）—— 校验规则 + proto 转换；
//! - `Bandwidth.Bps`（:452-491）—— `"100 mbps"` 带宽字符串 → bytes/s；
//! - `PortList`/`Int32Range`（common.go:212-275/289-338）—— 端口列表 / 区间。
//!
//! 消费方：hysteria dialer/hub（transport_config + CC 协商），splithttp H3 同构。

use std::io;

use xray_proto::xray::transport::internet::{QuicParams, UdpHop};

/// Go nil `QuicParams` 时的默认（dialer.go:78-82 / hub.go:256-262）。
#[must_use]
pub fn default_hysteria_quic_params() -> QuicParams {
    QuicParams {
        bbr_profile: "standard".into(),
        udp_hop: Some(UdpHop::default()),
        ..QuicParams::default()
    }
}

/// 从 `streamSettings.finalmask` JSON 解析 `quicParams`。
///
pub fn parse_quic_params(
    finalmask_json: Option<&serde_json::Value>,
) -> io::Result<Option<QuicParams>> {
    let Some(v) = finalmask_json else { return Ok(None) };
    let Some(qp) = v.get("quicParams") else { return Ok(None) };
    let Some(obj) = qp.as_object() else {
        return Err(invalid("quicParams: expected an object"));
    };

    let get_u64 = |k: &str| obj.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
    let get_i64 = |k: &str| obj.get(k).and_then(serde_json::Value::as_i64).unwrap_or(0);

    // bbrProfile：小写化；""→standard（Go :2154-2159）
    let mut bbr_profile = obj
        .get("bbrProfile")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    match bbr_profile.as_str() {
        "" => bbr_profile = "standard".into(),
        "conservative" | "standard" | "aggressive" => {}
        _ => return Err(invalid("unknown bbr profile")),
    }

    // brutalUp/Down：Bandwidth 字符串（Go :2164-2178；Bandwidth 底层 string，数字报错）
    let bw = |k: &str| -> io::Result<u64> {
        match obj.get(k) {
            None | Some(serde_json::Value::Null) => Ok(0),
            Some(serde_json::Value::String(s)) => parse_bandwidth_bps(s),
            Some(_) => Err(invalid(format!("quicParams: {k} must be a bandwidth string like \"100 mbps\""))),
        }
    };
    let brutal_up = bw("brutalUp")?;
    let brutal_down = bw("brutalDown")?;
    if brutal_up > 0 && brutal_up < 65_536 {
        return Err(invalid("BrutalUp must be at least 65536 bytes per second"));
    }
    if brutal_down > 0 && brutal_down < 65_536 {
        return Err(invalid("BrutalDown must be at least 65536 bytes per second"));
    }

    // congestion：小写化 ∈ {"",brutal,reno,bbr,force-brutal}；force-brutal 需 up（Go :2180-2188）
    let congestion = obj
        .get("congestion")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    match congestion.as_str() {
        "" | "brutal" | "reno" | "bbr" => {}
        "force-brutal" if brutal_up > 0 => {}
        "force-brutal" => return Err(invalid("force-brutal requires up")),
        _ => {
            return Err(invalid(format!(
                "unknown congestion control: {congestion}, valid values: reno, bbr, brutal, force-brutal"
            )))
        }
    }

    // udpHop（Go :2191-2192 校验 + :2227-2231 转换）
    let mut hop = UdpHop::default();
    if let Some(h) = obj.get("udpHop") {
        if !h.is_object() {
            return Err(invalid("udpHop: expected an object"));
        }
        if let Some(ports) = h.get("ports") {
            hop.ports = parse_port_list(ports)?;
        }
        if let Some(interval) = h.get("interval") {
            let (from, to) = parse_int32_range(interval)?;
            if (from != 0 && from < 5) || (to != 0 && to < 5) {
                return Err(invalid("Interval must be at least 5"));
            }
            hop.interval_min = from;
            hop.interval_max = to;
        }
    }

    // 窗口 ≥16384（Go :2195-2205）
    for (name, v) in [
        ("InitStreamReceiveWindow", get_u64("initStreamReceiveWindow")),
        ("MaxStreamReceiveWindow", get_u64("maxStreamReceiveWindow")),
        ("InitConnectionReceiveWindow", get_u64("initConnectionReceiveWindow")),
        ("MaxConnectionReceiveWindow", get_u64("maxConnectionReceiveWindow")),
    ] {
        if v > 0 && v < 16_384 {
            return Err(invalid(format!("{name} must be at least 16384")));
        }
    }
    // maxIdleTimeout ∈[4,120]∪{0}（Go :2207-2208）
    let max_idle_timeout = get_i64("maxIdleTimeout");
    if max_idle_timeout != 0 && !(4..=120).contains(&max_idle_timeout) {
        return Err(invalid("MaxIdleTimeout must be between 4 and 120"));
    }
    // keepAlivePeriod ∈[2,60]∪{0}（Go :2210-2211）
    let keep_alive_period = get_i64("keepAlivePeriod");
    if keep_alive_period != 0 && !(2..=60).contains(&keep_alive_period) {
        return Err(invalid("KeepAlivePeriod must be between 2 and 60"));
    }
    // maxIncomingStreams ≥8∪{0}（Go :2213-2214）
    let max_incoming_streams = get_i64("maxIncomingStreams");
    if max_incoming_streams != 0 && max_incoming_streams < 8 {
        return Err(invalid("MaxIncomingStreams must be at least 8"));
    }

    // debug（Go :2217-2220 设 HYSTERIA_*_DEBUG 环境变量；Rust CC 无 env 日志门面，忽略）
    let _ = obj.get("debug").and_then(serde_json::Value::as_bool);

    Ok(Some(QuicParams {
        congestion,
        bbr_profile,
        brutal_up,
        brutal_down,
        udp_hop: Some(hop),
        init_stream_receive_window: get_u64("initStreamReceiveWindow"),
        max_stream_receive_window: get_u64("maxStreamReceiveWindow"),
        init_conn_receive_window: get_u64("initConnectionReceiveWindow"),
        max_conn_receive_window: get_u64("maxConnectionReceiveWindow"),
        max_idle_timeout,
        keep_alive_period,
        disable_path_mtu_discovery: obj
            .get("disablePathMTUDiscovery")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        max_incoming_streams,
    }))
}

fn parse_bandwidth_bps(s: &str) -> io::Result<u64> {
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Ok(0);
    }
    let idx = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let val: f64 = s[..idx]
        .parse()
        .map_err(|_| invalid(format!("quicParams: invalid bandwidth value {s:?}")))?;
    let mul: u64 = match s[idx..].trim() {
        "" | "b" | "bps" => 1,
        "k" | "kb" | "kbps" => 1 << 10,
        "m" | "mb" | "mbps" => 1 << 20,
        "g" | "gb" | "gbps" => 1 << 30,
        "t" | "tb" | "tbps" => 1 << 40,
        unit => return Err(invalid(format!("quicParams: unsupported unit {unit:?}"))),
    };
    // Go :490 `uint64(val*float64(mul)) / 8`：先截断再整除。
    Ok((val * mul as f64) as u64 / 8)
}

fn parse_port_list(v: &serde_json::Value) -> io::Result<Vec<u32>> {
    let mut out = Vec::new();
    let mut push_range = |from: u32, to: u32| -> io::Result<()> {
        if !(1..=65_535).contains(&from) || !(1..=65_535).contains(&to) {
            return Err(invalid("invalid port"));
        }
        out.extend(from..=to);
        Ok(())
    };
    match v {
        serde_json::Value::Number(n) => {
            let p = n.as_u64().ok_or_else(|| invalid("invalid port"))? as u32;
            push_range(p, p)?;
        }
        serde_json::Value::String(s) => {
            for part in s.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if let Some((a, b)) = part.split_once('-') {
                    let from: u32 = a.trim().parse().map_err(|_| invalid("invalid port range"))?;
                    let to: u32 = b.trim().parse().map_err(|_| invalid("invalid port range"))?;
                    push_range(from.min(to), from.max(to))?;
                } else {
                    let p: u32 = part.parse().map_err(|_| invalid("invalid port"))?;
                    push_range(p, p)?;
                }
            }
        }
        _ => return Err(invalid("invalid port")),
    }
    Ok(out)
}

fn parse_int32_range(v: &serde_json::Value) -> io::Result<(i64, i64)> {
    let (from, to) = match v {
        serde_json::Value::Number(n) => {
            let n = n.as_i64().ok_or_else(|| invalid("invalid interval"))?;
            (n, n)
        }
        serde_json::Value::String(s) => {
            let (a, b) = s
                .split_once('-')
                .ok_or_else(|| invalid("invalid interval"))?;
            let from: i64 = a.trim().parse().map_err(|_| invalid("invalid interval"))?;
            let to: i64 = b.trim().parse().map_err(|_| invalid("invalid interval"))?;
            (from, to)
        }
        _ => return Err(invalid("invalid interval")),
    };
    // Go Int32Range.ensureOrder（common.go:332-338）
    Ok((from.min(to), from.max(to)))
}

fn invalid(msg: impl AsRef<str>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.as_ref().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fm(v: &str) -> serde_json::Value {
        serde_json::from_str(v).unwrap()
    }

    #[test]
    fn bandwidth_go_parity() {
        assert_eq!(parse_bandwidth_bps("").unwrap(), 0);
        assert_eq!(parse_bandwidth_bps("  ").unwrap(), 0);
        // 100 mbps = 100*1048576/8 = 13_107_200 B/s
        assert_eq!(parse_bandwidth_bps("100 mbps").unwrap(), 13_107_200);
        // 500 kbps = 500*1024/8 = 64_000
        assert_eq!(parse_bandwidth_bps("500 kbps").unwrap(), 64_000);
        // 1 gbps = 1024^3/8 = 134_217_728
        assert_eq!(parse_bandwidth_bps("1 gbps").unwrap(), 134_217_728);
        // 纯数字 = B/s：1000/8 = 125
        assert_eq!(parse_bandwidth_bps("1000").unwrap(), 125);
        // 单字母单位 + 大小写不敏感
        assert_eq!(parse_bandwidth_bps("100 M").unwrap(), 13_107_200);
        assert_eq!(parse_bandwidth_bps("1.5 mbps").unwrap(), 196_608);
        assert_eq!(parse_bandwidth_bps("1 TBPS").unwrap(), 137_438_953_472);
        // Go 语义：uint64(val*mul) 先截断再 /8
        assert_eq!(parse_bandwidth_bps("1.999 b").unwrap(), 0);
        // 非法单位 / 非法数字
        assert!(parse_bandwidth_bps("100 gbpsx").is_err());
        assert!(parse_bandwidth_bps("abc").is_err());
    }

    #[test]
    fn parse_none_cases() {
        assert!(parse_quic_params(None).unwrap().is_none());
        assert!(parse_quic_params(Some(&fm(r#"{"tcp":[]}"#))).unwrap().is_none());
        assert!(parse_quic_params(Some(&fm(r#"{"finalMask":{}}"#))).unwrap().is_none());
    }

    #[test]
    fn default_hysteria_params_match_go_nil_default() {
        let p = default_hysteria_quic_params();
        assert_eq!(p.bbr_profile, "standard");
        assert_eq!(p.congestion, "");
        assert_eq!(p.brutal_up, 0);
        assert_eq!(p.brutal_down, 0);
    }

    // ===== parse_quic_params：全字段 =====

    #[test]
    fn parse_full_fields() {
        let v = fm(
            r#"{"quicParams":{
                "congestion": "brutal",
                "bbrProfile": "aggressive",
                "brutalUp": "100 mbps",
                "brutalDown": "500 mbps",
                "udpHop": {"ports": "20800-20802,20810", "interval": "10-20"},
                "initStreamReceiveWindow": 16384,
                "maxStreamReceiveWindow": 65536,
                "initConnectionReceiveWindow": 32768,
                "maxConnectionReceiveWindow": 131072,
                "maxIdleTimeout": 45,
                "keepAlivePeriod": 15,
                "disablePathMTUDiscovery": true,
                "maxIncomingStreams": 64,
                "debug": true
            }}"#,
        );
        let p = parse_quic_params(Some(&v)).unwrap().unwrap();
        assert_eq!(p.congestion, "brutal");
        assert_eq!(p.bbr_profile, "aggressive");
        assert_eq!(p.brutal_up, 13_107_200);
        assert_eq!(p.brutal_down, 65_536_000);
        let hop = p.udp_hop.expect("udp_hop");
        assert_eq!(hop.ports, vec![20800, 20801, 20802, 20810]);
        assert_eq!(hop.interval_min, 10);
        assert_eq!(hop.interval_max, 20);
        assert_eq!(p.init_stream_receive_window, 16384);
        assert_eq!(p.max_stream_receive_window, 65536);
        assert_eq!(p.init_conn_receive_window, 32768);
        assert_eq!(p.max_conn_receive_window, 131072);
        assert_eq!(p.max_idle_timeout, 45);
        assert_eq!(p.keep_alive_period, 15);
        assert!(p.disable_path_mtu_discovery);
        assert_eq!(p.max_incoming_streams, 64);
    }

    #[test]
    fn parse_defaults_and_normalization() {
        // bbrProfile 大小写归一 + ""→standard（Go :2154-2159）；congestion 小写化（:2180）。
        let v = fm(r#"{"quicParams":{"congestion":"BBR","bbrProfile":"Conservative"}}"#);
        let p = parse_quic_params(Some(&v)).unwrap().unwrap();
        assert_eq!(p.congestion, "bbr");
        assert_eq!(p.bbr_profile, "conservative");
        // 空 quicParams 对象 → 全默认字段（bbr_profile=standard）
        let v = fm(r#"{"quicParams":{}}"#);
        let p = parse_quic_params(Some(&v)).unwrap().unwrap();
        assert_eq!(p.bbr_profile, "standard");
        assert_eq!(p.congestion, "");
        // udpHop ports 单数字 + interval 单数字（Go PortList/Int32Range 数字分支）
        let v = fm(r#"{"quicParams":{"udpHop":{"ports":20800,"interval":7}}}"#);
        let p = parse_quic_params(Some(&v)).unwrap().unwrap();
        let hop = p.udp_hop.unwrap();
        assert_eq!(hop.ports, vec![20800]);
        assert_eq!((hop.interval_min, hop.interval_max), (7, 7));
        // interval "20-10" 交换保序（Go ensureOrder）
        let v = fm(r#"{"quicParams":{"udpHop":{"interval":"20-10"}}}"#);
        let p = parse_quic_params(Some(&v)).unwrap().unwrap();
        let hop = p.udp_hop.unwrap();
        assert_eq!((hop.interval_min, hop.interval_max), (10, 20));
    }

    // ===== parse_quic_params：校验（Go :2153-2215 逐条） =====

    #[test]
    fn validation_rejects_go_parity() {
        let bad = |json: &str| {
            let v = fm(json);
            let e = parse_quic_params(Some(&v)).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{json}");
        };
        // 未知 congestion（Go :2187-2188）
        bad(r#"{"quicParams":{"congestion":"vegas"}}"#);
        // force-brutal 无 up（Go :2183-2185）
        bad(r#"{"quicParams":{"congestion":"force-brutal"}}"#);
        // 未知 bbrProfile（Go :2160-2161）
        bad(r#"{"quicParams":{"bbrProfile":"turbo"}}"#);
        // brutalUp < 65536（Go :2173-2174）
        bad(r#"{"quicParams":{"brutalUp":"64 kbps"}}"#);
        // brutalDown < 65536（Go :2176-2177）
        bad(r#"{"quicParams":{"brutalDown":"1000"}}"#);
        // udpHop interval < 5（Go :2191-2192）
        bad(r#"{"quicParams":{"udpHop":{"interval":3}}}"#);
        bad(r#"{"quicParams":{"udpHop":{"interval":"10-4"}}}"#);
        // 四个窗口 < 16384（Go :2195-2205）
        bad(r#"{"quicParams":{"initStreamReceiveWindow":1024}}"#);
        bad(r#"{"quicParams":{"maxStreamReceiveWindow":1024}}"#);
        bad(r#"{"quicParams":{"initConnectionReceiveWindow":1024}}"#);
        bad(r#"{"quicParams":{"maxConnectionReceiveWindow":1024}}"#);
        // maxIdleTimeout 越界 [4,120]（Go :2207-2208）
        bad(r#"{"quicParams":{"maxIdleTimeout":3}}"#);
        bad(r#"{"quicParams":{"maxIdleTimeout":121}}"#);
        // keepAlivePeriod 越界 [2,60]（Go :2210-2211）
        bad(r#"{"quicParams":{"keepAlivePeriod":1}}"#);
        bad(r#"{"quicParams":{"keepAlivePeriod":61}}"#);
        // maxIncomingStreams < 8（Go :2213-2214）
        bad(r#"{"quicParams":{"maxIncomingStreams":4}}"#);
        // 非法带宽单位 / ports 越界
        bad(r#"{"quicParams":{"brutalUp":"100 psi"}}"#);
        bad(r#"{"quicParams":{"udpHop":{"ports":"70000"}}}"#);
        bad(r#"{"quicParams":{"udpHop":{"ports":0}}}"#);
        // 非法带宽（数字类型——Go Bandwidth 底层 string，数字 unmarshal 失败）
        bad(r#"{"quicParams":{"brutalUp":100}}"#);
        // quicParams 非对象
        bad(r#"{"quicParams":"fast"}"#);
    }

    #[test]
    fn validation_boundary_values_pass() {
        // 边界值全部合法：65536 / 16384 / [4,120] / [2,60] / 8 / interval 5。
        let v = fm(
            r#"{"quicParams":{
                "congestion":"force-brutal",
                "brutalUp":"512 kbps",
                "udpHop":{"interval":5},
                "initStreamReceiveWindow":16384,
                "maxIdleTimeout":4,
                "keepAlivePeriod":2,
                "maxIncomingStreams":8
            }}"#,
        );
        let p = parse_quic_params(Some(&v)).unwrap().unwrap();
        assert_eq!(p.brutal_up, 65_536);
        assert_eq!(p.max_idle_timeout, 4);
        assert_eq!(p.keep_alive_period, 2);
        assert_eq!(p.max_incoming_streams, 8);
    }
}
