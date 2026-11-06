//! # xdns：DNS-over-UDP 隧道伪装（对应 Go `transport/internet/finalmask/xdns/`，v26.9.30）
//!
//! payload 编码进 DNS 查询名（base32 前缀 label + 伪装域名后缀）；服务端解码
//! payload 并按 clientID（fd::/8 派生地址）路由；响应按 qtype 编码为 answer
//! 段（A/CNAME/TXT/AAAA），经 [len2|0xC0] 帧聚合下发。
//!
//! ## 子模块
//!
//! - `dns`：DNS wire format 编解码（RFC1035，CNAME rdata 归一化）
//! - `domain`：伪装域名容量模型（Go `domain.go`）
//! - `frag`：分片重组（Go `frag.go`）
//! - `resp`：响应编解码 + SendManager（Go `resp.go`）
//! - `client`：`XdnsConnClient` 实现 [`super::UdpIo`]（Go `client.go`）
//! - `server`：`XdnsConnServer` 实现 [`super::UdpIo`]（Go `server.go`）
//! - `doh`：DoH resolver（RFC 8484，对应 Go `resolver_doh.go`）
//! - `doh3`：DoH-over-QUIC（HTTP/3，ALPN `["h3"]` 时启用，对应 `resolver_doh.go:52-104`）
//! - `base32`：RFC4648 base32（无 padding）
//!
//! 配置形态对齐 Go v26.10.17 `XDNS`（`infra/conf/transport_finalmask.go:815-911`）：
//! `resolvers[]` 为 `{addrs[], worker, tlsConfig, quicConfig}`，`type` 由每个
//! `addrs` 项的 URL scheme 决定（见 `build_resolver_configs`）：`udp` / `tcp` /
//! `https`（DoH）。Rust finalmask 隧道为 UDP-only ⇒ `tcp` resolver 运行期拒绝
//! （Go `resolver_tcp.go` 经 finalmask 拨号，本栈无 TCP 拨号句柄）；DoH 走独立
//! TLS+h2 直连，`tlsConfig.alpn == ["h3"]` 时改走 HTTP/3 over QUIC（差异见 `doh`
//! 与 `doh3` 模块头）。

pub(crate) mod base32;
mod client;
mod dns;
mod doh;
mod doh3;
mod domain;
mod frag;
mod resp;
mod server;

use std::{io, sync::Arc};

use xray_proto::xray::transport::internet::{
    QuicParams, finalmask::xdns::ResolverProto, tls::Config as TlsConfig,
};

use super::{UdpIo, Udpmask, mask_err};

/// poll 通知队列深度（Go `pollLimit`）。
pub(crate) const POLL_LIMIT: usize = 16;

/// 伪装域名配置（对应 Go `DomainProto`）。
#[derive(Debug, Clone)]
pub struct DomainConfig {
    pub(crate) name: String,
    pub(crate) len_limit: i32,
    pub(crate) label_limit: i32,
    pub(crate) types: Vec<u16>,
    pub(crate) edns0: i32,
}

/// resolver 分派类型（Go `resolver.go NewResolver` 按 `ResolverProto.type` 分派）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverKind {
    Udp,
    Tcp,
    /// `https://`：DoH（Go `NewDOHResolver`）。
    Doh,
}

/// resolver 配置（对应 Go `ResolverProto`：type/addr/worker/tls_config/quic_config）。
///
/// `worker`/`tls_config`/`quic_config` 对 udp/tcp 在 Go 运行时同样不读
/// （`resolver_udp.go`/`resolver_tcp.go` 只取 Addr，仅 DOH 读 worker/tls/quic），
/// 此处无损承载以对齐 wire；`tcp` 在本栈运行期拒绝（UDP-only 隧道），`https`
/// 的 TLS 参数在配置期校验后落 `doh::DohParams`。JSON 层由
/// `build_resolver_configs` 供给。
#[derive(Clone)]
pub struct ResolverConfig {
    pub kind: ResolverKind,
    pub addr: String,
    pub worker: i32,
    pub tls_config: Option<TlsConfig>,
    pub quic_config: Option<QuicParams>,
    /// `kind == Doh` 专用：配置期校验通过的 URL/SNI/信任根。
    pub doh: Option<doh::DohParams>,
}

impl std::fmt::Debug for ResolverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // proto 生成类型无 Debug，只打字段存在性
        f.debug_struct("ResolverConfig")
            .field("kind", &self.kind)
            .field("addr", &self.addr)
            .field("worker", &self.worker)
            .field("tls_config", &self.tls_config.is_some())
            .field("quic_config", &self.quic_config.is_some())
            .field("doh", &self.doh)
            .finish()
    }
}

impl ResolverConfig {
    /// Go `NewResolver`（resolver.go:17-27）的 `type` 分派：udp/tcp 照常构造，
    /// https（DOH）配置期校验并产出 `doh::DohParams`；未知 type 同 Go 报
    /// "unknown type"。
    pub fn from_proto(p: &ResolverProto) -> io::Result<Self> {
        let kind = match p.r#type.as_str() {
            "udp" => ResolverKind::Udp,
            "tcp" => ResolverKind::Tcp,
            "https" => ResolverKind::Doh,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("xdns: unknown resolver type {other:?}"),
                ));
            },
        };
        let doh = (kind == ResolverKind::Doh)
            .then(|| {
                doh::DohParams::from_proto(&p.addr, p.tls_config.as_ref(), p.quic_config.as_ref())
            })
            .transpose()?;
        Ok(Self {
            kind,
            addr: p.addr.clone(),
            worker: p.worker,
            tls_config: p.tls_config.clone(),
            quic_config: p.quic_config.clone(),
            doh,
        })
    }
}

/// xdns 配置（对应 Go `xdns.Config` protobuf）。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 服务端：伪装域名（结构与默认值见 `build_domain_config()`）。
    pub domains: Vec<DomainConfig>,
    /// 客户端：resolver 列表（经隧道直连服务端伪装出口）。
    pub resolvers: Vec<ResolverConfig>,
    /// 真实包后追加的空 poll 数（0-3）。
    pub extra_poll: i32,
}

impl Udpmask for Config {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        let inner: Arc<dyn UdpIo> = Arc::from(raw);
        let client = client::XdnsConnClient::new(inner, self)?;
        Ok(Box::new(client))
    }

    fn wrap_packet_conn_server(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        let inner: Arc<dyn UdpIo> = Arc::from(raw);
        let server = server::XdnsConnServer::new(inner, self)?;
        Ok(Box::new(server))
    }
}

/// JSON 域名对象 → [`DomainConfig`] 列表（默认值逐条对齐 Go `XDNS.Build`
/// `:833-858`：lenLimit 0→255、labelLimit 0→63；域名校验在 wrap 期 `Domain::new`）。
///
/// `names[]` 每项展开为一条同参域（Go `XDNSDomain.Names`，`transport_finalmask.go:813`）。
/// `names` 缺失/为空 = 硬错：Go 此处静默产出零域（xdns 失效），fail-loud 优于静默无效。
/// `types` 未给 = 空列表（Go `:850` 原样转出 `Types: nil`，运行期由 client/server
/// 各取缺省：client `[16]`、server `[1,5,16,28]`）。
pub(crate) fn build_domain_config(v: &serde_json::Value) -> io::Result<Vec<DomainConfig>> {
    let Some(obj) = v.as_object() else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "xdns: domain must be an object"));
    };
    let mut names = Vec::new();
    match obj.get("names") {
        Some(serde_json::Value::Array(arr)) => {
            for n in arr {
                let s = n.as_str().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "xdns: invalid names entry")
                })?;
                names.push(s.to_string());
            }
        },
        Some(_) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "xdns: names must be an array"));
        },
        None => {},
    }
    if names.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "xdns: domain missing names"));
    }
    // Go :842-847 `if LenLimit == 0 { 255 }`（显式 0 同样取缺省；负值留给 NewDomain 拒）
    let len_limit = match obj.get("lenLimit") {
        Some(x) if !x.is_null() => x
            .as_i64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "xdns: invalid lenLimit"))?
            as i32,
        _ => 0,
    };
    let len_limit = if len_limit == 0 { 255 } else { len_limit };
    let label_limit = match obj.get("labelLimit") {
        Some(x) if !x.is_null() => x
            .as_i64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "xdns: invalid labelLimit"))?
            as i32,
        _ => 0,
    };
    let label_limit = if label_limit == 0 { 63 } else { label_limit };
    let types = match obj.get("types") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(arr)) => {
            let mut types = Vec::with_capacity(arr.len());
            for t in arr {
                let t = t.as_i64().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "xdns: invalid type")
                })? as i32;
                types.push(u16::try_from(t).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "xdns: type out of u16 range")
                })?);
            }
            types
        },
        Some(_) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "xdns: types must be an array"));
        },
    };
    let edns0 = match obj.get("edns0") {
        Some(x) if !x.is_null() => x
            .as_i64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "xdns: invalid edns0"))?
            as i32,
        _ => 0,
    };
    Ok(names
        .into_iter()
        .map(|name| DomainConfig { name, len_limit, label_limit, types: types.clone(), edns0 })
        .collect())
}

/// Go `XDNS.Build` resolver 段（`transport_finalmask.go:859-905`）→ [`ResolverConfig`] 列表。
///
/// `XDNSResolver{addrs[], worker, tlsConfig, quicConfig}`（`:820-825`）：每个 `addrs`
/// 项按 URL scheme 展开成一条 resolver。
///
/// - `worker`：Go `:860-862` 缺省 32（udp/tcp 下 Go 不读，仍转出；`https` 即 DoH 并发数，`< 1`
///   配置期硬错，同 Go `NewDOHResolver` "invalid worker"）
/// - `tlsConfig`/`quicConfig`：只被 `NewDOHResolver` 读（`resolver_doh.go:46-53`）⇒ 仅在 `https`
///   项上校验并 materialize 成 [`doh::DohParams`]（udp/tcp 上恒 inert， 与 Go
///   运行时等价）；`tlsConfig` 未支持键配置期硬错（禁静默忽略），`quicConfig` 按 Go
///   `QuicParamsConfig.Build()` 校验后只在 ALPN `["h3"]` 时生效
/// - `type`/`settings`：Rust 旧方言，Go 无此键 ⇒ 硬错指路
pub(crate) fn build_resolver_configs(v: &serde_json::Value) -> io::Result<Vec<ResolverConfig>> {
    let mut out = Vec::new();
    let Some(arr) = v.get("resolvers").and_then(|x| x.as_array()) else {
        return Ok(out); // Go：缺键 = nil，零 resolver（wrap 期 "empty resolvers" 兜底）
    };
    for r in arr {
        let obj = r.as_object().ok_or_else(|| mask_err("xdns: resolver must be an object"))?;
        if obj.contains_key("type") || obj.contains_key("settings") {
            return Err(mask_err(
                "xdns: resolver keys `type`/`settings` are not Go keys (Go XDNSResolver is \
                 {addrs,worker,tlsConfig,quicConfig}); use addrs with scheme prefixes",
            ));
        }
        let worker = match obj.get("worker") {
            Some(x) if !x.is_null() => {
                i32::try_from(x.as_i64().ok_or_else(|| mask_err("xdns: invalid worker"))?)
                    .map_err(|_| mask_err("xdns: invalid worker"))?
            },
            _ => 0,
        };
        let worker = if worker == 0 { 32 } else { worker };
        let addrs: &[serde_json::Value] = match obj.get("addrs") {
            None | Some(serde_json::Value::Null) => &[],
            Some(serde_json::Value::Array(a)) => a,
            Some(_) => return Err(mask_err("xdns: resolver addrs must be an array")),
        };
        for a in addrs {
            let raw = a.as_str().ok_or_else(|| mask_err("xdns: resolver addr must be a string"))?;
            let (kind, addr) = resolve_addr(raw)?;
            let doh = if kind == ResolverKind::Doh {
                if worker < 1 {
                    return Err(mask_err("xdns: invalid worker"));
                }
                Some(doh::DohParams::from_json(&addr, obj.get("tlsConfig"), obj.get("quicConfig"))?)
            } else {
                None
            };
            out.push(ResolverConfig {
                kind,
                addr,
                worker,
                tls_config: None,
                quic_config: None,
                doh,
            });
        }
    }
    Ok(out)
}

/// Go `:879-905`：无 `://` 前缀按 `udp://` 解析；`tcp`/`udp` 归一为 `host:port`
/// （端口缺省 53），`https` 保留全 URL（DoH），其余 scheme 硬错。
fn resolve_addr(raw: &str) -> io::Result<(ResolverKind, String)> {
    let prefixed;
    let url = if raw.contains("://") {
        raw
    } else {
        prefixed = format!("udp://{raw}");
        prefixed.as_str()
    };
    let (scheme, rest) = url.split_once("://").unwrap_or((url, ""));
    let kind = match scheme {
        "udp" => ResolverKind::Udp,
        "tcp" => ResolverKind::Tcp,
        // Go 保留 `url.String()`（含 path/query）——DoH 的 POST 目标就是它
        "https" => return Ok((ResolverKind::Doh, url.to_string())),
        // Go `:903-904` 对 tcp/udp/https 之外的 scheme 一律 "invalid protocol"（`quic://`
        // 同样被拒；DoH-over-QUIC 走 `https://` + `tlsConfig.alpn ["h3"]`）⇒ 本栈保留
        // 更明确的指路文案，不做静默降级。
        "quic" | "http3" => return Err(doh::doh_over_quic()),
        other => return Err(mask_err(format!("xdns: invalid protocol {other:?}"))),
    };
    // Go url.URL：userinfo / path / query 不参与 Hostname()/Port()
    let authority = rest.rsplit_once('@').map_or(rest, |(_, h)| h);
    let authority = authority.split(['/', '?', '#']).next().unwrap_or("");
    let (host, port) = super::split_host_port(authority)?;
    let port = port.unwrap_or_else(|| "53".to_string());
    if !port.chars().all(|c| c.is_ascii_digit()) {
        return Err(mask_err(format!("xdns: invalid port in resolver addr {raw:?}")));
    }
    Ok((kind, join_host_port(&host, &port)))
}

/// Go `net.JoinHostPort`：host 含 `:`（IPv6 字面量）时补方括号。
fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use super::*;

    #[test]
    fn domain_config_defaults_len_and_label_limits() {
        let cfg =
            build_domain_config(&serde_json::json!({"names": ["a.example.com"], "types": [16]}))
                .unwrap();
        assert_eq!(cfg.len(), 1);
        assert_eq!(cfg[0].len_limit, 255);
        assert_eq!(cfg[0].label_limit, 63);
        assert_eq!(cfg[0].types, vec![16]);
        assert_eq!(cfg[0].edns0, 0);
        // Go :842-847：显式 0 与缺失同取缺省（0 不是合法上限）
        let zero = build_domain_config(
            &serde_json::json!({"names": ["a.com"], "lenLimit": 0, "labelLimit": 0}),
        )
        .unwrap();
        assert_eq!((zero[0].len_limit, zero[0].label_limit), (255, 63));
        // types 未给 = 空列表（Go :850 原样转出 nil，运行期按侧取缺省）
        assert!(zero[0].types.is_empty());
    }

    /// Go `XDNSDomain.Names[]`（transport_finalmask.go:813，Build :841-858）：数组
    /// 每项展开为一条同参域；`name` 旧方言兜底；两者皆缺硬错。
    #[test]
    fn domain_config_names_array_expands_per_name() {
        let cfg = build_domain_config(&serde_json::json!({
            "names": ["a.example.com", "b.example.com"],
            "lenLimit": 200, "labelLimit": 50, "types": [1, 16], "edns0": 1232
        }))
        .unwrap();
        assert_eq!(cfg.len(), 2);
        assert_eq!(cfg[0].name, "a.example.com");
        assert_eq!(cfg[1].name, "b.example.com");
        for d in &cfg {
            assert_eq!(d.len_limit, 200);
            assert_eq!(d.label_limit, 50);
            assert_eq!(d.types, vec![1, 16]);
            assert_eq!(d.edns0, 1232);
        }
        // names 非法形态硬错（Go 同样只认 string 数组）。
        assert!(
            build_domain_config(&serde_json::json!({"names": "a.com", "types": [16]})).is_err()
        );
        assert!(build_domain_config(&serde_json::json!({"names": [1], "types": [16]})).is_err());
    }

    #[test]
    fn domain_config_rejects_malformed() {
        assert!(build_domain_config(&serde_json::json!("a.com")).is_err());
        // names 是唯一 Go 键：单数 name 旧方言已删 → missing names
        assert!(build_domain_config(&serde_json::json!({"types": [16]})).is_err());
        assert!(build_domain_config(&serde_json::json!({"name": "a.com"})).is_err());
        assert!(
            build_domain_config(&serde_json::json!({"names": ["a.com"], "types": "txt"})).is_err()
        );
    }

    /// Go `XDNS.Build` resolver 段（`transport_finalmask.go:859-905`）：Go 形态
    /// `{addrs[], worker, tlsConfig, quicConfig}` → 每个 addrs 项一条 resolver。
    #[test]
    fn resolver_configs_go_shape_maps_each_addr() {
        let v = serde_json::json!({"resolvers": [{
            "addrs": ["8.8.8.8", "tcp://94.140.14.14:5353", "udp://[2001:4860:4860::8888]"],
            "worker": 8,
            "tlsConfig": {"serverName": "dns.google", "alpn": ["h2"]},
            "quicConfig": {"congestion": "bbr", "maxIdleTimeout": 30}
        }]});
        let rs = build_resolver_configs(&v).unwrap();
        assert_eq!(rs.len(), 3);
        // 无 scheme → udp，端口缺省 53（Go :879-881）
        assert_eq!((rs[0].kind, rs[0].addr.as_str()), (ResolverKind::Udp, "8.8.8.8:53"));
        // tcp scheme 保留显式端口
        assert_eq!((rs[1].kind, rs[1].addr.as_str()), (ResolverKind::Tcp, "94.140.14.14:5353"));
        // IPv6 字面量按 Go JoinHostPort 补方括号
        assert_eq!(rs[2].addr, "[2001:4860:4860::8888]:53");
        // worker 逐条继承（Go :859-862）
        assert!(rs.iter().all(|r| r.worker == 8));
        // tlsConfig/quicConfig：Go 仅 NewDOHResolver 读（resolver_doh.go:46-53），
        // https 在本栈配置期即拒 ⇒ udp/tcp 上两者恒 None，与 Go 运行时等价
        // （resolver_udp.go/resolver_tcp.go 只取 Addr）；不得因此拒启。
        assert!(rs.iter().all(|r| r.tls_config.is_none() && r.quic_config.is_none()));
    }

    /// worker 缺省 32（Go :860-862），端口缺省 53；`addrs` 缺键 = 零 resolver（Go nil）。
    #[test]
    fn resolver_configs_defaults_match_go() {
        let rs =
            build_resolver_configs(&serde_json::json!({"resolvers": [{"addrs": ["1.1.1.1"]}]}))
                .unwrap();
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].worker, 32);
        assert_eq!(rs[0].addr, "1.1.1.1:53");
        // Go conf 不校验 worker 下界（udp/tcp 不读），非 0 原样转出
        let rs = build_resolver_configs(
            &serde_json::json!({"resolvers": [{"addrs": ["1.1.1.1"], "worker": -1}]}),
        )
        .unwrap();
        assert_eq!(rs[0].worker, -1);
        // addrs 缺键 → 零 resolver（Go nil Addrs），不硬错
        assert!(
            build_resolver_configs(&serde_json::json!({"resolvers": [{"worker": 4}]}))
                .unwrap()
                .is_empty()
        );
        // resolvers 缺键同理
        assert!(build_resolver_configs(&serde_json::json!({})).unwrap().is_empty());
    }

    /// scheme 分派对齐 Go `:883-905`：`https` = DoH（全 URL 保留），`quic`/`http3`
    /// 本轮未实现 → 点名指路，其余未知 scheme 同 Go "invalid protocol"。
    ///
    /// 期望值由 Go 26.10.17 源码逐行复刻的探针实跑得出（`url.Parse` +
    /// `Hostname()`/`Port()` + `JoinHostPort`），不是推导。
    #[test]
    fn resolver_addr_scheme_dispatch_and_rejections() {
        // https：Go `addr = u.String()`（含 path/query）
        assert_eq!(
            resolve_addr("https://dns.google/dns-query").unwrap(),
            (ResolverKind::Doh, "https://dns.google/dns-query".to_string())
        );
        assert_eq!(
            resolve_addr("https://1.1.1.1:8443/q?x=1").unwrap(),
            (ResolverKind::Doh, "https://1.1.1.1:8443/q?x=1".to_string())
        );
        let Err(e) = resolve_addr("quic://dns.google/dns-query") else {
            panic!("DoH-over-QUIC 必须硬错");
        };
        assert!(e.to_string().contains("DoH-over-QUIC"), "{e}");
        assert!(e.to_string().contains("https://"), "错误须指路 https：{e}");
        assert!(resolve_addr("http3://dns.google").is_err());
        let Err(e) = resolve_addr("tls://dns.google") else {
            panic!("tls scheme must reject");
        };
        assert!(e.to_string().contains("invalid protocol"), "{e}");
        // 非数字端口（Go url.Parse 报 invalid port）
        assert!(resolve_addr("udp://1.1.1.1:dns").is_err());
        // userinfo / path 不参与 host:port（Go url.Hostname()/Port() 语义）
        assert_eq!(resolve_addr("udp://u:p@1.1.1.1:53/x").unwrap().1, "1.1.1.1:53");
        assert_eq!(resolve_addr("1.1.1.1:53/").unwrap().1, "1.1.1.1:53");
        assert_eq!(resolve_addr("[2001:db8::1]:5353").unwrap().1, "[2001:db8::1]:5353");
        // 裸 IPv6（无方括号）Go 把最后一个冒号后当端口 ⇒ 与 Go 同形（不"修正"）
        assert_eq!(resolve_addr("2001:4860:4860::8888").unwrap().1, "[2001:4860:4860:]:8888");
        // addrs 项非字符串 / resolver 非对象 硬错
        assert!(
            build_resolver_configs(&serde_json::json!({"resolvers": [{"addrs": [1]}]})).is_err()
        );
        assert!(build_resolver_configs(&serde_json::json!({"resolvers": ["x"]})).is_err());
    }

    /// `https://` 项：`tlsConfig` 配置期校验后落 `doh`（缺省 SNI/webpki 根），
    /// 未支持键与 `quicConfig` 硬错点名。
    #[test]
    fn resolver_configs_https_materializes_doh() {
        let rs = build_resolver_configs(&serde_json::json!({"resolvers": [{
            "addrs": ["https://dns.google/dns-query"],
            "worker": 8,
            "tlsConfig": {"serverName": "dns.google", "minVersion": "1.3"}
        }]}))
        .unwrap();
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].kind, ResolverKind::Doh);
        assert_eq!(rs[0].addr, "https://dns.google/dns-query");
        assert_eq!(rs[0].worker, 8);
        let doh = rs[0].doh.as_ref().expect("https 必须产出 DoH 参数");
        assert_eq!(doh.sni.as_deref(), Some("dns.google"));
        assert_eq!(doh.tls.alpn, vec!["h2".to_string()]);

        // worker < 1 = Go `NewDOHResolver` 的 "invalid worker"（配置期提前）
        let Err(e) = build_resolver_configs(&serde_json::json!({"resolvers": [{
            "addrs": ["https://dns.google/dns-query"], "worker": -1
        }]})) else {
            panic!("DoH worker<1 必须硬错");
        };
        assert!(e.to_string().contains("invalid worker"), "{e}");

        // udp 项上的 tlsConfig/quicConfig 仍 inert（Go udp/tcp resolver 不读）
        let rs = build_resolver_configs(&serde_json::json!({"resolvers": [{
            "addrs": ["1.1.1.1"], "tlsConfig": {"serverName": "x"}, "quicConfig": {"congestion": "bbr"}
        }]}))
        .unwrap();
        assert!(rs[0].doh.is_none() && rs[0].tls_config.is_none());

        // quicConfig（无 alpn h3）→ 配置期读入，仍走 h2（Go 只在 h3 分支消费其值）
        let rs = build_resolver_configs(&serde_json::json!({"resolvers": [{
            "addrs": ["https://dns.google/dns-query"], "quicConfig": {"congestion": "bbr"}
        }]}))
        .unwrap();
        let doh = rs[0].doh.as_ref().expect("https 必须产出 DoH 参数");
        assert!(!doh.h3, "无 alpn [\"h3\"] ⇒ 仍 h2");
        assert_eq!(doh.tls.alpn, vec!["h2".to_string()]);
        // alpn ["h3"] → DoH-over-QUIC（bd lf69h 后半）
        let rs = build_resolver_configs(&serde_json::json!({"resolvers": [{
            "addrs": ["https://dns.google/dns-query"], "tlsConfig": {"alpn": ["h3"]}
        }]}))
        .unwrap();
        let doh = rs[0].doh.as_ref().expect("https 必须产出 DoH 参数");
        assert!(doh.h3, "alpn [\"h3\"] 必须走 HTTP/3");
        assert_eq!(doh.tls.alpn, vec!["h3".to_string()]);
        // 未实现的 congestion（brutal/force-brutal）配置期硬错
        let Err(e) = build_resolver_configs(&serde_json::json!({"resolvers": [{
            "addrs": ["https://dns.google/dns-query"],
            "tlsConfig": {"alpn": ["h3"]},
            "quicConfig": {"congestion": "force-brutal"}
        }]})) else {
            panic!("force-brutal 必须硬错");
        };
        assert!(e.to_string().contains("force-brutal"), "{e}");
    }

    /// Go 侧 fixture（Go xray-core config.pb.go proto.Marshal 真实输出，
    /// protoc v6.33.5 --encode 字节一致交叉锚定）。生成命令：
    /// `reports/night-run-2026-10-20/tmp/xdnsprobe` 内 `go run . encode`，
    /// 输入 `xdns.Config{Resolvers: [{Type: "tcp", Addr: "1.1.1.1:53", Worker: 2}]}`。
    const GO_WIRE_RESOLVERS_TCP_HEX: &str = "12130a03746370120a312e312e312e313a35331802";

    /// Go↔Rust wire 互通（bd o7ns D4）：Go Marshal 字节 → prost 解码逐字段断言
    /// （type/addr/worker），Rust 重编码必须字节一致（双向同 fixture）。
    #[test]
    fn go_wire_fixture_decode_and_roundtrip() {
        use prost::Message as _;
        use xray_proto::xray::transport::internet::finalmask::xdns as proto_xdns;

        let bytes = hex::decode(GO_WIRE_RESOLVERS_TCP_HEX).unwrap();
        let cfg = proto_xdns::Config::decode(&bytes[..]).unwrap();
        assert!(cfg.domains.is_empty());
        assert_eq!(cfg.extra_poll, 0);
        assert_eq!(cfg.resolvers.len(), 1);
        let r = &cfg.resolvers[0];
        assert_eq!(r.r#type, "tcp");
        assert_eq!(r.addr, "1.1.1.1:53");
        assert_eq!(r.worker, 2);
        assert!(r.tls_config.is_none());
        assert!(r.quic_config.is_none());

        let re_encoded = cfg.encode_to_vec();
        assert_eq!(re_encoded, bytes);

        let rc = ResolverConfig::from_proto(r).unwrap();
        assert_eq!(rc.kind, ResolverKind::Tcp);
        assert_eq!(rc.addr, "1.1.1.1:53");
        assert_eq!(rc.worker, 2);
    }

    /// `from_proto` 按 Go `resolver.go NewResolver` 分派：udp/tcp/https 均构造
    /// （https 走 DoH 参数校验），未知 type 报 "unknown"。
    #[test]
    fn from_proto_dispatches_and_rejects() {
        use xray_proto::xray::transport::internet::finalmask::xdns as proto_xdns;

        let p = |t: &str| proto_xdns::ResolverProto {
            r#type: t.into(),
            addr: "1.1.1.1:53".into(),
            ..Default::default()
        };
        assert_eq!(ResolverConfig::from_proto(&p("udp")).unwrap().kind, ResolverKind::Udp);
        assert_eq!(ResolverConfig::from_proto(&p("tcp")).unwrap().kind, ResolverKind::Tcp);
        let https = ResolverConfig::from_proto(&proto_xdns::ResolverProto {
            r#type: "https".into(),
            addr: "https://dns.google/dns-query".into(),
            worker: 4,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(https.kind, ResolverKind::Doh);
        assert!(https.doh.is_some());
        // proto 路径：`next_protocol == ["h3"]` + quicConfig ⇒ DoH-over-QUIC
        let h3 = ResolverConfig::from_proto(&proto_xdns::ResolverProto {
            r#type: "https".into(),
            addr: "https://dns.google/dns-query".into(),
            worker: 4,
            tls_config: Some(TlsConfig { next_protocol: vec!["h3".into()], ..Default::default() }),
            quic_config: Some(QuicParams {
                congestion: "bbr".into(),
                max_idle_timeout: 30,
                ..Default::default()
            }),
        })
        .unwrap();
        let doh = h3.doh.as_ref().expect("https 必须产出 DoH 参数");
        assert!(doh.h3, "proto next_protocol [\"h3\"] 必须走 HTTP/3");
        assert_eq!(doh.tls.alpn, vec!["h3".to_string()]);
        // proto 路径的未实现控制器同样硬错
        let Err(e) = ResolverConfig::from_proto(&proto_xdns::ResolverProto {
            r#type: "https".into(),
            addr: "https://dns.google/dns-query".into(),
            quic_config: Some(QuicParams {
                congestion: "force-brutal".into(),
                ..Default::default()
            }),
            ..Default::default()
        }) else {
            panic!("proto force-brutal 必须硬错");
        };
        assert!(e.to_string().contains("force-brutal"), "{e}");
        // 非 https 的 addr 形态（Go 从 JSON 层拿到的就是 URL）
        assert!(ResolverConfig::from_proto(&p("https")).is_err());
        assert!(ResolverConfig::from_proto(&p("quic")).is_err());
    }

    /// worker/tls_config/quic_config 无损承载（udp 上 Go 运行时同样不读，
    /// 不得丢弃；对齐 Go conf 缺省 worker=32 的真实形态）。
    #[test]
    fn from_proto_carries_worker_tls_quic() {
        let p = ResolverProto {
            r#type: "udp".into(),
            addr: "9.9.9.9:53".into(),
            worker: 32,
            tls_config: Some(TlsConfig::default()),
            quic_config: Some(QuicParams::default()),
        };
        let rc = ResolverConfig::from_proto(&p).unwrap();
        assert_eq!(rc.kind, ResolverKind::Udp);
        assert_eq!(rc.worker, 32);
        assert!(rc.tls_config.is_some());
        assert!(rc.quic_config.is_some());
    }

    /// 双端互通的内存 UDP 管道（模拟 finalmask 隧道），供 loopback e2e 使用。
    struct PipeEnd {
        peer: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
        inbox: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    }

    #[async_trait::async_trait]
    impl UdpIo for PipeEnd {
        async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
            self.peer
                .send((buf.to_vec(), addr))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "pipe peer closed"))?;
            Ok(buf.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let (data, addr) = self
                .inbox
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"))?;
            let n = data.len().min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            Ok((n, addr))
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127u8, 0, 0, 1], 0)))
        }
    }

    fn test_config() -> Config {
        Config {
            domains: vec![DomainConfig {
                name: "t.example.com".into(),
                len_limit: 255,
                label_limit: 63,
                types: vec![16, 1], // TXT + A（随机域/类型覆盖）
                edns0: 0,
            }],
            resolvers: vec![ResolverConfig {
                kind: ResolverKind::Udp,
                addr: "127.0.0.1:53".into(),
                worker: 0,
                tls_config: None,
                quic_config: None,
                doh: None,
            }],
            extra_poll: 0,
        }
    }

    /// loopback e2e：client ↔ server 经内存管道全链路互通（上行小包 + 下行响应）。
    #[tokio::test]
    async fn loopback_client_server_exchange_payloads() {
        let (ca, sa) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(256);
        let (sb, ab) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(256);
        // ca: → client inbox（sender）；sa: client inbox（receiver）
        // sb: → server inbox（sender）；ab: server inbox（receiver）
        let client_pipe: Arc<dyn UdpIo> =
            Arc::new(PipeEnd { peer: sb, inbox: tokio::sync::Mutex::new(sa) });
        let server_pipe: Arc<dyn UdpIo> =
            Arc::new(PipeEnd { peer: ca, inbox: tokio::sync::Mutex::new(ab) });

        let cfg = test_config();
        let client = client::XdnsConnClient::new(client_pipe, &cfg).unwrap();
        let server = server::XdnsConnServer::new(server_pipe, &cfg).unwrap();

        // 上行：payload → client.send_to → 查询 → server.recv_from 解出
        client.send_to(b"hello xdns", "127.0.0.1:53".parse().unwrap()).await.unwrap();
        let mut buf = [0u8; 4096];
        let (n, up_addr) = tokio::time::timeout(Duration::from_secs(5), server.recv_from(&mut buf))
            .await
            .expect("uplink timeout")
            .unwrap();
        assert_eq!(&buf[..n], b"hello xdns");
        // server 侧 addr 必须是 clientID 派生的 fd::/8 IPv6 地址
        assert!(up_addr.is_ipv6());
        assert_eq!(up_addr.ip().to_string().as_bytes()[0], b'f'); // "fd.."

        // 下行：server.send_to → 响应 → client.recv_from 解出
        server.send_to(b"pong", up_addr).await.unwrap();
        let mut cbuf = [0u8; 4096];
        let (cn, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut cbuf))
            .await
            .expect("downlink timeout")
            .unwrap();
        assert_eq!(&cbuf[..cn], b"pong");
    }

    /// Go 形态配置可只给 `domains[].names`（不给 `types`）：JSON 层转出空列表，
    /// client 侧取 `[16]`、server 侧取 `[1,5,16,28]`（Go `client.go:72-74` /
    /// `server.go:55-57`），两侧都能起隧道并互通。
    #[tokio::test]
    async fn loopback_with_absent_types_uses_side_defaults() {
        let (ca, sa) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(256);
        let (sb, ab) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(256);
        let client_pipe: Arc<dyn UdpIo> =
            Arc::new(PipeEnd { peer: sb, inbox: tokio::sync::Mutex::new(sa) });
        let server_pipe: Arc<dyn UdpIo> =
            Arc::new(PipeEnd { peer: ca, inbox: tokio::sync::Mutex::new(ab) });
        let cfg = Config {
            domains: build_domain_config(&serde_json::json!({"names": ["t.example.com"]})).unwrap(),
            resolvers: build_resolver_configs(
                &serde_json::json!({"resolvers": [{"addrs": ["127.0.0.1:53"]}]}),
            )
            .unwrap(),
            extra_poll: 0,
        };
        assert!(cfg.domains[0].types.is_empty(), "JSON 层不得代填 types");
        let client = client::XdnsConnClient::new(client_pipe, &cfg).unwrap();
        let server = server::XdnsConnServer::new(server_pipe, &cfg).unwrap();

        client.send_to(b"hello xdns", "127.0.0.1:53".parse().unwrap()).await.unwrap();
        let mut buf = [0u8; 4096];
        let (n, up_addr) = tokio::time::timeout(Duration::from_secs(5), server.recv_from(&mut buf))
            .await
            .expect("uplink timeout")
            .unwrap();
        assert_eq!(&buf[..n], b"hello xdns");
        server.send_to(b"pong", up_addr).await.unwrap();
        let mut cbuf = [0u8; 4096];
        let (cn, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut cbuf))
            .await
            .expect("downlink timeout")
            .unwrap();
        assert_eq!(&cbuf[..cn], b"pong");
    }

    /// 53 字节 DNS 查询：解码后 13 字节，`[8]=0xC3`（flag8=3 且分片位），
    /// 但分片头 `[12..15)` 越界。无凭据、无需客户端实现即可构造。
    fn short_fragment_query() -> Vec<u8> {
        let decoded = [0x02u8, 0, 0, 0, 0, 0, 0, 0, 0xC3, 0, 0, 0, 0];
        let prefix = super::base32::encode_lower(&decoded);
        assert_eq!(prefix.len(), 21, "13 字节 base32 无 padding = 21 字符");
        // 头：id / flags(标准查询) / qd=1 / an=ns=ar=0
        let mut q = vec![0x12u8, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q.push(u8::try_from(prefix.len()).unwrap());
        q.extend_from_slice(&prefix);
        for label in ["t", "example", "com"] {
            q.push(u8::try_from(label.len()).unwrap());
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0); // 根
        q.extend_from_slice(&16u16.to_be_bytes()); // qtype TXT
        q.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
        q
    }

    /// bd itd0p：短分片 query（解码 13 字节，缺 `[12..15)` 分片头）曾让
    /// `server_read` 在 `decoded[13]` 索引越界 panic → recv 任务死亡 →
    /// 隧道永久失聪（其后每次重传都超时、不自动恢复）。
    ///
    /// 断言：连续 3 次都必须拿到 DNS 响应（QR 置位）——任务存活即证明。
    #[tokio::test]
    async fn short_fragment_query_keeps_recv_task_alive() {
        let (ca, sa) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(64);
        let (sb, ab) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(64);
        let raw: Arc<dyn UdpIo> =
            Arc::new(PipeEnd { peer: sb, inbox: tokio::sync::Mutex::new(sa) });
        let server_pipe: Arc<dyn UdpIo> =
            Arc::new(PipeEnd { peer: ca, inbox: tokio::sync::Mutex::new(ab) });
        let _server = server::XdnsConnServer::new(server_pipe, &test_config()).unwrap();

        let query = short_fragment_query();
        assert_eq!(query.len(), 53, "票面复现包：单个 53 字节 DNS 查询");
        for round in 0..3 {
            raw.send_to(&query, "127.0.0.1:53".parse().unwrap()).await.unwrap();
            let mut buf = [0u8; 4096];
            let (n, _) = tokio::time::timeout(Duration::from_secs(3), raw.recv_from(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("round {round}: 无应答（recv 任务已 panic 死亡）"))
                .unwrap();
            assert!(n >= 12, "round {round}: 响应至少 12 字节 DNS 头，实际 {n}");
            assert_eq!(buf[2] & 0x80, 0x80, "round {round}: QR 位必须置位");
        }
    }

    /// DoH 端到端（bd lf69h 验收）：`https://` resolver + 自签证书经
    /// `tlsConfig.certificates` 信任，走真实 TLS + h2 的 DoH 假服务器，与
    /// `XdnsConnServer` 全链路互通。
    ///
    /// 同时锁住三件事：①配置期 `https://` 不再被拒；②`tlsConfig.serverName` 真实
    /// 生效（连接 127.0.0.1、SNI/校验名 localhost）；③请求符合 RFC 8484
    /// （POST + `application/dns-message`）。
    #[tokio::test]
    async fn doh_resolver_loopback_end_to_end() {
        use tokio::net::TcpListener;
        use tokio_rustls::{
            TlsAcceptor,
            rustls::{
                ServerConfig,
                pki_types::{CertificateDer, PrivateKeyDer},
            },
        };

        xray_common::ensure_default_crypto_provider();

        // 自签证书（SAN: localhost）+ 服务端 rustls 配置（ALPN h2：DoH 客户端只发 h2）
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_pem = cert.pem();
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let doh_addr = listener.local_addr().unwrap();

        // 内存管道：DoH 服务器侧 ↔ XdnsConnServer 的 raw conn
        let (q_tx, q_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(64);
        let (r_tx, r_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(64);
        let server_pipe: Arc<dyn UdpIo> =
            Arc::new(PipeEnd { peer: r_tx, inbox: tokio::sync::Mutex::new(q_rx) });
        let http_pipe: Arc<dyn UdpIo> =
            Arc::new(PipeEnd { peer: q_tx, inbox: tokio::sync::Mutex::new(r_rx) });

        let cfg = Config {
            domains: build_domain_config(&serde_json::json!({"names": ["t.example.com"]})).unwrap(),
            resolvers: build_resolver_configs(&serde_json::json!({"resolvers": [{
                "addrs": [format!("https://127.0.0.1:{}/dns-query", doh_addr.port())],
                "worker": 2,
                // 连接目标是 127.0.0.1，校验名必须是 localhost ⇒ serverName 必须生效
                "tlsConfig": {
                    "serverName": "localhost",
                    "certificates": [{"certificate": cert_pem}]
                }
            }]}))
            .unwrap(),
            extra_poll: 0,
        };
        assert_eq!(cfg.resolvers[0].kind, ResolverKind::Doh);
        let server = server::XdnsConnServer::new(server_pipe, &cfg).unwrap();

        // DoH 假服务器：POST 体 = DNS 查询 → XdnsConnServer → 响应体回投
        #[allow(clippy::disallowed_methods, reason = "测试用 DoH 假服务器：accept 环")]
        let doh_server = tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { return };
                let acceptor = acceptor.clone();
                let http_pipe = http_pipe.clone();
                #[allow(clippy::disallowed_methods, reason = "测试用 DoH 假服务器：每连接一任务")]
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(sock).await else { return };
                    let Ok(mut conn) = h2::server::handshake(tls).await else { return };
                    while let Some(accepted) = conn.accept().await {
                        let Ok((req, mut respond)) = accepted else { return };
                        // RFC 8484 形态断言
                        assert_eq!(req.method(), http::Method::POST);
                        assert_eq!(
                            req.headers().get(http::header::CONTENT_TYPE).unwrap(),
                            "application/dns-message"
                        );
                        assert_eq!(
                            req.headers().get(http::header::ACCEPT).unwrap(),
                            "application/dns-message"
                        );
                        let mut body = req.into_body();
                        let mut query = Vec::new();
                        while let Some(chunk) = body.data().await {
                            query.extend_from_slice(&chunk.unwrap());
                        }
                        // 源地址对 server 无语义（clientID 从 payload 解出）
                        http_pipe.send_to(&query, doh_addr).await.unwrap();
                        let mut buf = [0u8; 4096];
                        let (n, _) = http_pipe.recv_from(&mut buf).await.unwrap();
                        let resp = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .header(http::header::CONTENT_TYPE, "application/dns-message")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(resp, false).unwrap();
                        send.send_data(bytes::Bytes::copy_from_slice(&buf[..n]), true).unwrap();
                    }
                });
            }
        });

        // 客户端：inner 隧道 conn 在纯 DoH 配置下不被使用（DoH 走独立 TLS+h2）
        let (dummy_tx, dummy_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(1);
        let unused_pipe: Arc<dyn UdpIo> =
            Arc::new(PipeEnd { peer: dummy_tx, inbox: tokio::sync::Mutex::new(dummy_rx) });
        let client = client::XdnsConnClient::new(unused_pipe, &cfg).unwrap();

        client.send_to(b"hello doh", "127.0.0.1:53".parse().unwrap()).await.unwrap();
        let mut buf = [0u8; 4096];
        let (n, up_addr) =
            tokio::time::timeout(Duration::from_secs(10), server.recv_from(&mut buf))
                .await
                .expect("DoH uplink timeout")
                .unwrap();
        assert_eq!(&buf[..n], b"hello doh");

        server.send_to(b"doh pong", up_addr).await.unwrap();
        let mut cbuf = [0u8; 4096];
        let (cn, _) = tokio::time::timeout(Duration::from_secs(10), client.recv_from(&mut cbuf))
            .await
            .expect("DoH downlink timeout")
            .unwrap();
        assert_eq!(&cbuf[..cn], b"doh pong");

        doh_server.abort();
    }
}
