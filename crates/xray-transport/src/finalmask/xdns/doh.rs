//! # xdns DoH resolver（对应 Go `resolver_doh.go`，v26.10.17）
//!
//! RFC 8484：`POST` + `Content-Type: application/dns-message`，body 与响应都是裸
//! DNS message（无 2B 长度前缀，HTTP/2 自带 framing）。传输 = TCP + TLS（ALPN
//! 固定 `h2`）+ 树内 `h2` 客户端（`h2`/`http`/`bytes` 均为 workspace 既有依赖，
//! 未引新外部 crate）。
//!
//! `worker` = 并发 POST 任务数（Go `NewDOHResolver` 的 `for range config.Worker`
//! 起 goroutine 组，共享一个无缓冲 `sendCh`）；JSON 层 worker 缺省 32（Go
//! `transport_finalmask.go:860-862`）。
//!
//! ALPN `["h3"]`（且仅此形态）改走 DoH-over-QUIC（`http3.Transport` 对位），见
//! `doh3` 子模块——与 Go `resolver_doh.go:52-104` 的 `len(NextProtocol)==1 &&
//! NextProtocol[0]=="h3"` 判据一致；其余 ALPN 组合零行为变化。
//!
//! ## 与 Go 的差异（bd lf69h）
//!
//! 1. **拨号面**：Go 用 finalmask `dialer.DialTCP` 拨 DoH 服务器（可带代理链/拨号 选项）；Rust xdns
//!    wrap 期只拿得到 `Box<dyn UdpIo>`（UDP-only，无 TCP 拨号 句柄）⇒ 本实现直连，不带 dialer
//!    能力面。
//! 2. **协议**：h2 路只做 HTTP/2（Go 默认 ALPN `["h2","http/1.1"]`，仅 h1.1 的服务器 Go 也能用）；
//!    本栈 ALPN 通告固定 `h2`（与 Go `tlsConfig.NextProtos` 同形）；服务器未协商出 h2 时按 Go
//!    `ForceAttemptHTTP2` + `DialTLSContext` 语义回落 HTTP/1.1。`["h3"]` 走 QUIC（差异见 `doh3`
//!    模块头）。
//! 3. **连接复用**：h2 路走 hyper-util legacy Client 连接池（keep-alive + HTTP/2 多路复用， Go
//!    `http.Transport` ForceAttemptHTTP2 对位，bd 5lpw3）；h3 路复用同一条 QUIC/h3 会话 （Go
//!    `http3.Transport` 连接池对位）。TLS 拨号面仍是直连（无 finalmask dialer，差异 1）。
//! 4. **超时**：单请求 30s（Go `http.Client` 无 timeout，挂死的 worker 永久失能）。h2 路 超时由
//!    legacy Client 收敛到请求流；h3 路超时后整条会话被 RAII 显式 CONNECTION_CLOSE（bd
//!    0x4tl：禁把连接留给服务端干等 idle timeout）。
//! 5. **429 冷却**：与 Go `resolver_doh.go:180-192`/`:224-252` 同款——`Retry-After` 的
//!    `delta-seconds` 形式落全 worker 共享的冷却窗，只进不退；窗内收到 payload 直接丢弃，
//!    不排队，并记限频 WARN。`HTTP-date` 形式不解析：本仓无日期解析器，禁为此加依赖，
//!    解析不出即不设冷却、不硬失败，与 Go 解析失败同款。**h2 / h3 共用同一个冷却窗** （Go
//!    `DOHResolver` 单一 `time` 字段，不分 transport；bd 6eqgp）。
//! 6. **缺 `tlsConfig`**：按 URL host 取 SNI + webpki 根（Go 硬错 "empty tls config" = 更严）；Go
//!    合法配置不受影响。
//!
//! ## 配置期口径
//!
//! `tlsConfig` 只接受 `serverName` / `alpn` / `certificates[].certificate` /
//! `disableSystemRoot` / `minVersion`（`allowInsecure: false` 也无害放行），其余键
//! 配置期硬错点名（禁静默忽略）；`quicConfig` 按 Go `QuicParamsConfig.Build()` 校验
//! 后落 `doh3::QuicOptions`，只在 ALPN `h3` 时生效（Go 只在 h3 分支读它）。
//!
//! ## 归属裁决（bd 1z3pl ARCH-03：不抽共享 DoH 骨架，留主仓 + 举证）
//!
//! 仓内共三套 DoH（app-dns `nameserver/doh.rs` hickory+裸 h2 / xray-tls `ech_doh.rs`
//! hickory+裸 h2 / 本模块自持 RFC1035 codec+hyper-util 池+h3），按 §3.5.5 三判据：
//! **判据①（零 Xray 语义 ⇒ udf）不过闸**——DoH 骨架内含大量 Go 对拍语义（本模块的
//! worker 组/Retry-After 冷却/超时/config 键校验、app-dns 的 deadline 预算、ech_doh 的
//! `ApplyECH` URL 拆分），且 HTTP/h2/QUIC 传输栈属 §3.5.3 网络**方向件**（udf 只收
//! 无方向进程级机制；udf `std-ext` 十三域无 HTTP/DNS 传输件，2026-11-06 实查）⇒ udf 不适用。
//! **判据②（默认落 xray-frame）评过后不采**——三份真正可共享的只剩 ~百行请求/响应
//! codec（POST + Content-Type + 状态/content-type 校验 + body 上限）；各自复杂度在
//! **连接生命周期**，且是三种互斥模型（本模块 hyper-util 池 + worker 队列 + h3 会话槽；
//! app-dns 手工 h2 + SessionLease + 看门狗 + `xray_frame::deadline::Budget`；ech_doh
//! 一次性查询 + 进程级 TTL 缓存）——统一 trait 覆盖不了这一级语义差异，抽了只会得到
//! 三个各自仍要自持生命周期的薄适配 + 框架 crate 新增 h2/http 直接依赖（xray-frame
//! 现仅 xray-buf 一个主仓依赖）。
//! **判据③（留主仓消费方）逐条举证**：① DNS 消息层三套三种（hickory 应用面 / hickory
//! ECH 提取 / 本模块 Go `Message.WireFormat` 对位自持 codec 含压缩指针）——Go 对拍
//! wire 语义属 Xray 语义，按 §3.5.3 例外条款留协议/消费 crate；② TLS 拨号面三套三种
//! （xray_tls uTLS 指纹 / rustls 缺省+可选 config / finalmask realm::tls 键校验），
//! xray-frame 若直依赖 xray-tls 会与 xray-tls→xray-transport→xray-frame 成环，只能泛型
//! IO 注入 ⇒ 适配层进一步加宽；③ **重抽风险**：本模块连接复用（bd 5lpw3）+ h3 会话槽
//! RAII CONNECTION_CLOSE（bd 0x4tl）+ 429 冷却共享窗（bd 28nbk/6eqgp）四票刚收口并
//! 实测验证，重抽=推翻刚验证成果，且框架路 CI 零保护（ARCH-01）放大回归不可见性。
//! **不复用另两套**：app-dns 面绑 hickory 应用 DNS + dispatcher 缓存族 + FxScope 托管，
//! 其 h2 会话池预算（`DOH_MAX_SESSIONS=8`）是 app DNS 语义，与 finalmask 隧道内
//! worker 组模型不同构；ech_doh 面是一次性 type65 查询（无会话复用），且 xray-tls
//! 依赖 xray-transport，本模块在 xray-transport 内反向复用它即成环。

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_channel as doh_queue;
use bytes::Bytes;
use http::{
    Method, StatusCode, Uri,
    header::{ACCEPT, CONTENT_TYPE},
};
use http_body_util::{BodyExt as _, Full};
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connected, Connection as HttpConnection},
    },
    rt::{TokioExecutor, TokioIo},
};
use parking_lot::Mutex;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tower_service::Service as TowerService;
use xray_proto::xray::transport::internet::{QuicParams, tls::Config as TlsConfigProto};

use super::doh3;
use crate::finalmask::{
    mask_err,
    realm::tls::{MinTlsVersion, TlsConfig, build_rustls_client_config, pem_certificates_to_der},
};

/// DoH 响应体上限（Go `resolver_doh.go` `pool4K`）。
pub(super) const DOH_RECV_MAX: usize = 4096;
/// 请求队列深度（Go `sendCh` 无缓冲；深度 1 等效「生产端等空闲 worker」）。
const QUEUE_CAP: usize = 1;
/// 单请求超时（Go 无 timeout，见模块头差异 4）。
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// DoH 媒体类型（RFC 8484 §4）。
pub(super) const DNS_MEDIA_TYPE: &str = "application/dns-message";
/// 本轮支持的 `tlsConfig` 顶层键；其余硬错。
const TLS_KEYS: [&str; 5] =
    ["serverName", "alpn", "certificates", "disableSystemRoot", "minVersion"];
/// 缺省 HTTPS 端口（Go `url.URL` 无端口时由 http 栈取 443）。
const DEFAULT_HTTPS_PORT: u16 = 443;

/// 429 冷却窗（Go `DOHResolver.time`）：全 worker 共享一个截止时刻，`None` = 从未冷却。
/// 锁内只读写 `Option<Instant>`，禁跨 await 持锁。h2 / h3 两路共用同一类型与实例
/// （bd 6eqgp，Go 单一 `time` 字段对位）。
pub(super) type Cooldown = Mutex<Option<Instant>>;

/// 取时走进程级时钟（`clippy::disallowed_methods` 禁裸 `Instant::now`）。
fn now() -> Instant {
    xray_frame::compat::clock().now_instant()
}

/// 冷却中？（Go `cooldown(time.Time{})` 返回 `now.Before(r.time)`）
fn cooling(cooldown: &Cooldown) -> bool {
    let Some(until) = *cooldown.lock() else { return false };
    now() < until
}

/// 只进不退（Go `cooldown(t)` 的 `if t.After(r.time) { r.time = t }`）：更早的截止时刻
/// 不得缩短已生效的窗。
pub(super) fn extend_cooldown(cooldown: &Cooldown, until: Instant) {
    let mut slot = cooldown.lock();
    if slot.is_none_or(|cur| until > cur) {
        *slot = Some(until);
    }
}

/// `Retry-After` → 冷却截止时刻。
///
/// 只实现 `delta-seconds` 形式（Go 同分支 `strconv.ParseUint(value, 10, 32)`，故超
/// u32 的秒数同样 `None`）。`HTTP-date` 形式不解析——本仓无 HTTP 日期解析器，不为此加
/// 依赖；解析不出 ⇒ `None`（Go 两种形式都失败时同样不设冷却，不硬失败）。
pub(super) fn retry_after_until(value: &str) -> Option<Instant> {
    let secs: u32 = value.parse().ok()?;
    Some(now() + Duration::from_secs(u64::from(secs)))
}

/// `quic://` / `http3://` scheme 的配置期硬错文案。
///
/// Go `transport_finalmask.go:903-904` 对 tcp/udp/https 之外的 scheme 一律
/// "invalid protocol"（`quic://` 同样被拒），本栈保留更明确的指路文案：
/// DoH-over-QUIC 走 `https://` + `tlsConfig.alpn ["h3"]`。
pub(crate) fn doh_over_quic() -> io::Error {
    mask_err(
        "xdns: scheme quic:// is not a Go xdns resolver scheme (Go rejects any scheme other \
         than tcp/udp/https): use https:// with tlsConfig.alpn [\"h3\"] for DoH-over-QUIC",
    )
}

/// `https` resolver 的配置期产物（JSON / proto 两路校验后同形）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DohParams {
    /// 完整 URL（Go `url.String()`，scheme = https）。
    pub(crate) url: String,
    /// SNI / 校验名覆盖（Go `tlsConfig.serverName`）；缺省取 URL host。
    pub(crate) sni: Option<String>,
    /// 已校验 TLS 参数（信任根 / ALPN / 协议版本）。
    pub(crate) tls: TlsConfig,
    /// `tlsConfig.alpn == ["h3"]`（Go `resolver_doh.go:52`）⇒ 走 HTTP/3 over QUIC。
    pub(crate) h3: bool,
    /// Go `quicConfig`（缺省 = Go 零值 `&internet.QuicParams{}`）；只在 [`Self::h3`] 时生效。
    pub(crate) quic: doh3::QuicOptions,
}

impl DohParams {
    /// JSON 层：`addrs` 里的 `https://` 项 + 同组 `tlsConfig`/`quicConfig`。
    pub(crate) fn from_json(
        url: &str,
        tls: Option<&Value>,
        quic: Option<&Value>,
    ) -> io::Result<Self> {
        // Go `XDNS.Build` 对每个带 quicConfig 的 resolver 都调 `QuicConfig.Build()`
        // （校验与 ALPN 无关），只在 h3 分支消费其值。
        let quic = doh3::QuicOptions::from_json(quic)?;
        parse_target(url)?; // 配置期校验 scheme/host（构造期不再失败）
        let mut out = Self {
            url: url.to_string(),
            sni: None,
            tls: TlsConfig { alpn: vec!["h2".to_string()], ..TlsConfig::default() },
            h3: false,
            quic,
        };
        let Some(tls) = tls.filter(|v| !v.is_null()) else {
            return Ok(out); // 缺省：URL host 作 SNI + webpki 根（见模块头差异 6）
        };
        let obj = tls
            .as_object()
            .ok_or_else(|| mask_err(format!("xdns: tlsConfig must be an object, got {tls}")))?;

        // Go `transport_security.go:362-364`：allowInsecure 已移除；false 无害放行。
        if obj.get("allowInsecure").and_then(Value::as_bool).unwrap_or(false) {
            return Err(mask_err(
                "xdns: tlsConfig \"allowInsecure\" is removed; DoH resolver never skips \
                 verification (use \"certificates\" with a CA PEM instead)",
            ));
        }
        if let Some(key) =
            obj.keys().find(|k| k.as_str() != "allowInsecure" && !TLS_KEYS.contains(&k.as_str()))
        {
            return Err(mask_err(format!(
                "xdns: tlsConfig key {key:?} is not supported by the DoH resolver (supported: \
                 serverName/alpn/certificates/disableSystemRoot/minVersion)"
            )));
        }

        if let Some(sn) = obj.get("serverName").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            out.sni = Some(sn.to_string());
        }
        out.apply_alpn(obj.get("alpn"))?;
        if let Some(arr) = obj.get("certificates").filter(|v| !v.is_null()) {
            out.apply_certificates(arr)?;
        }
        out.tls.disable_system_root =
            obj.get("disableSystemRoot").and_then(Value::as_bool).unwrap_or(false);
        out.apply_min_version(obj.get("minVersion").and_then(Value::as_str))?;
        Ok(out)
    }

    /// proto 层：`ResolverConfig::from_proto` 的 `https` 分派（wire 对齐用）。
    pub(crate) fn from_proto(
        url: &str,
        tls: Option<&TlsConfigProto>,
        quic: Option<&QuicParams>,
    ) -> io::Result<Self> {
        let quic = doh3::QuicOptions::from_proto(quic)?;
        parse_target(url)?;
        let mut out = Self {
            url: url.to_string(),
            sni: None,
            tls: TlsConfig { alpn: vec!["h2".to_string()], ..TlsConfig::default() },
            h3: false,
            quic,
        };
        let Some(p) = tls else { return Ok(out) };

        out.sni = Some(p.server_name.clone()).filter(|s| !s.is_empty());
        out.apply_alpn(Some(&Value::Array(
            p.next_protocol.iter().cloned().map(Value::String).collect(),
        )))?;
        out.tls.disable_system_root = p.disable_system_root;
        out.apply_min_version(Some(p.min_version.as_str()))?;
        // Go `loadCertificates` 把证书文件字节（PEM）放进 `Certificate.certificate`。
        for cert in &p.certificate {
            let pem = String::from_utf8_lossy(&cert.certificate);
            out.tls.ca_certificates.extend(pem_certificates_to_der(&pem)?);
        }

        let unsupported: Vec<&str> = [
            (p.enable_session_resumption, "enableSessionResumption"),
            (!p.max_version.is_empty(), "maxVersion"),
            (!p.cipher_suites.is_empty(), "cipherSuites"),
            (!p.fingerprint.is_empty(), "fingerprint"),
            (p.reject_unknown_sni, "rejectUnknownSni"),
            (!p.master_key_log.is_empty(), "masterKeyLog"),
            (!p.curve_preferences.is_empty(), "curvePreferences"),
            (!p.verify_peer_cert_by_name.is_empty(), "verifyPeerCertByName"),
            (!p.ech_server_keys.is_empty(), "echServerKeys"),
            (!p.ech_config_list.is_empty(), "echConfigList"),
            (p.ech_socket_settings.is_some(), "echSockopt"),
            (!p.pinned_peer_cert_sha256.is_empty(), "pinnedPeerCertSha256"),
            (p.use_system_ca, "useSystemCa"),
        ]
        .into_iter()
        .filter(|(set, _)| *set)
        .map(|(_, name)| name)
        .collect();
        if !unsupported.is_empty() {
            return Err(mask_err(format!(
                "xdns: tlsConfig keys {unsupported:?} are not supported by the DoH resolver"
            )));
        }
        Ok(out)
    }

    /// ALPN：空 = `h2`；`["h2"]` 放行；`["h3"]` = DoH-over-QUIC（Go `resolver_doh.go:52`
    /// 的 `len==1 && [0]=="h3"` 判据）；其余硬错。
    fn apply_alpn(&mut self, alpn: Option<&Value>) -> io::Result<()> {
        let Some(alpn) = alpn.filter(|v| !v.is_null()) else { return Ok(()) };
        let arr =
            alpn.as_array().ok_or_else(|| mask_err("xdns: tlsConfig alpn must be an array"))?;
        let mut protocols = Vec::with_capacity(arr.len());
        for p in arr {
            let p = p
                .as_str()
                .ok_or_else(|| mask_err("xdns: tlsConfig alpn must contain only strings"))?;
            protocols.push(p.to_string());
        }
        match protocols.as_slice() {
            [] => Ok(()),
            [one] if one == "h2" => Ok(()),
            [one] if one == "h3" => {
                self.h3 = true;
                self.tls.alpn = vec!["h3".to_string()];
                Ok(())
            },
            other => Err(mask_err(format!(
                "xdns: tlsConfig alpn {other:?} is not supported: DoH resolver speaks HTTP/2 \
                 (h2) or, as exactly [\"h3\"], HTTP/3 over QUIC"
            ))),
        }
    }

    /// `certificates[]`：只取 CA PEM（Go `getCertPool` 把所有项当信任根）。
    fn apply_certificates(&mut self, certs: &Value) -> io::Result<()> {
        let arr = certs
            .as_array()
            .ok_or_else(|| mask_err("xdns: tlsConfig certificates must be an array"))?;
        for entry in arr {
            let entry = entry
                .as_object()
                .ok_or_else(|| mask_err("xdns: tlsConfig certificates entry must be an object"))?;
            // `usage` 在 Go getCertPool 同样不参与根池选择 ⇒ 放行；其余键是服务端
            // 侧字段，客户端静默丢会让人以为生效 ⇒ 硬错点名。
            if let Some(key) = entry.keys().find(|k| !matches!(k.as_str(), "certificate" | "usage"))
            {
                return Err(mask_err(format!(
                    "xdns: tlsConfig certificates[].{key} is not supported (DoH client only \
                     needs the CA PEM \"certificate\")"
                )));
            }
            let pem = entry.get("certificate").and_then(Value::as_str).ok_or_else(|| {
                mask_err("xdns: tlsConfig certificates entry missing PEM \"certificate\"")
            })?;
            self.tls.ca_certificates.extend(pem_certificates_to_der(pem)?);
        }
        Ok(())
    }

    /// `minVersion`：1.2/1.3 生效；1.0/1.1 低于 rustls 下限 ⇒ 硬错（禁静默按默认）。
    fn apply_min_version(&mut self, min_version: Option<&str>) -> io::Result<()> {
        match min_version {
            None | Some("") => Ok(()),
            Some("1.2") => {
                self.tls.min_version = Some(MinTlsVersion::Tls12);
                Ok(())
            },
            Some("1.3") => {
                self.tls.min_version = Some(MinTlsVersion::Tls13);
                Ok(())
            },
            Some(other) => Err(mask_err(format!(
                "xdns: tlsConfig minVersion {other:?} is not supported: rustls floor is TLS 1.2 \
                 (use \"1.2\" or \"1.3\")"
            ))),
        }
    }
}

/// 解析后的 DoH 目标（绝对 URI，供 h2 生成 `:scheme`/`:authority`/`:path`）。
struct DohTarget {
    uri: Uri,
    host: String,
    port: u16,
}

/// URL → `scheme://host[:port]`（剥 userinfo / path / query），错误与日志文案专用。
///
/// 配置里的 DoH URL 可带凭据（`user:pass@`）与密钥（`?key=…`），整串进错误文本等于
/// 随「配置装配失败」把凭据外送（bd rjcu4）——只留与 `DohEndpoint` 拨号口径相同的
/// scheme+host+port。
pub(super) fn url_label(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    if scheme.is_empty() { host.to_string() } else { format!("{scheme}://{host}") }
}

/// URL → [`DohTarget`]：只认 `https://`，host 必填，端口缺省 443，路径缺省 `/`
/// （Go `http.NewRequest` 对空路径同样用 `/`）。
fn parse_target(url: &str) -> io::Result<DohTarget> {
    let uri: Uri = url
        .parse()
        .map_err(|e| mask_err(format!("xdns: invalid DoH url {}: {e}", url_label(url))))?;
    if uri.scheme_str() != Some("https") {
        return Err(mask_err(format!(
            "xdns: DoH url {} must use the https:// scheme",
            url_label(url)
        )));
    }
    let host = uri
        .host()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| mask_err(format!("xdns: DoH url {} has no host", url_label(url))))?
        .to_string();
    let port = uri.port_u16().unwrap_or(DEFAULT_HTTPS_PORT);
    // 规范化：空路径补 "/"，保留 query（Go 直接 POST 配置的 URL，同形）。
    let authority = match uri.port() {
        Some(_) => format!("{host}:{port}"),
        None => host.clone(),
    };
    let path = if uri.path().is_empty() { "/" } else { uri.path() };
    let path_and_query = match uri.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    };
    let uri = format!("https://{authority}{path_and_query}")
        .parse()
        .map_err(|e| mask_err(format!("xdns: invalid DoH url {}: {e}", url_label(url))))?;
    Ok(DohTarget { uri, host, port })
}

/// hyper-util legacy Client 请求体：一次性 DNS 报文。
type DohBody = Full<Bytes>;
/// h2 路客户端（连接池 + HTTP/2 多路复用，Go `http.Transport` 对位，bd 5lpw3）。
/// `Client` 内部 Arc 计数，全 worker 共享一个实例 = 共享一个池。
type DohClient = Client<DohConnector, DohBody>;

/// 单次请求的固定参数（所有 worker 共享）。
struct DohEndpoint {
    uri: Uri,
    /// 复用客户端：keep-alive 连接池 + HTTP/2 多路复用（模块头差异 3）。
    client: DohClient,
}

/// DoH h2 拨号端（[`DohClient`] 的 connector）：直连 TCP（模块头差异 1）+ rustls
/// TLS（ALPN 通告 = 配置原样 `["h2"]`，wire 面与 Go `tlsConfig.NextProtos` 同形）。
/// 拨号成功即记 `remote`（Go `setaddr`）。ALPN 协商结果经 [`DohStream::connected`]
/// 报告给 hyper 决定 HTTP 版本——Go `ForceAttemptHTTP2` + `DialTLSContext` 的
/// 「ALPN==h2 ⇒ HTTP/2，否则 HTTP/1.1」语义。
#[derive(Clone)]
struct DohConnector {
    tls: Arc<tokio_rustls::rustls::ClientConfig>,
    server_name: tokio_rustls::rustls::pki_types::ServerName<'static>,
    /// Go `setaddr`：拨号对端（响应包 addr 标签用）。
    remote: Arc<Mutex<SocketAddr>>,
    /// 拨号缺省目标（legacy client 传来的 URI authority 兜底）。
    host: String,
    port: u16,
}

impl TowerService<Uri> for DohConnector {
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<DohStream, Self::Error>> + Send>>;
    type Response = DohStream;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            // 内层 io::Error 面（`?` 走 From），出口统一装箱成 legacy Client 的错误类型。
            let stream: io::Result<DohStream> = async {
                let host = uri.host().unwrap_or(&this.host);
                let port = uri.port_u16().unwrap_or(this.port);
                let tcp = tokio::net::TcpStream::connect((host, port)).await.map_err(|e| {
                    io::Error::new(e.kind(), format!("xdns: DoH connect {host}:{port}: {e}"))
                })?;
                // Go `setaddr`：记录拨号对端，供响应包 addr 标签（见模块头）。
                if let Ok(peer) = tcp.peer_addr() {
                    *this.remote.lock() = peer;
                }
                let tls = TlsConnector::from(this.tls.clone())
                    .connect(this.server_name.clone(), tcp)
                    .await
                    .map_err(|e| {
                        io::Error::other(format!("xdns: DoH TLS handshake failed: {e}"))
                    })?;
                // ALPN 协商结果决定 hyper 的 HTTP 版本（h2 ⇒ HTTP/2，其余 ⇒ HTTP/1.1，
                // 同 splithttp Btls 分支形态）。
                let alpn_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                Ok(DohStream { io: TokioIo::new(tls), alpn_h2 })
            }
            .await;
            stream.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        })
    }
}

/// [`DohConnector`] 的连接：TLS 流 + ALPN 协商结果。
struct DohStream {
    io: TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    alpn_h2: bool,
}

impl hyper::rt::Read for DohStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for DohStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

impl HttpConnection for DohStream {
    fn connected(&self) -> Connected {
        if self.alpn_h2 { Connected::new().negotiated_h2() } else { Connected::new() }
    }
}

impl DohEndpoint {
    /// POST 一条 DNS 查询，返回响应体（≤ [`DOH_RECV_MAX`] 字节）。
    async fn post(&self, body: &[u8], cooldown: &Cooldown) -> io::Result<Vec<u8>> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.do_post(body, cooldown))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "xdns: DoH request timed out"))?
    }

    async fn do_post(&self, body: &[u8], cooldown: &Cooldown) -> io::Result<Vec<u8>> {
        let req = http::Request::builder()
            .method(Method::POST)
            .uri(self.uri.clone())
            .header(CONTENT_TYPE, DNS_MEDIA_TYPE)
            .header(ACCEPT, DNS_MEDIA_TYPE)
            .header(http::header::USER_AGENT, "") // Go：req.Header.Set("User-Agent", "")
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|e| io::Error::other(format!("xdns: DoH build request: {e}")))?;
        let response = self
            .client
            .request(req)
            .await
            .map_err(|e| io::Error::other(format!("xdns: DoH request: {e}")))?;

        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            // Go `resolver_doh.go:224-233`：只读 `Retry-After`；解析不出 ⇒ 不设冷却。
            if let Some(until) = response
                .headers()
                .get(http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(retry_after_until)
            {
                extend_cooldown(cooldown, until);
            }
        }
        if status != StatusCode::OK {
            return Err(io::Error::other(format!("xdns: DoH status {status}")));
        }
        let mut recv = response.into_body();
        let mut out = Vec::with_capacity(DOH_RECV_MAX);
        while let Some(frame) = recv.frame().await {
            let frame = frame.map_err(|e| io::Error::other(format!("xdns: DoH read body: {e}")))?;
            if let Some(chunk) = frame.data_ref() {
                let take = chunk.len().min(DOH_RECV_MAX - out.len());
                out.extend_from_slice(&chunk[..take]);
            }
            if out.len() >= DOH_RECV_MAX {
                break;
            }
        }
        Ok(out)
    }
}

/// DoH 传输选择（Go `resolver_doh.go:52-104` 的 `switch`）：`alpn == ["h3"]` 走
/// HTTP/3 over QUIC，其余走既有 TLS+h2（该路径一行未改）。
enum DohTransport {
    H2(DohEndpoint),
    H3(doh3::Doh3Endpoint),
}

impl DohTransport {
    /// POST 一条 DNS 查询，返回响应体（≤ [`DOH_RECV_MAX`] 字节）。
    ///
    /// `cooldown` 两路共用（429 冷却，见模块头差异 5；bd 6eqgp）。
    async fn post(
        &self,
        body: &[u8],
        remote: &Mutex<SocketAddr>,
        cooldown: &Cooldown,
    ) -> io::Result<Vec<u8>> {
        match self {
            Self::H2(endpoint) => endpoint.post(body, cooldown).await,
            Self::H3(endpoint) => endpoint.post(body, remote, cooldown).await,
        }
    }
}

/// DoH 传输端：`worker` 个 POST 任务共享一条请求队列（Go `DOHResolver`）。
pub(crate) struct DohResolver {
    tx: doh_queue::Sender<Vec<u8>>,
    /// 最近一次拨号的对端地址（Go `setaddr`）。
    remote: Arc<Mutex<SocketAddr>>,
    /// 429 冷却窗（Go `DOHResolver.time`）：生产路径只经 worker 各自的 Arc 克隆读写，
    /// 本字段是保留给测试断言窗长/冷却态的持有者。
    #[cfg(test)]
    cooldown: Arc<Cooldown>,
}

impl DohResolver {
    /// 校验配置并起 `worker` 个 POST 任务；响应字节经 `resp_tx` 回投（带 resolver 下标）。
    pub(crate) fn new(
        params: &DohParams,
        worker: i32,
        index: usize,
        resp_tx: mpsc::Sender<(usize, Vec<u8>)>,
    ) -> io::Result<Self> {
        // Go `NewDOHResolver`：`config.Worker < 1` → "invalid worker"。
        if worker < 1 {
            return Err(mask_err("xdns: invalid worker"));
        }
        let target = parse_target(&params.url)?;
        let tls = build_rustls_client_config(&params.tls)?
            .ok_or_else(|| io::Error::other("xdns: DoH tls config produced no client config"))?;
        let sni = params.sni.clone().unwrap_or_else(|| target.host.clone());
        let tls = Arc::new(tls);
        let remote = Arc::new(Mutex::new(SocketAddr::from(([0u8, 0, 0, 0], 0))));
        let endpoint = Arc::new(if params.h3 {
            DohTransport::H3(doh3::Doh3Endpoint::new(
                target.uri,
                target.host,
                target.port,
                tls,
                sni,
                params.quic.clone(),
            ))
        } else {
            let server_name =
                tokio_rustls::rustls::pki_types::ServerName::try_from(sni).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("xdns: invalid DoH SNI: {e}"),
                    )
                })?;
            let connector = DohConnector {
                tls,
                server_name,
                remote: remote.clone(),
                host: target.host.clone(),
                port: target.port,
            };
            DohTransport::H2(DohEndpoint {
                uri: target.uri,
                // 连接池 + HTTP/2 多路复用（bd 5lpw3）：全 worker 共享（Go 一个
                // `http.Client` 对位）。
                client: Client::builder(TokioExecutor::new()).build(connector),
            })
        });

        // PM-06：MPMC 有界通道——多 worker 各自 recv，无锁跨 await（tokio mpsc
        // Receiver 单消费者，旧实现 `Mutex<Receiver>` 锁跨 await 序列化所有 worker）。
        let (tx, rx) = doh_queue::bounded::<Vec<u8>>(QUEUE_CAP);
        let cooldown = Arc::new(Cooldown::default());
        for _ in 0..worker {
            let endpoint = endpoint.clone();
            let rx = rx.clone();
            let resp_tx = resp_tx.clone();
            let remote = remote.clone();
            let cooldown = cooldown.clone();
            #[allow(
                clippy::disallowed_methods,
                reason = "②豁免（bd kwevg · §3.5.6）：DoH worker（数据面 DoH 泵）；任务必须长于组件（进程级/数据面逐包泵/公开契约外返），不迁托管口"
            )]
            tokio::spawn(async move {
                let mut dropped = 0u64;
                // DoH 请求失败计数（限频窗口，bd u0pe2 ①）
                let mut failed = 0u64;
                loop {
                    let Ok(payload) = rx.recv().await else { return };
                    if cooling(&cooldown) {
                        // Go `resolver_doh.go:236-252`：冷却窗内取到的 payload 直接丢（不
                        // 排队），本次查询由客户端超时收场。限频 WARN——否则冷却期就是
                        // 「DNS 静默失败」（bd u0pe2 同型坑）。
                        dropped += 1;
                        if dropped == 1 || dropped % 32 == 0 {
                            crate::hot_log!(
                                tracing::Level::WARN,
                                "dropped={dropped} xdns: DoH server asked to back off (429), query dropped"
                            );
                        }
                        continue;
                    }
                    dropped = 0;
                    match endpoint.post(&payload, &remote, &cooldown).await {
                        Ok(body) => {
                            failed = 0;
                            if resp_tx.send((index, body)).await.is_err() {
                                return; // 读端已关（client 已 drop）
                            }
                        },
                        Err(e) => {
                            // DoH 请求失败 = DNS 解析面故障（证书/SNI/ALPN/网络/上游
                            // 5xx），Go 同点 resolver_doh.go:250-253 用 Severity_Error
                            // 恒可见；DEBUG 在生产默认 warn 门下不可见（bd u0pe2 ①）。
                            // 限频：故障窗首条 + 每 32 条，防服务器宕机时随查询刷屏
                            // （同上方 429 冷却丢弃的限频形态）。
                            failed += 1;
                            if failed == 1 || failed % 32 == 0 {
                                crate::hot_log!(
                                    tracing::Level::WARN,
                                    "fails={failed} error={e} xdns: DoH request failed"
                                );
                            }
                        },
                    }
                }
            });
        }
        Ok(Self {
            tx,
            remote,
            #[cfg(test)]
            cooldown,
        })
    }

    /// 记录的对端地址（Go `DOHResolver.Addr`）。
    pub(crate) fn remote_addr(&self) -> SocketAddr {
        *self.remote.lock()
    }

    /// 投递一条 DNS 查询（Go `Send`：队列满时等待空闲 worker）。
    pub(crate) async fn send(&self, payload: &[u8]) -> io::Result<()> {
        self.tx
            .send(payload.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "xdns: DoH resolver closed"))
    }

    /// 测试钩子：冷却窗快照（冷却中？+ 截止时刻）。doh3 测试断言 h3 的 429 落
    /// **同一个**冷却窗（bd 6eqgp）用；生产面无此读口。
    #[cfg(test)]
    pub(super) fn test_cooldown_state(&self) -> (bool, Option<Instant>) {
        (cooling(&self.cooldown), *self.cooldown.lock())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(tls: Option<Value>) -> io::Result<DohParams> {
        DohParams::from_json("https://127.0.0.1:8443/dns-query", tls.as_ref(), None)
    }

    /// 缺省：URL host 作 SNI、ALPN 固定 h2、无自定义根。
    #[test]
    fn json_defaults() {
        let p = params(None).unwrap();
        assert_eq!(p.sni, None);
        assert_eq!(p.tls.alpn, vec!["h2".to_string()]);
        assert!(p.tls.ca_certificates.is_empty());
        assert!(!p.tls.disable_system_root);
        assert!(p.tls.min_version.is_none());
    }

    /// `serverName` 生效（与 URL host 解耦）；`allowInsecure: false` 无害放行。
    #[test]
    fn json_server_name_and_allow_insecure_false() {
        let p = params(Some(serde_json::json!({
            "serverName": "dns.example.net",
            "allowInsecure": false,
            "alpn": ["h2"]
        })))
        .unwrap();
        assert_eq!(p.sni.as_deref(), Some("dns.example.net"));
    }

    /// `allowInsecure: true` 硬错（禁用跳过校验）。
    #[test]
    fn json_rejects_allow_insecure_true() {
        let e = params(Some(serde_json::json!({"allowInsecure": true}))).unwrap_err();
        assert!(e.to_string().contains("allowInsecure"), "{e}");
    }

    /// 未支持键配置期硬错点名（禁静默忽略）。
    #[test]
    fn json_rejects_unknown_key_by_name() {
        let e = params(Some(serde_json::json!({"fingerprint": "chrome"}))).unwrap_err();
        assert!(e.to_string().contains("fingerprint"), "{e}");
        let e = params(Some(serde_json::json!({"maxVersion": "1.3"}))).unwrap_err();
        assert!(e.to_string().contains("maxVersion"), "{e}");
    }

    /// ALPN：`["h3"]` → DoH-over-QUIC（`h3` 标记 + ALPN 落 rustls）；其它 → 只支持 h2。
    #[test]
    fn json_alpn_h3_and_other_rejected() {
        let p = params(Some(serde_json::json!({"alpn": ["h3"]}))).unwrap();
        assert!(p.h3, "alpn [\"h3\"] 必须走 HTTP/3");
        assert_eq!(p.tls.alpn, vec!["h3".to_string()]);
        let e = params(Some(serde_json::json!({"alpn": ["http/1.1"]}))).unwrap_err();
        assert!(e.to_string().contains("h2"), "{e}");
        // `["h3","h2"]` 不是 Go 的 h3 判据（要求 len==1）⇒ 硬错不静默择一
        let e = params(Some(serde_json::json!({"alpn": ["h3", "h2"]}))).unwrap_err();
        assert!(e.to_string().contains("alpn"), "{e}");
        // 显式 ["h2"] 放行，走 h2
        let p = params(Some(serde_json::json!({"alpn": ["h2"]}))).unwrap();
        assert!(!p.h3);
    }

    /// `quicConfig` 解析并按 Go `QuicParamsConfig.Build()` 校验（只在 h3 生效）。
    #[test]
    fn json_accepts_quic_config() {
        let p = DohParams::from_json(
            "https://127.0.0.1/dns-query",
            None,
            Some(&serde_json::json!({"congestion": "bbr", "maxIdleTimeout": 30})),
        )
        .unwrap();
        assert!(!p.h3, "quicConfig 单独出现不走 h3（Go 只在 alpn h3 时读它）");
        assert_eq!(p.tls.alpn, vec!["h2".to_string()]);

        // 未实现控制器硬错点名（禁静默忽略）
        let e = DohParams::from_json(
            "https://127.0.0.1/dns-query",
            Some(&serde_json::json!({"alpn": ["h3"]})),
            Some(&serde_json::json!({"congestion": "force-brutal"})),
        )
        .unwrap_err();
        assert!(e.to_string().contains("force-brutal"), "{e}");
    }

    /// `minVersion` 1.2/1.3 生效；1.0/1.1 与乱值硬错。
    #[test]
    fn json_min_version() {
        assert_eq!(
            params(Some(serde_json::json!({"minVersion": "1.3"}))).unwrap().tls.min_version,
            Some(MinTlsVersion::Tls13)
        );
        assert_eq!(
            params(Some(serde_json::json!({"minVersion": "1.2"}))).unwrap().tls.min_version,
            Some(MinTlsVersion::Tls12)
        );
        assert!(params(Some(serde_json::json!({"minVersion": "1.1"}))).is_err());
        assert!(params(Some(serde_json::json!({"minVersion": "2"}))).is_err());
    }

    /// `certificates[].certificate` 转 DER 信任根；`key`/`certificatePath` 硬错。
    #[test]
    fn json_certificates_take_ca_pem_only() {
        let (pem, _) = test_cert();
        let p = params(Some(serde_json::json!({
            "certificates": [{"certificate": pem, "usage": "AUTHORITY_VERIFY"}],
            "disableSystemRoot": true
        })))
        .unwrap();
        assert_eq!(p.tls.ca_certificates.len(), 1);
        assert!(p.tls.disable_system_root);
        let err =
            params(Some(serde_json::json!({"certificates": [{"certificate": pem, "key": "x"}]})))
                .unwrap_err();
        assert!(err.to_string().contains("key"), "{err}");
    }

    /// URL 规范化：`https://host` → 路径补 `/`；非 https / 无 host 硬错。
    #[test]
    fn url_normalization() {
        let t = parse_target("https://dns.google").unwrap();
        assert_eq!(t.uri.to_string(), "https://dns.google/");
        assert_eq!(t.port, 443);
        let t = parse_target("https://1.1.1.1:8443/dns-query?x=1").unwrap();
        assert_eq!(t.uri.to_string(), "https://1.1.1.1:8443/dns-query?x=1");
        assert_eq!(t.port, 8443);
        assert!(parse_target("http://dns.google/dns-query").is_err());
        assert!(parse_target("https:///dns-query").is_err());
    }

    /// 自签证书 PEM + 私钥 DER（SNI：localhost）。
    fn test_cert() -> (String, Vec<u8>) {
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_der())
    }

    /// h2 假 DoH 服务器（TLS + 自签证书）：第 n 个请求回 `script[min(n, len-1)]`。
    /// 返回 (端口, CA PEM, 命中计数, **TCP 连接计数**——连接复用断言用)。
    async fn mock_doh(
        script: Vec<(StatusCode, Option<&'static str>)>,
        delay: Duration,
    ) -> (u16, String, Arc<std::sync::atomic::AtomicUsize>, Arc<std::sync::atomic::AtomicUsize>)
    {
        use std::sync::atomic::AtomicUsize;

        use tokio::net::TcpListener;
        use tokio_rustls::{
            TlsAcceptor,
            rustls::{
                ServerConfig,
                pki_types::{CertificateDer, PrivateKeyDer},
            },
        };

        xray_common::ensure_default_crypto_provider();
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
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = hits.clone();
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_srv = accepts.clone();
        #[allow(clippy::disallowed_methods, reason = "测试用 DoH 假服务器：accept 环")]
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { return };
                // 一条 TCP 连接 = 一次 accept（连接复用断言：多次查询 ⇒ accepts 不涨）。
                accepts_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let script = script.clone();
                let hits = hits_srv.clone();
                let delay = delay;
                #[allow(clippy::disallowed_methods, reason = "测试用 DoH 假服务器：每连接一任务")]
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(sock).await else { return };
                    let Ok(mut conn) = h2::server::handshake(tls).await else { return };
                    while let Some(accepted) = conn.accept().await {
                        let Ok((req, mut respond)) = accepted else { return };
                        let n = hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let (status, retry_after) = script[n.min(script.len() - 1)];
                        let mut body = req.into_body();
                        while let Some(Ok(_)) = body.data().await {}
                        let mut resp = http::Response::builder().status(status);
                        if let Some(v) = retry_after {
                            resp = resp.header(http::header::RETRY_AFTER, v);
                        }
                        // 每请求一任务：延迟并行（连接内多流不互相阻塞）。
                        #[allow(
                            clippy::disallowed_methods,
                            reason = "测试用 DoH 假服务器：每请求一任务"
                        )]
                        tokio::spawn(async move {
                            if !delay.is_zero() {
                                tokio::time::sleep(delay).await;
                            }
                            if let Ok(send) = respond.send_response(resp.body(()).unwrap(), true) {
                                let _ = send; // 空体 + end_stream
                            }
                        });
                    }
                });
            }
        });
        (port, cert_pem, hits, accepts)
    }

    /// 指向 mock 服务器的 resolver（验证「全 worker 共享一个冷却窗」）。
    fn doh_resolver(
        port: u16,
        cert_pem: &str,
        worker: usize,
    ) -> (DohResolver, mpsc::Receiver<(usize, Vec<u8>)>) {
        let params = DohParams::from_json(
            &format!("https://127.0.0.1:{port}/dns-query"),
            Some(&serde_json::json!({
                "serverName": "localhost",
                "certificates": [{"certificate": cert_pem}]
            })),
            None,
        )
        .unwrap();
        let (resp_tx, resp_rx) = mpsc::channel::<(usize, Vec<u8>)>(8);
        (DohResolver::new(&params, worker as i32, 0, resp_tx).unwrap(), resp_rx)
    }

    /// 等 mock 服务器命中数达到 `want`（超时即失败，附实际值）。
    async fn wait_hits(hits: &std::sync::atomic::AtomicUsize, want: usize) {
        let deadline = now() + Duration::from_secs(10);
        while hits.load(std::sync::atomic::Ordering::SeqCst) < want {
            let got = hits.load(std::sync::atomic::Ordering::SeqCst);
            assert!(now() < deadline, "命中数停在 {got}，期望 {want}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// 等 429 落地的冷却窗（最多 5s；未落地即失败）。
    async fn wait_cooling(resolver: &DohResolver) {
        let deadline = now() + Duration::from_secs(5);
        while !cooling(&resolver.cooldown) {
            assert!(now() < deadline, "429 未设置冷却窗");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// bd 28nbk ①a：`429 + Retry-After: 60` ⇒ 冷却窗内 worker 丢弃后续查询，不再打服务器
    /// （Go `resolver_doh.go:236-252` 同款：丢 payload，不排队）。
    #[tokio::test]
    async fn doh_429_cooldown_drops_queued_queries() {
        let (port, cert, hits, _accepts) =
            mock_doh(vec![(StatusCode::TOO_MANY_REQUESTS, Some("60"))], Duration::ZERO).await;
        let (resolver, _resp_rx) = doh_resolver(port, &cert, 2);

        resolver.send(b"q1").await.unwrap();
        wait_hits(&hits, 1).await;
        wait_cooling(&resolver).await;
        let until = (*resolver.cooldown.lock()).expect("冷却窗必须已置位");
        assert!(
            until.duration_since(now()) > Duration::from_secs(50),
            "Retry-After: 60 的窗不足 50s：{until:?}"
        );

        for _ in 0..4 {
            resolver.send(b"q2").await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "冷却窗内仍把请求打到了服务器"
        );
    }

    /// bd 28nbk 补充（PM 门：丢弃不得变永久挂住）：冷却丢弃是**有界**的——窗按
    /// `Retry-After` 的秒数到点即恢复，worker 不被打死、也不阻塞在丢弃上。
    #[tokio::test]
    async fn doh_cooldown_expires_and_worker_stays_alive() {
        let (port, cert, hits, _accepts) =
            mock_doh(vec![(StatusCode::TOO_MANY_REQUESTS, Some("1"))], Duration::ZERO).await;
        let (resolver, _resp_rx) = doh_resolver(port, &cert, 2);

        resolver.send(b"q1").await.unwrap();
        wait_hits(&hits, 1).await;
        wait_cooling(&resolver).await;
        resolver.send(b"q2").await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1, "1s 窗内不该再发请求");

        // 窗到点（1s）后同一 worker 继续服务：`Retry-After` 的值被兑现，无永久停摆。
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(!cooling(&resolver.cooldown), "1s 的窗必须已过期");
        resolver.send(b"q3").await.unwrap();
        wait_hits(&hits, 2).await;
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// bd 28nbk ②：非法 `Retry-After`（HTTP-date / 乱串 / 超 u32）⇒ 不设冷却、不硬失败
    /// （Go 两种形式都解析失败时同样只报错）。
    #[tokio::test]
    async fn doh_429_illegal_retry_after_does_not_cool() {
        let (port, cert, hits, _accepts) = mock_doh(
            vec![
                (StatusCode::TOO_MANY_REQUESTS, Some("Wed, 21 Oct 2015 07:28:00 GMT")),
                (StatusCode::TOO_MANY_REQUESTS, Some("nonsense")),
                (StatusCode::TOO_MANY_REQUESTS, Some("99999999999999")),
            ],
            Duration::ZERO,
        )
        .await;
        let (resolver, _resp_rx) = doh_resolver(port, &cert, 2);

        for _ in 0..3 {
            resolver.send(b"q").await.unwrap();
        }
        wait_hits(&hits, 3).await;
        assert!(resolver.cooldown.lock().is_none(), "非法 Retry-After 不得设冷却窗");
    }

    /// bd 5lpw3 ①：同一 resolver 连续 N 次查询只建 **1** 条 TCP 连接（legacy Client
    /// 连接池 keep-alive + HTTP/2 多路复用，Go `http.Transport` 对位）。可断言计数
    /// 器 = 服务器侧 accept 计数，非肉眼观察。
    #[tokio::test]
    async fn doh_h2_reuses_connection_across_queries() {
        let (port, cert, hits, accepts) =
            mock_doh(vec![(StatusCode::OK, None)], Duration::ZERO).await;
        let (resolver, mut resp_rx) = doh_resolver(port, &cert, 1);

        for i in 0..3u8 {
            resolver.send(&[i]).await.unwrap();
            let (_, body) = tokio::time::timeout(Duration::from_secs(10), resp_rx.recv())
                .await
                .expect("响应超时")
                .expect("resolver 关闭");
            assert!(body.is_empty(), "mock 回空体");
        }
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 3, "3 次查询必须全命中");
        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "连接池必须复用同一条 TCP 连接（3 次查询 ≠ 3 次建连）"
        );
    }

    /// bd PM-06（验收「N 个 worker 同时在等 ⇒ 真并行」）：4 worker + 每请求 300ms
    /// 服务端延迟，连发 4 条查询 ⇒ 总耗时远小于串行 4×300ms（串行下界 1.2s，
    /// 并行 ≈ 0.3s；700ms 阈值给 CI 抖动留余量）。MPMC 通道下 4 个 worker 各自
    /// recv 等 items，同一时刻并发处理。
    #[tokio::test]
    async fn worker_pool_processes_queries_concurrently() {
        let delay = Duration::from_millis(300);
        let (port, cert, hits, _accepts) = mock_doh(vec![(StatusCode::OK, None)], delay).await;
        let (resolver, mut resp_rx) = doh_resolver(port, &cert, 4);

        let start = now();
        for i in 0..4u8 {
            resolver.send(&[i]).await.unwrap();
        }
        for _ in 0..4 {
            tokio::time::timeout(Duration::from_secs(10), resp_rx.recv())
                .await
                .expect("响应超时")
                .expect("resolver 关闭");
        }
        let elapsed = now().duration_since(start);
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 4);
        assert!(
            elapsed < Duration::from_millis(700),
            "4 条查询耗时 {elapsed:?}，仍是串行（串行下界 ≈ 1.2s）"
        );
    }

    /// bd 28nbk ①b/①c：`Retry-After` 只进不退（Go `if t.After(r.time) { r.time = t }`）——
    /// 更短的不缩短已生效的窗，更长的延长。
    #[test]
    fn cooldown_extension_never_shrinks() {
        let t0 = now();
        let window = Cooldown::default();
        extend_cooldown(&window, t0 + Duration::from_secs(60));
        assert_eq!(*window.lock(), Some(t0 + Duration::from_secs(60)));
        extend_cooldown(&window, t0 + Duration::from_secs(10));
        assert_eq!(
            *window.lock(),
            Some(t0 + Duration::from_secs(60)),
            "Retry-After: 10 缩短了 60s 的窗"
        );
        extend_cooldown(&window, t0 + Duration::from_secs(3600));
        assert_eq!(
            *window.lock(),
            Some(t0 + Duration::from_secs(3600)),
            "Retry-After: 3600 未延长窗"
        );
    }

    /// `Retry-After` 只认 `delta-seconds`（Go `strconv.ParseUint(value, 10, 32)` 同分支）。
    #[test]
    fn retry_after_parses_delta_seconds_only() {
        assert!(retry_after_until("0").is_some());
        assert!(retry_after_until("60").is_some());
        assert!(retry_after_until("Wed, 21 Oct 2015 07:28:00 GMT").is_none());
        assert!(retry_after_until("nonsense").is_none());
        assert!(retry_after_until("-1").is_none());
        assert!(retry_after_until("4294967296").is_none(), "超 u32 秒数 Go 同样失败");
    }

    /// `url_label`：只留 `scheme://host[:port]`。
    #[test]
    fn url_label_strips_userinfo_path_and_query() {
        assert_eq!(
            url_label("https://user:pass@dns.google:8443/dns-query?key=SECRET"),
            "https://dns.google:8443"
        );
        assert_eq!(url_label("https://dns.google"), "https://dns.google");
        assert_eq!(url_label("not-a-url"), "not-a-url");
    }

    /// bd rjcu4：配置期错误只留 `scheme://host:port`——凭据（`user:pass@`）与 query
    /// （`?key=SECRET`）不得进错误文本（会随「配置装配失败」上报）。
    #[test]
    fn config_errors_redact_url_credentials() {
        let redacted = |msg: &str| {
            assert!(!msg.contains("SECRET"), "query 泄漏：{msg}");
            assert!(!msg.contains("pass"), "userinfo 泄漏：{msg}");
            assert!(!msg.contains("/dns-query"), "path 未剥：{msg}");
        };
        // ① 无 host（authority 为空）
        let e = DohParams::from_json("https://user:pass@/dns-query?key=SECRET", None, None)
            .unwrap_err();
        redacted(&e.to_string());
        // ② 非 https：仍要说清是哪个目标（scheme://host:port）
        let e = DohParams::from_json("http://user:pass@dns.google:8443/q?key=SECRET", None, None)
            .unwrap_err();
        redacted(&e.to_string());
        assert!(e.to_string().contains("http://dns.google:8443"), "{e}");
        // ③ Uri 解析失败（空格）
        let Err(e) = parse_target("https://user:pass@ho st/q?key=SECRET") else {
            panic!("带空格的 URL 必须解析失败");
        };
        redacted(&e.to_string());
    }
}
