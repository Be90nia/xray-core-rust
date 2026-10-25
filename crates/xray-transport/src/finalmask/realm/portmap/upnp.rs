//! # UPnP IGD 客户端（SSDP 发现 → device description → SOAP；NAT-PMP 不可用时回退）
//!
//! 零新依赖：SSDP 走 tokio `UdpSocket`，description/SOAP 走仓内既有 `reqwest`。
//! 只覆盖 IGD 的 UDP 端口映射面：AddPortMapping / DeletePortMapping /
//! GetSpecificPortMappingEntry / GetExternalIPAddress；消息构造与解析都是纯函数，
//! 测试可直接喂合成字节。
//!
//! 限制（IGD v1 规范面）：没有「查询本映射实际外部端口」的 action，外部端口即
//! 请求端口（与 Go go-nat 的 UPnP 后端同做法）；租期由 `NewLeaseDuration` 给出。
//!
//! 不可信输入收口（SSDP 应答方是攻击者可控的）：
//! - SSDP 应答源必须是本机、默认网关或与网关同 /16 的主机（[`ssdp_peer_allowed`]）；
//! - description URL 的 host 必须是 IP 字面量，且与 SSDP 应答源同一个 host；
//! - `<URLBase>`/`controlURL` 不得把控制面搬到别的 host（host 必须等于 description host）；
//! - 不跟 HTTP 重定向（一次 302 就能把抓取导去任意内网主机）；
//! - description / SOAP 响应体流式读取，超上限立即中止（不先读完再校验）。

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use tokio::{
    net::UdpSocket,
    time::{Instant, timeout_at},
};

/// UPnP SSDP 组播地址（UPnP Device Architecture 1.1 §1.2.2 固定值）。
pub const SSDP_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);

/// IGD 端口映射服务类型前缀（`:1`/`:2` 版本后缀因设备而异，按前缀匹配）。
const WANIP_SERVICE_PREFIX: &str = "urn:schemas-upnp-org:service:WANIPConnection:";
/// PPP 拨号型网关的等价服务（优先 WANIPConnection，缺则用它）。
const WANPPP_SERVICE_PREFIX: &str = "urn:schemas-upnp-org:service:WANPPPConnection:";

/// SSDP 搜索目标（顺序即优先级）。
const SSDP_SEARCH_TARGETS: [&str; 3] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "upnp:rootdevice",
];

/// 映射描述（Go `portMapDescription`）。
const PORT_MAPPING_DESCRIPTION: &str = "hysteria-realm";
/// SSDP 响应上限（规范响应 <1.5KB）。
const SSDP_BUF_LEN: usize = 2048;
/// device description 上限（设备 XML 通常几 KB，防 OOM）。
const MAX_DESCRIPTION_SIZE: usize = 256 * 1024;
/// SOAP 响应上限（AddPortMapping 答复是空元素，fault 体 <1KB）。
const MAX_SOAP_RESPONSE_SIZE: usize = 64 * 1024;
/// SSDP 无应答时兜底候选端口（miniupnpd 缺省 5000；UPnP 标准端口段 49152/49153）。
const FALLBACK_PORTS: [u16; 3] = [5000, 49152, 49153];

/// 构造 M-SEARCH 请求（UPnP Device Architecture §1.3.2）。
#[must_use]
pub fn build_msearch(target: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_ADDR}\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {target}\r\n\r\n"
    )
}

/// 从 SSDP 响应取 `LOCATION`（description URL）。非 200 或缺 LOCATION → `None`。
#[must_use]
pub fn parse_ssdp_location(response: &str) -> Option<String> {
    let mut lines = response.lines();
    let status = lines.next()?;
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        return None;
    }
    lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("location").then(|| value.trim().to_string())
        })
        .find(|value| !value.is_empty())
}

/// 从 device description 提取 IGD 控制端点，返回 `(service_type, 绝对 controlURL)`。
///
/// WANIPConnection 优先，缺则退 WANPPPConnection；相对 controlURL 按
/// `<URLBase>`（缺则 description 自身的 LOCATION）解析。
#[must_use]
pub fn parse_control_url(description: &str, location: &str) -> Option<(String, String)> {
    let base = extract_tag(description, "URLBase").unwrap_or_else(|| location.to_string());
    let mut ppp: Option<(String, String)> = None;
    for block in blocks(description, "<service>", "</service>") {
        let Some(service_type) = extract_tag(block, "serviceType") else {
            continue;
        };
        let Some(control) = extract_tag(block, "controlURL") else {
            continue;
        };
        if service_type.starts_with(WANIP_SERVICE_PREFIX) {
            return resolve_url(&base, &control).map(|url| (service_type, url));
        }
        if ppp.is_none() && service_type.starts_with(WANPPP_SERVICE_PREFIX) {
            ppp = resolve_url(&base, &control).map(|url| (service_type, url));
        }
    }
    ppp
}

/// 构造 SOAP 1.1 请求体（UPnP IGD §3.2 动作调用形态）。
#[must_use]
pub fn build_soap_envelope(service_type: &str, action: &str, args: &[(&str, String)]) -> String {
    let mut args_xml = String::new();
    for (name, value) in args {
        args_xml.push_str(&format!("<{name}>{}</{name}>", xml_escape(value)));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
         <u:{action} xmlns:u=\"{service_type}\">{args_xml}</u:{action}>\
         </s:Body></s:Envelope>"
    )
}

/// SOAP 头 `SOAPAction` 值（带引号的 `"serviceType#action"`）。
#[must_use]
pub fn soap_action_header(service_type: &str, action: &str) -> String {
    format!("\"{service_type}#{action}\"")
}

/// SOAP Fault 里的 UPnP 错误（网关拒绝原因，必须可见）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoapError {
    pub code: String,
    pub description: String,
}

/// `GetSpecificPortMappingEntry` 答复（按外部端口查现存映射详情）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingEntry {
    pub internal_port: u16,
    pub internal_client: Ipv4Addr,
    pub enabled: bool,
    /// 网关回显的描述文本（XML 转义态）。
    pub description: String,
    pub lease_duration: u32,
}

/// 从 SOAP 响应体提取 UPnPError；非 fault 体 → `None`。
#[must_use]
pub fn parse_soap_error(body: &str) -> Option<SoapError> {
    let code = extract_tag(body, "errorCode")?;
    Some(SoapError { code, description: extract_tag(body, "errorDescription").unwrap_or_default() })
}

/// UPnP IGD 客户端（一次发现后常驻，供续租/删除复用）。
pub struct Client {
    http: reqwest::Client,
    control_url: reqwest::Url,
    service_type: String,
    local_ip: Ipv4Addr,
}

impl Client {
    /// SSDP 发现 + description 解析 + 本机 LAN 地址探测。
    ///
    /// 只走 SSDP：网关 1900 端口被局域网其他服务占用时永远收不到应答（实测存在），
    /// 需要兜底用 `discover_with_fallbacks`（`PortMapper` 生产路径已接线）。
    ///
    /// `search_addr` 可注入（单测指向本地 stub；生产为 [`SSDP_ADDR`] 组播）。
    pub async fn discover(search_addr: SocketAddrV4, timeout: Duration) -> io::Result<Self> {
        Self::discover_with_fallbacks(search_addr, timeout, &[]).await
    }

    /// [`Client::discover`] 加 SSDP 无应答兜底：依次直取 `fallbacks` 里的
    /// description URL，首个成功即用；全失败 → 一条错误保留 SSDP 失败原文 +
    /// 每个候选的结果（fail-visible）。
    pub(crate) async fn discover_with_fallbacks(
        search_addr: SocketAddrV4,
        timeout: Duration,
        fallbacks: &[String],
    ) -> io::Result<Self> {
        let ssdp_err = match ssdp_location(search_addr, timeout).await {
            // SSDP 应答源即该 description 的唯一可信 host（防抢答者把抓取导去别处）
            Ok((location, peer)) => {
                return Self::from_pinned_description(&location, peer, timeout).await;
            },
            Err(e) => e,
        };
        let mut attempts = Vec::new();
        for url in fallbacks {
            match Self::from_description_url(url, timeout).await {
                Ok(client) => return Ok(client),
                Err(e) => attempts.push(format!("{url}: {e}")),
            }
        }
        if attempts.is_empty() {
            return Err(ssdp_err);
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{ssdp_err}; description fallbacks failed: {}", attempts.join("; ")),
        ))
    }

    /// 已知 description URL 直建客户端（跳过 SSDP；兜底路径与真机取证用）。
    ///
    /// host 必须是 IP 字面量且通过 [`ssdp_peer_allowed`]：兜底候选由
    /// [`fallback_description_urls`] 用默认网关构造，此处把「调用方传进来的任意
    /// URL」也钉在同一白名单上。
    pub async fn from_description_url(location: &str, timeout: Duration) -> io::Result<Self> {
        let host = description_host(location)?;
        if !ssdp_peer_allowed(host, super::default_ipv4_gateway().ok()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "UPnP: description url host {host} is neither this host, the default gateway, \
                     nor on its /16"
                ),
            ));
        }
        Self::from_pinned_description(location, host, timeout).await
    }

    /// `expected_host` = 该 description 唯一可信的 host（SSDP 路径 = 应答源 IP，
    /// 兜底路径 = description URL 的 IP 字面量）；`<URLBase>`/`controlURL` 都不得
    /// 把控制面搬到别的 host。
    async fn from_pinned_description(
        location: &str,
        expected_host: Ipv4Addr,
        timeout: Duration,
    ) -> io::Result<Self> {
        let host = description_host(location)?;
        if host != expected_host {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "UPnP: description url {location:?} points at {host}, not the SSDP responder \
                     {expected_host}"
                ),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            // 不跟重定向：一次 302 就能把 description 抓取导去任意内网主机
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| io::Error::other(format!("UPnP: build http client failed: {e}")))?;
        let description = fetch_description(&http, location).await?;
        let (service_type, control) =
            parse_control_url(&description, location).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("UPnP: no WANIPConnection/WANPPPConnection service in {location}"),
                )
            })?;
        let control_url = reqwest::Url::parse(&control).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("UPnP: bad control url {control:?}: {e}"),
            )
        })?;
        let control_host = url_host_ipv4(&control_url).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("UPnP: control url {control:?} must carry an IPv4 literal host"),
            )
        })?;
        if control_host != expected_host {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "UPnP: control url {control:?} points at {control_host}, not the description \
                     host {expected_host}"
                ),
            ));
        }
        let local_ip = local_ipv4_towards(&control_url).await?;
        Ok(Self { http, control_url, service_type, local_ip })
    }

    /// 添加/续租 UDP 映射；返回外部端口（IGD v1 = 请求端口）。
    pub async fn add_udp_mapping(&self, internal_port: u16, lifetime_secs: u32) -> io::Result<u16> {
        let external_port = internal_port;
        let args = [
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", external_port.to_string()),
            ("NewProtocol", "UDP".to_string()),
            ("NewInternalPort", internal_port.to_string()),
            ("NewInternalClient", self.local_ip.to_string()),
            ("NewEnabled", "1".to_string()),
            ("NewPortMappingDescription", PORT_MAPPING_DESCRIPTION.to_string()),
            ("NewLeaseDuration", lifetime_secs.to_string()),
        ];
        self.soap("AddPortMapping", &args).await?;
        Ok(external_port)
    }

    /// 删除指定外部端口的 UDP 映射。
    pub async fn delete_udp_mapping(&self, external_port: u16) -> io::Result<()> {
        let args = [
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", external_port.to_string()),
            ("NewProtocol", "UDP".to_string()),
        ];
        self.soap("DeletePortMapping", &args).await?;
        Ok(())
    }

    /// 网关公网 IPv4。
    pub async fn get_external_address(&self) -> io::Result<Ipv4Addr> {
        let body = self.soap("GetExternalIPAddress", &[]).await?;
        let value = extract_tag(&body, "NewExternalIPAddress").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "UPnP: GetExternalIPAddress response missing NewExternalIPAddress",
            )
        })?;
        value.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("UPnP: invalid external ip {value:?}"),
            )
        })
    }

    /// 按外部端口查询现存 UDP 映射（IGD `GetSpecificPortMappingEntry`）。
    ///
    /// 映射不存在 → 网关 SOAP fault（miniupnpd 714 NoSuchEntry）→ `Err`：
    /// 删除后复查 714 即「映射确实删净」的带内证据。
    pub async fn get_udp_mapping(&self, external_port: u16) -> io::Result<MappingEntry> {
        let args = [
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", external_port.to_string()),
            ("NewProtocol", "UDP".to_string()),
        ];
        let body = self.soap("GetSpecificPortMappingEntry", &args).await?;
        let missing = |tag: &str| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("UPnP: GetSpecificPortMappingEntry response missing {tag}"),
            )
        };
        let internal_port = extract_tag(&body, "NewInternalPort")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| missing("NewInternalPort"))?;
        let internal_client = extract_tag(&body, "NewInternalClient")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| missing("NewInternalClient"))?;
        let enabled = extract_tag(&body, "NewEnabled").ok_or_else(|| missing("NewEnabled"))?;
        let description = extract_tag(&body, "NewPortMappingDescription")
            .ok_or_else(|| missing("NewPortMappingDescription"))?;
        let lease_duration = extract_tag(&body, "NewLeaseDuration")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| missing("NewLeaseDuration"))?;
        Ok(MappingEntry {
            internal_port,
            internal_client,
            enabled: enabled == "1",
            description,
            lease_duration,
        })
    }

    /// 发一次 SOAP 动作；HTTP 非 2xx 或 fault 体一律 `Err`（带网关错误码）。
    async fn soap(&self, action: &str, args: &[(&str, String)]) -> io::Result<String> {
        let envelope = build_soap_envelope(&self.service_type, action, args);
        let response = self
            .http
            .post(self.control_url.clone())
            .header(reqwest::header::CONTENT_TYPE, "text/xml; charset=\"utf-8\"")
            .header("SOAPAction", soap_action_header(&self.service_type, action))
            .body(envelope)
            .send()
            .await
            .map_err(|e| io::Error::other(format!("UPnP {action}: {e}")))?;
        let status = response.status();
        let body =
            read_body_capped(response, MAX_SOAP_RESPONSE_SIZE, &format!("UPnP {action} response"))
                .await?;
        if !status.is_success() {
            return Err(soap_failure(action, status.as_u16(), &body));
        }
        // 200 也可能是 fault 体（部分实现如此），同样不得当成功
        if let Some(err) = parse_soap_error(&body) {
            return Err(io::Error::other(format!(
                "UPnP {action} fault: errorCode {}: {}",
                err.code, err.description
            )));
        }
        Ok(body)
    }
}

fn soap_failure(action: &str, status: u16, body: &str) -> io::Error {
    match parse_soap_error(body) {
        Some(err) => io::Error::other(format!(
            "UPnP {action} failed: HTTP {status}: errorCode {}: {}",
            err.code, err.description
        )),
        None => io::Error::other(format!("UPnP {action} failed: HTTP {status}")),
    }
}

/// SSDP 无应答时的兜底候选：默认路由网关的常见 IGD description 端点。
///
/// 平台取不到默认路由（显式 `Unsupported` 等）→ 空表：错误文案如实表现为
/// 无候选，不猜网关地址。
pub(crate) fn fallback_description_urls() -> Vec<String> {
    let Ok(gateway) = super::default_ipv4_gateway() else {
        return Vec::new();
    };
    FALLBACK_PORTS.iter().map(|port| format!("http://{gateway}:{port}/rootDesc.xml")).collect()
}

/// SSDP 应答源是否可信：本机（单测 stub / 同机 IGD）、默认网关，或与网关同网段。
///
/// 拦的是「任何主机都能应答 1900」这一面：抢答者此后也只能让我们访问**它自己**
/// （description/control 的 host 钉在应答源上），无法把我们导去第三方内网主机。
///
/// shortcut: 同网段判定按 /16 前缀（不读接口掩码），覆盖 /16~/24 的常见局域网
/// （含本机实测的 192.168.88.0/23：网关 .88.1、IGD .89.249）；/8 级跨 /16 的
/// IGD 会被拒，症状是 SSDP 静默、走默认网关兜底候选（fail-visible，不静默成功）。
/// 取不到默认路由的平台（macOS）退化为「只收私有源」。升级点=按路由表 on-link
/// 掩码判定。
fn ssdp_peer_allowed(peer: Ipv4Addr, gateway: Option<Ipv4Addr>) -> bool {
    if peer.is_loopback() {
        return true;
    }
    let Some(gateway) = gateway else {
        // 取不到默认路由（macOS 未实现网关查询）→ 退化为「只收私有源」：盲 SSRF 仍关闭
        // （description/control 的 host 钉在应答源上，应答方最多能让我们访问它自己），
        // 只是少了「必须是本段」这一层。
        return peer.is_private();
    };
    peer == gateway || peer.octets()[..2] == gateway.octets()[..2]
}

/// URL 的 host 当且仅当是 IPv4 字面量才返回值（域名可 rebinding，一律拒）。
fn url_host_ipv4(url: &reqwest::Url) -> Option<Ipv4Addr> {
    url.host_str()?.parse().ok()
}

/// description URL 的 host（必须是 IPv4 字面量）。
fn description_host(location: &str) -> io::Result<Ipv4Addr> {
    let url = reqwest::Url::parse(location).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("UPnP: bad description url {location:?}: {e}"),
        )
    })?;
    url_host_ipv4(&url).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("UPnP: description url {location:?} must carry an IPv4 literal host"),
        )
    })
}

/// SSDP 搜索：并向各 search target，等首个「源可信且带 LOCATION」的 200。
///
/// 返回 `(description URL, 应答源 IPv4)`：应答源是后续抓取的唯一可信 host。
async fn ssdp_location(
    search_addr: SocketAddrV4,
    timeout: Duration,
) -> io::Result<(String, Ipv4Addr)> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    for target in SSDP_SEARCH_TARGETS {
        let message = build_msearch(target);
        sock.send_to(message.as_bytes(), SocketAddr::V4(search_addr)).await?;
    }
    let gateway = super::default_ipv4_gateway().ok();
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; SSDP_BUF_LEN];
    while Instant::now() < deadline {
        match timeout_at(deadline, sock.recv_from(&mut buf)).await {
            Err(_) => break,
            Ok(Err(e)) => {
                // ICMP 不可达（Windows 在无人应答时报 ECONNRESET）= 本轮没有可用响应；
                // 停 50ms 再收，避免持续性 socket 错误空转烧 CPU。
                crate::LOG.debug(format!("UPnP: SSDP recv error (ignored): {e}"));
                tokio::time::sleep(Duration::from_millis(50)).await;
            },
            Ok(Ok((n, addr))) => {
                let SocketAddr::V4(peer) = addr else {
                    continue; // IGD 面只走 IPv4
                };
                if !ssdp_peer_allowed(*peer.ip(), gateway) {
                    crate::LOG.debug(format!(
                        "UPnP: ignoring SSDP response from {} (not this host, the default gateway, \
                         nor on its /16)",
                        peer.ip()
                    ));
                    continue;
                }
                if let Some(location) = parse_ssdp_location(&String::from_utf8_lossy(&buf[..n])) {
                    return Ok((location, *peer.ip()));
                }
            },
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("UPnP: no SSDP response from {search_addr} within {timeout:?}"),
    ))
}

/// 抓 device description（体积上限走流式读，超限即中止解析）。
async fn fetch_description(http: &reqwest::Client, location: &str) -> io::Result<String> {
    let response = http.get(location).send().await.map_err(|e| {
        io::Error::other(format!("UPnP: fetch description {location:?} failed: {e}"))
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(io::Error::other(format!(
            "UPnP: fetch description {location:?} failed: HTTP {}",
            status.as_u16()
        )));
    }
    read_body_capped(response, MAX_DESCRIPTION_SIZE, &format!("description {location:?}")).await
}

/// 流式读响应体，超过 `cap` 立即中止（Content-Length 可被 chunked 或谎报绕过，
/// 先读完再校验 = 恶意响应直接 OOM）。
async fn read_body_capped(
    mut response: reqwest::Response,
    cap: usize,
    what: &str,
) -> io::Result<String> {
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| io::Error::other(format!("UPnP: read {what} failed: {e}")))?
    {
        if body.len() + chunk.len() > cap {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("UPnP: {what} exceeds the {cap} byte cap"),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// 本机通往控制端点的 IPv4（SOAP `NewInternalClient` 用）。
///
/// UDP `connect` 不发包，只让内核选源地址。
async fn local_ipv4_towards(control_url: &reqwest::Url) -> io::Result<Ipv4Addr> {
    let host = control_url.host_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "UPnP: control url has no host")
    })?;
    let port = control_url.port_or_known_default().unwrap_or(80);
    let target = tokio::net::lookup_host((host, port))
        .await?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("UPnP: control url host {host:?} resolved to no IPv4 address"),
            )
        })?;
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    sock.connect(target).await?;
    match sock.local_addr()?.ip() {
        std::net::IpAddr::V4(v4) => Ok(v4),
        std::net::IpAddr::V6(v6) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("UPnP: local address towards {target} is IPv6 ({v6}); IGD path is IPv4-only"),
        )),
    }
}

/// 取 `<tag>value</tag>` 的内文（去空白）；无此标签 → `None`。
fn extract_tag(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    let value = text[start..end].trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// 逐个取 `<open>…</close>` 块（含边界）。
fn blocks<'a>(text: &'a str, open: &str, close: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(close) else {
            break;
        };
        out.push(&rest[start..start + open.len() + end + close.len()]);
        rest = &after[end + close.len()..];
    }
    out
}

/// 相对 controlURL 按 base 解析为绝对 URL。
fn resolve_url(base: &str, reference: &str) -> Option<String> {
    reqwest::Url::parse(base).ok()?.join(reference).ok().map(|url| url.to_string())
}

/// XML 文本转义（映射描述/端口等都会进 XML）。
fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::finalmask::realm::portmap::test_support::{DESCRIPTION_XML, HttpStub, SsdpStub};

    const SERVICE: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";
    const PPP_SERVICE: &str = "urn:schemas-upnp-org:service:WANPPPConnection:1";

    /// 起一对 stub：SSDP 指向 HTTP description/SOAP 服务。
    async fn upnp_stubs() -> (SsdpStub, HttpStub) {
        let http = HttpStub::spawn(|req| match req.path.as_str() {
            "/rootDesc.xml" => (200, DESCRIPTION_XML.to_string()),
            "/ctl/IPConn" => {
                let action = req.header("SOAPAction").unwrap_or_default();
                if action.contains("GetExternalIPAddress") {
                    (
                        200,
                        "<s:Envelope><s:Body><u:GetExternalIPAddressResponse>\
                         <NewExternalIPAddress>203.0.113.9</NewExternalIPAddress>\
                         </u:GetExternalIPAddressResponse></s:Body></s:Envelope>"
                            .to_string(),
                    )
                } else if action.contains("AddPortMapping") {
                    (
                        200,
                        "<s:Envelope><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>"
                            .to_string(),
                    )
                } else if action.contains("DeletePortMapping") {
                    (
                        200,
                        "<s:Envelope><s:Body><u:DeletePortMappingResponse/></s:Body></s:Envelope>"
                            .to_string(),
                    )
                } else {
                    (500, "<error/>".to_string())
                }
            },
            _ => (404, "<nope/>".to_string()),
        })
        .await;
        let ssdp = SsdpStub::spawn(format!("http://{}/rootDesc.xml", http.addr)).await;
        (ssdp, http)
    }

    #[test]
    fn msearch_wire_fields() {
        let msg = build_msearch("urn:schemas-upnp-org:device:InternetGatewayDevice:1");
        let mut lines = msg.split("\r\n");
        assert_eq!(lines.next(), Some("M-SEARCH * HTTP/1.1"));
        assert_eq!(lines.next(), Some("HOST: 239.255.255.250:1900"));
        assert_eq!(lines.next(), Some("MAN: \"ssdp:discover\""));
        assert_eq!(lines.next(), Some("MX: 2"));
        assert_eq!(lines.next(), Some("ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1"));
        assert!(msg.ends_with("\r\n\r\n"));
    }

    #[test]
    fn ssdp_location_parse_case_insensitive_and_rejects_error() {
        let ok = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nlocation: http://10.0.0.1:5000/d.xml\r\n\r\n";
        assert_eq!(parse_ssdp_location(ok).as_deref(), Some("http://10.0.0.1:5000/d.xml"));
        let err = "HTTP/1.1 404 Not Found\r\nST: x\r\n\r\n";
        assert!(parse_ssdp_location(err).is_none());
        assert!(parse_ssdp_location("HTTP/1.1 200 OK\r\nST: x\r\n\r\n").is_none());
    }

    #[test]
    fn control_url_prefers_wanip_connection_and_resolves_relative() {
        let (service, url) =
            parse_control_url(DESCRIPTION_XML, "http://10.0.0.1:5000/rootDesc.xml")
                .expect("igd service");
        assert_eq!(service, SERVICE);
        assert_eq!(url, "http://10.0.0.1:5000/ctl/IPConn");
        // PPP 网关回退
        let ppp =
            DESCRIPTION_XML.replace("service:WANIPConnection:1", "service:WANPPPConnection:1");
        let (service, _) =
            parse_control_url(&ppp, "http://10.0.0.1:5000/rootDesc.xml").expect("ppp");
        assert_eq!(service, PPP_SERVICE);
        // 无 IGD 服务 → None（不猜）
        assert!(parse_control_url("<root><device/></root>", "http://x/").is_none());
    }

    #[test]
    fn soap_envelope_and_action_header_fields() {
        let envelope = build_soap_envelope(
            SERVICE,
            "AddPortMapping",
            &[
                ("NewProtocol", "UDP".to_string()),
                ("NewPortMappingDescription", "a&b<c".to_string()),
            ],
        );
        assert!(
            envelope.contains(
                "<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
            ),
            "{envelope}"
        );
        assert!(envelope.contains("<NewProtocol>UDP</NewProtocol>"), "{envelope}");
        assert!(
            envelope
                .contains("<NewPortMappingDescription>a&amp;b&lt;c</NewPortMappingDescription>"),
            "{envelope}"
        );
        assert_eq!(
            soap_action_header(SERVICE, "DeletePortMapping"),
            "\"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping\""
        );
    }

    #[test]
    fn soap_error_parse() {
        let body = "<s:Fault><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\
                    <errorCode>718</errorCode>\
                    <errorDescription>ConflictInMappingEntry</errorDescription>\
                    </UPnPError></detail></s:Fault>";
        let err = parse_soap_error(body).expect("fault");
        assert_eq!(err.code, "718");
        assert_eq!(err.description, "ConflictInMappingEntry");
        assert!(parse_soap_error("<ok/>").is_none());
    }

    #[test]
    fn ssdp_peer_allowlist_pins_gateway_subnet() {
        let gateway = Ipv4Addr::new(192, 168, 88, 1);
        assert!(ssdp_peer_allowed(Ipv4Addr::LOCALHOST, Some(gateway)), "本机 stub / 同机 IGD");
        assert!(ssdp_peer_allowed(gateway, Some(gateway)), "默认网关");
        assert!(ssdp_peer_allowed(Ipv4Addr::new(192, 168, 88, 77), Some(gateway)), "同 /24");
        // /23 拓扑（本机实测：网关 .88.1、IGD .89.249）必须放行
        assert!(ssdp_peer_allowed(Ipv4Addr::new(192, 168, 89, 249), Some(gateway)), "同 /16");
        assert!(!ssdp_peer_allowed(Ipv4Addr::new(10, 9, 9, 9), Some(gateway)), "异私有段");
        assert!(!ssdp_peer_allowed(Ipv4Addr::new(203, 0, 113, 7), Some(gateway)), "公网源");
        // 无网关锚点（macOS 面）：只收私有源，公网源仍拒
        assert!(ssdp_peer_allowed(Ipv4Addr::new(10, 9, 9, 9), None), "无锚点：私有源放行");
        assert!(!ssdp_peer_allowed(Ipv4Addr::new(203, 0, 113, 7), None), "无锚点：公网源拒绝");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ssdp_location_pointing_away_from_responder_is_rejected() {
        // 应答源 = 127.0.0.1，LOCATION 却指向别的主机 → 必须拒（盲 SSRF 入口），
        // 且根本不许发出那个 GET
        let ssdp = SsdpStub::spawn("http://10.9.9.9:5000/rootDesc.xml".to_string()).await;
        let err = Client::discover(ssdp.addr, Duration::from_secs(2))
            .await
            .err()
            .expect("foreign LOCATION host must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("not the SSDP responder 127.0.0.1"), "{msg}");
        assert!(msg.contains("10.9.9.9"), "{msg}");
        // 兜底入口（任意 URL）同样钉在白名单上
        let err = Client::from_description_url(
            "http://10.9.9.9:5000/rootDesc.xml",
            Duration::from_secs(2),
        )
        .await
        .err()
        .expect("off-allowlist description host must be rejected");
        assert!(err.to_string().contains("is neither this host, the default gateway"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn control_url_must_stay_on_description_host() {
        // `<URLBase>` 指到别的内网主机 → controlURL 被搬过去 → 必须拒
        let description = format!("<URLBase>http://10.9.9.9:5000/</URLBase>{DESCRIPTION_XML}");
        let http = HttpStub::spawn(move |req| match req.path.as_str() {
            "/rootDesc.xml" => (200, description.clone()),
            _ => (404, "<nope/>".to_string()),
        })
        .await;
        let ssdp = SsdpStub::spawn(format!("http://{}/rootDesc.xml", http.addr)).await;
        let err = Client::discover(ssdp.addr, Duration::from_secs(2))
            .await
            .err()
            .expect("control url off the description host must be rejected");
        assert!(err.to_string().contains("not the description host"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn redirects_are_not_followed() {
        // 302 指向自己另一条路径：一次跳转就能把抓取导去任意内网主机，必须不跟
        let http = HttpStub::spawn(|req| match req.path.as_str() {
            "/rootDesc.xml" => (302, String::new()),
            _ => (200, DESCRIPTION_XML.to_string()),
        })
        .await;
        let location = format!("http://{}/rootDesc.xml", http.addr);
        let err = Client::from_description_url(&location, Duration::from_secs(2))
            .await
            .err()
            .expect("302 must not be followed");
        assert!(err.to_string().contains("HTTP 302"), "{err}");
        let gets: Vec<_> = http.requests().into_iter().filter(|r| r.method == "GET").collect();
        assert_eq!(gets.len(), 1, "no follow-up request: {gets:?}");
    }

    /// 超上限即中止（流式）：stub 声明 10MB、只灌 300KB 后挂住不关。
    /// 「先读完再校验」在这种响应上只能干等 timeout，流式上限立刻报 cap。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversized_description_aborts_mid_stream() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind");
        let addr = listener.local_addr().expect("stub addr");
        tokio::spawn(async move {
            let Ok((mut sock, _peer)) = listener.accept().await else {
                return;
            };
            // 先读完请求头（真实服务端形态；不读就先写会让 Windows loopback 直接 RST）
            let mut req = Vec::new();
            let mut chunk = [0u8; 512];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match sock.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => req.extend_from_slice(&chunk[..n]),
                }
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n",
                10 * MAX_DESCRIPTION_SIZE
            );
            if sock.write_all(head.as_bytes()).await.is_err() {
                return;
            }
            // 灌过上限后就挂住：不关连接、不再发
            if sock.write_all(&vec![b'a'; 300 * 1024]).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let location = format!("http://{addr}/rootDesc.xml");
        let err = Client::from_description_url(&location, Duration::from_secs(5))
            .await
            .err()
            .expect("over-cap description must abort");
        assert!(err.to_string().contains("byte cap"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversized_soap_response_aborts() {
        let http = HttpStub::spawn(|req| match req.path.as_str() {
            "/rootDesc.xml" => (200, DESCRIPTION_XML.to_string()),
            _ => (200, "x".repeat(MAX_SOAP_RESPONSE_SIZE + 1)),
        })
        .await;
        let ssdp = SsdpStub::spawn(format!("http://{}/rootDesc.xml", http.addr)).await;
        let client = Client::discover(ssdp.addr, Duration::from_secs(2)).await.expect("discover");
        let err = client.add_udp_mapping(8080, 60).await.expect_err("over-cap soap must abort");
        assert!(err.to_string().contains("byte cap"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discover_then_map_and_delete_hits_expected_soap_fields() {
        let (ssdp, http) = upnp_stubs().await;
        let client = Client::discover(ssdp.addr, Duration::from_secs(2)).await.expect("discover");

        let external_port = client.add_udp_mapping(8080, 600).await.expect("add");
        assert_eq!(external_port, 8080, "IGD v1 external port == requested port");

        let ip = client.get_external_address().await.expect("external ip");
        assert_eq!(ip, Ipv4Addr::new(203, 0, 113, 9));

        client.delete_udp_mapping(8080).await.expect("delete");

        // SSDP 请求逐字段（三个 search target 各一包）
        let searches = ssdp.requests();
        assert_eq!(searches.len(), SSDP_SEARCH_TARGETS.len());
        for (msg, target) in searches.iter().zip(SSDP_SEARCH_TARGETS) {
            assert!(msg.starts_with("M-SEARCH * HTTP/1.1\r\n"), "{msg}");
            assert!(msg.contains("HOST: 239.255.255.250:1900\r\n"), "{msg}");
            assert!(msg.contains(&format!("ST: {target}\r\n")), "{msg}");
        }

        let requests = http.requests();
        assert_eq!(requests.len(), 4, "description + 3 SOAP actions");
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].path, "/rootDesc.xml");

        let add = &requests[1];
        assert_eq!(add.method, "POST");
        assert_eq!(add.path, "/ctl/IPConn");
        assert_eq!(
            add.header("SOAPAction"),
            Some("\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"")
        );
        assert!(add.header("Content-Type").unwrap_or_default().starts_with("text/xml"), "{add:?}");
        for needle in [
            "<NewRemoteHost></NewRemoteHost>",
            "<NewExternalPort>8080</NewExternalPort>",
            "<NewProtocol>UDP</NewProtocol>",
            "<NewInternalPort>8080</NewInternalPort>",
            "<NewEnabled>1</NewEnabled>",
            "<NewPortMappingDescription>hysteria-realm</NewPortMappingDescription>",
            "<NewLeaseDuration>600</NewLeaseDuration>",
        ] {
            assert!(add.body.contains(needle), "missing {needle} in {}", add.body);
        }
        // NewInternalClient = 本机通往控制端点的源地址（127.0.0.1 stub）
        assert!(
            add.body.contains("<NewInternalClient>127.0.0.1</NewInternalClient>"),
            "{}",
            add.body
        );

        let get_ip = &requests[2];
        assert!(
            get_ip.header("SOAPAction").unwrap_or_default().ends_with("#GetExternalIPAddress\"")
        );

        let del = &requests[3];
        assert!(del.header("SOAPAction").unwrap_or_default().ends_with("#DeletePortMapping\""));
        assert!(del.body.contains("<NewExternalPort>8080</NewExternalPort>"), "{}", del.body);
        assert!(del.body.contains("<NewProtocol>UDP</NewProtocol>"), "{}", del.body);
        assert!(!del.body.contains("NewLeaseDuration"), "{}", del.body);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn soap_fault_is_fail_visible() {
        let http = HttpStub::spawn(|req| match req.path.as_str() {
            "/rootDesc.xml" => (200, DESCRIPTION_XML.to_string()),
            _ => (
                500,
                "<s:Fault><detail><UPnPError><errorCode>718</errorCode>\
                 <errorDescription>ConflictInMappingEntry</errorDescription></UPnPError>\
                 </detail></s:Fault>"
                    .to_string(),
            ),
        })
        .await;
        let ssdp = SsdpStub::spawn(format!("http://{}/rootDesc.xml", http.addr)).await;
        let client = Client::discover(ssdp.addr, Duration::from_secs(2)).await.expect("discover");
        let err = client.add_udp_mapping(8080, 600).await.unwrap_err();
        assert!(err.to_string().contains("errorCode 718"), "{err}");
        assert!(err.to_string().contains("ConflictInMappingEntry"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discover_without_ssdp_response_is_fail_visible() {
        // 绑定后立刻丢弃：无人应答的 SSDP 端点
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind");
        let addr = match sock.local_addr().expect("addr") {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => unreachable!("v4 bind"),
        };
        drop(sock);
        let err = Client::discover(addr, Duration::from_millis(200))
            .await
            .err()
            .expect("no SSDP responder must fail");
        assert!(err.to_string().contains("no SSDP response"), "{err}");
    }

    /// 死 SSDP 端点（绑定后立刻释放：无任何应答）。
    async fn silent_ssdp_addr() -> SocketAddrV4 {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind");
        match sock.local_addr().expect("addr") {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => unreachable!("v4 bind"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discover_fallback_first_success_wins_and_client_works() {
        let http = HttpStub::spawn(|req| match req.path.as_str() {
            "/gw.xml" | "/gw2.xml" => (200, DESCRIPTION_XML.to_string()),
            "/ctl/IPConn" => (
                200,
                "<s:Envelope><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>".to_string(),
            ),
            _ => (404, "<nope/>".to_string()),
        })
        .await;
        let first = format!("http://{}/gw.xml", http.addr);
        let second = format!("http://{}/gw2.xml", http.addr);
        let client = Client::discover_with_fallbacks(
            silent_ssdp_addr().await,
            Duration::from_secs(2),
            &[first.clone(), second],
        )
        .await
        .expect("first fallback candidate must win");
        // 首个成功即用：第二个候选一个请求都不该发
        let gets: Vec<_> = http.requests().into_iter().filter(|r| r.method == "GET").collect();
        assert_eq!(gets.len(), 1, "{gets:?}");
        assert_eq!(gets[0].path, "/gw.xml");
        // 兜底得到的客户端 SOAP 照常可用
        client.add_udp_mapping(8080, 60).await.expect("add via fallback client");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discover_fallback_all_fail_reports_ssdp_and_each_candidate() {
        let http = HttpStub::spawn(|req| match req.path.as_str() {
            "/missing.xml" => (404, "<nope/>".to_string()),
            _ => (500, "<err/>".to_string()),
        })
        .await;
        let not_found = format!("http://{}/missing.xml", http.addr);
        // 已关闭的 TCP 端口（绑定后立刻释放）→ 连接拒绝
        let refused = {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
            let port = listener.local_addr().expect("addr").port();
            drop(listener);
            format!("http://127.0.0.1:{port}/rootDesc.xml")
        };
        let err = Client::discover_with_fallbacks(
            silent_ssdp_addr().await,
            Duration::from_secs(2),
            &[not_found.clone(), refused.clone()],
        )
        .await
        .err()
        .expect("all candidates dead must fail");
        let msg = err.to_string();
        assert!(msg.contains("no SSDP response from"), "SSDP original: {msg}");
        assert!(msg.contains(&not_found) && msg.contains("HTTP 404"), "{msg}");
        assert!(msg.contains(&refused), "{msg}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_udp_mapping_entry_then_714_after_delete() {
        // 删除后把查询切换为 714 fault（模拟 miniupnpd NoSuchEntry）
        let deleted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&deleted);
        let http = HttpStub::spawn(move |req| match req.path.as_str() {
            "/rootDesc.xml" => (200, DESCRIPTION_XML.to_string()),
            "/ctl/IPConn" => {
                let action = req.header("SOAPAction").unwrap_or_default();
                if action.contains("GetSpecificPortMappingEntry") {
                    if flag.load(std::sync::atomic::Ordering::Relaxed) {
                        (
                            200,
                            "<s:Envelope><s:Body><s:Fault><detail><UPnPError>\
                             <errorCode>714</errorCode>\
                             <errorDescription>NoSuchEntry</errorDescription>\
                             </UPnPError></detail></s:Fault></s:Body></s:Envelope>"
                                .to_string(),
                        )
                    } else {
                        (
                            200,
                            "<s:Envelope><s:Body><u:GetSpecificPortMappingEntryResponse>\
                             <NewInternalPort>8080</NewInternalPort>\
                             <NewInternalClient>127.0.0.1</NewInternalClient>\
                             <NewEnabled>1</NewEnabled>\
                             <NewPortMappingDescription>hysteria-realm</NewPortMappingDescription>\
                             <NewLeaseDuration>600</NewLeaseDuration>\
                             </u:GetSpecificPortMappingEntryResponse></s:Body></s:Envelope>"
                                .to_string(),
                        )
                    }
                } else if action.contains("DeletePortMapping") {
                    flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    (
                        200,
                        "<s:Envelope><s:Body><u:DeletePortMappingResponse/></s:Body></s:Envelope>"
                            .to_string(),
                    )
                } else {
                    (500, "<err/>".to_string())
                }
            },
            _ => (404, "<nope/>".to_string()),
        })
        .await;
        let ssdp = SsdpStub::spawn(format!("http://{}/rootDesc.xml", http.addr)).await;
        let client = Client::discover(ssdp.addr, Duration::from_secs(2)).await.expect("discover");

        let entry = client.get_udp_mapping(8080).await.expect("entry");
        assert_eq!(
            entry,
            MappingEntry {
                internal_port: 8080,
                internal_client: Ipv4Addr::LOCALHOST,
                enabled: true,
                description: "hysteria-realm".to_string(),
                lease_duration: 600,
            }
        );

        client.delete_udp_mapping(8080).await.expect("delete");
        let err = client.get_udp_mapping(8080).await.expect_err("gone after delete");
        assert!(err.to_string().contains("714"), "{err}");
        assert!(err.to_string().contains("NoSuchEntry"), "{err}");
    }

    /// 真机网关闭环（默认 `#[ignore]`）：SSDP 静默取证 → 直取 description URL →
    /// 生产兜底发现 → 建映射（可挂起供路由器侧核对）→ 删映射 → 复查 714=删净。
    /// 跑法：`XRAY_UPNP_REAL_GW=<网关 IPv4> cargo test -p xray-transport --lib \
    /// real_gateway_add_delete_roundtrip -- --ignored --nocapture`
    /// 可选 `XRAY_UPNP_REAL_GW_HOLD_SECS=<秒>`：add 后挂起，供 ssh 网关侧核对。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires a real IGD gateway; set XRAY_UPNP_REAL_GW=<ipv4>"]
    #[allow(clippy::print_stdout)] // 真机取证输出（--nocapture 人眼核对）
    async fn real_gateway_add_delete_roundtrip() {
        let gateway: Ipv4Addr =
            match std::env::var("XRAY_UPNP_REAL_GW").ok().and_then(|v| v.parse().ok()) {
                Some(gateway) => gateway,
                None => {
                    println!("set XRAY_UPNP_REAL_GW=<gateway IPv4> to run; skipping");
                    return;
                },
            };
        let timeout = Duration::from_secs(3);
        // 临时测试端口（34560-34599 段）；租期 120s：即使异常残留网关也自动过期
        const PORT: u16 = 34567;

        // 1) 前提：该网络 SSDP 静默（路由器 1900 端口被其他服务占用，实测 0 应答）
        match ssdp_location(SSDP_ADDR, timeout).await {
            Ok((location, peer)) => panic!(
                "SSDP unexpectedly answered from {peer} with {location}; the 'SSDP silent' premise \
                 no longer holds"
            ),
            Err(e) => println!("SSDP silent as expected: {e}"),
        }
        // 2) SSDP-only discover 必须失败（兜底前的现状缺口取证）
        let err = Client::discover(SSDP_ADDR, timeout)
            .await
            .err()
            .expect("SSDP-only discover must fail on this network");
        println!("SSDP-only discover failed as expected: {err}");
        // 3) 直取 description URL 构造（新兜底入口）
        let direct =
            Client::from_description_url(&format!("http://{gateway}:5000/rootDesc.xml"), timeout)
                .await
                .expect("direct description url");
        println!("direct client: service={}, control={}", direct.service_type, direct.control_url);
        println!("external address = {}", direct.get_external_address().await.expect("ext ip"));
        // 4) 生产兜底路径（PortMapper 生产用的同一入口）：以环境网关推候选， 端口序 =
        //    FALLBACK_PORTS（首个成功即用，:49152/49153 拒绝快速跳过）
        let candidates: Vec<String> = FALLBACK_PORTS
            .iter()
            .map(|port| format!("http://{gateway}:{port}/rootDesc.xml"))
            .collect();
        let client = Client::discover_with_fallbacks(SSDP_ADDR, timeout, &candidates)
            .await
            .expect("production fallback discovery via env gateway");
        println!(
            "fallback client: service={}, control={}",
            client.service_type, client.control_url
        );
        // 5) 建映射 + 带内 MATCH 确认（此后到删除之间只做查询/打印/挂起）
        let external = client.add_udp_mapping(PORT, 120).await.expect("add mapping");
        println!("added UDP mapping: internal {PORT} -> external {external}");
        let entry = client.get_udp_mapping(PORT).await.expect("query mapping");
        println!("router reports mapping: {entry:?}");
        assert_eq!(entry.internal_port, PORT);
        assert_eq!(entry.internal_client, client.local_ip);
        assert_eq!(entry.description, "hysteria-realm");
        if let Ok(secs) =
            std::env::var("XRAY_UPNP_REAL_GW_HOLD_SECS").map(|v| v.parse::<u64>().unwrap_or(0))
        {
            if secs > 0 {
                println!("holding mapping for {secs}s for router-side inspection...");
                tokio::time::sleep(Duration::from_secs(secs)).await;
            }
        }
        // 6) 删映射 + 复查 714：查询已删映射必须 NoSuchEntry（映射确实删净； 本机 miniupnpd 对
        //    delete-nonexistent 回 200，带内判据只能用查询）
        client.delete_udp_mapping(PORT).await.expect("delete mapping");
        println!("deleted mapping {PORT}");
        let err =
            client.get_udp_mapping(PORT).await.expect_err("deleted mapping must not be queryable");
        println!("re-query after removal: {err}");
        assert!(err.to_string().contains("714"), "expected 714 NoSuchEntry, got: {err}");
        // 7) 默认路由推导候选（fallback_description_urls 的生产形态）：非致命——
        //    本机默认路由是主网关（IGD 在 .249 非默认路由位），失败属拓扑事实
        match Client::discover_with_fallbacks(SSDP_ADDR, timeout, &fallback_description_urls())
            .await
        {
            Ok(_) => println!("default-route-derived fallback: ok"),
            Err(e) => println!(
                "default-route-derived fallback failed (IGD is not the default-route gateway on this host): {e}"
            ),
        }
    }
}
