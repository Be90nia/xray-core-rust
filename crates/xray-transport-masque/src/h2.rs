//! CONNECT-IP over HTTP/2（extended CONNECT，RFC 8441/9484）。
//!
//! 语义唯一源：Go `transport/internet/masque/dialer.go dialHTTP2` + `connectip/http2.go`
//! + `connectip/request.go`（v26.11.9 @ 676eaf66）。h2 帧层复用 hyper（规划 §3 第 1 行， **不移植**
//!   Go 手写 `http2.go`/`http2_server.go` 1294 行）；extended CONNECT 形态由 B0 spike
//!   验证（`tests/h2_extended_connect_spike.rs`，R1 已关闭）。
//!
//! 流程（[`connect_h2`]）：TLS 层之上发起 `:method=CONNECT + :protocol=connect-ip +
//! Capsule-Protocol: ?1` 空 body 请求 → 2xx 校验 → `Upgraded`（hyper 1.x 只实现
//! `hyper::rt::{Read,Write}`，经 `TokioIo` 适配）→ [`ConnectIpSession`]。

use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request};
use http_body_util::Full;
use hyper::ext::Protocol;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use xray_transport::h2_window::{
    H2_INITIAL_CONNECTION_WINDOW, H2_INITIAL_STREAM_WINDOW, H2_MAX_SEND_BUF_SIZE,
};

use crate::{
    config::Config,
    connect::{ConnectIpSession, Framing},
    error::{MasqueError, Result},
};

/// CONNECT-IP 请求协议名（Go `connectip/request.go:20 requestProtocol`）。
pub const CONNECT_IP_PROTOCOL: &str = "connect-ip";

/// h2 连接级 keep-alive PING 间隔：对齐 Go `common/net/net.go:20
/// ChromeH2KeepAlivePeriod = 45s`（`dialHTTP2` keepAlivePeriod 缺省）。
/// PING 超时用 hyper 缺省（20s，不另立数值）。
const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(45);

/// 在一条已建立的 IO（TLS 层之上）上发起 CONNECT-IP extended CONNECT，返回胶囊会话。
///
/// `authority` 为请求 `:authority`（Go `authority(config, serverName, port)` 产物，
/// config.host 优先的解析由调用方完成）。
pub async fn connect_h2(
    io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    config: &Config,
    authority: &str,
) -> Result<ConnectIpSession> {
    // 窗组 = 上浮常量（规划 §5 B2.4：splithttp 同款，值不变）；masque 单流隧道，
    // 连接窗即隧道吞吐钉（规划 §7 R2：16MiB send_buf / 32MiB 流窗起步，M2 加观测）。
    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    builder
        // keep-alive PING 依赖 timer（hyper 1.10 无 timer 时 Time::new() panic
        // —— spike 未开 keep-alive 故未暴露）；tokio 实现取 hyper_util TokioTimer。
        .timer(TokioTimer::new())
        .initial_stream_window_size(H2_INITIAL_STREAM_WINDOW)
        .initial_connection_window_size(H2_INITIAL_CONNECTION_WINDOW)
        .max_send_buf_size(H2_MAX_SEND_BUF_SIZE)
        .keep_alive_interval(H2_KEEP_ALIVE_INTERVAL)
        .keep_alive_while_idle(true);
    let (mut send_request, connection) = builder
        .handshake::<_, Full<Bytes>>(TokioIo::new(io))
        .await
        .map_err(|e| hyper_err("h2 handshake", e))?;
    // ②豁免（§3.5.6 ②-数据面逐包泵）：hyper h2 连接驱动（GOAWAY/EOF 侦听 + 帧泵），
    // 随 h2 连接 EOF 自终；寿命不越 ConnectIpSession（同形态登记见
    // xray-transport-naive/src/dial.rs）。
    #[allow(
        clippy::disallowed_methods,
        reason = "②豁免（§3.5.6 ②-数据面逐包泵）：hyper h2 连接驱动任务，随 h2 连接结束自终；寿命 = ConnectIpSession，close()/Drop 逐任务 abort"
    )]
    let driver = tokio::spawn(async move {
        if let Err(e) = connection.await {
            crate::LOG.debug(format!("masque: h2 connection ended: {e}"));
        }
    });

    // CONNECT-IP 请求（Go connectip/request.go NewRequest + establish 头合并）：
    // :method=CONNECT + 绝对 https URI + 空 body（hyper 对非空 CONNECT body 直接拒绝，
    // client.rs:716-733）。标准形态补 `:protocol=connect-ip` + `Capsule-Protocol: ?1`；
    // WARP（Cloudflare）形态**不带** `:protocol`（Go `http2.go:48-52` 改走
    // `Cf-Connect-Proto` 头），即普通 CONNECT。
    let uri = format!("https://{authority}{}", config.path);
    let mut req = Request::builder()
        .method(Method::CONNECT)
        .uri(&uri)
        .body(Full::new(Bytes::new()))
        .map_err(|e| MasqueError::Protocol(format!("masque: invalid request URI {uri:?}: {e}")))?;
    *req.headers_mut() = build_request_headers(config)?;
    if config.warp.is_none() {
        req.extensions_mut().insert(Protocol::from_static(CONNECT_IP_PROTOCOL));
    }

    let response =
        send_request.send_request(req).await.map_err(|e| hyper_err("CONNECT-IP request", e))?;
    // Go connectip client.go：2xx 之外一律拒绝（Rejected 带状态码）。
    if !response.status().is_success() {
        return Err(MasqueError::Rejected(response.status()));
    }
    let upgraded =
        hyper::upgrade::on(response).await.map_err(|e| hyper_err("stream upgrade", e))?;
    let framing = if config.warp.is_some() { Framing::Bare } else { Framing::Capsule };
    Ok(ConnectIpSession::new(TokioIo::new(upgraded), driver, framing))
}

/// 请求头装配（Go `establish`：config.Headers 合并 + `setUserAgent`）。
///
/// WARP（Cloudflare）变体按 `connectip/http2.go:48-52` 改写：删 `Capsule-Protocol`，
/// 加 `Cf-Connect-Proto: cf-connect-ip` + `Pq-Enabled: false`。
fn build_request_headers(config: &Config) -> Result<HeaderMap> {
    let mut map = HeaderMap::new();
    if config.warp.is_some() {
        map.insert(
            HeaderName::from_static("cf-connect-proto"),
            HeaderValue::from_static(crate::warp::CLOUDFLARE_PROTOCOL),
        );
        map.insert(
            HeaderName::from_static("pq-enabled"),
            HeaderValue::from_static(crate::warp::PQ_ENABLED),
        );
    } else {
        map.insert(HeaderName::from_static("capsule-protocol"), HeaderValue::from_static("?1"));
    }

    // User-Agent 别名解析（Go dialer.go setUserAgent）：缺省 chrome；""/"golang"
    // 删除 UA；chrome/firefox/safari/edge/curl → 动态版本 UA；其余原样透传。
    let ua_raw = config
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .map(|(_, v)| v.clone());
    let ua = match ua_raw.as_deref() {
        Some("") | Some("golang") => None,
        None | Some("chrome") | Some("firefox") | Some("safari") | Some("edge") | Some("curl") => {
            let alias = ua_raw.as_deref().unwrap_or("chrome");
            Some(xray_common::browser::build_user_agent(alias))
        },
        Some(other) => Some(other.to_string()),
    };
    if let Some(ua) = ua {
        let value = HeaderValue::from_str(&ua).map_err(|e| {
            MasqueError::Protocol(format!("masque: invalid User-Agent {ua:?}: {e}"))
        })?;
        map.insert(HeaderName::from_static("user-agent"), value);
    }

    for (k, v) in &config.headers {
        if k.eq_ignore_ascii_case("user-agent") {
            continue; // 已并入 UA 解析
        }
        let name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| {
            MasqueError::Protocol(format!("masque: invalid header name {k:?}: {e}"))
        })?;
        let value = HeaderValue::from_str(v)
            .map_err(|e| MasqueError::Protocol(format!("masque: invalid header {k:?}: {e}")))?;
        map.insert(name, value);
    }
    Ok(map)
}

fn hyper_err(stage: &str, e: hyper::Error) -> MasqueError {
    MasqueError::Io(std::io::Error::other(format!("masque: {stage}: {e}")))
}
