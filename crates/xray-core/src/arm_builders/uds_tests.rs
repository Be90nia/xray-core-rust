//! UDS 形态契约测试（bd 7y07s，`#[cfg(unix)]`）。
//!
//! 表登记的每个 UDS 形态都必须**从配置构出并起监听**——`#[cfg(unix)]` 分支在
//! Windows 上编译不到，非 unix 的 32/32 覆盖不到它们，本文件是这道契约闸。
//!
//! 断言口径（逐变体）：
//! 1. `spawn_one_inbound` 返回 `Ok(Some(handle))`（协议解析 + bind 全成功）；
//! 2. UDS 路径可建连（listener 真实在听，不只是构造返回）；
//! 3. 拆除后 socket 文件清理（不跨用例污染）。
//!
//! 端口取 62xxx：UDS 不消费 port，给真端口只为证明 unix 分派先于 port 解析
//! （若误落 TCP 路径会 bind 到 62xxx 而与本用例的 listen 路径断言不符）。

use std::sync::Arc;

use serde_json::json;
use tokio_util::sync::CancellationToken;
use xray_app_dispatcher::default::SimpleOhm;
use xray_conf::{BuiltEntry, BuiltInbound};

use crate::inbound::spawn_one_inbound;

const UUID: &str = "d342d11e-d424-4583-b36e-524ab1f0afa4";

/// freedom 出站 SimpleOhm（UDS 裸流臂要求 default handler 在场）。
fn freedom_ohm() -> Arc<SimpleOhm> {
    let ohm = Arc::new(SimpleOhm::new());
    ohm.set_default(Arc::new(xray_app_dispatcher::default::DialBridge::new(
        "freedom",
        xray_proxy_freedom::make_freedom_dial_fn(),
    )) as Arc<dyn xray_app_dispatcher::DispatchHandler>);
    ohm
}

/// 各协议的最小可构造 settings（与 inbound.rs 的 unix e2e 用例同源形态）。
fn settings_for(kind: &str) -> serde_json::Value {
    match kind {
        "vless" => json!({"clients": [{"id": UUID}], "decryption": "none"}),
        "vmess" => json!({"clients": [{"id": UUID}]}),
        "trojan" => json!({"clients": [{"password": "udspw"}]}),
        "shadowsocks" => json!({"method": "aes-256-gcm", "password": "udspw"}),
        _ => json!({}),
    }
}

fn uds_path(case: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("xray-uds-arm-{case}-{}.sock", std::process::id()))
}

fn inbound_at(kind: &str, tag: &str, sock: &std::path::Path, port: u16) -> BuiltInbound {
    BuiltInbound {
        entry: BuiltEntry {
            kind: kind.to_string(),
            data: serde_json::to_vec(&settings_for(kind)).expect("settings serialize"),
        },
        tag: tag.to_string(),
        port: Some(port),
        listen: Some(sock.to_string_lossy().into_owned()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

#[tokio::test]
async fn uds_table_forms_spawn_and_listen() {
    let _ = xray_transport_websocket::register::register_unix_listener();
    let ohm = freedom_ohm();
    let ws = json!({"network": "ws", "security": "none", "wsSettings": {"path": "/ws"}});
    // 5 个裸流形态（uds_stream）+ 4 个 transport 形态（uds_transport，走 ws）。
    let cases: [(&str, &str, Option<serde_json::Value>); 9] = [
        ("socks", "stream", None),
        ("vless", "stream", None),
        ("vmess", "stream", None),
        ("trojan", "stream", None),
        ("shadowsocks", "stream", None),
        ("vless", "transport", Some(ws.clone())),
        ("vmess", "transport", Some(ws.clone())),
        ("trojan", "transport", Some(ws.clone())),
        ("shadowsocks", "transport", Some(ws)),
    ];
    for (i, (kind, form, stream)) in cases.into_iter().enumerate() {
        let case = format!("{form}-{kind}");
        let sock = uds_path(&case);
        let _ = std::fs::remove_file(&sock);
        let mut ib = inbound_at(kind, &format!("uds-{case}"), &sock, 62_001 + i as u16);
        ib.stream_settings_json = stream;
        let handle = spawn_one_inbound(&ib, Arc::clone(&ohm), None, CancellationToken::new(), None)
            .await
            .unwrap_or_else(|e| panic!("{case}: uds spawn failed: {e}"))
            .unwrap_or_else(|| panic!("{case}: uds form must spawn a serve task"));
        // listener 真实在听：UDS 建连成功 = bind + accept 路径已就位。
        tokio::net::UnixStream::connect(&sock)
            .await
            .unwrap_or_else(|e| panic!("{case}: uds listener not accepting: {e}"));
        handle.abort();
        let _ = std::fs::remove_file(&sock);
    }
}

/// 表里无 UDS 槽的协议：unix 路径在 bind 前显式失败（原手写白名单的语义现由表
/// 的 `uds_stream: None` 表达，禁静默回落 TCP）。
#[tokio::test]
async fn uds_form_absent_fails_visible() {
    let sock = uds_path("absent-http");
    let _ = std::fs::remove_file(&sock);
    let ib = inbound_at("http", "uds-absent-http", &sock, 62_010);
    let err = spawn_one_inbound(&ib, freedom_ohm(), None, CancellationToken::new(), None)
        .await
        .expect_err("http over uds must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported, "got: {err}");
    assert!(
        err.to_string().contains("not supported over unix socket"),
        "错误文案须可见协议支持面，got: {err}"
    );
    assert!(!sock.exists(), "fail-fast 不得留下 socket 文件");
}
