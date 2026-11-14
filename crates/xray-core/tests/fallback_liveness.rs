//! **Fallback 功能存活证伪测试**（bd Xray-core-rust-rql9w 验收项 2）。
//!
//! 本仓有**两份** VLESS/Trojan `fallbacks` 解析实现（审计报告 B-2 陷阱）：
//!
//! - **死的那份**（已删）：`xray-conf/src/protocols.rs` 的 `VLessInboundFallbackConfig` /
//!   `TrojanInboundFallbackConfig` —— 宽松 `Option<Value>` 解析，生产零消费。
//! - **活的那份**（保留）：`xray-core/src/inbound.rs` 的 `build_vless_fallbacks` /
//!   `build_trojan_fallbacks` —— Go 对齐的**硬错**语义。
//!
//! 批量清死代码时若误删「活的那份」，VLESS/Trojan 的 fallback 功能即报废。本测试
//! **独立于**任何被审计的代码路径，从**用户配置 JSON** 出发走完整条生产链：
//!
//! ```text
//! 配置 fallbacks
//!   → xray-conf::Config::from_json_str（配置解析）
//!   → Config::build()（装配成 BuiltConfig）
//!   → xray_core::start_full（生产装配：arm_builders → build_vless_fallbacks）
//!   → VLESS/Trojan inbound 非协议流量 → 触发回落
//!   → fallback dest 收到**原始字节**（断言走了 fallback 目标）
//! ```
//!
//! 断言口径：fallback dest **确实收到**了客户端发来的原始 HTTP 字节（而非协议
//! 字节、而非连接被直接关断）——即回落链路端到端通。
//!
//! 覆盖面：VLESS（`xray-core/src/inbound.rs:build_vless_fallbacks`）与 Trojan
//! （`build_trojan_fallbacks`）两条独立解析路径，各自一个用例。

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// 串行化「探测空闲端口 → 释放 → 再绑定」窗口。
///
/// 同二进制内两个用例并行跑时会互相抢同一个探测端口 ⇒ CI 上偶发
/// `Address already in use (os error 98)`（os error 98），属测试自身竞态而非产品缺陷。
/// 用 tokio 互斥（跨 await 安全，不触发 clippy::await_holding_lock）串行化整段装配。
static PORT_WINDOW: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// 回落探针的观测结果。
struct FallbackProbe {
    /// fallback dest 实收字节（应 = 客户端发去的原始字节）。
    fb_bytes: Vec<u8>,
    /// 客户端从 fallback dest 回读到的字节（证明链路通，非关断）。
    echoed: Vec<u8>,
}

/// 起一个 VLESS/Trojan inbound（配置走**真实 JSON**）+ 打一次回落探针。
///
/// `protocol` = `"vless"` | `"trojan"`；`settings_extra` = 各协议自己的 clients 段。
/// 回落探针 = 「非协议流量（裸 HTTP）→ fallback dest」。
async fn probe_fallback(protocol: &str, settings_extra: serde_json::Value) -> FallbackProbe {
    // 端口窗口串行化：见 PORT_WINDOW 注释（守住整个探测→装配→起监听过程）。
    let _port_window = PORT_WINDOW.lock().await;
    // fallback dest：先 bind 拿到地址（避免 join! 里 bind 与 connect 竞态）。
    let fb_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fallback listener");
    let fb_addr = fb_listener.local_addr().expect("fallback local_addr");

    // 申请一个空闲 inbound 端口。
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind port probe");
    let in_port = probe.local_addr().expect("probe addr").port();
    drop(probe);

    let mut settings = serde_json::Map::new();
    for (k, v) in settings_extra.as_object().expect("settings object") {
        settings.insert(k.clone(), v.clone());
    }
    settings
        .insert("fallbacks".into(), serde_json::json!([{"dest": fb_addr.to_string(), "xver": 0}]));

    let cfg = xray_conf::Config::from_json_str(
        &serde_json::json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "tag": format!("{protocol}-fb-in"),
                "listen": "127.0.0.1",
                "port": in_port,
                "protocol": protocol,
                "settings": settings
            }],
            "outbounds": [{"protocol": "freedom", "tag": "direct"}]
        })
        .to_string(),
    )
    .expect("fallback config parses");
    let built = cfg.build().expect("fallback config builds");

    let (instance, _ohm, handles) =
        xray_core::start_full(&built).await.expect("instance starts with fallbacks");
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 回落探针：server 侧（fallback dest 收字节并回写）与 client 侧并发跑，
    // 不 spawn 子任务（避坑约束 5 的裸 spawn 红线）。
    // 回落**分两段**送到 fallback dest（Go 同款）：① 协议层已录制的首字节
    // （trojan 只录到 1 字节版本判定位就判非法；vless 录满首包）② 剩余流经
    // 管道转发。故两侧都**循环读满预期长度**，不能只读一次。
    let payload = b"GET /fallback-probe HTTP/1.1\r\nHost: example.invalid\r\n\r\n";
    let expected_len = payload.len();
    let (fb_bytes, echoed) = tokio::join!(
        async move {
            let (mut sock, _) = fb_listener.accept().await.expect("fallback accept");
            let mut buf: Vec<u8> = Vec::with_capacity(expected_len);
            let mut chunk = [0u8; 512];
            while buf.len() < expected_len {
                let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut chunk))
                    .await
                    .expect("fallback read timeout")
                    .expect("fallback read");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            sock.write_all(&buf).await.expect("fallback echo write");
            buf
        },
        async move {
            let mut client =
                TcpStream::connect(("127.0.0.1", in_port)).await.expect("connect inbound");
            client.write_all(payload).await.expect("write probe");
            let mut got: Vec<u8> = Vec::with_capacity(expected_len);
            let mut chunk = [0u8; 512];
            while got.len() < expected_len {
                let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut chunk))
                    .await
                    .expect("fallback echo timeout")
                    .expect("read fallback echo");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&chunk[..n]);
            }
            got
        }
    );

    // Instance 句柄是 Arc（close 需 &mut Instance），此处靠 abort 停机即可——
    // 端口由进程退出回收。
    drop(instance);
    for h in handles {
        h.abort();
    }
    FallbackProbe { fb_bytes, echoed }
}

/// VLESS：非 VLESS 流量 → fallback dest 收到原始字节。
///
/// 走**真实配置 JSON**（`xray-conf` 解析 → build → `start_full` 生产装配），
/// 不经任何测试专用捷径——被审计删掉的正是配置层那条路径。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vless_fallback_reaches_fallback_dest_from_real_config() {
    let probe = probe_fallback(
        "vless",
        serde_json::json!({
            "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
            "decryption": "none"
        }),
    )
    .await;

    assert!(
        probe.fb_bytes.starts_with(b"GET /fallback-probe"),
        "fallback dest must receive the original bytes, got {:?}",
        probe.fb_bytes
    );
    assert!(
        probe.echoed.starts_with(b"GET /fallback-probe"),
        "fallback dest must echo the original bytes back, got {:?}",
        probe.echoed
    );
}

/// Trojan：非 Trojan 流量（握手失败）→ fallback dest 收到原始字节。
///
/// 与 VLESS 用例**分开**——两者的 fallback 解析是两份独立实现
/// （`build_trojan_fallbacks` vs `build_vless_fallbacks`），删错任一份都只被
/// 对应用例逮住。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_fallback_reaches_fallback_dest_from_real_config() {
    let probe = probe_fallback(
        "trojan",
        serde_json::json!({"clients": [{"password": "fallback-probe-pass"}]}),
    )
    .await;

    assert!(
        probe.fb_bytes.starts_with(b"GET /fallback-probe"),
        "fallback dest must receive the original bytes, got {:?}",
        probe.fb_bytes
    );
    assert!(
        probe.echoed.starts_with(b"GET /fallback-probe"),
        "fallback dest must echo the original bytes back, got {:?}",
        probe.echoed
    );
}
