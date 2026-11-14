//! bd hsrtv：vmess **出站** `alterId≠0` 的兼容口径（与入站/框架路同源同语义）。
//!
//! Go 基准（`D:/Project/Xray-core` @ v26.11.9 `infra/conf/vmess.go:20-24`）：
//! `VMessAccount` 只有 `id` / `security` / `experiments` 三个字段，**无 alterId**
//! ⇒ `encoding/json` 把 `users[].alterId` 当未知键忽略，出站照常装配、照常连通。
//!
//! 本文件钉两件事：
//! 1. **装配**：`parse_vmess_config`（生产出站唯一解析点，`arm_builders/outbound.rs` 同源调用）对
//!    `alterId=64` 不拒启；
//! 2. **连通**：该配置产出的 outbound 真连一台 vmess 服务端并完成数据回环
//!    （证明「配了不生效」的旧缺口不存在，且不是「装配通过但握手失败」）。
//!
//! 旧行为（硬错拒启）的断言已被 `dispatcher.rs` 的
//! `parse_vmess_config_alter_id_nonzero_ignored` 取代。

#![cfg_attr(test, allow(clippy::disallowed_macros))] // 测试脚手架：直印进度；spawn 走 xray_common::testing（L3 闸不豁免）

use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use xray_app_dispatcher::default::{DialBridge, SimpleOhm};
use xray_common::{
    net::{address::Address, destination::Destination, network::Network, port::Port},
    uuid::UUID,
};
use xray_proxy_vmess::{
    MemoryUser,
    account::MemoryAccount,
    dispatcher::{make_vmess_dial_fn, parse_vmess_config},
    inbound::server::serve_vmess,
    validator::{TimedUserValidator, Validator},
};
use xray_transport::sockopt::SocketOptions;

/// 固定 UUID：与 `vmess_proxy_e2e.rs` 一致，避免每次运行随机化导致反重放状态污染。
fn sample_uuid() -> UUID {
    UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("uuid")
}

/// bd hsrtv：`alterId=64` 的**出站**配置不得拒启（Go 忽略未知键）。
///
/// 数字形态（旧 v2rayN 配置的常态）。
#[test]
fn outbound_alter_id_nonzero_is_accepted() {
    let data = br#"{
        "vnext": [{
            "address": "127.0.0.1",
            "port": 8443,
            "users": [{ "id": "66ad4540-b58c-4ad2-9926-ea63445a9b57", "alterId": 64 }]
        }]
    }"#;
    let cfg = parse_vmess_config(data).expect("alterId=64 不得拒启（Go 忽略未知键）");
    assert_eq!(cfg.user_uuid.to_string(), "66ad4540-b58c-4ad2-9926-ea63445a9b57");
}

/// 字符串形态 alterId（老配置生成器输出）同等只忽略、不拒启。
#[test]
fn outbound_alter_id_string_is_accepted() {
    let data = br#"{
        "vnext": [{
            "address": "127.0.0.1",
            "port": 8443,
            "users": [{ "id": "66ad4540-b58c-4ad2-9926-ea63445a9b57", "alterId": "64" }]
        }]
    }"#;
    assert!(parse_vmess_config(data).is_ok(), "字符串 alterId 不得拒启");
}

/// bd hsrtv 端到端：`alterId=64` 的出站配置**真连通**（装配 + 握手 + 数据回环）。
///
/// 拓扑：vmess 服务端（`serve_vmess` → freedom → echo）← 出站（`parse_vmess_config`
/// 产出的配置 → `make_vmess_dial_fn`）。证「只装配通过但握手失败」不成立。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbound_with_alter_id_64_connects_end_to_end() {
    // echo 目标
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let echo_port = echo_listener.local_addr().unwrap().port();
    xray_common::testing::spawn("alterid-echo-accept-loop", async move {
        loop {
            let Ok((sock, _)) = echo_listener.accept().await else { break };
            xray_common::testing::spawn("alterid-echo-conn", async move {
                let (mut rd, mut wr) = tokio::io::split(sock);
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });

    // vmess 服务端（用户表无 alterId —— Go 侧该键本就不存在）
    let ohm = Arc::new(SimpleOhm::new());
    let bridge = Arc::new(DialBridge::new("freedom", xray_proxy_freedom::make_freedom_dial_fn()))
        as Arc<dyn xray_app_dispatcher::DispatchHandler>;
    ohm.set_default(bridge);

    let uuid = sample_uuid();
    let validator = Arc::new(TimedUserValidator::new());
    validator
        .add(MemoryUser::new("alice@example.com", MemoryAccount::new(uuid)))
        .expect("add user");
    assert_eq!(Validator::count(&*validator), 1);

    let vmess_listener = xray_transport::system_listener::InboundTcpListener::bind(
        "127.0.0.1:0",
        SocketOptions::default(),
    )
    .await
    .expect("bind vmess");
    let vmess_port = vmess_listener.local_addr().unwrap().port();
    let ohm2 = Arc::clone(&ohm);
    let validator2 = Arc::clone(&validator);
    xray_common::testing::spawn("alterid-vmess-server", async move {
        let _ = serve_vmess(
            Arc::new(xray_frame::PluginContext::for_plugin("vmess")),
            vmess_listener,
            ohm2,
            validator2,
            None,
            std::time::Duration::from_secs(10),
        )
        .await;
    });

    // 出站：配置里带 alterId=64（生产同源的解析点）
    let settings = format!(
        r#"{{"vnext":[{{"address":"127.0.0.1","port":{vmess_port},"users":[{{"id":"66ad4540-b58c-4ad2-9926-ea63445a9b57","security":"auto","alterId":64}}]}}]}}"#
    );
    let cfg =
        Arc::new(parse_vmess_config(settings.as_bytes()).expect("alterId=64 出站配置必须装配成功"));
    let dial = make_vmess_dial_fn(cfg, Arc::new(xray_frame::PluginContext::for_plugin("vmess")));
    let dest = Destination::new(
        Address::from_ipv4_bytes([127, 0, 0, 1]),
        Port::new(echo_port),
        Network::TCP,
    );
    let mut conn = dial(&dest).await.expect("vmess dial（alterId=64 必须能连）");

    let payload = b"hello vmess outbound with alterId=64";
    conn.write_all(payload).await.expect("write");
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(std::time::Duration::from_secs(5), conn.read_exact(&mut got))
        .await
        .expect("read timeout")
        .expect("read");
    assert_eq!(&got, payload, "alterId=64 出站链路必须原样回环");
}
