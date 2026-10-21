//! G-12 policy 端到端（dofk 缺口；Go 对照 testing/scenarios/policy_test.go
//! `TestZeroBuffer`（:150）+ `TestVMessClosing`（:46））。
//!
//! 拓扑 = Go 原版双实例：
//!
//! ```text
//! test client ──raw TCP──▶ client instance（dokodemo in → vmess out，aes-128-gcm）
//!   ──vmess──▶ server instance（vmess in → freedom out）──▶ 目标 TCP server
//! ```
//!
//! dokodemo rewrite 目标 = 业务终点（Go `RewriteAddress/RewritePort` 语义：
//! 该 dest 由 vmess 请求头携带、由 server 侧 freedom 拨出）。
//!
//! ① `TestZeroBuffer`：server 侧 policy level 0 `bufferSize:0`（Go
//!    `Buffer{Connection:0}`）下 ≥1MB 流量仍完整往返。
//! ② `TestVMessClosing`：双侧 `uplinkOnly:0, downlinkOnly:0`（Go
//!    `Timeout{UplinkOnly:0, DownlinkOnly:0}`），目标 server 读一次即关（Go
//!    `startQuickClosingTCPServer`），客户端须在超时窗内读到 EOF（优雅关闭传播）。

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound};
use xray_core::functions::start_full;

/// VMess 测试 UUID（与 e2e_test.rs 惯例一致）。
const VMESS_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

/// bind :0 取空闲端口再释放。
async fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// freedom outbound（default 兜底；显式放行回环，同 e2e_test.rs 逃逸门先例）。
fn freedom_default() -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry {
            kind: "freedom".into(),
            data: br#"{"finalRules":[{"action":"allow","network":"tcp,udp","ip":["127.0.0.0/8","::1/128"]}]}"#
                .to_vec(),
        },
        tag: "direct".into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

/// server instance：policy app + vmess inbound + freedom outbound。
fn server_cfg(vmess_port: u16, policy_json: &[u8]) -> BuiltConfig {
    let mut cfg = BuiltConfig::default();
    cfg.apps.push(BuiltEntry { kind: "policy".into(), data: policy_json.to_vec() });
    cfg.inbounds.push(BuiltInbound {
        entry: BuiltEntry {
            kind: "vmess".into(),
            data: format!(r#"{{"clients":[{{"id":"{VMESS_UUID}","email":"policy@t","level":0}}]}}"#)
                .into_bytes(),
        },
        tag: "vmess-in".into(),
        port: Some(vmess_port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    });
    cfg.outbounds.push(freedom_default());
    cfg
}

/// client instance：（可选）policy app + dokodemo inbound（rewrite → 业务终点）
/// + vmess outbound（aes-128-gcm，对应 Go SecurityType_AES128_GCM）。
fn client_cfg(dok_port: u16, vmess_port: u16, dest_port: u16, policy_json: Option<&[u8]>) -> BuiltConfig {
    let mut cfg = BuiltConfig::default();
    if let Some(p) = policy_json {
        cfg.apps.push(BuiltEntry { kind: "policy".into(), data: p.to_vec() });
    }
    cfg.inbounds.push(BuiltInbound {
        entry: BuiltEntry {
            kind: "dokodemo".into(),
            // rewrite 目标 = 业务终点（vmess 头携带的真实目标，Go RewriteAddress 语义）
            data: format!(r#"{{"address":"127.0.0.1","port":{dest_port}}}"#).into_bytes(),
        },
        tag: "dok-in".into(),
        port: Some(dok_port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    });
    cfg.outbounds.push(BuiltOutbound {
        entry: BuiltEntry {
            kind: "vmess".into(),
            data: format!(
                r#"{{"vnext":[{{"address":"127.0.0.1","port":{vmess_port},"users":[{{"id":"{VMESS_UUID}","security":"aes-128-gcm"}}]}}]}}"#
            )
            .into_bytes(),
        },
        tag: "proxy".into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    });
    cfg
}

/// 起双实例拓扑，返回 (dokodemo 入口端口, 全部 inbound handles)。
async fn start_pair(
    server_policy: &[u8],
    client_policy: Option<&[u8]>,
    dest_port: u16,
) -> (u16, Vec<tokio::task::JoinHandle<()>>) {
    let vmess_port = pick_free_port().await;
    let dok_port = pick_free_port().await;
    let (_si, _soh, mut s_handles) =
        start_full(&server_cfg(vmess_port, server_policy)).await.unwrap();
    let (_ci, _coh, mut c_handles) =
        start_full(&client_cfg(dok_port, vmess_port, dest_port, client_policy))
            .await
            .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    s_handles.append(&mut c_handles);
    (dok_port, s_handles)
}

/// 无限回显 echo server（多连接；供 1MB 往返）。
async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        },
                    }
                }
            });
        }
    });
    port
}

/// 读一次即关的目标 server（Go startQuickClosingTCPServer 同语义）。
async fn spawn_quick_closing() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut b = [0u8; 1024];
                let _ = sock.read(&mut b).await;
                // drop → 立即关闭
            });
        }
    });
    port
}

/// Buffer{Connection:0} 零缓冲下 ≥1MB 流量仍完整往返（对应 Go TestZeroBuffer
/// 主断言；xor 判别等价替换为逐字节 pattern 比对）。
#[tokio::test]
async fn zero_buffer_still_carries_one_mb() {
    let echo_port = spawn_echo().await;
    let (dok_port, handles) =
        start_pair(br#"{"levels":{"0":{"bufferSize":0}}}"#, None, echo_port).await;

    // 1 MiB 确定性 pattern（素数步进避免对称游程）。
    let size = 1024 * 1024;
    let payload: Vec<u8> = (0..size).map(|i| ((i * 7 + 13) % 256) as u8).collect();

    let stream = TcpStream::connect(("127.0.0.1", dok_port)).await.unwrap();
    // 写读并发（避免双端写缓冲互塞的回环死锁）；into_split 供写半部进独立 task。
    let (mut rh, mut wh) = stream.into_split();
    let to_send = payload.clone();
    let writer = tokio::spawn(async move { wh.write_all(&to_send).await });
    let mut got = vec![0u8; size];
    tokio::time::timeout(Duration::from_secs(30), rh.read_exact(&mut got))
        .await
        .expect("1MB 往返超时")
        .unwrap();
    writer.await.unwrap().unwrap();
    assert_eq!(got, payload, "零缓冲（bufferSize:0）下 1MB 流量必须完整往返");
    for h in handles {
        h.abort();
    }
}

/// 服务端优雅关闭 → 客户端 EOF（对应 Go TestVMessClosing；双侧
/// uplinkOnly/downlinkOnly=0，目标 server 读一次即关，客户端须在超时窗内读到 EOF）。
#[tokio::test]
async fn vmess_graceful_close_propagates_eof() {
    let quick_port = spawn_quick_closing().await;
    let zero_win = br#"{"levels":{"0":{"uplinkOnly":0,"downlinkOnly":0}}}"#;
    let (dok_port, handles) = start_pair(zero_win, Some(zero_win), quick_port).await;

    let mut stream = TcpStream::connect(("127.0.0.1", dok_port)).await.unwrap();
    stream.write_all(&[0xABu8; 1024]).await.unwrap();
    let mut byte = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut byte))
        .await
        .expect("未在超时窗内收到关闭（EOF 传播失败）")
        .expect("读 EOF 时 IO 错误（期望优雅关闭而非 reset）");
    assert_eq!(n, 0, "服务端关闭后客户端必须读到 EOF（n=0），实际读到 {n} 字节");
    for h in handles {
        h.abort();
    }
}
