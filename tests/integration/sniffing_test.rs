//! G-03 嗅探端到端（dofk 缺口；Go 对照 testing/scenarios/feature_test.go:541
//! `TestDomainSniffing`）。
//!
//! Go 原版经真实 HTTPS（www.github.com）验证链路；本测试等价替换为全回环
//! 双 echo 判别器拓扑（无外网依赖），断言「路由按嗅探域名命中而非按 IP」：
//!
//! ```text
//! client ──CONNECT sniffed.example.com:443──▶ http-in（HTTP 代理 inbound）
//!   ──[inboundTag=http-in]──▶ redir（dokodemo outbound）
//!   ──▶ snif-in（dokodemo inbound，rewrite 127.0.0.1:443，
//!                sniffing={enabled, destOverride:[tls], routeOnly:true}）
//!   ──[域名规则→dom-a | IP 规则→ip-b，first-match-wins]──▶ dokodemo outbound
//!   ──▶ echo A / echo B
//! ```
//!
//! echo A/B 在连接建立时先回写互异 banner（`-A`/`-B`）再回显；客户端按 banner
//! 判定命中路径：
//! - 嗅探生效：route_target=SNI 域名 → 域名规则命中 → banner `-A`
//! - 对照组（嗅探关闭）：上下文无域名 → IP 规则命中 127.0.0.0/8 → banner `-B`
//!
//! 数据面同时验证：回显内容必须等于 `banner + ClientHello + 载荷`（隧道不改字节）。

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound};
use xray_core::functions::start_full;

/// 嗅探目标 SNI（路由规则 `full:` 精确匹配）。
const SNI: &str = "sniffed.example.com";
/// CONNECT 隧道建立后携带的业务载荷（ClientHello 之外再带一段真实字节）。
const PAYLOAD: &[u8] = b"sniffing e2e payload after client hello!";

/// bind :0 取空闲端口再释放（与既有 e2e 测试端口分配惯例一致）。
async fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// 标记 echo server：accept 后先写 banner，再无限回显。返回监听地址。
async fn spawn_banner_echo(banner: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
            if sock.write_all(banner).await.is_err() {
                continue;
            }
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
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
    addr
}

/// dokodemo outbound：忽略 dispatcher 传入的 dest，恒拨 `{address,port}`。
fn dokodemo_outbound(tag: &str, port: u16) -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry {
            kind: "dokodemo".into(),
            data: format!(r#"{{"address":"127.0.0.1","port":{port}}}"#).into_bytes(),
        },
        tag: tag.into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
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

/// 起完整嗅探拓扑，返回 (http 代理端口, instance, inbound handles)。
///
/// 规则序即匹配序（first-match-wins）：`inboundTag=http-in` 必须排在最前，
/// 否则 http-in 携带的 CONNECT 域名会提前命中域名规则、绕过嗅探 inbound。
async fn start_topology(
    sniffing_json: Option<serde_json::Value>,
) -> (u16, Arc<xray_core::Instance>, Vec<tokio::task::JoinHandle<()>>) {
    let echo_a = spawn_banner_echo(b"-A").await;
    let echo_b = spawn_banner_echo(b"-B").await;
    let http_port = pick_free_port().await;
    let snif_port = pick_free_port().await;

    let mut built = BuiltConfig::default();
    built.inbounds.push(BuiltInbound {
        entry: BuiltEntry { kind: "http".into(), data: b"{}".to_vec() },
        tag: "http-in".into(),
        port: Some(http_port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    });
    built.inbounds.push(BuiltInbound {
        entry: BuiltEntry {
            kind: "dokodemo".into(),
            // Go 原版 RewriteAddress/RewritePort 同形态：rewrite 到 127.0.0.1:443。
            data: br#"{"address":"127.0.0.1","port":443}"#.to_vec(),
        },
        tag: "snif-in".into(),
        port: Some(snif_port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json,
    });
    built.outbounds.push(freedom_default()); // i=0 → default
    built.outbounds.push(dokodemo_outbound("redir", snif_port));
    built.outbounds.push(dokodemo_outbound("dom-a", echo_a.port()));
    built.outbounds.push(dokodemo_outbound("ip-b", echo_b.port()));
    built.apps.push(BuiltEntry {
        kind: "routing".into(),
        data: format!(
            r#"{{"domainStrategy":"AsIs","rules":[
            {{"type":"field","inboundTag":["http-in"],"outboundTag":"redir"}},
            {{"type":"field","domain":["full:{SNI}"],"outboundTag":"dom-a"}},
            {{"type":"field","ip":["127.0.0.0/8"],"outboundTag":"ip-b"}}
        ]}}"#
        )
        .into_bytes(),
    });

    let (instance, _ohm, handles) = start_full(&built).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    (http_port, instance, handles)
}

/// 构造带 SNI 的最小 TLS ClientHello（与 xray-core functions.rs 测试同款构造，
/// 满足 dispatcher TlsSniffer 的 record → handshake → extensions → SNI 解析路径）。
fn build_client_hello_with_sni(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    // SNI extension body: server_name_list
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // list_len
    body.push(0x00); // name_type = host_name
    body.extend_from_slice(&(name.len() as u16).to_be_bytes());
    body.extend_from_slice(name);
    let mut ext: Vec<u8> = Vec::new();
    ext.extend_from_slice(&0x0000u16.to_be_bytes()); // extension type = SNI
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(&body);

    let mut hello: Vec<u8> = Vec::new();
    hello.extend_from_slice(&[0x03, 0x01]); // client version
    hello.extend_from_slice(&[0x42u8; 32]); // random
    hello.push(0x00); // session_id_len
    hello.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites_len
    hello.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
    hello.push(0x01); // compression_methods_len
    hello.push(0x00);
    hello.extend_from_slice(&(ext.len() as u16).to_be_bytes()); // extensions_len
    hello.extend_from_slice(&ext);

    let mut hs: Vec<u8> = vec![0x01]; // handshake type = ClientHello
    let l = hello.len();
    hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    hs.extend_from_slice(&hello);

    let mut rec: Vec<u8> = vec![0x16, 0x03, 0x01]; // record: Handshake
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// 走 HTTP CONNECT 隧道发送 ClientHello+载荷，回读 echo 全量。
/// 返回 (banner, 回显全量字节)；banner 标识命中路径（-A=域名规则 / -B=IP 规则）。
async fn run_connect_and_echo(http_port: u16) -> (Vec<u8>, Vec<u8>) {
    let mut client = TcpStream::connect(("127.0.0.1", http_port)).await.unwrap();
    client
        .write_all(format!("CONNECT {SNI}:443 HTTP/1.1\r\nHost: {SNI}:443\r\n\r\n").as_bytes())
        .await
        .unwrap();
    // 读 200 响应头（HTTP/1.1 200 Connection established\r\n\r\n，dial 前回写）。
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut byte))
            .await
            .expect("CONNECT 响应超时")
            .unwrap();
        assert!(n > 0, "连接在 CONNECT 响应前被关闭");
        head.extend_from_slice(&byte);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    assert!(head.contains(" 200 "), "CONNECT 应成功，实际响应头: {head}");

    // 隧道内：ClientHello（嗅探首包）+ 业务载荷，一次写入。
    let mut sent = build_client_hello_with_sni(SNI);
    sent.extend_from_slice(PAYLOAD);
    client.write_all(&sent).await.unwrap();

    // echo 先回 banner（2 字节），再原样回显全部字节。
    let mut got = vec![0u8; 2 + sent.len()];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut got))
        .await
        .expect("echo roundtrip 超时")
        .unwrap();
    (got[..2].to_vec(), got)
}

/// 断言回显数据面完整：banner 之后必须原样回显 ClientHello + 载荷。
fn assert_data_plane(all: &[u8]) {
    let mut expected = build_client_hello_with_sni(SNI);
    expected.extend_from_slice(PAYLOAD);
    assert_eq!(&all[2..], expected.as_slice(), "隧道必须原样回显全部字节");
}

/// 嗅探生效：TLS ClientHello SNI 被嗅探 → route_target=域名 → 域名规则命中
/// （echo A banner "-A"），且隧道数据面原样回显。对应 Go TestDomainSniffing
/// 「按嗅探结果路由」的核心断言。
#[tokio::test]
async fn sniffed_tls_sni_routes_by_domain_marker_a() {
    let (http_port, _instance, handles) = start_topology(Some(serde_json::json!({
        "enabled": true,
        "destOverride": ["tls"],
        "routeOnly": true
    })))
    .await;
    let (banner, all) = run_connect_and_echo(http_port).await;
    assert_eq!(
        banner,
        b"-A",
        "嗅探生效时路由应命中域名规则（echo A），实际 banner {banner:?}"
    );
    assert_data_plane(&all);
    for h in handles {
        h.abort();
    }
}

/// 对照组：嗅探关闭 → 上下文无域名 → 域名规则不命中 → IP 规则命中 127.0.0.0/8
/// （echo B banner "-B"）。与上一测试构成 A/B，证明是嗅探域名（而非 IP）驱动了
/// 分流；同时证明嗅探关闭路径本身数据面完好。
#[tokio::test]
async fn sniffing_disabled_falls_back_to_ip_rule_marker_b() {
    let (http_port, _instance, handles) = start_topology(None).await;
    let (banner, all) = run_connect_and_echo(http_port).await;
    assert_eq!(
        banner,
        b"-B",
        "嗅探关闭时路由应命中 IP 规则（echo B），实际 banner {banner:?}"
    );
    assert_data_plane(&all);
    for h in handles {
        h.abort();
    }
}
