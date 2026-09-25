//! mKCP finalmask 伪装 e2e：Rust client ↔ 录制 UDP proxy ↔ Rust server。
//!
//! 验收（bd 3lm）：
//! 1. mask 开启（aes128gcm + srtp header 叠加）roundtrip 正常；
//! 2. 线上字节非裸 KCP——proxy 录制包经同配置 chain decode 成功且 overhead 精确匹配（28B AEAD + 4B
//!    srtp），AEAD tag 验证即密码学证明；
//! 3. mask 关闭 roundtrip 不变（回归），且同 chain decode 裸 KCP 包必失败。

use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_transport::{
    connection::Connection,
    dialer::{StreamSettings, dial_with_settings},
    finalmask::parse_finalmask_udp_chain,
    listener_registry::{ConnHandler, TransportListener, listen_tcp},
    sockopt::SocketOptions,
};
use xray_transport_kcp::{register_dialer, register_listener};

/// aes128gcm(value) + srtp header 两条 mkcp-legacy 叠加（对齐 Go 多 mask 链）。
const MASK_ON: &str = r#"{"udp":[
    {"type":"mkcp-legacy","settings":{"value":"test-mask-pass"}},
    {"type":"mkcp-legacy","settings":{"header":"srtp"}}
]}"#;

/// 录制 + 双向转发的 UDP proxy。
struct RecordingProxy {
    captured: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    addr: SocketAddr,
}

impl RecordingProxy {
    fn start(server: SocketAddr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let addr = socket.local_addr().unwrap();
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let cap = Arc::clone(&captured);
        let st = Arc::clone(&stop);
        thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let mut client: Option<SocketAddr> = None;
            while !st.load(Ordering::Relaxed) {
                match socket.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        cap.lock().push(buf[..n].to_vec());
                        if src == server {
                            if let Some(c) = client {
                                let _ = socket.send_to(&buf[..n], c);
                            }
                        } else {
                            client = Some(src);
                            let _ = socket.send_to(&buf[..n], server);
                        }
                    },
                    Err(_) => {}, // read timeout → 检查 stop 后继续
                }
            }
        });
        Self { captured, stop, addr }
    }

    fn first_packet(&self) -> Vec<u8> {
        loop {
            if let Some(p) = self.captured.lock().first() {
                return p.clone();
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for RecordingProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn mkcp_settings(finalmask: Option<&str>) -> StreamSettings {
    let json: serde_json::Value = match finalmask {
        Some(fm) => serde_json::from_str(&format!(
            r#"{{"network":"mkcp","kcpSettings":{{}},"finalmask":{fm}}}"#
        ))
        .unwrap(),
        None => serde_json::from_str(r#"{"network":"mkcp","kcpSettings":{}}"#).unwrap(),
    };
    StreamSettings::from_json(Some(&json))
}

/// echo server handler：读到什么回什么。
fn echo_handler() -> ConnHandler {
    Arc::new(|conn: Box<dyn Connection>| {
        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(conn);
            let mut buf = vec![0u8; 8192];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if wr.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        if wr.flush().await.is_err() {
                            break;
                        }
                    },
                }
            }
        });
    })
}

async fn setup_server(settings: &StreamSettings) -> (SocketAddr, Box<dyn TransportListener>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = listen_tcp(addr, settings.clone(), SocketOptions::default(), echo_handler())
        .await
        .expect("listen mkcp");
    let local = listener.local_addr().expect("local addr");
    // listener 由调用方持有至测试体结束：drop → hub.close() → spawn_blocking 接收循环
    // ≤200ms 退出。不可 mem::forget：hub 永不关闭会使接收循环无限运行，
    // tokio Runtime::drop 等待 blocking task 永不返回 = 测试挂死。
    (local, listener)
}

async fn roundtrip_through(proxy_addr: SocketAddr, settings: &StreamSettings) -> Vec<u8> {
    let dest = Destination::new(
        Address::IPv4(Ipv4Addr::LOCALHOST),
        Port::new(proxy_addr.port()),
        Network::UDP,
    );
    let mut conn = dial_with_settings("mkcp", &dest, &SocketOptions::default(), settings)
        .await
        .expect("dial mkcp");
    conn.write_all(b"hello mkcp mask e2e").await.unwrap();
    conn.flush().await.unwrap();

    let mut echoed = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(15), conn.read(&mut echoed))
        .await
        .expect("echo timeout")
        .expect("echo read");
    echoed[..n].to_vec()
}

/// multi_thread flavor：即使某环节陷入 std 阻塞也不拖死 runtime 计时器，
/// 保证整体 60s 超时总能触发（挂死可见性）。
#[tokio::test(flavor = "multi_thread")]
async fn mask_on_roundtrip_and_wire_bytes_are_masked() {
    let run = async {
        register_dialer().unwrap();
        register_listener().unwrap();

        let settings = mkcp_settings(Some(MASK_ON));
        let (server_addr, _listener) = setup_server(&settings).await;
        let proxy = RecordingProxy::start(server_addr);

        // 1. 数据 roundtrip
        let echoed = roundtrip_through(proxy.addr, &settings).await;
        assert_eq!(echoed, b"hello mkcp mask e2e");

        // 2. 线上字节非裸 KCP：同配置 chain 可 decode（AEAD tag 验证 = 密码学证明）
        let fm: serde_json::Value = serde_json::from_str(MASK_ON).unwrap();
        let chain = parse_finalmask_udp_chain(Some(&fm)).unwrap().expect("chain");
        let raw = proxy.first_packet();
        let decoded = chain.decode(&raw).expect("captured packet decodes under mask chain");
        assert_eq!(raw.len() - decoded.len(), 28 + 4, "overhead = aes128gcm(28) + srtp(4)");
        assert_ne!(raw, decoded, "wire bytes differ from plaintext KCP segment");
    };
    if tokio::time::timeout(Duration::from_secs(60), run).await.is_err() {
        panic!("mask_on_roundtrip exceeded 60s overall budget — hung");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mask_off_roundtrip_unchanged_and_wire_is_bare_kcp() {
    let run = async {
        register_dialer().unwrap();
        register_listener().unwrap();

        let settings = mkcp_settings(None);
        let (server_addr, _listener) = setup_server(&settings).await;
        let proxy = RecordingProxy::start(server_addr);

        let echoed = roundtrip_through(proxy.addr, &settings).await;
        assert_eq!(echoed, b"hello mkcp mask e2e");

        // 回归：无 finalmask 时线上是裸 KCP——同 chain decode 必失败
        // （original FNV/长度校验 + AEAD tag 校验不可能偶然通过）
        let fm: serde_json::Value = serde_json::from_str(MASK_ON).unwrap();
        let chain = parse_finalmask_udp_chain(Some(&fm)).unwrap().expect("chain");
        let raw = proxy.first_packet();
        assert!(chain.decode(&raw).is_err(), "bare KCP packet must not decode under mask chain");
    };
    if tokio::time::timeout(Duration::from_secs(60), run).await.is_err() {
        panic!("mask_off_roundtrip exceeded 60s overall budget — hung");
    }
}
