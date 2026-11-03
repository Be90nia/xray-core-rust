#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 互通探针脚本化进度输出
//! VMess 客户端 ↔ **Go xray 服务端**互通探针（直挂连接的 wire 判别器）。
//!
//! Rust `make_vmess_dial_fn`（VmessConn 读写两半直挂 chunk wire）→ Go vmess inbound
//! → freedom → 本机 TCP echo；三种载荷各跑一遍：
//! - 5B：单 chunk，且响应头与首块 body 常在同一 TCP 段内到达；
//! - 9 KiB：跨 chunk 边界（> 单 chunk 明文容量 ≈ 8110B），验 nonce 逐块自增；
//! - 200 KiB：多轮读写的背压路径（poll_write 暂存 + 帧续推）。
//!
//! 编排：`python reports/audit-2026-11-03/scripts/run_vmess_go_interop.py`
//!
//! 手工运行（需先起 Go 侧）：
//! ```sh
//! XRAY_GO_VMESS_ADDR=127.0.0.1:PORT XRAY_ECHO_ADDR=127.0.0.1:PORT \
//! XRAY_TEST_UUID=<uuid> cargo test -p xray-proxy-vmess --test go_server_interop -- --ignored --nocapture
//! ```

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_common::{
    net::{address::Address, destination::Destination, port::Port},
    uuid::UUID,
};
use xray_frame::PluginContext;
use xray_proxy_vmess::{VmessOutboundConfig, make_vmess_dial_fn};

/// 逐尺寸往返：写 payload → 读回等长回显，逐字节比对。
#[tokio::test]
#[ignore = "needs Go xray vmess server + echo（run_vmess_go_interop.py 编排）"]
async fn vmess_go_server_roundtrip() {
    let go_addr = std::env::var("XRAY_GO_VMESS_ADDR").expect("XRAY_GO_VMESS_ADDR");
    let echo_addr = std::env::var("XRAY_ECHO_ADDR").expect("XRAY_ECHO_ADDR");
    let uuid =
        UUID::parse(&std::env::var("XRAY_TEST_UUID").expect("XRAY_TEST_UUID")).expect("parse uuid");
    let (go_host, go_port) = go_addr.rsplit_once(':').expect("go host:port");
    let (echo_host, echo_port) = echo_addr.rsplit_once(':').expect("echo host:port");

    let cfg = Arc::new(VmessOutboundConfig::new(
        uuid,
        Address::new_domain(go_host),
        Port::new(go_port.parse().expect("go port")),
    ));
    let ctx = Arc::new(PluginContext::for_plugin("vmess"));
    let dial = make_vmess_dial_fn(cfg, ctx);
    let dest = Destination::tcp(
        Address::new_domain(echo_host),
        Port::new(echo_port.parse().expect("echo port")),
    );

    for (name, len) in [("small", 5usize), ("cross-chunk", 9 * 1024), ("bulk", 200 * 1024)] {
        eprintln!("[roundtrip] {name}: {len}B");
        let mut conn = dial(&dest).await.expect("dial go server");
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        conn.write_all(&payload).await.expect("write payload");
        conn.flush().await.expect("flush payload");

        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(std::time::Duration::from_secs(30), conn.read_exact(&mut got))
            .await
            .expect("echo must arrive (Go 服务端响应头惰性 flush 不得卡死)")
            .expect("read echo");
        assert_eq!(got, payload, "{name}: 回显必须逐字节相同");
    }
}
