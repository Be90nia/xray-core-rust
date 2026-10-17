//! 集成测试：入站端口被占用 → 启动必须 fatal（bd 0z7u，对齐 Go xray 入站创建
//! 失败 → core 启动失败的语义）。
//!
//! 断言完整启动链路把 bind 失败传到顶层且带 inbound tag 上下文：
//! `start_full` → `spawn_inbounds`（ERROR 日志 + tag 包装）→ `spawn_one_inbound`
//! （`?`）→ `InboundTcpListener::bind` → `bind_tcp_listener`（bd hjtt backlog
//! 1024）Err。修复前该场景是裸 `Address already in use`（无 tag、可定位性差）。

use xray_conf::Config;
use xray_core::start_full;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn occupied_inbound_port_fails_startup_with_tag_context() {
    // 占住端口的「另一个进程」等价物。
    let holder = std::net::TcpListener::bind("127.0.0.1:0").expect("bind holder");
    let port = holder.local_addr().expect("local_addr").port();

    let cfg = Config::from_json_str(
        &serde_json::json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "tag": "occupied-in",
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {}
            }],
            "outbounds": [{"protocol": "freedom", "tag": "direct"}]
        })
        .to_string(),
    )
    .expect("config json parses");
    let built = cfg.build().expect("config builds");

    let err = match start_full(&built).await {
        Err(e) => e,
        Ok(_) => panic!("occupied inbound port must fail startup (Go xray fatal semantics)"),
    };
    let msg = err.to_string();
    assert!(msg.contains("occupied-in"), "error must carry inbound tag context, got: {msg}");
    assert!(msg.contains("start failed"), "error must carry start-failure framing, got: {msg}");
}

// backlog 数值（1024）无跨平台运行期断言手段（listen backlog 只能经 ss/netstat
// 观测，单元测试不可移植）——数值统一性由全仓 listener 创建点编译期走
// `bind_tcp_listener(addr, LISTEN_BACKLOG)` 常量保证（grep 可审计）。
