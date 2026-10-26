//! P1-7 B 块验收：L4 契约夹具 + Http403 响应体字节形态黑盒锁定（BH-1）。
//!
//! 字节锚是**独立抄写**的改动前 HEAD 行为快照（不从 `response.rs` 的
//! `HTTP_403_RESPONSE` 常量引用）——常量被改动时本测试必红，防 fixture
//! 跟着漂移。解析语义回归（custom base64 / 未知 type）在 `src/plugin.rs`
//! 单元测试覆盖；本文件管契约宏、装配门与字节锁定。

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use serde_json::json;
use xray_app_dispatcher::default::DispatchHandler;
use xray_buf::{
    io::{self, Reader, Writer},
    multi::MultiBuffer,
};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_features::inbound::InboundHandler;
use xray_frame::{
    ClauseId, Plugin, PluginDep,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_blackhole::{BlackholePlugin, ResponseConfig};
use xray_transport::link::Link;

/// 改动前 HEAD 快照（101 字节：CRLF 行末、Header 字典序、`Content-Length: 0`、
/// 头后单个空行）——与 Go v26.9.9 `http403response` 输出逐字节对齐。
const HTTP_403_FIXTURE: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nCache-Control: max-age=3600, public\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

#[test]
fn contract_macro_holds_for_blackhole() {
    assert_plugin_contract!(BlackholePlugin);
}

/// 契约面内容断言：适用子集 10 条、坑约束 4 走 N/A + 非空理由、BH-1 协议专属。
#[test]
fn contract_surface_declares_subset_na_and_extra() {
    let plugin = BlackholePlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "blackhole");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "blackhole 无依赖插件");

    assert_eq!(contract.clauses.len(), 10, "适用条款 = 12 条去掉坑约束 4（N/A）");
    assert!(
        !contract.clauses.contains(&ClauseId::PoolDiscipline),
        "坑约束 4 必须走 N/A 声明而非 clauses"
    );

    let [(na_clause, na_reason)] = contract.not_applicable else {
        panic!("blackhole 必须恰好声明一条 N/A（坑约束 4）");
    };
    assert_eq!(na_clause, &ClauseId::PoolDiscipline);
    assert!(!na_reason.trim().is_empty(), "N/A 理由必须非空（拍板 P2.2）");

    assert_eq!(
        contract.extra,
        &[("BH-1", "Http403 响应体字节形态恒定（Go 兼容）")],
        "协议专属条款 BH-1"
    );
}

/// 立即返回错误的 reader（EOF 约定：错误即 break drain，见 dispatcher.rs）。
struct EofReader;

impl Reader for EofReader {
    fn read_multi_buffer<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<MultiBuffer>> + Send + 'a>> {
        Box::pin(async { Err(io::Error::ReadError("eof".into())) })
    }
}

/// 收集写出字节的 writer（断言面：内容逐字节比对，非仅长度）。
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Writer for CaptureWriter {
    fn write_multi_buffer<'a>(
        &'a mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        for buffer in mb.iter() {
            self.0.lock().expect("capture lock").extend_from_slice(buffer.bytes());
        }
        Box::pin(async { Ok(()) })
    }
}

/// 装配选项（契约测试与装配测试共用的形态）。
fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：outbounds[] 按 protocol 路由（坑约束 7，PM 拍板不新增 plugins 段）。
fn blackhole_section_config(response: serde_json::Value) -> serde_json::Value {
    json!({ "outbounds": [
        { "protocol": "blackhole", "tag": "bh-out", "settings": { "response": response } }
    ] })
}

/// 黑盒锁定：插件链（build 解析 → 工厂产出 handler → dispatch 全链写出）
/// 的 Http403 字节与改动前快照**逐字节**一致。
#[tokio::test]
async fn http403_bytes_frozen_through_plugin_chain() {
    let plugin = Arc::new(BlackholePlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(blackhole_section_config(json!({ "type": "http" })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build: section routed + response parsed");

    // ① 插件 build 产物 = Http403（fail-visible 观察面）。
    assert_eq!(plugin.built_response().expect("built"), &ResponseConfig::Http403);

    // ② 插件工厂产出 outbound handler，dispatch 全链写出。
    let handler = plugin
        .dispatch_handler(Arc::new(xray_frame::PluginContext::for_plugin("blackhole")), "bh-out")
        .expect("dispatch handler");
    assert_eq!(handler.response(), ResponseConfig::Http403);

    let captured = Arc::new(Mutex::new(Vec::new()));
    let link = Link::new(Box::new(EofReader), Box::new(CaptureWriter(Arc::clone(&captured))));
    let dest = Destination::new(Address::new_domain("example.com"), Port::new(443), Network::TCP);
    handler.dispatch(&dest, link).await;

    {
        let written = captured.lock().expect("capture lock");
        assert_eq!(written.len(), HTTP_403_FIXTURE.len(), "写出字节数必须等于 fixture（101）");
        assert_eq!(&*written, HTTP_403_FIXTURE, "Http403 响应体必须与改动前快照逐字节一致（BH-1）");
    }

    framework.shutdown().await;
}

/// 入站 handler 同样由插件产出（构造面；bind 行为属既有 InboundHandler 实测）。
#[tokio::test]
async fn inbound_handler_produced_by_plugin() {
    let plugin = Arc::new(BlackholePlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(blackhole_section_config(json!({ "type": "http" })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");

    let inbound = plugin
        .inbound_handler(
            Arc::new(xray_frame::PluginContext::for_plugin("blackhole")),
            "bh-in",
            "127.0.0.1:0",
        )
        .expect("inbound handler");
    assert_eq!(inbound.tag(), "bh-in");

    framework.shutdown().await;
}

/// L5 装配门负向：缺段 fail-fast（坑约束 7 装配半边）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(BlackholePlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 blackhole 段必须 fail-fast");
    assert!(matches!(err, xray_frame::PluginError::Config(_)), "实际: {err}");
}

/// L5 装配门负向：未知 response type → build 硬错。
#[tokio::test]
async fn unknown_response_type_fails_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(blackhole_section_config(json!({ "type": "!!!mystery" })))
        .register(Arc::new(BlackholePlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("未知 response type 必须 build 失败");
    assert!(err.to_string().contains("mystery"), "错误必须携带未知 type: {err}");
}

// ── L4 行为夹具接线（P1-L4：每协议 crate 必调，缺=CI 红）──
// 按 contract() 声明面（src/plugin.rs BLACKHOLE_CLAUSES / BLACKHOLE_NOT_APPLICABLE）：
// 跑 conn_id(3) / deadline(2) / log(10,11)；跳过 pool(4)——blackhole 零缓冲分配
// （drain 逐帧丢弃、预置响应单次整写，全路径无缓冲池消费点），N/A 理由见声明面。

/// 夹具一（坑约束 3）：conn_id 非零/唯一/单调——无例外条款。
///
/// 执行面：`contract_test_context` 的指纹随进程掷点（`derive_fingerprint(None)`），
/// 基址落 0xFFF 邻域时同毫秒 64 连发会撞 IdGen fail-closed 配额臂（约 1.5%/掷点，
/// panic 消息含「配额耗尽」）——夹具整体在 catch_unwind 内彩排，撞配额臂则重掷
/// 指纹重跑（8 连败联合概率 ~1e-15），其余 panic 原样上抛。成功返回 = 宏断言在
/// 本 ctx 上真实执行且通过。
fn l4_run_conn_id_fixture(plugin: &'static str) {
    use std::{
        any::Any,
        panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    };

    let mut last: Option<Box<dyn Any + Send>> = None;
    for _ in 0..8 {
        let ctx = xray_frame::contract_assert::contract_test_context(plugin);
        match catch_unwind(AssertUnwindSafe(|| xray_frame::assert_conn_id_present!(ctx, 64))) {
            Ok(()) => return,
            Err(payload) => {
                let quota =
                    payload.downcast_ref::<String>().is_some_and(|m| m.contains("配额耗尽"))
                        || payload
                            .downcast_ref::<&'static str>()
                            .is_some_and(|m| m.contains("配额耗尽"));
                if !quota {
                    resume_unwind(payload);
                }
                last = Some(payload);
            },
        }
    }
    resume_unwind(last.expect("重掷循环至少记录一次失败 payload"));
}

#[test]
fn l4_conn_id_present() {
    l4_run_conn_id_fixture("blackhole");
}

/// 夹具二（坑约束 2）：deadline 双入口（with_deadline / HandshakeDeadline::guard）
/// 期限内 Ok、永不完成 Err(Elapsed) 且真超时。d 钉 100ms 上限（CI 慢机安全）。
#[tokio::test]
async fn l4_deadline_effective() {
    xray_frame::assert_deadline_effective!(std::time::Duration::from_millis(100), || async {})
        .await;
}

/// 夹具三（坑约束 10/11）：target 前缀 `xray_frame::blackhole` + conn_id/stage/
/// peer/dest 四元组齐全 + secrets 掩码（条款 11 适用 → 表传真实形态凭据样例）。
#[test]
fn l4_log_fields() {
    xray_frame::assert_log_fields!(
        domain: "blackhole",
        conn_id: 0x1234u128,
        stage: "Accept",
        peer: "203.0.113.7:443",
        dest: "example.com:80",
        secrets: ["blackhole-credential-sample"],
    );
}
