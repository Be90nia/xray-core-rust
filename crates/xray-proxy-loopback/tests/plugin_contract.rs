//! P1-8 验收：L4 契约夹具 + LB-1 转发字节冻结（黑盒）+ 装配链
//! register → build → bring_up → shutdown（`is_clean()`）。
//!
//! 字节锚 payload 独立抄写为本文件常量（不从测试外任何符号引用）；
//! loopback handler 的 dispatch 只是把 Link 原样交 sink（零读零写零改写），
//! LB-1 锁定 = sink 侧读出的字节与注入 payload 逐字节一致。
//!
//! （单文件合并 blackhole 样板的 plugin_contract.rs + plugin_assembly.rs，
//! 按本件任务书产出约定。）

use std::sync::{Arc, Mutex};

use serde_json::json;
use xray_app_dispatcher::default::{DispatchHandler, SniffingRequest};
use xray_buf::io::{Reader, new_reader, new_writer};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_frame::{
    ClauseId, Plugin, PluginDep, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_loopback::{LoopbackError, LoopbackFuture, LoopbackPlugin, LoopbackSink};
use xray_transport::link::Link;

/// LB-1 字节锚：含 NUL 与高位字节（证零改写/零截断/零 trim）。
const LB1_PAYLOAD: &[u8] = b"loopback-lb1-frozen\x00\x7F\x80\xFF-bytes-zero-rewrite";

#[test]
fn contract_macro_holds_for_loopback() {
    assert_plugin_contract!(LoopbackPlugin);
}

/// 契约面内容断言：坑约束 1-12 全适用（含 4 池纪律与 12 热路径冻结）、零 N/A、
/// deps 空（拍板 P1-8.1）、LB-1 协议专属。
#[test]
fn contract_surface_declares_all_clauses_and_lb1() {
    let plugin = LoopbackPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "loopback");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "拍板 P1-8.1：loopback 不声明 deps（运行期查表）");

    assert_eq!(contract.clauses.len(), 12, "坑约束 1-12 全适用");
    assert!(contract.clauses.contains(&ClauseId::PoolDiscipline), "坑约束 4 适用（无 N/A）");
    assert!(contract.clauses.contains(&ClauseId::HotPathFreeze), "坑约束 12 适用");
    assert!(contract.not_applicable.is_empty(), "loopback 零 N/A 声明");

    assert_eq!(
        contract.extra,
        &[("LB-1", "回环转发不经外部网络；转发字节原样零改写")],
        "协议专属条款 LB-1"
    );
}

/// 装配选项（blackhole 样板同款形态）。
fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：outbounds[] 按 protocol 路由（坑约束 7，PM 拍板不新增 plugins 段）。
fn loopback_section_config(inbound_tag: &str) -> serde_json::Value {
    json!({ "outbounds": [
        { "protocol": "loopback", "tag": "lb-out", "settings": { "inboundTag": inbound_tag } }
    ] })
}

/// 完整装配链：build 期段路由解析 → bring_up 三相 → 停机报告干净。
#[tokio::test]
async fn loopback_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(LoopbackPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(loopback_section_config("in-main"))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build phase");
    assert!(!framework.is_running(), "build 成功但未 bring_up，不得误报运行态");

    framework.bring_up().expect("bring_up: init/start 三相");
    assert!(framework.is_running());

    let report = framework.shutdown().await;
    assert!(report.is_clean(), "健康链停机报告必须干净");

    // 停机后插件 build 产物仍在（OnceLock 值语义独立于装配链生命周期）。
    assert_eq!(plugin.built_inbound_tag().expect("built"), "in-main");
}

/// 插件工厂产出 handler：section 的 inboundTag 流入 handler（tag 属注册期信息）。
#[tokio::test]
async fn handler_produced_by_plugin() {
    let plugin = Arc::new(LoopbackPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(loopback_section_config("in-main"))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");

    let handler = plugin.handler("lb-out").expect("handler");
    assert_eq!(handler.tag(), "lb-out");
    assert_eq!(handler.inbound_tag(), "in-main");

    framework.shutdown().await;
}

/// LB-1 黑盒 sink：记录 inbound_tag/sniffing 透传，drain link.reader 收集字节
/// （EOF 约定：错误即结束 drain，同 dispatcher.rs）。
#[derive(Debug, Default)]
struct CaptureSink {
    tags: Arc<Mutex<Vec<String>>>,
    sniffings: Arc<Mutex<Vec<SniffingRequest>>>,
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl LoopbackSink for CaptureSink {
    fn dispatch_loopback(
        &self,
        inbound_tag: String,
        _destination: Destination,
        sniffing: SniffingRequest,
        mut link: Link,
    ) -> LoopbackFuture<Result<(), LoopbackError>> {
        self.tags.lock().expect("tags lock").push(inbound_tag);
        self.sniffings.lock().expect("sniffings lock").push(sniffing);
        let bytes = Arc::clone(&self.bytes);
        Box::pin(async move {
            while let Ok(mb) = link.reader.read_multi_buffer().await {
                if mb.is_empty() {
                    break;
                }
                for buffer in mb.iter() {
                    bytes.lock().expect("bytes lock").extend_from_slice(buffer.bytes());
                }
            }
            Ok(())
        })
    }
}

/// LB-1 黑盒锁定：插件链（build → 工厂产出 → dispatch 全链）转发字节与注入
/// payload 逐字节一致；inbound_tag 按段配置透传、sniffing 零值透传
/// （Go loopback.go:56-62 未配置 = 零值）。
#[tokio::test]
async fn lb1_forwarded_bytes_frozen_through_plugin_chain() {
    let plugin = Arc::new(LoopbackPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(loopback_section_config("target-in"))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build: section routed + inboundTag parsed");

    let sink = Arc::new(CaptureSink::default());
    let handler =
        plugin.handler("lb-out").expect("handler").with_sink(sink.clone() as Arc<dyn LoopbackSink>);
    assert!(handler.has_sink(), "sink 已注入（运行期查表半边）");

    let link =
        Link::new(new_reader(std::io::Cursor::new(LB1_PAYLOAD.to_vec())), new_writer(Vec::new()));
    let dest = Destination::new(Address::new_domain("v1.mux.cool"), Port::new(9527), Network::TCP);
    handler.dispatch(&dest, link).await;

    assert_eq!(sink.tags.lock().expect("tags lock").as_slice(), ["target-in"]);
    assert!(
        !sink.sniffings.lock().expect("sniffings lock").first().expect("recorded").enabled,
        "未配置 sniffing 时透传零值（Go loopback.go:56-62）"
    );
    {
        let forwarded = sink.bytes.lock().expect("bytes lock");
        assert_eq!(forwarded.len(), LB1_PAYLOAD.len(), "转发字节数必须等于注入 payload（LB-1）");
        assert_eq!(
            &*forwarded, LB1_PAYLOAD,
            "转发字节必须与注入 payload 逐字节一致（LB-1：零改写）"
        );
    }

    framework.shutdown().await;
}

/// L5 装配门负向：缺段 fail-fast（坑约束 7 装配半边）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(LoopbackPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 loopback 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// L5 装配门负向：段在但缺 inboundTag → build 硬错。
#[tokio::test]
async fn missing_inbound_tag_fails_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(json!({ "outbounds": [
            { "protocol": "loopback", "tag": "lb-out", "settings": {} }
        ] }))
        .register(Arc::new(LoopbackPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("缺 inboundTag 必须 build 失败");
    assert!(err.to_string().contains("inboundTag"), "错误必须携带键名: {err}");
}

// ── L4 行为夹具接线（P1-L4：每协议 crate 必调，缺=CI 红）──
// 按 contract() 声明面（src/plugin.rs LOOPBACK_CLAUSES，12 条全适用、零 N/A）：
// 跑 conn_id(3) / deadline(2) / log(10,11) / pool(4)，无跳过项。

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
    l4_run_conn_id_fixture("loopback");
}

/// 夹具二（坑约束 2）：deadline 双入口（with_deadline / HandshakeDeadline::guard）
/// 期限内 Ok、永不完成 Err(Elapsed) 且真超时。d 钉 100ms 上限（CI 慢机安全）。
#[tokio::test]
async fn l4_deadline_effective() {
    xray_frame::assert_deadline_effective!(std::time::Duration::from_millis(100), || async {})
        .await;
}

/// 夹具三（坑约束 10/11）：target 前缀 `xray_frame::loopback` + conn_id/stage/
/// peer/dest 四元组齐全 + secrets 掩码（条款 11 适用 → 表传真实形态凭据样例）。
#[test]
fn l4_log_fields() {
    xray_frame::assert_log_fields!(
        domain: "loopback",
        conn_id: 0x1234u128,
        stage: "Accept",
        peer: "203.0.113.7:443",
        dest: "example.com:80",
        secrets: ["loopback-credential-sample"],
    );
}

/// 夹具四（坑约束 4/9）：借 N 还 N → PoolMetrics 配平（borrowed=0 且零溢出丢弃）。
#[test]
fn l4_pool_discipline() {
    let pool =
        xray_frame::pool::ManagedBufferPool::new(xray_frame::pool::XrayBufPool::new(8, 8), 8, 8);
    xray_frame::assert_pool_discipline!(pool, 4);
}
