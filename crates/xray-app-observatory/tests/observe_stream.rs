//! P3-3 统一观测流集成验收：Observer 探测结果经 `ObserveSink` 复用
//! `xray_frame::observe` 四元组（conn_id/stage/peer/dest）+ `LogFacade` 落点。
//!
//! 捕获用 `tracing::subscriber::set_default`（线程局部 RAII DefaultGuard）+
//! 自建 `with_writer` 闭环 writer（与 xray-frame P1-5 `observe_fields.rs`
//! 同款）；`LogFacade` emit 是运行时 target/level verbatim 分发（无 callsite
//! interest 缓存），`probe_all` 全程同步在本线程执行 → 捕获确定性成立。

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use xray_app_observatory::{
    config::{ObservatoryConfig, ProbeResult},
    observer::{FixedProbeExecutor, NoopOutboundSelector, Observer},
};
use xray_frame::observe::ObserveSink;

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    fn snapshot(&self) -> String {
        String::from_utf8(self.0.lock().expect("no poison").clone()).expect("utf8")
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("no poison").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture(buf: SharedBuf) -> tracing::subscriber::DefaultGuard {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(move || buf.clone())
        .finish();
    tracing::subscriber::set_default(subscriber)
}

#[test]
fn probe_results_flow_through_observe_fields() {
    let buf = SharedBuf::default();
    let _guard = capture(buf.clone());

    let sink = Arc::new(ObserveSink::new("observatory-test", Vec::new()));
    let o = Observer::new(ObservatoryConfig::default()).with_observe(sink);
    let executor = FixedProbeExecutor::new()
        .with_result("a", ProbeResult { alive: true, delay: 10, last_error_reason: String::new() });
    let selector = NoopOutboundSelector::new(vec!["a".into(), "b".into()]);

    let n = o.probe_all(&selector, &executor).expect("probe round");
    assert_eq!(n, 2, "两个 tag 各探测一次");

    let out = buf.snapshot();
    let lines: Vec<&str> = out.lines().filter(|l| l.contains("observatory probe tag=")).collect();
    assert_eq!(lines.len(), 2, "每条探测结果一条统一观测事件，got: {out}");

    for line in &lines {
        assert!(line.contains("stage=Forward"), "四元组 stage 必备: {line}");
        assert!(line.contains("peer=") && line.contains("dest="), "四元组 peer/dest 必备: {line}");
        assert!(line.contains("conn="), "四元组 conn_id（短 hex 展示）必备: {line}");
        assert!(
            line.contains("INFO xray_frame::observatory-test:"),
            "落点 target 钉死为 xray_frame::<domain>: {line}"
        );
    }

    let a = lines.iter().find(|l| l.contains("tag=a")).expect("tag=a 事件");
    assert!(a.contains("alive=true") && a.contains("delay=10ms"), "alive/delay 语义: {a}");
    let b = lines.iter().find(|l| l.contains("tag=b")).expect("tag=b 事件");
    assert!(b.contains("alive=false"), "未注册 tag 默认 dead: {b}");

    // conn 短 hex = u128 高 64 位非零（udf IdGen 真值，非占位）。
    for line in &lines {
        let hex = line.split("conn=").nth(1).and_then(|r| r.split(' ').next()).expect("conn hex");
        assert_eq!(hex.len(), 16, "短展示 id = 前 16 位 hex: {line}");
        assert!(hex.chars().any(|c| c != '0'), "conn 短 hex 非零: {line}");
    }
}

#[test]
fn no_sink_default_stays_silent() {
    let buf = SharedBuf::default();
    let _guard = capture(buf.clone());

    let o = Observer::new(ObservatoryConfig::default());
    let executor = FixedProbeExecutor::new();
    let selector = NoopOutboundSelector::new(vec!["a".into()]);
    o.probe_all(&selector, &executor).expect("probe round");

    assert!(
        !buf.snapshot().contains("observatory probe"),
        "未接线 ObserveSink 时零发射（缺省静默，既有路径零扰动）"
    );
}
