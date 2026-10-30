//! bd bb1dn 观测接线验收：审计事件流 → tracing 桥（udf `tracingx`）+ log-embed
//! 埋点门（`xray_frame::<域>` target）。
//!
//! 捕获用 `tracing::subscriber::set_default`（RAII DefaultGuard）。
//!
//! **单测试设计**（非两条）：tracing callsite interest 是进程级缓存，同二进制内
//! 任一测试先以无订阅者状态让 callsite 首评估 → 缓存 Never → 后续捕获恒 0 条
//! （udf CI 三族 flake 的 tracing 族同款根因）。两条断言合到同一测试 + 同一
//! 捕获窗，首评估必发生在捕获态。

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use skeleton::Store as _;
use xray_frame::logging::{LogAuditAction, LogFacade, audit};

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
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || buf.clone())
        .finish();
    tracing::subscriber::set_default(subscriber)
}

/// 端到端：真实消费点（`LogFacade::new`）→ 审计 store 计数前进 + `skeleton::audit`
/// 事件入 tracing + 域埋点带正确 target 且不泄漏密钥内容。
#[test]
fn observation_wiring_end_to_end() {
    let buf = SharedBuf::default();
    let _guard = capture(buf.clone());

    let before = audit().snapshot().facades;
    let _facade = LogFacade::new("observe_wire", vec![Arc::from("s3cret")]);
    // 直连 dispatch 一笔，验证 reducer 计数前进（store 读侧取证面）。
    audit().dispatch(LogAuditAction::Facade { secrets: 1 });
    let after = audit().snapshot().facades;
    assert_eq!(after, before + 2, "reducer 必须逐笔累加（审计状态前进）");

    let out = buf.snapshot();
    // 桥（udf tracingx）：target 与生命周期节点字段
    assert!(out.contains("skeleton::audit"), "udf 桥 target 必须可过滤: {out}");
    assert!(
        out.contains("kind=\"enqueued\"") || out.contains("kind=\"reduced\""),
        "生命周期节点必须入 tracing: {out}"
    );
    assert!(out.contains("seq="), "单调序号必须入字段: {out}");
    // 埋点门（log-embed 纪律）：域 target + 只记条数不记内容
    assert!(out.contains("xray_frame::log::domain"), "域 target 缺失: {out}");
    assert!(out.contains("facade domain=observe_wire"), "文案缺失: {out}");
    assert!(!out.contains("s3cret"), "密钥内容泄漏: {out}");
}
