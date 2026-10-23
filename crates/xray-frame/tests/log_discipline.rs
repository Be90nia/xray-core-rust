//! P0-7 日志纪律集成验收（任务书 2026-10-23 四组用例）：
//! mask_secrets 掩码实证 / target `xray_frame::<域>` 实证 / AlreadyInit /
//! 空 secrets 表原样透传。
//!
//! 捕获用 `tracing::subscriber::set_default`（RAII DefaultGuard）+ 自建
//! `with_writer` 闭环 writer；emit 面是运行时 target/level（tracing verbatim
//! 路径，无 callsite interest 缓存），线程局部订阅者捕获确定性成立。

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use xray_frame::logging::{LogFacade, init_from_env};

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

#[test]
fn masks_secrets_before_emit() {
    let buf = SharedBuf::default();
    let _guard = capture(buf.clone());
    let facade = LogFacade::new("assembly", vec![Arc::from("s3cret")]);

    facade.info("key is s3cret");

    let out = buf.snapshot();
    assert!(out.contains("***"), "masked output: {out}");
    assert!(!out.contains("s3cret"), "raw secret leaked: {out}");
}

#[test]
fn target_pinned_to_xray_frame_domain() {
    let buf = SharedBuf::default();
    let _guard = capture(buf.clone());
    let facade = LogFacade::new("assembly", vec![]);

    facade.info("hello");

    let out = buf.snapshot();
    assert!(out.contains("xray_frame::assembly"), "target missing in: {out}");
}

#[test]
fn empty_secrets_table_passes_through_verbatim() {
    let buf = SharedBuf::default();
    let _guard = capture(buf.clone());
    let facade = LogFacade::new("passthrough", vec![]);

    facade.warn("key is s3cret");

    let out = buf.snapshot();
    assert!(out.contains("key is s3cret"), "verbatim expected: {out}");
}

#[test]
fn duplicate_init_returns_already_init() {
    init_from_env(log::LevelFilter::Info).expect("first init ok");
    let second = init_from_env(log::LevelFilter::Info);
    assert!(
        matches!(second, Err(skeleton_infra::logx::AlreadyInit)),
        "重复 init → Err(AlreadyInit)"
    );
}
