//! 未注册 General 通道 emit：消息静默丢弃 + 缺装配首次告警一行（fail-visible，
//! bd 8zs12）。
//!
//! 独立测试二进制：进程内从不注册 General 槽，专测告警恰一次。告警经
//! `tracing::warn!`（生产 xray-cli 启动即装订阅者，可见）。

use std::sync::{Arc, Mutex};

#[derive(Default)]
struct WarnBuf(Mutex<Vec<u8>>);

impl WarnBuf {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(|p| p.into_inner())).into_owned()
    }
}

#[derive(Clone)]
struct WarnWriter(Arc<WarnBuf>);

impl std::io::Write for WarnWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.0.lock().unwrap_or_else(|p| p.into_inner()).extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for WarnWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// General 槽未注册：多次 emit 只告警一行，消息本体零输出，丢弃计数不动。
#[test]
fn unregistered_general_emit_warns_exactly_once() {
    let buf = Arc::new(WarnBuf::default());
    // 订阅者必须先于首次 emit 装好：callsite interest 有进程级缓存
    //（同 xray-app-log tests/common 纪律）。
    let _ = tracing_subscriber::fmt()
        .with_writer(WarnWriter(Arc::clone(&buf)))
        .with_max_level(tracing::Level::WARN)
        .try_init();

    xray_common::log::info("first unregistered emit");
    xray_common::log::warning("second unregistered emit");
    xray_common::log::error("third unregistered emit");

    let text = buf.text();
    assert_eq!(text.matches("no sink registered").count(), 1, "缺装配告警应恰一行: {text}");
    assert!(!text.contains("unregistered emit"), "消息本体仍须静默: {text}");
    assert_eq!(xray_common::log::channels().dropped_total(), 0, "未注册 emit 不计丢弃");
}
