//! accept 循环错误策略（共享助手）。
//!
//! 样板来源：grpc `transport.rs` 的 kind 分级 Err 分支 + xray-core `inbound.rs`
//! 的 `accept_fd_backoff`（大小写不敏感 "too many"）。四个铁律（443 静默死亡战役，
//! bd 工单见 reports/fix-accept-loop-death-20261023.md）：
//!
//! 1. **退出条件只有显式 close**（close_notify / abort 句柄 / endpoint `None`）。
//!    任何错误——尤其错误文本含 "closed" 的单连接级错误（rustls `PeerClosed`、 tungstenite
//!    `ConnectionClosed`、tungstenite `AlreadyClosed`）——永不作为退出
//!    条件（生产实证：26.10.10/26.10.11 上 443 监听因此静默消失，日志零线索）。
//! 2. **错误分级**：资源/瞬时类（EMFILE/ENFILE/EAGAIN/ENOMEM/EINTR）→ `warn` + 退避 500ms +
//!    继续；单连接级（握手失败、对端中途断开）→ `debug` + 继续； 其它未知 → `warn`
//!    （同文本连续重复降 `debug`，见 [`repeat_hint`]）+ 退避 500ms + 继续。
//! 3. **循环意外退出（非显式 close）必须 `error!` 留痕**，含 tag、local 与最后 错误（"发现 443
//!    跪了就写日志"）。
//! 4. 文本兜底匹配**大小写不敏感**（glibc 是 "Too many open files"，小写匹配 永不命中）。

use std::{future::Future, io, time::Duration};

use skeleton_infra::fx::TaskError;

/// 资源/瞬时类与未知类退避时长（与 xray-core `accept_fd_backoff` 的 500ms 一致）。
const BACKOFF: Duration = Duration::from_millis(500);

/// accept 错误分类（决定日志级别与是否退避；不含退出——退出只来自显式 close）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptErrorKind {
    /// 资源/瞬时类：`warn` + 退避 500ms + 继续（无条件 continue 会构成忙旋）。
    Resource,
    /// 单连接级：`debug` + 继续（避免扫描器/半开连接刷屏）。
    Connection,
    /// 其它未知：`warn` + 继续。
    Unknown,
}

/// 纯函数分类。
///
/// kind 可判则用 kind（`ProcessFdQuotaExceeded`/`SystemFdQuotaExceeded` 仍属
/// unstable io_error_more，EMFILE/ENFILE 多数落不进 kind 白名单）→ 大小写不敏感
/// "too many" 文本兜底；其余归 Unknown（warn + 继续，永不退出）。
pub fn classify(e: &io::Error) -> AcceptErrorKind {
    match e.kind() {
        // 单连接级：连接在 accept/首读阶段被客户端中止、重置或中途断开
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::TimedOut => AcceptErrorKind::Connection,
        // 资源/瞬时类（kind 集合与 grpc transport.rs 样板一致并补齐 EAGAIN/EINTR）
        io::ErrorKind::OutOfMemory
        | io::ErrorKind::ResourceBusy
        | io::ErrorKind::WouldBlock
        | io::ErrorKind::Interrupted => AcceptErrorKind::Resource,
        _ => {
            if e.to_string().to_lowercase().contains("too many") {
                AcceptErrorKind::Resource
            } else {
                AcceptErrorKind::Unknown
            }
        },
    }
}

/// 非单连接级错误退避 500ms 后返回；单连接级错误（握手失败 / 对端断开）立即返回
/// （循环 continue 前调用）。
///
/// `Unknown` 也退避（A3，audit 2026-11-15）：未知错误原样 continue 会构成忙旋 +
/// warn 洪水；退避不改变「永不退出」铁律，只把循环节奏压到 2 次/秒。
pub async fn backoff_if_not_connection(e: &io::Error) {
    if !matches!(classify(e), AcceptErrorKind::Connection) {
        tokio::time::sleep(BACKOFF).await;
    }
}

/// 同错误文本连续重复的采样（A3 warn 限频）：首现 / 换文本 → `None`（应 `warn`）；
/// 连续重复 → `Some(累计次数)`（应降 `debug`，带计数）。
///
/// `Resource` 类恒 `None`：EMFILE/ENFILE 的可见性不得被降级（既有路径不变）。
pub fn repeat_hint(e: &io::Error) -> Option<u64> {
    use std::sync::Mutex;
    static REPEAT: Mutex<Option<(String, u64)>> = Mutex::new(None);
    if matches!(classify(e), AcceptErrorKind::Resource) {
        return None;
    }
    let text = e.to_string();
    let mut slot = REPEAT.lock().unwrap_or_else(|poison| poison.into_inner());
    match slot.as_mut() {
        Some((last, n)) if *last == text => {
            *n = n.saturating_add(1);
            Some(*n)
        },
        _ => {
            *slot = Some((text, 1));
            None
        },
    }
}

/// accept 循环终局归一：panic 终局给摘要文本，显式 close/取消终局给 `None`。
/// sealed 面：仅 [`tokio::task::JoinError`] 与 `skeleton_infra::fx::TaskError`
/// 两种句柄错误实现，勿外增（443 铁律 3 的分类口径住在这里，只留一处）。
pub trait AcceptLoopExit {
    fn panic_detail(self) -> Option<String>;
}

impl AcceptLoopExit for tokio::task::JoinError {
    fn panic_detail(self) -> Option<String> {
        if self.is_panic() { Some(panic_brief(self.into_panic())) } else { None }
    }
}

impl AcceptLoopExit for TaskError {
    fn panic_detail(self) -> Option<String> {
        match self {
            TaskError::Panicked(detail) => Some(detail),
            _ => None,
        }
    }
}

/// 循环意外退出监控：await accept 循环句柄的终局，仅在 panic（非显式 close 的
/// 唯一退出途径）时 `error!` 留痕；显式 close（close_notify / abort → cancelled /
/// endpoint 关闭）不打日志。句柄两吃：[`tokio::task::JoinHandle`]（JoinError）
/// 或 FxScope 托管的 `Spawned::join()`（TaskError）——分类见 [`AcceptLoopExit`]。
///
/// 用法：spawn accept 循环后，把循环句柄（或 `spawned.join()`）move 交给本函数
/// 再 spawn 一个监控 task（句柄不可 Clone——还须向外返回句柄的调用点用「监控
/// 包裹」结构，见 `xray-transport/src/tcp/hub.rs` 的 `TcpHubListener::listen`）。
pub async fn supervise_accept_loop<E: AcceptLoopExit>(
    tag: &str,
    local: String,
    handle: impl Future<Output = Result<(), E>>,
) {
    if let Err(e) = handle.await {
        if let Some(detail) = e.panic_detail() {
            crate::LOG.error(format!(
                "[{tag}] inbound accept loop exited WITHOUT close signal — 监听已停止，该端口不再接受连接 (local: {local}, panic: {detail})"
            ));
        }
    }
}

/// panic payload 摘要（`JoinHandle` panic 时 payload 通常为 `&'static str`/`String`）。
fn panic_brief(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    // ===== classify（断言分类结果，不真实退避拖 CI）=====

    #[test]
    fn single_connection_errors_are_connection_class() {
        for kind in [
            io::ErrorKind::ConnectionAborted, // Linux accept 队列内被中止 ECONNABORTED
            io::ErrorKind::ConnectionReset,   // Windows 握手前重置 WSAECONNRESET
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::TimedOut,
        ] {
            assert_eq!(
                classify(&io::Error::from(kind)),
                AcceptErrorKind::Connection,
                "kind {kind:?} 应为单连接级"
            );
        }
    }

    #[test]
    fn resource_errors_are_resource_class() {
        for kind in [
            io::ErrorKind::OutOfMemory,
            io::ErrorKind::ResourceBusy,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
        ] {
            assert_eq!(
                classify(&io::Error::from(kind)),
                AcceptErrorKind::Resource,
                "kind {kind:?} 应为资源类"
            );
        }
    }

    #[test]
    fn emfile_enfile_detected_regardless_of_text_case() {
        // glibc 文本 "Too many open files" 大写开头——旧 `contains("too many")`
        // 大小写敏感的静默失效由不敏感兜底消除
        assert_eq!(classify(&io::Error::other("Too many open files")), AcceptErrorKind::Resource);
        assert_eq!(classify(&io::Error::other("too many open files")), AcceptErrorKind::Resource);
    }

    #[test]
    fn closed_text_never_maps_to_exit_because_exit_is_not_representable() {
        // "closed" 文本不参与分类：单连接级错误文本（生产杀手）落 Unknown 也只是
        // warn + 继续——AcceptErrorKind 没有"退出"变体，退出只来自显式 close 分支
        assert_eq!(
            classify(&io::Error::other("Connection closed normally")),
            AcceptErrorKind::Unknown
        );
        assert_eq!(
            classify(&io::Error::other("peer closed connection without sending TLS alert")),
            AcceptErrorKind::Unknown
        );
    }

    #[tokio::test]
    async fn backoff_skips_connection_errors_immediately() {
        // 单连接级零 sleep 直达返回（时序断言只排除断言里误入 sleep 路径）
        let start = xray_frame::compat::clock().now_instant();
        backoff_if_not_connection(&io::Error::from(io::ErrorKind::ConnectionReset)).await;
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    /// A3：未知类错误也退避（改前 Unknown 直接 continue ⇒ 忙旋 + warn 洪水）。
    #[tokio::test]
    async fn unknown_error_backs_off_for_500ms() {
        let start = xray_frame::compat::clock().now_instant();
        backoff_if_not_connection(&io::Error::other("synthetic unknown accept error")).await;
        assert!(start.elapsed() >= Duration::from_millis(450), "未知类必须退避 500ms");
    }

    /// A3：同文本连续重复降级；`Resource`（EMFILE）恒不降级。
    #[test]
    fn repeat_hint_demotes_only_non_resource_repeats() {
        let uniq = format!("synthetic unknown accept error {}", std::process::id());
        let e = io::Error::other(uniq);
        assert_eq!(repeat_hint(&e), None, "首现必须 warn");
        assert_eq!(repeat_hint(&e), Some(2), "连续重复降 debug 并计数");
        let emfile = io::Error::other("Too many open files");
        assert_eq!(repeat_hint(&emfile), None, "EMFILE 必须持续 warn（不降级）");
        assert_eq!(repeat_hint(&emfile), None, "EMFILE 重复也不降级");
    }

    // ===== supervise_accept_loop（测试③：意外退出 → error 级日志）=====

    /// 最小 Subscriber：捕获 (级别, message)。xray-transport 无 tracing-subscriber
    /// dev-dep（不动 Cargo.toml），手写捕获足够断言 error 留痕。
    struct CaptureLogs(Arc<Mutex<Vec<String>>>);

    impl tracing::Subscriber for CaptureLogs {
        fn enabled(&self, _meta: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _a: &tracing::span::Id, _b: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            struct MsgVisitor(String);
            impl tracing::field::Visit for MsgVisitor {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    if field.name() == "message" {
                        self.0.push_str(value);
                    }
                }

                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0.push_str(&format!("{value:?}"));
                    }
                }
            }
            let mut v = MsgVisitor(String::new());
            event.record(&mut v);
            let line = format!("{} {}", event.metadata().level(), v.0);
            self.0.lock().unwrap().push(line);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    #[tokio::test]
    async fn supervise_logs_error_with_tag_local_and_last_error_on_panic() {
        let logs = Arc::new(Mutex::new(Vec::new()));
        let _guard = tracing::subscriber::set_default(CaptureLogs(Arc::clone(&logs)));
        #[allow(clippy::disallowed_methods, reason = "测试：panic 任务（supervise 报警验证）")]
        let handle = tokio::spawn(async { panic!("listener fd gone") });
        supervise_accept_loop("test-ws", "127.0.0.1:443".into(), handle).await;

        let got = logs.lock().unwrap();
        assert!(
            got.iter().any(|m| m.contains("ERROR")
                && m.contains("test-ws")
                && m.contains("127.0.0.1:443")
                && m.contains("listener fd gone")
                && m.contains("WITHOUT close signal")),
            "意外退出必须 error 级留痕（含 tag/local/最后错误），实际: {got:?}"
        );
    }

    #[tokio::test]
    async fn supervise_is_silent_on_clean_close() {
        // 显式 close（循环正常结束 / cancelled）不打日志
        let logs = Arc::new(Mutex::new(Vec::new()));
        let _guard = tracing::subscriber::set_default(CaptureLogs(Arc::clone(&logs)));
        #[allow(clippy::disallowed_methods, reason = "测试：正常退出任务（supervise 静默验证）")]
        let handle = tokio::spawn(async {});
        supervise_accept_loop("test-ws", "127.0.0.1:443".into(), handle).await;

        let got = logs.lock().unwrap();
        assert!(got.is_empty(), "显式 close 不得产生日志: {got:?}");
    }
}
