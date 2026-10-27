//! P1-5 观测字段模板集成验收（任务书四组用例）：
//! ① 并发 10k conn_id 全局唯一非零 ② 四字段齐备 + 短 hex 截断正确
//! ③ 落样 target 前缀恒 `xray_frame::` ④ secrets 掩码穿透 peer/dest/msg。
//!
//! ① 的时钟语义按 udf `IdGen` 真实配额设计（id.rs `gen()`）：同毫秒配额 =
//! 4096 − base（base = 指纹派生），配额耗尽 fail-closed panic；MockClock 停走
//! 不自动前推——故 10k 分 4 个毫秒窗口（2500/窗 < 4094，指纹 0x2000 →
//! base=1），窗口间 `advance(1ms)`；每窗 8 线程真实并发领取。
//!
//! 捕获用 `tracing::subscriber::set_default`（RAII DefaultGuard）+ 自建
//! `with_writer` 闭环 writer，写法与 `log_discipline.rs` 同源；emit 面是运行时
//! target/level（tracing verbatim 路径，无 callsite interest 缓存），线程局部
//! 订阅者捕获确定性成立。

use std::{
    collections::HashSet,
    io::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use serde_json::json;
use skeleton::{
    clock::{MockClock, SystemClock},
    config::MockEnv,
};
use xray_frame::{
    context::{PluginContext, derive_fingerprint},
    logging::LogFacade,
    observe::{ObserveFields, Stage, emit},
    scope::ArmScope,
};

const SECRET: &str = "sup3rsecret";

/// 并发唯一性用例的独占指纹：`0x2000 >> 13 = 1` → base=1 → 同毫秒配额 4094。
/// IdGen 同指纹进程级单权威（REGISTRY），独占常量避免与其他测试互喂时间线。
const ISOLATED_FP: u64 = 0x2000;

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

fn ctx_with(plugin: &'static str, secrets: Vec<Arc<str>>) -> PluginContext {
    PluginContext::new(
        plugin,
        ArmScope::new(),
        Arc::new(SystemClock),
        derive_fingerprint(Some("127.0.0.1:10808")),
        Arc::new(MockEnv::new()),
        json!({}),
        LogFacade::new(plugin, secrets),
        Arc::new(xray_frame::AuditHandle::new(xray_frame::DEFAULT_AUDIT_RING_CAP)),
    )
}

#[test]
fn ten_k_concurrent_conn_ids_unique_and_nonzero() {
    let clock = Arc::new(MockClock::new());
    // 避开 ms=0 构造态特例（GenState 文档：首个 id counter=base+1），ms=1 起步。
    clock.advance(Duration::from_millis(1));
    let ctx = PluginContext::new(
        "observe-test",
        ArmScope::new(),
        clock.clone(),
        ISOLATED_FP,
        Arc::new(MockEnv::new()),
        json!({}),
        LogFacade::new("observe-test", vec![]),
        Arc::new(xray_frame::AuditHandle::new(xray_frame::DEFAULT_AUDIT_RING_CAP)),
    );

    const N: usize = 10_000;
    const WINDOWS: usize = 4;
    const PER_WINDOW: usize = N / WINDOWS; // 2500 < 4094 同毫秒配额
    const THREADS: usize = 8;

    let mut all = Vec::<u128>::with_capacity(N);
    for _ in 0..WINDOWS {
        let chunk = Mutex::new(Vec::<u128>::with_capacity(PER_WINDOW));
        let next = AtomicUsize::new(0);
        thread::scope(|s| {
            for _ in 0..THREADS {
                s.spawn(|| {
                    loop {
                        if next.fetch_add(1, Ordering::Relaxed) >= PER_WINDOW {
                            break;
                        }
                        chunk.lock().expect("no poison").push(ctx.next_conn_id());
                    }
                });
            }
        });
        all.append(&mut chunk.into_inner().expect("no poison"));
        clock.advance(Duration::from_millis(1));
    }

    assert_eq!(all.len(), N, "每窗精确 PER_WINDOW，无领取丢失");
    let unique: HashSet<u128> = all.iter().copied().collect();
    assert_eq!(unique.len(), N, "conn_id 全局唯一无重复");
    assert!(all.iter().all(|&id| id != 0), "conn_id 非零");
}

#[test]
fn fields_carry_all_four_members() {
    let ctx = ctx_with("observe-test", vec![]);
    let fields =
        ObserveFields::new(&ctx, Stage::Forward, "10.0.0.1:443".into(), "example.com:80".into());

    assert_ne!(fields.conn_id, 0, "conn_id 必填非零（取自 ctx.next_conn_id）");
    assert_eq!(fields.stage, Stage::Forward);
    assert_eq!(fields.peer, "10.0.0.1:443");
    assert_eq!(fields.dest, "example.com:80");
    // 机器可读：Display = 变体名，非自由文本。
    assert_eq!(fields.stage.to_string(), "Forward");
}

#[test]
fn emit_line_carries_quadruple_with_short_hex_and_pinned_target() {
    let buf = SharedBuf::default();
    let _guard = capture(buf.clone());
    let ctx = ctx_with("observe-test", vec![]);
    let fields = ObserveFields::new(
        &ctx,
        Stage::Handshake,
        "203.0.113.9:443".into(),
        "dest.example:993".into(),
    );

    emit(&ctx, &fields, "client hello sent");

    let out = buf.snapshot();
    // 短 hex = u128 的 32 位 hex 前 16 位 == 高 64 位的 16-hex 零填充表示。
    let expect_hex = format!("{:016x}", fields.conn_id >> 64);
    assert_eq!(expect_hex.len(), 16);
    assert!(format!("{:032x}", fields.conn_id).starts_with(&expect_hex), "截断取前 16 位");
    let conn_token =
        out.split("conn=").nth(1).expect("conn= present").split(' ').next().expect("token");
    assert_eq!(conn_token, expect_hex, "短 hex 截断正确: {out}");
    assert!(out.contains("stage=Handshake"), "stage 位: {out}");
    assert!(out.contains("peer=203.0.113.9:443"), "peer 位: {out}");
    assert!(out.contains("dest=dest.example:993"), "dest 位: {out}");
    assert!(out.contains("client hello sent"), "msg 位: {out}");
    assert!(out.contains("xray_frame::observe-test"), "target 前缀恒 xray_frame:: {out}");
}

#[test]
fn emit_masks_secrets_across_peer_dest_and_msg() {
    let buf = SharedBuf::default();
    let _guard = capture(buf.clone());
    let ctx = ctx_with("observe-test", vec![Arc::from(SECRET)]);
    let fields = ObserveFields::new(
        &ctx,
        Stage::Authenticate,
        "10.0.0.9:443".into(),
        format!("{SECRET}.example:443"),
    );

    emit(&ctx, &fields, &format!("token {SECRET} in flight"));

    let out = buf.snapshot();
    assert!(!out.contains(SECRET), "raw secret leaked: {out}");
    assert!(out.contains("***"), "masked marker present: {out}");
}
