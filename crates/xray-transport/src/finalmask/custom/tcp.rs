//! # TCP 自定义序列引擎（对应 Go `finalmask/header/custom/tcp.go`）
//!
//! 客户端/服务端各自持有一组 `TCPSequence`：握手期按顺序 write/read，
//! 完成后进入双 task 双向透传。失败时丢弃 pipe（client EOF）。

use std::{sync::Arc, time::Duration};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{
    TCPConfig, TCPItem, TCPSequence,
    evaluator::{EvalContext, evaluate_expr, evaluate_item_fields, measure_item, sizes_from_vars},
    state::StateStore,
};

/// 写一组 TCP item：按 delay_max 分段 flush，求值累加 → write_all。
///
/// 返回 false 表示底层写失败或求值出错；调用方应终止握手。
async fn write_sequence<W: AsyncWrite + Unpin>(
    w: &mut W,
    sequence: &TCPSequence,
    ctx: &mut EvalContext,
) -> bool {
    let mut merged: Vec<u8> = Vec::new();
    for item in &sequence.sequence {
        if item.delay_max > 0 {
            if !merged.is_empty() {
                if w.write_all(&merged).await.is_err() {
                    return false;
                }
                merged.clear();
            }
            let delay_ms = rand_between_i64(item.delay_min, item.delay_max).max(0) as u64;
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        match evaluate_item_fields(
            item.rand,
            item.rand_min,
            item.rand_max,
            &item.packet,
            &item.save,
            &item.var,
            item.expr.as_ref(),
            ctx,
        ) {
            Ok(v) => merged.extend_from_slice(&v),
            Err(_) => return false,
        }
    }
    if !merged.is_empty() && w.write_all(&merged).await.is_err() {
        return false;
    }
    true
}

/// 读并匹配一组 TCP item：每项先 measure 出长度，再 read_exact，按
/// rand/packet/var/expr 优先级校验 segment 一致性。
async fn read_sequence<R: AsyncRead + Unpin>(
    r: &mut R,
    sequence: &TCPSequence,
    ctx: &mut EvalContext,
) -> bool {
    for item in &sequence.sequence {
        let mut sizes = sizes_from_vars(&ctx.vars);
        let length = match measure_item(
            item.rand,
            &item.packet,
            &item.save,
            &item.var,
            item.expr.as_ref(),
            &mut sizes,
        ) {
            Ok(l) => l,
            Err(_) => return false,
        };
        let mut buf = vec![0u8; length];
        if r.read_exact(&mut buf).await.is_err() {
            return false;
        }
        if !match_item_segment(item, &buf, ctx) {
            return false;
        }
        if !item.save.is_empty() {
            ctx.vars.insert(item.save.clone(), buf);
        }
    }
    true
}

/// 按 rand/packet/var/expr 优先级校验 segment 是否符合 item 模式。
fn match_item_segment(item: &TCPItem, segment: &[u8], ctx: &mut EvalContext) -> bool {
    if item.rand > 0 {
        true
    } else if !item.packet.is_empty() {
        item.packet == segment
    } else if !item.var.is_empty() {
        matches!(ctx.vars.get(&item.var), Some(saved) if saved == segment)
    } else if let Some(expr) = &item.expr {
        match evaluate_expr(expr, ctx) {
            Ok(v) => matches!(v.as_bytes(), Ok(expected) if expected == segment),
            Err(_) => false,
        }
    } else {
        true
    }
}

/// 客户端握手：先写 clients[i]，再读 servers[j]；剩余 servers 读完后返回。
async fn client_handshake<RW>(raw: &mut RW, config: &TCPConfig, ctx: &mut EvalContext) -> bool
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    let mut j = 0;
    for i in 0..config.clients.len() {
        if !write_sequence(raw, &config.clients[i], ctx).await {
            return false;
        }
        if j < config.servers.len() {
            if !read_sequence(raw, &config.servers[j], ctx).await {
                return false;
            }
            j += 1;
        }
    }
    while j < config.servers.len() {
        if !read_sequence(raw, &config.servers[j], ctx).await {
            return false;
        }
        j += 1;
    }
    true
}

/// 服务端握手：先读 clients[i]，失败时写 errors[i]；成功则写 servers[j]。
async fn server_handshake<RW>(raw: &mut RW, config: &TCPConfig, ctx: &mut EvalContext) -> bool
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    let mut j = 0;
    for i in 0..config.clients.len() {
        if !read_sequence(raw, &config.clients[i], ctx).await {
            if i < config.errors.len() {
                let _ = write_sequence(raw, &config.errors[i], ctx).await;
            }
            return false;
        }
        if j < config.servers.len() {
            if !write_sequence(raw, &config.servers[j], ctx).await {
                return false;
            }
            j += 1;
        }
    }
    while j < config.servers.len() {
        if !write_sequence(raw, &config.servers[j], ctx).await {
            return false;
        }
        j += 1;
    }
    true
}

/// TCP bridge：先握手，成功后双 task 双向 pipe raw ↔ pipe。
pub(super) async fn bridge(
    mut raw: Box<dyn super::super::AsyncIo>,
    pipe: tokio::io::DuplexStream,
    is_client: bool,
    config: TCPConfig,
    state: Arc<StateStore>,
) {
    let mut ctx = EvalContext::new();
    if let Some(initial) = state.get("") {
        ctx.vars = initial;
    }

    let ok = if is_client {
        client_handshake(&mut raw, &config, &mut ctx).await
    } else {
        server_handshake(&mut raw, &config, &mut ctx).await
    };
    if !ok {
        return;
    }
    state.set("", &ctx.vars);

    let (mut r, mut w) = tokio::io::split(raw);
    let (mut pipe_r, mut pipe_w) = tokio::io::split(pipe);
    // 两个方向各自跑在自己的 task 里：对端不读 pipe 时只有回程（raw→pipe）阻塞，
    // 不传染写方向（bd hjkf：单 task `select!` + 分支体内 await 会整体饿死写方向）。
    #[allow(
        clippy::disallowed_methods,
        reason = "数据面泵任务（raw↔pipe 回程拷贝）；显式脱管：托管无收益（本层无 PluginContext 可穿），寿命随其所属连接/会话/进程对象，句柄无需持有（bd hj3jf 裁定）"
    )]
    let back = tokio::spawn(async move {
        // 读侧结束/出错 → 关掉 pipe 写侧，让对端读到 EOF（错误按流结束传播）。
        let _ = tokio::io::copy(&mut r, &mut pipe_w).await;
        let _ = pipe_w.shutdown().await;
    });
    let mut write_buf = vec![0u8; super::super::UDP_SIZE];
    loop {
        match pipe_r.read(&mut write_buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if w.write_all(&write_buf[..n]).await.is_err() {
                    break;
                }
            },
        }
    }
    let _ = w.shutdown().await;
    // 写侧结束后不再有回程数据可交（与旧单 task 版 break 即整体关闭的语义一致）。
    // shortcut: 不支持 app 半关后继续读回程（上层从不半关）；真有需求时把 abort
    // 换成 `let _ = back.await`。
    back.abort();
}

/// 闭区间随机 i64（对应 Go `crypto.RandBetween`）；max<=min 时返回 min。
fn rand_between_i64(min: i64, max: i64) -> i64 {
    if max <= min {
        return min;
    }
    use rand::Rng;
    rand::rng().random_range(min..=max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalmask::{AsyncIo, Tcpmask};

    fn item_packet(packet: &[u8]) -> TCPItem {
        TCPItem {
            delay_min: 0,
            delay_max: 0,
            rand: 0,
            rand_min: 0,
            rand_max: 0,
            packet: packet.to_vec(),
            save: String::new(),
            var: String::new(),
            expr: None,
        }
    }

    fn seq(items: Vec<TCPItem>) -> TCPSequence {
        TCPSequence { sequence: items }
    }

    /// 端到端：client 写 "PING"，server 读后写 "PONG"，client 读 "PONG"，
    /// 然后透传应用数据。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_server_handshake_then_pipe() {
        let cfg = super::super::Config {
            tcp: Some(TCPConfig {
                clients: vec![seq(vec![item_packet(b"PING")])],
                servers: vec![seq(vec![item_packet(b"PONG")])],
                errors: vec![],
            }),
            udp: None,
            udp_standalone: None,
            state_ttl: Duration::from_secs(5),
        };

        let (client_raw, server_raw) = tokio::io::duplex(crate::finalmask::UDP_SIZE * 4);
        let wrapped_client: Box<dyn AsyncIo> = cfg.wrap_conn_client(Box::new(client_raw)).unwrap();
        let wrapped_server: Box<dyn AsyncIo> = cfg.wrap_conn_server(Box::new(server_raw)).unwrap();

        use tokio::io::split;
        let (_cr, mut cw) = split(wrapped_client);
        let (mut sr, _sw) = split(wrapped_server);

        let msg = b"hello custom tcp";
        let write_fut = async {
            cw.write_all(msg).await.unwrap();
            cw.shutdown().await.ok();
        };
        let read_fut = async {
            let mut got = Vec::new();
            sr.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, msg);
        };
        tokio::join!(write_fut, read_fut);
    }

    /// 无 items（透明透传）——握手立即完成。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn empty_config_passes_through() {
        let cfg = super::super::Config {
            tcp: Some(TCPConfig::default()),
            udp: None,
            udp_standalone: None,
            state_ttl: Duration::from_secs(5),
        };

        let (client_raw, server_raw) = tokio::io::duplex(crate::finalmask::UDP_SIZE * 4);
        let wrapped_client: Box<dyn AsyncIo> = cfg.wrap_conn_client(Box::new(client_raw)).unwrap();
        let wrapped_server: Box<dyn AsyncIo> = cfg.wrap_conn_server(Box::new(server_raw)).unwrap();

        use tokio::io::split;
        let (_cr, mut cw) = split(wrapped_client);
        let (mut sr, _sw) = split(wrapped_server);

        let msg = b"transparent";
        let write_fut = async {
            cw.write_all(msg).await.unwrap();
            cw.shutdown().await.ok();
        };
        let read_fut = async {
            let mut got = Vec::new();
            sr.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, msg);
        };
        tokio::join!(write_fut, read_fut);
    }

    /// 写方向饿死回归（bd hjkf）：完整握手后进入数据面，对端 echo 在 app 不读期间
    /// 只能堆积在 pipe 里。单 task `select!` + 分支体内 `await` 会让 inner→pipe 的
    /// 阻塞传染写方向（app 写满 8 KiB pipe 后彻底停摆）。
    ///
    /// inner 用 1 MiB duplex 模拟真实 TCP 内核收发缓冲，app 侧 pipe 保持生产容量
    /// （`UDP_SIZE * 2` = 8 KiB）——唯一的人工窄口。阶梯 16K/64K/256K/512K。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_keeps_draining_write_side_while_echo_unread() {
        for &size in &[16 * 1024usize, 64 * 1024, 256 * 1024, 512 * 1024] {
            let cfg = super::super::Config {
                tcp: Some(TCPConfig::default()),
                udp: None,
                udp_standalone: None,
                state_ttl: Duration::from_secs(5),
            };
            let (client_raw, mut peer) = tokio::io::duplex(1 << 20);
            let mut app = cfg.wrap_conn_client(Box::new(client_raw)).unwrap();
            #[allow(clippy::disallowed_methods, reason = "测试：tcpmask echo 任务")]
            let echo = tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                loop {
                    match peer.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if peer.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        },
                    }
                }
            });

            let payload: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
            // 1) 只写不读：写方向不得因回程积压停摆。
            tokio::time::timeout(Duration::from_secs(5), app.write_all(&payload))
                .await
                .unwrap_or_else(|_| {
                    panic!("{size}B: write side starved while echo unread (head-of-line blocking)")
                })
                .expect("write ok");
            // 2) 开始读：echo 必须逐字节回齐。
            let mut got = vec![0u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(5), app.read_exact(&mut got))
                .await
                .unwrap_or_else(|_| panic!("{size}B: echo stalled after write"))
                .expect("echo read ok");
            assert_eq!(got, payload, "{size}B: echo corrupted");
            drop(app);
            let _ = echo.await;
        }
    }

    #[test]
    fn rand_between_clamps_when_max_le_min() {
        assert_eq!(rand_between_i64(5, 5), 5);
        assert_eq!(rand_between_i64(10, 3), 10);
    }

    #[test]
    fn rand_between_returns_inclusive() {
        for _ in 0..100 {
            let v = rand_between_i64(1, 10);
            assert!((1..=10).contains(&v));
        }
    }

    #[test]
    fn match_segment_packet_compares_literally() {
        let item = item_packet(b"abc");
        let mut ctx = EvalContext::new();
        assert!(match_item_segment(&item, b"abc", &mut ctx));
        assert!(!match_item_segment(&item, b"abd", &mut ctx));
    }
}
