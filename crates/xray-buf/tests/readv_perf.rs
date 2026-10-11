//! ReadV perf microbench: Real Windows listen+dup socket exercise.
//!
//! 复刻 bridge_link_with_stream_full 真实路径（dup 读腿走 ReadVSource::Whole）：
//! - readv=ON:  dup'd socket → ReadVReader 全 8 缓冲聚合读
//! - readv=OFF: dup'd socket → SingleReader 8KB 单缓冲顺序读
//!
//! A/B 同进程同 listener 仅切换 reader，对比 5MB 接收耗时。
//!
//! shortcut: 仅诊断 post-fix 验证用，无外部 API 暴露。

#![cfg(windows)]
// 测试编译单元统一豁免（数据面分配纪律见 crate clippy.toml）
#![allow(clippy::disallowed_methods)]

use std::{
    os::windows::io::{AsRawSocket, FromRawSocket},
    sync::Arc,
    time::Instant,
};

use tokio::{io::AsyncWriteExt, net::TcpListener};
use xray_buf::{
    io::{Reader, new_reader, new_readv_reader_whole},
    readv::{reload_env_settings, use_readv},
};

const PAYLOAD_LEN: usize = 5 * 1024 * 1024; // 5MB

fn make_payload(seed: u8) -> Vec<u8> {
    let mut v = vec![0u8; PAYLOAD_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = ((seed as usize + i) % 251) as u8;
    }
    v
}

async fn run_pipe(reader: &mut (dyn Reader + '_), payload_len: usize) -> usize {
    let mut got = 0usize;
    while got < payload_len {
        let mb = xray_buf::io::read_mb(reader).await.unwrap();
        if mb.is_empty() {
            break;
        }
        let n = mb.to_vec();
        got += n.len();
    }
    got
}

async fn bench_readv(use_readv_flag: bool) -> std::time::Duration {
    unsafe { std::env::set_var("xray.buf.readv", if use_readv_flag { "auto" } else { "disable" }) };
    reload_env_settings();
    assert_eq!(use_readv(), use_readv_flag, "env 闸门生效确认");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let payload = Arc::new(make_payload(7));

    let writer = tokio::spawn({
        let payload = Arc::clone(&payload);
        async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.set_nodelay(true).ok();
            let mut remaining: &[u8] = &payload;
            while !remaining.is_empty() {
                let n = s.write(remaining).await.unwrap();
                remaining = &remaining[n..];
            }
            s.shutdown().await.ok();
        }
    });

    let (server_stream, _peer) = listener.accept().await.unwrap();

    let raw = server_stream.as_raw_socket();
    let view = std::mem::ManuallyDrop::new(unsafe { std::net::TcpStream::from_raw_socket(raw) });
    let dup_stream = view.try_clone().unwrap();
    let tokio_dup = tokio::net::TcpStream::from_std(dup_stream).unwrap();

    let start = Instant::now();
    let mut reader: Box<dyn Reader> = if use_readv_flag {
        new_readv_reader_whole(tokio_dup)
    } else {
        let (rh, _wh) = tokio::io::split(tokio_dup);
        new_reader(rh)
    };
    let got = run_pipe(reader.as_mut(), PAYLOAD_LEN).await;
    let elapsed = start.elapsed();

    writer.await.unwrap();
    assert_eq!(got, PAYLOAD_LEN, "字节守恒 readv={use_readv_flag}");
    drop(server_stream);
    elapsed
}

#[tokio::test(flavor = "current_thread")]
async fn readv_whole_vs_single_5mb_throughput() {
    // 4 轮 A/B（暖身第一轮丢掉）。
    let mut samples: Vec<(bool, std::time::Duration)> = Vec::new();
    for _ in 0..4 {
        samples.push((true, bench_readv(true).await));
        samples.push((false, bench_readv(false).await));
    }
    eprintln!("\n[READV-PERF] ReadVSource::Whole 5MB dup-socket 回环（每轮分别 5MB 流）");
    for (i, (b, d)) in samples.iter().enumerate() {
        let mb_s = PAYLOAD_LEN as f64 / 1e6 / d.as_secs_f64();
        eprintln!("  #{} readv={:5}  dur={:?}  throughput={:.1} MB/s", i, *b, d, mb_s);
    }
    // 跳过第一轮 ON/OFF（暖身），余下 3 轮平均。
    let on: Vec<_> = samples.iter().skip(2).filter(|(b, _)| *b).map(|(_, d)| *d).collect();
    let off: Vec<_> = samples.iter().skip(2).filter(|(b, _)| !*b).map(|(_, d)| *d).collect();
    let on_avg = on.iter().sum::<std::time::Duration>() / on.len() as u32;
    let off_avg = off.iter().sum::<std::time::Duration>() / off.len() as u32;
    let on_mb_s = PAYLOAD_LEN as f64 / 1e6 / on_avg.as_secs_f64();
    let off_mb_s = PAYLOAD_LEN as f64 / 1e6 / off_avg.as_secs_f64();
    eprintln!(
        "  → ON  平均 {:?}  ({:.1} MB/s)  |  OFF 平均 {:?}  ({:.1} MB/s)  |  gap={:+.1}%",
        on_avg,
        on_mb_s,
        off_avg,
        off_mb_s,
        (off_mb_s - on_mb_s) / on_mb_s * 100.0,
    );
}
