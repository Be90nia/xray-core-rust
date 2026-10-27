# uds-spawn-batch — inbound.rs `cfg(unix)` 6 处裸 spawn → FxScope 托管

VERDICT: PASS

f17zu 收尾批次：`crates/xray-core/src/inbound.rs` UDS ×5 + `handle_connection` UDP associate ×1 迁 arm PluginContext（`FxScope` 托管），对齐 batch1（bd 39hko，13 处）已建形态。

## 迁移表

| 迁前行号 | 迁后行号 | 路径 | scope 归属 | 处置 |
|---|---|---|---|---|
| 396 | 397-405 | `handle_connection` SOCKS5 UDP associate relay pump | 每连接（TCP/UDS 泛型共用；`serve_socks5`/UDS socks 臂传入） | 迁：`plugin_ctx.spawn` + `_ctx` 锚；`Spawned::abort()` 保留「TCP 控制连接断开即终止 relay」语义（`skeleton-infra/src/fx.rs:368`） |
| 4227 | 4246-4268 | `spawn_unix_inbound` socks 臂 on_conn | arm scope（`arm_plugin_ctx(ib.entry.kind)`，与函数头 L4169 构造同源） | 迁 |
| 4267 | 4289-4315 | `spawn_unix_inbound` vless 臂 on_conn | 同上 | 迁；`build_vless_decryption` 改传 `plugin_ctx.clone()`（原按值消费，留本尊给闭包） |
| 4306 | 4332-4350 | `spawn_unix_inbound` vmess 臂 on_conn | 同上 | 迁 |
| 4343 | 4374-4393 | `spawn_unix_inbound` trojan 臂 on_conn | 同上 | 迁 |
| 4378 | 4414-4421 | `spawn_unix_inbound` shadowsocks 臂 on_conn | 同上 | 迁 |

统一形态（与 batch1/dns/serve_socks5 同款）：闭包内每调用克隆 `task_ctx` 锚入 future（`let _ctx = task_ctx;`），spawn 于 `plugin_ctx`，`.expect("arm FxScope is never closed")`。

## 保留清单及理由（宁少不错：0 处判不清，全部非目标红线）

| 位置 | 归属 | 不迁理由 |
|---|---|---|
| 460/716/783/886 | mux link ×4 | 契约 Non-goals：不碰 mux link |
| 1980 | SS 数据面泵 ×1 | 契约 Non-goals：不碰 SS 泵 |
| 3210/3215 | 监控壳 ×2（`spawn_inbound_serve` 监控包裹） | Non-goals |
| 3603/3794 | reality vision ×2 | Non-goals：不碰 vision |
| 4022 | tun ×1 | Non-goals |
| tests ×52 | 测试面 | 按既定口径不迁 |

## 文件顶 allow reason（最终原文，实测口径）

```
// L3 静态闸存量登记（bd a5r4j/lzzja 切片；batch2 后实盘 2026-10-27）：本文件
// 67 处（62 tokio::spawn：生产 10 + tests 52；5 std Instant 调用位，另有 5 处
// Instant 类型位置不计）>20 → 按分层规则挂文件级。生产 10 = mux link 4 +
// SS 数据面泵 1 + 监控壳 2 + reality vision 2 + tun 1；
// batch1 已迁 13 处 + batch2 已迁 6 处（UDP associate + UDS 每连接 5）生产
// spawn → arm PluginContext（bd 39hko）。
#![allow(
    clippy::disallowed_methods,
    reason = "inbound.rs 存量 67 处（62 tokio::spawn：生产 10 + tests 52；5 std Instant 调用位），>20 处/文件按分层规则挂文件级，迁移收口见 bd 39hko"
)]
```

机器核实（python 计数，非目测）：`tokio::spawn(` 调用 62 = 生产 10（mux×4@460/716/783/886 + SS 泵@1980 + 监控壳×2@3210/3215 + vision×2@3603/3794 + tun@4022）+ tests 52；`std::time::Instant::now()` 调用位 5 = 生产 1（:2453）+ tests 4（:6661/9357/9795/9838）；Instant 类型位 5（:2283/2285/2438/6662/6677）不计。62+5=67 与注释一致。

## 验收证据（实跑尾部）

### 1. Linux 床基线（改动前）

```
$ BORING_BSSL_ASSUME_PATCHED=1 BORING_BSSL_SOURCE_PATH=/root/boringssl-patched \
  CARGO_TARGET_DIR=/root/target-linux cargo check -p xray-core --all-targets
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 02s
```

⚠️ 基线先撞 btls 缓存债：不带 env 首跑 `xray-tls` 报 `SSL_send_post_handshake_record`/`SSL_seal_raw_tls13_record` not found in `btls_sys`（E0425）——`/root/target-linux/debug/build/btls-sys-*` 4 个缓存目录中 2 个 bindings 过旧、2 个 out 空目录（§5 已知「build.rs:646 静默早退」形态）。处置：清 4 个 btls-sys 构建缓存目录（可再生构建缓存）+ 带文档 env 重跑，bindgen 从 `/root/boringssl-patched`（实测含两符号，ssl.h count=2）重生成后绿。

### 2. Linux `cargo check --workspace --all-targets` → 0 error

```
    Checking xray-stress v0.1.0 (/mnt/d/Project/Xray-core-rust/crates/xray-stress)
    Checking xray-integration-tests v0.1.0 (/mnt/d/Project/Xray-core-rust/crates/../tests)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 04s
```

### 3. Linux `cargo clippy --workspace --all-targets -- -D warnings` → 0 error

```
    Checking xray-cli v0.1.0 (/mnt/d/Project/Xray-core-rust/crates/xray-cli)
    Checking xray-stress v0.1.0 (/mnt/d/Project/Xray-core-rust/crates/xray-stress)
    Checking xray-integration-tests v0.1.0 (/mnt/d/Project/Xray-core-rust/crates/../tests)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 07s
```

（退出码经 `PIPESTATUS` 保留；首次假失败见「过程修正 2」）

### 4. Linux `cargo test -p xray-core --all-targets` → 0 failed

```
running 484 tests
test feature_framework::tests::failed_start_rolls_back_started_features ... ok
test functions::tests::integration_trojan_tls_fallback_routes_failed_handshake ... ok
test instance::tests::close_after_failed_start_still_runs ... ok
test result: ok. 482 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 31.65s
running 1 test
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 1 test
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```

### 5. Windows `cargo check --workspace --all-targets` → 0 error

```
    Checking xray-core v0.1.0 (D:\Project\Xray-core-rust\crates\xray-core)
    Checking xray-cli v0.1.0 (D:\Project\Xray-core-rust\crates\xray-cli)
    Checking xray-stress v0.1.0 (D:\Project\Xray-core-rust\crates\xray-stress)
    Checking xray-integration-tests v0.1.0 (D:\Project\Xray-core-rust\tests)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 44.04s
```

（env：`BORING_BSSL_ASSUME_PATCHED=1 BORING_BSSL_SOURCE_PATH=D:/Project/Xray-core-rust/target/boringssl-patched PROTOC=D:/Project/tools/bin/protoc.exe LIBCLANG_PATH=D:\Program Files\llvm\bin`）

### 6. `cargo fmt -p xray-core -- --check` → 零 diff

```
$ cargo fmt -p xray-core -- --check && echo FMT_CLEAN
FMT_CLEAN
```

## 过程修正（如实记录）

1. 首版 socks 臂在 async move 块内 `Arc::clone(&plugin_ctx)` → E0507（async move 试图把 Fn 闭包捕获的 `plugin_ctx` move 出去）。修：闭包内先克隆局部 `conn_ctx` 传参，块只捕获局部变量。
2. workspace clippy 首跑报 `xray-proxy-dns (lib test)` 失败；单跑 `cargo clippy -p xray-proxy-dns --all-targets` 16s 零错误 → 判定为并发/管道退出码假失败（原命令 `2>&1 | tail` 吞了 PIPESTATUS），复跑全仓 clippy 取真实退出码（见 §3）。

## 未验证 / 残留

- e2e UDS 连接级行为未跑真实 UDS 客户端往返（`cargo test -p xray-core` 内含 `unix_socket_socks_inbound_e2e` 等 cfg(unix) e2e，484 全绿已覆盖该路径；Windows 侧 UDS 面编译不可达为平台事实，Windows 仅 check 验收）。
- `/root/target-linux` 的 btls 缓存已按文档 env 重建；后续 Linux 床使用者必须带 `BORING_BSSL_ASSUME_PATCHED=1 BORING_BSSL_SOURCE_PATH=/root/boringssl-patched`（与本仓 CLAUDE.md §1 Windows 形态同构）。
