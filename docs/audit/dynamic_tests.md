# 第四轮审计 — 动态验证轮 (dynamic_tests)

> 审计日期: 2026-09-06 | 基线: HEAD `c119dc0` (master, 工作树干净) | 环境: Windows 11 x64, debug profile, cargo 经 `D:\tmp\buildenv.bat`
> 方法: 实际运行测试套件, 以运行结果为证据; 只读审计, 未修改任何源码/测试文件
> Go 基准: D:/Project/Xray-core v26.7.28 (本机未构建 Go xray.exe, 见 P3-1)

## 执行摘要

| 套件 | 命令 | 结果 | 耗时 |
|---|---|---|---|
| A. 全 workspace 单测 | `cargo test --workspace --lib --no-fail-fast` | **52 目标 5557 passed / 0 failed / 4 ignored, 零 panic, 零编译错误** | 任务 455s (含编译 5m57s) |
| B. kcp 全目标 | `cargo test -p xray-transport-kcp -- --test-threads=1` | lib 147/0 全绿; **`tests/mask_roundtrip.rs` 2 个 e2e 全部挂死** (人工强杀) | 挂死 >13 min |
| C. 集成测试 crate | `cargo test -p xray-integration-tests --no-fail-fast -- --test-threads=1` | **17 目标 45 passed / 0 failed / 14 ignored**(ignored 均为需 `XRAY_GO_BIN` 的 Go 互操作) | 编译 2m14s + 运行 ~17 min |

**结论**: 默认单测与集成套件全绿 (确认干净); 唯一动态异常是 kcp `tests/mask_roundtrip.rs` 双用例确定性挂死 (P1), 另有 1 项安全特性 e2e 永久 ignored (P2)、3 项测试卫生问题 (P3)。本轮零失败用例, 无需 flaky 分诊。

---

## 一、测试画像总表 (Suite A, 52 crate×lib)

| crate | pass | fail | ign | | crate | pass | fail | ign |
|---|---|---|---|---|---|---|---|---|
| xray-app-commander | 86 | 0 | 0 | | xray-proxy-loopback | 22 | 0 | 0 |
| xray-app-dispatcher | 106 | 0 | 0 | | xray-proxy-socks | 49 | 0 | 0 |
| xray-app-dns | 153 | 0 | 0 | | xray-proxy-ss | 155 | 0 | 0 |
| xray-app-geodata | 68 | 0 | 0 | | xray-proxy-trojan | 55 | 0 | 0 |
| xray-app-log | 83 | 0 | 0 | | xray-proxy-tuic | 52 | 0 | 0 |
| xray-app-metrics | 69 | 0 | 0 | | xray-proxy-tun | 60 | 0 | 0 |
| xray-app-observatory | 148 | 0 | 0 | | xray-proxy-vless | 219 | 0 | 0 |
| xray-app-policy | 25 | 0 | 0 | | xray-proxy-vmess | 136 | 0 | 0 |
| xray-app-proxyman | 141 | 0 | 0 | | xray-proxy-wireguard | 88 | 0 | 0 |
| xray-app-reverse | 92 | 0 | 0 | | xray-reality | 101 | 0 | 1 |
| xray-app-router | 141 | 0 | 0 | | xray-tls | 133 | 0 | 3 |
| xray-app-stats | 115 | 0 | 0 | | xray-transport | 487 | 0 | 0 |
| xray-app-version | 21 | 0 | 0 | | xray-transport-grpc | 75 | 0 | 0 |
| xray-buf | 186 | 0 | 0 | | xray-transport-httpupgrade | 72 | 0 | 0 |
| xray-cli | 53 | 0 | 0 | | xray-transport-hysteria | 205 | 0 | 0 |
| xray-common | 443 | 0 | 0 | | xray-transport-kcp | 147 | 0 | 0 |
| xray-conf | 177 | 0 | 0 | | xray-transport-naive | 13 | 0 | 0 |
| xray-core | 246 | 0 | 0 | | xray-transport-quic | 9 | 0 | 0 |
| xray-crypto | 123 | 0 | 0 | | xray-transport-splithttp | 186 | 0 | 0 |
| xray-features | 71 | 0 | 0 | | xray-transport-tcp | 2 | 0 | 0 |
| xray-geodata | 247 | 0 | 0 | | xray-transport-websocket | 62 | 0 | 0 |
| xray-mux | 122 | 0 | 0 | | xray-xudp | 39 | 0 | 0 |
| xray-proto | 0 | 0 | 0 | | xray-proxy-anytls | 17 | 0 | 0 |
| xray-proxy-blackhole | 28 | 0 | 0 | | xray-proxy-dns | 56 | 0 | 0 |
| xray-proxy-dokodemo | 39 | 0 | 0 | | xray-proxy-freedom | 54 | 0 | 0 |
| xray-proxy-hysteria | 40 | 0 | 0 | | xray-proxy-http | 40 | 0 | 0 |

日志全量扫描: `panicked at` / `FAILED` / `error[` / `stack overflow` / `test exited abnormally` 全部零命中 (Suite A)。v47 基线继续成立且增长: vless 215→219, core 241→246; 曾 flaky 的 xray-common 本轮 443/0。

## 二、Suite B/C 明细

### Suite B (kcp)
- lib: `test result: ok. 147 passed; 0 failed` (0.25s) — 复跑一次结果一致。
- `tests/mask_roundtrip.rs`: **挂死**, 证据 `target/kcp_tests.log` L476-483:
  ```
  Running tests\mask_roundtrip.rs (...mask_roundtrip-77f33c54f1cd61b3.exe)
  running 2 tests
  test mask_off_roundtrip_unchanged_and_wire_is_bare_kcp ... error: test failed ...
  Caused by: process didn't exit successfully (exit code: 1)
  note: test exited abnormally
  ```
  (exit 1 为本人 `taskkill /F` 所致; 挂死时长 >13 分钟无任何输出)

### Suite C (integration, 17 目标)
| 目标 | pass | ign | | 目标 | pass | ign |
|---|---|---|---|---|---|---|
| vmess_test (integration) | 7 | 0 | | interop_ss | 0 | 5 |
| commander_api | 4 | 0 | | interop_trojan | 0 | 3 |
| compatibility | 5 | 0 | | interop_vless | 0 | 2 |
| dial_xray | 1 | 0 | | interop_vmess | 0 | 4 |
| e2e / e2e_p2 | 4+4 | 0 | | passive_connection | 1 | 0 |
| grpc_multimode | 4 | 0 | | ss / trojan / vless | 4/3/2 | 0 |
| transport_interop | 5 | 0 | | udp_connection | 1 | 0 |

零失败零异常签名。14 个 ignored 全部带 `#[ignore = "requires XRAY_GO_BIN (Go xray-core binary); run with --ignored"]`, 属设计内跳过。

---

## 三、发现清单

### [P1] kcp finalmask e2e 双用例确定性挂死, `cargo test`(不带 --lib) 工作流永久卡死
- **位置**: `crates/xray-transport-kcp/tests/mask_roundtrip.rs:179` (`mask_off_roundtrip_unchanged_and_wire_is_bare_kcp`) 与 `:157` (`mask_on_roundtrip_and_wire_bytes_are_masked`)
- **证据**: 3/3 复现——①Suite B `--test-threads=1` mask_off 挂 >13 min 后人工 taskkill (kcp_tests.log L476-483); ②单跑复验 `mask_off` 再次挂死; ③对照单跑 `mask_on --nocapture` 同样挂死 (mask_on.log L208 `running 1 test` 后 15 分钟无输出, job 900s 超时强杀)。**读侧有 15s 超时保护** (mask_roundtrip.rs:149 `tokio::time::timeout(15s, conn.read)`), 挂死却无超时 panic → 卡点必在 `listen_tcp`(:128) / `dial_with_settings`(:142) / `write_all`(:145) / `flush`(:146) 四个无超时 await 之一。--nocapture 下无 panic 输出, 排除"panic 后运行时关停挂起"。
- **定性**: 测试缺整体超时 (测试缺陷) + 底层 await 路径可能存在真死锁 (产品嫌疑) 双重问题。产品侧头号嫌疑=静态审计已立案的 mKCP listener 同 conv 重入锁死 (`xray-transport-kcp/listener.rs:223`, 第二轮 R3 P1)——mask_off 不走 finalmask mask 链, 挂死在两用例公共的 mKCP listener/dialer 路径, 与 R3 域吻合; 本轮无 Rust 调试器适配器 (仅 debugpy/dart), 未能抓栈定罪, **根因归属未证实**, 不重复立案 R3。
- **影响**: 任何贡献者/CI 跑默认 `cargo test --workspace` 将无限挂死 (仓库测试铁律"必须 --lib"即是此坑的口口相传版); finalmask 唯一 e2e (bd 3lm 验收) 在 Windows 永久不可用, mKCP 会话路径回归无法被测试捕获。
- **修复建议**: 先给测试补整体超时 (如 `#[tokio::test(flavor=...)]` 外层 `tokio::time::timeout(60s, ...)`) 使其"失败可见"而非挂死; 再沿 R3 线程 (listener.rs:223 conv 重入) 抓栈定位真根因。该测试引入于单一 commit 081ebb3 (finalmask 特性), 疑似仅在 Linux 容器验证过, Windows 首跑即挂。
- **负优化自查**: 直接 `#[ignore]` 或删除该测试 = 负优化 (掩盖可能的真死锁, 与历史"症状抑制"模式同类); 只加超时不停在根因也是半修——超时仅作为可诊断化的脚手架, 必须跟根因修复。

### [P2] REALITY btls 指纹矩阵 e2e 永久 ignored, 安全特性零动态验证
- **位置**: `crates/xray-reality/src/server.rs:1130-1132`
- **证据**: `#[ignore = "btls REALITY transcript mismatch (aai legacy DECODE_ERROR); needs pre-hash injection API in btls fork"]`, 注释 (server.rs:1179-1180) 明言"btls transcript mismatch 修复后启用"。
- **影响**: REALITY 是本项目头牌安全特性; btls 路径的指纹矩阵 (8 preset + 11 modern) 从未通过动态验证。前三轮在该文件域已有静态发现 (btls_reality.rs:234 P1 hooks 错误路径), 覆盖薄弱与缺陷存在呈正相关。
- **修复建议**: 上游 btls fork 补 pre-hash 注入 API 后启用; 或先用 rustls 路径跑矩阵、btls 路径单列。
- **负优化自查**: 删测试或降断言"修绿" = 负优化; 上游 API 缺失前保持 ignored + 本条留账是当前最优。
- (同族: `xray-tls/src/utls.rs:691,720,752` 三个 ignored 均为"需外网/诊断用途", 注释明确, 属**合理跳过**, 不立案。)

### [P3] 互操作测试 Go 基准默认路径失效, 仓库内 Go↔Rust 互操作默认不可达
- **位置**: `tests/integration/interop_helpers.rs:66-70`
- **证据**: 默认路径 `E:\Projcet\Xray-core\xray.exe` (盘符/拼写均为旧机残留); 本机 Go 仓库在 `D:/Project/Xray-core` 且无预构建 xray.exe, `XRAY_GO_BIN` 未设 → 14 个 Go 互操作测试即使 `--ignored` 也立即 binary-not-found。
- **影响**: 仓库内唯一的 Go↔Rust 双向互操作检查套件在这台开发机上开箱即坏; 真实互操作仅剩 dist/ 32 节点外置 harness 一条路, 测试矩阵与 CI 语义脱节。
- **修复建议**: 默认路径改读 `D:/Project/Xray-core` 或不存在时报清晰错误并提示设置 XRAY_GO_BIN; 一行级修复。
- **负优化自查**: 无; 纯正优化。

### [P3] app-log 存在缺 `#[test]` 的测试函数, 从未运行 (静默覆盖损失)
- **位置**: `crates/xray-app-log/src/feature.rs:110-116`
- **证据**: `fn log_feature_log_service_returns_service()` 无 `#[test]` 属性, 本轮编译告警直接实锤: "warning: function `log_feature_log_service_returns_service` is never used" (dynamic_tests_full.log L747-753)。Suite A 的 83 passed 不含它。
- **影响**: `log_service().restart_logger()` 断言从未执行过; 覆盖率统计虚高。
- **修复建议**: 补 `#[test]` 一行。
- **负优化自查**: 无。

### [P3] grpc_multimode 测试头注释过期, 与实际行为相反
- **位置**: `tests/integration/grpc_multimode_e2e_test.rs:12`
- **证据**: 注释称 "All tests `#[ignore]` — run with `cargo test --test integration_grpc_multimode -- --ignored`", 实际该文件已无任何 `#[ignore]` 属性, 本轮 4 用例默认全跑全绿。
- **影响**: 误导读者以为 gRPC 多模式只有手动验证; 文档可信度损耗。
- **修复建议**: 删该行注释。
- **负优化自查**: 无。

### 观察项 (不计发现)
- `xray-proto` lib 0 测试: prost codegen 声明 crate, 经 5000+ 上层用例间接覆盖, 可接受。
- 编译告警 ~427 实例 (72 个 crate×target 组合), 前三: xray-transport-hysteria 71 / xray-core 49 / xray-transport 31。多为 unused/dead_code, 无安全类; 建议择机清偿不阻塞。
- Suite A 有 4 ignored (P2 1 个 + 合理网络 skip 3 个), 已逐一核因, 无暗桩。

---

## 四、确认干净项 (动态证据)

1. **全 workspace lib 单测 5557/0 全绿**, 零 panic、零编译错误、零异常退出签名; 52 目标全覆盖 workspace 成员 (tests/benches 无 lib 目标, 属预期)。
2. **xray-common (历史 flaky) 443/0**, vless 219/0, core 246/0 — v47 基线无回归且增长。
3. **集成测试 45/0 全绿**: commander API、gRPC multimode 4 变体 (Rust↔Rust)、e2e/e2e_p2、trojan/ss/vless 协议链、UDP、passive connection、transport_interop 全部通过。
4. **grpc_multimode 4/4 通过与静态 R2 发现 (multiMode Go→Rust 方向截断) 不矛盾**: 该测试仅覆盖 Rust↔Rust (SOCKS5→VLESS-over-gRPC→freedom), Go→Rust 帧方向无动态覆盖——是覆盖盲区而非证据冲突, R2 维持。
5. **btls-sys debug 编译本次无 NASM/TRK 错误**, 无需 `tools/inject_btls_cache.py` 注入 (debug profile 全新编译 btls 链成功)。
6. 无"测试烂致误报失败"、无 flaky 需分诊 (零失败)。

## 五、覆盖盲区 (动态验证不可达面)

- **Go↔Rust 互操作**: 默认工作流零覆盖 (14 ignored + P3 路径失效 + 本机无 Go 二进制)。
- **mKCP server 会话/conv 路径**: 唯一 e2e 挂死 (P1) + 静态 R3 P1 在案, 该路径当前没有任何绿基线保护。
- **REALITY btls 指纹矩阵**: 永久 ignored (P2)。
- **grpc multiMode Go→Rust 方向**: 无测试。

## 六、运行环境注记

- `D:\tmp\buildenv.bat` 吞 cargo 退出码 (kcp 实际失败却报 `KCP_EXIT=0`) — 所有判定以日志文件为准, 建议后续脚本改用 `cargo ... ; exit /b %ERRORLEVEL%` 语义验证。
- 运行前已存在 2 个遗留 `xray.exe` 进程 (PID 21764/35684, 疑为 dist/ harness 残留), 未属本轮产物, 未清理; 若做固定端口集成测试可能构成干扰源。
- 测试日志留存: `target/dynamic_tests_full.log` (8858 行) / `target/kcp_tests.log` / `target/integration_tests.log` / `target/mask_on.log`。
