# qtzi-unwrap-清零 — 重做实施报告（reset 误清后按报告重做）

VERDICT: PASS

基线：HEAD 6cec4cd4，工作树起始仅 Cargo.lock（PM hickory 升级）+ .osv-scanner.toml + reports/。
本轮重做后：git diff --stat = 80 files changed, +530/-447（含 PM 已有的 Cargo.lock 变更）。

---

## 段① parking_lot 迁移（39 文件）

- 机械替换 251 处：lock.unwrap 85 / lock.expect 63 / read.expect 8 / write.expect 9 / read.unwrap 9 / write.unwrap 6 / 全限定 std::sync::Mutex 55 / std::sync::RwLock 16（含 `MutexGuard` → `parking_lot::MutexGuard` 自动命中）。
- 手工清理 25 处：std Result 容错形态（`.ok()`/`.map()`/`.is_ok_and()`/`if let Ok`/`.map_err`/`unwrap_or_else(|p| p.into_inner())`，位于 task/mod.rs、log/mod.rs ×4、peer/mod.rs ×2、default.rs Debug、socks/relay.rs、tuic/udp.rs ×4、websocket/server.rs ×6）+ 跨行链式 `.lock()\n.expect(...)` 漏网 4 处（tun/inbound.rs 测试区）+ kcp/sending.rs 测试 StdMutex 别名收敛。
- 导入组拆分 16 处（`use std::{..., sync::Mutex}` 多名组 / 多行组 → `use parking_lot::X;` + std 组保 Arc/Weak/atomic）。
- Cargo.toml 依赖 5 处：xray-crypto / xray-geodata / xray-proxy-socks / xray-transport-websocket 新增 `[dependencies] parking_lot = { workspace = true }`；xray-proxy-anytls 由 [dev-dependencies] 移入 [dependencies]（server.rs:196 生产引用）。
- 毒锁残留复核：39 文件 `std::sync::{Mutex,RwLock}` 零命中；范围外文件（tcp/hub.rs、udp/hub.rs、naive/inbound.rs、websocket/client.rs、mux worker 测试等）按契约不动。

## 段② attr patch（21 处）

- stress_tests.rs 顶部 `#![allow(clippy::unwrap_used)]`（1）
- wireguard/users.rs：`#[cfg(test)]` + `#[allow(clippy::unwrap_used)]`（1 处两项，**顺带修掉裸 `mod tests` 在 release 编译测试代码的 bug**）
- tun/device.rs tests / trait_tests / free_list_tests（3）
- transport/filelocker.rs（1）
- kcp 15 文件 config/connection/dialer/error/io/listener/output/receiving/register/round_trip/segment/sending/state/udp_hub/updater（15）
- 连带修复：users.rs:27 `DialFn` 导入改 `#[cfg(test)]`（cfg 修复后生产构建 unused import，wireguard lib.rs `#![deny(warnings)]` 下为硬错误）。

## 段③ expect 改写（报告 85 行项）

- **32 行项在 HEAD 已是 expect**（前批已合入：alloc.rs、task/mod.rs、built.rs、instance.rs、udp_session.rs、strategy_random、naive/dial、splithttp/transport、websocket/client、finalmask/mod、happy_eyeballs、headers/conn、vless common_conn/encryption mod、tuic/server、ss config/server/stream、freedom fragment/udp 等）。
- 本轮改写 57 站点 / 21 文件：dot 2、tcp 2、swap 2、proxyman handler 1、leastping 1、core outbound 2（含 match-guard 特殊例）、mux worker 1（短路特殊例）、key.rs 4、packet.rs 12、vmess dispatcher 1、vmess client 2、reality crypto 2、gecko 1、table 3、hysteria conn 3、salamander_socket 1、kcp connection 2、kcp segment 11、kcp sending 2、upload_queue 1、hub handler 1 行 4 unwrap 展开 5 行。
- packet.rs 报告计 8 → 实改 12：同守卫模式（`plain.len()/pkt.len()` 前置检查）全覆盖，4 处 `hdr[..8]/hdr[8..]` 为 [u8;16] 定长类型保证不可失败，按①类保留。
- 表位复核（验收 5）：43 文件生产区剩余 bare unwrap 仅 15 处，全部为审计①类保留（key.rs 1 处 IDENTITY_HEADER_LEN 切片、packet.rs 4 处 hdr 定长、finalmask/mod.rs 1 处常量 parse、sudoku/table.rs 1 处 SHA256 定长、hub/handler.rs 8 处静态 header/Response builder）——报告段③表位零裸 unwrap。

## lru 0.12 → 0.18 + hickory

- crates/xray-app-dns/Cargo.toml `lru = "0.18"`；`cargo update -p lru`：0.12.5 → 0.18.5（allocator-api2 移除）。
- 使用方适配：零。`LruCache::new(NonZeroUsize)` / `LruCache::unbounded()` 在 0.18 兼容（fakedns/mod.rs:79,119 原样编译）。
- hickory 0.26.1→0.26.3（PM 已改 lock）：check/test 全绿，零适配。

## 验收（全部本机实跑，配方 = Main 下发的最终 PATH+PROTOC+LIBCLANG+btls env）

1. `cargo check --workspace` → `Finished \`dev\` profile ... in 9.30s`，EXIT=0
2. `cargo clippy --workspace --all-targets -- -D warnings` → `Finished ... in 19.31s`，EXIT=0（存量噪音：vendor/rustls 2 warning + clippy.toml once_cell 提示，均非本轮引入、不被 -D 提升）
3. `cargo fmt --all -- --check` → **`Diff in` 零匹配**；`Incorrect newline style` 洪水为 CRLF 检出工作树 × rustfmt `newline_style="Unix"` 的环境噪音（大量未触碰文件同报，与规则库 autocrlf 条目一致）；本轮改动的 30 个文件已定向 rustfmt（LF 为仓标准，autocrlf 下 git diff 干净）
4. `cargo test -p xray-app-dns -p xray-buf -p xray-proxy-vless`：
   - xray-app-dns 193 passed / 0 failed + dns_e2e 6 passed / 0 failed
   - xray-buf 195 passed / 0 failed
   - xray-proxy-vless 260 passed / 0 failed + vless_proxy_e2e 2 passed / 0 failed + vps_interop 2 ignored（VPS 门控）
5. 段③表位 unwrap 复核：见段③节（0 裸 unwrap，15 处①类保留）

## 历史原因注明（负优化回看）

本次为 `git reset --hard` 误清后的按报告重做（契约明确），非盲目回档重实现。HEAD 中已有的 32 行项 expect 与局部 parking_lot（instance.rs、sending.rs、tun ParkMutex 等）系前批已合入 master 的产物，本轮未重复改动。

## 红线核对

vendor/ target/ protos/ dist/ docs/refs/ docs/ARCHITECTURE.md .github/workflows/ 根 Cargo.toml [patch.crates-io] 全程未动；xray-transport-tcp/register.rs 未触碰；`ponytail:` 注释（system_dialer.rs:629、bbr_sender.rs:236/301、dokodemo server.rs:176）一字未动；未 commit（归 PM）。

## 5 维自评

- 准确性 5/5 — 每项计数可溯源（sweep 脚本逐文件统计、grep 复核输出、验收命令原样摘录）
- 完整性 4/5 — 契约 6 步 + 5 验收全过；扣分：fmt 验收在 CRLF 工作树下只能以 `Diff in` 零匹配为判据（绝对"无输出"需 LF 检出/CI 复核，已注明）；速度 e2e 非本契约验收项
- 清晰度 5/5 — 段/计数/验收/保留项分层，行号+文件可定位
- 可执行性 5/5 — PM 可直接走 commit + CI dispatch；报告含全部改动面清单
- 简洁性 4/5 — 覆盖 80 文件的任务必要长度，无过程流水账

## 沉淀

- `~/.omp/agent/rules/rust.md`：std::sync→parking_lot 批量迁移三类漏网（跨行链式 / Result 容错形态 / dev-dep section 错置）+ 补扫手法。

## code-simplifier 自检

改动 0 处 / 触碰禁区 0 / diff +530/-447（全部为契约内功能改动，非简化清扫任务）
