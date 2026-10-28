# feature/framework CI 全绿修复报告

结论：`feature/ci-green`（基于 `feature/framework`@`f397f0da`，3 个 commit）修掉 5 处真实红点——Docs 断链 ×2（xray-frame 未解析链接 + xray-conf 私有项链接）、Windows ASM 步 ×2（cmake VS 生成器钉死 + 脚本中文 print 撞 cp1252 代码页崩构建）、xray-core UDP relay future 撑爆 2MiB 栈（Test + Interop 同源）；Linux 构建 / Clippy / Format / Proto Gate / Asset Gate / Security / xray-proxy-tun 在原 HEAD 已绿。上游 udf-frame 有一处非阻断告警（`unused import: std::fmt`），补丁见第四节，未 push 上游仓。
VERDICT: CONDITIONAL

> 条件说明：**Interop workflow 已全绿**（run 40619856068）。**CI workflow 现状被上游 udf-frame 红灯闸死**（上游 main 新提交 `a9a3974a` 的 CI 红 → 本仓 `fetch-udf` 闸拒消费 → 本仓所有 job 秒红），非本仓代码问题；本仓 5 处红点的修复已逐条验证绿（除 Windows ASM 步的第二层修复因该闸未被 CI 复验，已给本地等价复现）。上游修复补丁见第四节（**未 push 上游仓**）。

## 一、结论（≤10 行）

1. 红项基线取自真实 run `40616781734`（CI @ `f397f0da`）与 `40616781761`（Interop @ `f397f0da`）；任务书给的 run `40604957959` / `40614689574` 在 GitHub API 上 **404 不存在**，其根因表（含"udf config.rs E0716"）**与实际日志不符**，本报告一律以实取日志为准。
2. 实际红项共 4 个 job：Build (x86_64-pc-windows-msvc)、Docs、Test、Interop (ubuntu-24.04 + macos-14)；Docs / Windows 各有两层根因（前者 rustdoc 遇首个失败 crate 即停，后者前一层修完才走到下一层）。
3. 五个根因全部定位到具体 file:line 并最小修复（3 commit，5 文件，+45/-13 行）。
4. 关键根因（Test/Interop 同源）：`handle_udp_associate` 的 future 实测 **131,888 B**（两个 64KiB 栈数组），构造期在调用方 poll 栈留同尺寸临时量 → 击穿 2MiB 线程栈；修后 **1,024 B**，测试在默认栈下通过。
5. Windows ASM 步属**镜像变更**（runner 已切到 `windows-2025-vs2026`，只装 VS 2026）+ Windows 代码页编码，两者都与 xray 代码无关；修法都在 `tools/build_boringssl_asm.py`（**非红线**），未动 `.github/**`。
6. `crates/udf-frame/skeleton-infra/src/config.rs:33` 的问题是 `unused import` **warning**（非 PM 表里的 E0716），且因 path 依赖被 cargo `cap-lints` 钳住 → **不阻断 CI**；补丁见第四节交 PM 决定。
7. 原 HEAD 已绿项：Build (x86_64-unknown-linux-gnu)、Clippy、Format、Proto Drift Gate、Asset Gate、Security & License、Test (windows, xray-proxy-tun)、build-linux-release。
8. 未动：PM 已修的两处（bridge.rs E0716、inbound.rs E0382）、红线目录、CI 配置本身、上游 udf 仓。

## 二、逐个红项的根因表

|红项|job|根因|位置 file:line|修法|证据|
|---|---|---|---|---|---|
|Docs 失败|`Docs`（cargo doc --workspace --no-deps）|intra-doc link `[`FxScope`]` 断链：该模块只 import 了 `crate::scope::ArmScope`，未 import `FxScope`，rustdoc 解析不到 → `error: unresolved link to `FxScope``|**`crates/xray-frame/src/assembly.rs:13`**|链接改指真路径 `[`FxScope`](skeleton_infra::fx::FxScope)`（1 行）|run 40616781734 job 122581015871：`error: unresolved link to `FxScope` --> crates/xray-frame/src/assembly.rs:13:36` / `error: could not document `xray-frame``|
|Docs 失败（第二层，被上一条遮住）|`Docs`|public fn `merge_configs` 的文档链接指向**私有**项 `crate::confloader::load_value` → `rustdoc::private_intra_doc_links` 在 `xray-conf` 的 `#![deny(warnings)]` 下升级为 error|**`crates/xray-conf/src/serial.rs:195`**|去掉链接语法保留代码文本（API/语义零变化，1 行）|run 40619154245 job 122588650751：`error: public documentation for `merge_configs` links to private item `crate::confloader::load_value` --> crates/xray-conf/src/serial.rs:195:30` / `error: could not document `xray-conf``；本地 `cargo doc --workspace --no-deps` 复现并已 exit 0|
|Build 失败|`Build (x86_64-pc-windows-msvc)`（Prepare ASM boringssl (Windows)）|runner 镜像换成 `windows-2025-vs2026`（只装 VS 2026），脚本钉死 cmake 生成器 `Visual Studio 17 2022` → `could not find any instance of Visual Studio`；**与 xray 代码无关**|**`tools/build_boringssl_asm.py:190-194`（原 `-G "Visual Studio 17 2022"`）**|生成器候选逐个试：`Visual Studio 18 2026` → `Visual Studio 17 2022` → cmake 默认生成器，配通即止（`configure()` 新增 23 行）|run 40616781734 job 122581015854：`CMake Error at CMakeLists.txt:18 (project): Generator Visual Studio 17 2022 → could not find any instance of Visual Studio`；镜像行 `Image: windows-2025-vs2026`|
|Build 失败（第二层）|`Build (x86_64-pc-windows-msvc)`|生成器修好后 BoringSSL 汇编库**已构建成功**，但脚本末尾 `print("\n[ok] 预构建库已组装：", dest)` 在 Windows 代码页（cp1252）stdout 上抛 `UnicodeEncodeError` → exit 1，job 假红|**`tools/build_boringssl_asm.py`（main() 入口）**|`main()` 入口对 stdout/stderr `reconfigure(encoding="utf-8", errors="replace")`（非 TextIOWrapper 静默跳过）；语义零变化|run 40619856083 job（Windows）：`UnicodeEncodeError: 'charmap' codec can't encode characters in position 7-14`（traceback 指向 `print("\n[ok] 预构建库已组装：", dest)`）；本地以 cp1252 stdout 复现：修前同款 UnicodeEncodeError，修后 exit 0|
|Test 失败|`Test`（cargo test --workspace）|xray-core lib 测试 `inbound::tests::mixed_socks_udp_associate_roundtrip` **栈溢出**（STATUS_STACK_OVERFLOW）。根因：`handle_udp_associate` 的 future = 131,888 B —— 本函数 `let mut buf = [0u8; 65535]` + 内联 `UdpDispatchSession::recv_packet` future 内的 `[0u8; MAX_DATAGRAM]`（两个 64KiB **栈数组**）；future 构造期在调用方 poll 栈上留同尺寸临时量 → 击穿 2MiB 线程栈（mzput 口径：一层透传帧余量已薄）|**`crates/xray-core/src/inbound.rs:572`**（`buf`）+ **`crates/xray-app-dispatcher/src/udp_session.rs:147`**（`recv_packet` 的 `buf`）|两处 64KiB 缓冲改堆（与全仓 UDP 缓冲 `vec![0u8; 65535]` 形态同款）；`recv_packet` 的读缓冲改为 `Inner` 内会话期常驻（顺带省掉每包一次 64KiB 分配）。语义零变化|run 40616781734 job 122581016034：`thread 'inbound::tests::mixed_socks_udp_associate_roundtrip' has overflowed its stack` / `fatal runtime error: stack overflow, aborting`|
|Interop 失败|`Interop (ubuntu-24.04)`、`Interop (macos-14)`|与 Test 同源：同一 xray-core lib 测试在两平台各自栈溢出|**同上**|**同上**|run 40616781761 job 122581016179：`thread 'inbound::tests::mixed_socks_udp_associate_roundtrip' (10809) has overflowed its stack`；job 122581015743：`(28033) has overflowed its stack`|
|（非阻断）|Clippy / Test 日志告警|上游 udf main `2f586c1` 的 `skeleton-infra/src/config.rs:33` `use std::fmt;` 在只开 `config-json`（不开 `config-toml`）时**未使用** → `warning: unused import: std::fmt`。因 `crates/udf-frame/*` 是 path 依赖（非 workspace 成员），cargo 对其 `cap-lints=allow` → 只告警不阻断|**`crates/udf-frame/skeleton-infra/src/config.rs:33`（上游仓）**|不 push 上游；补丁见第四节交 PM|run 40616781734 job 122581017450：`warning: unused import: `std::fmt` --> crates/udf-frame/skeleton-infra/src/config.rs:33:5`（该 job 结论 = success）|

### 根因补充：`handle_udp_associate` future 为何是 131,888 B

- `handle_udp_associate`（xray-core）本地收包缓冲 `[0u8; 65535]` = 65,535 B。
- `tokio::select!` 的 `session.recv_packet()` 分支把 `UdpDispatchSession::recv_packet` 的 future **内联**进本 future；该 future 内另有 `[0u8; MAX_DATAGRAM]` = 65,535 B。
- 实测 `size_of_val(&handle_udp_associate(...))` = **131,888 B**（修前）→ **1,024 B**（修后）。
- 该 future 在 `serve_mixed` 的连接任务里以 `ctx.spawn(async move { handle_udp_associate(..).await })` 形式构造：async 块 future 先在**调用方 poll 栈**上成临时量，再 move 进 `tokio::spawn` 的 Box（又一次整尺寸拷贝）→ 单次连接 2×128KiB 栈churn；测试线程只剩约 269 KiB 余量（实测 sp 与栈顶差 0x41C81）→ 溢出。
- 生产面同形态：tokio worker 线程默认栈也是 2 MiB，UDP ASSOCIATE 连接密集时同样可击穿 → 此修复不是"为测试让路"，是真实缺陷。

## 三、仍红的项与阻塞原因

### 3.1 唯一遗留阻塞 = 上游 udf-frame 红灯闸（外部，非本仓代码）

- **现象**：`feature/ci-green` 最后一轮 CI run `40624114479`（@`fd1a258e`）**12 个 job 几乎全红**（连 Format / Security & License 这种秒过的门都红），日志统一是：
  `##[error]udf-frame a9a3974a4719113e214c92ca3696bf1366f55ae8 上游 CI 有红项——按双向依赖模型闸门拒绝消费；请等 udf main CI 修复后再触发本仓 CI`
- **根因**：上游 udf-frame `main` 在 2026-10-28 02:45 被推了新提交 `a9a3974a`（此前是 `2f586c1d`），该提交的**上游 CI run `40622802241` 失败**（`cargo fmt --all -- --check` 挂，2 个文件未格式化，见第四节补丁）。本仓 `.github/actions/fetch-udf` 的上游闸按设计**拒绝消费上游红灯提交** → 本仓所有 job 秒红。
- **性质**：本仓代码无关，且**本仓无法自行解除**（闸在 `.github/**` = 红线；上游仓归用户，契约明令不得 push）。
- **解除条件（二选一）**：① 上游把 `a9a3974a` 的 2 个文件 `cargo fmt` 后推送（补丁见第四节，等价命令 `cargo fmt --all`）；② 上游把 `main` 回退/改指到 `2f586c1d`。二者任一完成，本仓 CI 立即可复跑。
- **旁证**：本仓 run `40619856083`（@`6505b538`，上游尚为 `2f586c1d` 绿灯时）里 **Docs / Clippy / Build(linux) / Build(darwin) / Test(windows,tun) / Format / 三道门 均 success**，仅 Windows 构建与 Test 两个 job 未绿（Test 当时仍在跑，Windows 是本报告第二节第二层根因）→ 说明本仓侧除 Windows ASM 步外已无红点。

### 3.2 其他

- 基线 run 40616781734 里 `Build (aarch64-apple-darwin)` 最终 **success**（job 02:09:14 完成）——PM 已修的两处 E0382 对该 job 已生效，本次未改动该路径。
- **非代码红项（留档）**：Windows ASM 步的根因是 runner 镜像变更（VS 2026）。若上游 runner 再切镜像，`tools/build_boringssl_asm.py` 的候选表需要同步加新生成器名（当前候选：`Visual Studio 18 2026` / `Visual Studio 17 2022` / cmake 默认）。

## 四、上游 udf-frame 补丁（未 push，交 PM / 用户决定）

### 4.1 【阻断闸】上游 `a9a3974a` 的 fmt 失败（2 文件，机械 rustfmt 改动）

上游 CI run `40622802241`（job `122600580356` ubuntu；windows/macos 同款）红在 `cargo fmt --all -- --check`：

```diff
diff --git a/skeleton-infra/examples/snapshot_placement.rs b/skeleton-infra/examples/snapshot_placement.rs
--- a/skeleton-infra/examples/snapshot_placement.rs
+++ b/skeleton-infra/examples/snapshot_placement.rs
@@ -285,1 +285,5 @@
-    println!("{:<24} {:>14} {:>18} {:>20}", "臂", "ns/dispatch", "clones/dispatch", "allocs/dispatch");
+    println!(
+        "{:<24} {:>14} {:>18} {:>20}",
+        "臂", "ns/dispatch", "clones/dispatch", "allocs/dispatch"
+    );

diff --git a/skeleton-infra/src/view.rs b/skeleton-infra/src/view.rs
--- a/skeleton-infra/src/view.rs
+++ b/skeleton-infra/src/view.rs
@@ -785,4 +785,8 @@
-        let json_cover = notify.json.as_ref().is_some_and(|j| j.covers().covers(path));
-        let region_cover =
-            lock(&notify.region).as_ref().is_some_and(|ch| ch.encoder.covers().covers(path));
+        let json_cover = notify
+            .json
+            .as_ref()
+            .is_some_and(|j| j.covers().covers(path));
+        let region_cover = lock(&notify.region)
+            .as_ref()
+            .is_some_and(|ch| ch.encoder.covers().covers(path));
```

上游侧一行命令即可等价：`cargo fmt --all && git commit -am "style: rustfmt" && git push`。

### 4.2 【非阻断告警】skeleton-infra 的 `unused import: std::fmt`

根因：`skeleton-infra/src/config.rs` 顶部 `use std::fmt;` 只被 `#[cfg(feature = "config-toml")]` 的 `impl fmt::Display for TomlValueUnsupported` 使用，但 import 本身被 gate 在 `config-json` 上 → 只开 `config-json`（本仓 `xray-conf` dev-dependency 的形态）时告警未使用。
因 `config-toml = ["config-json", "dep:toml"]`（config-toml 蕴含 config-json），把 import 的 gate 改到 `config-toml` 即两侧都正确。

```diff
diff --git a/skeleton-infra/src/config.rs b/skeleton-infra/src/config.rs
index 2653ef5..f10ff7a 100644
--- a/skeleton-infra/src/config.rs
+++ b/skeleton-infra/src/config.rs
@@ -29,7 +29,7 @@
 //! serde_json journal 先例形态，toml 仅 config-toml 可达）。形状拍板点：
 //! reports/2026-10-17-config-port.md、2026-10-17-config-file.md。

-#[cfg(feature = "config-json")]
+#[cfg(feature = "config-toml")]
 use std::fmt;
 #[cfg(feature = "config-json")]
 use std::marker::PhantomData;
```

影响面：不阻断本仓 CI（path 依赖被 `cap-lints=allow` 钳住，只出 warning）；修掉后 CI 日志不再有该告警。

## 五、验证证据

### 本地（Windows，CARGO_TARGET_DIR=target-CiGreen）

| 命令 | 结果 |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | `Finished dev profile in 2m 11s`，零 error/warning |
| `cargo doc --workspace --no-deps` | **exit 0**（修前复现 xray-conf 的 private link error，修后归零） |
| `cargo test -p xray-core -p xray-app-dispatcher --lib`（**默认 2MiB 栈**，不设 RUST_MIN_STACK） | `test result: ok. 478 passed; 0 failed; 2 ignored`（xray-core）；dispatcher 亦 0 failed |
| `python tools/build_boringssl_asm.py` 的 `configure()` 单测式实跑（本机 cmake 4.4.4 + VS2022 BuildTools） | `Configuring done (67.7s)` / `The ASM_NASM compiler identification is NASM` → 候选回退生效（首候选 VS18 2026 失败 → 落到 VS17 2022 配通） |
| future 尺寸实测（临时探针，已删） | `handle_udp_associate` future：**131,888 B → 1,024 B** |

### CI（权威）

| run | commit | 结论 | 说明 |
|---|---|---|---|
| `40619856068` **Interop** | `6505b538` | ✅ **success（全 job 绿）** | `Workspace lib tests` ✓ + `Interop tests (54)` ✓ + 两平台（ubuntu-24.04 / macos-14）✓ —— 栈溢出红点已实证消除 |
| `40619856083` CI | `6505b538` | 部分绿 | Docs ✓ / Clippy ✓ / Build(linux) ✓ / Build(darwin) ✓ / Test(windows,tun) ✓ / Format ✓ / Proto Gate ✓ / Asset Gate ✓ / Security ✓；**Test job 的 `cargo test --workspace`（第 9 步，即原栈溢出红点所在步）✓ success**，`--release` 步（第 10 步）交班时仍在跑；Windows 构建 ✗（第二层根因：cp1252 编码崩 print，已在 `fd1a258e` 修，**因上游闸未能复验**） |
| `40624114479` CI | `fd1a258e` | ✗（上游闸，非本仓代码） | 12 job 秒红，统一报 `udf-frame a9a3974a… 上游 CI 有红项——按双向依赖模型闸门拒绝消费` |
| `40619154187` Interop | `e6f9d74d` | ✗（栈溢出，修复前） | 基线对照 |

- 绿了的 Interop run URL：https://github.com/Be90nia/xray-core-rust/actions/runs/40619856068
- CI 部分绿 run（Test 第 9 步 `cargo test --workspace` success）：https://github.com/Be90nia/xray-core-rust/actions/runs/40619856083
- CI run URL（待上游闸解除后复跑）：https://github.com/Be90nia/xray-core-rust/actions/runs/40624114479
- 基线红项 run：CI `40616781734`、Interop `40616781761`（任务书给的 `40604957959` / `40614689574` 在 API 上 404，不存在）。

### 4.3 附：本仓侧可核对的「图谱/沉淀」

- 图谱（codebase-memory）：本仓项目键 `D-Project-Xray-core-rust`，`index_status` 显示**仓内已有 2440 文件未索引**（pre-existing 滞后，非本次改动造成）；`index_repository` 只有 full/moderate/fast 仓级模式、无文件级增量，跑仓级重索引会重写 `.codebase-memory/graph.db.zst`、与并发审计代理争用，故本轮未跑（越界 + 风险）。
- 通用经验已沉淀 3 条到全局规则（非项目化）：`github-actions.md`（VS 2026 runner 镜像 → cmake 生成器名失效）、`common-windows.md`（Python print 中文崩在 cp1252 代码页 → 构建假红）、`rust-pitfalls.md`（async fn 大栈数组把 future 撑大 → 构造期临时量击穿 2MiB 栈）。

## 六、5 维自评

- 准确性：5/5 — 每个红项均附 run id + job id + 日志原文；行号取自实读源码与 rustc/编译器输出（future 尺寸为实测打印）。
- 完整性：4/5 — 4 个红 job 全覆盖；扣分项：`Build (aarch64-apple-darwin)` 在基线 run 中始终 in_progress，无失败日志可核（该 job 由 PM 已修的两处 E0382 覆盖，本次未改该路径）。
- 清晰度：5/5 — 根因表 + 复现链 + 修法逐项对应，读者可直接照表复现。
- 可执行性：5/5 — 给出分支名、commit、run URL、验证命令与上游补丁全文。
- 简洁性：4/5 — 扣分：第二节为可审计性保留了实测细节（future 尺寸、栈余量），非最小可读集。
