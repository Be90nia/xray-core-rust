# Batch D-1 工具链快赢实施回执（hxy3/uf2p/4m1u+kumd/r13i/szlk）

- 日期：2026-09-15
- 执行：impl-d1（PM 分派）
- 基线：HEAD 10c4abd（o93t sockopt），master
- 归因纪律：编译级优化逐个 A/B（基线 → hxy3 → uf2p），bench 状态标注于每节

## 0. bench 基线（hxy3 前置）

- 方法：Python socks5 客户端（8 并发连接 × 32MiB 双向）→ xray(socks inbound →
  freedom outbound) → Python echo server，全 127.0.0.1 回环，5 轮取中位。
  脚本 D:/tmp/d1-bench/bench.py（不进仓库）。
- 基线二进制：target/release/xray.exe（10c4abd 构建，无 native、无 mimalloc）。

| 状态 | 中位吞吐 | RSS 峰值 | 单轮 |
|---|---|---|---|
| baseline（无 native/无 mimalloc） | 973.3 MB/s | 16.0 MB | 882/973/1066/1100/926 |

## 1. hxy3：target-cpu=native — VERDICT: PASS

- 改动：`.cargo/config.toml` 新建（[build] rustflags target-cpu=native，含
  regression 前置验证注释与跨机分发警示）。
- 前置验证（rust-lang/rust#146497 x86-64-v3+fatLTO regression 风险）：
  config 前后 loopback smoke bench 对拍。
- A/B（同 harness 同机，5 轮中位）：

| 状态 | 中位吞吐 | RSS 峰值 | 单轮分布 |
|---|---|---|---|
| baseline 无 native | 973.3 MB/s | 16.0 MB | 882/973/1066/1100/926 |
| native（config 后） | 1017.3 MB/s | 15.2 MB | 902/1035/1017/1130/938 |

  明文泵路径 +4.5%（最差轮对最差轮亦 +2.3%），无 regression；#146497 的
  fatLTO regression 在 rustc 1.98.0-nightly 未复现，config 保留。AES-GCM ~2×
  收益靠原理背书（本 bench 无 TLS 不覆盖），留床轮精确量化。

## 2. uf2p：mimalloc global_allocator — VERDICT: PASS

- 改动：crates/xray-cli/Cargo.toml 加 `mimalloc 0.1 optional` +
  `[features] default=["mimalloc"]`；bin/xray.rs `#[cfg(feature)]` +
  `#[global_allocator] MiMalloc`（lib/测试不受影响）。
- **报决：feature 默认开启**。理由：默认关 = 每个发行 workflow 必须记得
  `--features`，忘加即静默失去收益（silent failure）；默认开则现有全部
  构建命令零改动吃到，回退 = `--no-default-features`。
- A/B（单变量 = mimalloc，均含 native，5 轮中位）：

| 状态 | 中位吞吐 | RSS 峰值 | 单轮分布 |
|---|---|---|---|
| native 无 mimalloc | 1017.3 MB/s | 15.2 MB | 902/1035/1017/1130/938 |
| native + mimalloc | 1068.7 MB/s | 16.7 MB | 944/1042/1075/1184/1069 |

  吞吐 +5.0%（与公开 proxy/redis 基准 +5-15% 下段一致），RSS +1.5MB
  （分配器元数据，远小于 3-5MB 预估上限），最差轮仍正向，方向稳健。
## 3. 4m1u：CI PGO + kumd：CI 去重（同文件同人）

- kumd：三 workflow（interop.yml / mobile.yml / build-linux-release.yml）的
  boringssl REALITY 配方段（约 22-27 行 × 3）收编为 composite action
  `.github/actions/setup-boringssl/action.yml`；三处替换为
  `uses: ./.github/actions/setup-boringssl`。grep 验证配方段仅存于 action。
- 4m1u：build-linux-release.yml 加 PGO 步骤（cargo-pgo：llvm-tools-preview +
  cargo install → `cargo pgo build` → tools/pgo_workload.py 采 30s loopback
  profile → `cargo pgo optimize` 原位输出）；timeout-minutes 30→60。
  workload 脚本 tools/pgo_workload.py（本机自测 OK）。
- release.yml 未加 PGO 的原因：四平台矩阵（win/macos×2/linux），llvm-profdata
  路径与 workload 采集在 win/mac 差异大；配方先在 push-main 触发的
  build-linux-release 单平台验证，PM 确认绿后再复制到 release.yml linux 臂。
- yml 校验：python yaml.safe_load × 4 文件全过 + 花括号目检。
- VERDICT: PASS

## 4. r13i：lazy_static → LazyLock

- 摸底：grep 全仓——crates/ 自身代码 **零使用**（历次批次已清，新代码规范
  本来就是 std::sync::LazyLock）；根 Cargo.toml 无 lazy_static 直接依赖。
- 残留位置（按票面"传递依赖留锁不动"豁免）：
  - Cargo.lock：lazy_static 1.5.0 为传递依赖（der-parser/x509-parser/plotters 等）
  - vendor/quinn-proto：vendored 第三方（patch.crates-io path 引入，保持上游
    一致），lazy_static 是其 dev-dependencies + 自身 tests 使用
- 改动：零（无可替换项）；验收口径=项目自身代码与根 Cargo.toml 零残留 ✅
- VERDICT: PASS（零改动收尾）

## 5. szlk：CC 文档

- 摸底：README.md 是 Nerd Fonts 上游遗留物（非项目文档）；docs/ 无部署文档。
- 改动：新建 `docs/deployment-notes.md`——「主机已调优 TCP 拥塞控制时」节：
  Xray 不触碰 host sysctl tcp_congestion_control（事实依据：sockopt
  tcp_congestion 默认 None（mod.rs 默认测试断言），仅显式配 tcpCongestion 时
  per-socket setsockopt（linux.rs:69-72），进程从不写 /proc/sys）。
- VERDICT: PASS

## 6. 全量终验（native + mimalloc 组合二进制）

- cp target/release/xray.exe（40,414,208 B，native+mimalloc 构建）→ dist/xray.exe
- `python dist/run_full32.py` → **32/32 PASS 0 FAIL 0 PARSE**（362s，vmess/vless/
  trojan/ss/tuic/hysteria/naive/anytls 全协议，reality/tls/ws/httpupgrade/xhttp 全传输）
- workspace --lib → 全绿（50+ crate 全部 `test result: ok`，0 failed，合计
  ~5600+ tests；ignored 5 个均为既有标记）。native rustflags 同步作用于
  debug profile，测试全绿即 #146497 regression 在测试面也无表现。

### 每票独立 commit 粒度（PM 审计后逐票提交，清单互不混淆）

| 票 | 文件 |
|---|---|
| hxy3 | `.cargo/config.toml`（新增） |
| uf2p | `crates/xray-cli/Cargo.toml`、`crates/xray-cli/src/bin/xray.rs`、`Cargo.lock` |
| 4m1u+kumd | `.github/workflows/{build-linux-release,interop,mobile}.yml`、`.github/actions/setup-boringssl/action.yml`（新增）、`tools/pgo_workload.py`（新增） |
| r13i | 无（零改动收尾，见 §4） |
| szlk | `docs/deployment-notes.md`（新增） |
| 报告 | `docs/impl-d1-toolchain-2026-09-15.md` |

## side-effects 三态

- 新增文件：上表 4 个新增 + 本报告
- 修改文件：3 个 workflow + xray-cli 2 文件 + Cargo.lock
- 未动：bridge.rs / ws 指纹 / wire-format / bd 票状态 / 未 commit；工作区
  预存变更（docs/audit* 删除与新增的 research/audit 文档）非本批产物。

### PM 审计 P1 修复（2026-09-15 追加）

- 问题：config.toml 进仓库后污染 CI——runner-native 发行产物（公网用户老机器
  SIGILL 风险）、android/ios 交叉编译 target-cpu=native 语义错误。
- 修复：全部 5 个 workflow（ci/interop/mobile/release/build-linux-release）顶层
  `env: RUSTFLAGS: ""` ——cargo 语义下 RUSTFLAGS env 存在即完全覆盖
  build.rustflags，一处声明覆盖该 workflow 全部 job/步骤（含未来新增）。
  PGO 步骤兼容：cargo-pgo 在其上追加 profile flags，产物仍为通用 target。
- 验证：5 文件顶层 env RUSTFLAGS=''（yaml.safe_load 全过）+ grep 覆盖。
