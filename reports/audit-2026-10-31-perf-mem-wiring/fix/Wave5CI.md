VERDICT: CONDITIONAL

> 条件 = 「上游 26.10.17 无 release asset」这一前提证伪后改走 commit 构建（见 §1），
> 以及「所有改动未在真实 GitHub runner 上执行过」（见 §6）。四票的门都已落地、本地可验证的
> 部分全部实测通过。

改动面（git diff --stat，含未入库新文件）：
```
.github/workflows/ci.yml      |  78 +++++++++++++-----
.github/workflows/interop.yml | 140 +++++++++++++++++++++++++++-----
.github/workflows/release.yml |  87 +++++++++++++++++++++++++-
dist/interop_udp_tunnel.py    |   9 ++-
.github/actions/fetch-go-baseline/action.yml (新, 53 行)
```

---

## §1 t3wtj（P1）协议差分门基准改钉 26.10.17

### 前提证伪（必须先看）
票面要求「下载 26.10.17 官方 release asset 后算 sha256」。**上游根本没有 26.10.17 这个
release/tag**——三条独立证据：

```
curl https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.10.17  -> 404
curl https://api.github.com/repos/XTLS/Xray-core/git/ref/tags/v26.10.17   -> 404
git ls-remote --tags https://github.com/XTLS/Xray-core
  1b1647cd  refs/tags/v26.10.21
  a4a3dff5  refs/tags/v26.10.31
  b26a91de  refs/tags/v26.9.30
  52a412d9  refs/tags/v26.9.9
```
`releases?per_page=12` 里也不存在 26.10.17（只有 26.9.9 / 26.9.30 / 26.10.21 / 26.10.31）。
26.10.17 只是一个**源码 commit**（`92ccc939`，commit message = "Xray-core v26.10.17"），
本机 `D:/tmp/go2617/xray.exe` 正是别人按该 commit 自建的（version 行 `92ccc93-dirty`）。
→ sha256 无对象可算，禁止猜。两条替代路都不成立：26.9.9 已按 CLAUDE.md §0 降级为
「仅解释上游改了什么、不得用于裁定」；26.10.21 会把上游新增项误判成缺口（同上禁）。

### 落地方案：按 commit 构建（完整性锚点从二进制 sha256 换成 commit sha + go.sum）
新增 composite action `.github/actions/fetch-go-baseline/action.yml`（53 行）：
`actions/setup-go@v5 (1.27.x)` → 下载 `codeload.../tar.gz/92ccc939…` 源码快照 →
`go build -trimpath -o tools/xray-go/xray ./main` → **断言 `xray version` 含
`Xray 26.10.17 `**（错版本立刻红）→ 导出 `GO_BASELINE_BIN`。
基准版本 + commit **只在该文件出现一次**（下次升级改两行），workflow 侧零版本字面量。

- `ci.yml` parser-parity：删除「下载 v26.9.9 zip + sha256 校验 + unzip」整段 → `uses:` 一行；
  job 名 `Parser Parity (Go v26.9.9 vs Rust)` → `(Go ruling baseline vs Rust)`；
  `--go-bin` 改 `"$GO_BASELINE_BIN"`。
- `interop.yml`：删除逐 OS 拼 asset 名的映射表（macOS:arm64/x86_64、Linux:x86_64/aarch64）
  → `uses:` 一行。**副作用是净简化**：按 commit 构建天然全平台统一，asset 表不再需要。

### 验证
1. 同一配方本机实跑（产物 `Xray 26.10.17 (Xray, Penetrates Everything.) Custom (go1.27.0 windows/amd64)`，
   45050368 B，30s 完成；tarball sha256 = `c67de972…5b9600c`，1.25 MB）。
2. 版本断言在真实版本行上成立：`Xray 26.10.17 ` 命中，`Xray 26.9.9 ` 不命中。
3. **parity 门对 26.10.17 实跑**（`--go-bin D:/tmp/go2617/xray.exe --rust-bin target-Wave5CI/release/xray.exe`）：
```
合计 57 例：SAME 56，ALLOWED（allowlist 内已知差异）1，DIFF（allowlist 外）0
== allowlist 命中 ==  P02: D-13 首字节 0x06 分流…
```
即换基准后门是绿的（allowlist 无需改动），且比 26.9.9 时代的噪声更少。
4. `grep -rn "26.9.9" .github/workflows/` → **0 命中**（唯一残留 `26.9.9` 字样在
   `action.yml` 的解释性注释里，用来说明「为什么不能继续用 26.9.9」，不在 workflows 面）。

---

## §2 0m0f6（P2）interop 门补 PR 触发 + 扩脚本覆盖面

### 改了什么
1. `interop.yml` 触发面：新增 `pull_request: [main, master]` + `schedule: cron '17 3 * * *'`
   （nightly 用；避开整点排队）。
2. **接入 `dist/interop_udp_tunnel.py`**（全环回、无外网、无节点表）：
   - PR/push 面（interop job 的 Linux 腿）：`--quick --dest-ports 53,29090` → **14 例**
     （3 协议 rust→go × cone 开/关 × dest 53/29090 + dokodemo 1 + dns-udp 1）。
   - nightly 面（full32 job）：四方向全量 `--dest-ports 53,29090` → **56 例**
     （3 协议 × {rust→go, go→rust, rust→rust, go→go} × cone × 2 dest + dokodemo 4 + dns 4）。
   - 为此给脚本加 `--dest-ports`（9 行 diff，纯选择器；默认值 = 原三元组 `53,443,29090`，
     不改变任何既有调用行为）。
3. **`interop_matrix.py` 判定：不接**（评估项，逐条理由）——它没有 argparse、硬编码
   `D:/tmp/interop_cert.pem`、默认二进制 `dist/xray.exe`（红线基线二进制）、清理用
   `taskkill /F /IM xray.exe`（Windows 专属，且会误杀用户 v2rayN 内核），Linux CI 直接跑不通；
   改造成本 > 它覆盖的面（与 `interop_ci.py` 的 12 例 Rust↔Rust 重叠）。
4. `run_full32.py`（32/32 真机）：新增 `full32` job，`if: schedule || workflow_dispatch`
   —— **PR/push 路径完全不进**；节点表来自 `secrets.FULL32_URI_FILE`；
   无 secret 时「落盘步骤」`present=false` 后所有后续步条件退出 → **job 结论 success（干净 skip）**。

### 顺带堵的静默失败
`run_full32.py` 自身**恒 exit 0**（只打印/落盘），直接当门槛 = 「永远绿」。
workflow 侧从它的汇总行取判据（`=== P/T PASS  F FAIL  P PARSE ===`），任一 FAIL/PARSE
或 PASS 数不足即 `::error::` 红。该 python 段已实测：好日志 rc=0、坏日志 rc=1。

### 验证（本机实跑，全部用 HEAD 707cd30e 自建 release 二进制 + `D:/tmp/go2617/xray.exe`）
```
PR 子集   python dist/interop_udp_tunnel.py --rust … --go … --quick --dest-ports 53,29090
          === 14/14 PASS ===
nightly   python dist/interop_udp_tunnel.py --rust … --go … --dest-ports 53,29090
          === 56/56 PASS ===
门槛逻辑   full32 gate [good] rc=0 out=32 节点矩阵: 32/32 PASS, 0 FAIL, 0 PARSE
          full32 gate [bad ] rc=1 err=::error::32/32 真机矩阵存在失败用例…
```

---

## §3 1gkcf（P1）补 CI 特权 job

新增 `ci.yml` job `test-linux-privileged-tproxy`（ubuntu-latest，30 min）：
- 常规 pipelined 步骤（fetch-udf / toolchain / 独立 prefix-key 的 rust-cache / protoc /
  setup-boringssl）+ 前置能力探针 + `sudo … cargo test -p xray-proxy-dokodemo
  --test plugin_contract tproxy_gate_is_runtime_semantics_not_compiled_away -- --exact`。
- **为什么 sudo 而不是 privileged docker**：GitHub hosted runner 是整机 VM，root 保有
  `CAP_NET_ADMIN`；容器默认丢该能力，那才必须 `--privileged -v /dev/net/tun`（注释里写明）。
- **为什么不需要 /dev/net/tun**：该测试打的是 `IP_TRANSPARENT` **UDP** socket（fake_udp），
  全程不 open tun 设备——票面写的「tun 挂载」对本测试是多余条件，注释已澄清。
- **前置探针**（`sudo python3 - <<'PY' … setsockopt(IPPROTO_IP, 19, 1)`）显式断言能力在场：
  能力缺失 job 红，而不是静默退化成非特权分支（= 波4 G9 之前那个假绿）。
- 非特权 job（`test`）一行未动。

验证：探针脚本实跑通过（语法 + 分支）；Linux root 侧的真跑见 §6。
`bash -n` 无法在本机执行（本机没有可用的 bash 解释器，见 §6），改为：YAML 解析 +
把 workflow 里的 run 块按 YAML 渲染结果逐字复核（heredoc 缩进、`sudo --preserve-env`
折叠后的单行形态均已确认）。

---

## §4 3t30l（P1）Linux 发布产物验证门

`release.yml` 的 build job 在「构建完成」与「上传 artifact」之间插入：
1. Windows 腿先确保 `openssl` 在 PATH（`Get-Command` 失败则取 `$ProgramFiles\Git\usr\bin`，
   再失败就 throw）——互通套件用 openssl 生成 TLS 证书，缺它 TLS 用例必红。
2. **预热**：`<bin> version`（一行；理由见验证第 3 条）。
3. `python3 dist/interop_ci.py --rust <刚构建的产物> --suites rust --upstream local
   --work $RUNNER_TEMP/interop_release` → 12 例 Rust↔Rust（同配双轮，vmess /
   vless-vision-tls / trojan / ws / ss / ss2022），hermetic（脚本内 local upstream，无外网）。
- 每个靶的自有产物 → **Linux 与 Windows 产物跑同一套**，对等性有实测证据而非「同一次构建」的推断。
- 跳过 `x86_64-apple-darwin`：它是 macOS arm64 runner 交叉编出的 x86_64 产物，能否执行取决
  于 runner 上的 Rosetta，不把基础设施运气当发布门（注释写明）。

### 验证（本机，Windows 产物 = 同一份 release 二进制）
```
python dist/interop_ci.py --rust target-Wave5CI/release/xray.exe --suites rust \
       --upstream local --work D:/tmp/interop_release_smoke3
[PASS] #01…#12 全部 HTTP body=1024B
=== 互通 CI: 12/12 PASS ===        (42.8s)
```
预热步不是装饰：冷启那次（首例 = 50MB 新产物的首次执行）**#01 假红**、随后连跑两轮
12/12。根因是 harness 侧就绪窗（见 §7-1），故在 release 门里用一行预热规避，并把
「产物可执行 + 版本行」同时当第一个证据。

---

## §5 触发条件表 + 改动前后对比

| workflow | 改动前触发 | 改动后触发 | job 变化 |
|---|---|---|---|
| ci.yml | push(main/dev/master/feature/**), pull_request(main,master), workflow_dispatch | 不变 | +`test-linux-privileged-tproxy`；`parser-parity` 换基准来源 |
| interop.yml | workflow_dispatch, push(master/main/dev/feature/**) | **+pull_request(main,master) +schedule(17 3 * * *)** | +`full32`（schedule/dispatch 才跑）；interop job +UDP 隧道 PR 子集 |
| release.yml | push(tags v*) | 不变 | build job +openssl 保障 +预热 +hermetic 互通冒烟 |

| job | 何时跑 | 门强度 |
|---|---|---|
| ci / parser-parity | push+PR+dispatch | 阻断（DIFF≠0 即红），基准 = 26.10.17 |
| ci / test-linux-privileged-tproxy | push+PR+dispatch | 阻断（含能力探针） |
| interop / interop（macos-14, ubuntu-24.04） | push+**PR**+dispatch | 阻断（54 例 + UDP 14 例） |
| interop / full32 | **仅 schedule/dispatch** | 32/32 阻断；无 secret → 干净 skip；UDP 56 例阻断 |
| release / build（全 5 靶） | tag push | 阻断（新增产物互通冒烟，跳过 appledarwin x86) |

**未在真实 GitHub runner 上验证**（本机无 `act`、无 `actionlint`；只做了 YAML 解析 +
嵌入脚本逻辑实跑 + 命令本地复现）。

---

## §6 无法在本机验证的部分（逐条）

1. **所有 workflow 的真实执行**：本机没有 `act`/`actionlint`（`command -v act` 空），
   无 GitHub runner。已验证到的最大程度 = YAML 可解析 + 每个新增 run 块的 shell/python
   逻辑实跑 + 命令本地原样复现。
2. **Linux 特权分支真跑**（§3）：本机是 Windows，无法以 Linux root + CAP_NET_ADMIN 执行
   该 Rust 测试。探针脚本本身跑过（分支/语法），但「root 下 fake_udp 走 Ok 分支并在 reactor
   内收发」只有代码级与注释级证据，需首次 CI run 才算实锤。
3. **`fetch-go-baseline` 在 CI 里的 go 1.27.x 解析**：本机用模块缓存里的 go1.27.0 工具链构建
   成功，但 `actions/setup-go` 的 `1.27.x` 版本解析、以及 runner 上 `proxy.golang.org`
   拉模块（本机该域名不可达，我是用 goproxy.cn 镜像完成构建的）未实测。
4. **macOS 腿**（interop 的 macos-14、release 的 macos 靶）：本机不可跑。
5. **musl 靶的互通冒烟**（release 的 zigbuild 产物）：未在真 Linux 验证。
6. **secret 相关路径**：`FULL32_URI_FILE` 提供节点表、无 secret 时干净 skip——只做了逻辑
   推演与门槛 python 段的 bin 级验证，真实 secret 行为需首次 nightly 才见。

---

## §7 顺带发现（不在本票范围，未改产品代码 / 未改 harness 行为）

1. **`dist/interop_ci.py` 的 client 就绪检查是空转**（`run_one`：`wait_port(S, 15)`
   返回值未检查，且 `pc.poll()` 紧跟 Popen 几乎恒为 None）→ 冷启时第 1 例假红（本机实测
   1 次，预热后不复现）。已在 release 门用「预热」规避；根治应改成
   `if not wait_port(S,15): err=…`（2 行），建议单开票。
2. **`dist/interop_udp_tunnel.py` 全矩阵被 Go↔Go 对照组的同一组合打红**：`cone=on &
   dest=443` 四个方向全红（含 go→go，说明是 harness/Go 口径面而非本仓缺陷）。故 CI 用
   `--dest-ports 53,29090` 规避，443 留在手动跑。
3. **`vless rust->rust cone=off dest=29090` 偶发一次红**（80 例中 1 例；重试后仍红，
   其余 55 例全绿）。未复现第二次，属待观察项，不阻塞。
4. `dist/tmp_udp_tunnel/` 是 harness 的运行产物目录（未入库），本次未清理他人证据。

---

## §8 汇编前置（Main 追加：qscjv 连锁，release.yml 逐靶硬门）

### 事实链（源码级，非假设）
- **NO_ASM 只在「windows host」分支设置**：btls-sys `build/main.rs:315-318`
  （源 = `C:\Users\Begonia\.cargo\git\checkouts\btls-e885d98e66dba79f\ab7f522\btls-sys`，
  即 Cargo.lock 钉的 `Be90nia/btls@ab7f522`）：
  `"windows" if config.host.contains("windows") => { … define("OPENSSL_NO_ASM", "YES") }`，
  原注释 *"not set up for cross-compiling using Visual Studio"*。
  → Linux/macOS/musl(zig) 路线**结构上没有关汇编的机制**（cmake 默认开，走 perl→GAS/.S，
  NASM 并非其消费者；macOS runner 镜像自带 nasm，同样不被消费）。
- **判别器实测**：本机 NO_ASM 时代的 11 个 `target/release/build/btls-sys-*/out/build/CMakeCache.txt`
  **全部含 `OPENSSL_NO_ASM:INTERNAL=YES`**；asm 开的构建该键根本不进 cache
  （`tools/build_boringssl_asm.py` 的 health() 用的就是同一判据，line 141-144）。

### release.yml 三层防线
1. **Windows**：既有 `setup-boringssl-asm` action（NASM 三级兜底，产不出即 hard-fail）
   → 预构建路线跳过 cmake → 不触发 NO_ASM。
2. **Linux**：加 `Install nasm (Linux)`（apt）——按派单对齐；已在注释写明 perl→GAS 路线
   不消费 NASM，装它是配方对齐 + 兜后手。macOS 不装（系统自带且不被消费，brew 只白耗时）。
3. **逐靶产物门 `Verify assembly BoringSSL (artifact gate)`**（Build 之后、冒烟之前，红即不发版）：
   - Windows 路线（无 CMakeCache 可查）：断言 `BORING_BSSL_PATH` 已导出 + 预构建三件齐 +
     复跑 `build_boringssl_asm.py --check`（CMakeCache 无 NO_ASM / NASM WORKS=1 / lib 体量）。
   - 非 Windows 路线：`ls -t target/<triple>/release/build/btls-sys-*/out/build/CMakeCache.txt`
     取最新一份，`grep OPENSSL_NO_ASM` 必须零命中（setup-boringssl 每次清残留目录，命中的必是本次构建）。
   - **「缺省 TLS 走 btls」已写进 release.yml 注释**（qscjv：xray-transport-tcp/register.rs
     缺省对齐 Go 的 Chrome uTLS hello；不配 fingerprint 的用户全部命中此路径）。

### 每靶处理表
| 靶 | 汇编路线 | 门 | 备注 |
|---|---|---|---|
| x86_64-pc-windows-msvc | 预构建（nasm） | `--check` 复跑 | 本机同序列实跑 PASS（下） |
| x86_64-unknown-linux-gnu | cmake（perl→GAS） | CMakeCache 判据 | runner 上 bash 原生，glob/find 形状已验证 |
| x86_64-unknown-linux-musl | cmake + zig cc（ASM 编译器=target 化 zig） | 同上 | **zig 的 ASM 未本机实测**（本机无 zig）——门会兜底：编不出汇编=红，显式失败不静默 |
| aarch64-apple-darwin | cmake（native） | 同上 | macOS host 无 NO_ASM 机制 |
| x86_64-apple-darwin | cmake（arm host 交叉） | 同上 | Rosetta 执行面已在该靶的互通冒烟里跳过，汇编门不依赖执行 |

### 验证（本机实跑）
1. `python -c "import yaml; …"` → ci/interop/release 三份 YAML 无异常。
2. **汇编构建序列本地实跑**（私有 `--dest target-Wave5CI/boringssl-asm`，不碰共享的
   `target/boringssl-asm/prebuilt`——多代理同树纪律）：
```
$ cmake -S target\boringssl-patched -B target-Wave5CI\build -G Visual Studio 18 2026 -A x64 -DCMAKE_ASM_NASM_COMPILER=D:\Project\tools\nasm.exe
…663 行 cmake+MSVC 输出，build_rc=0…
[ok] 预构建库已组装： target-Wave5CI\boringssl-asm
[ok] NASM: D:\Project\tools\nasm.exe
[ok] CMakeCache 无 OPENSSL_NO_ASM
[ok] CMAKE_ASM_NASM_COMPILER_WORKS=1
[info] 已组装 crypto.lib: 7051362 B（无汇编约 7,006,776 B）
```
   即 `build_boringssl_asm.py --check` 的完整 PASS 输出（rc=0）。
3. 产物符号佐证（llvm-nm crypto.lib）：`aesni_gcm_encrypt` / `chacha20_poly1305_open` /
   `chacha20_poly1305_open_sse41`（x86_64 纯汇编标记，无 C 同名回退）全 True。
4. **带汇编 vs 不带对比**：引用项目既有基线（bd jyipl，来源 = CLAUDE.md §5 与
   `.github/actions/setup-boringssl-asm` 描述）：vless+tcp+tls + chrome 指纹，
   NO_ASM 31.6 MB/s（cli CPU 18.8s）→ 带汇编 241.2 MB/s（2.48s），7.6×；
   REALITY 组 33.4 → 241.2。本机无 NO_ASM 产物可跑（Windows 产物均走预构建 asm 路线），
   未另跑 bench。

### 无法本机验证 / 上浮
- Linux/macOS/musl 三类门的**首跑**（判据本身已用本机 NO_ASM 残留 cache 正向验证：
  grep 命中即红）；musl 的 zig ASM 编译行为待首次 release run。
- 同暴露面未动（超出本票范围，**上浮 PM 裁决**）：`build-linux-release.yml`（生产 Linux
  构建走裸 cmake，asm 在但无产物门）与 `mobile.yml`（android/ios NDK 面）。
- 私有构建残留 `target-Wave5CI/{build,boringssl-asm}` 随本代理 target 目录战役结束清理。
