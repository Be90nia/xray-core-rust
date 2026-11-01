VERDICT: PASS（静态审计完成，零生产代码改动；核心结论：mobile.yml 双 job 只做到「能编译」——
Android 是 `--bin` 独立进程形态且**产物不落盘**，iOS 停在 `cargo check` 不链接；tun 的
device_stub 是**编译保形壳**而非接线：Go VpnService 模式的 fd 注入缝（`xray.tun.fd` env，
bd y93up）只实现在 `#[cfg(target_os = "linux")]`，**stub 不消费 env** ⇒ 移动宿主接不上；
btls-sys 的 android/ios cmake 分支本身健全（asm 全开，Windows 的 OPENSSL_NO_ASM 坑未外溢）；
aarch64 非"真回退"——RustCrypto `aes` 0.9 与 btls 在 arm64 均运行时探测并启用硬件 AES）

# ifnl9 — 移动端静态审计（零改动）

环境事实：本机 rustup 无 `aarch64-linux-android` / `aarch64-apple-ios` target、无 NDK、
无 macOS ⇒ 真编译不可行。所有"能否编译/链接"结论基于 CI 配置与源码形态的静态推理，
标 `[INFERENCE]`。

## §1 mobile.yml 逐 job 表

| job | runner | target | 命令 | 产物 | 链接 | 测试 |
|---|---|---|---|---|---|---|
| `android`（Android aarch64 build gate） | ubuntu-24.04 | aarch64-linux-android | `cargo build --workspace --bin xray --target aarch64-linux-android`（NDK r27c + `ANDROID_NDK_HOME`/CC/CXX/AR/CARGO_TARGET_…_LINKER 四件套 + setup-go + protoc + `.github/actions/setup-boringssl` REALITY 补丁树） | aarch64 ELF 可执行 | **是**（全量链接，含 btls-sys cmake 交叉编 BoringSSL） | 无（android 二进制不能在 host 跑，无模拟器） |
| `ios`（iOS aarch64 check gate） | macos-14 | aarch64-apple-ios | `cargo check --workspace --target aarch64-apple-ios` | **无** | **否**（check 不链接；iOS 链接期（dylib/符号/最小 OS 版本）零覆盖） | 无 |

- **iOS job 停在哪**：`cargo check` 是末步。check 之后没做的：链接成可执行/库、`cargo test`
  （test 要链接）、产物打包、`NEPacketTunnelProvider` 集成所需的 `cdylib`/FFI 导出面。
  唯一已覆盖的"编译之外"价值：check 也会执行 build.rs ⇒ btls-sys 的 ios cmake 分支
  （真编 BoringSSL for iphoneos）在 check 里被真实执行——iOS job 并非只查语法。
- 两 job 均**无 `upload-artifact`**（对比 `release.yml:206` / `build-linux-release.yml:80`）：
  Android 的 aarch64 可执行在 job 结束即丢弃——"编译门"过了，但**没有任何移动产物可取**。
- 触发面：`workflow_dispatch` + push 到 `master`/`main`/`dev`。当前波次在 feature 分支开发
  ⇒ **本树的 android/ios 编译门处于盲区** `[INFERENCE]`（除非手动 dispatch，无 CI 历史可查）。
- 文件头自带的降级预案（未启用）：若 btls-sys 交叉攻不下，降级为
  `check --exclude btls 依赖闭包` 并 echo 覆盖范围。

## §2 device_stub 门控矩阵

| 平台 | device 来源 | 依赖 | create 行为 | fd 注入（`xray.tun.fd`/`XRAY_TUN_FD`） |
|---|---|---|---|---|
| windows/macos/linux/bsd | `src/device.rs`（tun_rs 真实现，`lib.rs:49`） | tun-rs（`Cargo.toml:32-33` 按 `cfg(not(any(android, ios)))` 门控） | 直开设备；**Linux 上先查 env 继承 fd**（`device.rs:104-107` → `tun_fd::inherit_from_env`，bd y93up） | **Linux 实现**（`tun_fd.rs:107-108` `#[cfg(target_os = "linux")]`：fd 校验 TUNGETIFF + 非阻塞 + 可选清 offload → `AsyncDevice::from_fd` 接管）；非 Linux 设 env = `refuse_unsupported` 显式报错 |
| **android** | `device_stub.rs`（`lib.rs:53-55` `#[path]` 占用同一 `crate::device` 路径） | 无 tun-rs | **恒 `DeviceCreateFailed`**（文案注明 Android=VpnService 宿主注入） | **无任何分支**——stub 不读 env ⇒ 宿主就算把 fd 递进来也接不上 |
| **ios** | 同上 device_stub.rs | 无 tun-rs | 同上恒 Unsupported（文案注明 iOS=NEPacketTunnelProvider） | 同上无 |

要点：
1. **门控本身是"保形"不是"接线"**：stub 保持 `TunDevice` 类型签名与 `Tun` trait 实现可编译
   （两个 `#[cfg(test)]` 契约测试锁签名与 Unsupported 语义——注意它们只在 **host 平台**的
   `cargo test` 跑，android/ios target 的 test 在 CI 从不执行 `[INFERENCE]`：两 job 均无 test 步）。
2. **Android 的 VpnService 注入接口 = 空壳**：没有任何 JNI/FFI 导出、没有 `from_fd`/fd 参数
   进程接口；Go 的模式（`config.rs:64` 注释自述："fd 通过环境变量 `XRAY_TUN_FD` 传入"）
   在 Rust 侧只做完了 **Linux** 一条腿。Android 同为 Linux 内核，`TUNGETIFF`/`TUNSETOFFLOAD`
   ioctl 对 VpnService 建的 fd 同样可用 ⇒ 把 `tun_fd.rs`/`device.rs` 的继承分支从
   `cfg(target_os = "linux")` 放宽到 `cfg(any(target_os = "linux", target_os = "android"))`
   是成本最低的真接线（**只报告不实施**，交 PM）。
3. **iOS 的 NEPacketTunnelProvider 注入接口 = 空壳且更远**：NE 的 TUN fd 是 utun，**没有
   `TUNGETIFF` ioctl**，`tun_fd.rs` 的校验逻辑不能照搬，需要另写 apple 变体校验
   （fd 属性检查）`[INFERENCE]`；且 iOS 沙盒禁 exec ⇒ 进程形态不可行，必须 cdylib/FFI（见 §3）。
4. 门控错位风险检查：`plugin.rs`/`inbound.rs`/`netstack.rs` 等下游只 `use crate::device::TunDevice`
   （门控保住了类型路径），**未发现第二处平台假设**；tun inbound 在 android/ios 上启动即
   `DeviceCreateFailed`（fail-visible，不静默）——与"stub 未接线"现状自洽。

## §3 产物形态结论

- 全仓 `crates/*/Cargo.toml` 与根 `Cargo.toml`：`crate-type` 声明 **0 处** ⇒ 无 `cdylib`、
  无 `staticlib`；`#[no_mangle]` 导出：xray-cli/xray-core **0 处**。
- mobile.yml android 打的是 `--bin xray` ⇒ **产物形态 = 独立可执行进程**（aarch64 ELF）。
- 移动宿主怎么接：
  - **Android：进程形态可行且是既定语义**——宿主 App（Java/Kotlin）VpnService 建 TUN fd →
    `ProcessBuilder` 启动 xray 二进制（标准做法：二进制改名 `libxray.so` 放 `jniLibs/arm64-v8a/`
    规避 targetSdk 29+ 禁 exec 自家 files 目录 `[INFERENCE]`：Android 生态通行做法）→ 继承 fd +
    设 `XRAY_TUN_FD`。**前提 = 补 §2.2 的 stub fd 分支，当前接不上**。Go xray 在 Android 上
    同为进程形态（`libgojou.so` 除外）——语义对齐。
  - **iOS：进程形态不可行**（NEPacketTunnelProvider 扩展沙盒禁 exec）⇒ 必须走
    cdylib/staticlib + FFI（Swift 持有 fd 后调 Rust 启动入口），这一整块（crate-type、
    `#[no_mangle]` 启停 API、回调/日志桥）**完全不存在**。
- 产物去向：android job 无 upload-artifact ⇒ **当前移动端没有任何可分发的产物形态**；
  release.yml 矩阵 5 个桌面 target 也不含 android/ios（既有审计 G-22 已登记）。

## §4 btls-sys android/ios 构建分支与坑

对象：git dep `Be90nia/btls @ ab7f522`（Cargo.lock 钉定），`btls-sys/build/main.rs`（888 行，
`build = "build/main.rs"` 形态）。交叉判定 `should_use_cmake_cross_compilation`（:20-29）：
android 恒走 cmake 交叉；apple 仅当 **host 非 `-darwin`**（CI macos-14 host 是
aarch64-apple-darwin ⇒ iOS 构建不走 CMAKE_CROSSCOMPILING 定义块，但仍进 ios 平台参数臂）。

| 平台 | 分支（行号） | 关键定义 | 已知坑 |
|---|---|---|---|
| android | :265-285 | `ANDROID_NDK_HOME` **必须**（缺失即 panic）；`ANDROID_ABI=arm64-v8a`（aarch64）；NDK `android.toolchain.cmake`；`CMAKE_SYSTEM_VERSION=21`；`CMAKE_ANDROID_STL_TYPE=c++_shared`；bindgen 用 NDK prebuilt sysroot（:415-435，找不到仅 warning "try anyway"）；C++ 链接库 `c++`（:598） | min API 钉 21（NDK r27c 已弃 API<21，自洽）；`c++_shared` ⇒ 产物**运行期需要 libc++_shared.so**——以 `--bin` 独立进程分发时必须随包携带或改 `c++_static` `[INFERENCE]`（当前 mobile.yml 无处理步骤） |
| ios | :294-319 | `CMAKE_OSX_SYSROOT=iphoneos`（sim 变体另列）+ `CMAKE_OSX_ARCHITECTURES=arm64`；`-fembed-bitcode` + x86_64 模拟器 `-target` cflag；bindgen 走 `xcrun --show-sdk-path --sdk iphoneos`（:398-414） | **无 OPENSSL_NO_ASM** ⇒ asm 全开（iOS 不踩 Windows 那个坑）。风险点：`-fembed-bitcode` 在新版 Xcode 已弃用（no-op，无害）`[INFERENCE]`；macos/ios/windows 三平台 **symbol prefixing 被跳过**（:668-673）⇒ 无符号冲突防护，与系统 SSL 库共存时靠动态链接隔离 |
| windows（对照） | :325-330 | host 含 windows 的交叉/原生路径 `OPENSSL_NO_ASM=YES`（"Disable assembly support so that it at least builds"） | 既有 bd jyipl 的坑在本版 btls-sys 位于 **windows 臂**；**android/ios 臂无此定义** ⇒ Windows 的 NO_ASM 历史坑**未外溢**到移动双平台 |

结论：btls-sys 的移动双分支**形态健全**（官方支持路线：boringssl 对 android/iOS 均官方支持 +
NDK/Xcode 工具链文件）。剩余不确定性在「REALITY 补丁树 × NDK cmake」的实编历史——CI 若从未
绿过 mobile.yml（§1 触发面盲区），android 臂也只是"纸面健全" `[INFERENCE]`。

## §5 aarch64 加密回退分析

- **静态特性门**：`.cargo/config.toml` 的 rustflags（`target-cpu=x86-64` + sse4.1/4.2/popcnt）
  挂在 `cfg(target_arch = "x86_64")` ⇒ aarch64 交叉编译天然不命中（mobile.yml env 注释亦自述）。
  全仓 **无 `#[cfg(target_feature = "aes")]`** 或等价静态 AES 门（grep 0 命中）——不存在
  "x86 有、arm 没编进去"的静态不对称。
- **RustCrypto `aes`（0.9.3，xray-crypto/xray-proxy-ss/xray-proxy-vless/xray-transport 用；
  vmess 用 0.8 同设计）**：`src/lib.rs:173-174` `cfg(all(target_arch = "aarch64", not(miri)))`
  下编译 **aarch64 AES 后端**并用 `cpufeatures::new!(features_aes, "aes")` **运行时探测**
  ARMv8 Crypto Extensions，命中即 `backends::aarch64_aes`（:243）。⇒ 真机（全部 arm64 手机
  均有 crypto extensions）走**硬件 AES 指令**，**不是真回退**；软 AES 仅出现在无扩展的
  老 aarch64 CPU（罕见），正确性不受影响。
- **ring 0.17**（AES-GCM 主力，`xray-crypto/src/aead.rs:42`）：aarch64 的 ARMv8 汇编实现
  常编 + 运行时 CPU 探测门——同上，非回退 `[INFERENCE]`：ring 的既有标准行为。
- **btls-sys**（REALITY/指纹链路）：§4 已证 android/ios 臂 asm 全开 ⇒ BoringSSL 在移动双平台
  编进汇编版 AES/ChaCha20，非纯 C 回退。
- 结论：**aarch64 不存在"加密真回退"**；与 x86 的差异只是"无 SSE4 静态向量化加速的
  memcpy 类代码"（bd f39e 实测的 4.5× 差距来自 SSE4 对拷贝向量化，与加密原语无关），
  移动端若做吞吐基线需单独测 `[INFERENCE]`。

## §6 缺环境清单（真做移动端验证需要什么）

**Android（本机可补，纯 Windows 也可行）**：
1. `rustup target add aarch64-linux-android`（几十 MB）。
2. Android NDK **r27c**（CI 钉版，`nttld/setup-ndk@v1` 同版）：下载 ~600MB，解压后 ~2.5GB。
3. Go（BoringSSL cmake 生成步骤需要）+ protoc。
4. REALITY 补丁 BoringSSL 源树：`tools/inject_btls_cache.py` 或 `xray-stress/docker/setup_boringssl.sh`
   同款配方（btls-sys 消费 `BORING_BSSL_SOURCE_PATH`）。
5. `ANDROID_NDK_HOME` + CC/CXX/AR/CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER 四件套
   （照抄 mobile.yml "Set NDK cross env" 步）。
6. 磁盘预估：NDK 2.5GB + boringssl 构建 1-2GB + cargo target（--bin 全 workspace）3-6GB
   ⇒ **预留 ≥ 10GB** `[INFERENCE]`。
7. （可选）真机/模拟器跑二进制：模拟器需 Android Studio AVD（另 ~6GB）；仅"能编译+能链接"
   不需要。

**iOS（本机 Windows 不可行，必须 macOS + Xcode）**：
1. macos-14 级机器 + Xcode（含 iOS SDK；Xcode 安装 ~12GB，含组件 ~20GB）。
2. `rustup target add aarch64-apple-ios`；`brew install go protobuf`。
3. 磁盘预估 ≥ 25GB `[INFERENCE]`。
4. 若要 NEPacketTunnelProvider 集成验证：另需 Apple 开发者账号 + 真机（NE 的 TUN 权限
   模拟器不可用）——超出"编译门"范畴。

## §7 结论与建议

**现状一句话**：移动端 = 「编译门有了，集成缝没接，产物不落盘」。
- Android 门是全量链接的真编译（含 btls-sys 交叉），但产物即弃、且 `--bin` 进程形态的
  **fd 注入在 stub 里缺失**——宿主接不上。
- iOS 门是 check-only，不覆盖链接期；进程形态在 iOS 不可行，cdylib/FFI 工程为零。

**建议优先级**（均未实施，交 PM 拍板）：
1. **P1｜补 stub 的 fd 接管分支**：把 bd y93up 的 `tun_fd::inherit_from_env` + `device.rs`
   继承路径从 `cfg(target_os = "linux")` 放宽到 `+ target_os = "android"`（TUNGETIFF ioctl
   在 android 内核可用，tun_fd.rs 的校验逻辑可原样复用 `[INFERENCE]`）。这是一处 `cfg` 级
   改动，做完后 `--bin` 进程形态即可被 VpnService 宿主真实驱动——本票"半接线"的准确补全。
2. **P1｜mobile.yml android job 加 `upload-artifact`**：一行步骤，否则"编译门"过了也没有
   任何可取产物（顺带把产物形态决策固化：先 `--bin`，等 iOS 再议 cdylib）。
3. **P2｜iOS 链接期覆盖**：在 check 之后加一步最小链接（`cargo build -p xray-xudp` 之类
   小 crate 的 `--target aarch64-apple-ios` 构建即可触达链接器），成本远低于全量 build。
4. **P3｜cdylib/FFI 工程**（iOS 必需、Android 可选）：独立立项——crate-type、启停 API、
   日志/回调桥、fd 交接 API，是大工程不适合顺手做。
5. **P3｜mobile.yml 触发面**：feature 分支不触发 ⇒ 波次开发期编译门盲区；可加
   `pull_request` 路径过滤触发（与 PM 现有 CI 策略合并考虑）。
6. **不做**：本票不装 NDK/不真编译（环境事实）；不动 `tun_fd.rs` 的 Linux-only 校验语义；
   不把 `network=quic` 类 Go 移除特性问题引入移动面。
