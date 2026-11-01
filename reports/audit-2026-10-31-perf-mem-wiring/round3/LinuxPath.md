# Round 3 - LinuxPath：Linux-only 生产路径 + 验证覆盖缺口 + 接线完整性

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 视角：用户生产 = Linux VPS；本机开发 = Windows；CI = Linux/Windows/macOS 混合
- **本轮首次在真 Linux 内核实 Linux 分支**（WSL `ubuntu-xray`，kernel `6.6.87.2-microsoft-standard-WSL2`，root + `/dev/net/tun`）——前两轮的「Linux 专属面不可本机实测」缺口本轮部分关闭
- 只读审计，零产品代码改动

---

## 0 一句话结论

**Linux-only 分支的编译与单测覆盖其实比预期好（CI `test` job 跑在 ubuntu-latest，Linux cfg 分支真编译真跑）**；真正的缺口在三处：

1. **特权语义面（CAP_NET_ADMIN / root）在 CI 全无覆盖**——TPROXY / fakeudp / SO_MARK / IP_TRANSPARENT 在 GitHub runner（非 root）上永远走「权限错误」分支，等于没测；
2. **32/32 真实节点 e2e 只在 Windows 跑**，CI 无任何 Linux 端到端节点互通；
3. **Linux 产物只有「编译过 + `xray version` 冒烟」，无任何 Linux 上的功能验证**。

**并在真 Linux 上实测出 1 个 blocker 级缺陷**：`xray-proxy-dokodemo` 的 TPROXY 契约测试在 **root 下必 panic**（`fake_udp` 内 `UdpSocket::from_std` 需 Tokio reactor，而该测试是裸 `#[test]`）——**同一测试在 CI（非 root）绿、在生产 Linux VPS（root）红**。这是「测试写错了」而非「产品错了」，但它精确暴露了第 1 条缺口：CI 根本没跑到特权分支。

---

## 1 Linux-only 生产功能清单（18 项，四列验证状态）

图例：**生产可达** = 生产主路 `xray run -c` 可触发；**本机(Win)** = Windows 编译面；**测试** = 仓内是否有断言；**CI 覆盖** = 是否在 CI 的 Linux job 里真跑到（含是否真跑到特权分支）。

| # | 功能（描述） | 生产可达 | 本机(Win) | 测试 | CI 覆盖 | 未验证风险 |
|---|---|---|---|---|---|---|
| 1 | **splice(2) 零拷贝转发**（`xray-transport/src/splice.rs`，`bridge_link_with_stream_downlink_splice`） | 是（freedom 出站 + 裸 TCP 入站） | 否（cfg 出空模块，恒回退池化泵） | 是（6 单测 + core e2e） | 是（ubuntu `cargo test --workspace`） | **低**。本轮真 Linux 实测：6/6 绿 + core e2e 绿（`integration_splice_admitted_two_stack_echo`），内核 splice 真跑 |
| 2 | **SO_ORIGINAL_DST 透明代理（TCP REDIRECT）**（`sockopt/linux.rs:302` + `xray-core/src/inbound.rs:1592`） | 是（dokodemo `followRedirect=true`） | 否（`get_original_dst` 返回 Unsupported） | 是（31 个 dokodemo 测，含「无 orig dst 拒连」e2e） | 部分（只覆盖**非** REDIRECT 分支） | **中**。仓内**无 iptables REDIRECT 真链路测试**——`SO_ORIGINAL_DST` 真实取值路径（内核 conntrack 已改写 dst）从未被断言 |
| 3 | **UDP TPROXY（IP_TRANSPARENT + IP_RECVORIGDSTADDR + cmsg 原始目标）**（`xray-transport/src/udp/hub.rs:344-526`） | 是（dokodemo UDP `followRedirect`） | 否（恒 `recv_from` 普通面） | **零测试**（`bind_udp_tproxy_linux`/`parse_orig_dst_from_cmsg` 无任何用例） | 仅编译 | **高**。整条 TPROXY UDP 收包链（`recvmsg` + ancillary data 解析 + `parse_orig_dst_from_cmsg`）**零断言** |
| 4 | **fakeudp 伪造源地址回包**（`xray-proxy-dokodemo/src/fakeudp.rs`，`IP_TRANSPARENT` + bind 非本机地址） | 是（dokodemo UDP TPROXY 回包） | 否（恒返 `!linux` 错误） | 有但**写法错**（见 F1） | 部分（CI 非 root 只走 Err 分支） | **高**。真 Linux root 下**测试本身 panic**（F1）；生产路径 `fake_responder` 的 Ok 分支从未被断言 |
| 5 | **TUN 设备真创建 + vnet_hdr 剥/垫 + GRO 批收**（`xray-proxy-tun/src/device.rs`） | 是（`inbound:tun`） | 部分（走 wintun，不同实现） | 是（`inherit_vnet_tests` 2 例 + device 2 例） | 是（Linux job 编译+跑） | **低-中**。本轮真 Linux：**13/13 绿，真建了 `/dev/net/tun` 设备**，含 vnet_hdr 继承往返。CI 上 root 不足时走 SKIP 分支（静默绿） |
| 6 | **TUN fd 继承（`xray.tun.fd` env + `IFF_VNET_HDR`）**（`xray-proxy-tun/src/tun_fd.rs`） | 是（宿主注入 fd 模式） | 否（`refuse_unsupported` 明确报错） | 是（Linux-only 2 例） | 是 | **低**。本轮真 Linux 绿 |
| 7 | **TUN 系统路由接管（`ip route` + metric 1）**（`sysroute/executor.rs:144`） | 是（`autoSystemRoutingTable`） | 否（走 `route.exe`/`netsh`） | 仅**命令渲染串**断言（`Recording` 替身） | 是（渲染面） | **中**。真执行面（`apply_exec` 真实 spawn `ip route`）**无测试**——需 root + 改主机路由，CI 无条件跑不得 |
| 8 | **TUN 系统 DNS 接管（`resolvectl` + 防环路验证）**（`sysroute/executor.rs:219`、`dns_verify.rs`） | 是（`autoSystemDnsToGateway`） | 否（走 `netsh`） | 仅渲染串 + 纯函数验证 | 是（渲染面） | **中**。`resolvectl` 三条命令真执行未测；`dns_verify` 真探针（core 接线）无测试 |
| 9 | **DNS UDP `recvmmsg` 批收**（`xray-core/src/inbound.rs:2761`，**仅 linux+gnu**） | 是（DNS 入站） | 否（走 `recv_from` 单收） | **零测试** | 仅编译 | **中**。`DNS_UDP_RECV_BATCH=16` 批收路径无断言；且 **musl/uclibc 走的是另一条实现**，两版语义差异无对拍 |
| 10 | **Linux sockopt 全族**（`SO_MARK` / `SO_BINDTODEVICE` / `IP_TRANSPARENT` / `TCP_FASTOPEN` / `TCP_CONGESTION` / `TCP_WINDOW_CLAMP` / `TCP_USER_TIMEOUT` / `TCP_MAXSEG` / `SO_REUSEPORT` / `SO_RCVBUFFORCE`）（`sockopt/linux.rs`） | 是（出/入站 streamSettings.sockopt） | 部分（有 Windows 对应项） | 多为**平台无关**测试（断言配置解析，非真实 setsockopt 生效） | 部分 | **中**。`apply_tproxy_outbound_returns_err_for_unprivileged` **显式断言非特权下失败** -> 特权下成功路径无断言。`SO_MARK`/`SO_BINDTODEVICE` 无任何测试 |
| 11 | **QUIC UDP GSO（`UDP_SEGMENT`）+ 接收 GRO**（`xray-transport-quic/src/udp_gso.rs`） | 是（hysteria2/tuic QUIC） | 否（恒 1 段） | 是（Linux-only `gso_probe_reports_kernel_capability`） | 是 | **低**。本轮真 Linux 绿（6/6）。但断言 `segs > 1` **依赖内核 >=4.18**——旧内核 CI 会红 |
| 12 | **listen backlog 读 `/proc/sys/net/core/somaxconn`**（`system_listener.rs:57-92`） | 是（全部 TCP 监听） | 否（恒 `0x7fffffff`） | 是（3 例：解析语义 + 平台值） | 是 | **低**。本轮真 Linux 绿（读得 4096） |
| 13 | **UDS 入站 9 形态（5 裸流 + 4 transport）**（`xray-core/src/arm_builders/inbound.rs:953-1250`、`uds_tests.rs`） | 是（监听路径为 unix socket） | 否（`spawn_unix_inbound` 拒绝臂） | 是（`uds_tests.rs` 9 变体真起监听 + 5 个 e2e） | 是 | **低**。本轮真 Linux：`uds_table_forms_spawn_and_listen` 绿 |
| 14 | **gRPC commander over UDS**（`xray-app-commander/src/commander.rs:585`） | 是（api listen=unix path） | 否（明确报错 + next-step 指引） | 无 UDS 侧测试 | 仅编译 | **中**。Unix listen 绑定+serve 未测 |
| 15 | **Webhook over Unix socket**（`xray-app-router/src/webhook.rs:244`） | 是（router webhook url=`/path`） | 否（明确报错） | 仅 URL 解析测试 | 仅编译 | **中**。UnixStream connect + HTTP 握手未测 |
| 16 | **`/proc/self/status` 取线程数/RSS**（`xray-app-metrics/src/debug.rs:39`） | 是（metrics debug 输出） | 否（字段省略） | 无 | 仅编译 | **低**（观测面，非数据面） |
| 17 | **`/proc` 进程归属反查（路由条件 `process`）**（`xray-app-router/src/condition.rs:601`） | 是（路由条件命中进程） | 否 | 仅纯解析函数测试 | 仅编译 | **中**。`/proc/net/tcp` 扫 inode + 扫 `/proc/*/fd` 的真路径未测（需本机有真 socket） |
| 18 | **Unix abstract socket 路径补齐（108 字节）**（`inbound.rs:4687`、`xray-proxy-trojan/src/plugin.rs:261`） | 是（`@abstract` 形式监听） | 否 | 仅纯函数 | 仅编译 | **低-中**。硬编码 108 已有 `ponytail:` 注释标注；真 abstract bind 未测 |

**未实现的 Linux-only 机制**（grep 全仓零命中，供对照）：`io_uring`、`eBPF`、`netns`、`membarrier`、`prctl`、`rlimit` 自调、`SO_ZEROCOPY`、`sendmmsg`（除 recvmmsg）、`IP_TRANSPARENT` 之外的 `tcplinux` 系列。**WireGuard 走纯用户态 smoltcp netstack**（`xray-proxy-wireguard/src/netstack.rs`），**不依赖任何 Linux 内核模块** -> 无 Linux-only 风险。

---

## 2 CI 门覆盖矩阵

| 门 | workflow / job | 平台 | 实际跑什么 | 能发现什么盲区 |
|---|---|---|---|---|
| Format | `ci.yml/fmt` | ubuntu-latest | 逐 workspace member `cargo fmt -p --check` | 纯排版 |
| Clippy | `ci.yml/clippy` | ubuntu-latest | `cargo clippy --workspace --all-targets -- -D warnings` | **Linux cfg 分支的 lint**（含死代码/不可达） |
| Build x3 | `ci.yml/build` | ubuntu-22.04 / windows / macos-aarch64 | `cargo build --workspace --release` + debug；上传二进制 | 跨平台**编译**（musl 不在内） |
| **Test** | `ci.yml/test` | **ubuntu-latest** | `cargo test --workspace` + `--release`（**非 root**，跑前 `sysctl` 抬 `rmem_max`） | **Linux cfg 分支真编译真跑**（含 splice/UDS/dokodemo/TUN 渲染面）。盲区：**所有 CAP_NET_ADMIN 路径**（TPROXY/fakeudp/SO_MARK/IP_TRANSPARENT 恒走权限错误分支）；无 Linux 端到端节点互通 |
| Test (windows tun) | `ci.yml/test-windows-tun` | windows-latest | `cargo test -p xray-proxy-tun --all-targets` | Windows TUN/wintun 面。**Linux TUN 无对称 job**（Linux 由 workspace job 顺带覆盖） |
| Parser Parity | `ci.yml/parser-parity` | ubuntu-latest | Go v26.9.9 与 Rust **mixed 入站解析**差对拍（HTTP 38 + SOCKS5 19） | 入站解析器语义漂移。**不覆盖数据面** |
| Interop | `interop.yml/interop` | **ubuntu-24.04** + macos-14 | `cargo test --workspace --lib` + `dist/interop_ci.py`（Rust<->Rust 12 + Go->Rust 12 + Rust->Go 12 + extra 18/21） | **唯一在 Linux 上跑的真协议互通**（54~57 测）——但只覆盖 6 基础 + 6 新协议，**无 dokodemo/TUN/TPROXY/wireguard/splithttp-UDS** |
| Stress | `stress.yml/stress` | macos-14 x2 / ubuntu-latest x2 / windows x1（**仅 `workflow_dispatch`**） | `xray-stress` 12 场景长跑 + fd/RSS 斜率门 | 连接/会话资源回收。**手动触发，不阻塞主干** |
| Build Linux Release | `build-linux-release.yml` | ubuntu-24.04 host + **ubuntu:22.04 容器**（glibc 2.35） | PGO 三段构建 + `cargo test -p xray-reality --test reality_tls_smoke` + `file` 验产物 | **生产 Linux 产物在此产出**；但只跑 1 个 REALITY 冒烟测，**无 Linux 功能验证** |
| Musl Probe | `musl-probe.yml` | ubuntu-22.04（**仅 `workflow_dispatch`**） | `cargo zigbuild --release -p xray-cli --target x86_64-unknown-linux-musl` + `./xray version` | musl 能否编出。仅 `version` 冒烟；且 **musl 走 `recv_from` 回退**（recvmmsg 仅 gnu） |
| Release | `release.yml/build` | ubuntu-22.04 / windows / macos x2 | 5 目标产物构建 + 打包发版 | 发版产物。**零测试** |
| Fuzz Smoke | `ci.yml/fuzz` | ubuntu-latest（**仅 `workflow_dispatch`**） | 3 靶 x 30s（kcp/ss2022/vless） | 崩溃。**手动触发，不阻塞 PR** |
| Proto Drift / Asset Gate | `ci.yml` | ubuntu-latest | protos 镜像漂移 / geodata 资产 | 配置资产面 |

### 产物是否含 Linux 二进制

**含**。两条 Linux 产物线：

- **`build-linux-release.yml`** -> `xray-linux-gnu` artifact（PGO，**ubuntu:22.04 容器 -> glibc 2.35**，兼容生产 Debian 12 glibc 2.36）。这是**生产实际部署的产物**。
- **`release.yml`** -> `xray-linux-amd64`（ubuntu-22.04，glibc 2.35）+ `xray-linux-amd64-musl`（zig 静态，OpenWrt 系）。

**两条产物线互不验证**：`build-linux-release` 的 PGO 产物跑 1 个 REALITY 测；`release.yml` 的产物**一个测都不跑**（含发版资产本身）。

---

## 3 Findings

| # | 严重度 | 位置 | 问题 | 修法方向 |
|---|---|---|---|---|
| **F1** | **blocker** | `crates/xray-proxy-dokodemo/tests/plugin_contract.rs:167` + `src/fakeudp.rs:60` | **真 Linux root 下必 panic**：`tproxy_gate_is_runtime_semantics_not_compiled_away` 是裸 `#[test]`，调 `fake_udp()` -> `fake_udp_linux` -> `tokio::net::UdpSocket::from_std`（需 Tokio reactor）-> `panic!("there is no reactor running")`。**实测：root = FAILED，nobody = ok**（非 root 时 `IP_TRANSPARENT` setsockopt 先 EPERM 失败，永不到 `from_std`）。<br>=> **CI 绿是假绿**：GitHub runner 非 root，永远走 EPERM 分支；**生产 Linux VPS 通常 root -> 同一测试必红**。 | 测试改 `#[tokio::test]`；或 `fake_udp` 的 `from_std` 前先探测 reactor；或把「需 runtime」明确写进函数契约（生产侧 `fake_responder` 在 async 上下文，**产品侧无 bug**）。**另需加一条 CI Linux 特权 job**（见 §4 第 1 条）否则特权分支永远没测 |
| **F2** | 建议 | `crates/xray-transport/src/udp/hub.rs:344-526` | **UDP TPROXY 整条链零测试**：`bind_udp_tproxy_linux` / `start_recv_loop_tproxy_linux` / `parse_orig_dst_from_cmsg` / `is_ipv6_origdst_cmsg` 无任何用例。Go 对照面（`dokodemo.go:158-176` fakeudp 回包）也是生产 Linux 透明代理的**唯一 UDP 出向**。 | 补 Linux-only 单测：构造 `IP_RECVORIGDSTADDR` cmsg 字节喂 `parse_orig_dst_from_cmsg`，断言 v4/v6 解析 + 非首头忽略 + 长度不足拒；`bind_udp_tproxy_linux` 在无特权下断言 EPERM 而非 panic |
| **F3** | 建议 | `crates/xray-core/src/inbound.rs:2761-2930` | **DNS `recvmmsg` 批收零测试**，且与 musl/uclibc 的 `recv_from` 回退是**两套实现无对拍**。生产 Linux 是 gnu -> 走批收；OpenWrt musl -> 走单收。语义差异（批收时 `MSG_TRUNC` 丢弃、包序、channel 满丢包）无断言。 | 补 Linux-gnu-only 单测：起本地 UDP echo，灌 >16 个 query，断言收全 + 不重复；musl 回退面用纯函数对拍 |
| **F4** | 建议 | `crates/xray-transport/src/sockopt/linux.rs`（`set_so_mark` / `set_so_bindtodevice` / `set_ip_transparent`） | **`SO_MARK` / `SO_BINDTODEVICE` / `IP_TRANSPARENT` 三项无测试**。现有 `apply_tproxy_outbound_returns_err_for_unprivileged` **断言的是「非特权下失败」**——即 CI 恰好只测了失败分支。`SO_MARK` 是 iptables fwmark 策略路由的唯一入口，运维改路由规则的依赖点。 | 补「特权下成功 / 非特权下 EPERM」双向断言（需特权 job）；`SO_MARK` 至少加 `setsockopt` 参数回读断言（socket2 无 getter -> raw getsockopt） |
| **F5** | 建议 | `crates/xray-proxy-tun/src/sysroute/mod.rs`（`prepare` / `apply_changes_exec` / `revert`） | **TUN 真实系统变更面（真 spawn `ip route` / `resolvectl`）零测试**——仓内只断言「渲染出的命令字符串」。真执行需 root + 会改主机路由，CI 无条件跑不得 => **该面在 Linux 生产上的正确性完全未验证**（且失败会「宁可无 TUN」拒启动，属可见失败面）。 | 加 `#[ignore]` 真机测（需 root + 隔离 netns）：起临时 TUN -> `apply_exec` -> `ip route show` 断言 -> `revert_exec` -> 断言净空。人工/手动 job 跑 |
| **F6** | 建议 | `.github/workflows/ci.yml`（`test` job，line 148-176） | **Linux 特权面零覆盖**：整个 CI 无任何 job 以 root/CAP_NET_ADMIN 跑测试。后果已实证为 F1（测试在特权下红、非特权下绿——即 CI 门与生产态**相反**）。同类面还有 F2/F4/TUN 真实执行。 | 新增 `test-linux-privileged` job：`sudo -E` 跑特权标记的 Linux-only 测试子集（或给 runner `setcap cap_net_admin+ep` / 用 `sudo`）；并把 F1 的测试改成特权下也绿 |
| **F7** | 建议 | `.github/workflows/`（全仓 grep `run_full32`） | **32/32 真实节点 e2e 不在 CI**：唯一调用方 `tools/night_probe32_ci.py` 跑 **Windows CI 二进制**（`dist/run_full32.py`），且是本机脚本非 CI。=> **Linux 产物从无真实节点互通验证**；CI 的 `interop_ci.py` 只覆盖 6+6 协议，不含 dokodemo/tun/TPROXY/wireguard。 | 1) Linux job 跑 `interop_ci.py`（已做）-> 2) 把 `run_full32.py` 的 Linux 变体接入 Linux CI（或独立手动 job），用 `xray-linux-gnu` artifact 跑真实节点 |
| **F8** | 建议 | `.github/workflows/release.yml`（build job，无 test 步） | **发版 Linux 产物零测试**：5 目标产物构建完直接上传。`build-linux-release.yml`（PGO 线）至少跑了 1 个 REALITY 冒烟，`release.yml` 线一个都没跑 -> 两条线产物质量无对等门。 | release.yml 的 linux-gnu / linux-musl 目标加「产物冒烟」步（`xray version` + 1 个协议回环），或直接复用 `build-linux-release` 的 PGO 产物 |
| **F9** | 吹毛 | `crates/xray-transport-quic/src/udp_gso.rs:138-147` | `gso_probe_reports_kernel_capability` 硬断言 `segs > 1`（内核 >=4.18）-> 任何 <4.18 内核的 CI/自建 runner 会**恒红**（与本仓功能无关的环境假设）。 | 降级为「>=1 恒成立；>1 则打 info」，或按内核版本 gate |
| **F10** | 吹毛 | `crates/xray-proxy-dokodemo/src/server.rs:66-83`（`build_destination_ex`） | 该函数族全 `#[allow(dead_code)]`（注释：「待 transparent/redirect 接线票启用」），但**生产主路走的是 `xray-core/src/inbound.rs` 的 `serve_dokodemo`**（`arm_builders` -> 走 core）。=> 插件面 `DokodemoServer` 的 dest 构造是**影子实现**。非 Linux 平台两处语义不同：core 面 **拒连**，插件面 **静默 fallback 到 rewrite_address**（`server.rs:75-81` 自己写了 warn）。当前插件面不接生产，故为低危，但两处语义分叉已成事实。 | 二选一：1) 删插件面的 `build_destination*` 族（core 是唯一源）；2) 让插件面复用 core 的 `resolve_dokodemo_tcp_dest`。**勿**两边各留一份语义 |

---

## 4 上线 Linux 前必须补的验证（按风险排序，<=8 条，每条给最小可执行命令）

> 环境：WSL `ubuntu-xray`（root + `/dev/net/tun`）或任一 root Linux。需 `BORING_BSSL_ASSUME_PATCHED=1` + `BORING_BSSL_SOURCE_PATH=<patched boringssl>`（否则 `xray-tls` 编不过，见 §5）。

**1. 特权态 Linux 回归（最高优先——直接暴露 F1，且是 F2/F4/TUN 真执行的前置）**

```bash
# root 下跑全 workspace；当前必红于 dokodemo plugin_contract（F1）
sudo -E env PATH="$PATH" CARGO_TARGET_DIR=/root/target \
  cargo test --workspace --all-targets 2>&1 | tee /root/linux-root-full.log
# 判据：0 failed；且日志含 dokodemo plugin_contract 的 ok（而非 FAILED）
```

（若 CI 化：在 `ci.yml` 新增 `test-linux-privileged` job，`runs-on: ubuntu-latest` + `sudo -E cargo test ...`；或给 runner 加 `setcap cap_net_admin+ep`）

**2. UDP TPROXY 收包链真测（F2，本轮唯一「Linux-only 生产数据面 + 零断言」）**

```bash
# 新增 Linux-only 单测后跑；当前无此测试 = 覆盖缺口本身
sudo -E cargo test -p xray-transport --lib -- tproxy --nocapture
# 手工探针（无需写码）：确认本机内核 IP_RECVORIGDSTADDR 可用
sysctl net.ipv4.ip_nonlocal_bind; ip tuntap add dev xrayprobe mode tun
```

**3. Linux 产物跑真实节点 32/32（F7——当前 32/32 只跑 Windows 二进制）**

```bash
# 用 CI 产出的 Linux 产物（非本机 Windows 产物）
python3 dist/run_full32.py --bin ./xray-linux-gnu --uri-file <uris> --work /tmp/w32 --url https://www.youtube.com/
# 判据：32/32 [PASS]，0 [FAIL]
```

**4. TUN 真系统变更（路由 + DNS 接管 + 回滚）验证（F5——仓内零真执行覆盖）**

```bash
# 隔离 netns 内跑，避免改宿主路由
ip netns add xp && ip netns exec xp ./xray-linux-gnu run -c tun_sysroute.json
ip netns exec xp ip route show        # 断言 TUN 路由在位 + metric 1
ip netns exec xp resolvectl status xray0
ip netns exec xp ./xray-linux-gnu --stop && ip netns exec xp ip route show | grep -c xray0  # 断言回滚净空
```

**5. dokodemo 透明代理真链路（F2/F4 的端到端合口——含 iptables REDIRECT + TPROXY）**

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 18080
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j TPROXY --on-port 18080 --tproxy-mark 0x1/0x1
sudo ip rule add fwmark 0x1 table 100 && sudo ip route add local default dev lo table 100
# 打流后判据：dokodemo 日志出现真实原始目标（非 predefined），响应源地址 == 客户端原始目标
```

**6. DNS recvmmsg vs musl 单收双实现对拍（F3——生产 gnu 走批收，OpenWrt musl 走单收）**

```bash
# gnu 侧（本轮已绿，可复跑）
cargo test -p xray-core --lib -- dns --nocapture
# musl 侧：编 musl 产物后跑同一 DNS 入站回环（需交叉编译 + musl 运行时）
cargo zigbuild --release -p xray-cli --target x86_64-unknown-linux-musl
```

**7. `SO_MARK` / `SO_BINDTODEVICE` 特权生效断言（F4——现只测「非特权失败」）**

```bash
sudo -E cargo test -p xray-transport --lib -- sockopt --nocapture
# 判据：新增用例中「特权下 setsockopt 成功」为 ok（当前该分支不存在 -> 需先补测）
```

**8. QUIC GSO 内核版本下限体检（F9 + 生产 GSO 依赖）**

```bash
uname -r                                   # <4.18 的内核无 UDP_SEGMENT -> GSO 自动退化为 1 段
cargo test -p xray-transport-quic --lib -- gso --nocapture   # 本轮真 Linux 6/6 绿
```

---

## 5 未覆盖范围（诚实声明）

1. **本轮未在 Linux 上跑端到端真实节点互通（32/32）**——`run_full32.py` 在 WSL 下需 Windows 侧 URI 导出与节点可达性，编排成本高于本轮预算；CI 的 `interop_ci.py` 已覆盖 54~57 个协议级互通但不含 dokodemo/TUN/TPROXY/wireguard/UDS。
2. **未审计 musl / uclibc 产物**——`musl-probe` 是手动门且本轮未跑；uclibc 分支（`is_ipv6_origdst_cmsg` 恒 false、recvmmsg 无导出）**仅靠代码审阅判定，无实测**。
3. **未审 Linux 上的 wireguard 数据面**——静态确认走纯用户态 smoltcp netstack（无内核依赖、无 Linux cfg 分支），故判定无 Linux-only 风险，但**未实跑 wireguard 互通**。
4. **未在真 Linux 上验证 `net.core.rmem_max` 对生产吞吐的实际影响**——本轮只确认了「stock 212992 -> 4MB 断言失败、抬到 8MB -> 绿」（即 CI 那一步 sysctl 是**必需**而非可选，且**生产 VPS 缺此 sysctl 则该优化静默失效**）。吞吐数字不在本轮范围（前轮已覆盖）。
5. **未审计 eBPF / io_uring / netns / membarrier / prctl / 自调 rlimit**——全仓 grep 零命中，判定「未实现」而非「未审」。
6. **未重跑既有 CI**（契约非目标）；本轮所有 Linux 结论来自 WSL 本地实测 + workflow 文件静态审阅。

---

## 6 方法学备注（供后续轮次复用）

- **WSL `ubuntu-xray` 是可用的真 Linux 床**：root、`/dev/net/tun`、cargo/rustc 齐备、`/root/target` 有 7.3G 预热产物（省 40-90s/crate 编译）。启动脚本 `/root/xenv.sh`（`CARGO_TARGET_DIR=/root/target`、`CARGO_NET_OFFLINE=true`、`PROTOC`、`LIBCLANG_PATH`）。
- **`xray-tls` 在 WSL 编译需先修 btls**：`btls_sys` 缺 `SSL_send_post_handshake_record` / `SSL_seal_raw_tls13_record` -> 须 `export BORING_BSSL_ASSUME_PATCHED=1 BORING_BSSL_SOURCE_PATH=/root/boringssl-patched`（该树已含 `ssl/ssl_post_handshake.cc` 与 `include/openssl/ssl.h` 注入），并先 `find /root/target -path '*build/btls-sys-*' -mindepth 1 -delete` 清缓存。
- **写 WSL 脚本经 `cmd /c` 嵌套引号必炸**（`unexpected EOF while looking for matching '`）——用 `eval`(python) 写脚本到 `%TEMP%`，再 `wsl -d ubuntu-xray -- bash /mnt/c/Users/<u>/AppData/Local/Temp/x.sh` 执行。本仓 `write` 工具会**吃掉脚本内容里的字符**（实测 `--all-targets` 被吞成 `all-targets`、`echo` 被吞成 `cho`）-> WSL 脚本一律走 `eval`+python 写盘，**禁走 `write`**。
- **root 与非 root 的判别实验**：同一测试二进制用 `setpriv --reuid=65534 --regid=65534 --clear-groups <bin> <filter>` 跑非 root 版，可精确区分「特权分支覆盖」与「非特权分支覆盖」——本轮 F1 即由此定位。
- **`grep -c SKIP` 会被脚本自身的 header 行污染**（本轮误得「2 SKIP」实为 2 行标题）——统计 skip 必须 `grep -n 'SKIP'` 逐行看，且脚本 header 勿含该字样。
- **WSL 的 `rmem_max` 是 stock 212992**（!= CI 抬过的 8MB）-> 在 WSL 复现 CI 断言前先 `sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608`，否则 4MB rcvbuf 断言必红（环境问题，勿误判为代码缺陷）。
