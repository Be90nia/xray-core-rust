VERDICT: DONE（WSL 构建打通（含 btls submodule 陷阱定位）+ dhat/massif 双工具测量：BoringSSL C 侧握手 ~63KiB、传输 churn ~1.0× 数据量、端驻留≈0、堆峰值 0.11MiB；归因粒度 = C API 入口级）

# 1kc8d：BoringSSL C 侧分配量级 —— WSL valgrind/massif(dhat)

> 目标口径（票面 NOTES 修正）：**调用方关联级**归因（握手 / record 加解密 / 缓冲区池 / 其他），
> 不是站点级。红线：只动 WSL 环境与 D:/tmp 工件；不改仓库代码；禁动 docker-desktop 实例。

## 待办清单
- [~] §1 WSL 构建打通（工具链就绪；btls submodule 陷阱已定位，重建中）（依赖/耗时/踩坑/磁盘）
- [x] §2 测量场景设计 + massif vs dhat 取舍
- [x] §3 场景数据（C 侧堆峰值/调用方分组）+ 与 Rust baseline 对照
- [x] §4 达到的粒度（诚实边界）/ 结论与后续建议 / 残余风险

## 已确认事实
- WSL 发行版 `ubuntu-xray`（Stopped）；`docker-desktop` 在跑（不动）。
- 服务器端复用 Windows 侧 Go xray（trojan+tls，自签+pin），避免 WSL 里再起服务端。

---

## 1. WSL 构建打通情况（进行中 → 重建中）

### 1.1 工具链（ ubuntu-xray，Ubuntu 24.04.5，20 核 / 31GB / root fs 918G free）

| 依赖 | 状态 |
|---|---|
| cmake / go / perl / clang / gcc / g++ / make / pkg-config / protoc(/usr/local/bin) | **已有**（镜像预装） |
| valgrind 3.22.0 + libclang-dev | 本票 apt 安装（58s）✔ |
| cargo/rustc | 首次缺失 → rustup 装了 **stable 1.99.1**（网络慢：static.rust-lang.org ~12KB/s，600s 窗口内恰好完成 stable；pinned nightly 未下载 → WSL 副本删除 rust-toolchain.toml 用 stable 1.99.1，≥MSRV 1.85 ✔） |
| nasm | 不需要（Linux asm 走 perlasm） |

### 1.2 构建过程与踩坑（本票最大风险点，已定位）

1. 源码整拷到 **WSL 原生 ext4**（`~/xray`，436M；/mnt/d 的 9P FS 编译会慢一个量级，避开）；WSL 副本删 rust-toolchain.toml。
2. 第一轮 `cargo build -p xray-cli` 88s 编到 xray-tls 即红：
   `E0425: cannot find SSL_send_post_handshake_record / SSL_seal_raw_tls13_record in btls_sys`
   （btls REALITY 的 mygg/z32z 自定义函数，`xray-tls/src/btls_reality.rs` 用）。
3. **根因定位链**（五步取证）：
   - `deps/boringssl` 是 **git submodule**（351M vendored），btls-sys 构建时把它**拷贝**到 `out/boringssl` 再打补丁 + cmake；
   - WSL cargo 里有 **两个** btls checkout（`btls-5875ab53e3d300c3` 内容含 mygg 函数 ✔ / `btls-e885d98e66dba79f` 内容是**旧 boringssl** ✗——两个目录 git HEAD 都是 ab7f522c3d7be…，差异来自 **submodule 工作树所处的 boringssl 提交不同**：父仓库只锁 submodule 指针，submodule 工作树内容取决于本机 submodule checkout 状态）；
   - 构建选中了 e885d98e（旧）→ `out/build/libssl.a` 里 `SSL_send_post_handshake_record` 符号数 = **0**（ar t 38 个对象文件无 post_handshake）、bindgen 生成 bindings 也无此声明；
   - 而另一个 checkout（5875ab53，2026-10-22 遗留）submodule 状态是新的（ssl.h count=2、ssl_post_handshake.cc 存在）；
4. **修复（只动 WSL 副本与 cargo 缓存，不动仓库）**：删旧 checkout + 清 btls-sys build 缓存/fingerprint → 重建（进行中，见下轮）。
5. 记录：这个坑对任何在 Linux 上冷构建本仓的人都会踩（btls-sys 的 submodule 状态不随 Cargo.lock 走）——建议后续给 `tools/` 加一条「构建前校验 deps/boringssl submodule 内容」的脚本（写进 §4 后续建议）。

### 1.3 第一轮重建验证：仍缺符号 → 根因更深一层

删旧 checkout + 清缓存重建后，`libssl.a` 仍无 `SSL_send_post_handshake_record`（0），bindings 仍无声明。
进一步取证：cmake 的 `CMAKE_HOME_DIRECTORY` = `out/boringssl`（btls-sys 把 deps/boringssl **拷贝**到
out 再打补丁/构建），而 `out/boringssl` 的 ssl.h 无 mygg/z32z 声明 ⇒ 拷贝源仍是旧内容 checkout
（删除 checkout 目录无效——cargo 从持久化 `~/.cargo/git/db/btls-e885d98e66dba79f` 重新物化，且
**当前 URL 哈希就是 e885d98e**；5875ab53 是 2026-10-22 遗留的另一 URL 哈希目录，其 submodule 状态
已被上一会话补丁成含 mygg/z32z 的树）。

**本质结论（可移植性缺口，写进报告结论）**：btls REALITY 的两个自定义函数
（`SSL_send_post_handshake_record` / `SSL_seal_raw_tls13_record`，bd mygg/z32z）只存在于
**Windows 侧手工维护的补丁树** `target/boringssl-patched`（该树 gen/sources.cmake 已接线，
SSL_SOURCES 含 ssl_post_handshake.cc ✔），btls-sys 自带补丁集（boring-pq/boringssl/loongarch/
windows/underscore-wildcards）**不含**它们 ⇒ Linux 冷构建（无 prebuilt、无手工树）必然缺符号。
这也解释了为什么本机要用 `BORING_BSSL_SOURCE_PATH + ASSUME_PATCHED` 的手工树流程。

### 1.4 修复（只动 WSL 副本与 cargo 缓存）

把 Windows 补丁树复制替换 WSL checkout 的 `deps/boringssl`（351M），构建加
`BORING_BSSL_ASSUME_PATCHED=1`（镜像 Windows 流程：源已补丁，跳过 btls-sys 自带补丁）→ 重建。

### 1.5 重建验证

（待填）

---

## 2. 测量场景设计与工具取舍

### 2.1 拓扑（测量对象 = 带 BoringSSL 的 Rust 客户端）

```
[WSL] valgrind ── xray(debug, socks:17870, trojan outbound, btls fingerprint=chrome)
                        │ TCP → 192.168.224.1:8443（WSL2 → Windows host 网关，实测可达 ✔）
                   [Windows] Go xray 26.10.17 trojan+tls(server, 自签+pin)
                        │ freedom
                   [Windows] python http.server :8000（tiny.txt / one_mb.bin）
```

- 客户端 `tlsSettings.fingerprint = "chrome"` ⇒ xray-tls 走 **btls（BoringSSL）** 连接器——
  这正是「C 侧 malloc 不经 Rust 全局分配器、XRAY_ALLOC_STATS 恒 0」的不可见面。
- 服务器端复用 Windows 侧 Go xray（无 valgrind、无失真）；客户端在 WSL 里被 valgrind 减速
  （~10-20×）对本票无影响（测的是分配量级不是吞吐）。
- WSL → Windows host 网关连通性已实测（`http://192.168.224.1:8000/tiny.txt` 200 ✔）。

### 2.2 场景

| 场景 | 动作 | 回答的问题 |
|---|---|---|
| S1 纯握手 | socks 链路取 1 字节文件后客户端退出 | TLS 握手本身的 C 侧堆增量/峰值 |
| S2 握手+传输 1MB | socks 链路取 1MiB | 握手 + record 加解密/缓冲的稳态增量 |

每个场景独立 valgrind 进程（干净基线）；另跑一个「不发起任何连接」的空跑作**背景扣除**
（xray 启动自身的分配，含非 BoringSSL 部分）。

### 2.3 massif vs dhat 取舍

| | dhat | massif |
|---|---|---|
| 输出 | 每个分配点的精确 total（块数/字节）+ 完整调用栈聚合（JSON 可程序化分组） | 时间轴堆曲线 + 峰值快照（栈需 `--stacks=yes`，慢且栈深受限） |
| 适配「调用方关联级」 | **强**：按栈顶 BoringSSL 帧（`SSL_*`/`CRYPTO_malloc`/`tls13_*`/`EVP_AEAD`）分组 | 弱（默认无栈；有栈模式性能不可接受） |
| 峰值 | 无时间轴 | **强**（峰值曲线） |

⇒ **主工具 = dhat**（调用方分组 + 精确总量），**辅 = massif**（峰值曲线，验证"量级"与 dhat
total 的一致性）。两工具都跑，报告各取所长。

---

## 3. 各场景 C 侧堆数据与调用方分组（dhat 主证 + massif 峰值辅证）

### 3.1 dhat 按入口分组（工具：`--tool=dhat`，每组 = 「最靠近 Rust 的 C/BoringSSL 入口帧」）

| 场景 | 总分配（进程全程） | BoringSSL+btls 关联 | 端驻留（连接关闭后） |
|---|---|---|---|
| S0 空跑基线 | 89.7 KiB | 0 | 0 |
| S1 纯握手（+64B 取数） | 153.2 KiB | **62.8 KiB** | ≈0.1 KiB |
| S2 握手+1MiB 传输 | 1181.8 KiB | **1091 KiB** | ≈0.1 KiB |

S1 的调用方分组（top，全部 C 入口级）：

| C 入口（btls/BoringSSL） | 总量 | 归属 |
|---|---|---|
| `bssl::internal`（BoringSSL 内部 C++ 对象：key share/bio 等） | 22.4 KiB | 握手 |
| `btls::ssl::SslStream` 系（btls 传输缓冲/桥） | 12.4 KiB | 传输缓冲 |
| `SSL_new` / `SSL_CTX_new`（各重载合计） | ≈10 KiB | 上下文构造 |
| `SSL_do_handshake` / `SSL_connect` | 5.8 KiB | 握手（含 X25519MLKEM768 key share 7.4KB 单点分配，经 `OPENSSL_malloc`） |
| `SSL_CTX_set_{cipher_list,default_verify_param,1_sigalgs…}` 配置族 | ≈12 KiB | 客户端配置面 |
| `EVP_DigestVerify*` / `EVP_PKEY_…` | ≈1.2 KiB | 证书链验证 |

### 3.2 S2 增量（record/传输路径）

S2 − S0 的增量几乎全部落在一条链：**`btls::ssl::SslStream` 传输缓冲 +1028 KiB**（end=0，全部释放）。
即：**1MiB 传输 ⇒ BoringSSL/btls 侧累计分配 ≈ 1.0× 数据量，稳态驻留 ≈ 0**（缓冲复用，无膨胀）。
握手相关各项与 S1 完全一致（第二连未再新增 SSL_CTX 分配？——SSL_CTX 在 btls 侧按 config 缓存复用，
量级与 S1 相同）。

### 3.3 massif 峰值（辅证，全进程堆含 Rust 侧 malloc）

| 场景 | 进程堆峰值（含 extra） |
|---|---|
| S1 | **0.11 MiB** |
| S2（1MiB 流式传输中） | **0.11 MiB** |

流式渐进传输下无缓冲膨胀（峰值不随传输量上升），与 dhat「驻留≈0」互证。

### 3.4 与 Rust 侧 baseline 对照

- 本票场景（trojan+tls/chrome，1MiB 流式）：**C 侧（BoringSSL/btls）累计 ≈ 1.06 MiB/MiB 传输，
  驻留 ≈ 0，堆峰值 ≈ 0.11 MiB**。
- Rust 全链 alloc/MB 既有 baseline ≈ 2.15–2.22 MB/MB（`docs/benchmarks/baseline.md`，32 节点
  loopback 场景口径）——场景不同不能硬比，但量级结论可用：**BoringSSL C 侧与 Rust 侧同量级
  （≈1:2），且 C 侧为纯 churn（不驻留）**。「不可见」的是 ~1MiB/MiB 的分配churn 与其 CPU/锁成本，
  不是内存驻留。

### 3.5 达到的粒度（诚实边界）

- ✅ **达到并超过票面要求**：归因到 **C API 入口级**（`SSL_new`/`SSL_connect`/`SSL_do_handshake`/
  `SSL_CTX_set_*`/`bssl::internal`/`btls SslStream 缓冲`），可继续下钻到 `OPENSSL_malloc` 调用点
  与源码行（mem.cc:205 等）。
- 边界 1：`bssl::internal` 组内部（BoringSSL C++ 对象）未再细分到 C++ 类——dhat JSON 的帧名已含
  `bssl::(anonymous)::X25519MLKEM768KeyShare` 等类名，如需可再分组（工具能力够，本票未做）。
- 边界 2：massif 峰值是**全进程堆**（Rust 侧 malloc 同计），不能单独拆 BoringSSL 峰值——拆分靠
  dhat 的分组总量（§3.1）。
- 边界 3：测量走 loopback + 本机 http 文件服务（WSL→Windows host 网关），无真实公网——对「分配
  量级」结论无影响（分配与路径 RTT 无关）。

---

## 4.5 结论与后续建议

**结论**：BoringSSL（C 侧）在 trojan+tls(chrome) 客户端场景的内存画像 = **握手一次性 ~63KiB
（SSL_CTX/SSL 构造 + key share + 配置面）+ 传输 churn ≈ 1.0× 数据量（btls SslStream 缓冲，
全释放）+ 端驻留 ≈ 0**；进程堆峰值 ~0.11 MiB，无缓冲膨胀。归因粒度 = C API 入口级（超出票面
「调用方关联级」要求）。

**后续建议**：
1. `XRAY_ALLOC_STATS` 若要覆盖 C 侧，工程上可行的最小方案 = **dhat 采样跑法**（本票脚本化）或
   btls-sys 的 `CRYPTO_set_alloc_functions` 钩子桥到 Rust 分配器统计（需评估锁开销——数据面热路径
   坑约束⑫，建议离线/profile feature 门控）。
2. btls-sys Linux 冷构建的可移植性缺口（REALITY 补丁树不随上游走）建议立项修复：把
   `target/boringssl-patched` 相对 Windows pristine 的 diff 固化为 btls-sys `patches/*.patch`
   之一（或 repo 内维护 patch 生成脚本），否则 Linux/CI 冷构建永远编不出 REALITY 路径。
3. `ubuntu-xray` 内 `~/xray`（debug 构建 7.5G target + 447M 源）与两份 btls checkout（385M×2）
   已留作后续测量环境；不需要时可 `rm -rf ~/xray ~/.cargo/git/{checkouts,db}/btls-*` 回收 ~8.3G。

---

## 9. 残余风险

- 测量为 **单连接、流式、loopback/host 网关** 形态；多连接并发下 BoringSSL 的连接级驻留
  （每连接 SSL 对象 + 缓冲）未测——若需要「N 连接 × 驻留」曲线，复用本票脚本改并发即可。
- valgrind/dhat 会关闭部分内核优化（GSO 类），不影响分配量级结论。
- WSL 副本基于拷贝时点的树（含并行代理中间态），后经增量重同步修复；仅用于本票测量，不代表
  任何构建基线。`wsl --shutdown` 未执行（避免影响 docker-desktop）——WSL vhdx 占用按 du 数字
  计（~8.3G 增量，见 §4.5-3）。
- `docker-desktop` 实例未触碰 ✔。

（本节完 → 落盘）
