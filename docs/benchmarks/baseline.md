# 数据面性能基线（框架支线 Phase 0 护栏）

- 日期：2026-10-11
- 基线哈希：master 4a5ea630（enc8x h2 流控窗三连修）+ AllocGuard 工作树
- 用途：oracle-framing-arch Phase 0「没有数字不许开工」——P1 数据面收口
  （splithttp 四处 to_vec、io.rs 去 box、Bytes 零拷贝入口）以此为对照组。

## 环境

| 项 | 值 |
|---|---|
| 机器 | Windows 11 x64（开发工作站，非隔离测速床） |
| 工具链 | rustc 1.98.0-nightly (cced03bfd 2026-05-28)，clippy 0.1.97 |
| profile | release 默认（`.cargo/config.toml` 不存在，无 target-cpu=native；仅 `.bak` 存档） |
| 构建 | 见下节命令（btls-sys 原生环境配方） |
| 窗口特性 | 本机 loopback 窗口摆动大：单轮 147→173 MB/s（约 16%），首传有暖机凹坑 |

## 构建命令（复现用）

```bat
cd /d D:\Project\Xray-core-rust
cmd /c "set PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;D:\Project\tools\bin;D:\Program Files\Git\cmd;C:\Users\Begonia\.cargo\bin;C:\Windows\System32;C:\Windows;D:\Program Files\llvm\bin&& set PROTOC=D:\Project\tools\bin\protoc.exe&& set LIBCLANG_PATH=D:\Program Files\llvm\bin&& set BORING_BSSL_ASSUME_PATCHED=1&& set BORING_BSSL_SOURCE_PATH=D:\Project\Xray-core-rust\target\boringssl-patched&& cargo build --release -p xray-cli"
```

## 拓扑（对齐生产 ib39380 形态）

```
curl → socks5h://127.0.0.1:11081 (cli xray: socks 入站 + vless(mlkem-enc) 出站)
     → xhttp(mode=auto)+reality → 127.0.0.1:18453 (srv xray: xhttp+reality+enc 入站)
     → freedom → python http.server:18100/big.bin (200 MiB)
每轮 3 次 curl 下载，取 speed_download。
```

## 采集命令（复现用）

```bash
# 参照组（旧二进制，无计数）
python tools/loopback_alloc_bench.py --tag <名> --runs 3 \
  --xray D:/Project/Xray-core-rust/target/release/xray.pre-allocguard.exe

# 对照组（新二进制，计数关——零开销验证）
python tools/loopback_alloc_bench.py --tag <名> --runs 3 \
  --xray D:/Project/Xray-core-rust/target/release/xray.exe

# alloc/MB 采集（新二进制，计数开）
python tools/loopback_alloc_bench.py --tag <名> --runs 3 --alloc-stats \
  --xray D:/Project/Xray-core-rust/target/release/xray.exe
```

计数契约：`XRAY_ALLOC_STATS=1|true|on` 开启进程级 alloc/dealloc 次数+字节数
统计；`XRAY_ALLOC_STATS_INTERVAL_MS`（默认 1000）控制 stderr 周期采样行
（前缀 `[xray-alloc-stats]`）。alloc/MB = 窗口前采样→末次采样的
Δalloc_bytes ÷ 下载字节。默认关闭时仅一次 Relaxed load 直通分支（零开销路径）。

## 2026-10-27 复测校准（同锚二进制 · 绝对值不可跨窗口比较）

- **复测对象**：本文立锚期的同一基线二进制（master 4a5ea630），同机同拓扑。
- **两次读数，差别全在"窗口是否干净"**：
  | 窗口 | 读数 | 窗口内是否有并发编译 |
  |---|---|---|
  | 16:28 前后（W6 A′/B） | **128.6-131.1 MB/s** | **有**（2 个子代理并发 cargo 编译） |
  | 19:15-19:19（W5 A/B，12 个 200MB 窗口） | **155.4 / 157.1 MB/s**（两态均值） | **无**（前后进程快照空，全树 manifest 仅 10 个本面文件差） |
- **结论（已更正）**：**154-167 MB/s 锚区间是可达的**——128-131 那组是**并发编译污染**下的读数，不能作为"锚失效"的证据。生效的是"测量必须独占 CPU"这条前提，不是"锚过期"。
- **性能门纪律（据此定稿）**：
  1. **测量窗口内禁止任何 cargo 编译**（含其他代理/PM）：谁要测，先 `write agent://all` 广播窗口，其他人暂停编译（读写代码可以）；窗口前后各记一次 cargo/rustc 进程快照作取证；
  2. **两个测量窗口严禁重叠**（重叠 = 双方数据都作废）；
  3. 主判据 = **同窗 A/B 相对差**（A 态 = 仅回退本波改动、保留其余在树增量；各 ≥3 轮交错）；
  4. **A/B 混杂即作废须重跑**（A 态构建早于其他波落码 → A 缺增量 B 含增量）；
  5. 绝对值照实报告，**并附"窗口内并发编译有无"的进程快照**——否则绝对值不可解释。
- 证据：`reports/audit-2026-10-27/w6-hotlog.md`（污染窗数据）· W5 A/B 窗口取证（19:15-19:19，manifest 差集 10 文件 + 进程快照空）。

## 吞吐结果（MB/s，十进制）

| 轮次 | 二进制 | 计数 | #1（暖机） | #2 | #3 |
|---|---|---|---|---|---|
| R1 | pre-allocguard（旧） | 关 | 147.0 | 171.2 | 171.1 |
| R1B | 旧 | 关 | 155.5 | 172.9 | — |
| R1C | 旧 | 关 | 148.3 | 171.0 | — |
| R2 | 新（wrapper） | 关 | 153.4 | 159.7 | 165.5 |
| R2B | 新 | 关 | 151.8 | 168.6 | — |
| R2C | 新 | 关 | 154.8 | 169.0 | 169.4 |
| R3 | 新 | **开** | 148.4 | 166.0 | 167.7 |

- 历史基线：154-167 MB/s（enc8x 战役同拓扑）——本轮全部落点健康。
- 稳态（去掉每块首传暖机）中位：旧 171.1，新关计数 168.6 → 差 ~1.5%，
  远小于 16% 窗口摆动带，且暖机形态两二进制一致 → **wrapper 零开销直通成立
  （无显著回归）**。[INFERENCE] 机制上 wrapper 关态仅每 alloc 一次 Relaxed
  load + 未跳转分支，无可测损耗机制；1.5% 差异属窗口噪声。
- 计数开启（R3）稳态 166.0/167.7，与关计数同带（采样行 eprintln 每 1s 一次，
  不在数据热路径）。

## alloc/MB 首测（R3，600 MiB 窗口）

| 进程 | Δalloc_bytes | Δalloc_n | alloc/MB（每 MiB 有效载荷的堆分配流量） |
|---|---|---|---|
| srv（xhttp+reality+enc 入站 + freedom 出站） | 1,291,809,602 | 188,209 | **2.15 MiB/MiB** |
| cli（socks 入站 + vless(enc) 出站） | 1,331,198,474 | 464,870 | **2.22 MiB/MiB** |

- 解读：全栈 relay 每传递 1 MiB 有效载荷产生 ~2.2 MiB 堆分配流量；分配次数
  少而单次均量大（srv ~6.9 KB/次、cli ~2.9 KB/次）——池化在工作，大块拷贝
  （splithttp h2 chunk/上传分块/XUDP 帧累积）是 alloc 字节的大头，即 P1 收口
  目标。live_bytes 收敛（srv 窗末 4.7 MB、cli 0.9 MB），无泄漏迹象。
- P1 验收口径：同法复测 alloc/MB 下降 + 吞吐不降（同窗 A/B）。

## clippy 数据面禁令护栏（同批落地）

- 范围（per-crate clippy.toml）：`xray-buf`、`xray-transport-splithttp`、
  `xray-app-dispatcher`；禁 `slice::to_vec` 与
  `xray_buf::multi::MultiBuffer::to_vec`（生产代码；测试编译单元经
  lib.rs `cfg_attr(test, allow)` / tests 文件头 `#![allow]` 统一豁免）。
- 注意：slice 方法路径 root 段必须写 primitive 关键字 `slice`（clippy
  find_primitive_impls 机制），写 `alloc::slice::`/`std::slice::` 解析不到。
- 白名单登记（生产 9 处，均带理由注释）：
  - splithttp：`dialer.rs:92/375`（h2/h3 上传分块，P1）、`upload_queue.rs:167`
    （部分消费重打包，P1）、`hub/handler.rs:330`（h2 chunk 入 Packet，P1）、
    `h3_client.rs:199`（ALPN 配置，冷路径）
  - dispatcher：`udp_session.rs:208/273`（XUDP 帧解析/累积，P1）、
    `sniffer.rs:771/815`（QUIC HP 解密可变副本 + AAD 借用分裂，算法固有）、
    `default.rs:1524`（cached_bytes 诊断访问器）
- 未覆盖角落（后续批次补）：`to_owned()`/`collect::<Vec<_>>()`/
  `Vec::from(&buf[..])` 等价形态；grpc 编码双拷贝；vless 握手期 to_vec（冷）；
  `Vec::new`+逐段 extend。

## 已知局限

- A/B 为 10s 块级交替（非秒级交错），且本机窗口摆动大；精确到 1% 的判别需
  netem 隔离测速床或真实 endpoint 同窗配对（30gf 方法论）。
- alloc/MB 为进程级累计（含握手/建连一次性开销），非纯数据路径口径；
  P1 对比时用同法采样保持口径一致。

## P1 收口对照（R4，同法采样，commit 3287ef93）

| 指标 | 基线（R3） | P1 终态 | Δ |
|---|---|---|---|
| alloc/MB server | 2.15 MiB/MiB | 2.136 | -0.6% |
| alloc/MB client | 2.22 MiB/MiB | 2.168 | -2.3% |
| alloc 次数 server | 188,209 | 165,722 | **-12.0%** |
| alloc 次数 client | 464,870 | 308,355 | **-33.7%** |
| loopback 吞吐 | 154-167 带稳态 | 149.3/168.5/167.7（暖机后稳态带内） | 持平 |

- 解读：被消除的分配均为小对象（chunk to_vec/segment/box），总字节由池化大
  buffer 主导——mimalloc 下小分配字节成本≈0，故字节口径变化小；**次数大降
  （cli -33.7%）才是收益正身**（分配器调用频率/锁/cache 压力）。v1 可证伪
  条款触发判定：alloc/MB 字节口径 <5% 且 loopback 无差 → io.rs 去 box **保留
  改造但降级为非性能票**，真实收益待真实端点同窗 A/B 复测（深谷未测，如实
  标注）。cli live_bytes 窗末 138MB 异常值疑采样残留，待复测非泄漏结论。
