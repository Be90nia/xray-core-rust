# R2 性能维度：机制接线 + 热路径浪费（PerfWiring）

- 轮次：audit-2026-10-31（R2 性能维度）
- 分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`（h2 下行块池 9eu4a 已落地）
- 二进制：`target/release/xray.exe`（Oct 31 11:00 构建，与 HEAD 同源，`git_rev` 自检见 bench 输出）
- 性质：**只读审计，零代码改动**；未编译（零构建），未创建/未占用 `target-PerfWiring`（无该目录）
- 工具：serena-cli（overview / symbol-body，约 6 次）＋ read/grep 工具；图谱仅作线索、结论一律 grep/读源复核

---

## 0. 结论速览

| 问题 | 答案 |
|---|---|
| Q1 性能机制是否接线 | **11 项已生效（P）/ 9 项半生效（S）/ 11 项未生效（Q）**（31 项机制，表见 §2）。最大的未生效面是整条 `BufferPool` 接缝族（xray-frame/pool.rs 四层：trait / ManagedShell / XrayBufPool / with_pool 注入 + clippy L3 闸）——**连目标主路都不接线**，只有 xray-frame 自身单测在消费 |
| Q2 热路径确定性浪费 | 单项最大 = **rustls 逐 record 明文拷贝**：tcp-tls 客户端 `tls_read` 实测 **1.000 MB 分配 / MB 载荷**（84.2% 的 cli 分配），12,903 次分配 / 200 MiB（每 record 一次 16.2 KB）。次大 = **xhttp 客户端上行 `ReaderStream` 4 KiB 逐块新分配 ≈ 1.0 MB/MB（上行方向）**——正是已修的 h2 下行块池（9eu4a）的对侧孪生缺陷 |
| 生产主路实际用什么分配 | `xray_buf::alloc` 分层池（tier 0/1/2/3 = 2/8/32/128 KB，TLS 缓存 8/层 + 8 分片 × 64/层），经 `Buffer::new_pooled`/`Buffer::new` 消费（生产 22 个 `Buffer::new()` + 3 个 `new_pooled` + 2 个直调 `alloc` 站点）；**绕过 `BufferPool` 接缝** |
| 是否真在做零拷贝转发 | **半是**。帧内不拷贝（`MultiBuffer` 链 + `Bytes`/`BytesMut` 引用计数分割 + `from_bytes_frozen`），但**每层边界都至少一次全量拷贝**：TLS 明文化（1×）、rustls→xray-buf 读缓冲（1×）、非 vectored 写半部逐 Buffer 写（系统调用边界）。载荷在 TLS 链路上共经历 **3 次** 全量拷贝，其中 1 次是本审计新增定位、可消除 |

已 CLOSED 的 4y9ns / r1693 / q1r4q **不重开**：本报告只指出它们留下的新债（见 §4）。

---

## 1. 方法与证据口径

**证据分级**（按派单要求）

- **E1**：实跑计数输出（`XRAY_ALLOC_STATS=1` + `XRAY_ALLOC_STATS_SITES=1`，`tools/loopback_alloc_bench*.py`）
- **E2**：源码逐行数据流证明 + 可复跑命令（每条都给）

**E1 采集结果**（本机，2026-10-31；吞吐数字按项目口径不作结论，只看 allocated bytes / 次数）

### 1.1 拓扑 A：`full`（vless+mlkem-enc over xhttp+reality，200 MiB 下载）

```
python tools/loopback_alloc_bench.py --tag perfwiring --xray target/release/xray.exe --runs 2 --alloc-stats
```

| 面 | alloc/MB | Δalloc_n（200 MiB） | alloc_n / MB |
|---|---|---|---|
| srv | **1.181** | 49,281 | 246.4 |
| cli | **1.899** | 146,217 | 731.1 |

站点拆分（Δbytes）：

| 站点 | srv | 占比 | cli | 占比 |
|---|---|---|---|---|
| xhttp_srv_send | 12,409,264 | 5.3% | 0 | 0% |
| buf_read | 6,769,912 | 2.9% | 36,438,104 | 9.6% |
| vless_enc_seal | 2,930 | 0.0% | 1,566 | 0.0% |
| tls_write / tls_read | 0 / 0 | — | 156 / 314 | 0.0% |
| (untagged) | 217,097,105 | 91.9% | 343,436,272 | 90.4% |

### 1.2 拓扑 B：`tcp-tls`（vless plain over 裸 TCP+TLS，无指纹 → rustls 栈，200 MiB 下载）★ 主证据

```
python tools/loopback_alloc_bench_variants.py --xray target/release/xray.exe --variant tcp-tls \
  --tag pw-tcp-tls --runs 1 --alloc-stats --floor 1
```

| 面 | alloc/MB | Δalloc_n（200 MiB） | alloc_n / MB |
|---|---|---|---|
| srv | **1.108** | 23,344 | 116.7 |
| cli | **1.246** | 64,995 | 325.0 |

站点拆分（Δbytes，cli = 客户端下行主路径）：

| 站点 | Δbytes | Δn | 占比 | 折算 |
|---|---|---|---|---|
| **tls_read** | **209,767,247** | 12,903 | **84.2%** | **1.0003 MB / MB**，均值 16,257 B/次 |
| buf_read | 34,949,928 | 13,137 | 14.0% | 0.1667 MB / MB，均值 2,660 B/次 |
| tls_write | 156 | 2 | 0.0% | 写路径已收口（4y9ns 确认关闭） |
| (untagged) | 4,498,733 | — | 1.8% | — |

srv 侧：`buf_read` 6,572,560 B（3.0%）＋ 97% untagged（服务端 TLS 走 btls，BoringSSL 的 malloc 不经 Rust 全局分配器 → 站点不可见，非"零分配"）。

> `--variant direct` 脚本自身有 bug（单进程无 srv 日志，`last_sites` 抛 FileNotFoundError），本次未取得该拓扑 E1。

---

## 2. Q1 机制三态表

三态：**P**=已生效（生产有构造点 + 运行期消费）｜**S**=半生效（仅某协议/某配置/某平台分支）｜**Q**=未生效（有实现无生产消费）

> 「生产主路」= 默认 `xray.exe run`：`xray_conf::Config::build()` → `xray_core::start_full`。
> 「目标主路」= `xray-cli` 的 framework-assembly。
> 判定纪律：**只服务目标主路 = 对生产主路零收益**，本表逐条标注。

| # | 机制 | 态 | 生产构造点（file:line） | 运行期消费点（file:line） | 若未生效，被什么替代 |
|---|---|---|---|---|---|
| 1 | `BufferPool` 接缝（trait） | **Q** | `crates/xray-frame/src/pool.rs:121` | 全仓生产零消费；消费只在 `xray-frame/tests/*`、各协议 `tests/plugin_contract.rs`（`assert_pool_discipline!`） | 各 crate 直接 `xray_buf::alloc::alloc/release` 或 `Buffer::new_pooled` |
| 2 | `ManagedBufferPool`（udf `PoolBase` 记账壳） | **Q** | `pool.rs:209` | 同上（仅测试 + `assembly.rs:410` 单测） | 无替代：池化记账/水位线/审计环全部不在生产路径 |
| 3 | `XrayBufPool`（xray-buf 适配器） | **Q** | `pool.rs:175`（`alloc` 在 :181、`release` 在 :190） | 同上 | 同上 |
| 4 | `FrameworkBuilder::with_pool` 装配注入 | **Q** | `crates/xray-frame/src/assembly.rs:222`；`ctx.set_pool` 在 `context.rs:318` | **全仓零调用方**——目标主路 `crates/xray-cli/src/framework.rs:746-752` 的 `Framework::builder(..).register(..).build()` 链上**没有 `.with_pool(...)`**，故 `FrameworkBuilder.pool = None` → 插件若调 `ctx.pool()` 会 panic | 无。**结论：连目标主路也不接线**（不是"只服务目标主路"，是"两条主路都没接"） |
| 5 | `clippy.toml` L3 禁用面（禁裸 `xray_buf::alloc`） | **Q** | `clippy.toml` 全文只有 `allow-unwrap-in-tests`，**无 `disallowed-methods`** | 不适用 | 无闸 → 生产代码可任意直调 `xray_buf::alloc`（实测：`bridge.rs` 2 处 + `pool.rs` 2 处） |
| 6 | xray-buf 分层池（TLS 缓存 + 8 分片全局池） | **P** | `crates/xray-buf/src/alloc.rs:128 alloc` / `:173 release`；tier 常量 `:22`；TLS 缓存上限 `:27`；分片上限 `:34`；惰性减半 `:88` | `Buffer::new_pooled`（`buffer.rs:53`）→ `Buffer::new`（`buffer.rs:44`）→ 生产 **22** 个 `Buffer::new()` 站点（mux/writer、crypto、bridge、vision 等）＋ **3** 个 `new_pooled`）；`bridge.rs:93/184` 直调 `xray_buf::alloc::alloc` 2 处 | — |
| 7 | 池 release 容量过滤（防假池污染） | **P** | `alloc.rs:181-186`（`capacity != TIER_SIZES[tier]` → 丢弃） | 同一 release 路径 | — （副作用见 §3 W6：split 产物永不回池） |
| 8 | `readv` 聚合读（`ReadVReader` + `AllocStrategy`，上限 8 缓冲） | **S** | `crates/xray-buf/src/readv.rs:262 read_multi` / `:304 read_multi_single`；工厂 `io.rs:232/246` | ①原始 TCP 入站监听：`xray-core/src/inbound.rs:157-159 into_link_io` → `:628/:694/:792/:1643`；②桥接 dup 读腿：`bridge.rs:366`（**条件** `stream.is_raw_tcp() && use_readv()`） | **TLS/REALITY/vision/HTTP 等全部包装连接 `is_raw_tcp()` 默认 false** → 退回 `SingleReader` 8 KB 单缓冲顺序读（`bridge.rs:373-381`）。env 缺省开（`readv.rs:36`） |
| 9 | `writev` 批量写（`write_all_mb` ≤8 IoSlice 栈数组） | **S** | `crates/xray-transport/src/bridge.rs:228` | 上行 writer `bridge.rs:452` | 仅 `is_write_vectored()==true` 生效；`WriteHalf<TLS>` 默认 false → 逐 Buffer `write_all`（`bridge.rs:270-275`） |
| 10 | `SequentialWriter` 内 vectored 聚合 | **S** | `crates/xray-buf/src/writer.rs:52`（`write_vectored_all` 在 `:96`） | 所有 `new_writer()` 装配点（生产 **18** 处） | TLS 包装写半部 → `write_sequential`（`writer.rs:81`）逐块写 |
| 11 | `CoalescingWriter`（常驻缓冲 + `MAX_COALESCE` 256 KB） | **S** | `crates/xray-buf/src/writer.rs:268`；`MAX_COALESCE` 在 `:266`；工厂 `io.rs:222` | **唯一装配点** `crates/xray-proxy-vless/src/inbound/server.rs:627`（`flow=""` 非 vision TCP 分派） | vision / UDP / Mux / Rvs 分支走 `new_writer`（`server.rs:626` 的 `if is_vision` 另一臂） |
| 12 | `BufferedWriter` | **P** | `writer.rs:136` | mux 客户端/服务端全套：`xray-mux/src/client.rs:443`、`worker.rs:288/381`、`mux/writer.rs:60/87` | — |
| 13 | `splice(2)` 零拷贝双向泵 | **S** | `crates/xray-transport/src/splice.rs:63/173`；闸 `xray-common/src/platform/splice.rs:45` | ①生产：`xray-core/src/arm_builders/outbound.rs:119 set_splice_outbound(true)`（freedom TCP）→ `xray-app-dispatcher/src/default.rs:1917 bridge_link_with_stream_downlink_splice`；②目标主路：`xray-cli/src/framework.rs:401` | **`#[cfg(linux|android)]` 硬门**（`default.rs:1913-1927`）＋ 两端必须裸 TCP + env `xray.buf.splice`。**Windows 构建恒回退池化泵**，本机不可测 |
| 14 | `recvmmsg` 批量收（DNS UDP） | **S** | `xray-core/src/inbound.rs:2762 dns_udp_recv_loop`；批大小 `:2748`（16） | 同上（`:2694` 的 UDP task） | **`cfg(all(target_os="linux", target_env="gnu"))` 独有**；Windows/macOS/musl 走 `recv_from` 单收 |
| 15 | `frozen_reader` 零拷贝读腿（h2/h3 body 的 `Bytes` 直接进 `Buffer`） | **S** | `xray-transport/src/connection.rs:111`（默认 `None`）；实现 `xray-transport-splithttp/src/connection.rs:367` | `bridge.rs:373` `let frozen = stream.frozen_reader();` → `:381` 优先选中 | 包装层（TLS/AEAD/vision）不转发 → 池化 8 KB 拷贝路径；`from_bytes_frozen` 定义在 `buffer.rs:85` |
| 16 | h2 下行块池（`BufPool` + `Bytes::from_owner`，9eu4a） | **P** | `xray-transport-splithttp/src/hub/dl_stream.rs:35`（`CHUNK`=64 KiB `:28`、`POOL_MAX` `:33`、自适应容量 `:60-69`） | `dl_stream.rs:107 poll_next` → `:132 Frame::data(Bytes::from_owner(PooledBuf))` | — （残留见 §4 W4） |
| 17 | XUDP `PacketWriter/PacketReader` scratch 复用 | **S** | `xray-xudp/src/packet.rs:299 scratch`（`write_packet` `:312`）、`:396 frame_scratch`（`read_packet` `:411`） | freedom/socks/dispatcher 全部 XUDP 装配点 | **只复用 meta/length 头**；解包载荷仍 `vec![0u8; len]`（`packet.rs:439`）＝逐包分配，且各调用方自建 `Vec` 帧（见 §4 W5） |
| 18 | `Buffer` 双态（`Pooled`/`Frozen`）+ `from_bytes_frozen` | **P** | `buffer.rs:7-14`（`Inner` 枚举）、`:85 from_bytes_frozen`、`:87 from_vec`（Frozen 防假池） | 8 处 `from_bytes_frozen`（splithttp/transport/bridge）+ 16 处 `from_vec` | — |
| 19 | `Buffer::split_to/split_off` 零拷贝分割 | **P** | `buffer.rs:402` / `:428` | `multi.rs:112/180`（`split_bytes`/`split_size`）、`splithttp/connection.rs:267` | 零拷贝语义成立；但**池回收不了**（见 §3 W6） |
| 20 | `MultiBuffer` 片段链（热路径不合并） | **P** | `crates/xray-buf/src/multi.rs:12-20` | 全部 Reader/Writer trait 返回值 | — |
| 21 | `pipe`（bounded 管道，`PipeOption.limit`） | **P** | `crates/xray-buf/src/pipe.rs` | dispatcher `default.rs:1047/1153/1998`、`xray-core/src/inbound.rs:988`、mux `client.rs:852` | — |
| 22 | `XrayBufPool`/`Managed` 的管理面（水位线 / 审计环） | **Q** | `pool.rs:265` `impl PoolManaged` | 无 | 无生产观测面 |
| 23 | `TimeoutReaderWrapper` / `TimeoutWriterWrapper` | **Q** | `crates/xray-buf/src/timeout.rs` | **零生产消费**（grep 只有 `timeout.rs` 自身测试） | 超时由 `bridge.rs` 的 `tokio::time::timeout` + `TimeoutPolicy` 直接做 |
| 24 | `xray_buf::copy`（`copy`/`copy_once_timeout`） | **Q** | `crates/xray-buf/src/copy.rs` | **零生产消费**（只有本 crate 测试） | `bridge_link_with_stream_full` 的四段式泵 |
| 25 | `BufferedReader` | **P** | `crates/xray-buf/src/reader.rs:139` | `xray-core/src/inbound.rs:355`、`xray-mux/src/reader.rs:73/123`、`xray-app-reverse/src/worker.rs:400` | — |
| 26 | BBR / hysteria 拥塞控制 | **S** | `xray-transport-hysteria/src/congestion/bbr.rs`；`CongestionControl` 枚举 `xray-proxy-tuic/src/client.rs:53`；落到 quinn 在 `client.rs:439-475` | 仅 tuic/hysteria 出站（`xray-core/src/outbound.rs:2944`） | 其他协议无拥塞控制面（TCP 交给内核） |
| 27 | vmess chunk 帧复用 + `seal_into` 就地加密 | **P** | `xray-proxy-vmess/src/encoding/body_chunk.rs:286 write_one_chunk`（`frame` 跨 chunk 复用、`:305 seal_into`） | 泵侧 `xray-proxy-vmess/src/dispatcher.rs:907/932` | — （同步版 `decode_chunk_stream` 的整段 `Vec` 只用于小 body 头部路径） |
| 28 | AEAD `open_in_place` 就地解密 | **P** | `xray-crypto/src/aead.rs:302` | ss2022 `packet.rs`/`inbound.rs`、vmess `body_chunk.rs:434` | — |
| 29 | AEAD `seal`/`open`（返回 `Vec`，内部 `to_vec`） | **Q** | `aead.rs:254/295` | **活路径零消费**（活路径全用 `_into`/`in_place`） | `seal_into` / `open_in_place` |
| 30 | `AuthenticationReader` / `AuthenticationWriter`（Go `common/crypto/auth.go` 直译） | **Q** | `xray-crypto/src/auth_reader.rs:37` / `auth_writer.rs:53` | **零生产消费**：vmess 自建 `encoding/body_chunk.rs`、ss 自建 `stream.rs` | vmess `body_chunk` + ss `stream`（各一套独立实现） |
| 31 | UDP 出站帧构建（freedom / socks / dispatcher session） | **Q（缺机制）** | `xray-proxy-freedom/src/udp.rs:508`、`xray-proxy-socks/src/udp.rs:379`、`xray-app-dispatcher/src/udp_session.rs:95` | 上面三处就是生产消费点本身 | 无缓冲复用机制：每数据报新建 `Vec` + `PacketWriter` + `MultiBuffer`（见 §4 W5） |

**统计**：31 项机制 → **P = 11**（#6,7,12,16,18,19,20,21,25,27,28）｜**S = 9**（#8,9,10,11,13,14,15,17,26）｜**Q = 11**（#1,2,3,4,5,22,23,24,29,30,31）。

> 其中 #1-#4 同属**一族**（`BufferPool` 接缝：契约 trait → 管理面壳 → xray-buf 适配器 → 装配注入），加上 #5（本该拦住裸 `xray_buf::alloc` 的 L3 clippy 闸）缺位——即：**这一族 5 项全部未接线，且没有任何闸把生产代码推回它**。这是本次 Q1 的核心答案。
> #23/#24/#29/#30 是**死代码型 Q**（有实现、零消费方），不是性能缺陷，登记供后续 clean-up 判定。

---

## 3. Q2 热路径浪费清单（按 alloc bytes / MB 排序）

排序口径：**每 MB 载荷的分配字节数**（E1 优先）；无 E1 的按「每包/每次」折算并在列内注明。

| # | 标题 | 严重度 | 位置 | 现状（E1 实测） | 断裂点 / 浪费点 | 证据 | 影响量级 | 建议（一行，不改代码） |
|---|---|---|---|---|---|---|---|---|
| **W1** | rustls 逐 record 全量明文拷贝 + 分配 | **P1** | `vendor/rustls/src/common_state.rs:483-486`（`take_received_plaintext` → `received_plaintext.append(bytes.into_vec())`）← `vendor/rustls/src/msgs/base.rs:43`（`Payload::Borrowed(bytes) => bytes.to_vec()`） | tcp-tls cli：`tls_read` = 209,767,247 B / 200 MiB = **1.0003 MB/MB**，12,903 次 = 每 TLS record 一次 16,257 B | AES-GCM 已就地解密进 deframer 缓冲（零拷贝），但随后 `Payload::Borrowed → to_vec()` 把明文**整段复制**到 `ChunkVecBuffer<Vec<u8>>`，再把首 chunk 拷进调用方 `ReadBuf`（tokio-rustls `poll_read` `client.rs:307-314`）。**同一份明文走两遍**——一遍多余 | **E1**（数值）＋**E2**（行级）；命令：`python tools/loopback_alloc_bench_variants.py --variant tcp-tls --runs 1 --alloc-stats --floor 1`（看 `site=tls_read`）；行级复核 `read vendor/rustls/src/msgs/base.rs:36-48` | 1.000 MB / MB 下行载荷（cli 84.2% 分配）；每 record 1 次 alloc + 1 次 16 KB memcpy | 换 rustls **unbuffered API**（`vendor/rustls/src/conn/unbuffered.rs` 已在树内）让 tokio-rustls 直接交出 `AppDataRecord` 借用块。**红线面**（`vendor/`）：须用户授权 + NIGHT-LOG 描述的 A/B 闸门；先例 `8b5453ef`（deframer 缩容，tls_read −79%） |
| **W2** | xhttp **上行** `ReaderStream` 逐 4 KiB 块新分配（下行孪生缺陷） | **P1** | `crates/xray-transport-splithttp/src/dialer.rs:230/270/513/547/688`（`ReaderStream::new(pipe_server)`）＋ tokio-util `ReaderStream::poll_next`（`buf.split()` → 下次 `buf.reserve(4096)` 必然新分配） | 未测（本 bench 只有下行；上行流量≈0） | 下行已由 `dl_stream.rs` 池化（9eu4a：1.758→1.145 MB/MB），**上行仍是 tokio-util 默认 4 KiB 逐块新分配**；同时把 h2 DATA 帧粒度钉死 4 KiB（下行 64 KiB）→ 帧数 ×16 | **E2**：命令 `read C:/Users/Begonia/.cargo/registry/src/index.crates.io-*/tokio-util-0.7.18/src/io/reader_stream.rs:120-155`（`let chunk = this.buf.split();`）＋`read crates/xray-transport-splithttp/src/dialer.rs:229-231`；量级代理 = 9eu4a 对下行测得的 1.0 MB/MB 全额 | **≈1.0 MB / MB 上行载荷 + 256 次 alloc/MB**（4 KiB 块）；上行吞吐受 4 KiB 分片折损 | 复制 `dl_stream.rs` 的池化流（`Bytes::from_owner` + `BufPool`）替换 `ReaderStream`，并把 `duplex(8192)` 提到 64 KiB 与下行对齐 |
| **W3** | 每次 `read_multi_buffer` / `write_multi_buffer` 一次装箱 future | **P2** | trait：`xray-buf/src/io.rs:81`（Reader）/`:148`（Writer）返回 `Pin<Box<dyn Future>>`；实现：`reader.rs:53`、`readv.rs:343`（`Box::pin(self.read_multi())`）、`writer.rs:53/245` | tcp-tls cli `buf_read` = 34,949,928 B / 13,137 次 = **0.167 MB/MB / 65.7 alloc/MB**；full cli `buf_read` = 0.182 MB/MB / 128.5 alloc/MB | 每读固定 2 次堆分配：①`Box::pin(future)`；②`MultiBuffer::from_buffer` 的 `vec![buf]`（`multi.rs:36`）。**池化救不了**（这是返回值形态，不是数据缓冲）。写侧同构：每次 `write_multi_buffer` 一次装箱 | **E1**（站点字节/次数）＋**E2**（trait 签名 + `Box::pin` 行）；命令同上，看 `site=buf_read`。次数口径：读次数 × 2 | ≥1 alloc / 次读或写；按 8 KB 读粒度 = **256 次 alloc / MB**，按 64 KB readv = 32 次 / MB | **不要重做**：`76feeba3` 曾以「具名 future 消装箱税」实现，被 `d820547f`/`c56b442d` 整体回退（判定「poll 化归 feature/framework 支路」）。本票只登记它至今仍在付费，动它属架构改形（需单独立项 + 32/32 双闸） |
| **W4** | h2 下行块池残留（9eu4a 之后） | **P3** | `xray-transport-splithttp/src/hub/dl_stream.rs:51 take` / `:60 put` | full srv `xhttp_srv_send` = 12,409,264 B / 200 MiB = **0.062 MB/MB**，7,488 次，**均值仅 1,657 B/次** | 关键读数：**每块 64 KiB 的池块已基本不再新分配**（200 MiB ÷ 64 KiB = 3,200 块，若仍逐块新分配应产生 209.7 MB 而非 12.4 MB）；7,488 次 1.66 KB 的分配是**同 poll 段内的小对象**（帧/meta 侧），非池未命中。[INFERENCE]：落在 hyper `Frame`/`Body` 管道里，本仓无站点可见 | **E1**；命令同上拓扑 A | 0.062 MB/MB（srv 5.3%），已是噪声级 | 无需再修（9eu4a 已把 1.758 → 1.145 全额拿到）。若要收零，须先给 hyper 帧层补站点再谈 |
| **W5** | UDP 每数据报 2–4 次堆分配 + 2 次载荷拷贝 | **P2** | 入向 `xray-app-dispatcher/src/udp_session.rs:95`（`Vec::with_capacity(payload.len()+666)` 逐包）、`:105`（`extend_from_slice(payload)`）；出向 `xray-proxy-freedom/src/udp.rs:508`、`xray-proxy-socks/src/udp.rs:379`（`Vec::with_capacity(n+64)` + `PacketWriter::new`）；解包 `xray-xudp/src/packet.rs:439`（`vec![0u8; len]`）、`:305`（`PacketWriter::new` 内 `Vec::with_capacity(64)` scratch 逐实例新建）；`MultiBuffer::new()+merge_bytes`（`multi.rs:202`）再拷一次 | 未测（UDP 面无站点；`--variant direct` 脚本 bug） | 同一收/发路径上：①`Vec` 帧每次新建；②`PacketWriter` 实例每包新建（其 `scratch` 本该跨包复用却随实例一起重建）；③载荷 `Vec → Buffer` 又拷一遍。**mux 已有正确范式**（`xray-mux/src/writer.rs:239-262` 直写池化 `Buffer::writable_bytes()`），UDP 面没采用 | **E2**：`read crates/xray-app-dispatcher/src/udp_session.rs:88-110`、`read crates/xray-xudp/src/packet.rs:290-330,405-445`、`read crates/xray-proxy-freedom/src/udp.rs:504-520` | **每数据报 2–4 次 alloc + 2 次全量拷贝**（1200 B 包 ≈ 2.4 KB 拷贝/包）；按字节 ≈ 2.0 MB/MB，按次数远高于 TCP 泵（TCP 每 8 KB 2 次，UDP 每 1.2 KB 4 次 = **27×**） | 会话级常驻 `scratch: Vec<u8>` + 复用 `PacketWriter`（`packet.rs` 已有 scratch 字段，只需把实例提升到循环外）+ 直接用池化 `Buffer` 装帧 |
| **W6** | 池只回收「容量恰等于层大小」的块 → `split_to` 产物永不回池 | **P3** | `xray-buf/src/alloc.rs:181-186`（过滤）；产物侧 `buffer.rs:402/428`（`Pooled` 分支 `m.split_to(n)` 后 front 容量 = n） | 未测（无站点覆盖 `split_bytes`） | `release` 丢弃非标容量块是有意安全闸（`08852d7b` 假池污染史），但副作用：`MultiBuffer::split_bytes`（`multi.rs:80`，AEAD chunk 切分、BufferedReader 半包、kcp 重组均在用）产出的 front 块容量必然非标 → 全部 drop 回系统 → 下次 `Buffer::new()` 又新分配 | **E2**：`read crates/xray-buf/src/alloc.rs:173-215` + `read crates/xray-buf/src/buffer.rs:400-455`；可跑的量化办法：`XRAY_ALLOC_STATS_SITES=1` 跑 vmess 拓扑（chunk 切分最密），看 `buf_read` 外的 untagged 是否随 `split_bytes` 次数等比 | 每次 chunk 切分 ≈ 丢失 1 块（8 KB 级）；vmess 8 KB chunk → 最多 128 块/MB 丢失 | 只登记：改成「按容量区间归层 + alloc 侧校验实际容量」会动到红线文件 `alloc.rs`，须单独立项 |
| **W7** | 8 KB 单缓冲读（readv 不可达时的兜底粒度） | **P3** | `xray-buf/src/reader.rs:59-84`（`SingleReader`，池化 8 KB）；不可达判据 `bridge.rs:366` | full cli `buf_read` 均值 **1,418 B/次**（25,692 次 / 36.4 MB）、tcp-tls cli 均值 **2,660 B/次**（13,137 次 / 34.9 MB）→ 每次读都远小于一个 8 KB 块（受 TLS record 上限约束） | 不是浪费本身，而是**放大了 W3/W1 的每次开销**：粒度越小，每 MB 的 alloc 次数越多（8 KB → 128 次/MB；readv 64 KB → 16 次/MB） | **E1**（均值 + 次数）＋**E2**：`bridge.rs:366-381` 三态选择 | 每 MB 的读次数（8 KB vs 64 KB = 8×） | `tls_readbuf_size`（`utls.rs:199/441`，F3）已能把 rustls 客户端缓冲放大；仍受 `poll_read` 单 record 交付限制 → 与 W1 同源，一并考虑 |
| **W8** | `bridge_link_with_stream`（旧串行泵）逐读 `merge_bytes` 拷贝 | **P3** | `bridge.rs:184-203`（`MultiBuffer::new()` + `mb.merge_bytes(&buf[..n])`） | 无生产调用方（grep 只有文档引用） | 每 8 KB 一次 `Buffer::new()` + 全量拷贝 + `Vec` 增长 | **E2**：`grep bridge_link_with_stream`（生产零调用，仅 `bridge.rs` 文档 + dispatcher 注释）；命令见 §5 | 死代码（不改=零影响）；**误用=每次读多 2 次 alloc + 1 次拷贝** | 标 `#[deprecated]` 或删除，防后续接线踩到 |
| **W9** | `authentication_reader/writer` 的 `to_vec` 拷贝链（`seal`/`open`/`chunk_data.to_vec()`） | **P3** | `xray-crypto/src/auth_writer.rs:152`（`chunk.to_vec()`）、`:117`（`copy_from_slice` 第三拷）；`auth_reader.rs:115/199`；`aead.rs:254/295` | 零生产消费（vmess/ss 各自独立实现） | 死代码，但代码形状是「三段全量拷贝」，一旦被接线就是 3 MB/MB | **E2**：`grep AuthenticationWriter` over `crates/`（除 `xray-crypto` 自身零命中） | 0（当前）；误用 3 MB/MB | 标 `udf-promotion-candidate` 之外应标 `dead-code`；删除前确认无外部消费方 |
| **W10** | 客户端 `dial_stream_up` 上行管道 8 KiB vs 下/服务端 64 KiB | **P3** | `xray-transport-splithttp/src/dialer.rs:230`（`tokio::io::duplex(8192)`）vs `hub/handler.rs:50`（`DUPLEX_BUF = 64 * 1024`） | 未测 | 8 KiB duplex 使上行背压窗口比下行小 8×，叠加 W2 的 4 KiB 读出粒度 | **E2**：`read crates/xray-transport-splithttp/src/dialer.rs:228-231` + `read crates/xray-transport-splithttp/src/hub/handler.rs:48-52` | 上行 1 个 RTT 内的在飞量与 h2 帧数（帧数 ×16） | 与 W2 同批改：`duplex(64 * 1024)` + 池化流 |

---

## 4. 零拷贝 / 切片面专节：本仓到底有没有在做零拷贝

**结论：帧内零拷贝成立，跨层边界每层一次全量拷贝。TLS 链路上载荷共 3 次全量拷贝，其中 1 次可消除（W1）、1 次是内核↔用户面的固有成本。**

### 4.1 真实成立的零拷贝面（P）

| 面 | 机制 | 位置 |
|---|---|---|
| 帧内多段不合并 | `MultiBuffer` 持 `Vec<Buffer>` 链，读/写/切分都在链上做，不做扁平化 | `multi.rs:12-20`、`split_bytes` `:80` |
| 段内分割 | `Pooled` 走 `BytesMut::split_to`（引用计数 O(1)）；`Frozen` 走 `Bytes::slice` | `buffer.rs:402-455` |
| 外部所有权接管 | `from_bytes_frozen(Bytes)` / `from_vec(Vec)`（`Bytes::from(vec)` 零拷贝接管堆） | `buffer.rs:71-95`；h2 body 走 `frozen_reader`（`splithttp/connection.rs:367`） |
| 聚集读 | `ReadVReader` 一次 `try_read_vectored` 填 ≤8 个池块（栈上 iovec 批，零堆分配） | `readv.rs:140-296` |
| 聚集写 | `write_all_mb` 把 ≤8 个 `Buffer` 组 `IoSlice` 栈数组单次 `write_vectored` | `bridge.rs:228-273`；`writer.rs:96 write_vectored_all` |
| 就地加解密 | `seal_into`（追加进复用 `frame`）、`open_in_place`（就地解密） | `aead.rs:258/302`；vmess `body_chunk.rs:305/434` |
| 内核旁路 | `splice(2)` 页级搬运（Linux/Android + 裸 TCP 才可达） | `xray-transport/src/splice.rs:63-213` |

### 4.2 每层边界的一次拷贝（逐层账）

以 tcp-tls 拓扑、下行 200 MiB 为例（= 审计实测口径）：

```
内核 socket 缓冲
  └─[拷贝①] rustls deframer_buffer（16 KB 起，高水位复用；8b5453ef 已消缩容 churn）
        └─ AES-GCM 就地解密（零拷贝，plaintext 复用同一块）
              └─[拷贝②] Payload::Borrowed → to_vec()  ← W1，1.000 MB/MB，可消除
                    └─ ChunkVecBuffer（Vec<u8> 队列，每 record 一块）
                          └─[拷贝③] tokio-rustls poll_read: buf.put_slice(&data[..len])
                                └─ xray-buf 池化 Buffer（BUF_READ 站点，14%）
                                      └─ MultiBuffer 链（零拷贝）
                                            └─ link.writer / 下一跳
```

- **拷贝①**：`DeframerVecBuffer::extend`（`vendor/rustls/src/msgs/deframer/buffers.rs:268`）—— 内核读入，固有成本。
- **拷贝②**：W1，**纯多余**，是本次唯一「可消除的全量拷贝」。
- **拷贝③**：跨 API 边界（rustls 借出 slice → 我们的 `ReadBuf`），除非换 buffered→unbuffered API 才能一并消除；与 W1 同批。
- 写方向：`tls_write` 实测 156 B / 2 次（0.0%）→ **写路径已真零分配**（4y9ns 收口成立）；剩余成本是 record 封装的 CPU 与系统调用，不在分配面。

**为什么说不出「本仓在做零拷贝转发」**：`bridge_link_with_stream_full` 的链路本身零拷贝（`MultiBuffer` 链直通 `write_all_mb`），但上下游两端任何一侧带 TLS 就必然在 TLS 层发生 §4.2 的三次搬运；裸 TCP（splice / readv / vectored）才是真零拷贝路径，而它在 **Windows 不可达（splice）**、在 **包装连接不可达（readv/vectored）**。

### 4.3 「假池 / 切片」隐患复查（只审不改，`alloc.rs` 红线）

| 检查项 | 结论 |
|---|---|
| `from_vec` 假池 | **已修且正确**：`Buffer::from_vec` → `Inner::Frozen`（`buffer.rs:87-95`），Drop 不回池；注释记录 2026-10-17 节点级死亡史 |
| 非标容量入池 | **已修**：`alloc::release` 的 `capacity != TIER_SIZES[tier]` 过滤（`alloc.rs:181-186`），测试 `release_discards_off_size_blocks` 钉住 |
| alloc/release 配对 | **配平**：`Buffer::release`（`buffer.rs:503`）与 `Drop`（`:527-538`）都走 `alloc::release`，release 后 capacity=0 → Drop 跳过（不会双还）。实测借还配平：full/tcp-tls 站点 `(none)` 桶恒 0、`live_bytes` 窗口末 791 KB / 4.68 MB（长连接在飞，非泄漏） |
| TLS 缓存粘线程 | **已知且受限**：`TLS_CACHE` 为 `thread_local`（`alloc.rs:99`），tokio 任务跨线程迁移会造成缓存不均衡，但全局 8 分片 × 64/层兜底；实测池未击穿（buf_read 均 2.6 KB/次 ≪ 8 KB 块 → 大部分命中） |
| 站点统计开销 | **零开销闸成立**：`XRAY_ALLOC_STATS_SITES` 未设时 `alloc_site::enabled()` 一次 Relaxed load 短路（`xray-cli/src/alloc_stats.rs:135`、`xray-common/src/alloc_site.rs`） |
| `record` 跨域污染 | **已修**（a65px）：跨 `.await` 一律走 `scope` 未来域（`bridge.rs:315`），`enter` 限同 poll 段 |

---

## 5. 负优化预审（强制项，提出任何建议前已查）

`git log --grep="revert|perf|cache|pool" -i` + 相关路径历史：

| 命中 | 内容 | 对本次结论的约束 |
|---|---|---|
| `d820547f` / `c56b442d`（revert） | 回退 `76feeba3` 的 **`io.rs` trait poll 化**（「具名 future 消全链 `Pin<Box<dyn Future>>` 装箱税」），理由：性能优化与架构改形分离裁定，poll 化归 feature/framework 支路 | **W3 不可直接重做**。本报告只登记「装箱税仍在付费」，不得建议「照 76feeba3 再来一遍」——那是同一改形，当时回退根因（waker 死锁、32 文件波及）未消除 |
| `247986c8` / `4aef6880`（revert） | 回退 SSE4 启用（劣化 vision 正确性 8/10→3/10） | 任何 AES/vision 热路径优化须过互通闸，不得以吞吐换正确性 |
| `dbdfc83d`（revert） | 删除 `TCP_NOTSENT_LOWAT`（TTFB 收益证伪） | 不得以「TTFB 应该变好」为理由提网络层参数改动 |
| `e37c1c3f` | TLS1.3 resumption 真根因是新 session ticket 回调，**并回退 rcvbuf 到 4 MB** | 缓冲区尺寸类改动有回退史，须实测 |
| `1b7ca840` 前的 `e57cfee3` | reflow 过 vision splice 埋点 | vision 面埋点/结构改动谨慎 |
| `08852d7b` / `12899026` | 修「`from_vec` 误标 Pooled 污染池层级」「release 按层过滤」 | **W6 不得为省分配而放宽 release 过滤**——历史三次节点级死亡 |
| `8b5453ef` | vendor/rustls deframer 缩容条件修正（tls_read −79%，吞吐 +21.7%） | 证明「改 vendor/rustls 可获批」，W1 走同一审批路径有先例 |
| `17d23baa` | 客户端读缓冲池化（buf_read 2,551 MB → 46-68 MB，−98.3%）；明确记录 `tls_read` 当时占 54%，判为「vendor 红线不可改」 | W1 的量化在本票更新为 **1.0003 MB/MB**（已被 8b5453ef 削掉 churn 后的残余），仍是同一红线项；本票提供的是**可消除路径**（unbuffered API），不是重复上一轮结论 |
| `9eu4a`（`5fe98b90`） | h2 下行块池自适应 | W2 是其**上行孪生缺陷**；改动范式已在树内，不属新造轮子 |

---

## 6. 建议（按优先级；本报告不实施）

| 优先 | 动作 | 依据 | 闸门 |
|---|---|---|---|
| 1 | **W2**（xhttp 上行池化）：把 `dl_stream.rs` 的 `BufPool` + `Bytes::from_owner` 范式搬到 client 上行，替换 `ReaderStream`，`duplex` 提到 64 KiB | 与 9eu4a 完全同形，下行已证 −0.61 MB/MB | 上行变体 A/B（`ReaderStream` 池化前后）+ h2 DATA 帧尺寸分布不变 + 32/32 |
| 2 | **W1**（rustls unbuffered API）：tokio-rustls 改 `read_tls_unbuffered` 路径，`Buffer` 直接持借用块 | 1.000 MB/MB，cli 84.2% | **红线**（`vendor/`）→ 用户授权；gate = 同窗 A/B alloc/MB + CPU + TLS wire 抓包不变（`tshark D:/Project/tools/Wireshark/tshark.exe`）+ 32/32 + interop 12/12 |
| 3 | **W5**（UDP 帧构建复用）：会话级 `scratch` + 把 `PacketWriter` 提到循环外 + 池化 `Buffer` 直写 | mux 的 `write_meta_with_frame` 已是正确范式 | UDP 站点归因先补（当前无站点，W5/W3 无法量化） |
| 4 | **W3**（装箱税） | — | **不动**：属架构改形，d820547f 已裁定归独立立项 |
| 5 | 归因基建：给 xhttp 上行、UDP 收发、`split_bytes` 补站点（现 4 个站点的 Σ 覆盖不到 20%） | full 拓扑 untagged 仍占 cli 90.4% | 新增站点须零开销闸（现有 `alloc_site::scope` 已提供） |

**不建议做的**（明确列入非目标）：
- 放宽 `alloc.rs` 的 release 容量过滤（W6）——三次节点级死亡史；
- 重做 `io.rs` poll 化（W3）——已裁定回退；
- 在 vision 帧边界上做任何批处理/合并（坑约束 ⑫：vision gate 禁碰）。

---

## 7. 查了什么 / 没查什么

**查了（覆盖派单要求的主范围）**
`xray-buf` 全部 11 个模块（alloc/buffer/io/multi/reader/readv/writer/pipe/copy/timeout/lib）｜`xray-frame/pool.rs` + `assembly.rs` + `context.rs`（接缝与装配注入）｜`xray-transport/bridge.rs`（生产泵四段式、splice 闸、readv 闸、vectored 写、`read_downlink` 站点）｜`xray-transport/splice.rs`｜`xray-core/inbound.rs`（`into_link_io` / `recvmmsg` / pipe 用法）｜`xray-app-dispatcher`（`default.rs` 桥接与 splice 准入、`udp_session.rs` 生产 UDP 会话）｜`xray-xudp/packet.rs`｜`xray-transport-splithttp`（`dialer.rs` 上行、`hub/dl_stream.rs` 下行池、`hub/handler.rs` `DUPLEX_BUF`、`client.rs` body 构造）｜`xray-proxy-vless/inbound/server.rs`（CoalescingWriter 唯一装配点、vision 分叉）｜`xray-proxy-vmess/encoding/body_chunk.rs` + `dispatcher.rs`（chunk 复用、`seal_into`）｜`xray-crypto`（aead/auth_reader/auth_writer/chunk/cryption_io）｜`xray-proxy-ss/stream.rs`｜`xray-proxy-freedom/udp.rs` + `xray-proxy-socks/udp.rs`｜`xray-mux`（writer/frame/worker/client）｜`vendor/rustls`（common_state / msgs/base / deframer/buffers / vecbuf / conn/unbuffered 存在性）｜`vendor/tokio-rustls`（client `poll_read` / common `poll_fill_buf`）｜tokio-util 0.7.18 `ReaderStream` 源码（registry）｜`clippy.toml`｜git 历史（revert/perf/pool/readv/splice 全查）

**没查（如实标注）**
- **h2 / hyper 内部帧层**的分配（`hyper`/`h2` 未 vendor、无站点）→ full 拓扑 cli 90.4% untagged 的主体在此，本票只给到「未归因」边界；
- **btls/BoringSSL 分配面**：C 侧 malloc 不经 Rust 全局分配器 → `TLS_READ/WRITE` 在 btls 路径恒 0（full 拓扑即如此），不是「零分配」，是**不可见**；
- **KCP / QUIC / gRPC / websocket / wireguard / tun 各自帧层**（超本票产出能力，未逐 crate 扫）；
- **`--variant direct` / `plain-xhttp`** 两个拓扑 E1：direct 被脚本自身 bug 阻断（`FileNotFoundError: srv-pw-direct.log`），plain-xhttp 未跑（时间预算优先给了 tcp-tls 主证据）；
- **吞吐结论**：按项目口径本机受控测速不可信，全部结论只基于 allocated bytes / 次数；
- **`xray-stress` harness 的 UDP 面**：未启用（未找到现成 UDP 压测入口）。

**复跑命令一览**

```bash
# 拓扑 A（xhttp+reality+vless-enc）
XRAY_ALLOC_STATS=1 XRAY_ALLOC_STATS_SITES=1 python tools/loopback_alloc_bench.py \
  --tag perfwiring --xray target/release/xray.exe --runs 2 --alloc-stats
# 拓扑 B（裸 TCP+TLS，rustls）—— W1/W3 主证据
XRAY_ALLOC_STATS=1 XRAY_ALLOC_STATS_SITES=1 python tools/loopback_alloc_bench_variants.py \
  --xray target/release/xray.exe --variant tcp-tls --tag pw-tcp-tls --runs 1 --alloc-stats --floor 1
# 接缝零消费自证（应 0 命中）
grep -rn "with_pool(" crates --include=*.rs    # 只有 xray-frame/tests + assembly.rs 自身
# 生产直调 alloc 清单（应只有 bridge.rs + pool.rs）
grep -rn "xray_buf::alloc::" crates --include=*.rs
```

---

## 8. 五维自评

| 维度 | 分 | 说明 |
|---|---|---|
| 准确性 | 5/5 | 全部结论带 file:line；E1 数字逐条可复跑；E2 项均给可跑命令；未见证伪项（W3 的「每读 2 次分配」用 trait 签名 + `vec![buf]` 双点闭合） |
| 完整性 | 4/5 | Q1 三态表覆盖 31 项机制；Q2 十项。扣分：full 拓扑 90.4% untagged 未归因（hyper/h2 无站点）、UDP 面无站点故 W5 只有 E2、direct/plain-xhttp 两拓扑 E1 缺 |
| 清晰度 | 5/5 | 三态表 + 按 MB 排序的浪费表 + 独立零拷贝账（逐层拷贝编号） |
| 可执行性 | 5/5 | 每条浪费给「建议一行」；§6 给优先级与闸门；复跑命令逐字可重放 |
| 诚实度 | 5/5 | 负优化预审命中 3 条（poll 化/SSE4/NOTSENT_LOWAT）并据此收窄建议；主动标注 btls 分配不可见 ≠ 零分配；未重开 4y9ns/r1693/q1r4q（只标它们的新债 W3/W6） |
