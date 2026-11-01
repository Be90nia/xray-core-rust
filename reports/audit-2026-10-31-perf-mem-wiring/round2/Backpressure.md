# 第二轮审计 R2-慢对端 / 资源耗尽面（从外往里）

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 实物：`target/release/xray.exe`（`version` 输出 `git_rev=5fe98b907c7b550d4a70202abb475e26ee89013d`，与 HEAD 一致）
- 口径：生产主路 = 默认 `xray.exe run -c`（本报告全部实测走该二进制，无 cargo 构建）
- 视角：**攻击者/故障/慢对端**——对端不发读、只发不收、半开连接、握手蹲坑、会话风暴
- 与第一轮无重叠：本轮 5 条发现全部是「对端行为驱动的外部资源上界」；第一轮 18 条（接线/分配/泄漏）一条未重报
- 全部脚本可复现：`reports/audit-2026-10-31-perf-mem-wiring/round2/scripts/`，采样 TSV 在 `round2/tmp/`
- 环境说明：① 端口段自用 18.0xx/18.1xx + 目标 190xx，未与他人撞；② 13:25 有代理执行 `Stop-Process -Name xray -Force` 按名广杀，**本次未受影响**（所有探针在误杀前已完成并自行 `proc.terminate()`，无需重启、无数据缺口）；③ 运行期间可能有其他代理的 xray 实例并发争用 loopback/CPU——本报告全部判据是 **RSS 增量与字节数**（如 2000MB→2592MB）与 **句柄计数**，非吞吐/延迟，故并发环境不改变结论

## 0 结论

`VERDICT: FAIL` —— **存在 1 条未认证远程 OOM**（splithttp packet-up 请求体无上限整读，实测单连接 7.7s 把 RSS 打到 2.59GB），
外加 3 条未认证会话表无上限（dokodemo 每源地址 152KB/源、socks UDP 每会话 55.8KB、splithttp session 表 952KB/会话）
与 1 条 h2 并发流无上限（41.7KB/流，单 fd 放大 20MB）。
TCP 双向泵（含半关闭、握手限时、UDP 多目标）经实测**守住了上界**，问题集中在 **HTTP 传输层读 body** 与 **UDP/会话表**。

## 1 基线与瓶颈

| 指标 | 基线值 | 瓶颈点 | 根因 |
|---|---|---|---|
| 单连接 POST 大 body 的 RSS | 16.3MB | **2592.2MB**（+2576MB，7.7s 推 2000MB） | `body.collect()` 无上限，尺寸校验在整读之后（Go 用 `LimitReader` 前置） |
| dokodemo UDP 每源会话 | 16.2MB | **135.1MB / 800 源**（152KB/源，线性） | `peers: HashMap<SocketAddr, _>` 无容量门 + 每会话 mpsc(64)+64KiB buf |
| socks UDP associate 每会话 | 15.9MB | **81.2MB / 1200 会话**（55.8KB/会话，线性） | `UdpDispatchSession` 每会话 `vec![0u8; 65535]` + duplex 256KiB×2 |
| splithttp 会话表（1MB 内 body） | 16.7MB | **121.2MB / 100 会话**（952KB/会话） | `SessionMap` 无容量门，session id 客户端自选，30s 才 reap |
| h2/gRPC 每流成本 | 16.0MB | **36.4MB / 500 流（1 条 TCP 连接）**（41.7KB/流） | Builder 未设 `max_concurrent_streams`，h2 通告无限 |

## 2 发现（8 列）

### F1 — splithttp packet-up 请求体无上限整读入内存（未认证远程 OOM）

| 列 | 内容 |
|---|---|
| 标题 | splithttp `handle_packet_up` 用 `body.collect()` 整读请求体，尺寸校验在整读之后 |
| 严重度 | **P0** |
| 位置 | `crates/xray-transport-splithttp/src/hub/handler.rs:286`（15s 超时包住 collect）→ `:568`（`body.collect().await...to_bytes()`）→ `:292`（`if payload.len() > ctx.sc_max_each_post_bytes` **事后**才判） |
| 触发输入/条件 | 任意 h2（或 h3）客户端：`POST /<path>/<session>/<seq>?x_padding=<100..1000 字符>`，body 持续推送。不需要任何 Xray 凭据——host/path/padding 三项都是默认值可见、客户端流量可得 |
| 后果 | **OOM**：内存 ≈ 15s 内已推送字节数，逐请求独立、可并发（且同连接可开无限流，见 F5）。实测 1 条连接 1 个请求 7.7s 推 2000MB → RSS 16.3MB→**2592.2MB**；15s 到期回 408，攻击者可立即重开 |
| 证据等级 | **E1**：`python scripts/splithttp_probe.py --mb 2000 --port 18100` → `[client0] sent=2000.0MB in 7.7s status=None` / `[splithttp] base_rss=16.3MB peak_rss=2592.2MB delta=+2575.9MB`；采样 `tmp/samples-splithttp.tsv`，日志 `tmp/xray-splithttp.log` |
| Go 侧对照 | Go `transport/internet/splithttp/hub.go:289-300`：先 `if request.ContentLength > scMaxEachPostBytes` 直接 413，否则 `buf.ReadAllToBytes(io.LimitReader(request.Body, int64(scMaxEachPostBytes)+1))`——**最多读 1MB（默认）**。Rust 完全缺失该上限 |
| 建议一行 | `extract_packet_payload` 改用受限流：逐帧累加，`len > sc_max_each_post_bytes` 立即 413（等价 Go `io.LimitReader`），并把 `ContentLength` 预检前置 |

### F2 — dokodemo UDP 每源地址一会话，无上限且每会话 ~152KB（UDP 源可伪造 → 远程放大，未认证）

| 列 | 内容 |
|---|---|
| 标题 | dokodemo UDP per-peer 会话表无容量上限 + 每会话 mpsc(64)+64KiB 常驻 buf |
| 严重度 | **P0** |
| 位置 | `crates/xray-core/src/inbound.rs:1714`（`let mut peers: HashMap<SocketAddr, PeerSession>`）、`:1730`（首包 `mpsc::channel(64)` + spawn）、`:1765`（仅 60s 定时 `retain`，**无 len 上限**）、`:1775`（`DOKODEMO_UDP_IDLE=60s`）；每会话成本来自 `crates/xray-app-dispatcher/src/udp_session.rs:174`（`buf: vec![0u8; MAX_DATAGRAM]`，即 64KiB）+ `:157-158`（`duplex(256KiB)`×2） |
| 触发输入/条件 | 需部署 dokodemo-door 入站（`network: udp`）；向其端口**每源地址发 1 个数据报**。UDP 源地址可伪造，一个攻击主机即可生成任意多源地址；无需 TCP 连接、无需凭据 |
| 后果 | **内存线性无上限 + 会话数无上限**：实测 800 源 → +118.9MB（152KB/源），`peers` 表 60s 才清；量级换算 100k 源 ≈ 15GB。同时每源一条 task + 出站 UDP socket（fd） |
| 证据等级 | **E1**：`python scripts/stream_sessions_probe.py --mode dokodemo --n 800` → `[dokodemo] sources=800 base_rss=16.2MB after_rss=135.1MB delta=+118.9MB => 152.2KB/source handles 165->999`；采样 `tmp/samples-dokodemo.tsv` |
| Go 侧对照 | Go `proxy/dokodemo/dokodemo.go:109-201` 同样是「每源一条 conn → `Process` → `DispatchLink`」，**也无会话上限**（模型平）；差异在**每会话成本**：Go 的 per-session 结构是 `udp/dispatcher.go:173-175` 的 `dispatcherConn{cache: make(chan *udp.Packet, 16)}`，缓冲来自池化 `buf.New()`（`common/buf/buffer.go:13` `Size = 8192`）——空闲会话≈0，队列最坏 16×8KB=128KB；Rust 是首包即提交 64KiB vec + 256KiB×2 duplex 预留 + **64 深度 payload 队列（最坏 64×64KiB=4MB）**，即空闲成本与队列最坏值分别劣化到「不可忽略」与 32× |
| 建议一行 | `peers` 加显式容量门（固定或配置上限，溢出丢弃最旧/直接丢包），`UdpDispatchSession` 的 64KiB buf 改共享池懒分配 |

### F3 — socks UDP associate：每会话 55.8KB 常驻、无上限、存活到 300s ConnectionIdle

| 列 | 内容 |
|---|---|
| 标题 | 每个 UDP dispatch 会话在首包即提交 64KiB buf（+duplex 预留），会话表无上限 |
| 严重度 | **P1** |
| 位置 | `crates/xray-app-dispatcher/src/udp_session.rs:174`（`buf: vec![0u8; MAX_DATAGRAM]`，`establish()` 内即分配）、`:157-158`（`tokio::io::duplex(256KiB)`×2）、`:37`（`DUPLEX_BUF`）；会话生命周期由 `crates/xray-core/src/inbound.rs:436`（`handle_udp_associate` 的 `idle` 键，默认 `ConnectionIdle=300s`，**每收一包续期**） |
| 触发输入/条件 | socks 入站（默认 `auth: noauth`）+ UDP ASSOCIATE（1 条 TCP 控制连接）+ 每会话 1 个数据报；包可指向任意目标（cone NAT 单 socket，目标数不放大） |
| 后果 | **内存线性无上限 + fd**：实测 1200 会话 → +65.3MB（55.8KB/会话）；会话在被持续续期时永不回收（300s 空闲窗），攻击者以很低速率即可长期钉住 N×56KB |
| 证据等级 | **E1**：`python scripts/udp_sessions_probe.py --n 1200 --port 18096` → `associates=1200 ... delta=+65.3MB => 55.8KB/session handles 164->1410`（400 会话同口径 57.6KB/会话，线性）；采样 `tmp/samples-udpsess.tsv` |
| Go 侧对照 | Go `transport/internet/udp/dispatcher.go:173-175`（每 session `cache: make(chan *udp.Packet, 16)`）+ `common/buf/buffer.go:13`（`Size = 8192`，池化）——**空闲会话≈0 字节，无 64KiB 常驻**；会话数同样无上限（平）。此条是「会话模型相同下，Rust 把 idle 成本从 ~0 抬到 56KB/会话并保持 300s」 |
| 建议一行 | 64KiB 收包缓冲改为进程级 `BufferPool` 借还（第一轮 `a0m9d` 的接缝正好可用），并按 `max_buffered_posts` 同风格给 dispatch 会话表加容量门 |

### F4 — splithttp 会话表无上限：session id 客户端自选、30s 才回收、每会话可滞留 64MB

| 列 | 内容 |
|---|---|
| 标题 | `SessionMap` 无容量门；`session_id` 来自 URL，服务端不校验来源 |
| 严重度 | **P1**（与 F1 同一传输、同一未认证面，但 F1 修好也**不能**消掉本条） |
| 位置 | `crates/xray-transport-splithttp/src/hub/session.rs:70-118`（`upsert` get-or-create，无 len 检查；`:105` 30s 定时 reap）、`crates/xray-transport-splithttp/src/upload_queue.rs:101`（每会话 `mpsc::channel(64)`，条目是 ≤1MB 的 payload）、`crates/xray-transport-splithttp/src/hub/handler.rs:292-303`（只有 >`sc_max_each_post_bytes` 才拒，默认 1MB） |
| 触发输入/条件 | `POST /<path>/sess<N>/1?x_padding=...`，`sess<N>` 每次不同，body ≤1MB（刚好过年限检查），从不发 GET（无 GET 则 30s 后 reap） |
| 后果 | **内存线性无上限**：实测 100 会话 × 900KB → +93.0MB（952 字节/1 字节上传，峰值继续涨到 121.2MB）；理论上每会话可堆到 64×1MB=64MB，1000 会话即是 GB 级。未认证 |
| 证据等级 | **E1**：`python scripts/splithttp_probe.py --sessions 100 --concurrency 0 --mb 0` → `session done ok_responses=99` / `base_rss=16.7MB peak_rss=109.7MB delta=+93.0MB per_session=952KB` |
| Go 侧对照 | Go `hub.go:56-88` `upsertSession` + `sync.Map` 同样是**无上限**（模型平），但 Go 每会话持的是 `io.ReadCloser` 流（`upload_queue.go` 的 `Packet.Reader`），**不把 1MB 实体读进内存**；Rust 的 `Packet{payload: Bytes}` 是整包内存（`upload_queue.rs:33-40` 的 ponytail 简化注释自陈「不保留 Reader 流式路径」） |
| 建议一行 | 会话表加容量上限（如 1024，溢出拒绝新 session id），并恢复 Go 的「payload 是流不是整包内存」形态（或至少给队列按字节数封顶而非条数） |

### F5 — h2/gRPC/splithttp 服务端并发流无上限，每流 ~41.7KB，单条 TCP 连接即可放大

| 列 | 内容 |
|---|---|
| 标题 | h2 服务端 Builder 只调窗口，从不设 `max_concurrent_streams`（全仓 0 处设置） |
| 严重度 | **P2** |
| 位置 | `crates/xray-transport-grpc/src/transport.rs:770-774`（`server::Builder` + `initial_window_size(16MB)` + `initial_connection_window_size(32MB)`，无流上限）、`crates/xray-transport-splithttp/src/transport.rs:563-574`（同形态）；grep 全仓 `max_concurrent_streams` = 0 命中 |
| 触发输入/条件 | 一条 TCP（可加 TLS）连接上开 N 个 stream，只发 HEADERS 不发 body：gRPC 路径过 POST+`content-type: application/grpc` 即进 handler，随后 VLESS 握手读把任务挂到 60s 超时 |
| 后果 | **1 fd → N×41.7KB**：实测 500 流/1 连接 → +20.4MB，0 个 RST_STREAM（服务端未通告上限，客户端可无限开）。放大比 ≈ 20MB / 1 fd |
| 证据等级 | **E1**：`python scripts/stream_sessions_probe.py --mode h2streams --n 500` → `[h2streams] opened=500 resets=0 base_rss=16.0MB after_rss=36.4MB delta=+20.4MB => 41.7KB/stream handles 164->173` |
| Go 侧对照 | **splithttp 不齐**：Go 走 `http.Server`+`http2`（`hub.go:559-564`），Go http2 服务端缺省 `MaxConcurrentStreams=250`；Rust hyper 无该设置 = 无限。**gRPC 平**：Go `grpc.NewServer(options...)`（`transport/internet/grpc/hub.go:84-97`）未设 `MaxConcurrentStreams`，grpc-go 缺省也是无限 |
| 建议一行 | 两条 h2 服务端 Builder 加 `.max_concurrent_streams(Some(250))`（对齐 Go http2 缺省），并在装配期按需可调 |

## 3 已测有界（非发现，防止后续误报/回档）

| 面 | 实测 | 结论 |
|---|---|---|
| TCP 上行「对端不读」 | socks→freedom→从不 recv 的目标，客户端推到 **12.4MB 停滞**，RSS +4.6MB | 有界（`pipe.limit=512KiB` 背压 + bridge `mpsc(64)`） |
| TCP 下行「客户端不读」 | 目标狂写 25s，RSS **+1.3MB** | 有界 |
| VLESS 裸 TCP 上行 | 客户端 8.8MB 停滞，RSS **+0.9MB** | 有界（vless 无额外预读缓冲） |
| gRPC 大 body 反压 | grpc 传输同场景只堆到 **1.3MB**（+2.9MB RSS） | 有界：app 停止 poll 后 h2 窗自动关（`release_capacity` 提前归还在实测中**未**放大） |
| 握手蹲坑 | 300 条空连接 = 46KB/连接，**60s 内全部回收**（handles 475→183） | 有界（`handshake_timeout_for` 恒 60s，缺 policy 也兜底） |
| 半关闭 | 300 条 `shutdown(WR)` 连接 **2s 内全部断开**（handles 196→187，客户端 300/300 读到 EOF） | 有界（`bridge_link_with_stream_full` 的 uplink_only/downlink_only=1s 窗） |
| UDP 目标风暴 | 1 会话 4000 个不同目标，RSS **+0.6MB**、handles +7 | 有界（cone NAT：每会话单出站 socket，不按目标建会话） |
| mux 子会话数 | `ServerWorker::process_frame` 的 session id 是 u16（`crates/xray-mux/src/frame.rs`） | 受协议上界约束：单 carrier 最多 65536 子会话，与 Go 平；未做端到端实测（E2，代码证据 `crates/xray-core/src/inbound.rs:333-375`） |

## 4 回归保护（建议挂 CI / 契约测试）

1. **splithttp body 上限**（对应 F1）：测试用 h2 客户端 POST 8MB body（`sc_max_each_post_bytes` 默认 1MB），断言 ①响应 413 ②进程 RSS 增量 < 8MB ③服务端读取字节数 ≤ 上限+1（进程内计数器）。纯断言即可红，不需要压测。
2. **dokodemo / socks UDP 会话上限**（F2/F3）：装配一个 `max_udp_sessions` 后，喂 `上限+N` 个源/会话，断言存活会话数 == 上限、丢弃计数 > 0、RSS 不随未上限输入线性增长。
3. **h2 流上限**（F5）：一条连接开 300 流，断言收到 ≥50 个 `RST_STREAM`（服务端通告 250）或流计数门生效。
4. **回归口径**：以上全部只跑本机 release 二进制（`target/release/xray.exe`），不引入 cargo 构建依赖，符合本轮「用现成二进制实测」的环境约束。

## 5 架构建议（locality / deletion test）

- **F1 的修法必须落在 handler 内部**：`extract_packet_payload` 是唯一读 body 的地方，加上限不外溢任何调用方（deletion test：删掉该函数即无第二个读取点）。
- **F2/F3 共享根因**：`UdpDispatchSession::establish` 的 64KiB `vec!` 是「每会话缓冲」这一设计的泄漏点。正确收敛是把它换成主仓已有的 `xray-buf::alloc` 池（第一轮 `a0m9d` 已指出该池接缝零消费），会话对象只持有「借来的 Buffer」——一处改动同时覆盖 socks/dokodemo/ss2022/vless-UDP 四个消费面，属 module 内部局部化改造。
- **会话表容量门是缺失的抽象**：dokodemo `peers`、splithttp `SessionMap`、UDP dispatch 会话表三处各自 `HashMap` + 各自 `retain`，都没有容量语义。按 CLAUDE.md §3.5.2（禁造轮子），这类「有界注册表 + 淘汰策略」应直接复用 udf `BoundedRegistry`（fail-closed insert + 确定序 iter），而不是在三个地方各写一遍淘汰。

## 6 本轮查了什么 / 没查什么

**查了**：TCP 双向泵背压（socks / vless / grpc 三条路径）、半关闭、握手蹲坑（socks 明文）、pipe/duplex/mpsc 各层缓冲上限与默认值、dokodemo/socks UDP 会话表与每会话成本、ss2022 UDP 会话表（代码面）、splithttp 全链路（body 读取 / session 表 / upload queue / 流上限）、gRPC 服务端 h2 Builder 与 stream accept 循环、h2 收窗放大（16MB/32MB）实测、accept 错误退避（`accept_fd_backoff` 500ms，非忙旋）。

**没查**：① 真机 VPS（本机回环带宽上限，量级换算已标注）；② Go 二进制 A/B（本机无 Go 版 xray，Go 列全部为源码证据 E2）；③ ss2022 UDP 会话风暴的端到端实测（需 PSK 客户端，仅代码面：`serve_ss2022_udp` 的 `sessions`/`server_sessions` 双表 + 每会话出站 socket，500s/60s 双超时，风险形态同 F2 但需认证）；④ hysteria/QUIC 与 tun/wg 的流窗与帧缓冲（Linux 专属面不可本机实测）；⑤ TCP 连接总数的 OS 级 fd 上限行为（无应用层上限，与 Go 平，属部署话题）。

---

### 附：复现命令

```bash
# F1 splithttp body 无上限（2000MB → RSS 2592MB）
python reports/audit-2026-10-31-perf-mem-wiring/round2/scripts/splithttp_probe.py --mb 2000 --port 18100
# F2 dokodemo 每源会话（800 源 → +118.9MB）
python reports/audit-2026-10-31-perf-mem-wiring/round2/scripts/stream_sessions_probe.py --mode dokodemo --n 800
# F3 socks UDP associate 会话成本（1200 会话 → +65.3MB）
python reports/audit-2026-10-31-perf-mem-wiring/round2/scripts/udp_sessions_probe.py --n 1200 --port 18096
# F4 splithttp session 表（100 会话 → +93.0MB）
python reports/audit-2026-10-31-perf-mem-wiring/round2/scripts/splithttp_probe.py --sessions 100 --concurrency 0 --mb 0
# F5 h2 流放大（500 流/1 连接 → +20.4MB）
python reports/audit-2026-10-31-perf-mem-wiring/round2/scripts/stream_sessions_probe.py --mode h2streams --n 500
# 反向对照（有界面）
python reports/audit-2026-10-31-perf-mem-wiring/round2/scripts/bounded_probe.py --mode upslow --mb 800
python reports/audit-2026-10-31-perf-mem-wiring/round2/scripts/bounded_probe.py --mode downflood --seconds 25
python reports/audit-2026-10-31-perf-mem-wiring/round2/scripts/halfclose_probe.py --n 300
```

## 5 维自评

| 维 | 分 | 依据 |
|---|---|---|
| 证据充分性 | 4.5/5 | 5 条发现 5 条 E1，均可用一条命令复现；有界面同样实测（反向对照） |
| 影响判断 | 4.5/5 | F1 直接给到「单连接 2.59GB」的 OOM 数字；每会话成本给了线性斜率，可外推 |
| Go 对照 | 3.5/5 | F1/F5(splithttp) 有精确 `file:line`；Go 侧运行时成本未实测，会话类对照标 [INFERENCE] |
| 生产可达性 | 4/5 | 全部经默认 `xray.exe run -c` 实测；splithttp/dokodemo/socks 均为标准入站，但需部署侧真配了该入站（F1 只对 splithttp 传输成立） |
| 与第一轮去重 | 5/5 | 全为新面对（外部对端行为驱动的上界），18 条禁报名单零重报 |
