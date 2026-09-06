# Xray-core-rust 深度审计汇总 (AUDIT_SUMMARY)

> 审计日期: 2026-09-05 | 基线: v54 后 HEAD ee7c6c7 | 方法: 6 维度并行只读审计,不改任何代码
> 基准对照: Go Xray-core v26.7.28 (D:/Project/Xray-core) | 报告均含 file:line 证据

## 统计总览

| 维度 | 报告 | P0 | P1 | P2 |
|---|---|---|---|---|
| 性能优化 | [performance.md](performance.md) | 0 | 5 | 7 |
| 内存+泄漏 | [memory.md](memory.md) | 0 | 4 | 6 |
| 高并发 | [concurrency.md](concurrency.md) | 0 | 3 | 4 |
| 功能完善度(对照 Go) | [completeness.md](completeness.md) | 0 | 6 | 15 |
| 功能 bug+静默失败 | [bugs.md](bugs.md) | 1 | 1 | 2 |
| 安全 | [security.md](security.md) | 2 | 3 | 9 |
| **合计** | | **3** | **22** | **43** |

## P0(必须立即修)

| # | 维度 | 发现 | 位置 | 一句话 |
|---|---|---|---|---|
| S1 | 安全 | SOCKS Password 认证完全绕过 | xray-proxy-socks/server.rs:366-377,296-331 | 方法协商 NoAuth 回退 + SOCKS4 零校验双路径,Go 基准均严格拒绝 |
| S2 | 安全 | HTTP 握手无界+无超时 | xray-proxy-http/server.rs:306-328; xray-core/inbound.rs:1866 | 无行长度/行数上限,无 policy 时握手无超时 → 未认证单连接 OOM/slowloris |
| B1 | bug | TUIC H3 帧长无上限 | xray-proxy-tuic/h3.rs:182-190 | 未认证对端 9 字节帧头即触发 `vec![0u8; len]` TB 级分配 → 进程 abort |

## P1 按主题分组(22 条,详见各报告)

**内存泄漏(4)**: reverse BridgeWorker↔ServerWorker 强引用环(worker.rs:355) / DNS 缓存清理任务零调用方(ips 无上限) / ss2022 UDP server_sessions 只插不删(inbound.rs:1102) / reverse monitor 无视 close()(重启双循环)

**并发(3)**: mux XUDP clone 语义破坏状态流转→同 GlobalID New 帧静默丢弃+条目泄漏(worker.rs:276) / VLESS ENC 共享锁跨无超时握手→服务端黑洞时 outbound 永久挂死(dispatcher.rs:178) / burst healthping 锁内同步探测 200s 量级占死 worker(burst_observer.rs:220)

**安全加固(3)**: REALITY hooks 错误路径泄漏+地址复用串号(btls_reality.rs:234) / 无 policy 时 socks/http/mixed 握手零超时(slowloris) / SS-2022 UDP 会话 HashMap 永不清理(与内存组交叉确认)

**性能(5)**: 裸 TCP 腿无 writev 批量(每 64KB 多 7 次 syscall,writer.rs:36) / 加密数据面每 record 2-4 次堆分配(Go 为池化 in-place) / finalmask 每包 spawn+假唤醒(mod.rs:447) / buf 池无上限不收缩(alloc.rs:153) / CommonConn 每 record 双分配+memmove

**功能完善度(6)**: 生产路由装配 NotImplementedSelector→balancer 全失效(wiring.rs:376) / httpupgrade 入站 TLS acceptor 构建后丢弃(register.rs:89) / FakeDNS 引擎从未注入(register.rs:684) 等三处"定义了但没接线"

**bug(1)**: Trojan 客户端 UDP 帧解析错误被吞→rbuf 无界增长 OOM 且零日志(dispatcher.rs:223,入站侧有正确处理可对齐)

## P2 摘要(43 条,详各报告)

nonce 换 key 不对称 / SlidingWindow 淘汰后重放窗口 / from_utf8_unchecked UB-by-contract / legacy SS seen_ivs 无界 / policy level-1 覆盖用户配置 / plain HTTP 静默吞错 / observatory 内联阻塞探测 / mux 空池并发穿透 / tuic 池无 single-flight / buf 双分配池化机会 等

## 审计可信度说明

- 全部发现带 file:line 代码证据;TOP 发现经二次 grep/read 复核
- 防误报: 近期已根治项清单(poll_write 裸 Pending/dirty 状态机/ss2022 sing wire/私钥嗅探/UDP 路由/xor_mode 等)已下发各代理,未出现重复报告
- 负优化预审: 与历史 revert(splice×2/xor 重写)逐一核对无冲突
- unsafe 全仓 37+ 文件逐一评估: 仅 2 处需关注(btls hooks + from_utf8_unchecked),其余必要且正确
- 9 个高风险编解码点(vmess/mux/KCP/socks5/trojan UDP/hysteria varint/DNS)对照 Go 确认无缺陷
- 限制: 静态审计+逻辑推导,未跑 benchmark/模糊测试;P0/P1 修复后建议以现有 e2e 矩阵回归

## 建议修复顺序

1. **P0×3**(安全+远程 abort): SOCKS 认证绕过 / HTTP 握手界限 / TUIC 帧限幅 —— 都是未认证可达,优先级最高
2. **P1 泄漏+挂死组**: ENC 锁跨握手 / XUDP clone 语义 / 三个会话表泄漏 / reverse 引用环
3. **P1 功能组**: balancer NotImplementedSelector / httpupgrade TLS 丢弃 / FakeDNS 未接线(用户可感知的功能缺失)
4. **P1 性能组**: writev / 分配池化(收益最大路径: 加密数据面)
5. P2 按需清偿

---

# 第二轮补漏审计 (2026-09-05,5 切面)

第一轮没覆盖的切面:全平台对称 / 配置→装配 diff / 超时矩阵 / 传输层字节级 / 可观测性。

## 第二轮统计

| 切面 | 报告 | P1 | P2 | P3 |
|---|---|---|---|---|
| 全平台对称 | [platform.md](platform.md) | 0 | 3 | 5 |
| 配置→装配 diff | [config_wiring.md](config_wiring.md) | 4 | 10 | - |
| 超时/资源限制矩阵 | [timeouts.md](timeouts.md) | 3 | 7 | - |
| 传输层深度 | [transport_deep.md](transport_deep.md) | 3 | 16 | 9 |
| 可观测性/统计 | [observability.md](observability.md) | 3 | 3 | 1 |
| **小计** | | **13** | **39** | **15** |

## 两轮合计: P0×3 / P1×35 / P2×82 / P3×16

## 第二轮 P1(13 条)

**配置静默失效组(系统性 camelCase 键名不匹配)**:
- C1 policy 键族静默全丢(connIdle/uplinkOnly/bufferSize/statsUser*/system) app_config.rs:42-87
- C2 observatory/burstObservatory 键族整体 no-op app_config.rs:94-120
- C3 burst executor 生产无注入路径,Rust 方言键致 instance.start() 硬失败 burst_feature.rs:59
- C4 出站级 mux.enabled 静默无复用(concurrency 零消费) outbound.rs:490-507

**超时/资源限制组**:
- T1 vless/trojan/vmess/ss 四协议 inbound 握手读无超时,配 policy 也不生效(slowloris 全覆盖) vless server.rs:643 等
- T2 policy bufferSize 单位错 1024 倍:用户配 512KB 被钳成 512B,吞吐坍缩 register.rs:436-443
- T3 hysteria 认证后 varint 直接分配→单帧进程 abort(TUIC P0 同族,认证后降 P1) protocol.rs:105-116

**传输层组**:
- R1 hysteria UDP 中继 Rust↔Go 断裂:Go 日期门触发 quic-go 不发 DATAGRAM TP,send_datagram 全败(quinn 无 AssumePeer);TCP 路径不受影响故 32 节点未暴露 quinn_adapter.rs:193
- R2 gRPC multiMode 多元素 MultiHunk 帧静默截断→Go→Rust 方向数据丢失 bulk 必现 transport.rs:76-88
- R3 mKCP 服务端 sessions 表永久泄漏(close 空实现)+同 conv 重连锁死 listener.rs:223-228

**可观测性组**:
- O1 用户级流量统计/在线 IP 统计生产零接线(消费端就绪计数端缺失,配置静默无效) default.rs:713-734
- O2 metrics 导出器 StatsCollector 未注入,/metrics 恒空 register.rs:397-410
- O3 anytls 出站 >255 字节域名 expect panic,远端一条 HTTP CONNECT 稳定复现(全仓 317 处 unwrap 审计后唯一网络可达 panic) anytls socks.rs:56-62

## 亮点确认(干净项)

- KCP 状态机/RTT/序号回绕、gRPC 帧编解码/半关闭、WS 帧桥、quicParams 映射、tuic 池生命周期:字节级对照确认干净
- 平台五维(dup/epoll-IOCP/信号/路径/setrlimit)核销无缺口;Linux/Windows 双向无 P1 平台缺陷
- xpadding Huffman 表 19 处错值(P2,脚本对拍 RFC 7541 发现)——tokenish 指纹用户注意

## 修订后修复顺序

1. **P0×3**(不变): SOCKS 认证绕过 / HTTP 握手无界 / TUIC 帧限幅
2. **新增 P1 插队**: 四协议握手无超时(T1,与 P0 同族 slowloris) / bufferSize 1024 倍(T2,一配就坏) / hysteria varint 炸弹(T3)
3. **配置失效组 C1-C4**(用户配置静默不生效,信任损害最大面)
4. **传输层 R1-R3**(hysteria UDP 互通断裂/multiMode 丢数据/mKCP 泄漏)
5. **可观测性 O1-O3 + 第一轮泄漏/挂死/功能组**
6. P2/P3 按需
