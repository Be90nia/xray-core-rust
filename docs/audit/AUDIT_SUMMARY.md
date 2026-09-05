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
