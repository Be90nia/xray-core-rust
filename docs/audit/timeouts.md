# 超时与资源限制矩阵审计 (timeouts)

> 审计: 2026-09-05 第三方核验恢复落盘 | 方法: 全仓 timeout 包装覆盖率矩阵 vs Go policy 默认值
> 结论: DNS 查询(4s)、QUIC/系统拨号(16s)、TUIC 拨号(30s)、bridge 数据泵 idle 覆盖良好;缺口集中在 **inbound 握手读**与 **policy 参数消费链**

## Go 基准

- handshake=**60s**(features/policy/policy.go:127-134,非 4s)、connectionIdle=300s、uplinkOnly=downlinkOnly=1s
- 全部 inbound(vless/trojan/vmess/ss/hysteria)decode 前设 `SetReadDeadline(Timeouts.Handshake)`(vless inbound.go:282 / trojan server.go:153 / vmess inbound.go:229 / ss server.go:202)
- bufferSize 单位 KB,构建时 ×1024(infra/conf/policy.go:29-33);-1=无限制;默认走 WithoutSizeLimit

## P1 发现

### T1 [P1] vless/trojan/vmess/ss 四协议 inbound 握手读完全无超时(policy 在场也不生效)

- vless: `decode_request_header(false, &mut first, &mut stream, ...)`(inbound/server.rs:643-645,fallback :266 同)无 timeout 包裹
- trojan: 服务端握手 6 段连续 `read_exact`(xray-proxy-trojan/src/server.rs:236-325)无超时
- vmess: `decode_request_header_async`(xray-proxy-vmess/src/inbound/server.rs:169)无超时;仅错误 drain 路径硬编码 4s(:181-182,注释称"对齐 4s"但 Go 默认 60s)
- ss: serve_ss 全路径(xray-core/src/inbound.rs:824-973)无 timeout
- 影响: 未认证 TCP 连接连上不发数据即可无限期占住 tokio task+FD+TLS 缓冲(slowloris);即使配置 policy.handshake 也不生效——代码路径没有消费该值
- 修复: 四个 serve 入口补 handshake_timeout(取 policy_for_level,缺省 60s),握手段 `tokio::time::timeout` 包裹;vmess drain 4s 改读 policy
- 负优化自查: 纯增加超时,对正常握手(毫秒级)零影响;注意 timeout Duration 必须从 policy 读而非再硬编码

### T2 [P1] policy bufferSize 单位错 1024 倍:用户配 512(KB)被钳成 512 字节

- 链路: xray-conf `buffer_size: Option<u32>` 原样透传(app_config.rs:54)→ register.rs:436-443 `connection: bs as i32` 无 ×1024 → policy convert.rs:65-74 1:1 → dispatcher `pipe_opt.limit`(default.rs:703-707)按字节语义使用(pipe.rs:64-66)
- 影响: 按 Go 语义写 bufferSize:512(512KB)的连接被钳到 512B 写窗口,吞吐坍缩;附带:①Go `-1`=无限制,Rust u32 无法表达,配置解析直接失败 ②Rust 默认 DEFAULT_BUFFER_CONNECTION=512KB 恒 WithSizeLimit,Go 默认 -17 走 WithoutSizeLimit——默认行为即偏离
- 修复: register.rs 构建处 ×1024;buffer_size 改 i32(<0 → 无限制);默认值对齐 Go
- 负优化自查: 修的是数值换算,零性能影响;-1 语义注意 pipe limit=-1 的既有约定

### T3 [P1] hysteria 认证后 TCP request 解析 varint 直接分配:单帧进程 abort

- `read_tcp_request` 中 addr_len/padding_len 均线上 varint(可达 2^62,protocol.rs:31-45),`vec![0u8; addr_len]`(:105)与 `vec![0u8; padding_len]`(:114)分配先于校验;调用方 8192 字节累计上限(inbound.rs:376-386)防"解析不动"不防"解析得动"
- 已认证客户端发 padding_len=2^40 即 TB 级 alloc → abort;客户端侧 read_tcp_response `vec![0u8; msg_len]`(:152)同形
- 对照 Go: 读前 SetReadDeadline(HANDSHAKE)(hysteria server.go:132-143),padding 流式丢弃不整块分配
- 修复: addr≤255+16 / padding,msg≤64KB 上限,超限 ProtocolParse 错;padding 按块读丢弃
- 负优化自查: 限幅只砍非法值,合法流量(addr 最长 255+16)零影响

## P2 发现(7 条)

1. **bridge 数据面超时硬编码**:用户 policy 的 connIdle/uplinkOnly/downlinkOnly 全部不生效(bridge.rs:174-256 常量);且半关闭窗口 UplinkOnly/DownlinkOnly 语义与 Go **互换**(被硬编码掩盖,bridge.rs:124-290 与 Go app/dispatcher 对照坐实)
2. **ws/grpc/httpupgrade 双侧握手无超时**,客户端拨号绕过 dial_system 的 16s 包装
3. **TUIC lazy 初始化无超时**(pool init 路径,dial 本体已有 30s)
4. **QUIC/hysteria 拨号无外层超时**(quinn connect 前的 lookup_host/connect 无包装;Go v26.7.28 已移除 QUIC transport,Rust 侧为扩展,基线以 hysteria/tuic 实际需求定)
5. **freedom UDP accum 无上限 + 终止帧不结束会话**(udp.rs:95-215):Go xudp 收到畸形/终止帧即 EOF 结束会话(xudp.go:130-230),Rust Ok(None) 继续累积
6. **dispatcher policy 恒 level 0**:per-connection 用户策略无法到达(与 O1 统计未接线同域)
7. **buffer 默认值语义偏差**(并入 T2 附带项,独立跟踪默认行为对齐)

## 附:unbounded 通道全景

全仓 unbounded_channel 大多在 #[cfg(test)];生产命中:xicmp(第一轮已报)、fakedns `LruCache::unbounded()`(fakedns/mod.rs,有容量语义待核)、freedom udp relay(见 P2-5)。quinn_adapter 三处 unbounded 全在测试模块,干净。

## 确认干净项(证据)

- dial_system 16s 超时与 Go 对齐(system_dialer.rs)
- DNS 查询默认 4s 对齐(app-dns cached.rs)
- TUIC 拨号 30s 包装(dispatcher.rs:140-200)
- bridge ConnectionIdle 生产接线存在(只是硬编码,见 P2-1)
- policy manager 生产接线完整(set_policy_manager 全仓有消费)
