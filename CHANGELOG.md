# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- naive 入站实现（88vp 收口）：rustls+hyper h2 CONNECT 隧道（404 fallback/407 恒定时间认证/padding 协商），extra 套件加回 naive；顺带根因修复 outbound PaddingWriter Pending 重入重复发送真 bug
- 互操作矩阵交叉方向扩满：Go→Rust 与 Rust→Go 各 6→12 协议（+splithttp/grpc/reality/hysteria2/anytls/tuic），CI 默认 37→54 测，既有用例零改动
- REALITY mirror 字节级等价（z32z）：新 BoringSSL 原语 `SSL_seal_raw_tls13_record`（inner-plaintext 级 seal，不追加 inner type）经 vendor 注入脚本 → xray-tls 封装（iOS 门控）→ gate 接线恢复发送体，wire 形态与 Go tls.go:417-426 逐字段同构
- readv 热路径 criterion 基准（并发形态吞吐）+ use_readv 闸门收敛单一事实源

### Changed

- 全库 rustfmt 新规则重排（CI stable 工具链升级致 Format job 全库违规，一次性对齐，零语义）
- CI 修复：runner 镜像不再预装 protoc——clippy/build(三平台)/test/docs/fuzz 五 job 补装

- fuzz 基建：cargo-fuzz 三靶（kcp segment / ss2022 packet / vless inbound 解码）+ CI fuzz job（workflow_dispatch 触发，nightly + ASAN 30s/靶 smoke，不阻塞主干）
- 压测泄漏门禁：`tools/check_stress_leak.py` 斜率判定（fd/RSS 超阈 fail，drain 回落豁免固有 idle 堆积）+ stress 场景 `--drain-secs` 阶段接入 `stress.yml`
- 项目 README 真实化（架构/协议/构建/CI 全文档）+ `CHANGELOG.md` 建立

### Changed

- 供应链锁定：btls/tokio-btls/btls-sys/rustls-fork/tokio-rustls-fork 五个 git 依赖 branch→rev 锁定（当前已审基线，禁漂移）
- 生产 unwrap 系统性审计：295 处逐处分类落表 docs/audit-unwrap-2026-09-25.md（infallible 203 / 前置守卫 90 / 真风险 2 修复），口径含三类测试代码剔除法
- 热路径拷贝批：freedom UDP 泵逐读双拷贝→池化直写；MultiBuffer `remove(0)` O(n²) 残余→单次 drain（split_first_bytes/split_first/read_to）

### Fixed

- mux 帧编码 `Network::Unix` 目标远程可达 panic → 显式 `Err`（对齐 Go 无 panic 路径）
- VLESS 0-RTT `handshake_zero_rtt` 会话 TOCTOU expect panic → miss 语义显式拒绝（`expired ticket`）

- 互通矩阵扩展 1.5×2：新增 `rust_to_go` 反向套件（Rust→Go 6 协议）+ 新协议 splithttp/gRPC/REALITY/Hysteria2/AnyTLS/TUIC（默认套件 37 测 = Rust↔Rust 12 + Go→Rust 6 + Rust→Go 6 + 新协议 13）（`1dfdb769`）
- interop 新增 splithttp/kcp/httpupgrade 三脚本（双向 + R↔R 共 12 测），Go→Rust go suite 3→6 协议（`22a08743`）
- 压测 harness `xray-stress`：12 场景协议矩阵（REALITY 短连接风暴/长连接大流量/hysteria2 0-RTT/混合 mKCP+UDP/vmess+ws/trojan+grpc 等）+ RSS/FD/吞吐/延迟分位采样 + ps1/sh/Dockerfile 三档载体 + CI `stress.yml`（`61676c1b`、`b27e2e96`、`b160f6b6`，启动期修复 `1df923ad`、`0bb4176d`、`149f2d7c`、`6aa30564`）
- REALITY 服务端 opt-in btls acceptor：`serverAcceptor` 配置三态（默认 rustls 零回归）+ btls 路径后握手 mirror 记录；iOS target 门控（`aa04602a`、`44027f73`）
- REALITY 后握手记录 FFI 原语 `SSL_send_post_handshake_record`（boringssl 注入 + bindgen，wire 形态对齐 Go reality tls.go）（`5c831c58`）
- REALITY 抗主动探测 maxUselessRecords：CCS 三档探测层（tier 1/16/32/MaxInt）+ vless+reality / splithttp 消费侧接线（`ff145750`、`a20b3f01`）
- Hysteria2 出站 0-RTT（DialEarly parity，port-hop 重连同受益）（`c6296071`）
- XHTTP/3 拥塞控制生产接线：quicParams 缺省 BBR/bbr/reno/force-brutal 全语义对齐 Go dialer.go（`012a3239`）
- sockopt QUIC 系 UDP 端点缓冲：默认 8MB 下限（只升不降 + FORCE 回退，sockopt 显式值优先）（`51d6747e`）
- ECH `echConfigList` 从必败降级接通真实 DoH 查询（RFC 9460 HTTPS RR wire 解析 + echm 提取 + TTL 缓存）（`108740b7`）
- mimalloc 全局分配器 feature 默认开启（`c9e11fc2`）
- mKCP TTI 校验上限 1000→5000（对齐 Go PR #5755）（`2fcd3c75`）
- TUIC 服务端拥塞控制配置面 + CC 桥 hysteria_bbr/brutal（`4cc5c99d`、`f49f4542`）
- REALITY 后量子：X25519MLKEM768 混合密钥交换 + ML-DSA-65 验签原语 + ServerHello 捕获（`27dfd1ee`、`4490c921`）

### Changed

- 性能波 A：mux 帧读池化 + vmess/SS/WebSocket 热路径零拷贝小修 + REALITY mirror 解锁（`28bce568`）
- tokio 1.52.3→1.53.1（规避 LIFO 回归）+ RuntimeMetrics 假唤醒护栏（`c142b344`）
- REALITY mirror 发送体删除（26zn 方案 B）：消除 48B 载荷静默污染地雷，gate 命中仅记日志（`3d5b3e1f`、`b76269bd`）
- trojan v2 草案实现恢复保留（官方 trojan 规范先行、Go 滞后，按草案默认值实现）（`5ddd1cb5`）
- VLESS Vision Go→Rust 套件恢复默认（RecordFramer 修复后 VPS 连续 5 次 PASS）（`8646b76f`）
- CI stress 基础设施：Windows ephemeral 端口 + TIME_WAIT 调优、nofile 上限提升、分批 matrix 防 6h 平台墙、boringssl/protoc Windows 路径修复（`d7e5b8bc`、`97402f05`、`028828a7`、`067d86f3`、`5d1cab9b`、`52e29c84`、`352ecc92`、`b93f0df6`）

### Fixed

- 压测资源泄漏：s9 anytls fd 泄漏、s10 vless+splithttp fd+RSS 双泄漏、s12 vmess+splithttp H3 堆泄漏、s6 trojan+grpc fd 泄漏 + H3 连接级关闭缺口（`633778bb`、`171b0e55`）
- interop 收口 10 缺陷：REALITY 跨栈 sig_algs/keyshare 门、splithttp h2 `:authority` host 门、anytls 入站 handler 保活、TUIC 证书 pin 接线、hysteria2/anytls/naive 出站注册接线（`6aa33adc`、`9c4c75c7`、`dec6fd80`）
- VLESS Vision 入站 RecordFramer 记录对齐读：rustls 贪婪 recv 合流裸尾致 Linux 确定性挂的根修（`8cfc17ac`）
- splithttp 非 btls 出站恒拨 127.0.0.1:80（hyper-util legacy client IP 字面量短路 resolver）（`5fd80270`）
- splithttp 非 btls 出站 `alpn_protocols.clear()` 误删致构建即 panic（`0787bbcb`）
- DNS serveStale/serveExpiredTTL/disableCache 全局→per-NS 合并（原全局开关死配置，对齐 Go dns.go）（`402a761a`）
- gRPC path_escape 分号转义对齐 Go url.go（`d4840580`）
- REALITY probe `detect_one` 加 15s 护栏超时（静默对端握手挂死 CI 43min 的根修）（`0c85ffca`）
- VLESS Vision splice 激活闸门：flush inner + DIRECT 帧后封读 inner，根治 macOS 互通竞态（`7c62fd1a`、`71f1a5e2`）
- 三轮审计全量修复 28 票：语义/并发/安全/拷贝落地（routing fail-open、encryption 明文降级、geoip 德摩根、FakeDNS pending 等）（`94d7fe99`）
- REALITY 收尾批 + P3 清扫批：42 票全量收官（`8bb36239`）

### Security

- quinn 0.11.12→0.11.18：6 个远程 DoS/panic 公告修复（GHSA qfwj/2hv7/hmxj/465w/ppcp/3g6h）+ ACK 捆绑性能；hysteria2 vendor patch 正交重放（`6e5745c6`、`cbc0ce52`）
