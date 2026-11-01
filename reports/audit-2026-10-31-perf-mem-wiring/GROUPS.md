# 修复分组方案（2026-10-31 审计 73 张票 → 11 组）

原则：**组间文件面互斥**（同一文件只归一组）；同根因同组；每组"单会话可完成 + 可独立验收"。
**性能锚（用户口径 2026-10-31）**：V2rayN 测速 CDN/argo ≈50–60 MB/s、直连 ≥27 MB/s。**任何速度倒退 = 代码有罪推定**，组验收必过这一门。

## 波次（≤3 并行，滚动补位）

| 波 | 组 | 并行 |
|---|---|---|
| 1 | G2 inbound 面、G3 UDP 隧道、G4 splithttp | 3 并行 |
| 2 | G1 装配 fail-fast、G6 TLS、G8 生命周期 | 3 并行 |
| 3 | G5 IO/框架、G7 DNS/观测、G10 计划票 | 3 并行 |
| 4 | G9 测试与 CI、G11 收尾散键、86i4h 阶段2 | 3 并行 |

串行约束（文件面决定）：`functions.rs` G1(波2)→G7(波3)；`wiring.rs` G2(波1)→G11(波4)；`xray-conf/protocols.rs` 仅 G11；`scope.rs` G5(波3)→86i4h-阶段2(波4)。

---

## G1 装配 fail-fast + 出站面（8 票，波2）
| 票 | 级 | 内容 |
|---|---|---|
| vaye2 | P0 | 路由解析失败静默降级 → 拒启 |
| o91s4 | P0 | 出站 warn+skip → fail-fast |
| 5w5z0 | P0 | freedom finalRules 丢项 → 硬错 |
| ucjcl | P1 | API AddOutbound 补 senderSettings 映射 |
| lu37q | P1 | gRPC Routing/Observatory 后端注入 |
| 0bzcd | P1 | 13 条配置面 fail-open（随本组门统一修） |
| jwg8y | P2 | Go 已移除 feature（proxySettings/noise/flow）改拒启 |
| 3nt18 | P1 | geodata.outbound 接 dispatcher |

文件面：`xray-core/src/{functions.rs,outbound.rs,register.rs}`、`xray-proxy-freedom/config.rs`、`xray-app-commander/commander.rs`、`xray-app-router/router.rs`

## G2 inbound 面（9 票，波1）
| 票 | 级 | 内容 |
|---|---|---|
| u4efe | P0 | ss 空口令拒启 + 多用户逐个匹配（含 ss2022 容差 p45qd 同 crate 顺手） |
| zmpxy | P0 | dokodemo UDP 会话容量门 |
| ym0z8 | P1 | AddInbound 同锁内 insert+spawn，取消返回 Err |
| bz800 | P1 | anytls 无口令拒启 + 测试期望反转 |
| hl8q6 | P1 | 七协议 UserManager 热更 |
| vdl95 | P1 | 未知协议 inbound 拒启 + sniffing 排除表 fail-fast（masque 部分引 55yh7 不做） |
| 9c8k6 | P2 | should_append 整体替换 / AddRule 载荷 / register_user_manager 复活 |
| il9lh(部分) | P3 | TPROXY fake_cache 256 上界 + LRU |
| p45qd | P2 | ss2022 容差 |

文件面：`xray-core/src/inbound.rs`、`xray-core/src/arm_builders/inbound.rs`（2026-10-31 PM 批准扩面：仅新增 register_* + 参数透传，供 hl8q6 用）、`xray-proxy-ss/**`、`xray-proxy-trojan/src/server.rs`（2026-10-31 PM 批准扩面：仅为 hl8q6 改 serve_trojan 签名共享 Validator）、`xray-proxy-anytls/inbound.rs`、`xray-cli/api_exec.rs`、`xray-app-commander/grpc.rs:676`、`xray-app-router/router.rs:234`（与 G1 不同文件区域：commander.rs vs grpc.rs ✔）
⚠ vdl95 另占 `wiring.rs:340-445`（wiring.rs 全组归 G2，G11 的 probeInterval 排波4）

## G3 UDP 隧道 wire（7 票，波1）
| 票 | 级 | 内容 |
|---|---|---|
| t0ls1 | P0 | UDP 隧道 4 处契约同改（出站剥帧/mux client/mux server/入站保持） |
| zu7tk | P1 | socks5 UDP 7600B 上限定位与修复 |
| tini5 | P1 | socks UDP 会话缓冲按需 + 上限 |
| yfcnr | P1 | anytls UDP-over-TCP 帧实现 |
| j7de2 | P2 | tuic UDP 分片重组 + quic 模式配对 |
| 1fm1l(UDP半) | P2 | UDP 每包 4 分配 → 复用 scratch |
| 1ksxu(D3/D6) | P2 | freedom 域名择优取址 + FRAG 日志 |

文件面：`xray-app-dispatcher/{udp_session.rs,packet.rs}`、`xray-proxy-{vless,vmess,trojan}/dispatcher.rs`、`xray-mux/{client,worker}.rs`、`xray-proxy-freedom/udp.rs`、`xray-proxy-socks/udp.rs`、`xray-proxy-anytls/outbound.rs`、`xray-proxy-tuic/udp.rs`
**验收加门**：新增 `dist/interop_udp_tunnel.py` 四象限（协议×方向×cone×端口）+ 用户测速锚

## G4 splithttp 专项（4 票，波1）
| 票 | 级 | 内容 |
|---|---|---|
| dct2d | P0 | body 按 ContentLength 预检 + LimitReader |
| 3zbwx | P1 | SessionMap 容量门 + id 校验 |
| 1fm1l(xhttp半) | P2 | 上行 ReaderStream → 泛化 dl_stream 块池 |
| 2xgln | P2 | max_concurrent_streams 上限（grpc+splithttp） |

文件面：`xray-transport-splithttp/**`、`xray-transport-grpc/transport.rs`

## G5 IO/框架（3 票，波3）
| 票 | 级 | 内容 |
|---|---|---|
| rjt2o | P1 | bridge.rs watch 中止闸 + select 臂（已验证形态，零额外拷贝） |
| 86i4h(阶段1) | P2 | xray-frame spawn_reaping API + ArmScope/ConnScope 内部接线（阶段2=25 处组件替换放波4） |
| sex3y | P2 | dnsLog 生产者 + 写失败 fail-visible + obs collector 注入 |

文件面：`xray-core/src/bridge.rs`、`xray-frame/{scope.rs,compat.rs}`、`xray-app-log/**`、`xray-app-metrics/**`

## G6 TLS（5 票，波2）
| 票 | 级 | 内容 |
|---|---|---|
| idtl1 | P1 | vcn 无 pin 走 CA 验链分支 |
| qscjv | P1 | 缺省指纹对齐 Go（Chrome utls） |
| mwvwd | P2 | 缺 cert 拒启 / 套件协商 / min-maxVersion 拍板 |
| 1avs1 | P2 | 系统根加载路径 |
| slv4n | P2 | TLS 适配层 unbuffered 化（先量 CPU） |

文件面：`xray-tls/**`、`xray-transport-tcp/register.rs`、TLS 调用侧适配层

## G7 DNS/观测（4 票，波3，在 G1 后）
| 票 | 级 | 内容 |
|---|---|---|
| 7qxjj | P1 | ownLink 三处修复 |
| 64nmm | P1 | 帧格式按客户端网络 |
| 1ksxu(D5/D7) | P2 | dns 入站协议拍板 + TC=1 兜底回落 |
| s6h2j | P2 | bufferSize/per-user level 接进生产 pipeline |

文件面：`xray-app-dns/**`、`xray-core/src/functions.rs:816 区`（串行 G1 后）、`xray-core/src/arm_builders/mod.rs`（dns 键）、`xray-app-dispatcher/default.rs`+pipe

## G8 生命周期（4 票，波2）
| 票 | 级 | 内容 |
|---|---|---|
| nip4p | P1 | reverse set_deps 注入 + vless portal 赋值 |
| txtpo | P2 | vmess SessionHistory ctx.spawn 30s retain |
| cinni | P1 | wg send 锁内不 await |
| 37jw1 | P2 | BBR profile 接线或删 + 空体补齐 |
| a3tos | P1 | hysteria2 入站解析并强制 finalmask（非法拒启） |

文件面：`xray-app-reverse/**`、`xray-proxy-vless/src/inbound/server.rs:775 区`、`xray-proxy-vmess/src/encoding/server.rs`、`xray-proxy-wireguard/driver.rs`、`xray-transport-hysteria`BBR、`xray-proxy-hysteria/inbound.rs:5312 区`

## G9 测试与 CI（8 票，波4 最后）
| 票 | 级 | 内容 |
|---|---|---|
| amynv | P1 | L4 夹具持真实插件实例断言真实副作用 |
| 7k7mj | P1 | 4 条错误期望随对应票修反转 |
| 05ac1 | P1 | 56 错误变体补测（凭据面部分已随 G2，做剩余） |
| t3wtj | P1 | 差分门基线 26.9.9→26.10.17（⚠ workflows 红线，先要授权） |
| 0m0f6 | P2 | interop 门 PR 触发 + run_full32 接入（同上红线） |
| 1gkcf | P1 | fakeudp 测试 reactor 修复 + CI 特权 job |
| jf1wv | P1 | TPROXY 链最小断言（同特权 job） |
| 3t30l | P1 | Linux 产物 32/32 门 + release build 验证 |

文件面：`tests/**`、各协议 `tests/`（仅本组域）、`.github/workflows/`（需授权）、`tools/night_probe32*`

## G11 收尾散键（5 票，波4）
| 票 | 级 | 内容 |
|---|---|---|
| x0f0r | P2 | settings 散键批次（downloadSettings/masquerade/udpHop/keepAlive/permitWithoutStream/uot/level/ws header/alpn/udpIdleTimeout/xmux/echForceQuery/metrics.tag/qType） |
| 7kp03 | P3 | 死代码清理（按删除三问，证据类不删） |
| k0hdi | P2 | 凭据掩码补全七族 |
| vkirx | P3 | 传输口径差异族（逐项拍板对齐或文档标注） |
| a0m9d | P3 | BufferPool 台账一行或建跟踪票 |

文件面：`xray-conf/{protocols.rs,secrets.rs}`、各传输 crate 零散键、死代码文件

## G10 计划票（7 票，按需穿插）
`6dgk2` 供应链 · `ifnl9` 移动端 · `3q3h0` 数值 · `zlezx` 公网多跳(等 CDN 参数) · `dm2wo` A/B harness(含 QUIC 测速) · `1kc8d` C 侧分配 · `0270p` QUIC(对端=sing-box)

---

## 每组统一验收门
1. 组内票逐条 bd close，带【验证命令+关键输出】
2. `cargo test --workspace --all-targets` + `clippy -D warnings` + `fmt --check` 全绿（构建环境变量见 CLAUDE.md §1；CARGO_TARGET_DIR 独立带组名）
3. 32/32 真机 + interop 12/12；改 wire/UDP 的组（G3/G4）加跑 `interop_udp_tunnel.py` 四象限
4. **用户测速锚**：组完成后用户 V2rayN 跑一轮——CDN/argo 50–60、直连 ≥27；**任何倒退即打回**（有罪推定=代码问题）
5. 开工前 PM 复核 `git status` 与组文件面无越界

## 现有产物锚（防回档，勿动）
- TCP 154–167 MB/s（`docs/benchmarks/baseline.md`）、TCP 50/50（round4 LinuxE2E）、DOD 十判据（`reports/audit-2026-10-31/dod-sweep-summary.md`）
- 红线不动：`xray-buf/src/alloc.rs`、vision gate/splice、`xray-transport-tcp/register.rs` 4 维、`vendor/`、`tests/`、`.github/workflows/`（G9 两票需单独授权后动）、`dist/`、`protos/`
