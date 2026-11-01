# 修复战役总账（四波收口，2026-10-31 → 11-01）

分支 `feature/fix-inbound-parity`，起点 `5fe98b90` → 终点 `707cd30e`（含波1 `98c8a360` / 波2 `a8534efd` / 波3 `3f520e58`）。

## 提交

| 提交 | 内容 | 文件 |
|---|---|---|
| `98c8a360` | 波1：G2 inbound / G3 UDP 隧道 / G4 splithttp | 38 files +4232/−787 |
| `a8534efd` | 波2：G1 装配 fail-fast / G6 TLS / G8 生命周期 + 2 个 P0 + mux 回归 | 34 files +2098/−488 |
| `3f520e58` | 波3：G5 IO/框架 / G7 DNS 观测 / G10 计划票 | 26 files +1696/−349 |
| `707cd30e` | 波4：G9 测试与 CI / G11 收尾散键 / 86i4h 阶段2 + tproxy P0 | 81 files +2015/−2057 |

## 票面

| 阶段 | open |
|---|---|
| 战役开始 | 73（含 9 张 P0） |
| 波1 后 | 64（P0 剩 5） |
| 波2 后 | 47（**P0 清零**） |
| 波3 后 | 37 |
| 波4 后 | **31**（P1×10 / P2×11 / P3×10） |

累计关闭 **42 张**（含全部 9 张 P0 + 6 张本轮新发现的 P0）。

## 各波关键成果

### 波1（3 P0 组）
- **t0ls1** UDP 隧道 wire：四处帧转换契约，修前 rust→go 是 53B 垃圾、go→rust 上游 0 字节 → cone 关 `36/36` 字节级 PASS
- **dct2d** splithttp OOM：RSS **3656MB→15.2MB** 且 413 拒收；上行 alloc/MB **2.583→1.291**、**84→243 MB/s**
- **u4efe/zmpxy** ss 空口令 open proxy + dokodemo 会话爆炸

### 波2（3 P0 组 + 2 个 P0 补位）
- **vaye2/o91s4/5w5z0** 装配 fail-fast：5 个坏配置全部启动期 `exit=1`（原为 warn+skip 静默直连）
- **idtl1** TLS 验链：pin 空→跳过、vcn 多名逐个 webpki 全验；D1/D1b 从拒→accept（btls+rustls 双实现）
- **f2ap9** IP 字面量归一化：路由 `ip` 规则从"永不命中"恢复（E1：leak→blocked）
- **itd0p** xdns 越界：53 字节单包原 panic+隧道永久失聪 → 3/3 即时应答

### 波3（3 组 + 1 个 P0 计划票产出）
- **rjt2o** bridge 中止闸：A/B 137 vs 139 MB/s（无退化），对端不读 3 轮 6/6 收尾、句柄持平
- **86i4h 阶段1** spawn_reaping API + 三 scope 接线
- **7qxjj/64nmm/1ksxu/s6h2j** DNS ownLink 贯通 + 帧格式解耦 + TC=1 兜底 + per-level bufferSize
- **3q3h0** xmc `rand_delay` u32 截断（>4.29s 取样被压 / span=2^32 除零）

### 波4（2 组 + 阶段2 + P0）
- **jf1wv（新发现 P0）** tproxy recv 热自旋：`user 8.09+sys 1.90`（整核 100%，单核饿死）→ `0.00+0.00`；3 个 `#[ignore]` 转正为回归门，反证"只转正不修码必红"
- **86i4h 阶段2** 36 处每事件 spawn → `compat::spawn_reaping`（20 文件）
- **7kp03** 死代码删 9 项；**x0f0r** 15 键逐键判定（接线 6 / 按 Go 处置 3 / 建票 4）
- **amynv/05ac1** 16 crate 契约夹具 + 4 crate 错误变体补测

## 三个回归（都是本轮自伤，全部已修）

| 回归 | 引入 | 根因 | 修法 |
|---|---|---|---|
| mux UDP 两条（GlobalID 缺失 + echo 超时） | 波1 t0ls1 | 边界转换只做一半：meta-only New 的 gid 写读不对称 + normal new 未转换 | 读侧剩余恰 8B 补读 gid；`handle_normal_new` 统一转换 |
| reverse portal 两条 | 波1 + MuxRegress 上轮 | 「所有 UDP 都转换」误伤 internal 目标（域名+端口 0 的裸 ProtoControl） | 判据改 `is_internal_target`，转换入口收敛为 `xudp_boundary_link` |
| anytls uot 挂死 | 波1 yfcnr | 空 MultiBuffer 不写帧 → reader 永等帧头 | 空载荷也写 `0x0000`（对齐 Go），>60s 挂死 → 0.00s |

## 最终门禁（PM 亲跑）

| 门 | 结果 |
|---|---|
| `cargo check --workspace --all-targets` | 绿 |
| `cargo clippy --workspace --all-targets -- -D warnings` | **绿（零告警）** |
| `cargo test --workspace --all-targets --no-fail-fast` | 仅 **3 条已知既有红**（vless/vmess `*_outbound_udp_roundtrip_e2e`、splithttp `h3_server_receives_stream_one`，均有票） |
| `cargo fmt`（本方 crate） | 0 diff（`crates/udf-frame/**` 为外部工作副本，有既有漂移，不属维护面） |
| `dist/interop_ci.py --upstream local`（vs Go 26.10.17） | **43/43 PASS** |
| `dist/interop_udp_tunnel.py` | cone 关 **36/36 PASS**；12 条失败全为 cone=on dest=443 且含 Go↔Go（既有面） |
| release 构建 | 绿（50.5MB） |

## 未完成（需用户输入或授权）

| 项 | 阻塞原因 |
|---|---|
| **32/32 真机** | 无节点表（`vps测试连接.txt` 不存在；VPS 199.* 批已下线） |
| **测速锚**（CDN 50–60 / 直连 ≥27 MB/s） | 需用户 V2rayN 实测 |
| **t3wtj / 0m0f6**（CI 基线 + interop 门） | 需改 `.github/workflows/**`（红线），已给可 patch 方案 |
| **1gkcf / 3t30l**（特权 job / Linux 产物门） | 同上（job 定义属 workflows） |
| **qscjv**（缺省指纹对齐 Go） | 落在红线 `register.rs`；且会让无指纹用户落入 7.6× 慢路径，需用户拍板 |
| **zi7bx**（freedom 默认拦私网 vs Go 不拦） | 行为差异待拍板 |
| **1kc8d**（C 侧分配） | 需授权 `apt-get install valgrind` |
| **zlezx**（公网多跳） | 需域名/入口/协议族三项输入 |

## 报告索引

`fix/` 下各组：`WAVE1-SUMMARY.md`、`G1Assembly.md`、`G6Tls.md`、`G8Lifecycle.md`、`G5IOFrame.md`、`G7DnsObs.md`、`G10Plan.md`、`G9TestCI.md`、`G11Keys.md`、`86i4hPhase2.md`、`MuxRegress.md`、`P0-wire.md`
