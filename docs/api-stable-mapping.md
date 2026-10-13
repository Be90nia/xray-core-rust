# API 稳定映射（stable-surface mapping）

> M6 standards 批产物（bd Xray-core-rust-75rv ⑥）。落实 `docs/refs/oracle-framing-arch.md`
> §4「API 转正门槛（hard gate）」与 §5.3「Go↔Rust 映射表 + PR porting note」两项缺口。
>
> **本表是治理契约，不是宣传页**：stable 标注 = 对全仓承诺；无证据支撑的点一律 candidate/
> internal，禁止给未定型 API 写承诺（oracle §4：3 用户之前一律 `pub(crate)` 或 `#[doc(hidden)]`）。

## 0. 判级规则（hard gate，逐条对齐 oracle-framing-arch §4）

| 判级 | 门槛 | 语义 |
|---|---|---|
| **stable** | ≥3 个真实协议用户 + 每用户有同窗 A/B 数字（或全仓基线报告背书） | 对外承诺：破坏性变更须走 RFC + porting note |
| **candidate** | 用户数达标但 A/B 材料不全，或形状单一（<3 种协议形状） | 允许演进；新代码可用，文档不得承诺 |
| **internal** | 单用户 / 装配面 / 规划中（【规划·P*】） | 不承诺；candidates 转正前默认 pub(crate) 或 doc(hidden) |

A/B 证据的合法载体：`docs/benchmarks/baseline.md`、`docs/refs/*alloc-audit*`、
`docs/audit-性能-2026-10-12.md`、bd 票（性能战役留档）。

## 1. 稳定面标注表（骨架对血肉的接口面）

| API 点 | Go 对应 | 用户（≥3 才可 stable） | A/B / 基线证据 | 判级 |
|---|---|---|---|---|
| `xray_buf::{alloc, Buffer, MultiBuffer}`（池句柄 + 链式缓冲） | `buf.{MultiBuffer, Bifier}` | tcp / ws / httpupgrade / grpc / splithttp / kcp / hysteria / tuic / vmess / trojan / ss（全协议经 dispatcher relay 消费） | `docs/benchmarks/baseline.md`（loopback 154-167 MB/s；alloc/MB 2.15/2.22）+ `docs/refs` alloc-audit | **stable** |
| `xray_buf::io::{Reader, Writer, AsyncReader/AsyncWriter}` | `buf.Reader/Writer` | dispatcher 装饰链 / 各 transport | 形状多样但 box 税已知（ARCHITECTURE §2 坑 7；io.rs:76-93），poll 化在【规划·P1】 | **candidate**（禁写承诺，等 P1 poll 直通） |
| `xray_transport::connection::Connection` | `internet.Conn` | 全 Layer 3 transport（tcp/kcp/ws/httpupgrade/grpc/splithttp/quic/naive） | 32/32 协议互操作（interop 套件）+ loopback 基线 | **stable** |
| `xray_transport::link::Link`（reader/writer 对） | `Link`（dispatcher 上下行载体） | dispatcher / 全 proxy outbound/inbound | s1-s12 压测矩阵（stress.yml 基建） | **stable** |
| `xray_transport::bridge`（池化泵 + 半关闭范式） | `common/transfer.go` transfer | 全 relay 类协议（dispatcher pump / 各 transport） | splice 双 revert 教训 + 压测 drain 观察窗（leak 判定通过） | **stable**（泵语义冻结：300s idle / 1s 半关闭窗） |
| `xray_transport::sockopt` | `internet/socket_opts` | tcp / quic / hysteria / dns / commander | tcpboost 88m0 修复 + 真机压测 | **candidate**（平台差异面仍在收口：statx/FreeBSD 等） |
| `xray_app_dispatcher::{DispatchHandler, OutboundHandlerManager, DialFn}` | `app/dispatcher` 接口组 | proxyman / core wiring / commander / router / 全 proxy | 生产 wiring（xray-core 方案 B snapshot）+ 32/32 | **stable** |
| `xray-tls` utls（`u_client` + `Fingerprint`） | `utls.ClientHelloID` | tcp / ws / httpupgrade / grpc / splithttp（transport 层 fingerprint 接线） | 32 节点指纹战役（btls 真指纹实现） | **candidate**（transport 6/7 接线补齐前不转正） |
| vision（`xray-proxy-vless::encryption`） | `vless/encryption` | 仅 vless 单用户 | vision 池化 commit 7681f7cc（3.3→20+ MB/s） | **internal**（单用户，禁 stable） |
| quinn/hysteria 适配层（`xray-transport-hysteria::quinn_adapter`） | Go quic-go 封装 | hysteria / tuic / splithttp-H3 | s3/s8/s12 压测 + h2 窗钉修复（enc8x 战役） | **candidate** |
| 框架五件套（事件管理器 / accept 托管 / 调度托管 / 热调参 / log facade） | —（Go 无对应骨架） | 未落地 | 【规划·P2-P8】 | **internal**（规划态，见 ARCHITECTURE §1.2/§1.3） |

## 2. Go↔Rust 核心映射表（§5.3）

上游同步（sync Go Xray-core）时的第一查阅表；PR 触及左列 Go 文件时，Rust 侧落点按本表找。

| Go（v26.9.9 基线） | Rust | 备注 |
|---|---|---|
| `buf.MultiBuffer` / `buf.Bifier` | `xray_buf::multi::MultiBuffer` / `xray_buf::alloc` | 池化语义：Drop 回池；禁 to_vec 扁平化（dispatcher/buf clippy.toml 红线） |
| `buf.Buffer`（8192 缺省） | `xray_buf::buffer::Buffer` | `alloc 后 resize` 坑已由构造内建（坑 3） |
| `buf.Reader` / `buf.Writer` | `xray_buf::io::{Reader, Writer}` | 每调用装箱 box 税（坑 7）——装饰层不再加 Box::pin |
| `common/net.{Conn, Link}` | `xray_transport::{connection::Connection, link::Link}` | |
| `common/task.{Close, Run, ParallelForN}` | `xray_common::task::{Close, Run, ParallelForN}` | 大写名对位（non_snake_case 豁免登记） |
| `transport/internet` dialer / listener | `xray_transport::{dialer, listener_registry, system_listener}` | |
| `transport/internet/headers/*`（utp/wechat/srtp…） | `xray_transport::headers::*` | 伪装头：config 仅构造形态保留，encode 写死字节 |
| `transport/internet/sockopt` | `xray_transport::sockopt` | 含 SO_ORIGINAL_DST / TCP_CONGESTION / bind-to-device |
| `transport/internet/utls` | `xray-tls::{utls, fingerprint, btls_client}` | REALITY 走 btls（BoringSSL）非 utls |
| `app/dispatcher` | `xray-app-dispatcher`（含 sniffer / XUDP udp_session） | |
| `app/proxyman/{inbound,outbound}` | `xray-app-proxyman` | |
| `app/router`（condition/strategy/balancing） | `xray-app-router` | |
| `app/dns`（nameserver/fakedns/hosts） | `xray-app-dns` | DoH/DoT/DoQ/QUIC nameserver 全套 |
| `app/observatory`（burst/healthping） | `xray-app-observatory` | |
| `app/stats` / `app/log` / `app/policy` / `app/reverse` / `app/metrics` / `app/version` / `app/geodata` / `app/commander` | `xray-app-*` 同名 crate | |
| `infra/conf` | `xray-conf`（built.rs 装配 + jsonconf） | `env:` 注入语义对位 |
| `infra/conf/serial` / JSON loader | `xray-conf::{Format, load_str}` | |
| `main/`（instance/functions） | `xray-core::{Instance, functions::start_full}` | |
| `features/extension` | `xray-features` | |
| `proxy/{vless,vmess,trojan,shadowsocks,socks,http,dns,blackhole,freedom,dokodemo,loopback,wireguard,anytls,tuic,hysteria}` | `xray-proxy-*` 同名 crate | |
| `transport/internet/{kcp,quic,grpc,websocket,httpupgrade,splithttp,hysteria}` | `xray-transport-{kcp,quic,grpc,websocket,httpupgrade,splithttp,hysteria}` | |
| `common/mux` / `xudp` | `xray-mux` / `xray-xudp` | |
| `geodata` / `geosite` | `xray-geodata`（matcher/protocol loader） | |

映射缺口登记（Go 有、Rust 无稳定面）：framework 五件套（【规划】）、MASQUE/XDRIVE（M7 评估票）、
`transport/internet/tagged`（nuisance 散点按票承接）。发现新缺口 → 追加本表，不改 refs/ 裁决。

## 3. PR porting note 字段（§5.3，PR 模板约定）

上游同步 PR 必带字段（机械但防漏）：

```
porting note（缓冲语义）: 上游本次改动是否触及 buf 所有权/窗口/超时/accept 语义？
  [ ] 否（纯逻辑/协议分支）
  [ ] 是 → 列出 Rust 侧对应改动点（按 §2 映射表定位到 crate::path）：
      1. <crate::path 或 新增点>
porting note（A/B）: 若触及数据面（读写路径/缓冲/加密），附同窗 A/B 数字或标注
      「需要 golden_window 复测」（方法：tools/golden_window_test.py）
```

## 4. 维护规则

1. 转正/降级必须改本表并留证据链接；`stable` 行同步在代码 `///` 注明「stable-surface: 见
   docs/api-stable-mapping.md」。
2. 每轮 standards 审计（M6 后继票）复查判级；上游大版本同步后检查 §2 映射缺口。
3. 本表与 `docs/ARCHITECTURE.md` §1 冲突时以 ARCHITECTURE 为准并回改本表。
