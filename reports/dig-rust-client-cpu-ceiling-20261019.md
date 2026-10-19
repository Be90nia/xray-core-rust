# Rust 客户端全节点共同天花板：CPU 空转 + 88% 停顿（2026-10-19 PM 独立重审）

> 触发：用户"rust 客户端怎么都上不去、所有 cdn/argo 没有一个能到 60"；要求抛开既有子代理结论重审。
> 结论来源：全部为 PM 本机实测（与用户 v2rayN 同机同窗同节点配置），不依赖任何子代理报告。

## 1. 核心数据（同机、同节点、同窗口）

节点配置取自 v2rayN 真实测速配置（`binConfigs/configTest*`，trojan×xhttp@443 / httpupgrade@8443，
`home.begonia92.top`，path 与 v2rayN 逐字一致）。下载目标 = VPS 自建文件源（`176.122.139.45:18999`，
经 CF 链路），curl 单连接 100-315MB，CPU 用 `Get-Process.TotalProcessorTime` 前后差。

| 场景 | 吞吐 | CPU 消耗 | **MB / CPU-秒** |
|---|---|---|---|
| Rust · CF · xhttp | 31.2 MB/s | 9.12s / 10.1s 墙钟（≈0.91 核） | **34.5** |
| Rust · CF · httpupgrade | 31.6 MB/s | 8.56s | **36.7** |
| Go · CF · xhttp | 18.2 MB/s | 2.80s（0.28 核） | **112.5** |
| Go · CF · httpupgrade | 29.0 MB/s | 1.64s | **191.7** |
| Rust · 回环 · 明文 | 267.6 MB/s | 0.86s | 244.0 |
| Rust · 回环 · TLS(btls) | 212.7 MB/s | 1.44s | 145.9 |
| Rust · 回环 · TLS + RTT100ms 注入 | 147.6 MB/s | 0.94s | 223.7 |
| Rust · 回环 · TLS + 1400B 小分片投递 | 117.3 MB/s | 0.88s | 239.7 |
| Rust · 回环 · TLS + 限速 6.3MB/s | 6.35 MB/s | 0.58s / 26.4s（0.02 核） | 274.9 |

**判据**：Rust 在真实链路上每 CPU 秒只能产出 ~35MB，Go 是 112-192MB；本地任何形态（含 RTT、
小分片、限速）Rust 都保持 146-245MB/CPU-s。**问题不在 TLS 本体、不在 bridge、不在 RTT、不在分片粒度。**

## 2. 停顿分布（P7LM 原始日志，XRAY_P7LM_TRACE=1）

一次 314.6MB / 11.4s 的真实链路下载：

- 批次数：39,466（几乎全部 8KB）
- 停顿 >5ms：**365 次，合计 9.27s（占墙钟 81%）**
- 同一段传输 CPU 消耗 ≈ 9.1s —— **CPU 时间 ≈ 停顿时间**，即停顿期间在烧 CPU
- 拨号次数 = 1，TLS 握手 = 2（无重连churn，排除"每停顿一次重连"）

## 3. 代码层核查（逐个排除）

| 层 | 结论 |
|---|---|
| bridge 主循环（down_reader/down_writer） | `select!` + `timeout`，等待时正确挂起；仅每批重建 timeout（µs 量级） |
| `xray-buf::reader::SingleReader` | `inner.read().await` 直通，无循环重试 |
| `xray-buf::pipe`（socks 腿） | CountingNotify + await，无自旋 |
| `xray-buf::readv` | 仅裸 TCP 生效（`is_raw_tcp()`），TLS 路径不走它 |
| **vendored btls fork（`Be90nia/btls`）** | **两处忙等循环**：`ssl/mod.rs:4097 read_uninit` 与 `:4327 Write::write` —— `WANT_READ && io_error().is_none()` 分支为空 `{}` 立即重试；tokio-btls `poll_read` 直通该循环 |

btls 的 `read_uninit` 在 BoringSSL 返回 WANT_READ 且**无 errno**（BIO retry 语义）时不会返回
Pending，而是原地再调 SSL_read —— 在真实 WAN 的送达时序下进入空转；本地回环/代理的送达形态
（record 整块到达、或数据持续可用）均未触发该条件，因此本地无法复现（9 组对照全部 146-245 MB/CPU-s）。

## 4. 与旧结论的关系

- 10-18 子代理报告的"客户端停顿 + 烧核"方向被本次独立实测**确认**（数值不同：它报 129 次停顿/1.6s，
  实测 365 次/9.27s；它报 530µs/record 均匀成本被证伪，实测为停顿主导）。
- 旧报告未能定位自旋点；本次把唯一代码级自旋点收敛到 vendored btls fork 的 `read_uninit` /
  `Write::write`。
- F2（服务端写聚合）、F3（rustls 64KB 读缓冲，btls 分支显式返回 0）、F-A（xhttp h2 流窗）均不触及
  该路径 —— 这解释了"换了所有修复版依然上不去"。

## 5. 未证与下一步（需授权）

未证：btls 循环与 365 次停顿的逐事件对应关系（Windows 无 strace；`GetProcessIoCounters` 计数
未取到，需 perfview 或产品内打点）。

三个可执行方向：
1. **改 vendored btls fork**：`read_uninit`/`Write::write` 的 `WANT_READ && no-errno` 分支改为返回
   `WouldBlock`（让 tokio-btls 映射 Pending），重编验证。风险：fork 改动需回归指纹/握手（红线依赖）。
2. **产品内打点**：在 btls fork 的循环里加迭代计数（编译期 feature），直接证明空转次数。
3. **perfview/WPR 采样**：抓一次真实链路下载的 CPU 栈样本，直接看热点（无需改代码）。

## 6. 验收口径（修好后）

- 同一节点同窗：Rust ≥ Go 的 80%，即 ≥45 MB/s / 单连接；
- MB/CPU-秒 ≥ 100；
- P7LM >5ms 停顿 ≤ 10 次/300MB。
