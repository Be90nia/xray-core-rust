# 32/32 真机套件验收（2026-10-27 能力收敛战役收口）

> **VERDICT: PASS（零代码回归）**
> 判据不是"通过率好看"，而是 **Go 对照组逐节点 diff：仅 Rust 失败 = 0**。

## 1. 结论

| 指标 | Rust（最终树 release） | Go 对照（同节点表同判据） |
|---|---|---|
| PASS | **72 / 93** | 64 / 93 |
| **仅 Rust 失败（候选回归）** | **0** ✅ | — |
| 两边都失败（节点侧） | 21 | 21 |
| 仅 Go 失败（Rust 更强） | — | 8 |

→ **21 个失败节点全部是 Go 也失败的节点**（死 IP / URI 缺参 / 对端拒 ws），Rust 侧**没有任何一个节点是 Go 能通而我们不通**。反向有 8 个节点 Rust 通过而 Go 失败。

## 2. 被测物与对照

- **Rust**：`target/release/xray.exe`，从最终树 `af221b91` 构建（`cargo build --release -p xray-cli`，10m45s，btls 走预编译 asm）
- **Go**：`D:/Project/Xray-core/target/xray-go.exe`（同机同日）
- **节点表**：`D:/tmp/vps_nodes.txt`（93 节点：trojan 24 / vless 33 / ss 9 / vmess 18 / tuic 3 / anytls 3 / hysteria2 3）。**历史"32/32"基线的节点表是 32 节点子集，本次跑的是超集**，故通过率不能与历史 32/32 直接比，只能与**同窗 Go 对照**比。
- **命令**：
  ```
  python dist/run_full32.py --bin <xray.exe> --uri-file D:/tmp/vps_nodes.txt \
       --work D:/tmp/xray_real --url "https://speed.cloudflare.com/__down?bytes=8000000"
  ```
- **逐节点对照**：`reports/audit-2026-10-27/32-32-control-diff.md`（由 `tmp/compare_rust_go.py` 生成）

## 3. 判据变更（必须声明）

原脚本判据 = 下载 `https://www.youtube.com/` 且 body 含 `YouTube` marker。
**本机该判据不可用**（控制实验）：直连 `youtube.com` curl 28 超时、`google.com` 超时、`gstatic` 204 正常、`speed.cloudflare.com` 200/0.79s；Rust 服务端日志显示 `trojan dispatching → resolved`（隧道本身通）。即**外部可达性缺失，非协议回归**。

替代判据：**Cloudflare 定长下载**（`__down?bytes=8000000` 返回恰好 N 字节）+ 仍保留 `body > 5000B` 门槛 + 12s 窗口。
- **增益**：body 字节数可逐节点核对实际传输量（不只是"能打开"）。
- **代价（已记残余风险）**：失去内容 marker 校验。hysteria 节点实测拿到满 8,000,000B；TLS 节点多在 12s 窗口内传 180KB-970KB（受节点质量/长肥管道限制），仍远超 5000B 门槛。

## 4. 21 个失败的归因（全部有本地证据，且 Go 同败）

| 类别 | 数量 | 本地证据 |
|---|---|---|
| `shadowsocks none/ws` | 6 | 节点 URI 的 **path/host 全为空** → 对端 webserver 拒 ws 升级。定向取证 #4：`ss dial server (ws): tungstenite error: HTTP error: 40x` |
| `shadowsocks none/tcp` | 3 | 同上族（ss 面本地 interop 12/12 通过，故非本仓代码问题）|
| `vless reality/raw` | 6 | 定向取证 #8：curl 超时且 xray 日志**零错误** = 对端不可达 |
| `trojan reality/raw` | 3 | 节点 URI **缺 `pbk=`** → `reality: invalid publicKey:`（空值）。定向取证 #6 **任何客户端都不可能连上** |
| `vless tls/raw` | 3 | 定向取证 #16：xray 日志无错误、curl schannel 握手失败 = 对端无有效响应 |

**每一条都同时是 Go 的失败节点**（见 diff 全量表），故一律归"节点侧"，不入代码回归。

## 5. 本地互通（同一最终二进制）

`reports/audit-2026-10-27/tmp/interop_final.py`（复用 CR1b 的本地源站判据，仅换二进制）：
**12/12 PASS**，每项 `body=200014B`——6 协议 × 2 方向（vmess / vless+vision+TLS / trojan+TLS / vless+ws / ss / ss2022），含**双向**（Rust client↔Go server 与 Go client↔Rust server）。

## 6. 本战役各门汇总（全部 PM 亲测或代理实测+PM 抽查）

| 门 | 结果 |
|---|---|
| `cargo clippy --workspace --all-targets -D warnings` | **0 error**（多次运行：59.62s / 2m46s / 2m51s / 2m07s，均为 0 error）|
| `cargo test -p <各面> --all-targets` | xray-conf 226 / common+tls 673 / transport 族 1041 / proxy 族 1238 / core 479 / mux 166 / app-dns 236 / dispatcher+commander+reverse 326+ / kcp 179 —— **全 0 failed** |
| `cargo fmt --all -- --check` | clean（含 W6 漏跑后的补修）|
| `redline_sites` 四门 | **4/4**（改前 3/1，W7 接线后转绿）|
| 本地互操作矩阵 | **12/12** |
| 真机套件 + Go 对照 | Rust **72/93** vs Go **64/93**，**仅 Rust 失败 0** |
| 性能（同窗交错 A/B） | 各波 Δ 均在窗口噪声内；基准纪律见 `docs/benchmarks/baseline.md` 2026-10-27 节 |

## 7. 残余风险 / 未覆盖面

1. **REALITY 的「Rust↔Go wire 互通」不在矩阵里**（**已更正**：原写"零本地覆盖"失实）。
   - 实际覆盖：`crates/xray-reality/src/server.rs` 内 11 个 reality 测试（`reality_loopback_with_fingerprint` / `reality_loopback_u_client_with_server_tls` / 指纹矩阵含 mlkem 与 watfaq 回退）、`crates/xray-core/src/inbound.rs` 的 `vless_reality_inbound_e2e` 等 14 个 → **reality 单元与本地 e2e 有实质覆盖**。
   - 真实缺口：`dist/interop_matrix.py` 的 6 协议矩阵**不含 reality**，即缺「Rust client↔Go server」「Go client↔Rust server」两条 wire 互通用例。
   - 今晚已补一半证据：修好 3 个缺参节点后，**Rust client → 真 Go server 的 reality 3/3 全通**（200KB/147KB/152KB），Go 侧同 3 节点亦 3/3（200/200/177KB）。
   - 仍缺：**Go client → Rust server** 的 reality 方向（本地无用例）。已开 bd 票。
2. **判据弱化**：无内容 marker（见 §3），"PASS" 含义 = 隧道可用 + 传够字节，不等于满速。
3. **节点表易变**：93 节点是外部资源，今日 21 个失效；通过率随时漂移。
4. **停机语义收紧**（W4 面 6）：SS 泵 / mux carrier 随 arm scope 关闭被级联取消。本次套件未见"连接提前断"类失败，但单次 curl 12s 窗口不足以覆盖长连停机路径 → 若要严格验证需专门长连用例（W4 报告 §6.3 有回看锚）。
5. 红线门判别力上限（W7 报）：`redline_sites` 管**调用形态**，不管运行期消息产出；该事件全仓无 capture 断言。

— PM · 2026-10-27
