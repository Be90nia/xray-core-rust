# HANDOFF — ss 双死 + 直连族 26 钉 + F2/F3 部署事故（2026-10-19 晨）

> 零上下文接续指南。产物全指针化，禁复制内容。
> 项目：D:/Project/Xray-core-rust（master `3156f08d`）

---

## 1. 当前状态

### 已完成
- **F-A**（xhttp 客户端 h2 流窗 16→32MB）commit `8780187e`，A/B 四档 RTT +42~53%，CI 全绿。
- **F2/F3**（TLS 数据面：服务端写聚合 + rustls 客户端读缓冲 64KB）工作树曾被 revert 事故冲掉，已从 `reports/fix-f2f3-tls-datapath-20261018.diff` 恢复并 commit `3156f08d`，CI 全绿。
- **服务端已回滚 `8780187e`**（md5 `44e59c54`）：3156f08d 服务端二进制**杀死 ss inbound**（见 §3.1），回滚后用户 v2rayN Go 客户端实测 ss-ws-cdn 47.9 / ss-ws-argo 41.1 复活。
- v2rayN 客户端现役 `3156f08d`（md5 `d45cbc12`，含 F3+F-A）。

### 进行中（交接焦点）
- **ss 双死根因链**，三个独立案子（§3）。
- Linux build 39179020228（3156f08d artifact）已出——**禁直接部署**，先过 §3.1。

### 被阻塞
- Rust ss 特异死在本机无法复现：本机国际入口窗口容量 **~17MB/s 天花板**（早 7-8 点实测，直连与代理同撞线），用户 v2rayN 环境容量 50+。受控数字低于 17 的全部无效。

---

## 2. 关键决策与理由

| 决定 | 理由 | 错了损失什么 |
|---|---|---|
| 服务端回滚 8780187e | 3156f08d 服务端 Go+Rust ss 全灭，止血 | F2 服务端修复暂不生效（直连族 26 钉继续） |
| v2rayN 客户端保持 3156f08d | 客户端侧无回归证据（死因全在服务端/环境） | 无——可随时换回备份 `D:/tmp/xray-8780187e.exe`（2bfd7a58） |
| 受控实验禁再下"代码无罪/有罪"结论 | 管线 17 天花板 + 全部用 http 目标（v2rayN 是 https）| 已有教训：今晨"黄金窗全绿"结论作废过一次 |
| 3156f08d 服务端冻结待查 | §3.1 未结案前部署任何新版都会再杀 ss | 再部署一次 = 用户 ss 再全灭一次 |

---

## 3. 未完事项（owner = 下会话 PM）

### 3.1 查 3156f08d 服务端 ss 杀手【最高优】
- **现象**：8:03 部署 3156f08d 服务端后，ss-ws-cdn/argo 对 Go 与 Rust 客户端**全部** `000`（今晨 7 点 8780187e 服务端时 Rust 十轮全绿）；回滚即复活（用户实测 47.9/41.1）。
- **疑点**：F2 只动 `xray-proxy-vless/src/inbound/server.rs`（vless flow="" 门控）理论无关 ss；F3 动 `utls.rs`（UConn 分派）+ `connection.rs`（Box 转发）+ `bridge.rs`（+125 行，读批接线）——**agsbx 的 ss inbound 带 ws+tls，服务端 TLS accept/读路径若被 F3 波及即全灭**。先 diff 审 bridge.rs 服务端分支。
- **方法**：本地起 3156f08d 服务端（从 VPS 拉同款 ss inbound 配置）复现 → 二分 diff。
- **复访条件**：部署任何服务端新版前必须结案。

### 3.2 Rust ss 特异死抓现场（用户环境）
- 昨晚用户图（服务端 8780187e 时代）：Rust ss-cdn 超时 `-1` + ss-argo `net_http_ssl_connection_failed`，**Go 同窗 53/56 活**——真 Rust 客户端特异，未解。
- 已排除：salt 重复（`rand::random` 每连接独立）、replay（拨号无重试）、F2/F3 回归（老版同死）。
- 抓捕配方：`D:/tmp/ab-ss/storm_ss.py`（debug 日志版客户端）——**下次用户环境再死时保持现场**，换 debug 客户端抓建链层第一现场。
- 注意 https 目标从未在受控测过（v2rayN 是 https）——补 `curl -x socks5h://... https://...` 对照。

### 3.3 直连族 26 钉（-54% 纯代码税）
- 用户图：Rust 五条直连 reality/tls 节点（trojan-reality/trojan-tls/v1-reality-vision/v1-xhttp-reality-enc/vless-tls-vision）**齐钉 25.6-26.2**，Go 同族 41-57。机制 = `reports/dig-tls-receive-20261018.md` 的 TLS 接收 18-19ms 周期停顿（Rust 独有）。
- F2 服务端写聚合是对症修复，因回滚未生效。**复访条件 = §3.1 结案后重部署**。
- F1（停顿定位到 await 行）待派：tokio-console 或 down_write 打点，方案在 dig-tls-receive §4 F1。

### 3.4 清理（下次碰 VPS 时顺手）
- `/tmp/sstest/`（f.bin + srv.py 多线程 http 18999）+ `iptables -D INPUT -p tcp --dport 18999 -j ACCEPT`。
- 本机 `D:/tmp/ab-ss/` 残留进程/tasklist 检查。

### 3.5 低优
- tr-xhttp-cdn 20.8（Go 55.2，同族 vm-xhttp-cdn Rust 44.5 正常）——trojan+xhttp+cdn 组合特异性。

---

## 4. 产物指针

| 产物 | 位置 |
|---|---|
| F-A 报告 | `reports/fix-fa-xhttp-window-20261018.md` |
| F2/F3 报告+diff | `reports/fix-f2f3-tls-datapath-20261018.md` / `.diff` |
| TLS 停顿深挖 | `reports/dig-tls-receive-20261018.md` |
| ss 客户端深挖 | `reports/dig-ss-client2-20261018.md`、`dig-ss-argo-20261018.md` |
| DirectPump（26 钉前案） | `reports/dig-direct-pump-20261018.md` |
| 客户端备份 | `D:/tmp/xray-8780187e.exe`(2bfd7a58) / `D:/tmp/xray-3156f08d.exe`(d45cbc12) / Go=`D:/tmp/ab-cdn/go-xray.exe`(d4ca1c66) |
| 实验脚本 | `D:/tmp/ab-ss/{conc_same,storm_ss,conc_hs}.py` + `cdn_12829/13829/14829.json`（端口错开的同款 ss 配置） |
| ss 节点凭据（脱敏指针） | `D:/tmp/ssdig_20261018/cdn.json`、`argo.json`；v2rayN DB=`guiConfigs/guiNDB.db` |
| 服务端部署配方 | gh artifact zip → ssh `-p 26617 root@176.122.139.45`（免密）→ `/root/agsbx/xray` + `systemctl restart xr`，验 `md5sum` + `ss -tlnp | grep -c xray`（应 26） |
| CI artifact（3156f08d Linux） | run `39179020228` |

## 5. 环境警告（血泪）

1. **本机窗口容量 ~17MB/s**（早间实测）——受控测速数字 <17 的都别下结论；用户 v2rayN 环境 >50。
2. **v2rayN 默认 socks 口 10829/10830** 会撞实验配置端口——实验用 12829+。
3. v2rayN 的 xray 被杀会自动重启——别乱 `taskkill /im xray.exe`（会误伤用户进程）。
4. OMP bash 拦 `tail/grep/head`——日志用 python 内读。
5. **git revert/checkout 会冲掉工作树未提交改动**（F2/F3 丢失事故）——改动完成即 commit。
6. 服务端部署后 ss 验活必须 **Go+Rust 双客户端**（单 Rust 绿不能排除 ss 杀手——本轮 Go 也死才暴露）。

## 6. suggested-skills
`systematic-debugging`（§3.1 根因）· `subagent-method` · 派单用 7-part 契约 + Ponytail（报告不实施）
