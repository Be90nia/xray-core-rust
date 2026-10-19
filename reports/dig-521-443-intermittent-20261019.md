# 443 监听偶发丢失致 vl-ws-cdn 521 现场

> 日期: 2026-10-19 PM
> 状态: 缓解, 未根因
> 关联: 724cc20f - 同号 521 的旧修复, 但**不同机制**（旧=accept loop 卡死; 今=监听根本未起）

## 现象

v2rayN 测速网格中 `vl-ws-cdn` 行（home.begonia92.top:443 ws tls）显示 `-1` + Cloudflare `521`（"Web Server Is Down"）。
同窗口其它 ws-cdn 节点（tr-ws-cdn 2096 / vm-ws-cdn 2083 / ss-ws-cdn 443→origin 39003）全部正常。
说明 443 这一个端口单独出事, 不是整服务或整网络。

## 定位证据

VPS 直接核对:

```
$ ss -tln | grep :443
(空)                          ← 443 完全无人监听
$ iptables-save | grep 443   ← ufw ACCEPT, 防火墙未挡
$ openssl x509 -enddate ... cdnym.crt ← 2126 年过期, 证书无问题
```

服务进程仍活着（Main PID 430, uptime 2h+），但 443 入站**根本没绑上**。这与 CF 521（"origin refused"）完全吻合。

## 时间线 - 关键证据是"老问题"且与换核无关

| 时刻 (北京) | 事件 | 443 状态 |
|---|---|---|
| 08:03 | 部署 3156f08d 服务端 | 正常 (ss 是它杀的) |
| 09:09 | 回滚到 44e59c54 | 正常 (你 10:4x 测 vl-ws-cdn 51.1 = 443 活着) |
| 11:30 | **每日定时重启** (crontab `30 3 * * *` flock /www/server/cron/ff26... 触发机器 reboot) | **443 丢失** |
| 13:48 | 我做受控重启实验 (systemctl reboot) | 正常 (2.5 秒内 xray pid 461 干净绑上) |

同内核、同配置、同 ufw、同 cert; **三次重启 一次丢 两次赢**。典型的间歇性开机竞态。

## 既往史

VPS 备份目录里躺着一份 `xray.bak.20261015-pre521fix`（10-15 03:18）——历史上打过一次 521 战役，git 里有 `724cc20f fix: ws h2 拒绝路径 spawn 化——扫描器 h2 探测钉死串行 accept loop 致 CF 521`。但**那是另一种 521**：扫描器用 h2 探测把 ws 入站串行 accept loop 钉死, edge 看不到 origin 响应 → CF 521。修复后整个 inbound 还活着、只是 accept 卡了。
**本次 521 形态不同**：xray 根本没绑上 443, 没有 accept loop 可言, 服务是健康的但少了一个 listener。两个独立 bug, 修了一个不等于修另一个。

## 已落地的缓解

1. **/etc/cron.d/xr443guard** - 每 2 分钟: 443 没人占 + xray 活着 → 重启 xray（10 分钟最多一次, 死循环防护）  
   今日 11:30 那次丢 443 后, 这个守卫会在 11:32 前自动拉起, 而无需人介入。
2. **/etc/systemd/system/xr.service.d/override.conf** - `Environment=RUST_LOG=info`  
   此前 xray 启动 INFO 行没进 journal（unit 没设 RUST_LOG, 默认 EnvFilter 从空环境等于全静音）。下次重启 journal 里会有完整的 listener bind 序列, 包含任何 bind 失败的原始报错。
3. **boot443watch.service + /usr/local/bin/boot443watch.sh** - 开机 0.3 秒粒度盯 443, 任何 5 分钟内的绑定/释放/进程归属变化都记到 `/var/log/boot443watch.log`, 抓到 `users:(("name",pid=X,fd=Y))` 可直接定抢者。

## 未解 + 候选

**未解**: 今日 13:48 这次实验重启把 443 干净绑上, 监视器没看到任何抢占者, 也没看到 443 被释放。两次都是 xray 第一次就绑成功。**没复现 = 暂时没现场可挖**。

**候选方向**（按概率排序）:

1. **xray 端 listener task spawn 静默失败**（继承自历史 706 裸 spawn 问题类）——某个 accept 任务的 `tokio::spawn` 在启动时序里被 drop, 该 inbound 的 listener 任务从未进入 accept loop。dec9e3d5 的"bind fail fatal"只覆盖 bind 系统调用, 不覆盖 task spawn 后的运行时退出。
2. **systemd 启动顺序竞态**——`After=network.target` 但 `networking.service` 在 03:30:16 启动时 FAILED（journal 实锤: `networking.service loaded failed failed Raise network interfaces`）。某些 socket 选路可能在网络接口未全起时静默失败。
3. **TIME_WAIT 残留/端口重用竞态**——11:30 重启前一刻的 443 连接在 5-tuple 上有重叠, 二次 bind 在某些内核上 silent fail。

候 1 是代码层根治（listener bind 加 retry 循环、accept 任务 spawn 用 `let _ = handle.spawn(...)` 显式 log；命中 706 裸 spawn 的整类）。

## 验收预测

- 短期: 守卫保命, 11:30 丢了 2 分钟内自愈, 不再需要人盯着。
- 复现时: 监视器 + RUST_LOG 自动拍下 xray 自己的 bind 报错或 task spawn 失活现场, 那就是根治的输入。
- 根治: 在 `crates/xray-transport/src/system_listener.rs` 的 spawn 路径加 bind retry + spawn 失败告警（受控派单, 不在今天 scope）。
