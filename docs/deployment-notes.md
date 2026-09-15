# 部署注意事项

## 主机已调优 TCP 拥塞控制时（BBRPlusV3 / xanmod / 魔改内核 CC）

Xray-core-rust **不触碰**宿主机的全局拥塞控制设置：

- 进程不会读写 `/proc/sys/net/ipv4/tcp_congestion_control`，也不会修改任何
  `/proc/sys/net/`/* sysctl。内核 TCP 路径始终使用宿主机当前默认 CC
  （例如 tcpboost/BBRPlusV3 内核的 `bbrplusv3`、xanmod 的 BBR/Shrine 等），
  Xray 的 TCP 出站/入站连接继承该默认。
- 唯一设置 CC 的路径是 per-socket 显式配置：在出站的 `sockopt` 中写
  `"tcpCongestion": "<算法名>"` 时，Xray 仅对**该出站新建的 socket** 执行
  `setsockopt(TCP_CONGESTION)`（对齐 Go `sockopt_linux.go` 语义；Linux 生效，
  其他平台忽略；算法未加载时内核返回 ENOENT）。不配置（默认）= 完全不设置。

因此：

| 宿主机情况 | 行为 |
|---|---|
| 已装 BBRPlusV3/xanmod/魔改 CC 并设为默认 | Xray 直接受益，无需任何配置，也不会覆盖你的设置 |
| 想让 Xray 出站流量走特定 CC | 仅对需要的出站配 `sockopt.tcpCongestion`，其余流量不受影响 |
| 未做任何调优 | 行为与标准内核默认一致（通常 cubic），Xray 不代管 sysctl |

> 历史背景：曾评估过「QUIC 默认 CC 切 BBR」（bd 6wem），因未实测改默认行为
> 有回归风险被收口（50074b2 教训）。当前默认行为保持与 Go baseline 一致：
> QUIC 路径用 quinn 内置 CC，TCP 路径完全交给内核。
