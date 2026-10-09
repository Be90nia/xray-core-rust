# xray-stress summary — run `stress-1790421621`

- duration: 18000s
- finished: unix=1790440025

## 内存（进程 RSS）

- baseline (first 10%): 772.6 MB
- first / last / peak: 16.0 / 1011.7 / 1011.7 MB
- linear slope: 48.41 MB/h (6.27 %/h of baseline)
- leak threshold: 5.0 %/h
- verdict: **SUSPECT — RSS 线性增长超阈值**

## 吞吐（scenarios=[S7, S8, S9, S10, S11, S12]）

- first-25% window avg: 1432760 B/s
- last-25% window avg: 10282646 B/s
- tail/head ratio: 7.177
- verdict: **OK**

## 场景计数

| scenario | conn_ok | conn_fail | tx_bytes | rx_bytes | p50_ms | p95_ms | p99_ms |
|---|---|---|---|---|---|---|---|
| s7-ss-tcp | 656053 | 25927 | 41331339 | 41331339 | 10.1 | 28.1 | 255.4 |
| s8-tuic | 653508 | 22849 | 41171004 | 41171004 | 9.9 | 27.7 | 277.2 |
| s9-anytls | 111354 | 6396 | 7015302 | 7015302 | 13.2 | 29.9 | 280.5 |
| s10-vless-xhttp | 197208 | 11240 | 12424104 | 12424104 | 35.5 | 48.5 | 324.1 |
| s11-http-proxy | 633991 | 26471 | 39941433 | 39941433 | 17.2 | 31.6 | 249.2 |
| s12-vmess-h3 | 478302 | 19247 | 30133026 | 30133026 | 17.1 | 33.1 | 255.0 |

错误计数表：上表 conn_fail 列即每场景失败连接数。
