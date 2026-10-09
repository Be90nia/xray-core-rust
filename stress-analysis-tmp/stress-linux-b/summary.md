# xray-stress summary — run `stress-1790421304`

- duration: 18000s
- finished: unix=1790439678

## 内存（进程 RSS）

- baseline (first 10%): 6380.8 MB
- first / last / peak: 22.6 / 6869.9 / 6961.0 MB
- linear slope: 60.01 MB/h (0.94 %/h of baseline)
- leak threshold: 5.0 %/h
- verdict: **OK — 未检出线性泄漏**

## 吞吐（scenarios=[S7, S8, S9, S10, S11, S12]）

- first-25% window avg: 2915111 B/s
- last-25% window avg: 20569578 B/s
- tail/head ratio: 7.056
- verdict: **OK**

## 场景计数

| scenario | conn_ok | conn_fail | tx_bytes | rx_bytes | p50_ms | p95_ms | p99_ms |
|---|---|---|---|---|---|---|---|
| s7-ss-tcp | 947308 | 0 | 59680404 | 59680404 | 0.8 | 2.2 | 4.6 |
| s8-tuic | 947723 | 0 | 59706549 | 59706549 | 0.7 | 2.1 | 4.8 |
| s9-anytls | 837053 | 59 | 52734339 | 52734339 | 40.9 | 42.7 | 43.7 |
| s10-vless-xhttp | 878251 | 0 | 55329813 | 55329813 | 1.3 | 32.6 | 33.3 |
| s11-http-proxy | 936159 | 0 | 58978017 | 58978017 | 2.3 | 6.6 | 8.2 |
| s12-vmess-h3 | 930923 | 318 | 58648149 | 58648149 | 3.3 | 7.1 | 8.1 |

错误计数表：上表 conn_fail 列即每场景失败连接数。
