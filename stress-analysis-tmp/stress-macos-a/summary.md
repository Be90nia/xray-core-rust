# xray-stress summary — run `stress-1790421590`

- duration: 18000s
- finished: unix=1790439992

## 内存（进程 RSS）

- baseline (first 10%): 904.4 MB
- first / last / peak: 15.5 / 1127.4 / 1127.7 MB
- linear slope: 45.24 MB/h (5.00 %/h of baseline)
- leak threshold: 5.0 %/h
- verdict: **SUSPECT — RSS 线性增长超阈值**

## 吞吐（scenarios=[S1, S2, S3, S4, S5, S6]）

- first-25% window avg: 1760376022 B/s
- last-25% window avg: 10543470415 B/s
- tail/head ratio: 5.989
- verdict: **OK**

## 场景计数

| scenario | conn_ok | conn_fail | tx_bytes | rx_bytes | p50_ms | p95_ms | p99_ms |
|---|---|---|---|---|---|---|---|
| s1-short | 687942 | 16123 | 43340346 | 43340346 | 33.0 | 56.8 | 273.6 |
| s2-long | 12 | 4 | 31361782 | 31361782 | 25.7 | 49.0 | 100.0 |
| s3-quic | 8301698 | 15099 | 0 | 136015020032 | 1.9 | 4.3 | 25.6 |
| s4-mixed-kcp | 118076 | 338 | 104394395123 | 104394395123 | 65.4 | 944.7 | 1126.4 |
| s5-vmess-ws | 717241 | 16930 | 45186183 | 45186183 | 27.7 | 61.2 | 270.8 |
| s6-trojan-grpc | 215874 | 1492 | 13600062 | 13600062 | 2.7 | 48.1 | 305.4 |

错误计数表：上表 conn_fail 列即每场景失败连接数。
