# xray-stress summary — run `stress-1790421332`

- duration: 18000s
- finished: unix=1790439704

## 内存（进程 RSS）

- baseline (first 10%): 2268.0 MB
- first / last / peak: 24.3 / 2555.9 / 2575.6 MB
- linear slope: 38.62 MB/h (1.70 %/h of baseline)
- leak threshold: 5.0 %/h
- verdict: **OK — 未检出线性泄漏**

## 吞吐（scenarios=[S1, S2, S3, S4, S5, S6]）

- first-25% window avg: 1854060142 B/s
- last-25% window avg: 10943636796 B/s
- tail/head ratio: 5.903
- verdict: **OK**

## 场景计数

| scenario | conn_ok | conn_fail | tx_bytes | rx_bytes | p50_ms | p95_ms | p99_ms |
|---|---|---|---|---|---|---|---|
| s1-short | 939438 | 0 | 59184594 | 59184594 | 2.3 | 3.8 | 4.4 |
| s2-long | 341 | 4 | 773508561 | 773508561 | 14.5 | 55.6 | 219.7 |
| s3-quic | 9185783 | 3 | 0 | 150499868672 | 1.8 | 2.1 | 2.7 |
| s4-mixed-kcp | 238412 | 1 | 104305058747 | 104305058747 | 51.1 | 651.0 | 898.9 |
| s5-vmess-ws | 748529 | 0 | 47157327 | 47157327 | 41.4 | 42.4 | 42.9 |
| s6-trojan-grpc | 945556 | 0 | 59570028 | 59570028 | 1.3 | 2.8 | 3.3 |

错误计数表：上表 conn_fail 列即每场景失败连接数。
