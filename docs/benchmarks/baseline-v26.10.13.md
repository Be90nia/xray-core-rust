# 性能基版 v26.10.13（2026-10-13 定案）

> 用户拍板：**以此版为基线，以后任何版本速度低于此版 = 有问题（回归）**，必须查因修复。

## 基版信息

| 项 | 值 |
|---|---|
| tag | `v26.10.13` |
| commit | `ae2f826e` |
| binary md5 (win) | `74f4dc6d477fc63e94cb1fd33df592b9` |
| 关键内容 | 3287ef93 优化波（vision 单 IoSlice 直借 + splithttp/grpc/kcp 池化）+ ede17f53（RAW_WRITE_ARM_DELAY 5ms + arm 结构守卫）+ poll 化回退后基线 + target-cpu=native |

## 基线速度（2026-10-13 用户实测）

| 场景 | 基线 |
|---|---|
| us1:39824 raw+reality 直连（vless+vision），v2rayN 多线程测速 | **≥25 MB/s（用户确认"完美恢复"）** |
| 参考带宽上限 | 用户直连历史最好 ~30 MB/s（搬瓦工 GIA + bbrplus） |

## 测量方法约定

- **验收方法 = v2rayN 多线程测速**（用户原生方法）——PM 单线程 curl 数字（~4 MB/s）与多线程（25+）不可直接比（聚合效应，勿自造冤案）
- 相对对比必须同 binary 同窗交替；跨时间窗对比无效（regime 摆动）
- 定时自动验收工具：`tools/golden_window_test.py`（schtasks + FRDBG 现场日志 + 中位数判据）

## 回归判据

- v2rayN 实测 < 25 MB/s（同节点同方法）→ **回归，开 bd 票查因**
- 已知不可归因于代码的噪声源（先排除再定罪）：线路 regime 摆动（跨窗）、v2rayN 测速缓存行（一字不差=缓存）

## 历史教训（本案结案记录）

根因 = v2rayN 停留在 10-11 19:20 旧构建，缺 3287ef93（10-11 23:45）优化波。
"新版变慢"第一动作：核对 binary 构建时间 vs master commit 时间线。
