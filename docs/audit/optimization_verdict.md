# bd issue 正优化/负优化判定书 (optimization_verdict)

> 判定日期: 2026-09-06 | 范围: 四轮审计全部 4 P0 + 53 P1(独立 issue)+ P2/P3 汇总
> 依据: docs/audit/negative_optimization.md 表二(38 项修复建议负优化预审)+ 各报告逐条负优化自查 + 表三历史回退模式对照
> 判定已写回 bd 每条 issue 的 note,本文档为留档汇总

## 判定结论

**57 条 P0/P1 issue:全部为正优化,零条负优化,无一关闭。**

| 判定 | 数量 | 说明 |
|---|---|---|
| ✅ 正优化(低风险) | 41 | 修了只赚不赔:安全性/正确性/泄漏修复,无性能回退 |
| ✅ 正优化(高危前置) | 5 | 见下,修复正确但必须带测试阶梯+benchmark |
| ✅ 正优化(行为激活) | 6 | 修复=配置语义变化,须 changelog+snake/camel 双 alias |
| ✅ 正优化(零风险) | 1 | h2 CVE,cargo update 一行 |
| ❌ 负优化(P0/P1) | 0 | 无 |

## 高危前置组(5,正优化但严禁裸合入)

触碰 v49/v50/v51/v35 事故同文件或同模式,必须带阶梯:单测→stress(duplex 512KB)→interop→32 节点,逐级通过+benchmark 才合:

1. `Xray-core-rust-03pz` VLESS ENC 共享锁缩窄(dispatcher.rs:178)——v46 0-RTT 接线处
2. `Xray-core-rust-ni2s` 裸 TCP 腿 writev 批量——数据面泵
3. `Xray-core-rust-s6pt` CommonConn 每 record 双分配池化——v50/v51 根治同文件
4. `Xray-core-rust-gfb5` finalmask waker 重构——v49 splice 挂死同模式
5. `Xray-core-rust-w1l8` 出站 mux 包装——**分阶段:第一版只做 warn 消静默;完整 wrap 属 v35/R2 组合事故面**

## 行为激活组(6,需 changelog+兼容)

`4nbu`(balancer selector) / `51c5`(httpupgrade TLS) / `wyv6`(FakeDNS) / `aiaz`+`uc9n`(键族 rename **必须 snake/camel 双 alias,否则破坏现存 Rust 方言用户配置**) / `umqf`(burst 装配)

## 明确判负优化:不修(P2/P3 域,已标注留档)

| 项 | 报告 | 负优化理由 |
|---|---|---|
| 换掉 rsa 0.9.10(Marvin Attack) | dependencies | 上游无修复,换 ring/openssl/自实现 blinding 均判定负优化;正确处置=deny.toml 留档+收缩暴露 |
| aead 0.6-rc 退回 0.5 | dependencies | 刻意选择,退版连带 chacha20 yanked |
| 强删 watfaq rustls fork 的 aws_lc_rs | dependencies | provider panic 风险,须全 TLS 回归,先留档 |
| legacy ss retain 清扫改后台任务 | negative_optimization A4 | 当前量级改了反而复杂化 |
| WeakCache 换 arc_swap | negative_optimization A5 | 无 benchmark 证据前不动(铁律) |
| vmess max_padding_hint 精确化 | negative_optimization A7 | 修了无收益 |
| kcp mask_roundtrip 直接 ignore/删除 | dynamic_tests | 掩盖真死锁=负优化;先加整体超时再抓根因 |

## 判定方法

- 每条 issue 的修复建议对照:①性能回退风险(热路径/锁/分配变化) ②行为破坏面(现存用户配置/流量路径) ③与 7 起历史回退事件根因同源性(表三逐一核对,无一同源)
- b069b1a(唯一正向性能提交)未被回退,池化类建议与其同向
