# Security Policy

> **5 维安全审计 4 P1 必修项配套披露流程**（GO-WITH-CONDITIONS 必备）
> 覆盖：btls/Watfaq rustls git fork 供应链、MemoryAccount Debug 泄露、t2js REALITY 偏离 Go、VMess u16 截断 7 处

## Supported Versions

| Crate 系列 | 支持状态 | 安全披露 |
|---|---|---|
| `xray-tls` / `xray-reality` (含 btls + Watfaq rustls git fork) | 维护中——但**git fork 依赖**待 PM 拍板迁移 | 即时修复 |
| 17 个 `xray-proxy-*` (VLESS/VMess/Trojan/SS/Hysteria2/TUIC/AnyTLS/WireGuard/Naive) | 维护中 | 即时修复 |
| 9 个 `xray-transport-*` (TCP/WS/HTTPUpgrade/SplitHTTP/gRPC/KCP/QUIC) | 维护中 | 即时修复 |
| `xray-buf` / `xray-mux` / `xray-app-dispatcher` (数据面 + 控制面) | 维护中 | 即时修复 |
| `xray-stress` / `xray-cli` / `xray-core` | 维护中 | 即时修复 |
| `feature/framework` 分支（起点 f242e67b） | 预生产——**仅 dev 用** | 提交者直发 issue |

**旧版本不在披露范围**——master 旧 commit 不修（迁移到新版本即可）。

## Reporting a Vulnerability

### 5 维 P1 必修项（生产换核前消化）

| ID | 风险 | 披露路径 |
|---|---|---|
| **P1-001** btls v0.5.6 (0x676e67 git fork) + Watfaq rustls v0.23.40 (e6e8e7e git fork) 两条核心 TLS 依赖均为社区 fork 无 release tag | 供应链风险+CVE 修复滞后 | 公开 GitHub Security Advisory + 邮件 |
| **P1-002** MemoryAccount (SS/Trojan/VLESS) `derive(Debug)` 含明文密码/UUID | tracing/panic 泄露密钥级敏感数据 | 公开 GitHub Security Advisory |
| **P1-003** t2js REALITY X25519-only CH accept-more 偏离 Go reject→forward 语义 (osn1 注释自承认) | 协议字节级与 Go 不对齐，互操作分裂 | 公开 GitHub Security Advisory |
| **P1-004** VMess chunk size u16 截断静默替换 u16::MAX（7 处）| 收侧解析错位无错误 | 公开 GitHub Security Advisory |

### 披露方式

**优先**：GitHub Security Advisories（私有披露）
- https://github.com/Be90nia/xray-core-rust/security/advisories/new

**备选**：邮件（24h 响应）
- 联系项目维护者——通过 GitHub @Be90nia 私信

**不在范围**（请走普通 issue）：
- 协议设计/性能优化建议 → GitHub Issues
- 协议 wire format 边界 → bd 票面 `xray-frame-form`
- CI/构建问题 → GitHub Issues

## Disclosure Timeline

```
T+0   报告人提交（GitHub Security Advisory 私有）
T+24h 维护者确认收到 + 给初步分类
T+72h 维护者给评估（影响范围 + 优先级 + 修复计划）
T+7d  修复 commit（如果是 P0/P1 critical）
T+14d 公开披露（同步 release tag）
```

**P0 critical 例外**：24h 内出 fix（不经 7d 流程）。

## Security Audit Trail

| 日期 | 审计 | 报告 |
|---|---|---|
| 2026-09-15 | 5 维 60 findings 战役 | docs/audit-fix-{2f8o,30gf,4jrt,88m0,onx4,osn1,txhn,xf6z,zl5t}.md |
| 2026-09-24 | 性能 + unwrap 模式审计 | docs/audit-perf-2026-09-24.md, docs/audit-unwrap-2026-09-25.md |
| 2026-10-12 | 立项级 5 维 + 9 票审视 | docs/audit-安全-2026-10-12.md (4 P1 必修) |

## PGP 密钥

> 项目维护者使用 GitHub 账号托管公钥——首次披露时建立信任链。

---

**5 维安全审计 5 维评分 3.4/5** —— 4 P1 必修项是本披露流程的核心保护对象。
