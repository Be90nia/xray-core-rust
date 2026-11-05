# protos/ — Protobuf schema 镜像

> Go Xray-core **v26.10.17** 同步的 protobuf schema 镜像
> ⚠️ **这里是编译源**：`crates/xray-proto/build.rs` 直接读 `../../protos` 生成 prost 代码，
> 改这里 = 改生成类型（旧记「纯参考，不参与编译」已过期）。
> 宪法 §3.2 Step 0 "动手前 grep Go 基线" 的源头

## 用途

5 个子目录（app/common/core/proxy/transport）= Go Xray-core 的 proto schema 镜像：
- 用于 Xray-core-rust 协议实现时**对齐** Go 的 wire format
- 用于 v1 验证「字段名/字段类型/嵌套结构」一致
- 用于 PR review 时的 Go-Rust 对照查表

## 与 cargo 关系

- `protos/` 不在 `Cargo.toml` workspace.members 里，但 **`crates/xray-proto` 编译期消费**它
  （build.rs → protoc → prost）；`protos/` 一改，`xray-proto` 及其下游全部重编
- `protos/.checksums.json` 是漂移门账本：CI job `Proto Drift Gate` 跑
  `python3 tools/check_proto_drift.py --manifest`，内容与账本不一致即红
- 改完必须 `python3 tools/check_proto_drift.py --write` 重生成账本（哈希按 LF 归一，
  Windows 工作树 CRLF 不误报）

## 同步机制

```bash
# 手动同步（建议加到 M2 onv9 短期 sync 工单）
rsync -av D:/Project/Xray-core/proxy/ D:/Project/Xray-core-rust/protos/proxy/
```

## 何时用

- 写新协议**前**：grep `protos/<proto>/` 验证 wire format
- 写 vless/vmess/trojan/ss 等 wire 编解码**时**：以 protos 为契约
- 框架 P2 协议注册表**时**：protos 是核心契约
- DEBT-013（v2 协议 wire format 契约测试）**直接消费** protos/

## 红线

- **默认不改**：镜像以 Go 26.10.17 为唯一事实源；`python3 tools/check_proto_drift.py --upstream D:/Project/Xray-core`
  的能量出真实漂移清单（逐条按下面判据定性，非一刀切）
- **确需偏离**（仅两种，且必须带证据）：
  1. Go 有新版本而我们未跟 → 按 Go 同步
  2. Rust 独有能力需要 proto 承载 → **只允许两种情况**：
     - 有 Rust 消费点：用**高位 tag**（避开 Go 已占用段，如 `QuicParams.udp_hop = 100`）+ 件头注释写明「Rust 扩展，Go 无此字段」
     - 无 Rust 消费点：**删掉**（配了不生效的死旋钮 = 打回项，bd zg6eg）
- 手改后必须 `--write` 更新 `.checksums.json`，并在报告里附 Go 行号证据
- protos/ 本身**不**.gitignore（保持对齐可追溯）
