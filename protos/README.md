# protos/ — Protobuf schema 镜像

> Go Xray-core v26.9.9 同步的 protobuf schema 镜像——**纯参考**，**不参与编译**
> 宪法 §3.2 Step 0 "动手前 grep Go 基线" 的源头

## 用途

5 个子目录（app/common/core/proxy/transport）= Go Xray-core 的 proto schema 镜像：
- 用于 Xray-core-rust 协议实现时**对齐** Go 的 wire format
- 用于 v1 验证「字段名/字段类型/嵌套结构」一致
- 用于 PR review 时的 Go-Rust 对照查表

## 与 cargo 关系

- `protos/` 不在 `Cargo.toml` workspace.members 里
- 不参与 cargo build / cargo test
- 不应改这里的文件——所有修改从 `D:/Project/Xray-core` Go 基线同步

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

- 不在 protos/ 写新 .proto 文件（修改 Go 基线同步）
- 不在 Xray-core-rust 仓里改 protos/ 内容（破坏对齐）
- protos/ 本身**不**.gitignore（保持对齐可追溯）
