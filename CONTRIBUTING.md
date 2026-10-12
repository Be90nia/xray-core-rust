# Contributing to Xray-core-rust

> 框架 P4 API 转正时的用户迁移入口——**CLAUDE.md 是 AI 代理入口，本文件是人类协作者入口**
> 协议接入详见 `docs/ARCHITECTURE.md` §3 recipe

## 0. 工作流

```
clone → setup → pick a ticket → branch → code → test → PR → review → merge
```

## 1. Setup（5 分钟）

```bash
# 1. 装 rustup + 选 nightly（rust-toolchain.toml 自动应用）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default nightly-2026-05-28

# 2. 装平台依赖（Windows / macOS / Linux 各不同，详见 CLAUDE.md §1）

# 3. 装 boringssl 冷编补丁（避免 btls 静默早退）
cmd /c "set BORING_BSSL_ASSUME_PATCHED=1 && set BORING_BSSL_SOURCE_PATH=D:\Project\Xray-core-rust\target\boringssl-patched && python tools/inject_btls_cache.py"

# 4. 验证
cargo build --release -p xray-cli
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

## 2. 协议接入 Recipe（CLAUDE.md §1 上手 + ARCHITECTURE.md §3 详细）

### Step 0：动手前 grep Go 基线（铁律）

```bash
# 协议语义——先看 Go 怎么写
grep -rn "your_protocol" D:/Project/Xray-core/  # Go 基线
```

**铁律**：issue 前提错误率 20+/22——每条协议**动手前**先 grep Go。

### Step 1：建 crate

```bash
# 样板：xray-proxy-mock
mkdir crates/xray-proxy-mock
cat > crates/xray-proxy-mock/Cargo.toml <<EOF
[package]
name = "xray-proxy-mock"
version = "0.1.0"
edition = "2021"

[dependencies]
xray-buf = { path = "../xray-buf" }
xray-common = { path = "../xray-common" }
xray-features = { path = "../xray-features" }
# 带 TLS 时加 xray-tls
EOF
```

### Step 2：实现编解码 + 握手回调

- `src/protocol/`：帧编解码（纯函数，buffer 规则见 ARCHITECTURE.md §3.1 ②）
- `src/outbound.rs`：独立 Handler（测试装配路径）
- `src/inbound.rs`：Inbound handler（框架 P2 accept 时用）

### Step 3：测试

```bash
# unit + integration（位于 tests/）
cargo test -p xray-proxy-mock
```

## 3. Commit 规范

- **格式**：`<type>: <description>`（git 自动）
- **type**：`feat` / `fix` / `docs` / `chore` / `refactor` / `test` / `perf`
- **scope**（可选）：`buf` / `mux` / `vless` / `tls` / `framework` / `audit` / `doc`
- **示例**：`fix(mux): 帧 meta 池化修复 alloc 次数`
- **暂存卫生**：禁 `git add -A` 一把梭，逐文件 add

## 4. PR 流程

### 4.1 必填

- [ ] `cargo test --workspace` 绿
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` 绿
- [ ] `cargo fmt --all -- --check` 绿
- [ ] `cargo doc --workspace --no-deps` 绿（公开项不能链私有项）
- [ ] CHANGELOG.md 更新（如果用户可见变化）
- [ ] bd 票面（如果是修复 issue）—— 关闭 + append notes

### 4.2 提交 PR

```bash
git push origin feature/your-feature
# GitHub 上开 PR
```

**PR 模板**（待补 `.github/ISSUE_TEMPLATE`）：摘要 + 关联 bd 票 + 测试矩阵 + 影响面

### 4.3 Review 责任

- **协议改动**：arch + protocol 双 review
- **数据面 hot path**：performance-reviewer
- **密码学/auth**：security-reviewer
- **API 暴露**：reviewer
- **框架改动**（feature/framework）：architect + framework 工作流

## 5. 5 维+9 票贡献规范

- **每个 PR 必带 5 维自评**（准确性/完整性/清晰度/可执行性/简洁性 各 1-5）
- **每个 finding 必给文件:行号 + 严重度 P0/P1/P2/P3**
- **每张 P0 必修 必落 bd 票**（label=audit）
- **每张 PR 必跑"30gf 方法论"**（同 binary 同窗交替 A/B）—— 性能债不可悄悄回归

## 6. 提交流程图

```
local branch → push → GitHub PR
                   ↓
              CI 9 宽门（fmt + clippy + test + build matrix + doc）
                   ↓
              review 1（5 维相关 specialist）
              review 2（PM 拍板）
                   ↓
              merge 到 master（squash）
                   ↓
              触发 release workflow（如打了 tag）
```

---

**Xray-core-rust 接受任何符合 Go Xray-core v26.9.9 wire format 的贡献——镜像式 1:1 移植，不自创范式。**
