# Xdrive 真实云后端活体验证手册（Drive / S3）

> bd yc54c G2 收口件。两个 env 门控的活体测试：`tests/drive_live.rs`（Google Drive）、
> `tests/s3_live.rs`（任意 S3 兼容端点）。**用户明早提供凭据后，按本手册两步即可跑通真实验证。**
>
> **脱敏纪律（硬约束）**：凭据只经环境变量注入，不落库、不进仓库/报告/日志；测试输出只打
> **前 6 位脱敏前缀**。验证完成后建议吊销/轮换所用凭据。

---

## 0. 一页速览

| 测试 | 必填 env | 命令 |
|---|---|---|
| Drive 1MiB 往返 | `XDRIVE_DRIVE_CLIENT_ID` `XDRIVE_DRIVE_CLIENT_SECRET` `XDRIVE_DRIVE_REFRESH_TOKEN` `XDRIVE_DRIVE_FOLDER_ID` | `cargo test -p xray-transport-xdrive --test drive_live -- --ignored --nocapture` |
| S3 1MiB 往返 | `XDRIVE_S3_ENDPOINT` `XDRIVE_S3_REGION` `XDRIVE_S3_BUCKET` `XDRIVE_S3_ACCESS_KEY` `XDRIVE_S3_SECRET_KEY` | `cargo test -p xray-transport-xdrive --test s3_live -- --ignored --nocapture` |

- 缺任一必填 env ⇒ 测试**打印缺失清单后 SKIP**（不算失败）。
- `#[ignore]` 门：普通 `cargo test` 永不触碰；带 `-- --ignored` 才真跑。
- 每个测试做：**put 1MiB 伪随机 → get 逐字节比对 → list 含对象 → delete → get 断言 NotFound**；
  对象随机命名、跑完即删（断言中途失败会打印对象名，便于手工清理）。
- S3 另有两个可选 env：`XDRIVE_S3_SESSION_TOKEN`（临时凭据第三元）、`XDRIVE_S3_PATH_STYLE`
  （`false` = virtual-hosted 寻址，缺省 `true` = path-style）。

---

## 1. Google Drive

### 1.1 凭据获取（一次性，约 10 分钟）

1. **建项目**：打开 <https://console.cloud.google.com> → 顶部项目选择器 →「新建项目」→
   名字随意（如 `xdrive-live`）→ 创建 → 选中该项目。
2. **启用 Drive API**：左侧菜单「API 和服务 → 库」→ 搜索 `Google Drive API` → 点进 →
   「启用」。
3. **配置 OAuth 同意屏幕**：「API 和服务 → OAuth 同意屏幕」→ 选 `External` → 填应用名
   （如 `xdrive-live`）→ 用户支持电子邮件填你自己 → 一路保存；在「测试用户（Test users）」
   里**添加你自己的 Google 账号**（不加会报 `access_blocked`）。
4. **建 OAuth 客户端**：「API 和服务 → 凭据 → 创建凭据 → OAuth 客户端 ID」→ 应用类型选
   **桌面应用** → 创建 → 复制 **客户端 ID**（`*.apps.googleusercontent.com`）和
   **客户端密钥**。⇒ 得到 `XDRIVE_DRIVE_CLIENT_ID`、`XDRIVE_DRIVE_CLIENT_SECRET`。
5. **取 refresh token**：打开 <https://developers.google.com/oauthplayground> →
   右上角**齿轮** → 勾选「Use your own OAuth credentials」→ 填入上一步的 Client ID /
   Client Secret → 左侧授权框手动输入 scope：
   `https://www.googleapis.com/auth/drive` → 「Authorize APIs」→ 用**第 3 步里加的账号**
   登录并同意 → 「Exchange authorization code for tokens」→ 复制 **refresh_token**。
   ⇒ 得到 `XDRIVE_DRIVE_REFRESH_TOKEN`。
6. **取文件夹 ID**：打开 <https://drive.google.com> → 新建一个文件夹（如 `xdrive-live`）→
   进入该文件夹 → 浏览器地址栏末段即 folder id（形如
   `1a2B3c4D5e6F7g8H9iJkLmNoPqRsTuVw`）。⇒ 得到 `XDRIVE_DRIVE_FOLDER_ID`。

> scope 用 `auth/drive`（全量）最省事；嫌大可换 `auth/drive.file`（仅访问本应用创建的
> 文件——**但 remoteFolder 必须是该应用自己创建的文件夹**，手工建的文件夹会 404）。

### 1.2 运行

bash（Linux/macOS/WSL/git-bash）：

```bash
export XDRIVE_DRIVE_CLIENT_ID='xxx.apps.googleusercontent.com'
export XDRIVE_DRIVE_CLIENT_SECRET='GOCSPX-xxx'
export XDRIVE_DRIVE_REFRESH_TOKEN='1//0gxxx'
export XDRIVE_DRIVE_FOLDER_ID='1a2B3c4D5e6F'
cargo test -p xray-transport-xdrive --test drive_live -- --ignored --nocapture
```

Windows PowerShell：

```powershell
$env:XDRIVE_DRIVE_CLIENT_ID='xxx.apps.googleusercontent.com'
$env:XDRIVE_DRIVE_CLIENT_SECRET='GOCSPX-xxx'
$env:XDRIVE_DRIVE_REFRESH_TOKEN='1//0gxxx'
$env:XDRIVE_DRIVE_FOLDER_ID='1a2B3c4D5e6F'
cargo test -p xray-transport-xdrive --test drive_live -- --ignored --nocapture
```

### 1.3 预期输出（脱敏形态）

```text
Drive 活体：client_id=123456… client_secret=GOCSPX… refresh_token=1//0g… folder=1a2B3c…
对象名：xdrive-live/live-1731388800-12345.seg（断言失败时请手工删除该残件）
...
test drive_roundtrip_1mib ... ok
```

跑完 Drive 文件夹里**不留残件**（成功路径已删除并验证 NotFound）。

### 1.4 排障

| 症状 | 原因 | 处置 |
|---|---|---|
| `invalid_grant` | refresh token 过期/吊销，或 Client ID/Secret 与签发时不一致 | 重跑 1.1 第 5 步 |
| `access_blocked` / `unauthorized_client` | 同意屏没加测试用户，或 OAuth 客户端类型非桌面应用 | 1.1 第 3/4 步补齐 |
| `accessNotConfigured`（403） | 项目未启用 Drive API | 1.1 第 2 步 |
| 404 `File not found` | folder id 错（复制成了整段 URL） | 1.1 第 6 步，取地址栏**末段** |

---

## 2. S3（AWS / MinIO / R2 等任意 S3 兼容端点）

### 2.1 凭据获取

**AWS**：

1. <https://console.aws.amazon.com/iam> → 用户 → 创建用户（勾选编程访问）→ 直接附加策略
   `AmazonS3FullAccess`（正式环境应收窄到单桶前缀）→ 创建后立即复制
   **Access Key ID / Secret Access Key**（Secret 只显示一次）。
2. S3 控制台建一个桶（如 `xdrive-live`），记下所在 region（如 `us-east-1`）。
3. env 取值：`XDRIVE_S3_ENDPOINT=https://s3.us-east-1.amazonaws.com`、
   `XDRIVE_S3_REGION=us-east-1`、`XDRIVE_S3_BUCKET=xdrive-live`、两个 KEY 照抄。
   临时凭据（STS）另加 `XDRIVE_S3_SESSION_TOKEN`。

**MinIO（本机，零云成本自测）**：

```bash
docker run -d --name minio -p 9000:9000 -e MINIO_ROOT_USER=akminio -e MINIO_ROOT_SECRET=skminio minio/minio server /data
docker exec minio mc alias set local http://127.0.0.1:9000 akminio skminio && docker exec minio mc mb local/xdrive-live
```

env：`XDRIVE_S3_ENDPOINT=http://127.0.0.1:9000`、`XDRIVE_S3_REGION=us-east-1`、
`XDRIVE_S3_BUCKET=xdrive-live`、`XDRIVE_S3_ACCESS_KEY=akminio`、`XDRIVE_S3_SECRET_KEY=skminio`。
（`http://` 端点测试自动跳过 TLS。）

> Cloudflare R2：端点 `https://<account>.r2.cloudflarestorage.com`、region 填 `auto`、
> API Token 页拿 Access Key/Secret；path-style 与 virtual-hosted 均支持，缺省即可。

### 2.2 运行

```bash
export XDRIVE_S3_ENDPOINT='https://s3.us-east-1.amazonaws.com'
export XDRIVE_S3_REGION='us-east-1'
export XDRIVE_S3_BUCKET='xdrive-live'
export XDRIVE_S3_ACCESS_KEY='AKIAxxx'
export XDRIVE_S3_SECRET_KEY='xxx'
cargo test -p xray-transport-xdrive --test s3_live -- --ignored --nocapture
```

PowerShell 同理（`$env:XDRIVE_S3_…='…'` 五连后同一条 cargo 命令）。

### 2.3 预期输出（脱敏形态）

```text
S3 活体：endpoint=https://s3.us-east-1.amazonaws.com region=us-east-1 bucket=xdrive-live path_style=true access_key=AKIAxx… secret_key=xxx… session_token=…
对象名：xdrive-live/live-1731388800-12345.seg（断言失败时请手工删除该残件）
...
test s3_roundtrip_1mib ... ok
```

### 2.4 排障

| 症状 | 原因 | 处置 |
|---|---|---|
| `SignatureDoesNotMatch` | Secret Key 错，或端点经代理改写请求 | 核对 Key；绕开中间代理 |
| `NoSuchBucket` | 桶名/region 不匹配 | 建桶；region 与端点一致 |
| 403 `AccessDenied` | IAM 策略缺权限，或 virtual-hosted 寻址桶名非 DNS 兼容 | 放宽策略；`XDRIVE_S3_PATH_STYLE=false` 只在端点支持 vhost 时用 |
| 连接超时 | 企业网络拦 443 出站 | 换本机 MinIO 先自测 |

---

## 3. 脱敏与安全说明

- 凭据**只**从进程环境变量读取；测试代码不含任何字面凭据，输出/断言消息只含**前 6 位 +
  省略号**（`mask()` 函数，见两个测试文件）。
- bash `export` 会留在 shell history：跑完 `history -c` 或用一次性 shell；PowerShell 的
  `$env:` 只活在当前会话，关窗即消失。
- 报告/票面引用验证结果时只写脱敏前缀与 PASS/FAIL，不贴完整凭据。
- 验证完成后建议：Google 侧在 OAuth 同意屏删除测试应用或吊销 refresh token；AWS 侧停用/
  轮换访问键。

## 4. 与既有测试的关系

| 文件 | 端点 | 性质 |
|---|---|---|
| `tests/s3_e2e.rs` / `tests/drive_.rs` / `tests/template_ops.rs` | 进程内 mock | 快速回归面，`cargo test` 默认跑 |
| `tests/s3_real_backend.rs` | 本机 moto（`XDRIVE_S3_ENDPOINT` 指向 `127.0.0.1`） | 第三方 S3 实现锚，`#[ignore]` |
| `tests/s3_live.rs` / `tests/drive_live.rs` | **真实云** | 本手册，`#[ignore]` + 真凭据 |
