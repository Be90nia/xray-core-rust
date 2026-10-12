# bd 4jrt 修复报告：setup_boringssl_reality.py 锚点失配静默空插

日期：2026-10-09 ｜ 范围：`tools/setup_boringssl_reality.py`（+65/-11，仅此一文件）

## 结论

**VERDICT: FIXED**。锚点未命中从「静默空插仍打 applied」改为硬错（带 文件:锚点摘要）；`apply_reality_patches` 末尾新增符号自校验（6 目标文件 REALITY 符号计数必须 >0）；对现存 `target/debug/build/btls-sys-*/out/boringssl` 目录干跑验证 8 场景全部真实反映状态（成功/已存在/硬错），无假 applied。

## 改动清单

| 位置 | 内容 |
|---|---|
| `insert_after` | 新增 `what` 参数；未命中 → `SystemExit("{what}: anchor not found (boringssl version drift?): {anchor[:80]!r}")` |
| `replace_exact` | n=0 与 n>1 分开报：n=0 = 锚点漂移硬错（旧版误提示 "already applied?"），n>1 才是已应用 |
| `_read_target`（新） | 目标文件缺失（空/非 boringssl 树）→ 明确 SystemExit，替代 FileNotFoundError traceback |
| `VERIFY_SYMBOLS` + `verify_reality_patches`（新） | 6 目标文件 × 符号计数 >0 断言，任一为 0 即硬错；apply 末尾自动调用，亦可独立只读调用 |
| `apply_reality_patches` | 7 处读取改走 `_read_target`；3 处 `insert_after` 补 `what`；ssl_lib.cc 手工 find 报错补锚点摘要；末尾接 `verify_reality_patches(dest)` |

## 干跑验证（python 3.14，py_compile 零错）

1. **已 patch 目录幂等回放**（`955f…`/`c598…`）：7 步全 `already present (skip)` + `self-check ok`，exit 0，零写入。
2. **只读自校验**：两目录 `verify_reality_patches` 独立调用 OK。
3. **缺失目录**（`btls-sys-3e75b1656db62cee/out/boringssl`）与**空目录**：`reality patch target missing: …\include\openssl\ssl.h — empty or non-boringssl tree?`，exit 1。
4. **场景 A insert_after 漂移**（ssl.h 锚点函数名被改）：`include/openssl/ssl.h: anchor not found (boringssl version drift?): 'OPENSSL_EXPORT int SSL_set1_client_key_shares(SSL *ssl,\n…'`，exit 1。
5. **场景 B replace_exact 漂移**（handshake.cc 锚点被改）：前 4 步正常 skip，随后 `handshake.cc: anchor not found (boringssl version drift?): 'bool ssl_add_message_cbb(SSL *ssl, CBB *cbb) {\n…'`，exit 1。
6. **场景 C 全成功插入路径**（已 patch 树剥离 1-6 步 REALITY 块后重放）：1-6 步真实 `applied`、7-8 步 skip、`self-check ok` —— 证明 "applied" 只在真实写盘后打印。
7. **场景 D 事故树回放**：`6dfc…`（本机 LNK2019 零符号树，复制到临时目录、原件未动）7 步全 applied + self-check ok —— 修复版工具可完整修复事故树。

## 验收对照

- [x] 未命中锚点 → 硬错（文件:锚点:上下文摘要），禁静默继续 —— 场景 A/B
- [x] apply 末尾自校验符号计数 >0 —— `verify_reality_patches`，场景 D 末行
- [x] 现存目录幂等测试：已 patch OK-through、空/缺失明确报错 —— 场景 1/3
- [x] 干跑输出真实反映状态，无假 applied —— 场景 C（applied 仅在真实插入后）
- [x] python 语法零错 —— `py_compile` OK
- [x] 不做真编译（btls 重编留给 CI/后续构建）

## 残余风险 / 未做

- 未跑真实 cargo/btls 重编（任务明确豁免）；下一次真实构建是终验门（PM 验证可按票面 `cargo test --lib -p xray-core`）。
- `6dfc…` 事故原件保留未动（回放用临时副本）；该 stale 构建目录可由 PM 决定清理或重建。
- tls13_client.cc 自校验仅断言正向符号（`ssl_reality_server_hello_maybe`）；session_id 回显删除的残留断言维持 apply 第 7 步既有检查。
