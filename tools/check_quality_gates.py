#!/usr/bin/env python3
"""je3u3 质量门八件套 —— MASTER-BACKLOG「防复发机制」表的脚本化落盘。

八道门（对应 MASTER-BACKLOG.md 门表 1-4 + CQ-04 / PM-04 / u0pe2 / er2q5 防复发 +
bd st3l1/s4xsk 的 `#[ignore]` 登记 + bd xosi9 的 ②类 spawn 登记）：
  (a) 失败留痕门    生产代码禁 `hot_log!(DEBUG, "error=…")` 形态——失败在默认
                    warn 门下必须可见（bd u0pe2 ① 缺陷指纹：26 处失败留痕在
                    loglevel=warn 下零痕迹）。白名单只登记有 Go 源码依据的
                    瞬断重放噪声站（splithttp packet-up replay-once，
                    Go `canRetryError` 同不打日志，重放失败由 dialer WARN 兜底）。
  (b) 抑制登记门    每个 `allow(dead_code)`（含 cfg_attr 变体）必须带理由——
                    同行尾注 / 下 2 行 / 紧邻前向注释块（er2q5 交工口径：
                    「邻接注释」双向计，前向注释不漏判）；
                    `allow(unused_imports)` 恒为 0（er2q5 14→0，零豁免）。
  (c) 登记簿漂移门  跑既有 Rust 交叉断言（登记簿常量 vs 实现值，bd sgdwm 面向
                    `xray-core::memory_budget` mod tests + `xray-frame::budget`
                    tests）——脚本只负责「CI 必跑这些断言」，断言本体不在此维护。
  (d) 注释漂移抽查  登记簿/上限类整数常量的邻接注释：注释带绑定语数字但常量值
                    的任何等价表示（十进制 / N KiB/MiB 分级 / 浮点 MiB）都不在
                    注释中 ⇒ 报漂移嫌疑。保守放行三口：值已复述 / 注释自述
                    「交叉断言」（(c) 已钉住，数字漂移有测试兜底）/ 登记簿在飞债。
                    抽查语义：启发式，误放由人审兜，误红登记后收紧。
  (e) ignore 理由门 每个 `#[ignore]` 必须带 `reason = "..."`（bd st3l1 / s4xsk：
                    裸 ignore 12 处全无理由，且理由是「这测试为什么不能常跑」的
                    唯一档案）。**不判 reason 内容**（票号是否仍 OPEN 由人审）——
                    门只管「有没有写」；理由里的票号过期属登记面债，见 bd s4xsk。
  (f) 锁跨 await 门 tokio 锁 guard 跨 `.await` 的静态门（bd auf6h / PM-13）：
                    clippy 的 `await_holding_lock` 只认 `std::sync` 与「guard 绑定在
                    async 块里」的形态；本仓大量用 `tokio::sync::Mutex<Receiver>` /
                    `Mutex<Stream>` 作「!Sync 容器 + 独占读写」包装，clippy 完全不看。
                    门扫两种 tokio 形态：① 链式 `x.lock().await.m().await`（PM-06 家族，
                    持锁等对端）② 绑定 `let g = x.lock().await` 后同一块内 `.await`
                    （`drop(g)` 之前）。`parking_lot`/`std` 的 `!Send` guard 跨 await 在
                    Send future 里根本编译不过，故不入本门（(f) 只收 tokio 面）。
  (g) scope 契约门    ADR-0004 B3 组件 scope 持有件契约静态门（实现住
                    `tools/check_scope_claims.py`，本脚本只做汇总——房规同 (f)）：
                    .rs 注释/doc 与 docs/**/*.md 禁「drop/丢弃/归零 … 即/=/⇒ …
                    abort」伪 Drop-abort 断言（A5；白名单 = ADR-0004 自身 + 正确
                    口吻/禁令引文行）；crates/** 禁 `compat::ManagedScope` 残留
                    （B1' 收口）；同文件 JoinSet+ComponentScope 并存仅 WARN
                    （A6，人工确认是否双账本）。CI 的 quality-gates job 只跑扫描
                    面——self-test 由 `check_quality_gates.py --self-test`（含 (g)
                    段）或 `check_scope_claims.py --self-test` 本地跑。

用法（房规 check_udp_binds.py / check_proto_drift.py）：
  python tools/check_quality_gates.py             # 八道门全跑（(c) 含 cargo）
  python tools/check_quality_gates.py --no-cargo  # 只跑静态门 (a)(b)(d)(e)(f)(g)(h)（快路径）
  python tools/check_quality_gates.py --list      # 枚举 (a)(b)(d)(f)(h) 全部命中与分类
  python tools/check_quality_gates.py --self-test # 每道门各一条故意违反→必须报错
  python tools/check_lock_across_await.py [--list|--self-test]  # (f) 单独跑（实现所在）

扫描语义（与 check_udp_binds.py 同源，直接复用其基础设施）：
- (a)(b)(d) 只扫 crates/*/src/**（排除 crates/udf-frame——独立仓工作副本，纪律归
  udf CI；排除 tests 目录与 `#[cfg(test)]` 块——测试面不属生产纪律面）。
- (e) 相反：`#[ignore]` 只长在测试面，故扫 crates/** 与 tests/** 全树（仍排除
  udf-frame），不剥离 `#[cfg(test)]`。
- 命中判定在注释/字符串剥离后的文本上做（位置保持，行号不变）；理由判定
  （(b)）与注释窗口（(d)）回原文本取——剥离函数逐字符掏空、不位移。
- 已知盲区（登记，不静默）：(a) 只匹配消息字面量以 `error=` 开头的形态
  （u0pe2 判定表同口径）；`tracing::debug!`/`log::debug!` 面不在本门
  （生产留痕走 hot_log 单口，见 xray-common logx 纪律）。
  (h) ②类 spawn 登记（bd xosi9 / CLAUDE.md §3.5.6）：生产面每处
                    `tokio::spawn` / `tokio::task::spawn` / `std::thread::spawn`
                    必须有覆盖它的 `#[allow(clippy::disallowed_methods, reason=…)]`
                    （逐站，**必须与 spawn 同一函数体内**——bd fx93f 裁定：行距
                    临近会被跨 fn 的陈旧 allow 蹭过），或该文件在
                    SPAWN_FILE_LEVEL_REGISTRY 内用 `#![allow]` 覆盖；reason 命中
                    模板串（`任务必须长于组件` / 「进程级+数据面逐包泵+公开契约外返」
                    三连）视为无理由。
                    `#![cfg_attr(test, allow(…))]` 不覆盖生产面。
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# 复用 d597w 门的基础设施（候选文件 / 注释与字符串剥离 / cfg(test) 剥离 /
# 行号与括号配对）——同一套扫描语义，禁在两个门脚本里各养一份 lexer。
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_udp_binds import (  # noqa: E402  (房规工具导入)
    candidate_files,
    line_of,
    strip_cfg_test_blocks,
    strip_comments_and_strings,
)
from check_lock_across_await import (  # noqa: E402  (房规工具导入)
    GUARD_ACROSS_AWAIT_REGISTRY,
    gate as gate_f,
    scan_guard_across_await,
)
from check_scope_claims import (  # noqa: E402  (房规工具导入)
    gate as gate_g,
    scan_drop_abort_claims,
    scan_managed_scope_residue,
)

INT_TYPES = {
    "i8", "i16", "i32", "i64", "isize",
    "u8", "u16", "u32", "u64", "usize",
}

# ---------------------------------------------------------------------------
# (a) 失败留痕门
# ---------------------------------------------------------------------------

# DEBUG 变体：`DEBUG` / `tracing::Level::DEBUG` / `Level::DEBUG`（宁误红不漏放）。
HOT_LOG_DEBUG_ERROR = re.compile(
    r"\bhot_log!\s*\(\s*(?:tracing::)?(?:Level::)?DEBUG\s*,\s*\"error"
)

# ---------------------------------------------------------------------------
# (a) 门扩面：DEBUG 级失败留痕（bd c43mw）
# ---------------------------------------------------------------------------
# 旧 (a) 只认 `hot_log!(DEBUG, "error…` 一种字面形态；生产里大量失败留痕写成
# `LOG.debug(...)` / `tracing::debug!(...)`，默认 `warn` 门下同样零痕迹，门看不见。
# 扩面后：**任意 DEBUG 级日志**（hot_log! / LOG.debug / tracing::debug! / debug!）
# 的消息窗口里出现失败语义标记 ⇒ 命中。
DEBUG_LEVEL_CALL = re.compile(
    r"\bhot_log!\s*\(\s*(?:tracing::)?(?:Level::)?DEBUG\b"
    r"|\bLOG\.debug\s*\("
    r"|\btracing::debug!\s*\("
    r"|\blog::debug!\s*\("
    r"|(?<![\w:.])debug!\s*\("
)
# 失败语义标记（宁误红不漏放；窗口内命中即算）。
FAILURE_TEXT = re.compile(r"error\s*=|err\s*=|failed|failure|失败", re.IGNORECASE)
# 消息窗口上限：一份日志调用连同格式化参数很少超过这个宽度（括号配对失败时的兜底）。
DEBUG_TRACE_WINDOW = 240


def log_call_span(text: str, call_start: int) -> str:
    """取一条日志调用的实参区间文本（括号配对，跳过字符串体）。

    只在**调用自身**的实参里找失败标记——否则 240 字符窗口会吃掉下一条语句
    （实测会把「querying SRV record」误判成失败留痕）。括号配对失败时退化成
    固定宽度窗口（宁误红不漏放）。
    """
    text = text[:call_start + DEBUG_TRACE_WINDOW]
    i = text.find("(", call_start)
    if i < 0:
        return text[call_start:]
    depth = 0
    in_str = False
    j = i
    while j < len(text):
        c = text[j]
        if in_str:
            if c == "\\":
                j += 2
                continue
            if c == '"':
                in_str = False
            j += 1
            continue
        if c == '"':
            in_str = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[call_start:j + 1]
        j += 1
    return text[call_start:]


# 登记簿（bd c43mw 分批）：键 = 文件相对路径，值 = 该文件「保留 DEBUG」的依据。
# 契约分两档：
#   【go-debug】Go 同位也是 DEBUG/不记日志（单连接级 accept / 逐包瞬断 / 重试中继）
#   【defer】   本票配额内未覆盖（bd c43mw 第二批），逐文件点名，门每次运行都报数
FAILURE_TRACE_DEBUG_REGISTRY: dict[str, str] = {
    "crates/xray-app-dispatcher/src/default.rs": (
        "go-debug：sniffing 失败 → 用原 dest 继续（降级非失败，Go sniff 失败同样不报错）"
    ),
    "crates/xray-app-dns/src/dial.rs": (
        "go-debug：多地址顺序尝试的逐地址失败（connect failed / TIMEOUT / skipped DNS "
        "server）——最终失败经 last_err 上抛给查询方；DoH resolve failed 已提 WARN"
    ),
    "crates/xray-app-dns/src/nameserver/doh.rs": (
        "go-debug：热会话失效 → 重建连接（瞬断中继，重连成功无痕）；query failed 已提 WARN"
    ),
    "crates/xray-app-dns/src/nameserver/dot.rs": (
        "go-debug：池化连接失效 → 立即重连（瞬断中继）"
    ),
    "crates/xray-app-dns/src/nameserver/tcp.rs": (
        "go-debug：池化连接失效 → 立即重连（瞬断中继）"
    ),
    "crates/xray-app-dns/src/nameserver/udp.rs": (
        "go-debug：per-NS UDP recv loop 退出（单查询失败由 query 路径上抛给调用方）"
    ),
    "crates/xray-app-reverse/src/relay.rs": (
        "go-debug：portal 单向写失败 = 该子流终态（对端已断），非服务级失败；"
        "提级会按连接刷屏。Go 同位 `errors.LogDebug`（proxy/socks/server.go:88 同族口径）"
    ),
    "crates/xray-app-router/src/router.rs": (
        "go-debug：DNS 解析失败后规则仅按域名匹配（降级路径，非连接失败）"
    ),
    "crates/xray-cli/src/identity.rs": "go-debug：构建指纹不可得 → 'unknown'（信息性降级）",
    "crates/xray-core/src/inbound.rs": (
        "go-debug：28 处均为**逐连接握手 / 逐包解码 / 逐包发送**失败（socks·http·ss·ss2022 "
        "握手，udp decode/dispatch，dns udp handle，REALITY/trojan verify→fallback）。"
        "这类站点按连接/按包发生，提级 WARN 即等于给扫描器一个日志洪泛面（安全回退，"
        "CLAUDE.md §5「不为好看付出抗压能力」）。Go 侧同族站点同为 debug："
        "proxy/socks/server.go:88 `errors.LogDebug(ctx, \"Not Socks request…\")`"
        "（逐连接嗅探失败）、:198 逐包 `LogDebug`。真正的服务级失败（listener 错误、"
        "启动失败）已分别走 warn/error 且不在本表。"
    ),
    "crates/xray-stress/src/scenarios.rs": "go-debug：压测 harness 逐轮重连留痕（非产品面）",
    "crates/xray-tls/src/btls_client.rs": (
        "go-debug：SSL_set_session 失败 → 走 full handshake（无会话复用，功能不损）"
    ),
    "crates/xray-transport/src/happy_eyeballs.rs": (
        "go-debug：竞速拨号逐地址失败（最终由胜者 / 汇总错误决定）"
    ),
    "crates/xray-transport/src/sockopt/mod.rs": (
        "go-debug：TCP_FASTOPEN_CONNECT 不可用 → 普通握手（内核能力探测）"
    ),
    "crates/xray-transport/src/system_dialer.rs": (
        "go-debug：逐地址拨号尝试失败 / fallback family 探测（最终错误上抛调用方）"
    ),
    "crates/xray-transport/src/system_listener.rs": (
        "go-debug：MPTCP / listener controller / SO_PEERCRED 能力不可用 → 回退（能力探测）"
    ),
    "crates/xray-transport/src/tcp/hub.rs": (
        "go-debug：单连接级 accept 错误 → 继续监听（按连接刷屏，不可提级）"
    ),
    "crates/xray-transport-grpc/src/transport.rs": (
        "go-debug：dial 重试中间态（最终失败上抛）/ tcpmask wrap 失败回退 None"
    ),
    "crates/xray-transport-httpupgrade/src/register.rs": (
        "go-debug：单连接级 accept / 首字节等待 / 握手失败 → 继续监听（按连接刷屏）"
    ),
    "crates/xray-transport-hysteria/src/quinn_adapter.rs": (
        "go-debug：单流/单连接级 QUIC accept·读失败与 h3 会话结束（按连接刷屏）"
    ),
    "crates/xray-transport-hysteria/src/register.rs": (
        "go-debug：单连接级 accept 错误 → 继续监听"
    ),
    "crates/xray-transport-naive/src/dial.rs": "go-debug：h2 连接驱动结束（连接级终态）",
    "crates/xray-transport-naive/src/inbound.rs": (
        "go-debug：单连接级 TLS accept / h2 连接结束 / tunnel upgrade 失败（按连接刷屏）"
    ),
    "crates/xray-transport-splithttp/src/transport.rs": (
        "go-debug：单连接级 accept 错误 / XHTTP tcpmask wrap 回退 / REALITY fallback"
    ),
    "crates/xray-transport-websocket/src/register.rs": (
        "go-debug：单连接级握手/accept 错误与连接池补给拨号失败（按连接刷屏；池补给失败"
        "最终由拨号方错误兜底）"
    ),
}



# 白名单（文件级，房规同 check_udp_binds）。**只准登记「有 Go 源码依据的瞬断
# 重放噪声」**，新增白名单条目必须在报告/票面点名 Go 对位依据。
FAILURE_TRACE_WHITELIST: dict[str, str] = {
    "crates/xray-transport-splithttp/src/client.rs": (
        "u0pe2 判定表 #20：packet-up 连接级瞬断重放一次（GetBody）。Go "
        "canRetryError 路径同样不打日志；重放失败 → dialer.rs WARN 兜底 + "
        "错误上抛；提级 = 正常网络抖动刷屏"
    ),
}

# ---------------------------------------------------------------------------
# (b) 抑制登记门
# ---------------------------------------------------------------------------

ALLOW_DEAD_CODE = re.compile(r"allow\s*\(\s*dead_code\s*\)")
ALLOW_UNUSED_IMPORTS = re.compile(r"allow\s*\(\s*unused_imports\s*\)")

# 理由形态（机械代理，er2q5「邻接注释」口径）：
#   同行：属性收口 `]` 后同一行出现 `//` 且有非空文字；
#   下 2 行：属性行之后两行内，以 `//` 开头的非空注释行；
#   前向块：属性行向上紧邻的连续注释行（`//` `///` `//!`）。
COMMENT_LINE = re.compile(r"^\s*//")
TRAILING_COMMENT = re.compile(r"//")

# 临时登记：实测裸 allow（待清债，不属本票面——er2q5 已交工，发现即登记放行并
# 在报告列 file:line）。键 = f"{文件}#{宿主符号}"（宿主符号提取失败时用行号键）。
ALLOW_DEBT_REGISTRY: dict[str, str] = {}

# ---------------------------------------------------------------------------
# (d) 注释漂移抽查门
# ---------------------------------------------------------------------------

CONST_ITEM = re.compile(
    r"(?:^|\n)[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?const\s+"
    r"([A-Z_][A-Z0-9_]*)[ \t]*:[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*([^;\n]+);"
)
SIMPLE_INT_EXPR = re.compile(r"^\s*\d[\d_]*\s*(?:(?:<<|\*|\+|-)\s*\d[\d_]*\s*)*$")

# 绑定语关键词：注释里数字与「上限/缺省/预算」类断言词相邻才算对常量值的声明
# （抽查降噪：纯历史叙事/估算旁注/引用编号不算绑定）。
BINDING_KEYWORD_WORDS = (
    "上限|上界|硬顶|至多|最多|不超过|缺省|默认|容量|预算|账面|合计|配额|并发|条数|条目"
)
BINDING_KEYWORD = re.compile(BINDING_KEYWORD_WORDS)
# 数字 + 可选单位（含浮点 MiB 形态，如「≈ 2.5MiB」）；单位组含时间拼写
# （s/秒/ms——按常量名后缀选时间制或字节制换算）。
UNIT_GROUP = r"KiB|MiB|GiB|KB|MB|GB|B|sec|ms|s|秒"
NUM_WITH_UNIT = re.compile(rf"(\d[\d,_.]*)[ \t]*({UNIT_GROUP})?")
FLOAT_WITH_UNIT = re.compile(rf"(\d+\.\d+)[ \t]*({UNIT_GROUP})")
# 绑定语数字：关键词后 0-6 个非数字字符内的数字（含单位）。关键词在数字**后**
# （如「8 条」）不构成对值的声明，不取。
BINDING_NUM = re.compile(
    r"(?:" + BINDING_KEYWORD_WORDS + r")[^\d]{0,6}(\d[\d,_.]*)[ \t]*(" + UNIT_GROUP + r")?"
)
# 引用/日期/票号剥离：RFC 编号 / bd·票号 / commit / 日期 / 版本号 / 字母开头的
# 混合 token（IPv4、x25519、sha256、wz2b、b2og、uwq9n）不是常量值声明（抽查降噪）。
CITATION = re.compile(
    r"(?:RFC|rfc|bd|CVE|§|票|commit|version|rev)[#: ]*[A-Za-z]*\d[\w]*"
    r"|\d{4}-\d{2}-\d{2}"
    r"|v\d+(?:\.\d+)*"
    r"|\b[A-Za-z]{1,6}\d[\da-zA-Z]*\b"
)

UNIT_BYTES: dict[str, int] = {
    "": 1, "B": 1,
    "KiB": 1024, "KB": 1024,
    "MiB": 1024**2, "MB": 1024**2,
    "GiB": 1024**3, "GB": 1024**3,
}
# 时间制：常量名后缀 _MS / _SECS 选定基准单位，注释里的 s/秒/ms 按同一制换算。
TIME_NAME = re.compile(r"_(MS|SECS|SECONDS|SECS)$")
TIME_UNITS_MS: dict[str, int] = {
    "": 1, "ms": 1, "s": 1000, "sec": 1000, "秒": 1000,
    "m": 60_000, "min": 60_000, "分": 60_000,
}
TIME_UNITS_S: dict[str, int] = {
    "": 1, "s": 1, "sec": 1, "秒": 1,
    "m": 60, "min": 60, "分": 60,
}

CROSS_ASSERT_MARK = "交叉断言"


def units_for(name: str) -> dict[str, int]:
    """按常量名后缀选单位制：字节制（缺省）或时间制（_MS / _SECS 族）。"""
    m = TIME_NAME.search(name)
    if m is None:
        return UNIT_BYTES
    return TIME_UNITS_MS if m.group(1) == "MS" else TIME_UNITS_S

# 临时登记：实测注释漂移嫌疑（⚠️ CommentDrift 代理正在同批修注释漂移——本票
# 只建门 + 登记，不改任何 rust 文件；其交工后清空本登记簿收紧）。
# 键 = f"{文件}#{常量名}"；值 = 裁定理由。分两类：
#   【已裁定·注释正确】启发式假阳（值是注释数字的算术合成/叙事口径，逐一人工核证），
#     收紧时逐条复议；
#   【在飞债】CommentDrift 待修站点（本轮无）。
COMMENT_DRIFT_REGISTRY: dict[str, str] = {
    "crates/xray-app-dispatcher/src/udp_session.rs#DUPLEX_BUF": (
        "已裁定·注释正确：256KiB = 单包 65535 + 帧头 + 多包裕量（「留多包裕量」"
        "明示非 1:1 对应；4× 头寸）。值非注释单数直达，属容量推导注释"
    ),
    "crates/xray-app-dns/src/dnscommon.rs#RECV_MAX": (
        "已裁定·注释正确：65535 = 2B 长度前缀的表示上界（2^16−1）；「2B」指"
        "前缀宽度不是值本身"
    ),
    "crates/xray-proxy-tuic/src/client.rs#DEFAULT_STREAM_RECEIVE_WINDOW": (
        "已裁定·注释正确：1.25MB 是 quinn 缺省流收窗（被本常量覆盖的旧值，"
        "bd wp9o 高 BDP 窗钉叙事），本常量 16MiB 为覆盖值；历史叙事非本值声明"
    ),
    "crates/xray-proxy-vmess/src/inbound/chunk_stream.rs#PAYLOAD_MAX": (
        "已裁定·注释正确：8176 = 8KiB 池块 − AEAD tag 16B（tag 长度在邻接"
        "常量面，窗口内未复述数字）"
    ),
    "crates/xray-transport-hysteria/src/salamander_socket.rs#MAX_WIRE_DATAGRAM": (
        "已裁定·注释正确：65544 = QUIC max_udp_payload_size 64KiB + salt 8B"
        "（salt 长度在下一常量 smSaltLen 注释面，窗口内未复述数字）"
    ),
}

# ---------------------------------------------------------------------------
# (c) 登记簿漂移门——跑既有 Rust 交叉断言（断言本体住 xray-core::memory_budget
# mod tests 与 xray-frame::budget tests；改任一实现值即红，脚本只负责必跑）。
# ---------------------------------------------------------------------------

LEDGER_CROSS_ASSERT_TARGETS: list[list[str]] = [
    ["cargo", "test", "-p", "xray-core", "memory_budget"],
    ["cargo", "test", "-p", "xray-frame", "--lib", "budget"],
]


# ---------------------------------------------------------------------------
# 扫描基础设施
# ---------------------------------------------------------------------------

def strip_comments_keep_strings(src: str) -> str:
    """逐字符掏空注释（// 与 /* */），字符串/字符字面量**原样保留**、位置不变。

    (a) 门专用：指纹 `hot_log!(DEBUG, "error=…")` 的 `error=` 在字符串字面量里，
    字符串不能掏空；注释必须掏空（doc 注释里提到该形态不算命中）。
    字符串里的 `//`（如 "https://…"）不误判为注释——状态机跳过字符串体。
    """
    out = list(src)
    i, n = 0, len(src)
    NORMAL, LINE_C, BLOCK_C = range(3)
    state = NORMAL
    while i < n:
        c = src[i]
        if state == NORMAL:
            if src.startswith("//", i):
                state = LINE_C
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if src.startswith("/*", i):
                state = BLOCK_C
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if c == '"':  # 字符串体原样跳过（含转义）
                i += 1
                while i < n and src[i] != '"':
                    i += 2 if src[i] == "\\" else 1
                i += 1
                continue
            if c == "'":  # char 字面量整体跳过（生命周期 'a 只跳引号）
                m = re.match(r"'(\\.|[^\\'])'", src[i:])
                if m:
                    i += len(m.group(0))
                    continue
                i += 1
                continue
            i += 1
        elif state == LINE_C:
            if c == "\n":
                state = NORMAL
            else:
                out[i] = " "
            i += 1
        else:  # BLOCK_C
            if src.startswith("*/", i):
                out[i] = out[i + 1] = " "
                state = NORMAL
                i += 2
            else:
                if c != "\n":
                    out[i] = " "
                i += 1
    return "".join(out)


def load_production(root: Path) -> dict[Path, str]:
    """candidate_files 全量读入；返回 {路径: 原文}。

    ⚠️ candidate_files 的 `parts[1] == "udf-frame"` 排除假设**相对路径**（rglob
    在 root 为绝对路径时产出绝对路径，parts[1] 恒为盘符后第一级）——此处按
    相对 posix 路径补一道硬排除（udf-frame 独立仓，纪律归 udf CI）。
    """
    out: dict[Path, str] = {}
    for rs in candidate_files(root):
        r = rs.relative_to(root).as_posix()
        if r.startswith("crates/udf-frame/") or r.startswith("udf-frame/"):
            continue
        try:
            out[rs] = rs.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    return out


def production_clean(root: Path, raw: dict[Path, str]) -> dict[Path, str]:
    """注释+字符串掏空、cfg(test) 块剥离后的生产面文本（(b)/(d) 命中面）。"""
    out: dict[Path, str] = {}
    for rs, src in raw.items():
        out[rs] = strip_cfg_test_blocks(strip_comments_and_strings(src))[0]
    return out


def rel(root: Path, p: Path) -> str:
    return p.relative_to(root).as_posix()


# ---------------------------------------------------------------------------
# (a) 扫描
# ---------------------------------------------------------------------------

def scan_failure_traces(root: Path, whitelist: dict[str, str] | None = None) -> list[dict]:
    """生产代码 `hot_log!(DEBUG, "error=…")` 命中（白名单文件按登记分类）。

    --self-test 复用本函数（whitelist 注入临时夹具白名单，房规同 check_udp_binds）。
    """
    whitelist = FAILURE_TRACE_WHITELIST if whitelist is None else whitelist
    hits: list[dict] = []
    for rs, src in load_production(root).items():
        cleaned = strip_cfg_test_blocks(strip_comments_keep_strings(src))[0]
        for m in HOT_LOG_DEBUG_ERROR.finditer(cleaned):
            r = rel(root, rs)
            hits.append({
                "file": r,
                "line": line_of(cleaned, m.start()),
                "kind": "WHITELISTED" if r in whitelist else "PRODUCTION",
                "reason": whitelist.get(r, ""),
            })
    return hits


def scan_failure_traces_debug(
    root: Path, registry: dict[str, str] | None = None
) -> list[dict]:
    """DEBUG 级日志里的失败留痕（bd c43mw 扩面；旧 (a) 只认 `error=` 字面形态）。

    窗口判定：从调用点起 240 字符内出现 `error=` / `err=` / `failed` / `failure` /
    `失败` 即算命中（宁误红不漏放）。已由旧 (a) 形态覆盖的 `hot_log!(DEBUG, "error…`
    不重复报。
    """
    registry = FAILURE_TRACE_DEBUG_REGISTRY if registry is None else registry
    hits: list[dict] = []
    for rs, src in load_production(root).items():
        cleaned = strip_cfg_test_blocks(strip_comments_keep_strings(src))[0]
        r = rel(root, rs)
        for m in DEBUG_LEVEL_CALL.finditer(cleaned):
            if HOT_LOG_DEBUG_ERROR.match(cleaned, m.start()) is not None:
                continue  # 旧形态归 (a) 主门（白名单契约更严）
            window = log_call_span(cleaned, m.start())
            if FAILURE_TEXT.search(window) is None:
                continue
            hits.append({
                "file": r,
                "line": line_of(cleaned, m.start()),
                "registered": r in registry,
                "reason": registry.get(r, ""),
            })
    return hits


# ---------------------------------------------------------------------------
# (b) 扫描
# ---------------------------------------------------------------------------

def attr_span(cleaned: str, hit_start: int) -> tuple[int, int] | None:
    """命中点所属属性的 [ ] 跨度（`allow(...)` 所在的那一层方括号）。"""
    open_idx = cleaned.rfind("[", 0, hit_start)
    if open_idx == -1:
        return None
    depth = 0
    for j in range(open_idx, len(cleaned)):
        if cleaned[j] == "[":
            depth += 1
        elif cleaned[j] == "]":
            depth -= 1
            if depth == 0:
                return open_idx, j + 1
    return None


def has_reason(src: str, span: tuple[int, int]) -> bool:
    """er2q5「邻接注释」三形态：同行尾注 / 下 2 行注释行 / 紧邻前向注释块。"""
    start, end = span
    first_line = line_of(src, start)
    last_line = line_of(src, end - 1)
    # 1) 同行尾注：属性收口后同一行出现 `//` 且有文字
    line_end = src.find("\n", end)
    if line_end == -1:
        line_end = len(src)
    tail = src[end:line_end]
    tpos = tail.find("//")
    if tpos != -1 and tail[tpos + 2:].strip():
        return True
    lines = src.split("\n")
    # 2) 下 2 行：以 // 开头的非空注释行
    for k in range(last_line, min(last_line + 2, len(lines))):
        if COMMENT_LINE.match(lines[k]) and lines[k].strip().removeprefix("//").strip():
            return True
    # 3) 前向块：属性行向上紧邻的连续注释行（≥1 行非空）
    k = first_line - 2  # 0-based 上一行
    while k >= 0 and COMMENT_LINE.match(lines[k]):
        if lines[k].strip().removeprefix("//").strip():
            return True
        k -= 1
    return False


def subject_ident(src: str, span: tuple[int, int]) -> str:
    """allow 宿主符号名（登记簿键用；解析失败退化为行号键）。"""
    _, end = span
    tail = src[end:]
    tail = re.sub(r"\s*#\[[^\]]*\]", "", tail)  # 跳过属性链上后续属性
    m = re.match(
        r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?"
        r"(?:fn|struct|enum|union|const|static|mod|trait|type|let)?\s*"
        r"([A-Za-z_][A-Za-z0-9_]*)",
        tail,
    )
    return m.group(1) if m else f"@line{line_of(src, end)}"


def scan_suppressions(root: Path) -> dict[str, list[dict]]:
    """生产面 allow(dead_code) 全量 + 裸 allow（无邻接理由）+ unused_imports。"""
    raw = load_production(root)
    all_hits: list[dict] = []
    bare: list[dict] = []
    unused: list[dict] = []
    for rs, src in raw.items():
        cleaned = strip_cfg_test_blocks(strip_comments_and_strings(src))[0]
        r = rel(root, rs)
        for m in ALLOW_DEAD_CODE.finditer(cleaned):
            span = attr_span(cleaned, m.start())
            if span is None:
                continue
            reasonless = not has_reason(src, span)
            entry = {
                "file": r,
                "line": line_of(cleaned, m.start()),
                "ident": subject_ident(src, span),
                "bare": reasonless,
            }
            all_hits.append(entry)
            if reasonless:
                bare.append(entry)
        for m in ALLOW_UNUSED_IMPORTS.finditer(cleaned):
            unused.append({"file": r, "line": line_of(cleaned, m.start())})
    return {"all": all_hits, "bare": bare, "unused": unused}


# ---------------------------------------------------------------------------
# (d) 扫描
# ---------------------------------------------------------------------------

def eval_int_expr(expr: str) -> int | None:
    """纯整数字面量四则/移位（const 求值的安全子集）；其余形态拒判。"""
    if not SIMPLE_INT_EXPR.match(expr):
        return None
    try:
        node = ast_literal(expr)
    except (ValueError, SyntaxError):
        return None
    return node


def ast_literal(expr: str) -> int:
    """安全的整数字面量算术求值（只允许已由 SIMPLE_INT_EXPR 过滤的形态）。"""
    tokens = re.findall(r"\d[\d_]*|<<|\*|\+|-", expr)
    # Python eval 对 1 << 20 / 2 * 1024 * 1024 与 Rust 同义（此形态无除法/浮点）
    text = " ".join(t.replace("_", "") for t in tokens)
    for tok in text.split():
        if tok not in {"<<", "*", "+", "-"} and not tok.isdigit():
            raise ValueError(tok)
    return int(eval(text))  # noqa: S307  (形态已被 SIMPLE_INT_EXPR + 白名单算符钉死)


def comment_numbers(comment: str, units: dict[str, int]) -> set[int]:
    """注释里的数字（含浮点+单位按单位制换算成基准值；纯数字去分隔符）。

    浮点形态（`≈ 2.5MiB`）优先吞掉其覆盖区间，避免把 `2.5` 拆成 `2` 和 `5MiB`
    两个假数字；单位制由常量名后缀决定（字节制/时间制）。
    """
    vals: set[int] = set()
    covered: list[tuple[int, int]] = []
    for m in FLOAT_WITH_UNIT.finditer(comment):
        v = parse_count(m.group(1), m.group(2), units)
        if v is not None:
            vals.add(v)
        covered.append(m.span())
    for m in NUM_WITH_UNIT.finditer(comment):
        if any(m.start() < e and m.end() > s for s, e in covered):
            continue  # 已被浮点形态覆盖
        v = parse_count(m.group(1), m.group(2), units)
        if v is not None:
            vals.add(v)
    return vals


def compositions(numbers: set[int], target: int) -> bool:
    """值 = 注释数字的算术合成（两/三数的和差积商）——覆盖本仓惯用的
    「取整留余量 / 头+载荷 / 16×4KiB / 65535−28」式取值注释。"""
    nums = sorted(numbers)
    if target in nums:
        return True
    for a in nums:
        for b in nums:
            if a == b:
                continue
            if target in (a + b, a - b, a * b) or (b and target == a // b and a % b == 0):
                return True
    for i, a in enumerate(nums):
        for j, b in enumerate(nums):
            if i == j:
                continue
            for c in nums[i + 1:]:
                if c in (a, b):
                    continue
                if target in (a + b + c, a * b * c, a + b - c, a * b + c):
                    return True
    return False


def comment_window(src: str, item_start: int, item_end: int) -> str:
    """常量的邻接注释窗口：紧邻上方的连续注释行 + 同行 `;` 后尾注。"""
    lines = src.split("\n")
    first_line = line_of(src, item_start)
    block: list[str] = []
    k = first_line - 2  # 0-based 上一行
    while k >= 0 and COMMENT_LINE.match(lines[k]):
        block.append(lines[k])
        k -= 1
    line_end = src.find("\n", item_end)
    if line_end == -1:
        line_end = len(src)
    tail = src[item_end:line_end]
    tpos = tail.find("//")
    if tpos != -1:
        block.append(tail[tpos:])
    return "\n".join(reversed(block))


def parse_count(token: str, unit: str | None, units: dict[str, int]) -> int | None:
    """数字 token（整数或小数）× 单位 → 基准单位值。

    单位不在本常量的单位制里（如字节制常量注释里出现 `300s`）按无单位裸数
    处理；非整结果（秒制下的 500ms）不可能等于整数常量值，返回 None 跳过。
    """
    t = token.replace("_", "").strip(".,")
    mult = units.get(unit or "")
    if mult is None:
        mult = units[""]
    try:
        val = float(t) * mult
    except ValueError:  # 多重点等非数字形态（如 1.2.3）
        return None
    return int(val) if val == int(val) else None


def binding_numbers(comment: str, units: dict[str, int]) -> set[int]:
    """绑定语数字：上限/缺省/预算类关键词紧邻（≤6 非数字字符）的数字×单位。"""
    vals: set[int] = set()
    for m in BINDING_NUM.finditer(comment):
        v = parse_count(m.group(1), m.group(2), units)
        if v is not None:
            vals.add(v)
    return vals


def scan_comment_drift(root: Path, raw: dict[Path, str], cleaned_map: dict[Path, str]) -> list[dict]:
    """登记簿/上限类整数常量：绑定语声明的数字与常量值不一致 ⇒ 嫌疑。

    判定顺序（抽查精度优先）：
      ① 引用剥离（RFC/bd 票号/日期）后注释无数字 → 不判；
      ② 值的任何等价表示（十进制/分级单位/浮点 MiB）在注释任一处复述 → 放行；
      ③ 注释自述「交叉断言」→ 放行（(c) 门测试兜住值漂移，注释数字不担保真）；
      ④ 无绑定语声明（关键词紧邻的数字）→ 不判（纯叙事/旁注属人审面）；
      ⑤ 绑定语数字与值一致 → 放行；否则 → 嫌疑。
    """
    suspects: list[dict] = []
    for rs in cleaned_map:
        cleaned = cleaned_map[rs]
        src = raw[rs]
        r = rel(root, rs)
        for m in CONST_ITEM.finditer(cleaned):
            name, ty, expr = m.group(1), m.group(2), m.group(3)
            if ty not in INT_TYPES:
                continue
            v = eval_int_expr(expr)
            if v is None or v < 0:
                continue
            # CONST_ITEM 以 (?:^|\n) 起配：起点可能是常量行上一行的换行符本身，
            # 行号与注释窗口都要跳过它，否则差一行（前向注释块会取空）。
            lead = 1 if cleaned[m.start()] == "\n" else 0
            item_start, item_end = m.start() + lead, m.end()
            # 原文取窗口：cleaned 与 src 位置一致，但 cleaned 里注释已掏空——
            # 用命中行的行号回原文取块。
            window = comment_window(src, item_start, item_end)
            if not re.search(r"\d", window):
                continue
            plain = CITATION.sub(" ", window)
            units = units_for(name)
            all_nums = comment_numbers(plain, units)
            if not all_nums:
                continue
            if v in all_nums or compositions(all_nums, v):
                continue  # ② 值已复述（含算术合成：头+载荷 / 16×4KiB / 65535−28）
            if CROSS_ASSERT_MARK in window:
                continue  # ③ (c) 门已钉住
            binding = binding_numbers(plain, units)
            if not binding:
                continue  # ④ 无绑定语声明，人审面
            if v in binding or compositions(binding, v):
                continue  # ⑤ 绑定一致
            key = f"{r}#{name}"
            entry = {
                "file": r,
                "line": line_of(cleaned, item_start),
                "const": name,
                "value": v,
                "comment_numbers": sorted(all_nums),
                "binding_numbers": sorted(binding),
                "registered": key in COMMENT_DRIFT_REGISTRY,
                "reason": COMMENT_DRIFT_REGISTRY.get(key, ""),
            }
            suspects.append(entry)
    return suspects


# ---------------------------------------------------------------------------
# (e) ignore 理由门扫描
# ---------------------------------------------------------------------------

# 裸 `#[ignore]` 与等价物 `#[ignore = ""]`（有属性无理由，同属「没写为什么」）。
IGNORE_BARE = re.compile(r'#\[\s*ignore\s*(?:=\s*""\s*)?\]')


def scan_bare_ignores(root: Path) -> list[dict]:
    """`#[ignore]`（无 `reason`）全仓命中（bd st3l1 / s4xsk）。

    `#[ignore]` 只长在测试面（`#[cfg(test)]` 块 / `tests/` 目录），故本门与
    (a)(b)(d) 相反：扫全树、不剥离 cfg(test)。注释里提到 `#[ignore]`（如
    「标 #[ignore] 因需要网络」）先被掏空，不算命中。
    """
    hits: list[dict] = []
    for base in (root / "crates", root / "tests"):
        if not base.is_dir():
            continue
        for rs in sorted(base.rglob("*.rs")):
            if "udf-frame" in rs.relative_to(root).parts:
                continue
            src = rs.read_text(encoding="utf-8", errors="replace")
            cleaned = strip_comments_keep_strings(src)
            for m in IGNORE_BARE.finditer(cleaned):
                hits.append({"file": rel(root, rs), "line": line_of(cleaned, m.start())})
    return hits


# ---------------------------------------------------------------------------
# (f) 锁跨 await 门：实现住 `tools/check_lock_across_await.py`（bd auf6h）。
# 本脚本只做汇总——同一套扫描语义不在两处各养一份（房规同 check_udp_binds）。
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# (h) ②类 spawn 登记门（bd xosi9 / CLAUDE.md §3.5.6）
# ---------------------------------------------------------------------------
# 判据：生产面每处 `tokio::spawn` / `tokio::task::spawn` / `std::thread::spawn`
# 必须有覆盖它的 `#[allow(clippy::disallowed_methods, reason = "…")]`（逐站，或
# 文件级 `#![allow]` 且该文件进 SPAWN_FILE_LEVEL_REGISTRY），且 reason 不是模板
# 复述——模板理由 = 没写理由（§3.5.6「禁自造子类」的反向判据）。
SPAWN_CALL = re.compile(r"\b(?:tokio::spawn|tokio::task::spawn|std::thread::spawn)\s*\(")
ALLOW_DISALLOWED_METHODS = re.compile(
    r"(#!?)\[\s*allow\s*\(([^\[\]]*?clippy::disallowed_methods[^\[\]]*?)\)\s*\]", re.S
)
REASON_STR = re.compile(r'reason\s*=\s*"((?:[^"\\]|\\.)*)"')
# 模板理由指纹：命中即视为「无实义理由」。
SPAWN_TEMPLATE_REASON = ("任务必须长于组件",)
SPAWN_TEMPLATE_TRIPLE = ("进程级", "数据面逐包泵", "公开契约外返")

# 文件级 allow 登记簿：只有本表列出的文件才允许用文件级 allow 覆盖生产 spawn
# （每项写清为何无法逐站：站点数超分层阈值，且理由已在文件头成立）。
# ⚠️ 值里**禁写站点处数**——处数由工具数出来（gate (h) 输出逐文件计数，bd fx93f：
# 手写「8 处」与实际数不符，说明手写数字一旦漂移就是假账）。
SPAWN_FILE_LEVEL_REGISTRY: dict[str, str] = {
    "crates/xray-transport-grpc/src/transport.rs": (
        "文件级 allow 覆盖该文件全部生产 spawn（h2 conn driver / accept / close_notify / "
        "ping_pong / duplex 泵），超层阈值（>20 处/文件挂文件头，见 crate clippy.toml）；"
        "寿命随 h2 连接（bd a5r4j/lzzja/hj3jf）"
    ),
}


FN_HEAD = re.compile(r"\bfn\s+([A-Za-z_]\w*)")
# fn 项前缀（属性之后）：可见性 + 限定符，到 `fn` 关键字为止。
FN_ITEM_PREFIX = re.compile(
    r"\s*(?:pub(?:\s*\([^()]*\))?\s+)?(?:(?:const|async|unsafe|extern)\s+)*fn\s+"
)


def matching_brace(cleaned: str, open_idx: int) -> int | None:
    """`{` 配对的 `}` 下标（cleaned 已掏空注释/字符串 ⇒ 花括号只在代码面）。"""
    depth = 0
    for j in range(open_idx, len(cleaned)):
        if cleaned[j] == "{":
            depth += 1
        elif cleaned[j] == "}":
            depth -= 1
            if depth == 0:
                return j
    return None


def fn_body_scopes(cleaned: str) -> list[tuple[int, int, int, str]]:
    """全部函数体跨度 `(`fn` 偏移, 体开 `{` 偏移, 体闭 `}` 偏移, 函数名)`。

    签名里的 `(`/`[` 组必须跳过——形参 `[u8; 8]` 的 `;` 不是项结束（bd fx93f：
    按「首个 `;`」判会漏掉整只 fn，其内 spawn 变成「函数外」）。`fn f();`
    （trait/impl 声明）在括号组之外先遇 `;` ⇒ 跳过。
    """
    scopes: list[tuple[int, int, int, str]] = []
    for m in FN_HEAD.finditer(cleaned):
        j, depth = m.end(), 0
        while j < len(cleaned):
            c = cleaned[j]
            if c in "([":
                depth += 1
            elif c in ")]":
                depth = max(0, depth - 1)
            elif depth == 0 and c in "{;":
                break
            j += 1
        if j >= len(cleaned) or cleaned[j] == ";":
            continue
        close = matching_brace(cleaned, j)
        if close is not None:
            scopes.append((m.start(), j, close, m.group(1)))
    return scopes


def enclosing_fn(
    scopes: list[tuple[int, int, int, str]], pos: int
) -> tuple[int, int, int, str] | None:
    """包含 pos 的最内层函数体；None = 函数外（模块级 const/static/宏体）。"""
    best = None
    for scope in scopes:
        if scope[1] < pos < scope[2] and (best is None or scope[1] > best[1]):
            best = scope
    return best


def allow_owner(
    scopes: list[tuple[int, int, int, str]], cleaned: str, start: int, end: int
) -> tuple[int, int, int, str] | None:
    """逐站 allow 归属的函数体。

    两种形态：① 属性直接挂在 fn/方法上（`#[allow] fn f()`，含 `impl` 里的方法）⇒
    归属该 fn；② 属性挂在函数体内的语句上 ⇒ 归属所在 fn。函数外的常量/静态块
    属性（如宏体）⇒ None。
    """
    j = end
    while j < len(cleaned):
        if cleaned[j].isspace():
            j += 1
        elif cleaned[j] == "#":
            # 跳过紧随其后的其它属性（`#[inline]` 等）
            k = cleaned.find("[", j)
            if k == -1:
                return enclosing_fn(scopes, start)
            depth = 0
            while k < len(cleaned):
                if cleaned[k] == "[":
                    depth += 1
                elif cleaned[k] == "]":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            j = k + 1
        else:
            break
    m = FN_ITEM_PREFIX.match(cleaned[j:j + 400])
    if m is not None:
        head = j + m.group(0).rfind("fn")
        for scope in scopes:
            if scope[0] == head:
                return scope
    return enclosing_fn(scopes, start)


def spawn_reason_is_template(reason: str) -> bool:
    """reason 是否只是分类枚举复述（模板）——是则等同没写理由。"""
    if not reason.strip():
        return True
    if any(m in reason for m in SPAWN_TEMPLATE_REASON):
        return True
    return all(m in reason for m in SPAWN_TEMPLATE_TRIPLE)


def scan_spawn_registrations(
    root: Path, registry: dict[str, str] | None = None
) -> list[dict]:
    """生产面 spawn 调用 × 覆盖它的 disallowed_methods allow（(h) 门命中面）。

    覆盖判据（优先序）：① 同一文件、**同一函数体**内位于 spawn 之前的逐站
    `#[allow(…)]`（bd fx93f：行距临近不算——`transport.rs:357` 曾借 59 行外另一
    函数的 reason 过门；属性直接挂在 fn/方法上则归属该 fn，见 `allow_owner`）；
    ② 文件级 `#![allow(…)]`（恒覆盖全文，但只认登记簿内的文件）；③ 只有别的函数
    的逐站 allow ⇒ STALE_ALLOW（跨 fn 的陈旧 allow 不得顺带覆盖）。函数外（模块级
    const/static/宏体）的 spawn 无「同一函数体」可言，逐站 allow 一律不认 ⇒ 落在
    ②/③/裸 spawn 判定上（宁淹不错）。

    位置口径：命中在 `strip_comments_and_strings + strip_cfg_test_blocks` 的文本上定位
    （字符串被掏空 ⇒ 字符串里的花括号不干扰函数体配对）；reason 原文按同一字符
    偏移回**原始源码**取（两次剥离都是原位掏空，偏移不变）。
    """
    registry = SPAWN_FILE_LEVEL_REGISTRY if registry is None else registry
    hits: list[dict] = []
    for p in candidate_files(root):
        r = rel(root, p)
        if r.startswith("crates/udf-frame/") or r.startswith("udf-frame/"):
            continue
        try:
            src = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        # 生产面文本：注释+字符串掏空 → cfg(test) 块剥离（测试面归 clippy.toml 批量豁免）。
        cleaned = strip_cfg_test_blocks(strip_comments_and_strings(src))[0]
        if "spawn" not in cleaned:
            continue
        scopes = fn_body_scopes(cleaned)
        allows = []
        for m in ALLOW_DISALLOWED_METHODS.finditer(cleaned):
            # 属性体（含 reason 原文）从原文本同偏移取。
            body = src[m.start():m.end()]
            if "cfg_attr" in body and "test" in body:
                continue  # cfg_attr(test, …)：测试面豁免，不覆盖生产
            rm = REASON_STR.search(body)
            allows.append(
                {
                    "start": m.start(),
                    "end": m.end(),
                    "line": line_of(cleaned, m.start()),
                    "inner": m.group(1) == "#!",
                    "reason": rm.group(1) if rm else "",
                }
            )
        for m in SPAWN_CALL.finditer(cleaned):
            line = line_of(cleaned, m.start())
            host = enclosing_fn(scopes, m.start())
            prev = [a for a in allows if a["start"] < m.start()]
            near = [
                a
                for a in prev
                if not a["inner"]
                and host is not None
                and allow_owner(scopes, cleaned, a["start"], a["end"]) == host
            ]
            inner = [a for a in prev if a["inner"]]
            if near:
                a, kind = near[-1], "ADJACENT"
            elif inner:
                a = inner[-1]
                kind = "FILE_LEVEL_REGISTERED" if r in registry else "FILE_LEVEL_UNREGISTERED"
            elif prev:
                a, kind = prev[-1], "STALE_ALLOW"
            else:
                hits.append(
                    {"file": r, "line": line, "kind": "UNREGISTERED", "reason": "", "allow": None}
                )
                continue
            if kind in ("ADJACENT", "FILE_LEVEL_REGISTERED") and spawn_reason_is_template(
                a["reason"]
            ):
                kind = "TEMPLATE_REASON"
            hits.append(
                {"file": r, "line": line, "kind": kind, "reason": a["reason"], "allow": a["line"]}
            )
    return hits


# ---------------------------------------------------------------------------
# 门执行
# ---------------------------------------------------------------------------

def gate_a_hot_log(root: Path) -> tuple[bool, str]:
    """(a) 主形态：`hot_log!(DEBUG, "error=…")` 硬红 + 白名单。"""
    hits = scan_failure_traces(root)
    prod = [h for h in hits if h["kind"] == "PRODUCTION"]
    lines = []
    if prod:
        lines.append(f"FAIL (a) 失败留痕门：生产代码 `hot_log!(DEBUG, \"error=…\")` {len(prod)} 处：")
        for h in prod:
            lines.append(f"  {h['file']}:{h['line']}")
            lines.append("    → 失败必须默认 warn 门可见：提级 WARN（逐包加限频）或给出 Go 对位依据进白名单")
        wl = [h for h in hits if h["kind"] == "WHITELISTED"]
        lines.append(f"  （白名单放行 {len(wl)} 处：{'; '.join(sorted({h['file'] for h in wl}))}）")
        return False, "\n".join(lines)
    wl = [h for h in hits if h["kind"] == "WHITELISTED"]
    return True, (
        f"OK (a) 失败留痕门：生产代码零 DEBUG error= 留痕"
        f"（白名单 {len(wl)} 处：{'; '.join(sorted({h['file'] for h in wl})) or '无'}）"
    )


def gate_a(root: Path, registry: dict[str, str] | None = None) -> tuple[bool, str]:
    """(a) 失败留痕门：主形态（旧）+ DEBUG 级扩面（bd c43mw）合并判定。"""
    registry = FAILURE_TRACE_DEBUG_REGISTRY if registry is None else registry
    ok, msg = gate_a_hot_log(root)
    dbg = scan_failure_traces_debug(root, registry)
    unreg = [h for h in dbg if not h["registered"]]
    defer = [
        h for h in dbg if h["registered"] and registry[h["file"]].startswith("defer")
    ]
    if not dbg:
        return ok, msg + "\nOK (a2) DEBUG 级失败留痕：零命中"
    if unreg:
        files = sorted({h["file"] for h in unreg})
        out = [msg]
        out.append(
            f"FAIL (a2) DEBUG 级失败留痕（bd c43mw 扩面）：未登记 {len(unreg)} 处 / "
            f"{len(files)} 文件："
        )
        for h in unreg:
            out.append(f"  {h['file']}:{h['line']}")
        out.append(
            "    → 真失败提级 WARN/ERROR（逐包/单连接级加限频）；确属 Go 同位 DEBUG 则登记 "
            "FAILURE_TRACE_DEBUG_REGISTRY（go-debug: <Go 依据>）"
        )
        return False, "\n".join(out)
    out = [
        msg,
        f"OK (a2) DEBUG 级失败留痕（bd c43mw 扩面）：{len(dbg)} 处全部登记"
        f"（go-debug {len(dbg) - len(defer)} / defer {len(defer)}）",
    ]
    if defer:
        per_file: dict[str, int] = {}
        for h in defer:
            per_file[h["file"]] = per_file.get(h["file"], 0) + 1
        detail = "; ".join(f"{f}×{n}" for f, n in sorted(per_file.items()))
        out.append(f"  defer（bd c43mw 第二批待提级）：{detail}")
    return ok, "\n".join(out)


def gate_b(root: Path) -> tuple[bool, str]:
    res = scan_suppressions(root)
    lines = []
    registered = []
    for b in res["bare"]:
        key = f"{b['file']}#{b['ident']}"
        if key in ALLOW_DEBT_REGISTRY:
            registered.append(b)
        else:
            lines.append(f"  {b['file']}:{b['line']}  ({b['ident']})")
    unregistered = len(res["bare"]) - len(registered)
    if res["unused"] or unregistered:
        if res["unused"]:
            lines.insert(0, f"FAIL (b) 抑制登记门：allow(unused_imports) {len(res['unused'])} 处（恒 0）：")
            for u in res["unused"]:
                lines.insert(1, f"  {u['file']}:{u['line']}")
        if unregistered:
            lines.append(
                f"FAIL (b) 抑制登记门：裸 allow(dead_code)（无邻接理由）{unregistered} 处："
            )
        return False, "\n".join(lines)
    debt = ", ".join(f"{b['file']}:{b['line']}({b['ident']})" for b in registered) or "无"
    return True, (
        f"OK (b) 抑制登记门：allow(dead_code) {len(res['all'])} 处全部带邻接理由"
        f"（裸 0；临时登记放行 {len(registered)}：{debt}）；allow(unused_imports)=0"
    )


def gate_d(root: Path) -> tuple[bool, str]:
    raw = load_production(root)
    cleaned_map = production_clean(root, raw)
    suspects = scan_comment_drift(root, raw, cleaned_map)
    unreg = [s for s in suspects if not s["registered"]]
    reg_keys = {f"{s['file']}#{s['const']}" for s in suspects}
    stale = [k for k in COMMENT_DRIFT_REGISTRY if k not in reg_keys]
    lines = []
    if stale:
        lines.append(
            f"WARN (d)：登记簿陈旧条目（嫌疑已消失，可删除）：{'; '.join(stale)}"
        )
    if unreg:
        lines.append(f"FAIL (d) 注释漂移抽查门：绑定语声明的数字与常量值不一致（未登记）{len(unreg)} 处：")
        for s in unreg:
            lines.append(
                f"  {s['file']}:{s['line']}  {s['const']} = {s['value']}"
                f"  绑定数字={s['binding_numbers']}  注释数字={s['comment_numbers']}"
            )
    reg = [s for s in suspects if s["registered"]]
    if unreg:
        if reg:
            lines.append(f"  （登记簿放行 {len(reg)} 处）")
        return False, "\n".join(lines)
    debt = "; ".join(f"{s['file']}:{s['line']} {s['const']}" for s in reg) or "无"
    ok_msg = (
        f"OK (d) 注释漂移抽查门：整数常量注释数字与值一致（嫌疑 0；"
        f"登记簿放行 {len(reg)}：{debt}）"
    )
    if stale:
        return True, ok_msg + "\n" + "\n".join(lines)
    return True, ok_msg


def gate_e(root: Path) -> tuple[bool, str]:
    hits = scan_bare_ignores(root)
    if not hits:
        return True, "OK (e) ignore 理由门：全部 `#[ignore]` 带 reason"
    lines = [f"FAIL (e) ignore 理由门：`#[ignore]` 无 reason {len(hits)} 处："]
    for h in hits:
        lines.append(f"  {h['file']}:{h['line']}")
    lines.append(
        "    → 补 `reason = \"...\"`（写清为何不能常跑：外部对端 / 真机网络 / 人工诊断床）；"
        "禁删测试或改成永不执行"
    )
    return False, "\n".join(lines)


def gate_h(root: Path, registry: dict[str, str] | None = None) -> tuple[bool, str]:
    """(h) ②类 spawn 登记门：生产 spawn ⊆ 逐站/文件级 allow 登记集合（bd xosi9）。"""
    hits = scan_spawn_registrations(root, registry)
    bad = [
        h
        for h in hits
        if h["kind"]
        in ("UNREGISTERED", "FILE_LEVEL_UNREGISTERED", "STALE_ALLOW", "TEMPLATE_REASON")
    ]
    file_level = [h for h in hits if h["kind"] == "FILE_LEVEL_REGISTERED"]
    file_level_counts = {
        f: sum(1 for h in file_level if h["file"] == f)
        for f in sorted({h["file"] for h in file_level})
    }
    file_level_desc = "; ".join(f"{f}={n}" for f, n in file_level_counts.items()) or "无"
    if bad:
        lines = [f"FAIL (h) ②类 spawn 登记门：未登记/理由无效 {len(bad)} 处（生产 spawn 共 {len(hits)}）："]
        for h in bad:
            where = f"  allow@{h['allow']}" if h["allow"] else "  无 allow"
            lines.append(f"  {h['file']}:{h['line']}  {h['kind']}{where}")
            if h["kind"] == "STALE_ALLOW":
                lines.append("    → 该 allow 属另一个函数体（或函数外）；逐站 allow 必须写在 spawn 所在函数体内")
            if h["kind"] == "TEMPLATE_REASON":
                lines.append("    → reason 只是分类枚举复述；改写为该站自己的寿命/不可托管理由（§3.5.6 ②类三项，禁自造子类）")
        lines.append(
            "    → 逐站补 `#[allow(clippy::disallowed_methods, reason = \"…\")]`"
            "（写在 spawn 所在函数体内）；"
            "①类站点写 `①类待迁移（bd xosi9 改判）：…；目标托管口 = …`"
        )
        return False, "\n".join(lines)
    return True, (
        f"OK (h) ②类 spawn 登记门：生产 spawn {len(hits)} 处全部登记"
        f"（逐站 allow {len(hits) - len(file_level)} / 文件级登记 {len(file_level)} 处"
        f"：{file_level_desc}；模板理由 0）"
    )


def gate_c(run_cargo: bool) -> tuple[bool, str]:
    if not run_cargo:
        return True, "SKIP (c) 登记簿漂移门：--no-cargo（静态快路径不含 cargo 面）"
    lines = []
    for cmd in LEDGER_CROSS_ASSERT_TARGETS:
        print(f"  → {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        except subprocess.TimeoutExpired:
            lines.append(f"FAIL (c): {' '.join(cmd)} 超时 1800s")
            return False, "\n".join(lines)
        tail = "\n".join((proc.stdout + proc.stderr).strip().splitlines()[-12:])
        if proc.returncode != 0:
            lines.append(f"FAIL (c): {' '.join(cmd)} exit {proc.returncode}")
            lines.append(tail)
            return False, "\n".join(lines)
        lines.append(f"  exit 0: {tail.splitlines()[-1] if tail.strip() else ''}")
    return True, "OK (c) 登记簿漂移门：交叉断言全绿\n" + "\n".join(lines)


# ---------------------------------------------------------------------------
# --self-test：四道门各一条「故意违反 → 脚本报错」用例（AC#3，形态照
# check_udp_binds.py --self-test 的临时树 + 断言式）。
# ---------------------------------------------------------------------------

def cmd_self_test() -> int:
    ok = True
    with tempfile.TemporaryDirectory(prefix="qgates-") as td:
        troot = Path(td)
        src = troot / "crates" / "fx" / "src"
        src.mkdir(parents=True)

        # (a) 故意违反：DEBUG error= 留痕必须命中；非 error 的 DEBUG 与白名单文件必须放行
        (src / "bad_trace.rs").write_text(
            'fn f(e: String) {\n'
            '    crate::hot_log!(DEBUG, "error={e} doh post failed");\n'
            '}\n',
            encoding="utf-8",
        )
        (src / "ok_trace.rs").write_text(
            'fn g(e: String) {\n'
            '    crate::hot_log!(DEBUG, "tick processed");\n'
            '    crate::hot_log!(tracing::Level::WARN, "error={e} visible at warn");\n'
            '}\n',
            encoding="utf-8",
        )
        (src / "wl.rs").write_text(
            'fn h(e: String) {\n'
            '    crate::hot_log!(\n'
            '        DEBUG,\n'
            '        "error={e} packet-up request failed on connection level, replaying once"\n'
            '    );\n'
            '}\n',
            encoding="utf-8",
        )
        test_wl = {"crates/fx/src/wl.rs": "self-test whitelist"}

        def check(label: str, cond: bool) -> None:
            nonlocal ok
            nonlocal_ok = cond
            print(f"  [{'OK' if nonlocal_ok else 'FAIL'}] {label}")
            ok &= nonlocal_ok

        hits = scan_failure_traces(troot, whitelist=test_wl)
        by = {h["file"]: h["kind"] for h in hits}
        check("(a) DEBUG error= 故意违规必须报", by.get("crates/fx/src/bad_trace.rs") == "PRODUCTION")
        check("(a) 非 error DEBUG 留痕不误报", "crates/fx/src/ok_trace.rs" not in by)
        check("(a) 多行形态 + 白名单必须放行", by.get("crates/fx/src/wl.rs") == "WHITELISTED")

        # (a2) DEBUG 级失败留痕扩面（bd c43mw）：LOG.debug/tracing::debug! 形态必须命中；
        # 消息不含失败语义、或失败语义落在**下一条语句**，都不许误报。
        (src / "dbg_trace.rs").write_text(
            'fn f(e: String) {\n'
            '    crate::LOG.debug(format!("error={e} grpc accept failed"));\n'
            '    tracing::debug!(error = %e, "doh: query failed");\n'
            '    crate::LOG.debug("tick processed");\n'
            '    crate::LOG.debug("querying SRV record for address port strategy");\n'
            '    let _ = could_fail();\n'
            '}\n',
            encoding="utf-8",
        )
        dbg_hits = scan_failure_traces_debug(troot, registry={})
        dbg_lines = [h["line"] for h in dbg_hits if h["file"] == "crates/fx/src/dbg_trace.rs"]
        check("(a2) LOG.debug / tracing::debug! 失败留痕必须报", dbg_lines == [2, 3])
        ok_a2, msg_a2 = gate_a(troot, registry={})
        check("(a2) 未登记 ⇒ 门必须红", not ok_a2 and "FAIL (a2)" in msg_a2)
        # 只判 (a2) 面：临时树里的旧形态违规（bad_trace.rs）属 (a) 主门，不在本条断言范围
        _, msg_a2_reg = gate_a(troot, registry={"crates/fx/src/dbg_trace.rs": "go-debug: self-test"})
        check("(a2) 登记后 ⇒ (a2) 面绿", "OK (a2)" in msg_a2_reg)

        # (b) 裸 allow 必须报；同行/下2行/前向注释理由必须放行；unused_imports 恒报
        (src / "bare.rs").write_text(
            "#[allow(dead_code)]\n"
            "pub fn orphan() {}\n",
            encoding="utf-8",
        )
        (src / "reasoned.rs").write_text(
            "// 前向注释：drop-glue 契约（er2q5 口径）\n"
            "#[allow(dead_code)]\n"
            "pub struct Anchor;\n"
            "#[allow(dead_code)] // 同行尾注理由\n"
            "pub fn kept() {}\n"
            "#[allow(dead_code)]\n"
            "// 下 1 行理由\n"
            "pub fn kept2() {}\n"
            "// 平台面：非 unix 无消费点\n"
            "#[cfg_attr(not(unix), allow(dead_code))]\n"
            "pub struct Platform;\n",
            encoding="utf-8",
        )
        (src / "unused.rs").write_text(
            "#[allow(unused_imports)]\n"
            "use std::collections::HashMap;\n",
            encoding="utf-8",
        )
        res = scan_suppressions(troot)
        bare_files = {b["file"] for b in res["bare"]}
        check("(b) 裸 allow 故意违规必须报", "crates/fx/src/bare.rs" in bare_files)
        check("(b) 三形态理由（前向/同行/下2行）+ cfg_attr 前向不误报",
              bare_files.isdisjoint({"crates/fx/src/reasoned.rs"}))
        check("(b) allow(unused_imports) 恒报", len(res["unused"]) == 1)

        # (d) 绑定语数字 ≠ 值必须报；值复述/无数字必须放行；浮点 MiB 表示必须认
        (src / "drift.rs").write_text(
            "/// 握手在途并发上限（128 条）。\n"
            "pub const HANDSHAKE_CAP: usize = 64;\n",
            encoding="utf-8",
        )
        (src / "match.rs").write_text(
            "/// 保守预算（96MB；留 24MB 给抖动）。\n"
            "pub const BUDGET: usize = 96 * 1024 * 1024;\n"
            "/// 条目上界（估算档 ≈ 2.5MiB，单条 2~20KiB 取上沿）。\n"
            "pub const EST: usize = 128 * 20 * 1024;\n"
            "/// 平台语义（无数字，无从判漂移）。\n"
            "pub const NO_NUM: usize = 4096;\n",
            encoding="utf-8",
        )
        raw = load_production(troot)
        cleaned_map = production_clean(troot, raw)
        drift = scan_comment_drift(troot, raw, cleaned_map)
        drift_files = {d["file"] for d in drift}
        check("(d) 绑定语数字漂移（128 vs 64）故意违规必须报", "crates/fx/src/drift.rs" in drift_files)
        check("(d) 值复述（96MB）/浮点 MiB（2.5MiB）/无数字注释不误报",
              drift_files.isdisjoint({"crates/fx/src/match.rs"}))

        # (c) 交叉断言由 cargo 测试本体执行，脚本只负责命令接线——自测钉命令面
        check("(c) 交叉断言命令接线",
              LEDGER_CROSS_ASSERT_TARGETS == [
                  ["cargo", "test", "-p", "xray-core", "memory_budget"],
                  ["cargo", "test", "-p", "xray-frame", "--lib", "budget"],
              ])

        # (e) 裸 #[ignore] 必须报；带 reason / 注释里提及必须放行
        (src / "ignored.rs").write_text(
            "#[tokio::test]\n"
            "#[ignore]\n"
            "async fn bare_ignored() {}\n"
            "#[tokio::test]\n"
            '#[ignore = ""]\n'
            "async fn empty_reason_ignored() {}\n",
            encoding="utf-8",
        )
        (src / "ignored_ok.rs").write_text(
            "/// 注释里提到 #[ignore] 不算命中。\n"
            "#[tokio::test]\n"
            '#[ignore = "需要外部对端"]\n'
            "async fn reasoned_ignored() {}\n",
            encoding="utf-8",
        )
        bare_lines = {h["line"] for h in scan_bare_ignores(troot) if h["file"] == "crates/fx/src/ignored.rs"}
        check("(e) 裸 #[ignore] 与空 reason 故意违规必须报", bare_lines == {2, 5})
        check(
            "(e) 带 reason / 注释提及不误报",
            all(
                h["file"] != "crates/fx/src/ignored_ok.rs" for h in scan_bare_ignores(troot)
            ),
        )

        # (f) tokio guard 跨 await：链式/绑定两形态必须报；drop/嵌套 spawn 必须放行
        (src / "lock_bad.rs").write_text(
            "async fn chain(m: &tokio::sync::Mutex<Rx>) -> Option<i32> {\n"
            "    let v = m.lock().await.recv().await;\n"
            "    v\n"
            "}\n"
            "async fn bound(m: &tokio::sync::Mutex<Rx>) {\n"
            "    let g = m.lock().await;\n"
            "    other().await;\n"
            "    drop(g);\n"
            "}\n",
            encoding="utf-8",
        )
        (src / "lock_ok.rs").write_text(
            "async fn dropped(m: &tokio::sync::Mutex<Rx>) {\n"
            "    let g = m.lock().await;\n"
            "    drop(g);\n"
            "    other().await;\n"
            "}\n"
            "async fn spawned(m: &tokio::sync::Mutex<Rx>) {\n"
            "    let g = m.lock().await;\n"
            "    tokio::spawn(async move {\n"
            "        other().await;\n"
            "    });\n"
            "    drop(g);\n"
            "}\n",
            encoding="utf-8",
        )
        lock_hits = scan_guard_across_await(troot)
        lock_forms = {(h["file"], h["form"]) for h in lock_hits}
        check(
            "(f) 链式 + 绑定两形态故意违规必须报",
            {("crates/fx/src/lock_bad.rs", "chain"), ("crates/fx/src/lock_bad.rs", "bound")}
            <= lock_forms,
        )
        check(
            "(f) drop 后 await / 嵌套 spawn 内 await 不误报",
            all(h["file"] != "crates/fx/src/lock_ok.rs" for h in lock_hits),
        )
        ok_f, _ = gate_f(troot)
        check("(f) 有命中且未登记 ⇒ 门必须红", not ok_f)
        ok_f_reg, _ = gate_f(
            troot, registry={"crates/fx/src/lock_bad.rs#v": "accepted", "crates/fx/src/lock_bad.rs#g": "accepted"}
        )
        check("(f) 全部登记 ⇒ 门必须绿", ok_f_reg)

        # (g) scope 契约门（ADR-0004 B3）：伪 Drop-abort 断言 / B1' 残留 / A6 WARN
        docs_arch = troot / "docs" / "architecture"
        (docs_arch / "adr").mkdir(parents=True)
        (src / "scope_bad.rs").write_text(
            "// 句柄丢弃即 abort 在途任务\npub struct S1;\n", encoding="utf-8"
        )
        (src / "scope_ok.rs").write_text(
            "/// Drop 不作中止保证，为实现事实，非契约保证。\n"
            "/// 若为最后一份强引用，则 JoinSet drop ⇒ abort 全组（udf 语义）。\n"
            "pub struct S2;\n",
            encoding="utf-8",
        )
        (src / "scope_residue.rs").write_text(
            "// 旧口径同 compat::ManagedScope。\npub struct S3;\n", encoding="utf-8"
        )
        (docs_arch / "scope_bad.md").write_text(
            "# 坏文\n\nscope 句柄丢弃即 abort 在途任务。\n", encoding="utf-8"
        )
        (docs_arch / "adr" / "adr-0004-component-scope-holder-contract.md").write_text(
            "禁令描述：句柄丢弃 ⇒ 在途任务 abort 这类文案不得再写。\n", encoding="utf-8"
        )
        scope_claims = scan_drop_abort_claims(troot)
        claim_keys = {(h["file"], h["line"]) for h in scope_claims}
        check(
            "(g) .rs 注释与 docs 伪 Drop-abort 断言必须报",
            {("crates/fx/src/scope_bad.rs", 1), ("docs/architecture/scope_bad.md", 3)}
            <= claim_keys,
        )
        check(
            "(g) 正确口吻行与 ADR-0004 自身不报",
            not any(
                h["file"].endswith(("scope_ok.rs", "adr-0004-component-scope-holder-contract.md"))
                for h in scope_claims
            ),
        )
        check(
            "(g) compat::ManagedScope 残留必须报",
            any(h["file"] == "crates/fx/src/scope_residue.rs" for h in scan_managed_scope_residue(troot)),
        )
        check("(g) 伪断言+残留 ⇒ 门必须红", not gate_g(troot)[0])

        # (h) ②类 spawn 登记门（bd xosi9）：紧邻 allow 放行 / 裸 spawn 红 /
        # 模板理由红 / 文件级未登记红 / cfg_attr(test, …) 不覆盖生产。
        (src / "spawn_ok.rs").write_text(
            "fn ok() {\n"
            "    #[allow(clippy::disallowed_methods, reason = \"逐包泵：寿命 = 该连接，EOF 即自终\")]\n"
            "    tokio::spawn(async {});\n"
            "}\n",
            encoding="utf-8",
        )
        (src / "spawn_bare.rs").write_text(
            "fn bad() {\n    tokio::spawn(async {});\n}\n", encoding="utf-8"
        )
        (src / "spawn_tpl.rs").write_text(
            "fn bad() {\n"
            "    #[allow(clippy::disallowed_methods, reason = \"②豁免：任务必须长于组件（进程级/数据面逐包泵/公开契约外返），不迁托管口\")]\n"
            "    tokio::spawn(async {});\n"
            "}\n",
            encoding="utf-8",
        )
        (src / "spawn_file.rs").write_text(
            "#![allow(clippy::disallowed_methods, reason = \"文件级：站点数超阈值\")]\n"
            "fn f() {\n    std::thread::spawn(|| {});\n}\n",
            encoding="utf-8",
        )
        (src / "spawn_testcfg.rs").write_text(
            "#![cfg_attr(test, allow(clippy::disallowed_methods))]\n"
            "fn f() {\n    tokio::spawn(async {});\n}\n",
            encoding="utf-8",
        )
        # bd fx93f：allow 归属按**函数体**判定（旧行距 ≤60 的窗口能蹭 59 行外另一
        # 函数的 reason——transport.rs:357 即此形态）。
        (src / "spawn_cross_fn.rs").write_text(
            "fn backoff() {\n"
            "    #[allow(clippy::disallowed_methods, reason = \"挂钟抖动：本函数无 clock 注入面\")]\n"
            "    let _ = 0;\n"
            "}\n"
            "\n"
            "async fn driver() {\n"
            "    tokio::spawn(async {});\n"
            "}\n",
            encoding="utf-8",
        )
        # 反向必须判绿：allow 与 spawn 同函数，中间隔块级嵌套（非「紧邻行」形态）。
        (src / "spawn_same_fn.rs").write_text(
            "fn pump() {\n"
            "    #[allow(clippy::disallowed_methods, reason = \"逐包泵：寿命 = 该连接，EOF 即自终\")]\n"
            "    if true {\n"
            "        tokio::spawn(async {});\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        spawn_hits = {h["file"]: h["kind"] for h in scan_spawn_registrations(troot, registry={})}
        check(
            "(h) 紧邻 allow（实义理由）放行",
            spawn_hits.get("crates/fx/src/spawn_ok.rs") == "ADJACENT",
        )
        check("(h) 裸 spawn 必须报", spawn_hits.get("crates/fx/src/spawn_bare.rs") == "UNREGISTERED")
        check(
            "(h) 模板理由必须报",
            spawn_hits.get("crates/fx/src/spawn_tpl.rs") == "TEMPLATE_REASON",
        )
        check(
            "(h) 文件级 allow 未登记必须报 / 登记后放行",
            spawn_hits.get("crates/fx/src/spawn_file.rs") == "FILE_LEVEL_UNREGISTERED"
            and [
                h["kind"]
                for h in scan_spawn_registrations(
                    troot, registry={"crates/fx/src/spawn_file.rs": "self-test"}
                )
                if h["file"] == "crates/fx/src/spawn_file.rs"
            ]
            == ["FILE_LEVEL_REGISTERED"],
        )
        check(
            "(h) cfg_attr(test, allow(…)) 不覆盖生产 spawn",
            spawn_hits.get("crates/fx/src/spawn_testcfg.rs") == "UNREGISTERED",
        )
        check(
            "(h) allow 在 A 函数 / spawn 在 B 函数 ⇒ STALE_ALLOW（bd fx93f）",
            spawn_hits.get("crates/fx/src/spawn_cross_fn.rs") == "STALE_ALLOW",
        )
        check(
            "(h) allow 与 spawn 同函数体（含块级嵌套）⇒ 放行（bd fx93f 反向例）",
            spawn_hits.get("crates/fx/src/spawn_same_fn.rs") == "ADJACENT",
        )
        check("(h) 有违规 ⇒ 门必须红", not gate_h(troot, registry={})[0])

    print("SELF-TEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 2


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def cmd_list(root: Path) -> int:
    a_ok, a_msg = gate_a(root)
    print(a_msg)
    b_ok, b_msg = gate_b(root)
    print(b_msg)
    raw = load_production(root)
    cleaned_map = production_clean(root, raw)
    print(f"allow(dead_code) 全量 {len(scan_suppressions(root)['all'])} 处（含 cfg_attr 变体；测试面已剥离）")
    d = scan_comment_drift(root, raw, cleaned_map)
    print(f"(d) 整数常量注释嫌疑 {len(d)} 处（含登记簿放行）：")
    for s in d:
        mark = "REGISTERED" if s["registered"] else "SUSPECT"
        print(f"  {mark}  {s['file']}:{s['line']}  {s['const']} = {s['value']}  注释数字={s['comment_numbers']}")
    e_ok, e_msg = gate_e(root)
    print(e_msg)
    print("(f) tokio guard 跨 await 命中（含登记簿放行）：")
    for h in scan_guard_across_await(root):
        key = f"{h['file']}#{h['var']}"
        mark = "REGISTERED" if key in GUARD_ACROSS_AWAIT_REGISTRY else "UNREGISTERED"
        print(f"  {mark}  {h['file']}:{h['line']}  {h['var']}（{h['form']}）")
    f_ok, f_msg = gate_f(root)
    print(f_msg)
    g_ok, g_msg = gate_g(root)
    print(g_msg)
    h_ok, h_msg = gate_h(root)
    print(h_msg)
    for h in scan_spawn_registrations(root):
        print(f"  {h['kind']:22} {h['file']}:{h['line']}")
    return 0 if (a_ok and b_ok and e_ok and f_ok and g_ok and h_ok) else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="je3u3 质量门八件套（失败留痕/抑制登记/登记簿漂移/注释漂移/ignore 理由/锁跨 await/scope 契约/②类 spawn 登记）"
    )
    ap.add_argument("--no-cargo", action="store_true", help="跳过 (c) cargo 面（纯静态快路径）")
    ap.add_argument("--list", action="store_true", help="枚举 (a)(b)(d)(f)(h) 全部命中与分类")
    ap.add_argument("--self-test", action="store_true", help="注入违规自测（八道门各一条）")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = ap.parse_args()
    if args.self_test:
        return cmd_self_test()
    if args.list:
        return cmd_list(args.root)

    results: list[tuple[str, bool, str]] = []
    results.append(("a", *gate_a(args.root)))
    print(results[-1][2])
    results.append(("b", *gate_b(args.root)))
    print(results[-1][2])
    d_gate = gate_d(args.root)
    results.append(("d", *d_gate))
    print(d_gate[1])
    e_gate = gate_e(args.root)
    results.append(("e", *e_gate))
    print(e_gate[1])
    f_gate = gate_f(args.root)
    results.append(("f", *f_gate))
    print(f_gate[1])
    g_gate = gate_g(args.root)
    results.append(("g", *g_gate))
    print(g_gate[1])
    h_gate = gate_h(args.root)
    results.append(("h", *h_gate))
    print(h_gate[1])
    c_gate = gate_c(run_cargo=not args.no_cargo)
    results.append(("c", *c_gate))
    print(c_gate[1])

    failed = [name for name, ok, _ in results if not ok]
    if failed:
        print(f"\n质量门 FAIL：{'/'.join(failed)}")
        return 1
    print(
        "\n质量门 PASS：(a) 失败留痕 / (b) 抑制登记 / (c) 登记簿漂移 / (d) 注释漂移抽查"
        " / (e) ignore 理由 / (f) 锁跨 await / (g) scope 契约 / (h) ②类 spawn 登记"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
