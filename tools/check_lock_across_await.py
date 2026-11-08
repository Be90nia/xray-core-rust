#!/usr/bin/env python3
"""锁跨 await 静态门（bd auf6h / PM-13）—— 全仓扫「持锁 guard 跨 `.await`」。

为什么自建门：clippy 的 `await_holding_lock` 只认 `std::sync` guard，且只在 guard
绑定于 async 块内时报；本仓大量用 `tokio::sync::Mutex<Receiver>` / `Mutex<Stream>`
作「!Sync 容器 + 独占读写」包装，clippy 完全不看。`parking_lot`/`std` 的 `!Send`
guard 跨 await 在 Send future 里根本编译不过，故本门只收 tokio 面。

扫两种 tokio 形态：
  ① chain `let v = x.lock().await.m().await` —— guard 是临时值，锁一直持有到内层
    await 返回（PM-06 家族：持锁等对端）；
  ② bound `let g = x.lock().await` 后同一块内出现 `.await`（`drop(g)` 之前）；
  ③ temp  `x.lock().await.m().await`（不在 `let` 绑定里）——临时 guard 活到本条语句
    结束（右侧是 `{...}` 块体时活到块尾），中间再 await 就是持锁等对端。

判定边界（宁可少报也不刷屏，逐条登记在登记簿）：
  - `drop(g)` 之后不再计（显式放锁）；
  - 嵌套 `async move {}` / `spawn(..)` 之后不再计（所有权已交给新 task）。
已知盲区（登记，不静默）：`match x.lock().await { .. }` 与 `x.lock().await.f().await`
这类「临时 guard 不在 `let` 绑定里」的形态不覆盖——写这种形态本身就违反本门纪律，
review 面兜。

登记簿（GUARD_ACROSS_AWAIT_REGISTRY）：键 = `f"{文件}#{变量名}"`（按符号锚，不按
行号——行号随树漂移，见 pzjpj）。值前缀两类：
  【accepted】设计性：guard 就是「独占读写 / !Sync 包装 / 单飞 / 启动期一次性」的
             本体，跨 await 不可消除；改窄要么无 API 支持（`&mut` 独占），要么引入
             竞态（单飞失效、多 spawn 一组泵）。
  【debt】    真隐患（持锁等对端 / 跨慢 syscall）：应改窄，逐条写清属主面与改法。

用法：
  python tools/check_lock_across_await.py            # 门（未登记即 exit 1）
  python tools/check_lock_across_await.py --list     # 枚举命中 + 登记分类
  python tools/check_lock_across_await.py --self-test # 临时树注入违规，验门不空转
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

# 复用 d597w 门的基础设施（候选文件 / 注释与字符串剥离 / cfg(test) 剥离 / 行号）
# ——同一套扫描语义，禁在两个门脚本里各养一份 lexer。
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_udp_binds import (  # noqa: E402  (房规工具导入)
    candidate_files,
    line_of,
    strip_cfg_test_blocks,
    strip_comments_and_strings,
)

# tokio 锁绑定形态：`let [mut] v[: T] = <recv>.lock().await`
TOKIO_LOCK_BINDING = re.compile(
    r"let\s+(?:mut\s+)?(?P<var>\w+)\s*(?::[^=;]+)?=\s*(?P<expr>[^;]*?)\.\s*lock\s*\(\s*\)\s*\.await"
)
# 绑定合法收尾：`?` / `unwrap()` / `unwrap_or_else(..)` / `expect(..)` 之后即 `;`。
# 收尾不成立 ⇒ `let` 拿到的不是 guard（guard 是临时，语句末就 drop）——此时另按
# 「链式形态」判：同一语句里还有 `.await` ⇒ 临时 guard 跨 await。
LOCK_BIND_TAIL = re.compile(
    r"\s*(?:\?|\.unwrap\(\)|\.unwrap_or_else\([^;]*\)|\.expect\((?:[^()]|\([^()]*\))*\))*\s*;"
)
# 不透明边界：此后的 `.await` 不属 guard 生命周期（新 task / 新 future 自带所有权）。
OPAQUE_BOUNDARY = re.compile(r"\basync\s+move\b|\basync\s*\{|\bspawn\s*\(|\bspawn_blocking\s*\(")

# 任意 tokio 锁获取（临时 guard 形态用：`x.lock().await.m().await`，不含 `let` 绑定）。
TOKIO_LOCK_ANY = re.compile(r"\.\s*lock\s*\(\s*\)\s*\.await")
RECEIVER_IDENT = re.compile(r"([A-Za-z_]\w*)\s*\.?\s*$")

GUARD_ACROSS_AWAIT_REGISTRY: dict[str, str] = {
    "crates/xray-app-dns/src/nameserver/doh.rs#_gate": (
        "accepted：建连门（并发 A/AAAA 冷启动只建一条连接，门内复查）——持锁跨 "
        "open_session 就是单飞语义本体，一次建连即释放"
    ),
    "crates/xray-app-dns/src/nameserver/udp.rs#slot": (
        "accepted：per-NS 通道槽，持锁跨 UdpChannel::bind 防重复 bind（毫秒级一次性）"
    ),
    "crates/xray-core/src/outbound.rs#guard": (
        "accepted：DNS 上游写半部独占（Mutex<Option<OwnedWriteHalf>>），临界区只有一次 "
        "write_dns_frame().await；拨号/解析已移出锁外（bd pzxvn）"
    ),
    "crates/xray-mux/src/writer.rs#guard": (
        "accepted：carrier 写半部独占（lock 即「单写者」），一次 write_multi_buffer"
    ),
    "crates/xray-proxy-anytls/src/inbound.rs#slot": (
        "accepted：inbound start 一次性（AlreadyStarted 门），持锁跨建服务器是该门本体"
    ),
    "crates/xray-proxy-dokodemo/src/server.rs#guard": (
        "accepted：inbound start 一次性（AlreadyStarted 门）"
    ),
    "crates/xray-proxy-tuic/src/pool.rs#_guard": (
        "accepted：per-key 单飞拨号锁（double-check 后复用池内连接）——持锁跨 dial "
        "正是单飞本体，去掉即重复拨号"
    ),
    "crates/xray-proxy-wireguard/src/driver.rs#_single": (
        "accepted：单飞拨号闸——持锁跨 dialer().await 就是「并发 send 只拨一条」本体"
    ),
    "crates/xray-proxy-wireguard/src/driver.rs#res": (
        "accepted：连接写锁 + 有界写超时（DIALED_WRITE_TIMEOUT），死锁不成立"
    ),
    "crates/xray-transport-grpc/src/encoding.rs#data": (
        "accepted：HunkStream 读写要 &mut，Mutex 即独占读写本体（recv_hunk）"
    ),
    "crates/xray-transport-grpc/src/encoding.rs#stream": (
        "accepted：同上（send_hunk 要 &mut）"
    ),
    "crates/xray-transport-grpc/src/encoding.rs#raw": (
        "accepted：同上（MultiHunk recv_hunk 要 &mut）"
    ),
    "crates/xray-transport-hysteria/src/conn.rs#data": (
        "accepted：Mutex<Receiver> 是 Receiver 非 Sync 的容器，持锁即「独占读」语义"
        "（去掉则多读者语义不成立）"
    ),
    "crates/xray-transport-hysteria/src/udphop.rs#pkt": (
        "accepted：同 conn.rs#data（Mutex<Receiver> 独占读）"
    ),
    "crates/xray-transport-splithttp/src/h3_client.rs#send_req": (
        "accepted：h3 `SendRequest` 建流要 &mut，send_request().await 期间必须持锁；"
        "已在拿到 stream 后立即 drop（PM-13/N7 建议形态）"
    ),
    "crates/xray-transport-websocket/src/ws_bridge.rs#guard": (
        "accepted：per-conn 写锁（心跳 ping 一次 send），锁粒度=一次写"
    ),
    "crates/xray-transport/src/finalmask/realm/conn.rs#guard": (
        "accepted：Mutex<Receiver> 独占读（realm 数据面单读者）"
    ),
    "crates/xray-transport/src/finalmask/xdns/client.rs#pkt": (
        "accepted：Mutex<Receiver> 独占读（xdns 客户端应答取包）"
    ),
    "crates/xray-transport/src/finalmask/xdns/server.rs#pkt": (
        "accepted：Mutex<Receiver> 独占读（xdns 服务端取包）"
    ),
    "crates/xray-transport/src/finalmask/xicmp.rs#sh": (
        "accepted：Mutex<Receiver> 独占读（xicmp 共享收包队列）"
    ),
    "crates/xray-app-proxyman/src/inbound/worker.rs#inbound_rx": (
        "accepted：Mutex<Receiver> 独占读（Go udpConn.Read 单读者语义；持锁即「一次只一个"
        "读者」的排序本体，换 MPMC 会放开并发读打乱单读者语义）"
    ),
    "crates/xray-transport/src/finalmask/udphop.rs#rx": (
        "accepted：Mutex<Receiver> 独占读（udphop 转发泵取包，单读者）"
    ),
    "crates/xray-transport/src/finalmask/xicmp_sock.rs#rx": (
        "accepted：Mutex<Receiver> 独占读（raw ICMP 收包线程 → 单队列，取包必须独占）"
    ),
}


def rel(root: Path, p: Path) -> str:
    return p.relative_to(root).as_posix()


def load_production(root: Path) -> dict[Path, str]:
    """生产面候选文件：crates/*/src/**，排除 udf-frame 与 `#[cfg(test)] mod X;` 挂载的测试支撑文件。"""
    files = candidate_files(root)
    mounted: set[str] = set()
    raw: dict[Path, str] = {}
    for rs in files:
        r = rel(root, rs)
        if r.startswith("crates/udf-frame/") or r.startswith("udf-frame/"):
            continue
        try:
            src = rs.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        raw[rs] = src
        _, mods = strip_cfg_test_blocks(strip_comments_and_strings(src))
        for name in mods:
            mounted.add(rel(root, rs.parent / f"{name}.rs"))
            mounted.add(rel(root, rs.parent / name / "mod.rs"))
    return {rs: src for rs, src in raw.items() if rel(root, rs) not in mounted}


def enclosing_block_end(text: str, pos: int) -> int | None:
    """`pos` 处代码所属最内层 `{...}` 的收口位置（找不到返回 None）。"""
    j = pos - 1
    depth = 0
    while j >= 0:
        if text[j] == "}":
            depth += 1
        elif text[j] == "{":
            if depth == 0:
                break
            depth -= 1
        j -= 1
    if j < 0:
        return None
    depth = 0
    k = j
    while k < len(text):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return k
        k += 1
    return None


def temp_guard_scope(text: str, pos: int) -> int:
    """临时 guard 的作用域终点：depth0 的 `;`（语句末）或块体 `{...}` 的配对 `}`。"""
    i = pos
    depth = 0
    while i < len(text):
        c = text[i]
        if c in "([":
            depth += 1
        elif c in ")]":
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0:
            if c == ";":
                return i
            if c == "{":
                end = enclosing_block_end(text, i + 1)
                return len(text) if end is None else end
            if c == "}":
                return i
        i += 1
    return len(text)


def scan_guard_across_await(root: Path) -> list[dict]:
    """tokio 锁 guard 跨 `.await` 命中（三种形态见模块 doc）。"""
    hits: list[dict] = []
    for rs, src in load_production(root).items():
        cleaned = strip_cfg_test_blocks(strip_comments_and_strings(src))[0]
        r = rel(root, rs)
        bindings = list(TOKIO_LOCK_BINDING.finditer(cleaned))
        for m in bindings:
            var = m.group("var")
            if m.group("expr").strip().startswith("*"):
                continue  # `*lock()` 解引用取值：guard 是临时，语句末 drop
            after = cleaned[m.end():]
            tail = LOCK_BIND_TAIL.match(after)
            if tail is None:
                # 链式形态：同一语句内还有 `.await`
                semi = after.find(";")
                stmt = after[:semi] if semi >= 0 else after
                if ".await" in stmt:
                    hits.append(
                        {"file": r, "line": line_of(cleaned, m.start()), "var": var, "form": "chain"}
                    )
                continue
            block_end = enclosing_block_end(cleaned, m.end())
            if block_end is None:
                continue
            seg = cleaned[m.end() + len(tail.group(0)):block_end]
            drop = re.search(r"\bdrop\s*\(\s*" + re.escape(var) + r"\s*\)", seg)
            if drop is not None:
                seg = seg[:drop.start()]
            opaque = OPAQUE_BOUNDARY.search(seg)
            if opaque is not None:
                seg = seg[:opaque.start()]
            if ".await" in seg:
                hits.append(
                    {"file": r, "line": line_of(cleaned, m.start()), "var": var, "form": "bound"}
                )
        # ③ 临时 guard 形态：`x.lock().await.m().await`（不在上面 `let` 绑定里）
        for m in TOKIO_LOCK_ANY.finditer(cleaned):
            if any(b.start() <= m.start() < b.end() for b in bindings):
                continue  # `let` 绑定形态已由上面判过
            head = RECEIVER_IDENT.search(cleaned[max(0, m.start() - 80):m.start()])
            end = temp_guard_scope(cleaned, m.end())
            seg = cleaned[m.end():end]
            opaque = OPAQUE_BOUNDARY.search(seg)
            if opaque is not None:
                seg = seg[:opaque.start()]
            if ".await" in seg:
                hits.append({
                    "file": r,
                    "line": line_of(cleaned, m.start()),
                    "var": head.group(1) if head else "@temp",
                    "form": "temp",
                })
    return hits


def gate(root: Path, registry: dict[str, str] | None = None) -> tuple[bool, str]:
    """未登记即红；登记簿分 accepted / debt 两档（debt 放行但每次报数）。"""
    registry = GUARD_ACROSS_AWAIT_REGISTRY if registry is None else registry
    hits = scan_guard_across_await(root)
    keys = {f"{h['file']}#{h['var']}" for h in hits}
    unreg = [h for h in hits if f"{h['file']}#{h['var']}" not in registry]
    stale = [k for k in registry if k not in keys]
    lines: list[str] = []
    if stale:
        lines.append(f"WARN (f)：登记簿陈旧条目（命中已消失，可删）：{'; '.join(stale)}")
    if unreg:
        lines.append(
            f"FAIL (f) 锁跨 await 门：未登记的 tokio guard 跨 `.await` {len(unreg)} 处："
        )
        for h in unreg:
            lines.append(f"  {h['file']}:{h['line']}  {h['var']}（{h['form']}）")
        lines.append(
            "    → 改窄（锁内只取/放，或 `drop(guard)` 后再 await）；"
            "确属设计性（独占读写/单飞/!Sync 包装）则登记理由"
        )
        return False, "\n".join(lines)
    debt = [h for h in hits if registry[f"{h['file']}#{h['var']}"].startswith("debt")]
    accepted = len(hits) - len(debt)
    ok = (
        f"OK (f) 锁跨 await 门：tokio guard 跨 await 命中 {len(hits)} 处全部登记"
        f"（accepted {accepted} / debt {len(debt)}）"
    )
    if debt:
        detail = "; ".join(f"{h['file']}:{h['line']} {h['var']}" for h in debt)
        ok += f"\n  debt（待改窄）：{detail}"
    if stale:
        return True, ok + "\n" + "\n".join(lines)
    return True, ok


def cmd_list(root: Path) -> int:
    hits = scan_guard_across_await(root)
    print(f"(f) tokio guard 跨 await 命中（含登记簿放行）{len(hits)} 处：")
    for h in hits:
        key = f"{h['file']}#{h['var']}"
        mark = "REGISTERED" if key in GUARD_ACROSS_AWAIT_REGISTRY else "UNREGISTERED"
        print(f"  {mark}  {h['file']}:{h['line']}  {h['var']}（{h['form']}）")
    ok, msg = gate(root)
    print(msg)
    return 0 if ok else 1


def cmd_self_test() -> int:
    """临时树三用例：chain / bound 必须报，显式 drop 与「块表达式收窄」必须不误报。"""
    ok = True
    with tempfile.TemporaryDirectory(prefix="lockawait-") as td:
        troot = Path(td)
        src = troot / "crates" / "fx" / "src"
        src.mkdir(parents=True)
        fake = "async fn awaitable() {}\n"
        (src / "bad_chain.rs").write_text(
            "async fn f(rx: &M) -> Option<u8> {\n"
            "    let v = rx.lock().await.recv().await;\n"
            "    v\n}\n" + fake,
            encoding="utf-8",
        )
        (src / "bad_bound.rs").write_text(
            "async fn g(m: &M) {\n"
            "    let g = m.lock().await;\n"
            "    awaitable().await;\n"
            "    *g += 1;\n}\n" + fake,
            encoding="utf-8",
        )
        (src / "ok_drop.rs").write_text(
            "async fn h(m: &M) {\n"
            "    let g = m.lock().await;\n"
            "    drop(g);\n"
            "    awaitable().await;\n}\n" + fake,
            encoding="utf-8",
        )
        (src / "ok_scope.rs").write_text(
            "async fn k(m: &M) {\n"
            "    let v = {\n"
            "        let g = m.lock().await;\n"
            "        *g\n"
            "    };\n"
            "    awaitable().await;\n}\n" + fake,
            encoding="utf-8",
        )
        (src / "bad_temp.rs").write_text(
            "async fn recv(&self) -> Option<u8> {\n"
            "    self.rx.lock().await.recv().await\n}\n" + fake,
            encoding="utf-8",
        )
        (src / "ok_temp.rs").write_text(
            "async fn drain(&self) {\n"
            "    let _ = self.rx.lock().await.reserve();\n"
            "    awaitable().await;\n}\n" + fake,
            encoding="utf-8",
        )

        def check(label: str, cond: bool) -> None:
            nonlocal ok
            print(f"  [{'OK' if cond else 'FAIL'}] {label}")
            ok &= cond

        hits = scan_guard_across_await(troot)
        by = {(h["file"], h["form"]) for h in hits}
        check("(f) 链式形态必须报", ("crates/fx/src/bad_chain.rs", "chain") in by)
        check("(f) 绑定形态必须报", ("crates/fx/src/bad_bound.rs", "bound") in by)
        check("(f) 临时 guard 形态必须报", ("crates/fx/src/bad_temp.rs", "temp") in by)
        check("(f) 显式 drop 不误报", not any(f == "crates/fx/src/ok_drop.rs" for f, _ in by))
        check("(f) 块表达式收窄不误报", not any(f == "crates/fx/src/ok_scope.rs" for f, _ in by))
        check("(f) 语句内取放不误报", not any(f == "crates/fx/src/ok_temp.rs" for f, _ in by))
        ok_unreg, msg_unreg = gate(troot, registry={})
        check("(f) 未登记 ⇒ 门必须红", not ok_unreg and "FAIL (f)" in msg_unreg)
        ok_reg, msg_reg = gate(
            troot,
            registry={
                "crates/fx/src/bad_chain.rs#v": "accepted: self-test",
                "crates/fx/src/bad_bound.rs#g": "accepted: self-test",
                "crates/fx/src/bad_temp.rs#rx": "accepted: self-test",
            },
        )
        check("(f) 全部登记 ⇒ 门必须绿", ok_reg and "OK (f)" in msg_reg)
    return 0 if ok else 2


def main() -> int:
    ap = argparse.ArgumentParser(description="锁跨 await 静态门（bd auf6h / PM-13）")
    ap.add_argument("--list", action="store_true", help="枚举全部命中与登记分类")
    ap.add_argument("--self-test", action="store_true", help="临时树注入违规自测")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = ap.parse_args()
    if args.self_test:
        return cmd_self_test()
    if args.list:
        return cmd_list(args.root)
    ok, msg = gate(args.root)
    print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
