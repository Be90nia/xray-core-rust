"""Go/Rust 入站解析器差分对拍床（bd c4ueq，CI 门 harness）。

母本：reports/audit-2026-10-29/tmp/{bed3.py,s2_parser3.py,hzjgv_socks.py}，
按 CI 需要裁剪合并：bed 生命周期收进本文件（跨平台 kill，不再依赖 taskkill/pid 文件），
配置按端口现场生成，单一命令跑完全部用例。

语义：同一原始字节流分别打 Go v26.9.9 与 Rust 的 mixed 入站（HTTP 38 例 + SOCKS5 19 例），
比三维判据：①响应字节（HTTP 侧剥 Date 头）②连接关闭方式（eof）③源站是否真收到转发。

裁决：
  SAME       字节与关闭方式一致（SOCKS 成功帧 BND 按床端口归一，两床端口本就不同）
  ALLOWED    差异命中 ALLOWLIST（已知残留差异，逐条带理由，不得静默绿）
  DIFF       allowlist 外差异 → 打印差异用例表，退出码非零 → CI 红

关闭方式的判据按用例声明（`add(..., eof_judge=...)`）：
  "both"  两侧 eof 都必须一致（默认）
  "rust"  只判 Rust 侧必须在对端观察窗内关闭；Go 侧关闭时刻只记 note——用于关闭时刻
          由 Go 自身策略计时（半关闭宽限窗）决定的用例，见 H38 的注释与
          reports/audit-2026-10-30/ParityFlake.md。

用法：
  python parity.py --go-bin <go-xray> --rust-bin <rust-xray> [--workdir DIR]
                   [--only CASE_ID ...]
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
ORIGIN_PY = os.path.join(BASE, "origin.py")

# 默认端口：本机验证契约 = 127.0.0.1 44xxx 段；CI 无冲突，固定即可复现。
DEF_ORIGIN_PORT = 44801
DEF_GO_PORT = 44811
DEF_RUST_PORT = 44810


# ---------------------------------------------------------------- 用例定义
def step(send, window=2.0, shutdown=False, close_wait=0.0):
    """window = 收响应的主窗；close_wait = 主窗内没等到 EOF 时再等关闭的附加窗。

    close_wait 只用于「字节已在主窗收全、关闭时刻取决于对端计时」的用例（如 H38）：
    Go 参考实现的关闭走半关闭宽限窗（freedom.go:388/427 `SetTimeout` 的
    DownlinkOnly/UplinkOnly），该计时受 runner 负载影响可漂出主窗；把关闭观察
    与字节观察分开，字节判据仍是主窗内的硬断言。
    """
    return {"send": send, "window": window, "shutdown": shutdown, "close_wait": close_wait}


def http(head_bytes, window=2.5, shutdown=False):
    return [step(head_bytes, window, shutdown)]


def head(lines):
    """把请求行 + 头拼成 CRLF 请求（自动补空行）。"""
    return b"".join(l if l.endswith(b"\r\n") else l + b"\r\n" for l in lines) + b"\r\n"


CASES = []


def add(cid, group, summary, steps, eof_judge="both"):
    """eof_judge：'both' = 两侧关闭方式都判（默认）；'rust' = 只判 Rust 侧关闭，
    Go 侧关闭时刻只作旁证记录（用于对端关闭由 Go 内部策略计时决定、负载下无界的用例）。"""
    CASES.append({"id": cid, "group": group, "summary": summary, "steps": steps,
                  "eof_judge": eof_judge})


def build_cases(origin_port):
    """端口参数化地展开 57 例（母本 s2_parser3.py 的用例表，CONNECT 指向源站真端口）。"""
    O = b"127.0.0.1:%d" % origin_port
    DST = bytes([127, 0, 0, 1, origin_port >> 8, origin_port & 0xFF])

    # ------------------------------------------------ HTTP 请求行/头解析 38 例
    add("H01", "基线", "绝对 URI GET /cl（健康检查）",
        http(head([b"GET http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b"Connection: close"])))
    add("H02", "请求行", "缺版本号（两段）",
        http(head([b"GET http://" + O + b"/cl", b"Host: " + O, b"Connection: close"])))
    add("H03", "请求行", "method 与 URI 之间双空格",
        http(head([b"GET  http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b"Connection: close"])))
    add("H04", "请求行", "URI 与版本之间双空格",
        http(head([b"GET http://" + O + b"/cl  HTTP/1.1", b"Host: " + O, b"Connection: close"])))
    add("H05", "请求行", "版本后多一个空格",
        http(head([b"GET http://" + O + b"/cl HTTP/1.1 ", b"Host: " + O, b"Connection: close"])))
    add("H06", "请求行", "URI 含非 ASCII 0xE9",
        http(head([b"GET http://" + O + b"/\xe9 HTTP/1.1", b"Host: " + O, b"Connection: close"])))
    add("H07", "请求行", "超长 method（4096 字节）",
        http(head([b"X" * 4096 + b" http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b"Connection: close"])))
    add("H08", "请求行", "超长 URI（16KB 路径）",
        http(head([b"GET http://" + O + b"/" + b"a" * 16384 + b" HTTP/1.1", b"Host: " + O, b"Connection: close"])))
    add("H09", "请求行", "URI 含控制字符 0x01",
        http(head([b"GET http://" + O + b"/a\x01b HTTP/1.1", b"Host: " + O, b"Connection: close"])))
    add("H10", "请求行", "URI 含 NUL",
        http(head([b"GET http://" + O + b"/a\x00b HTTP/1.1", b"Host: " + O, b"Connection: close"])))
    add("H11", "请求行", "小写 method get",
        http(head([b"get http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b"Connection: close"])))
    add("H12", "请求行", "HTTP/9.9 版本",
        http(head([b"GET http://" + O + b"/cl HTTP/9.9", b"Host: " + O, b"Connection: close"])))
    add("H13", "请求行", "URI 内含空格",
        http(head([b"GET http://" + O + b"/a b HTTP/1.1", b"Host: " + O, b"Connection: close"])))
    add("H14", "头", "重复 Host（两个不同值）",
        http(head([b"GET http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b"Host: example.com", b"Connection: close"])))
    add("H15", "头", "裸 LF 换行（无 CR）",
        http(b"GET http://" + O + b"/cl HTTP/1.1\nHost: " + O + b"\nConnection: close\n\n"))
    add("H16", "头", "header 名含空格 Ho st:",
        http(head([b"GET http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b"Ho st: x", b"Connection: close"])))
    add("H17", "头", "超长 header 行（16KB 值）",
        http(head([b"GET http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b"X-Big: " + b"a" * 16384, b"Connection: close"])))
    add("H18", "头", "200 个 header",
        http(head([b"GET http://" + O + b"/cl HTTP/1.1", b"Host: " + O]
                  + [b"X-H%d: v" % i for i in range(200)] + [b"Connection: close"])))
    add("H19", "头", "header 无冒号",
        http(head([b"GET http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b"BadHeader", b"Connection: close"])))
    add("H20", "头", "header 名为空（: v）",
        http(head([b"GET http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b": v", b"Connection: close"])))
    add("H21", "头", "obs-fold 续行（行首空格）",
        http(head([b"GET http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b"X-Fold: a", b" b", b"Connection: close"])))
    add("H22", "CL/TE", "冲突的重复 Content-Length（5 与 10）",
        http(head([b"POST http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b"Content-Length: 5",
                   b"Content-Length: 10", b"Connection: close"]) + b"0123456789", window=3.0))
    add("H23", "CL/TE", "CL 与 TE:chunked 共存",
        http(head([b"POST http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b"Content-Length: 5",
                   b"Transfer-Encoding: chunked", b"Connection: close"]) + b"5\r\nhello\r\n0\r\n\r\n", window=3.0))
    add("H24", "CL/TE", "TE 非 chunked（gzip）",
        http(head([b"GET http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b"Transfer-Encoding: gzip",
                   b"Connection: close"])))
    add("H25", "CL/TE", "负 Content-Length",
        http(head([b"POST http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b"Content-Length: -5",
                   b"Connection: close"]) + b"hello"))
    add("H26", "CL/TE", "超大 Content-Length（20 位）",
        http(head([b"POST http://" + O + b"/cl HTTP/1.1", b"Host: " + O,
                   b"Content-Length: 99999999999999999999", b"Connection: close"]) + b"hello"))
    add("H27", "CL/TE", "带 + 号的 Content-Length（+5）",
        http(head([b"POST http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b"Content-Length: +5",
                   b"Connection: close"]) + b"hello"))
    add("H28", "CL/TE", "POST CL=5 正常 body（基线）",
        http(head([b"POST http://" + O + b"/cl HTTP/1.1", b"Host: " + O, b"Content-Length: 5",
                   b"Connection: close"]) + b"hello"))
    add("H29", "绝对URI", "绝对 URI 无 Host 头",
        http(head([b"GET http://" + O + b"/cl HTTP/1.1", b"Connection: close"])))
    add("H30", "绝对URI", "绝对 URI 带 userinfo",
        http(head([b"GET http://user:pass@" + O + b"/cl HTTP/1.1", b"Host: " + O, b"Connection: close"])))
    # 无端口 = 默认 80：两侧同回 503，但 Rust freedom 单次失败退避 5×2s，实测
    # 10.8s 才响应（parity-s2-parser.md §4.4）——窗必须 ≥14s，压窗会把 Rust 侧
    # 真响应截成 open 制造假差异。数字 IP 无 DNS，loopback 拒连即回，14s 只是上限。
    add("H31", "绝对URI", "绝对 URI 无端口（默认 80）",
        http(head([b"GET http://127.0.0.1/cl HTTP/1.1", b"Host: 127.0.0.1", b"Connection: close"]), window=14.0))
    add("H32", "绝对URI", "绝对 URI IPv6 字面量 [::1]:源站端口",
        http(head([b"GET http://[::1]:%d/cl HTTP/1.1" % origin_port,
                   b"Host: [::1]:%d" % origin_port, b"Connection: close"]), window=14.0))
    add("H33", "绝对URI", "百分号编码路径穿越 %2e%2e%2f",
        http(head([b"GET http://" + O + b"/a%2e%2e%2fb%2e%2e%2fetc/passwd HTTP/1.1", b"Host: " + O,
                   b"Connection: close"])))
    add("H34", "绝对URI", "字面 .. 路径穿越",
        http(head([b"GET http://" + O + b"/../../etc/passwd HTTP/1.1", b"Host: " + O, b"Connection: close"])))
    add("H35", "截断", "半截请求头后半关闭（无空行）",
        [step(b"GET http://" + O + b"/cl HTTP/1.1\r\nHost: " + O + b"\r\n", 3.0, shutdown=True)])
    add("H36", "截断", "空请求（仅 CRLFCRLF）",
        http(b"\r\n\r\n"))
    add("H37", "截断", "仅裸 CR 分隔（无 LF）",
        http(b"GET http://" + O + b"/cl HTTP/1.1\rHost: " + O + b"\r\r"))
    # H38 关闭时刻**不判两侧相等**（eof_judge="rust"）：
    #   客户端发完 CONNECT 头即半关闭、隧道内零字节。Rust 收到上行 EOF 立即
    #   `shutdown()` 上游写半部（xray-transport/src/bridge.rs 上行收尾），源站读侧
    #   立刻 EOF → 隧道在毫秒级关闭；Go 的 freedom 上行 `buf.Copy` 收尾后不转发 FIN，
    #   改由半关闭宽限窗（Go SessionDefault UplinkOnly/DownlinkOnly=1s，freedom.go:388/427
    #   `SetTimeout` + common/signal ActivityTimer 的 Periodic 计时）在 ~1s 后整体关闭。
    #   于是「关闭快慢」是 Go 侧策略计时差，不是解析器差异，且该计时在 CPU 争用下可漂出
    #   任意时长（实测 2 核绑定 + 负载：3/8 轮 >6s 未关）→ 主窗内比两侧 eof 会在随机 CI
    #   轮次打红（run 40896435024 即 go eof=False@3.003 vs rust eof=True@0.001）。
    #   判据因此改为：字节必须全等（主窗内硬断言）+ **Rust 必须在主窗+close_wait 内关闭**
    #   （防挂死/防泄漏回归，实测 Rust 0.002~0.15s，余量 ~70 倍），Go 侧关闭时刻进旁证。
    add("H38", "截断", "CONNECT 后立即半关闭（无隧道数据）",
        [step(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % (origin_port, origin_port),
              3.0, shutdown=True, close_wait=10.0)], eof_judge="rust")

    # ------------------------------------------------ SOCKS5 握手 19 例
    GREET = step(b"\x05\x01\x00", 1.5)
    CONNECT = b"\x05\x01\x00\x01" + DST

    add("P01", "基线", "noauth + CONNECT 源站 + 隧道内 GET",
        [GREET, step(CONNECT, 1.5), step(b"GET /cl HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", 2.5)])
    add("P02", "greeting", "版本字节 0x06",
        [step(b"\x06\x01\x00", 1.5)])
    add("P03", "greeting", "nmethods=0",
        [step(b"\x05\x00", 1.5)])
    add("P04", "greeting", "仅不支持的 method 0xFF",
        [step(b"\x05\x01\xff", 1.5)])
    add("P05", "greeting", "仅 GSSAPI(0x01)",
        [step(b"\x05\x01\x01", 1.5)])
    add("P06", "greeting", "方法表含 NOAUTH 与 USERPASS（02 00）",
        [step(b"\x05\x02\x02\x00", 1.5)])
    add("P07", "greeting", "truncated greeting（仅 0x05）后半关闭",
        [step(b"\x05", 2.0, shutdown=True)])
    add("P08", "request", "request 版本字节 0x04（应 0x05）",
        [GREET, step(b"\x04\x01\x00\x01" + DST, 1.5)])
    add("P09", "request", "RSV 非 0（0xFF）",
        [GREET, step(b"\x05\x01\xff\x01" + DST, 1.5)])
    add("P10", "request", "CMD=0x00 越界",
        [GREET, step(b"\x05\x00\x00\x01" + DST, 1.5)])
    add("P11", "request", "CMD=0x05 越界",
        [GREET, step(b"\x05\x05\x00\x01" + DST, 1.5)])
    add("P12", "request", "ATYP=0x00 越界",
        [GREET, step(b"\x05\x01\x00\x00" + DST, 1.5)])
    add("P13", "request", "ATYP=0x05 越界",
        [GREET, step(b"\x05\x01\x00\x05" + DST, 1.5)])
    add("P14", "address", "域名长度 0",
        [GREET, step(b"\x05\x01\x00\x03\x00" + DST[-2:], 2.0)])
    add("P15", "address", "域名长度 255（255 字节名，DNS 必败）",
        [GREET, step(b"\x05\x01\x00\x03\xff" + b"a" * 255 + DST[-2:], 8.0)])
    add("P16", "address", "域名含高位字节（\\xff\\xfe\\x80）",
        [GREET, step(b"\x05\x01\x00\x03\x03\xff\xfe\x80" + DST[-2:], 8.0)])
    add("P17", "截断", "request 截断到 VER CMD RSV 后半关闭",
        [GREET, step(b"\x05\x01\x00", 2.0, shutdown=True)])
    add("P18", "截断", "IPv4 地址截断（只给 2 字节）后半关闭",
        [GREET, step(b"\x05\x01\x00\x01\x7f\x00", 2.0, shutdown=True)])
    add("P19", "截断", "缺端口 2 字节后半关闭",
        [GREET, step(b"\x05\x01\x00\x01\x7f\x00\x00\x01", 2.0, shutdown=True)])


# ---------------------------------------------------------------- 已知残留差异 allowlist
# 棘轮纪律：allowlist 只准放「当前树实测仍存在的差异」，allowlist 外任何差异 = 红。
# 修掉对应差异后必须**删除条目**（不得回填）。对照基线：reports/audit-2026-10-29/
# parity-s2-parser.md（对 0dde3359 报了 12 个根因簇 D-1..D-13）；其中 D-1..D-8、
# D-10..D-12 已在 feature/fix-inbound-parity 分支修掉（2026-10-29 对 8db30521
# 本床全量复跑 57 例实证）——若这些用例将来再红，是回归，禁止加回 allowlist。
# 注：P01/P08/P09/P15 的成功帧 BND 伪差由 split_bnd 结构化归一（Go 回监听地址:端口、
# 两床端口本就不同），不进 allowlist；D-9（Rust BND 取值语义）由该归一遮蔽、另行跟踪。
ALLOWLIST = {
    "P02": "D-13 首字节 0x06 分流：Rust 立即断，Go 交 HTTP 解析器挂 60s（bd 记录在案）",
    # P15 结构上已 SAME（BND 归一 + 双侧 8s 窗内关闭）；留条目只兜 DNS/退避时序抖动。
    # 若常态性触发，先查 freedom 退避轮次改动，不要当噪声吞掉。
    "P15": "伪差异（BND+退避时序）；时序兜底防 CI 抖动",
}


# ---------------------------------------------------------------- 探针
def read_until(sock, t0, deadline, rx, send_err):
    """读到 deadline（绝对时刻）或对端 EOF；返回 (rx, eof, eof_at, send_err)。eof_at 自 t0 起算。"""
    while time.time() < deadline:
        sock.settimeout(max(0.05, deadline - time.time()))
        try:
            d = sock.recv(65536)
        except socket.timeout:
            break
        except OSError as e:  # RST 等
            return rx, True, round(time.time() - t0, 3), send_err or repr(e)
        if not d:
            return rx, True, round(time.time() - t0, 3), send_err
        rx += d
    return rx, False, None, send_err


def probe(port, steps):
    """按步骤发字节并收字节；返回 {connect, steps:[{rx_hex, eof, eof_at, ...}]}。"""
    out = {"connect": True, "steps": []}
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3.0)
    except OSError as e:
        return {"connect": False, "error": repr(e), "steps": []}
    try:
        for st in steps:
            t0 = time.time()
            sent, send_err = True, None
            try:
                s.sendall(st["send"])
                if st.get("shutdown"):
                    s.shutdown(socket.SHUT_WR)
            except OSError as e:
                sent, send_err = False, repr(e)
            rx, eof, eof_at, send_err = read_until(s, t0, t0 + st["window"], b"", send_err)
            # 主窗内字节已收全但没等到关闭：按 close_wait 追加观察关闭时刻（语义见 step()）
            if not eof and st.get("close_wait"):
                rx, eof, eof_at, send_err = read_until(
                    s, t0, t0 + st["window"] + st["close_wait"], rx, send_err)
            out["steps"].append({"sent": sent, "send_err": send_err, "rx_hex": rx.hex(),
                                 "rx_len": len(rx), "eof": eof, "eof_at": eof_at,
                                 "open": not eof and not rx,
                                 "elapsed": round(time.time() - t0, 3)})
            if eof:
                break
    finally:
        try:
            s.close()
        except OSError:
            pass
    return out


def norm_http(hexstr):
    """归一：剥 Date 头（随机时间），返回可比较的字符串。"""
    b = bytes.fromhex(hexstr)
    keep = [ln for ln in b.split(b"\r\n") if not ln.lower().startswith(b"date:")]
    return b"\r\n".join(keep).decode("latin-1")


def split_bnd(rx_hex):
    """把 10 字节 SOCKS5 成功回复拆成 (帧头前 4 字节, BND 6 字节)。非成功帧原样返回。

    BND 归一依据（hzjgv_socks.py 母本）：Go 回自己的监听地址:端口、Rust 回 0.0.0.0:0，
    两台服务器端口本就不同——只比帧头与 ATYP，BND 原值记进索引。
    （D-9：Rust 侧 BND 恒零本身是已登记差异，对拍床不做语义判定。）
    """
    b = bytes.fromhex(rx_hex)
    if len(b) == 10 and b[0] == 5 and b[1] == 0:
        return b[:4].hex(), b[4:].hex()
    return rx_hex, ""


def summarize(side_res):
    """把一侧探针结果压成一行摘要（差异用例表用）。"""
    if not side_res["connect"]:
        return "connect-failed"
    parts = []
    for st in side_res["steps"]:
        if st["rx_len"]:
            parts.append("%dB%s" % (st["rx_len"], "+eof" if st["eof"] else ""))
        else:
            parts.append("eof" if st["eof"] else "open")
    return "/".join(parts) or "no-steps"


def compare(case, g, r):
    """返回 (verdict, note)。判据 = 字节（归一后）+ 关闭方式，两维都一致才算 SAME。

    `case["eof_judge"] == "rust"`：只判 Rust 侧关闭（对端关闭时刻由 Go 内部策略计时
    决定的用例，见 CASES 里 H38 的说明）。此时 Go 侧 eof/eof_at 只写进 note 作旁证；
    判定改成「声明了 close_wait 的步骤，Rust 必须在主窗 + close_wait 内关闭」。
    """
    cid, eof_judge = case["id"], case.get("eof_judge", "both")
    if not g["connect"] or not r["connect"]:
        return "DIFF", "connect failed on one side"
    ng, nr = len(g["steps"]), len(r["steps"])
    if ng != nr:
        return "DIFF", f"step count {ng} vs {nr}"
    notes = []
    bnd_notes = []
    close_diff = []
    for i, (a, b) in enumerate(zip(g["steps"], r["steps"]), 1):
        if a["eof"] != b["eof"]:
            if eof_judge == "rust":
                notes.append(f"step{i} 关闭时刻旁证（不判）：go eof={a['eof']}@{a['eof_at']}s "
                             f"rust eof={b['eof']}@{b['eof_at']}s")
            else:
                close_diff.append(f"step{i} 关闭方式不同：go eof={a['eof']} rust eof={b['eof']}")
        if eof_judge == "rust" and not b["eof"] and case["steps"][i - 1].get("close_wait"):
            close_diff.append(f"step{i} rust 未在观察窗内关闭（eof=False）")
        if a["rx_hex"] == b["rx_hex"]:
            continue
        if cid.startswith("H"):
            na, nb = norm_http(a["rx_hex"]), norm_http(b["rx_hex"])
            if na == nb:
                notes.append(f"step{i}: 仅 Date 头不同（已归一）")
                continue
        hg, bnd_g = split_bnd(a["rx_hex"])
        hr, bnd_r = split_bnd(b["rx_hex"])
        if bnd_g and bnd_r:
            if hg != hr:
                return "DIFF", f"step{i} 帧头不同 go={hg} rust={hr}"
            bnd_notes.append(f"step{i} BND 已归一 go={bnd_g} rust={bnd_r}")
            continue
        return "DIFF", f"step{i} 字节不同" + (
            "；" + "；".join(notes + bnd_notes) if notes or bnd_notes else "")
    if close_diff:
        return "DIFF", "；".join(close_diff + notes + bnd_notes)
    tail = "（Go 侧关闭时刻仅记录）" if eof_judge == "rust" else ""
    return "SAME", f"字节全等且关闭方式相同{tail}" + ("（BND 已归一）" if bnd_notes else "")


# ---------------------------------------------------------------- 生命周期
def wait_port(port, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def proxy_cfg(listen_port):
    """mixed 入站 + freedom 出站；finalRules allow 是回环拓扑的 Go 官方逃生门
    （freedom 默认 BlockPrivate 会黑掉 loopback 拨号——dist/interop_matrix.py 先例）。"""
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "in", "protocol": "mixed", "listen": "127.0.0.1", "port": listen_port,
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": False},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom",
                       "settings": {"finalRules": [{"action": "allow"}]}}],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }


def origin_count(logpath):
    try:
        with open(logpath, "rb") as f:
            return f.read().count(b"\n")
    except OSError:
        return 0


# ---------------------------------------------------------------- 主流程
def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--go-bin", required=True)
    ap.add_argument("--rust-bin", required=True)
    ap.add_argument("--origin-port", type=int, default=DEF_ORIGIN_PORT)
    ap.add_argument("--go-port", type=int, default=DEF_GO_PORT)
    ap.add_argument("--rust-port", type=int, default=DEF_RUST_PORT)
    ap.add_argument("--workdir", default=None, help="证据落盘目录（默认 target/parser_parity）")
    ap.add_argument("--only", nargs="*", help="只跑指定 case id（调试用）")
    args = ap.parse_args()

    repo = os.path.abspath(os.path.join(BASE, "..", ".."))
    workdir = os.path.abspath(args.workdir) if args.workdir else os.path.join(repo, "target", "parser_parity")
    os.makedirs(workdir, exist_ok=True)
    origin_log = os.path.join(workdir, "origin-requests.jsonl")

    build_cases(args.origin_port)
    cases = CASES
    if args.only:
        want = set(args.only)
        cases = [c for c in cases if c["id"] in want]

    procs = []
    try:
        # 起三件套：源站 + Go + Rust
        log = open(os.path.join(workdir, "origin.log"), "ab")
        procs.append(subprocess.Popen([sys.executable, ORIGIN_PY, str(args.origin_port), origin_log],
                                      stdout=log, stderr=log))
        if not wait_port(args.origin_port):
            print("FATAL: origin did not listen on %d" % args.origin_port, file=sys.stderr)
            return 2
        for name, binary, port in (("go", args.go_bin, args.go_port),
                                   ("rust", args.rust_bin, args.rust_port)):
            cfgpath = os.path.join(workdir, "cfg-%s.json" % name)
            with open(cfgpath, "w", encoding="utf-8") as f:
                json.dump(proxy_cfg(port), f, indent=1)
            lg = open(os.path.join(workdir, "%s.log" % name), "wb")
            procs.append(subprocess.Popen([binary, "run", "-c", cfgpath], stdout=lg, stderr=lg))
            if not wait_port(port):
                print("FATAL: %s (%s) did not listen on %d；日志 %s"
                      % (name, binary, port, os.path.join(workdir, "%s.log" % name)), file=sys.stderr)
                return 2

        idx = {}
        rows = []
        for case in cases:
            cid = case["id"]
            c0 = origin_count(origin_log)
            g = probe(args.go_port, case["steps"])
            c1 = origin_count(origin_log)
            r = probe(args.rust_port, case["steps"])
            c2 = origin_count(origin_log)
            verdict, note = compare(case, g, r)
            if verdict == "DIFF" and cid in ALLOWLIST:
                verdict, note = "ALLOWED", "allowlist: %s" % ALLOWLIST[cid]
            rec = {"id": cid, "group": case["group"], "summary": case["summary"],
                   "req_hex": b"".join(s["send"] for s in case["steps"]).hex(),
                   "go": g, "rust": r, "verdict": verdict, "note": note,
                   "go_summary": summarize(g), "rust_summary": summarize(r),
                   "origin_fwd": {"go": c1 - c0, "rust": c2 - c1}}
            idx[cid] = rec
            rows.append(rec)
            print(f"{cid} [{verdict:7s}] {case['summary']} | {note} | "
                  f"fwd go={rec['origin_fwd']['go']} rust={rec['origin_fwd']['rust']}")
            for side, res in (("go", g), ("rust", r)):
                rx = b"".join(bytes.fromhex(s["rx_hex"]) for s in res["steps"])
                with open(os.path.join(workdir, f"{cid}.rx-{side}.bin"), "wb") as f:
                    f.write(rx)
            with open(os.path.join(workdir, f"{cid}.req.bin"), "wb") as f:
                f.write(bytes.fromhex(rec["req_hex"]))

        with open(os.path.join(workdir, "index.json"), "w", encoding="utf-8") as f:
            json.dump(idx, f, indent=1, ensure_ascii=False)

        same = sum(1 for x in rows if x["verdict"] == "SAME")
        allowed = [x for x in rows if x["verdict"] == "ALLOWED"]
        diffs = [x for x in rows if x["verdict"] == "DIFF"]
        print(f"\n合计 {len(rows)} 例：SAME {same}，ALLOWED（allowlist 内已知差异）{len(allowed)}，"
              f"DIFF（allowlist 外）{len(diffs)}")

        if diffs:
            print("\n== 差异用例表（allowlist 外，需归因或修码）==")
            for x in diffs:
                print(f"  {x['id']} [{x['group']}] {x['summary']}")
                print(f"      go  : {x['go_summary']}  fwd={x['origin_fwd']['go']}")
                print(f"      rust: {x['rust_summary']}  fwd={x['origin_fwd']['rust']}")
                print(f"      note: {x['note']}")
            return 1
        if allowed:
            print("\n== allowlist 命中（显式已知差异，非静默绿）==")
            for x in allowed:
                print(f"  {x['id']}: {ALLOWLIST[x['id']]}")
        return 0
    finally:
        for p in procs:
            try:
                p.kill()
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
