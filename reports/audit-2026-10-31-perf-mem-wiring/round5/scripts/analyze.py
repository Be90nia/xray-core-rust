"""抓包结构解析：把录制字节还原成「帧头账本」，用于两侧对比。

子命令（args: <verb> <file...>）：
  kcp   <up.bin> [down.bin]    KCP 段解析（conv/cmd/opt/sn/una/len + 残留字节）
  ws    <c2s.bin> <s2c.bin>    HTTP upgrade 头 + WS 帧头
  http  <c2s.bin> <s2c.bin>    HTTP/1.1 请求行/头 + body 分块边界
  h2    <c2s.bin> <s2c.bin>    HTTP/2 帧头 + SETTINGS + HEADERS 原文
  mux   <c2s.bin>              VLESS 请求头 + mux 帧头
所有输出为 `key=value` 行，便于直接 diff。
"""
from __future__ import annotations

import struct
import sys


def records(path: str) -> list[bytes]:
    """读 UdpRec 落盘格式（2B BE 长度 + 原文）。"""
    out = []
    with open(path, "rb") as f:
        d = f.read()
    off = 0
    while off + 2 <= len(d):
        n = struct.unpack(">H", d[off:off + 2])[0]
        off += 2
        out.append(d[off:off + n])
        off += n
    return out


def read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# ------------------------------------------------------------------ KCP

def kcp_segments(data: bytes) -> tuple[list[dict], int]:
    segs: list[dict] = []
    off = 0
    n = len(data)
    while off + 4 <= n:
        conv, cmd, opt = struct.unpack(">HBB", data[off:off + 4])
        off += 4
        if cmd == 1:  # data
            if off + 14 > n:
                off = n
                break
            ts, sn, una, ln = struct.unpack(">IIIH", data[off:off + 14])
            off += 14
            pl = data[off:off + ln]
            off += ln
            if len(pl) < ln:
                off = n
                break
            segs.append({"cmd": 1, "conv": conv, "opt": opt, "ts": ts, "sn": sn,
                         "una": una, "len": ln, "payload": pl, "head": pl[:16].hex()})
        elif cmd == 0:  # ack
            if off + 13 > n:
                off = n
                break
            win, una, ts = struct.unpack(">III", data[off:off + 12])
            off += 12
            cnt = data[off]
            off += 1
            if off + 4 * cnt > n:
                off = n
                break
            nums = list(struct.unpack(">" + "I" * cnt, data[off:off + 4 * cnt]))
            off += 4 * cnt
            segs.append({"cmd": 0, "conv": conv, "opt": opt, "win": win,
                         "una": una, "ts": ts, "cnt": cnt, "nums": nums[:6]})
        else:
            if off + 12 > n:
                off = n
                break
            sn, rn, rto = struct.unpack(">III", data[off:off + 12])
            off += 12
            segs.append({"cmd": cmd, "conv": conv, "opt": opt, "sn": sn, "rn": rn, "rto": rto})
        if off > n:
            break
    return segs, n - off


def cmd_kcp(paths: list[str]) -> None:
    for p in paths:
        pkts = records(p)
        segs: list[dict] = []
        leftover = 0
        for d in pkts:
            s, left = kcp_segments(d)
            segs += s
            leftover += left
        data_segs = [s for s in segs if s["cmd"] == 1]
        acks = [s for s in segs if s["cmd"] == 0]
        convs = sorted({s["conv"] for s in segs})
        sns = sorted({s["sn"] for s in data_segs})
        print(f"# {p}")
        print(f"packets={len(pkts)} pkt_lens={sorted({len(d) for d in pkts})}")
        print(f"segments={len(segs)} data={len(data_segs)} ack={len(acks)} "
              f"other={len(segs) - len(data_segs) - len(acks)}")
        print(f"convs={convs} opt_vals={sorted({s['opt'] for s in segs})} "
              f"cmds={sorted({s['cmd'] for s in segs})}")
        print(f"leftover_bytes={leftover}")
        print(f"payload_total={sum(s['len'] for s in data_segs)} "
              f"uniq_sn={len(sns)} sn_range={sns[0] if sns else '-'}..{sns[-1] if sns else '-'}")
        if data_segs:
            print(f"first_data={data_segs[0]}")
            print(f"last_data={data_segs[-1]}")
        if acks:
            print(f"first_ack={acks[0]}")
            print(f"ack_cnt_hist={sorted({a['cnt'] for a in acks})}")


# ------------------------------------------------------------------ HTTP 层

def take_headers(data: bytes) -> tuple[list[str], int]:
    """切出头部文本块；返回 (行列表, 头结束偏移)。"""
    idx = data.find(b"\r\n\r\n")
    if idx < 0:
        return [], 0
    head = data[:idx].decode("latin-1")
    return head.split("\r\n"), idx + 4


def cmd_ws(c2s: str, s2c: str) -> None:
    up = read(c2s)
    down = read(s2c)
    lines, off = take_headers(up)
    print("# c2s 请求行/头")
    for ln in lines:
        print("  " + ln)
    print(f"orig_path_full={lines[0] if lines else '-'}")
    # 余下是 WS 帧
    frames = ws_frames(up[off:])
    print(f"c2s_ws_frames={len(frames)} opcodes={sorted({f['op'] for f in frames})} "
          f"masked={sorted({f['mask'] for f in frames})} "
          f"lens={sorted({f['len'] for f in frames})[:12]}")
    print(f"c2s_ws_leftover={frames[-1]['leftover'] if frames else 0}")
    dl, doff = take_headers(down)
    print("# s2c 状态行/头")
    for ln in dl:
        print("  " + ln)
    dfr = ws_frames(down[doff:])
    print(f"s2c_ws_frames={len(dfr)} opcodes={sorted({f['op'] for f in dfr})} "
          f"masked={sorted({f['mask'] for f in dfr})} lens={sorted({f['len'] for f in dfr})[:12]}")


def ws_frames(d: bytes) -> list[dict]:
    out = []
    off = 0
    while off + 2 <= len(d):
        b0, b1 = d[off], d[off + 1]
        fin = b0 >> 7
        op = b0 & 0x0F
        masked = b1 >> 7
        ln = b1 & 0x7F
        off += 2
        if ln == 126:
            if off + 2 > len(d):
                break
            ln = struct.unpack(">H", d[off:off + 2])[0]
            off += 2
        elif ln == 127:
            if off + 8 > len(d):
                break
            ln = struct.unpack(">Q", d[off:off + 8])[0]
            off += 8
        off += 4 if masked else 0
        off += ln
        out.append({"fin": fin, "op": op, "mask": masked, "len": ln,
                    "leftover": max(0, off - len(d))})
        if off > len(d):
            break
    return out


def cmd_http(c2s: str, s2c: str) -> None:
    up = read(c2s)
    down = read(s2c)
    print("# c2s 全部请求（按 CRLFCRLF 切）")
    for ln in scan_requests(up):
        print("  " + ln)
    print("# s2c 全部响应/请求（按 CRLFCRLF 切）")
    for ln in scan_requests(down):
        print("  " + ln)


def scan_requests(d: bytes) -> list[str]:
    """粗切：把每个头部块的首行 + 关键头 + 紧随 body 的长度列出。"""
    out = []
    off = 0
    while True:
        idx = d.find(b"\r\n\r\n", off)
        if idx < 0:
            break
        head = d[off:idx].decode("latin-1").split("\r\n")
        first = head[0]
        hdrs = {h.split(":", 1)[0].lower(): h.split(":", 1)[1].strip()
                for h in head[1:] if ":" in h}
        start = idx + 4
        body_len = 0
        if hdrs.get("transfer-encoding", "").lower() == "chunked":
            body_len, nchunks, tail = scan_chunked(d, start)
            out.append(f"{first} | te=chunked chunks={nchunks} chunk_lens={tail[:8]} "
                       f"bodylen={body_len} hdrs={sorted(hdrs)}")
            off = start + chunked_span(d, start)
        elif "content-length" in hdrs:
            body_len = int(hdrs["content-length"] or 0)
            out.append(f"{first} | cl={body_len} hdrs={sorted(hdrs)}")
            off = start + body_len
        else:
            out.append(f"{first} | no-body-marker hdrs={sorted(hdrs)}")
            off = start
        if off >= len(d):
            break
    return out


def scan_chunked(d: bytes, off: int) -> tuple[int, int, list[int]]:
    total = 0
    lens = []
    n = 0
    while off < len(d):
        e = d.find(b"\r\n", off)
        if e < 0:
            break
        try:
            sz = int(d[off:e].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            break
        off = e + 2
        if sz == 0:
            n += 1
            break
        lens.append(sz)
        total += sz
        n += 1
        off += sz + 2
    return total, n, lens


def chunked_span(d: bytes, off: int) -> int:
    start = off
    while off < len(d):
        e = d.find(b"\r\n", off)
        if e < 0:
            return len(d) - start
        try:
            sz = int(d[off:e].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return len(d) - start
        off = e + 2
        if sz == 0:
            return off - start
        off += sz + 2
    return len(d) - start


# ------------------------------------------------------------------ HTTP/2

H2_NAMES = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST", 4: "SETTINGS",
            5: "PUSH", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION"}


def cmd_h2(c2s: str, s2c: str) -> None:
    for tag, p in (("c2s", c2s), ("s2c", s2c)):
        d = read(p)
        print(f"# {tag} 前缀={d[:24]!r}")
        off = 24 if d.startswith(b"PRI * HTTP/2.0") else 0
        hist: dict[str, int] = {}
        settings: list[str] = []
        heads: list[str] = []
        while off + 9 <= len(d):
            ln = int.from_bytes(d[off:off + 3], "big")
            typ = d[off + 3]
            flags = d[off + 4]
            sid = int.from_bytes(d[off + 5:off + 9], "big") & 0x7FFFFFFF
            body = d[off + 9:off + 9 + ln]
            off += 9 + ln
            name = H2_NAMES.get(typ, f"?{typ}")
            hist[name] = hist.get(name, 0) + 1
            if typ == 4 and not (flags & 1):
                o = 0
                while o + 6 <= len(body):
                    k = struct.unpack(">H", body[o:o + 2])[0]
                    v = int.from_bytes(body[o + 2:o + 6], "big")
                    settings.append(f"{k}={v}")
                    o += 6
            elif typ in (1, 9):
                printable = "".join(chr(c) if 32 <= c < 127 else "." for c in body)
                heads.append(f"sid={sid} fl={flags} len={ln} {printable[:180]}")
        print(f"{tag}_frames={hist}")
        print(f"{tag}_settings={settings}")
        for h in heads[:8]:
            print(f"{tag}_hdrs {h}")


# ------------------------------------------------------------------ mux

def cmd_mux(c2s: str) -> None:
    d = read(c2s)
    # VLESS 请求头: ver(1) uuid(16) addonlen(1) addon cmd(1) port(2) atyp(1) addr
    if len(d) < 20:
        print("too-short")
        return
    ver = d[0]
    addon_len = d[17]
    cmd = d[18 + addon_len]
    port = struct.unpack(">H", d[19 + addon_len:21 + addon_len])[0]
    atyp = d[21 + addon_len]
    addr_off = 22 + addon_len
    if atyp == 1:
        addr = ".".join(str(b) for b in d[addr_off:addr_off + 4])
        body_off = addr_off + 4
    elif atyp == 2:
        addr = ".".join(str(b) for b in d[addr_off:addr_off + 16])
        body_off = addr_off + 16
    elif atyp == 3:
        n = d[addr_off]
        addr = d[addr_off + 1:addr_off + 1 + n].decode("latin-1")
        body_off = addr_off + 1 + n
    else:
        addr = f"?atyp={atyp}"
        body_off = addr_off
    print(f"vless ver={ver} addon_len={addon_len} cmd={cmd} port={port} atyp={atyp} addr={addr}")
    print(f"body_off={body_off} total={len(d)}")
    body = d[body_off:]
    if body:
        # mux 帧头: metadata(NewWriter: sessionID u16, status u8, option u8, network u8, port u16, atyp u8, addr)
        print(f"mux_body_head={body[:48].hex()}")
        if len(body) >= 7:
            sid, status, option, network = struct.unpack(">HBBB", body[:5])
            print(f"mux session={sid} status={status} option={option} network={network}")


def kcp_stream(path: str) -> bytes:
    """按 sn 升序重组 data segment 载荷（KCP 保序，sn 单调）。"""
    pkts = records(path)
    segs: list[dict] = []
    for d in pkts:
        s, _ = kcp_segments(d)
        segs += [x for x in s if x["cmd"] == 1]
    segs.sort(key=lambda x: x["sn"])
    return b"".join(s["payload"] for s in segs)


def cmd_kcpdiff(a: str, b: str) -> None:
    x = kcp_stream(a)
    y = kcp_stream(b)
    print(f"a={a} len={len(x)}  b={b} len={len(y)}")
    print(f"a[:48]={x[:48].hex()}")
    print(f"b[:48]={y[:48].hex()}")
    n = min(len(x), len(y))
    first = next((i for i in range(n) if x[i] != y[i]), -1)
    print(f"first_diff_off={first} identical_prefix={first if first >= 0 else n}")
    if first >= 0:
        print(f"a_at={x[max(0, first - 8):first + 24].hex()}")
        print(f"b_at={y[max(0, first - 8):first + 24].hex()}")


if __name__ == "__main__":
    verb = sys.argv[1]
    args = sys.argv[2:]
    if verb == "kcp":
        cmd_kcp(args)
    elif verb == "ws":
        cmd_ws(args[0], args[1])
    elif verb == "http":
        cmd_http(args[0], args[1])
    elif verb == "h2":
        cmd_h2(args[0], args[1])
    elif verb == "kcpdiff":
        cmd_kcpdiff(args[0], args[1])
    elif verb == "mux":
        cmd_mux(args[0])
    else:
        raise SystemExit("unknown verb " + verb)
