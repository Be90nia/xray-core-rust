"""UDP 面差分：socks5 UDP ASSOCIATE / dokodemo UDP / 源地址透传 / 分片 / 零长 / 空闲超时。

每条用例两侧各起一个实例跑同一份字节，比可观测行为。
"""
import json
import socket
import struct
import sys
import time

from mocksrv import (PORTS, Instance, UdpEcho, socks5_udp_associate, socks5_udp_frame,
                     socks5_udp_recv, wait_port)

RESULTS = []


def record(case, side, obs, verdict_note=""):
    RESULTS.append({"case": case, "side": side, "obs": obs, "note": verdict_note})


def socks_cfg(side, port):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }


def dokodemo_cfg(side, port, dst_port):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "dok-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": dst_port, "network": "udp"}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }


# ───────────────────────── 用例 ─────────────────────────
def case_socks_udp_echo(side):
    """U1 socks5 UDP ASSOCIATE：payload 原样回显 + 目标看到的源地址。"""
    echo = UdpEcho(PORTS["echo"])
    echo.start()
    port = PORTS[f"{side}_socks"]
    inst = Instance(side, "socks_udp", socks_cfg(side, port)).start()
    try:
        if not wait_port(port, tcp=True):
            record("U1_socks_udp_echo", side, {"error": "no listen"})
            return
        bnd, bport, ctrl, rep = socks5_udp_associate("127.0.0.1", port)
        payload = b"hello-udp-0123456789"
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(3.0)
        u.sendto(socks5_udp_frame("127.0.0.1", PORTS["echo"], payload),
                 (bnd, bport))
        got = socks5_udp_recv(u, 3.0)
        time.sleep(0.4)
        obs = {
            "associate_rep": rep,
            "bnd": f"{bnd}:{bport}",
            "reply": (got or {}).get("payload", b"").decode("latin-1", "replace"),
            "reply_src": (got or {}).get("src"),
            "reply_frag": (got or {}).get("frag"),
            "echo_seen_count": len(echo.seen),
            "echo_peer": (echo.seen[0][0], echo.seen[0][1]) if echo.seen else None,
            "echo_payload": echo.seen[0][2] if echo.seen else None,
        }
        u.close()
        ctrl.close()
        record("U1_socks_udp_echo", side, obs)
    finally:
        inst.stop()
        echo.stop()


def case_socks_udp_zero_len(side):
    """U2 socks5 UDP：零长度 payload。"""
    echo = UdpEcho(PORTS["echo"])
    echo.start()
    port = PORTS[f"{side}_socks"]
    inst = Instance(side, "socks_udp", socks_cfg(side, port)).start()
    try:
        if not wait_port(port, tcp=True):
            record("U2_socks_udp_zero_len", side, {"error": "no listen"})
            return
        bnd, bport, ctrl, _ = socks5_udp_associate("127.0.0.1", port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(3.0)
        u.sendto(socks5_udp_frame("127.0.0.1", PORTS["echo"], b""), (bnd, bport))
        got = socks5_udp_recv(u, 3.0)
        time.sleep(0.4)
        record("U2_socks_udp_zero_len", side, {
            "reply_present": got is not None,
            "reply_len": len(got["payload"]) if got else None,
            "echo_seen_count": len(echo.seen),
            "echo_payload_len": len(echo.seen[0][2]) // 2 if echo.seen else None,
        })
        u.close()
        ctrl.close()
    finally:
        inst.stop()
        echo.stop()


def case_socks_udp_large(side):
    """U3 socks5 UDP：2000 字节大包（超 MTU）。"""
    echo = UdpEcho(PORTS["echo"])
    echo.start()
    port = PORTS[f"{side}_socks"]
    inst = Instance(side, "socks_udp", socks_cfg(side, port)).start()
    try:
        if not wait_port(port, tcp=True):
            record("U3_socks_udp_large", side, {"error": "no listen"})
            return
        bnd, bport, ctrl, _ = socks5_udp_associate("127.0.0.1", port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(3.0)
        payload = bytes(range(256)) * 8  # 2048 字节
        u.sendto(socks5_udp_frame("127.0.0.1", PORTS["echo"], payload), (bnd, bport))
        got = socks5_udp_recv(u, 3.0)
        time.sleep(0.4)
        record("U3_socks_udp_large", side, {
            "sent_len": len(payload),
            "reply_len": len(got["payload"]) if got else None,
            "reply_matches": (got["payload"] == payload) if got else None,
            "echo_seen_count": len(echo.seen),
            "echo_len": len(echo.seen[0][2]) // 2 if echo.seen else None,
        })
        u.close()
        ctrl.close()
    finally:
        inst.stop()
        echo.stop()


def case_socks_udp_frag(side):
    """U4 socks5 UDP：FRAG != 0 的帧应被丢弃（Go 不支持分片）。"""
    echo = UdpEcho(PORTS["echo"])
    echo.start()
    port = PORTS[f"{side}_socks"]
    inst = Instance(side, "socks_udp", socks_cfg(side, port)).start()
    try:
        if not wait_port(port, tcp=True):
            record("U4_socks_udp_frag", side, {"error": "no listen"})
            return
        bnd, bport, ctrl, _ = socks5_udp_associate("127.0.0.1", port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(2.0)
        u.sendto(socks5_udp_frame("127.0.0.1", PORTS["echo"], b"fragmented", frag=1),
                 (bnd, bport))
        got = socks5_udp_recv(u, 2.0)
        time.sleep(0.4)
        logs = inst.drain(0.6)
        record("U4_socks_udp_frag", side, {
            "reply_present": got is not None,
            "echo_seen_count": len(echo.seen),
            "log_frag_mentions": [l for l in logs if "frag" in l.lower()][:3],
        })
        u.close()
        ctrl.close()
    finally:
        inst.stop()
        echo.stop()


def case_dokodemo_udp(side):
    """U5 dokodemo-door UDP：payload 回显 + 源地址。"""
    echo = UdpEcho(PORTS["echo"])
    echo.start()
    port = PORTS[f"{side}_dok"]
    inst = Instance(side, "dok_udp", dokodemo_cfg(side, port, PORTS["echo"])).start()
    try:
        if not wait_port(port):
            record("U5_dokodemo_udp", side, {"error": "no listen"})
            return
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(3.0)
        u.sendto(b"dok-udp-payload", ("127.0.0.1", port))
        try:
            data, _ = u.recvfrom(65535)
        except socket.timeout:
            data = None
        except ConnectionResetError as e:
            # Windows：ICMP port unreachable → WSAECONNRESET
            record("U5_dokodemo_udp", side, {"error": f"ConnectionReset: {e}",
                                              "echo_seen_count": len(echo.seen)})
            data = None
        time.sleep(0.4)
        record("U5_dokodemo_udp", side, {
            "reply": data.decode("latin-1", "replace") if data else None,
            "echo_seen_count": len(echo.seen),
            "echo_peer": (echo.seen[0][0], echo.seen[0][1]) if echo.seen else None,
        })
        u.close()
    finally:
        inst.stop()
        echo.stop()


def case_socks_udp_multi(side):
    """U6 socks5 UDP：连续 3 个数据报（会话保持 + 顺序）。"""
    echo = UdpEcho(PORTS["echo"])
    echo.start()
    port = PORTS[f"{side}_socks"]
    inst = Instance(side, "socks_udp", socks_cfg(side, port)).start()
    try:
        if not wait_port(port, tcp=True):
            record("U6_socks_udp_multi", side, {"error": "no listen"})
            return
        bnd, bport, ctrl, _ = socks5_udp_associate("127.0.0.1", port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(3.0)
        replies = []
        for i in range(3):
            u.sendto(socks5_udp_frame("127.0.0.1", PORTS["echo"], f"pkt{i}".encode()),
                     (bnd, bport))
            g = socks5_udp_recv(u, 2.0)
            replies.append(g["payload"].decode() if g else None)
        time.sleep(0.4)
        record("U6_socks_udp_multi", side, {
            "replies": replies,
            "echo_seen_count": len(echo.seen),
        })
        u.close()
        ctrl.close()
    finally:
        inst.stop()
        echo.stop()


def case_socks_udp_unknown_dest(side):
    """U7 socks5 UDP：目标端口无人监听 → 行为。"""
    port = PORTS[f"{side}_socks"]
    inst = Instance(side, "socks_udp", socks_cfg(side, port)).start()
    try:
        if not wait_port(port, tcp=True):
            record("U7_socks_udp_unknown_dest", side, {"error": "no listen"})
            return
        bnd, bport, ctrl, _ = socks5_udp_associate("127.0.0.1", port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(2.0)
        u.sendto(socks5_udp_frame("127.0.0.1", 28099, b"nobody"), (bnd, bport))
        got = socks5_udp_recv(u, 2.0)
        time.sleep(0.6)
        logs = inst.drain(0.6)
        record("U7_socks_udp_unknown_dest", side, {
            "reply_present": got is not None,
            "alive": inst.alive(),
            "log_tail": [l for l in logs if "refus" in l.lower() or "error" in l.lower()
                         or "fail" in l.lower()][:4],
        })
        u.close()
        ctrl.close()
    finally:
        inst.stop()


def case_socks_udp_idle(side):
    """U8 socks5 UDP：ctrl 连接关闭后数据报是否仍被转发（会话收割）。"""
    echo = UdpEcho(PORTS["echo"])
    echo.start()
    port = PORTS[f"{side}_socks"]
    inst = Instance(side, "socks_udp", socks_cfg(side, port)).start()
    try:
        if not wait_port(port, tcp=True):
            record("U8_socks_udp_idle_close", side, {"error": "no listen"})
            return
        bnd, bport, ctrl, _ = socks5_udp_associate("127.0.0.1", port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(2.0)
        u.sendto(socks5_udp_frame("127.0.0.1", PORTS["echo"], b"before-close"),
                 (bnd, bport))
        g1 = socks5_udp_recv(u, 2.0)
        ctrl.close()          # 关闭关联 TCP
        time.sleep(1.0)
        before = len(echo.seen)
        u.sendto(socks5_udp_frame("127.0.0.1", PORTS["echo"], b"after-close"),
                 (bnd, bport))
        g2 = socks5_udp_recv(u, 2.0)
        time.sleep(0.5)
        record("U8_socks_udp_idle_close", side, {
            "first_reply": g1["payload"].decode() if g1 else None,
            "after_close_reply": g2["payload"].decode() if g2 else None,
            "echo_count_before": before,
            "echo_count_after": len(echo.seen),
        })
        u.close()
    finally:
        inst.stop()
        echo.stop()


CASES = [
    ("U1_socks_udp_echo", case_socks_udp_echo),
    ("U2_socks_udp_zero_len", case_socks_udp_zero_len),
    ("U3_socks_udp_large", case_socks_udp_large),
    ("U4_socks_udp_frag", case_socks_udp_frag),
    ("U5_dokodemo_udp", case_dokodemo_udp),
    ("U6_socks_udp_multi", case_socks_udp_multi),
    ("U7_socks_udp_unknown_dest", case_socks_udp_unknown_dest),
    ("U8_socks_udp_idle_close", case_socks_udp_idle),
]


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for name, fn in CASES:
        if only and only != name:
            continue
        for side in ("go", "rust"):
            fn(side)
            print(f"[done] {name} {side}", flush=True)
    out = PORTS and f"udp_results_{only}.json" if only else "udp_results.json"
    path = f"D:/Project/Xray-core-rust/reports/audit-2026-10-31-perf-mem-wiring/round4/tmp/{out}"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(RESULTS, f, indent=2, ensure_ascii=False)
    print("results ->", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
