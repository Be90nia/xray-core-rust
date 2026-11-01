#!/usr/bin/env python
"""一次性诊断：TCP 裸代理抓 vless carrier 字节，解析 mux New 帧的 GlobalID。

拓扑：probe → client(rust, socks+mux out) → [tap 29270 → server 29263] → go/rust server。
输出：client→server 方向每个 mux New 帧的 (session_id, status, target, global_id)。
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(_HERE))))
sys.path.insert(0, os.path.join(_ROOT, "dist"))
sys.path.insert(0, _ROOT)

import interop_udp_tunnel as h  # noqa: E402

TAP_PORT = 29270


def main() -> int:
    rust = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.abspath(
        "target-Wave7Cone/release/xray.exe"
    )
    go = r"D:\tmp\go2617\xray.exe"
    h.EXE["rust"] = rust
    h.EXE["go"] = go

    up, up2 = 29291, 29292
    recs = [h.UdpRecorder(up), h.UdpRecorder(up2)]
    for r in recs:
        r.start()
    socks_port, cli_port, srv_port = 29361, 29362, 29363

    # tap：TCP 转发 + 抓 client→server 字节
    captured = bytearray()
    cap_lock = threading.Lock()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", TAP_PORT))
    srv.listen(1)

    def pump(src: socket.socket, dst: socket.socket, is_up: bool) -> None:
        while True:
            try:
                data = src.recv(65535)
            except OSError:
                break
            if not data:
                break
            if is_up:
                with cap_lock:
                    captured.extend(data)
            try:
                dst.sendall(data)
            except OSError:
                break
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def acceptor() -> None:
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            u = socket.create_connection(("127.0.0.1", srv_port))
            threading.Thread(target=pump, args=(c, u, True), daemon=True).start()
            threading.Thread(target=pump, args=(u, c, False), daemon=True).start()

    threading.Thread(target=acceptor, daemon=True).start()

    out = h.tunnel_outbound("vless", TAP_PORT, True)  # 客户端连 tap
    client = h.Instance("rust", "diag_client", h.client_cfg(socks_port, out))
    server = h.Instance("go", "diag_server", h.server_cfg(h.tunnel_inbound("vless", srv_port)))
    server.start()
    client.start()
    try:
        assert h.wait_port(socks_port) and h.wait_port(srv_port) and h.wait_port(TAP_PORT)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 0))
        ctrls = []
        for tgt in (up, up2):  # 两条 associate（同一 UDP 源端口），两个目标
            _bnd, rport, ctrl = h.socks5_udp_associate("127.0.0.1", socks_port)
            ctrls.append(ctrl)
            udp.sendto(h.socks5_udp_frame("127.0.0.1", tgt, h.PAYLOAD), ("127.0.0.1", rport))
            time.sleep(0.4)
        time.sleep(1.5)
        time.sleep(2.0)
        print("recorder seen:", [len(r.seen) for r in recs])
        lines = server.drain(2.0)
        print(f"server total lines: {len(lines)}")
        for ln in lines:
            print("SRV:", ln.strip()[:170])
        for c in ctrls:
            c.close()
    finally:
        client.stop()
        server.stop()
        for r in recs:
            r.stop()

    # vless 明文承载：[ver(1)][uuid(16)][addons_len(1)][addons][cmd(1)][port(2)][atyp(1)][addr]…
    # 之后才是 mux carrier 字节流 → 暴力找合法帧链起点（meta_len∈[4,512] 且 status∈{1,2,4}）
    with cap_lock:
        buf = bytes(captured)
    off = None
    for start in (33, *range(20, min(60, len(buf)))):
        p, ok = start, True
        for _ in range(2):  # 预检：能连续解出两帧才算对齐
            if p + 2 > len(buf):
                ok = False
                break
            ml = int.from_bytes(buf[p : p + 2], "big")
            if not (4 <= ml <= 512) or p + 2 + ml > len(buf) or buf[p + 4] not in (1, 2, 4):
                ok = False
                break
            cur = p + 2 + ml
            if buf[p + 5] & 1:
                if cur + 2 > len(buf):
                    ok = False
                    break
                cur += 2 + int.from_bytes(buf[cur : cur + 2], "big")
            p = cur
        if ok:
            off = start
            break
    idx = 0
    print(f"captured {len(buf)} bytes uplink; frame-chain start offset = {off}")
    if off is None:
        print(f"head hex: {buf.hex()}")
        return 0
    while off + 2 <= len(buf) and idx < 12:
        meta_len = int.from_bytes(buf[off : off + 2], "big")
        if not (4 <= meta_len <= 512) or off + 2 + meta_len > len(buf):
            print(f"[stop] bad meta_len {meta_len} at {off}")
            break
        meta = buf[off + 2 : off + 2 + meta_len]
        session_id = int.from_bytes(meta[0:2], "big")
        status = meta[2]
        opt = meta[3]
        names = {1: "New", 2: "Keep", 4: "KeepAlive"}
        has_data = opt & 1
        cur = off + 2 + meta_len
        data_len = -1
        if has_data and cur + 2 <= len(buf):
            data_len = int.from_bytes(buf[cur : cur + 2], "big")
            cur += 2
        # New+UDP 帧的 GlobalID 在地址段之后（固定偏移不可靠，扫 meta 里是否含 gid 尾部）
        print(
            f"frame#{idx} off={off} session={session_id} status={names.get(status, status)} "
            f"opt={opt} meta_len={meta_len} data_len={data_len} meta_hex={meta.hex()}"
        )
        off = cur + (data_len if data_len >= 0 else 0)
        idx += 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
