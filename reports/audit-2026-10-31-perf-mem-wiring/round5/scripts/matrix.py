"""传输 × 方向矩阵执行器：载荷完整性（64KB 双向）+ wire 落盘。

用法：
    python matrix.py            # 全部用例
    python matrix.py kcp ws     # 只跑指定用例
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wire as W  # noqa: E402

UP = 65536
DOWN = 65536


def run_case(name: str, srv_stream: dict, cli_stream: dict, wire_udp: bool = False,
             mux: dict | None = None, base: int = 28300, nconns: int = 1) -> dict:
    """一个方向：binary_srv 做服务端 + binary_cli 做客户端。"""
    ports = W.PORTS.block(base)
    listen, relay_p, socks_p = ports
    echo = W.Echo(name)   # 载荷面恒 TCP（KCP 只是承载为 UDP）
    rec = None
    srv = cli = None
    out = {"case": name, "ok": False, "err": "", "wire": "", "detail": ""}
    try:
        rec = (W.UdpRec(listen, name, relay_p) if wire_udp
               else W.TcpRec(listen, name, relay_p))
        srv = W.Proc(W.SRV_BIN, W.server_cfg(listen, srv_stream), name + ".srv")
        # 就绪探测走服务端真实监听口（UDP 口不能 TCP 探，改为进程存活 + 等固定窗）
        if wire_udp:
            time.sleep(1.2)
            if srv.p.poll() is not None:
                out["err"] = "服务端启动即退出"
                out["detail"] = srv.read_log()[-600:].replace("\n", " | ")
                return out
        elif not W.wait_port(listen, timeout=25):
            out["err"] = "服务端未就绪"
            out["detail"] = srv.read_log()[-600:].replace("\n", " | ")
            return out
        cli = W.Proc(W.CLI_BIN, W.client_cfg(socks_p, rec.port, cli_stream, mux), name + ".cli")
        if not W.wait_port(socks_p, timeout=25):
            out["err"] = "socks 未就绪"
            out["detail"] = "srv_log_tail=" + srv.read_log()[-600:].replace("\n", " | ")
            return out

        # 每条子流用不同 seed 的载荷：串流（cross-talk）必然被判不一致
        size = UP if nconns == 1 else UP // 2
        dsize = DOWN if nconns == 1 else DOWN // 2
        ups = [W.payload(size, 7 + k) for k in range(nconns)]
        downs = [W.payload(dsize, 11 + k) for k in range(nconns)]
        # echo 回写的必须是同一个 up；down 方向用「服务端主动下发」不可行，
        # 故用第二次写入不同 seed 判定下行是否独立完整。
        t0 = time.time()
        socks = [W.socks5_connect(socks_p, "127.0.0.1", echo.port) for _ in range(nconns)]
        try:
            # 全部先写（制造并发子流），再逐条读回
            for k, s in enumerate(socks):
                W.send_all(s, ups[k])
            for k, s in enumerate(socks):
                got = W.recv_exact(s, len(ups[k]))
                if got != ups[k]:
                    first = next((i for i in range(min(len(got), len(ups[k])))
                                  if got[i] != ups[k][i]), -1)
                    out["err"] = f"conn{k} 上行往返不一致（首差 {first}）"
            for k, s in enumerate(socks):
                W.send_all(s, downs[k])
            for k, s in enumerate(socks):
                got2 = W.recv_exact(s, len(downs[k]))
                if got2 != downs[k]:
                    first = next((i for i in range(min(len(got2), len(downs[k])))
                                  if got2[i] != downs[k][i]), -1)
                    out["err"] += f"；conn{k} 第二段往返不一致（首差 {first}）"
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass
        dt = time.time() - t0

        # 等 echo 记账落定
        end = time.time() + 6
        while time.time() < end:
            with echo.lock:
                if echo.conns:
                    break
            time.sleep(0.05)

        with echo.lock:
            recs = [dict(r) for r in echo.conns]
        rx_total = sum(r["rx"] for r in recs)
        want = sum(len(u) + len(d) for u, d in zip(ups, downs))
        out["detail"] = (f"echoconns={len(recs)} echorx_total={rx_total} "
                         f"echoshas={sorted({r['rx_sha'][:8] for r in recs})}")
        if rx_total < want:
            out["err"] += f"；echo 收到字节不足 {rx_total}<{want}"

        dumped = rec.dump()
        p1 = dumped[0] if dumped else ""
        if wire_udp:
            out["wire"] = f"up={len(rec.up)}pkt down={len(rec.down)}pkt {p1}"
        else:
            per = " ".join(f"[{len(t['c2s'])}/{len(t['s2c'])}]" for t in rec.transcripts)
            out["wire"] = f"conns={rec.conns} per_conn(c2s/s2c)={per}"
        out["ok"] = not out["err"]
        out["dt"] = round(dt, 3)
        return out
    except Exception as e:  # noqa: BLE001 —— 审计脚本：一律记为失败并继续
        out["err"] = f"{type(e).__name__}: {e}"
        return out
    finally:
        for o in (cli, srv):
            if o:
                o.close()
        if rec:
            rec.close()
        echo.close()
        time.sleep(0.3)


def run_dir(name: str, srv_bin: str, cli_bin: str, **kw) -> dict:
    W.SRV_BIN = srv_bin
    W.CLI_BIN = cli_bin
    return run_case(name, **kw)


# ------------------------------------------------------------------ 各传输配置

NONE = "none"


def ws_ed_stream(ed: int, host: str = "localhost", path: str = "/ws") -> dict:
    return {"network": "websocket", "security": NONE,
            "wsSettings": {"path": path, "host": host, "ed": ed}}


def ws_stream(host: str = "localhost", path: str = "/ws") -> dict:
    return {"network": "websocket", "security": NONE,
            "wsSettings": {"path": path, "host": host}}


def hu_stream(path: str = "/hu") -> dict:
    return {"network": "httpupgrade", "security": NONE,
            "httpupgradeSettings": {"path": path, "host": "localhost"}}


def xh_stream(mode: str, path: str = "/xh") -> dict:
    return {"network": "splithttp", "security": NONE,
            "splithttpSettings": {"path": path, "host": "localhost", "mode": mode}}


def grpc_stream(svc: str = "GunService") -> dict:
    return {"network": "grpc", "security": NONE,
            "grpcSettings": {"serviceName": svc}}


def kcp_stream(**over) -> dict:
    s = {"mtu": 1350, "tti": 20, "uplinkCapacity": 100, "downlinkCapacity": 100,
         "congestion": False, "readBufferSize": 2, "writeBufferSize": 2,
         "header": {"type": "none"}, "seed": ""}
    s.update(over)
    return {"network": "kcp", "security": NONE, "kcpSettings": s}


def tcp_stream() -> dict:
    return {"network": "tcp", "security": NONE}


CASES = [
    # name, kind(udp?), server_stream, client_stream, mux
    ("tcp-control", False, tcp_stream(), tcp_stream(), None),
    ("tcp-multi4", False, tcp_stream(), tcp_stream(), None, 4),
    ("ws", False, ws_stream(), ws_stream(), None),
    ("ws-ed", False, ws_ed_stream(2048), ws_ed_stream(2048), None),
    ("ws-ed-big", False, ws_ed_stream(8192), ws_ed_stream(8192), None),
    ("ws-multi4", False, ws_stream(), ws_stream(), None, 4),
    ("ws-ed-path", False, ws_stream(path="/ws?ed=2048"), ws_stream(path="/ws?ed=2048"), None),
    ("ws-ed-path-q", False, ws_stream(path="/ws?ed=1024&x=1"),
     ws_stream(path="/ws?ed=1024&x=1"), None),
    ("httpupgrade", False, hu_stream(), hu_stream(), None),
    ("grpc", False, grpc_stream(), grpc_stream(), None),
    ("kcp", True, kcp_stream(), kcp_stream(), None),
    ("kcp-seed", True, kcp_stream(seed="audit-seed"), kcp_stream(seed="audit-seed"), None),
    ("xh-packet-up", False, xh_stream("packet-up"), xh_stream("packet-up"), None),
    ("xh-stream-up", False, xh_stream("stream-up"), xh_stream("stream-up"), None),
    ("xh-stream-one", False, xh_stream("stream-one"), xh_stream("stream-one"), None),
    ("xh-auto", False, xh_stream("auto"), xh_stream("auto"), None),
    ("mux8", False, tcp_stream(), tcp_stream(), {"enabled": True, "concurrency": 8}),
    ("mux-h2mux", False, tcp_stream(), tcp_stream(),
     {"enabled": True, "concurrency": 8, "xudpConcurrency": 8, "xudpProxyUDP443": "reject"}),
    ("mux-multi4", False, tcp_stream(), tcp_stream(),
     {"enabled": True, "concurrency": 8}, 4),
    ("mux-c1", False, tcp_stream(), tcp_stream(), {"enabled": True, "concurrency": 1}, 2),
]


def main(argv: list[str]) -> int:
    name_filters = [a for a in argv[1:] if not a.startswith("only-")]
    dir_filters = [a[5:] for a in argv[1:] if a.startswith("only-")]
    results = []
    for case in CASES:
        name, udp, ss, cs, mux = case[:5]
        nconns = case[5] if len(case) > 5 else 1
        if name_filters and not any(w in name for w in name_filters):
            continue
        for tag, sb, cb, base in (("R2G", W.GO, W.RUST, 28300),
                                  ("G2R", W.RUST, W.GO, 28400),
                                  ("R2R", W.RUST, W.RUST, 28400),
                                  ("G2G", W.GO, W.GO, 28300)):
            if dir_filters and tag not in dir_filters:
                continue
            t0 = time.time()
            r = run_dir(f"{tag}-{name}", sb, cb, srv_stream=ss, cli_stream=cs,
                        wire_udp=udp, mux=mux, base=base, nconns=nconns)
            r["tag"] = tag
            r["wall"] = round(time.time() - t0, 1)
            results.append(r)
            print(f"{r['case']:<28} {'PASS' if r['ok'] else 'FAIL'} "
                  f"{r['wire']} {r['detail']} {r['err']}"[:300], flush=True)
    ok = sum(1 for r in results if r["ok"])
    print(f"\n=== {ok}/{len(results)} PASS ===")
    with open(os.path.join(W.WORK, "matrix-result.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=1, ensure_ascii=False)
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    os.makedirs(W.WORK, exist_ok=True)
    sys.exit(main(sys.argv))
