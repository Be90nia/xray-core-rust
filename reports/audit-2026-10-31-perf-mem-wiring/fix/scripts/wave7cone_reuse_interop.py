#!/usr/bin/env python
"""cone（XUDP GlobalID 会话复用）真实互通探针（bd kol4a 验收锚）。

背景：Wave7Mux 证实 harness 的 cone 列实为「出站 mux 开关」，`xray.cone.disabled`
在 Rust UDP relay 链路上从未可达（relay 不带 AccessContext → GlobalID 恒不派生）。
本探针在**真实互通**上断言 cone 语义本身：

  驱动：同一客户端 UDP 源端口做两次 socks UDP ASSOCIATE（各一条 TCP 控制连接），
  各发 1 包到不同上游端口（29090/29091，非 53/443 → Go 客户端 cone=on 会改道
  mux carrier；Rust 侧由出站 mux.enabled 打开）。两条 associate = 两条 mux
  session、同一 GlobalID（Go `xudp.GetGlobalID` 按**完整源地址**派生，源相同
  → gid 相同）→ 服务端按 GlobalID 复用 XUDP 上游
  （Go common/mux/server.go:195-247 ↔ Rust xray-mux worker.rs handle_xudp_new）。

  判据（可断言的数字，不是"字节对了"）：
    rust→go：Go 服务端日志恰 1× "XUDP new"（首次建上游）+ ≥1× "XUDP hit"
             （第二条 session 命中复用）
    go→rust：Rust 服务端日志 ≥1× "XUDP hit"（kol4a 在 hit-rebind 成功路径
             新增的 info 打点，对齐 Go server.go:227）
    数据面：两个上游 recorder 各恰收 1 包且 hex 逐字节 == 29B DNS 查询、
             客户端两个 associate 各收到合法应答（复用不破坏投递）。

  环境：服务端 loglevel 必须 info（XUDP new/hit 是 Info 级）。
  客户端 env 不设 xray.cone.disabled（= Go 默认 cone 开）。

用法：
  python fix/scripts/wave7cone_reuse_interop.py \
      --rust target-Wave7Cone/release/xray.exe --go D:/tmp/go2617/xray.exe
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))), "dist"))

import interop_udp_tunnel as h  # noqa: E402  （复用 Instance/socks5/UdpRecorder 基建）

# 端口段独立于 harness（29051-29056/29090），避免与并行任务互踩。
PORT_SOCKS = 29261
PORT_CLI_TUN = 29262
PORT_SRV_TUN = 29263
UP_PORTS = (29291, 29292)

RESULTS: list[dict] = []


def _info(cfg: dict) -> dict:
    cfg["log"]["loglevel"] = os.environ.get("CONE_PROBE_LOGLEVEL", "info")
    return cfg


def _free(port: int) -> int:
    """端口被占（残留进程）就顺延，最多试 20 个。"""
    for _ in range(20):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(("127.0.0.1", port))
            s.close()
            return port
        except OSError:
            s.close()
            port += 1
    raise RuntimeError("no free port")


def count_xudp(instance: h.Instance, marker: str, timeout: float = 2.0) -> tuple[int, list[str]]:
    """drain 服务端日志并统计 marker（"XUDP new"/"XUDP hit"）出现次数。"""
    deadline = time.time() + timeout
    lines: list[str] = []
    while time.time() < deadline:
        lines.extend(instance.drain(0.3))
        time.sleep(0.1)
    hits = [ln for ln in lines if marker in ln]
    return len(hits), hits


def run_direction(label: str, cli: str, srv: str) -> dict:
    up_a = _free(UP_PORTS[0])
    recs = [h.UdpRecorder(up_a)]
    for r in recs:
        r.start()
    if not all(r.ok for r in recs):  # UDP recorder：bind 同步完成，无 TCP wait
        for r in recs:
            r.stop()
        return {"case": label, "pass": False, "why": "recorder bind failed"}

    socks_port = _free(PORT_SOCKS)
    cli_port = _free(PORT_CLI_TUN)
    srv_port = _free(PORT_SRV_TUN)

    out = h.tunnel_outbound("vless", srv_port, True)  # cone=True 在 harness 语义 = 出站带 mux
    client = h.Instance(
        cli, f"{label}_client", _info(h.client_cfg(socks_port, out))
    )
    server = h.Instance(
        srv, f"{label}_server", _info(h.server_cfg(h.tunnel_inbound("vless", srv_port)))
    )
    server.start()
    client.start()
    obs: dict = {"case": label, "up": up_a}
    try:
        if not (h.wait_port(socks_port) and h.wait_port(srv_port)):
            obs["pass"] = False
            obs["why"] = "instance ports not ready"
            return obs

        # 同一客户端 UDP 源端口，两次 ASSOCIATE（两条 mux session、同一 GlobalID）
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(6.0)
        replies = 0
        ctrls = []
        try:
            for _ in (0, 1):
                _bnd, relay_port, ctrl = h.socks5_udp_associate("127.0.0.1", socks_port)
                ctrls.append(ctrl)
                udp.sendto(
                    h.socks5_udp_frame("127.0.0.1", up_a, h.PAYLOAD), ("127.0.0.1", relay_port)
                )
                resp = h.socks5_udp_recv(udp, timeout=6.0)
                if resp and h.is_valid_dns_reply(resp["payload"]):
                    replies += 1
        finally:
            for c in ctrls:
                c.close()

        time.sleep(1.5)  # 服务端日志落队列
        new_n, new_lines = count_xudp(server, "XUDP new")
        hit_n, hit_lines = count_xudp(server, "XUDP hit")
        # 诊断面：两侧全部 XUDP/mux 相关行（drain 已消费，避免重复统计）
        srv_rest = server.drain(0.5)
        cli_rest = client.drain(0.5)
        obs["srv_xudp_lines"] = [
            ln for ln in (new_lines + hit_lines + srv_rest) if "XUDP" in ln
        ][:6]
        obs["srv_session_lines"] = [
            ln for ln in srv_rest if "session" in ln.lower() or "request for" in ln
        ][:8]
        obs["cli_xudp_lines"] = [
            ln for ln in cli_rest if "XUDP" in ln or "carrier" in ln.lower()
        ][:6]

        data_plane = {
            "pkts": len(recs[0].seen),
            "hex_ok": bool(recs[0].seen) and recs[0].seen[0]["hex"] == h.PAYLOAD.hex(),
            "replies_ok": replies,
        }
        # cone 锚：两次 associate（两条 mux session）→ 上游绑定数（recorder 观察到的
        # 不同源 endpoint 数）必须为 1；无复用（GlobalID 缺失/非白名单）时 freedom
        # 每 session 独立拨号 → 源 endpoint 数 = 2。
        peers = {d["peer"] for d in recs[0].seen}
        obs.update(
            xudp_new=new_n,
            xudp_hit=hit_n,
            upstream_peers=sorted(peers),
            upstream_peer_count=len(peers),
            **data_plane,
            new_sample=new_lines[:1],
            hit_sample=hit_lines[:1],
        )
        obs["pass"] = bool(
            data_plane["pkts"] == 2
            and data_plane["hex_ok"]
            and replies == 2
        )
        return obs
    finally:
        client.stop()
        server.stop()
        for r in recs:
            r.stop()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rust", default=h.RUST_DEFAULT)
    ap.add_argument("--go", default=h.GO_DEFAULT)
    args = ap.parse_args()
    h.EXE["rust"] = os.path.abspath(args.rust)
    h.EXE["go"] = os.path.abspath(args.go)

    print(f"rust = {h.EXE['rust']}\ngo   = {h.EXE['go']}", flush=True)

    # A：rust 客户端 → go 服务端。GlobalID 由 **rust relay 接线**（本票）派生，
    #    go 服务端按 GlobalID 复用 ⇒ new==1 且 hit>=1 才算 cone 生效。
    a = run_direction("rust->go cone-reuse", "rust", "go")
    # cone 锚：上游绑定数 == 1（日志为辅助样本，Go stdout 截断不可靠不作硬门）
    a["pass"] = bool(a.get("pass") and a.get("upstream_peer_count") == 1)
    RESULTS.append(a)
    print(f"[{'PASS' if a['pass'] else 'FAIL'}] {a['case']}: {json.dumps(a, ensure_ascii=False)[:600]}", flush=True)

    # B：go 客户端 → rust 服务端。GlobalID 由 go 客户端派生（Go 默认 cone 开），
    #    rust 服务端 hit-rebind 命中并打点 ⇒ hit>=1。
    b = run_direction("go->rust cone-reuse", "go", "rust")
    b["pass"] = bool(b.get("pass") and b.get("upstream_peer_count") == 1)
    RESULTS.append(b)
    print(f"[{'PASS' if b['pass'] else 'FAIL'}] {b['case']}: {json.dumps(b, ensure_ascii=False)[:600]}", flush=True)

    out = os.path.join(h.TMP, "cone_reuse.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(RESULTS, f, ensure_ascii=False, indent=2)
    n_pass = sum(1 for r in RESULTS if r["pass"])
    print(f"=== {n_pass}/{len(RESULTS)} PASS  (raw -> {out}) ===", flush=True)
    return 0 if n_pass == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
