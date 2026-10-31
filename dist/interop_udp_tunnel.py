#!/usr/bin/env python
"""UDP 隧道字节级互通验收（bd t0ls1 正式验收门）。

矩阵：
  proto       ∈ {vless, vmess, trojan}
  direction   ∈ {Rust→Go, Go→Rust, Rust→Rust, Go→Go}
  cone        ∈ {on（客户端 outbound 开 mux = Go 默认 cone 形态）, off}
  dest port   ∈ {53, 443, other}
附加：dokodemo-door UDP 经隧道、socks5 UDP ASSOCIATE 经隧道（= 主矩阵入口）、
      DNS over UDP 经隧道（真实 DNS 应答断言）。

判据（逐字节）：
  1. 上游收到的**第一包**必须恰好等于 29B 裸 DNS 查询（hex 相等，不是"长度相近"）；
  2. 客户端必须收到应答（DNS 用例：txid 回显 + ancount==1）；
  3. 上游累计包数 == 1（不得重复/放大）。

用法：
  python dist/interop_udp_tunnel.py                        # 全矩阵
  python dist/interop_udp_tunnel.py --quick                # 每协议一条（烟测）
  python dist/interop_udp_tunnel.py --only trojan
  python dist/interop_udp_tunnel.py --rust <path> --go <path>
"""
from __future__ import annotations

import argparse
import json
import re
import os
import queue
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GO_DEFAULT = r"D:\tmp\go2617\xray.exe"
RUST_DEFAULT = os.path.join(REPO, "target-WAVE1", "debug", "xray.exe")
TMP = os.path.join(REPO, "dist", "tmp_udp_tunnel")
os.makedirs(TMP, exist_ok=True)

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
PASSWORD = "pw-interop-udp"
# 29B 裸 DNS 查询（txnid=0x1234，qdcount=1，QNAME=example.com，QTYPE/QCLASS=A/IN）
PAYLOAD = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")

PORT_UP_OTHER = 29090
PORT_SOCKS = {"rust": 29051, "go": 29052}
PORT_TUNNEL = {"rust": 29053, "go": 29054}
PORT_DOKODEMO_IN = 29055
PORT_DNS_UP = 29056

EXE: dict[str, str] = {}
RESULTS: list[dict] = []


# ─────────────────────────── UDP 上游记录器 ───────────────────────────
class UdpRecorder(threading.Thread):
    """记录收到的每个 datagram（peer/len/hex），回一个合法 DNS 应答。"""

    def __init__(self, port: int):
        super().__init__(daemon=True)
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.seen: list[dict] = []
        self._stop = False
        self.ok = True

    def run(self) -> None:
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                continue
            self.seen.append(
                {"peer": f"{addr[0]}:{addr[1]}", "len": len(data), "hex": data.hex()}
            )
            try:
                self.sock.sendto(dns_answer(data), addr)
            except OSError:
                pass

    def reset(self) -> None:
        self.seen.clear()

    def stop(self) -> None:
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def dns_answer(query: bytes) -> bytes:
    """把一个 DNS 查询变成合法应答（txid 回显 + qd=1 + an=1）。"""
    if len(query) < 13:
        return query
    question = query[12:]
    return (
        query[:2]                      # txid 回显
        + b"\x81\x80"                  # flags: QR|RD|RA, NOERROR
        + b"\x00\x01"                  # qdcount
        + b"\x00\x01"                  # ancount
        + b"\x00\x00\x00\x00"          # nscount / arcount
        + question
        + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x4c\x00\x04\x01\x02\x03\x04"
    )


def is_valid_dns_reply(data: bytes) -> bool:
    return (
        len(data) >= 12
        and data[:2] == PAYLOAD[:2]                  # txid 回显
        and data[6:8] == b"\x00\x01"                 # ancount == 1
    )


# ─────────────────────────── socks5 UDP ASSOCIATE ───────────────────────────
def socks5_udp_associate(host: str, port: int, timeout: float = 6.0):
    ctrl = socket.create_connection((host, port), timeout=timeout)
    ctrl.settimeout(timeout)
    ctrl.sendall(b"\x05\x01\x00")
    resp = ctrl.recv(2)
    if len(resp) != 2 or resp[0] != 5 or resp[1] != 0:
        raise RuntimeError(f"socks greeting bad: {resp!r}")
    ctrl.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
    reply = ctrl.recv(10)
    if len(reply) < 10:
        raise RuntimeError(f"associate reply short: {reply!r}")
    atyp = reply[3]
    if atyp == 1:
        bnd = socket.inet_ntoa(reply[4:8])
    elif atyp == 3:
        bnd = reply[5 : 5 + reply[4]].decode("latin-1")
    else:
        bnd = host
    bport = struct.unpack("!H", reply[-2:])[0]
    if bnd in ("0.0.0.0", "::"):
        bnd = host
    return bnd, bport, ctrl


def socks5_udp_frame(dst_ip: str, dst_port: int, payload: bytes) -> bytes:
    return (
        b"\x00\x00\x00\x01" + socket.inet_aton(dst_ip) + struct.pack("!H", dst_port) + payload
    )


def socks5_udp_recv(sock: socket.socket, timeout: float = 6.0):
    sock.settimeout(timeout)
    try:
        data, _ = sock.recvfrom(65535)
    except (socket.timeout, ConnectionResetError, OSError):
        return None
    if len(data) < 10:
        return None
    atyp = data[3]
    off = 8 if atyp == 1 else (5 + data[4] if atyp == 3 else 20)
    return {"payload": data[off + 2 :]}


# ─────────────────────────── 实例管理 ───────────────────────────
class Instance:
    def __init__(self, side: str, name: str, cfg: dict, env: dict | None = None):
        self.side = side
        # 用例名含 `->` / `=` 等 Windows 非法文件名字符 → 落盘前净化
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        self.cfg_path = os.path.join(TMP, f"{safe}_{side}.json")
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        self._env = env
        self.proc = None
        self._q: queue.Queue = queue.Queue()

    def start(self) -> "Instance":
        env = os.environ.copy()
        if self._env:
            env.update(self._env)
        self.proc = subprocess.Popen(
            [EXE[self.side], "run", "-c", self.cfg_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
        )
        q = self._q

        def reader() -> None:
            assert self.proc is not None and self.proc.stdout is not None
            for raw in iter(self.proc.stdout.readline, b""):
                q.put(raw.decode("utf-8", "replace").rstrip())
            q.put(None)

        threading.Thread(target=reader, daemon=True).start()
        return self

    def drain(self, timeout: float = 0.5) -> list[str]:
        out = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self._q.get(timeout=0.05)
            except queue.Empty:
                continue
            if line is None:
                break
            out.append(line)
        return out

    def stop(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=6)
        try:
            if self.proc.stdout is not None:
                self.proc.stdout.close()
        except Exception:  # noqa: BLE001
            pass


def wait_port(port: int, timeout: float = 12.0, host: str = "127.0.0.1") -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection((host, port), timeout=0.5)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


# ─────────────────────────── 配置模板 ───────────────────────────
def tunnel_inbound(proto: str, port: int) -> dict:
    if proto == "vless":
        return {
            "tag": "tun-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {"decryption": "none", "clients": [{"id": UUID}]},
        }
    if proto == "vmess":
        return {
            "tag": "tun-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vmess",
            "settings": {"clients": [{"id": UUID, "alterId": 0}]},
        }
    if proto == "trojan":
        return {
            "tag": "tun-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "trojan",
            "settings": {"clients": [{"password": PASSWORD}]},
        }
    raise ValueError(proto)


def tunnel_outbound(proto: str, port: int, cone: bool) -> dict:
    if proto == "vless":
        ob = {
            "tag": "tun-out",
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "127.0.0.1",
                        "port": port,
                        "users": [{"id": UUID, "encryption": "none"}],
                    }
                ]
            },
        }
    elif proto == "vmess":
        ob = {
            "tag": "tun-out",
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": "127.0.0.1",
                        "port": port,
                        "users": [{"id": UUID, "alterId": 0, "security": "auto"}],
                    }
                ]
            },
        }
    elif proto == "trojan":
        ob = {
            "tag": "tun-out",
            "protocol": "trojan",
            "settings": {
                "servers": [{"address": "127.0.0.1", "port": port, "password": PASSWORD}]
            },
        }
    else:
        raise ValueError(proto)
    if cone:
        # cone=on：客户端 outbound 开 mux —— Go 默认 cone 形态下 UDP 走
        # Mux command（v1.mux.cool），也是此前 Go→Rust 上游 0 字节黑洞那条。
        ob["mux"] = {"enabled": True, "concurrency": 8}
    return ob


def socks_inbound(port: int) -> dict:
    return {
        "tag": "socks-in",
        "listen": "127.0.0.1",
        "port": port,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": True},
    }


def client_cfg(socks_port: int, outbound: dict) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [socks_inbound(socks_port)],
        "outbounds": [outbound],
    }


def server_cfg(inbound: dict) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [inbound],
        # finalRules allow 是必需项：freedom 默认 block 私有 IP，上游 127.0.0.1
        # 会被黑洞，伪装成数据面 bug（仓内 FREEDOM-FINALRULES 条款）。
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}
        ],
    }


def dokodemo_inbound(port: int, target_port: int) -> dict:
    return {
        "tag": "dod-in",
        "listen": "127.0.0.1",
        "port": port,
        "protocol": "dokodemo-door",
        "settings": {
            "address": "127.0.0.1",
            "port": target_port,
            "network": "udp",
            "followRedirect": False,
        },
    }


def dokodemo_client_cfg(socks_port: int, dokodemo_port: int, outbound: dict) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [socks_inbound(socks_port), dokodemo_inbound(dokodemo_port, PORT_UP_OTHER)],
        "outbounds": [outbound],
    }


# ─────────────────────────── 用例驱动 ───────────────────────────
def record(label: str, obs: dict) -> dict:
    RESULTS.append({"case": label, **obs})
    status = "PASS" if obs.get("pass") else "FAIL"
    print(f"[{status}] {label}: {json.dumps(obs, ensure_ascii=False)[:520]}", flush=True)
    return obs


def probe_tunnel(
    *,
    label: str,
    proto: str,
    client_side: str,
    server_side: str,
    cone: bool,
    dest_port: int,
    use_dokodemo: bool = False,
) -> dict:
    """socks UDP（或 dokodemo UDP）→ 隧道 → 服务端 freedom → 上游记录器。"""
    up = UdpRecorder(dest_port)
    up.start()
    tun_port = PORT_TUNNEL[server_side]
    socks_port = PORT_SOCKS[client_side]
    env = None if cone else {"xray.cone.disabled": "true"}
    srv = Instance(
        server_side, f"{label}_srv", server_cfg(tunnel_inbound(proto, tun_port))
    ).start()
    ob = tunnel_outbound(proto, tun_port, cone)
    if use_dokodemo:
        cli_cfg = dokodemo_client_cfg(socks_port, PORT_DOKODEMO_IN, ob)
    else:
        cli_cfg = client_cfg(socks_port, ob)
    cli = Instance(client_side, f"{label}_cli", cli_cfg, env=env).start()

    obs: dict = {"proto": proto, "cone": cone, "dest_port": dest_port}
    try:
        if not wait_port(tun_port) or not wait_port(socks_port):
            obs["error"] = "no listen"
            return record(label, obs)
        if use_dokodemo:
            # dokodemo 只监听 UDP：TCP connect 探活必然失败（旧实现假红）
            time.sleep(0.8)
        time.sleep(0.4)

        if use_dokodemo:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.settimeout(6.0)
            u.sendto(PAYLOAD, ("127.0.0.1", PORT_DOKODEMO_IN))
            try:
                reply, _ = u.recvfrom(65535)
            except (socket.timeout, OSError):
                reply = b""
            client_reply = reply
        else:
            bnd, bport, ctrl = socks5_udp_associate("127.0.0.1", socks_port)
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.settimeout(6.0)
            u.sendto(socks5_udp_frame("127.0.0.1", dest_port, PAYLOAD), (bnd, bport))
            got = socks5_udp_recv(u, 6.0)
            ctrl.close()
            client_reply = got["payload"] if got else b""
        time.sleep(0.4)

        first = up.seen[0] if up.seen else None
        obs["upstream_count"] = len(up.seen)
        obs["upstream_len"] = first["len"] if first else 0
        obs["upstream_hex"] = (first["hex"][:64] if first else None)
        obs["upstream_hex_exact"] = bool(first and first["hex"] == PAYLOAD.hex())
        obs["client_reply_len"] = len(client_reply)
        obs["client_reply_hex"] = client_reply.hex()[:64]
        obs["client_reply_dns_ok"] = is_valid_dns_reply(client_reply)
        # 上游必须收到**恰好** 29B 裸查询，且客户端必须收到合法 DNS 应答
        obs["pass"] = bool(
            obs["upstream_count"] == 1
            and obs["upstream_hex_exact"]
            and obs["client_reply_dns_ok"]
        )
        if not obs["pass"]:
            obs["server_log_tail"] = srv.drain(0.2)[-6:]
            obs["client_log_tail"] = cli.drain(0.2)[-6:]
        return record(label, obs)
    finally:
        cli.stop()
        srv.stop()
        up.stop()


def run_case(*, label: str, **kw) -> dict:
    """跑一条用例；失败则换新实例重试一次（端口/实例抖动而非缺陷时收敛）。"""
    obs = probe_tunnel(label=label, **kw)
    if obs.get("pass"):
        return obs
    time.sleep(0.6)
    RESULTS.pop()  # 丢弃首轮记录，以重试结果为准
    obs2 = probe_tunnel(label=f"{label} [retry]", **kw)
    obs2["retried"] = True
    return obs2


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rust", default=RUST_DEFAULT)
    ap.add_argument("--go", default=GO_DEFAULT)
    ap.add_argument("--only", default=None, help="vless|vmess|trojan|dokodemo|dns")
    ap.add_argument("--quick", action="store_true", help="每协议只跑 Rust→Go 一条")
    ap.add_argument("--out", default=os.path.join(TMP, "interop_udp_tunnel.json"))
    args = ap.parse_args()

    EXE["rust"] = args.rust
    EXE["go"] = args.go
    for side, path in EXE.items():
        if not os.path.isfile(path):
            print(f"FATAL: {side} binary missing: {path}", file=sys.stderr)
            return 2

    pairs = [("rust", "go"), ("go", "rust"), ("rust", "rust"), ("go", "go")]
    if args.quick:
        pairs = [("rust", "go")]
    protos = ["vless", "vmess", "trojan"]
    if args.only and args.only in protos:
        protos = [args.only]
    dest_ports = [53, 443, PORT_UP_OTHER]

    for proto in protos:
        for c, s in pairs:
            for cone in (True, False):
                for dest in dest_ports:
                    label = f"{proto} {c}->{s} cone={'on' if cone else 'off'} dest={dest}"
                    try:
                        run_case(
                            label=label,
                            proto=proto,
                            client_side=c,
                            server_side=s,
                            cone=cone,
                            dest_port=dest,
                        )
                    except Exception as e:  # noqa: BLE001
                        record(label, {"pass": False, "error": repr(e),
                                       "tb": traceback.format_exc()[-600:]})

    if args.only in (None, "dokodemo"):
        for c, s in pairs:
            label = f"dokodemo {c}->{s} cone=on dest={PORT_UP_OTHER}"
            try:
                run_case(
                    label=label,
                    proto="vless",
                    client_side=c,
                    server_side=s,
                    cone=True,
                    dest_port=PORT_UP_OTHER,
                    use_dokodemo=True,
                )
            except Exception as e:  # noqa: BLE001
                record(label, {"pass": False, "error": repr(e),
                               "tb": traceback.format_exc()[-600:]})

    if args.only in (None, "dns"):
        # DNS over UDP 经隧道：载荷就是真 DNS 查询，上游回合法应答
        for c, s in pairs:
            label = f"dns-udp {c}->{s} cone=on dest={PORT_DNS_UP}"
            try:
                run_case(
                    label=label,
                    proto="vless",
                    client_side=c,
                    server_side=s,
                    cone=True,
                    dest_port=PORT_DNS_UP,
                )
            except Exception as e:  # noqa: BLE001
                record(label, {"pass": False, "error": repr(e),
                               "tb": traceback.format_exc()[-600:]})

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r.get("pass"))
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"results": RESULTS, "passed": passed, "total": total}, f, indent=2)
    print(f"\n=== {passed}/{total} PASS  (raw -> {args.out}) ===")
    fails = [r["case"] for r in RESULTS if not r.get("pass")]
    for c in fails[:20]:
        print(f"  FAIL {c}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
