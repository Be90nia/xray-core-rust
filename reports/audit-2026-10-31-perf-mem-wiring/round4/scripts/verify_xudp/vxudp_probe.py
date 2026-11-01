"""VerifyXudp 独立复核 harness（Windows 本地）。

目标：独立复现「Rust 隧道端点的 UDP 载荷裹 XUDP 帧」断言，并测绘影响面。

拓扑（每用例两个 xray 实例 + 一个 python UDP 上游记录器）：

  客户端实例: socks inbound(udp=true) -> <隧道协议> outbound -> 服务端
  服务端实例: <隧道协议> inbound -> freedom outbound -> python UDP 上游记录器

判据：
  1. python UDP 上游收到的 payload 十六进制 + 长度（决定性字节证据）
  2. socks 客户端是否收到回包（往返是否成立）
  3. 控制组：socks -> freedom 直连（不经隧道）→ 上游应收到裸 payload

端口段 28200-28249（避开他人 28050-28099）。
"""
import json
import os
import queue
import socket
import struct
import subprocess
import sys
import threading
import time

GO = r"D:\tmp\go2617\xray.exe"
RUST = r"D:\Project\Xray-core-rust\target\release\xray.exe"
TMP = r"D:\Project\Xray-core-rust\reports\audit-2026-10-31-perf-mem-wiring\round4\tmp\verify_xudp"
os.makedirs(TMP, exist_ok=True)

SIDE_EXE = {"go": GO, "rust": RUST}
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
PASSWORD = "pw-verify-xudp"

# 端口段 28200-28249
PORT_UPSTREAM = 28210        # python UDP 上游记录器
PORT_SOCKS = {"rust": 28211, "go": 28212}
PORT_TUNNEL = {"rust": 28213, "go": 28214}


# ────────────────────────── UDP 上游记录器 ──────────────────────────
class UdpRecorder(threading.Thread):
    """UDP 上游：记录收到的 (peer, payload hex)，原样回显。"""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.seen = []
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.seen.append({"peer": f"{addr[0]}:{addr[1]}", "len": len(data),
                              "hex": data.hex()})
            try:
                self.sock.sendto(data, addr)
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


# ────────────────────────── socks5 UDP 客户端 ──────────────────────────
def socks5_udp_associate(host, port, timeout=5.0):
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
        ln = reply[4]
        bnd = reply[5:5 + ln].decode("latin-1")
    else:
        bnd = host
    bport = struct.unpack("!H", reply[-2:])[0]
    if bnd in ("0.0.0.0", "::"):
        bnd = host
    return bnd, bport, ctrl


def socks5_udp_frame(dst_ip, dst_port, payload, frag=0):
    return (b"\x00\x00" + bytes([frag]) + b"\x01" + socket.inet_aton(dst_ip)
            + struct.pack("!H", dst_port) + payload)


def socks5_udp_recv(sock, timeout=4.0):
    sock.settimeout(timeout)
    try:
        data, _ = sock.recvfrom(65535)
    except socket.timeout:
        return None
    except ConnectionResetError:
        return None
    if len(data) < 10:
        return None
    atyp = data[3]
    off = 8 if atyp == 1 else (5 + data[4] if atyp == 3 else 20)
    return {"src": data[4:8].hex(), "sport": struct.unpack("!H", data[off:off + 2])[0],
            "payload": data[off + 2:]}


# ────────────────────────── 实例管理 ──────────────────────────
class Instance:
    def __init__(self, side, name, cfg, env=None):
        self.side = side
        self.name = name
        self.cfg_path = os.path.join(TMP, f"{name}_{side}.json")
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        self.lines = []
        self.proc = None
        self._env = env
        self._q = None

    def start(self):
        env = os.environ.copy()
        if self._env:
            env.update(self._env)
        self.proc = subprocess.Popen(
            [SIDE_EXE[self.side], "run", "-c", self.cfg_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        q = queue.Queue()

        def reader():
            for raw in iter(self.proc.stdout.readline, b""):
                q.put(raw.decode("utf-8", "replace").rstrip())
            q.put(None)

        threading.Thread(target=reader, daemon=True).start()
        self._q = q
        return self

    def drain(self, timeout=1.0):
        out = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self._q.get(timeout=0.1)
            except queue.Empty:
                continue
            if line is None:
                break
            out.append(line)
        self.lines.extend(out)
        return out

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        try:
            self.proc.stdout.close()
        except Exception:  # noqa: BLE001
            pass


def wait_port(port, timeout=8.0, host="127.0.0.1", tcp=True):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if tcp:
                s = socket.create_connection((host, port), timeout=0.5)
                s.close()
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((host, port))
                s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


# ────────────────────────── 配置模板 ──────────────────────────
def tunnel_inbound(proto):
    if proto == "vless":
        return {"tag": "tun-in", "listen": "127.0.0.1", "port": 0, "protocol": "vless",
                "settings": {"decryption": "none",
                             "clients": [{"id": UUID, "email": "a@b"}]}}
    if proto == "vmess":
        return {"tag": "tun-in", "listen": "127.0.0.1", "port": 0, "protocol": "vmess",
                "settings": {"clients": [{"id": UUID, "alterId": 0, "email": "a@b"}]}}
    if proto == "trojan":
        return {"tag": "tun-in", "listen": "127.0.0.1", "port": 0, "protocol": "trojan",
                "settings": {"clients": [{"password": PASSWORD, "email": "a@b"}]}}
    raise ValueError(proto)


def tunnel_outbound(proto, port):
    if proto == "vless":
        return {"tag": "tun-out", "protocol": "vless",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": port,
                                        "users": [{"id": UUID, "encryption": "none"}]}]}}
    if proto == "vmess":
        return {"tag": "tun-out", "protocol": "vmess",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": port,
                                        "users": [{"id": UUID, "alterId": 0,
                                                   "security": "auto"}]}]}}
    if proto == "trojan":
        return {"tag": "tun-out", "protocol": "trojan",
                "settings": {"servers": [{"address": "127.0.0.1", "port": port,
                                          "password": PASSWORD}]}}
    raise ValueError(proto)


def client_cfg(socks_port, outbound):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [outbound],
    }


def server_cfg(tun_port, inbound):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [inbound],
        # finalRules allow 是必需项：vless/vmess/trojan 入站名 → freedom 默认
        # block 私有 IP（Go freedom.go:167 defaultBlockPrivateRule）→ 上游
        # 127.0.0.1 会被黑洞，伪装成数据面 bug（仓内 FREEDOM-FINALRULES 条款）。
        "outbounds": [{"tag": "direct", "protocol": "freedom",
                       "settings": {"finalRules": [{"action": "allow"}]}}],
    }


# ────────────────────────── 用例 ──────────────────────────
RESULTS = []


def record(case, side, obs):
    RESULTS.append({"case": case, "side": side, "obs": obs})
    print(f"[{case}] {side}: {json.dumps(obs, ensure_ascii=False)[:400]}", flush=True)


# 29B 裸 DNS 形态的载荷（与 LinuxE2E 轮同形态，便于对照）
PAYLOAD = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")


def run_tunnel_case(proto, client_side, server_side, label):
    """客户端侧 socks UDP → 隧道 → 服务端侧 freedom → 上游记录器。"""
    up = UdpRecorder(PORT_UPSTREAM)
    up.start()
    tun_port = PORT_TUNNEL[server_side]
    socks_port = PORT_SOCKS[client_side]
    inbound = tunnel_inbound(proto)
    inbound["port"] = tun_port
    srv = Instance(server_side, f"{label}_srv_{server_side}", server_cfg(tun_port, inbound)).start()
    cli = Instance(client_side, f"{label}_cli_{client_side}",
                   client_cfg(socks_port, tunnel_outbound(proto, tun_port))).start()
    obs = {"proto": proto}
    try:
        if not wait_port(tun_port) or not wait_port(socks_port):
            obs["error"] = "no listen"
            record(label, f"{client_side}->{server_side}", obs)
            return
        time.sleep(0.8)
        bnd, bport, ctrl = socks5_udp_associate("127.0.0.1", socks_port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        u.sendto(socks5_udp_frame("127.0.0.1", PORT_UPSTREAM, PAYLOAD), (bnd, bport))
        got = socks5_udp_recv(u, 5.0)
        time.sleep(0.8)
        obs["upstream_count"] = len(up.seen)
        obs["upstream"] = up.seen[0] if up.seen else None
        obs["client_reply_len"] = len(got["payload"]) if got else 0
        obs["client_reply_hex"] = got["payload"].hex() if got else None
        obs["client_reply_matches_payload"] = bool(got and got["payload"] == PAYLOAD)
        logs = srv.drain(0.8) + cli.drain(0.8)
        obs["errors"] = [l[:200] for l in logs
                         if "error" in l.lower() or "fail" in l.lower()
                         or "invalid" in l.lower()][:4]
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        up.stop()
    record(label, f"{client_side}->{server_side}", obs)


def run_control_case(client_side, label):
    """控制组：socks UDP → freedom 直连（不经隧道）。"""
    up = UdpRecorder(PORT_UPSTREAM)
    up.start()
    socks_port = PORT_SOCKS[client_side]
    cfg = client_cfg(socks_port, {"tag": "direct", "protocol": "freedom"})
    cli = Instance(client_side, f"{label}_{client_side}", cfg).start()
    obs = {"proto": "none(direct)"}
    try:
        if not wait_port(socks_port):
            obs["error"] = "no listen"
            record(label, client_side, obs)
            return
        time.sleep(0.8)
        bnd, bport, ctrl = socks5_udp_associate("127.0.0.1", socks_port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        u.sendto(socks5_udp_frame("127.0.0.1", PORT_UPSTREAM, PAYLOAD), (bnd, bport))
        got = socks5_udp_recv(u, 5.0)
        time.sleep(0.8)
        obs["upstream_count"] = len(up.seen)
        obs["upstream"] = up.seen[0] if up.seen else None
        obs["client_reply_len"] = len(got["payload"]) if got else 0
        obs["client_reply_matches_payload"] = bool(got and got["payload"] == PAYLOAD)
        logs = cli.drain(0.8)
        obs["errors"] = [l[:200] for l in logs
                         if "error" in l.lower() or "fail" in l.lower()][:4]
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        up.stop()
    record(label, client_side, obs)


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    # 控制组（不经隧道）
    if only in (None, "control"):
        for side in ("rust", "go"):
            try:
                run_control_case(side, f"CTRL_direct_{side}")
            except Exception as e:  # noqa: BLE001
                record(f"CTRL_direct_{side}", side, {"harness_error": f"{type(e).__name__}: {e}"})
    # 隧道矩阵：vless / vmess / trojan × 4 方向
    for proto in ("vless", "vmess", "trojan"):
        for client_side in ("rust", "go"):
            for server_side in ("rust", "go"):
                label = f"T_{proto}_{client_side}_{server_side}"
                if only and only not in label:
                    continue
                try:
                    run_tunnel_case(proto, client_side, server_side, label)
                except Exception as e:  # noqa: BLE001
                    record(label, f"{client_side}->{server_side}",
                           {"harness_error": f"{type(e).__name__}: {e}"})
                time.sleep(0.4)
    path = os.path.join(TMP, "vxudp_results.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(RESULTS, f, indent=2, ensure_ascii=False)
    print("results ->", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
