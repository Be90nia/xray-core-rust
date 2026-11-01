"""splithttp 互通矩阵：3 mode × {h2, h3} × 3 方向 = 18 测（bd 1xfap）。

用途：核实 `h3 + stream-one` 组合在 **Rust 服务端**是否回空响应（G4 波次登记的既有缺陷）。
判据（与 G4 同口径）：64 KiB 上行 → 本地 echo 回显 → 逐字节比对（UP/DOWN 各 65536 且字节一致）。
上游 = 脚本内 TCP echo（hermetic，不依赖外网）。

方向：Rust→Rust（对照）、Rust→Go（Rust 客户端 + Go 服务端）、Go→Rust（Go 客户端 + Rust 服务端）。
h3 由 ALPN 选路（Go `dialer.go:95` / Rust `dialer.rs:292 decide_http_version`）：
两端 `tlsSettings.alpn = ["h3"]` → 服务端走 QUIC/h3、客户端走 h3。

用法：python wave7_h3_matrix.py --rust <xray.exe> --go D:/tmp/go2617/xray.exe
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import subprocess
import threading
import time

WORK = os.path.join("D:/tmp", "wave7_h3_matrix")
CERT = os.path.join(WORK, "cert.pem")
KEY = os.path.join(WORK, "key.pem")
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
PAYLOAD = bytes(range(256)) * 256  # 65536 B，确定性内容
OPENSSL_CNF = """[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no
[dn]
CN = localhost
[v3_req]
subjectAltName = DNS:localhost,IP:127.0.0.1
"""
MODES = ["packet-up", "stream-up", "stream-one"]


def gen_cert():
    os.makedirs(WORK, exist_ok=True)
    cnf = CERT + ".cnf"
    with open(cnf, "w") as f:
        f.write(OPENSSL_CNF)
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", KEY, "-out", CERT, "-days", "2", "-config", cnf],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("openssl 证书生成失败: " + r.stderr.strip()[:300])
    with open(CERT) as f:
        der = base64.b64decode("".join(l for l in f.read().splitlines() if "-----" not in l))
    return hashlib.sha256(der).hexdigest()


PIN = gen_cert()


def split_srv(mode, h3):
    tls = {"certificates": [{"certificateFile": CERT, "keyFile": KEY}]}
    if h3:
        tls["alpn"] = ["h3"]
    return {"network": "splithttp", "security": "tls",
            "splithttpSettings": {"path": "/xhttp", "mode": mode, "host": "localhost"},
            "tlsSettings": tls}


def split_cli(mode, h3, download=None, xmux=None):
    tls = {"serverName": "localhost", "pinnedPeerCertSha256": PIN}
    if h3:
        tls["alpn"] = ["h3"]
    ss = {"path": "/xhttp", "mode": mode, "host": "localhost"}
    if xmux is not None:
        # xmux 配置（Go `splithttpSettings.xmux`）：五维判定参数。
        ss["xmux"] = xmux
    if download is not None:
        # 下载侧通道（Go `splithttp.Config.DownloadSettings` = 完整 StreamConfig）：
        # 独立 address/port（此处指向本脚本的 TCP 转发器——**证据锚**：下行连接必经它）
        # + 独立 TLS + 自己的 splithttpSettings（host/path 与主侧一致，session 才能对上）。
        ss["downloadSettings"] = {
            "address": "127.0.0.1",
            "port": download["port"],
            "network": "splithttp",
            "security": "tls",
            "tlsSettings": dict(tls),
            "splithttpSettings": {"path": "/xhttp", "mode": mode, "host": "localhost"},
        }
    return {"network": "splithttp", "security": "tls",
            "splithttpSettings": ss,
            "tlsSettings": tls}


class Forwarder:
    """TCP 转发器（下载侧 destination 的证据锚）。

    下行（downloadSettings 指定的 address/port）经它转发到真正的 splithttp hub；
    上行直连 hub 端口。因此「下行确实走了 downloadSettings」= 该转发器被连上 ✓
    （不依赖「看起来成功」）。
    """

    def __init__(self, target_port):
        self.target_port = target_port
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.accepted = 0
        self.stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self.srv.settimeout(0.5)
        while not self.stop:
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.accepted += 1
            threading.Thread(target=self._pump, args=(conn,), daemon=True).start()

    def _pump(self, conn):
        try:
            up = socket.create_connection(("127.0.0.1", self.target_port), timeout=5)
        except OSError:
            conn.close()
            return

        def relay(a, b):
            try:
                while True:
                    data = a.recv(65536)
                    if not data:
                        break
                    b.sendall(data)
            except OSError:
                pass
            finally:
                for s in (a, b):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        t1 = threading.Thread(target=relay, args=(conn, up), daemon=True)
        t2 = threading.Thread(target=relay, args=(up, conn), daemon=True)
        t1.start()
        t2.start()
        t1.join(60)
        t2.join(60)
        conn.close()
        up.close()

    def close(self):
        self.stop = True
        try:
            self.srv.close()
        except OSError:
            pass


def build(idx, mode, h3, download=None, xmux=None):
    """服务端端口 P（h3 走 UDP）、客户端 socks 端口 S。"""
    p = 18500 + idx * 2
    s = p + 1
    si = {"port": p, "listen": "127.0.0.1", "protocol": "vless",
          "settings": {"clients": [{"id": UUID}], "decryption": "none"},
          "streamSettings": split_srv(mode, h3)}
    co = {"protocol": "vless", "settings": {"vnext": [
        {"address": "127.0.0.1", "port": p,
         "users": [{"id": UUID, "encryption": "none"}]}]},
        "streamSettings": split_cli(mode, h3, download, xmux)}
    return p, s, si, co


def kill_xray(*bins):
    """只杀**本脚本用的**两个二进制（按镜像名），不碰同机其他 xray 进程。

    多代理共用一台机器时，`taskkill /IM xray.exe` 会误杀别人的被测进程——故这里按
    传入路径的 basename 杀，且调用方应使用唯一命名的二进制副本。
    """
    for b in bins:
        name = os.path.basename(b)
        subprocess.run(["cmd", "/c", "taskkill /F /IM " + name],
                       capture_output=True, timeout=10)


class Echo:
    """本地 TCP echo（上游）：收多少回多少。"""

    def __init__(self):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self.srv.settimeout(0.5)
        while not self.stop:
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._echo_one, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo_one(conn):
        try:
            conn.settimeout(20)
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.stop = True
        try:
            self.srv.close()
        except OSError:
            pass


def socks_connect(socks_port, dest_port, timeout=25):
    s = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00", "socks greeting failed"
    req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + dest_port.to_bytes(2, "big")
    s.sendall(req)
    rep = s.recv(10)
    assert len(rep) >= 2 and rep[1] == 0, f"socks connect failed {rep!r}"
    return s


def run_one(idx, mode, h3, server_bin, client_bin, tag, echo, loglevel="warning", forwarder=None,
            xmux=None, access_log=None):
    download = {"port": forwarder.port} if forwarder is not None else None
    p, s, si, co = build(idx, mode, h3, download, xmux)
    srv_log = {"loglevel": loglevel}
    if access_log:
        srv_log["access"] = access_log
    scfg = {"log": srv_log, "inbounds": [si],
            "outbounds": [{"protocol": "freedom",
                           "settings": {"finalRules": [{"action": "allow"}]}}]}
    ccfg = {"log": {"loglevel": loglevel},
            "inbounds": [{"listen": "127.0.0.1", "port": s, "protocol": "socks",
                          "settings": {"udp": False}}],
            "outbounds": [co]}
    scp = os.path.join(WORK, f"s{idx}.json")
    ccp = os.path.join(WORK, f"c{idx}.json")
    with open(scp, "w") as f:
        json.dump(scfg, f)
    with open(ccp, "w") as f:
        json.dump(ccfg, f)
    kill_xray(server_bin, client_bin)
    time.sleep(0.4)
    ps = subprocess.Popen([server_bin, "run", "-c", scp],
                          stdout=open(os.path.join(WORK, f"s{idx}.log"), "wb"),
                          stderr=subprocess.STDOUT)
    time.sleep(2.5)
    pc = subprocess.Popen([client_bin, "run", "-c", ccp],
                          stdout=open(os.path.join(WORK, f"c{idx}.log"), "wb"),
                          stderr=subprocess.STDOUT)
    up = down = 0
    err = ""
    try:
        sock = socks_connect(s, echo.port)
        sock.sendall(PAYLOAD)
        buf = b""
        while len(buf) < len(PAYLOAD):
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        up = len(PAYLOAD)
        down = len(buf)
        ok = down == len(PAYLOAD) and buf == PAYLOAD
        err = "bytes-identical" if ok else "BYTES-MISMATCH"
        sock.close()
    except Exception as e:  # noqa: BLE001
        ok, err = False, repr(e)[:80]
    ps.terminate()
    pc.terminate()
    kill_xray(server_bin, client_bin)
    time.sleep(0.3)
    # downloadSettings 维度：下行必须真的经过转发器（downloadSettings 的 address/port）。
    dl_conns = forwarder.accepted if forwarder is not None else -1
    if forwarder is not None and dl_conns < 1:
        ok = False
        err += " (download leg did NOT go through downloadSettings destination)"
    verdict = "PASS" if ok else "FAIL"
    print(f"[{verdict}] #{idx:02d} {tag:9s} {'h3' if h3 else 'h2'}/{mode:11s} "
          f"UP:{up} DOWN:{down} dl_conns:{dl_conns} {err}", flush=True)
    return verdict == "PASS"



def run_xmux_case(idx, server_bin, client_bin, tag, echo, xmux, n_conns=10, label="xmux"):
    """xmux 复用证据锚：**客户端侧 TCP 连接数** < 拨号次数。

    做法：在客户端出站目标前插一个 TCP 转发器（[`Forwarder`]），客户端 vnext 端口
    指向它 ⇒ `forwarder.accepted` = 客户端为这些代理连接实际打开的 TCP 连接数。
    池化生效 ⇒ 连接数明显 < N；不复用 ⇒ ≈ N（甚至更多，GET/POST 各一条）。

    注：不能用服务端 access log 计数——splithttp 的 access 行是**入站会话**数
    （每条代理连接一行），TCP 复用时仍是 N 行，测不到底层连接复用。
    """
    p, s, si, co = build(idx, "packet-up", False, None, xmux)
    fwd = Forwarder(p)
    co["settings"]["vnext"][0]["port"] = fwd.port
    scfg = {"log": {"loglevel": "warning"}, "inbounds": [si],
            "outbounds": [{"protocol": "freedom",
                           "settings": {"finalRules": [{"action": "allow"}]}}]}
    ccfg = {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": s, "protocol": "socks",
                          "settings": {"udp": False}}],
            "outbounds": [co]}
    scp = os.path.join(WORK, f"s{idx}.json")
    ccp = os.path.join(WORK, f"c{idx}.json")
    with open(scp, "w") as f:
        json.dump(scfg, f)
    with open(ccp, "w") as f:
        json.dump(ccfg, f)
    kill_xray(server_bin, client_bin)
    time.sleep(0.4)
    ps = subprocess.Popen([server_bin, "run", "-c", scp],
                          stdout=open(os.path.join(WORK, f"s{idx}.log"), "wb"),
                          stderr=subprocess.STDOUT)
    time.sleep(2.5)
    pc = subprocess.Popen([client_bin, "run", "-c", ccp],
                          stdout=open(os.path.join(WORK, f"c{idx}.log"), "wb"),
                          stderr=subprocess.STDOUT)
    # 等 socks 入站端口监听（只探 TCP，不做 SOCKS 握手——握手会真拨号，污染连接计数）
    ready_deadline = time.time() + 10
    while time.time() < ready_deadline:
        try:
            socket.create_connection(("127.0.0.1", s), timeout=1).close()
            break
        except OSError:
            time.sleep(0.2)
    t0 = time.time()
    ok_bytes = 0
    err = ""
    try:
        for _ in range(n_conns):
            sock = socks_connect(s, echo.port)
            sock.sendall(PAYLOAD)
            buf = b""
            while len(buf) < len(PAYLOAD):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
            if buf == PAYLOAD:
                ok_bytes += len(buf)
            sock.close()
    except Exception as e:  # noqa: BLE001
        err = repr(e)[:60]
    wall = time.time() - t0
    ps.terminate()
    pc.terminate()
    kill_xray(server_bin, client_bin)
    time.sleep(0.4)
    accepts = fwd.accepted
    fwd.close()
    thr_mbs = (ok_bytes / 1024 / 1024) / wall if wall > 0 else 0.0
    # 判据：字节全对 + 连接数明显少于拨号数（复用）。控制组用"每拨号必换 client"
    # 的 xmux（hMaxRequestTimes=1）跑出 ≈N 的反证。
    ok = ok_bytes == n_conns * len(PAYLOAD)
    verdict = "PASS" if ok else "FAIL"
    print(f"[{verdict}] #{idx:02d} {tag:9s} {label:10s} conns={n_conns} "
          f"tcp_conns={accepts} bytes={ok_bytes} wall={wall:.2f}s thr={thr_mbs:.1f}MB/s {err}",
          flush=True)
    # 单用例只判"字节全对"；复用判定在 main 里用 no-reuse 对照（顺序形态下
    # tcp_conns 可能 > conns——每条代理连接结束会终止下载流，hyper 池随之多拨）。
    return (verdict == "PASS", accepts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rust", required=True)
    ap.add_argument("--go", required=True)
    ap.add_argument("--only", default="", help="过滤子串（mode/方向），如 h3/stream-one")
    ap.add_argument("--loglevel", default="warning")
    ap.add_argument("--xmux", action="store_true",
                    help="追加 xmux 维度：N 次代理连接经 TCP 转发器计数，客户端 TCP 连接数 "
                         "< N 即复用生效；并跑 no-reuse 控制组（hMaxRequestTimes=1）作反证")
    ap.add_argument("--xmux-conns", type=int, default=10)
    ap.add_argument("--dl", action="store_true",
                    help="追加 downloadSettings 维度（h2 + stream-up）：下行经 TCP 转发器，"
                         "转发器被连上 = 下行确实走了 downloadSettings 的 address/port")
    a = ap.parse_args()
    os.makedirs(WORK, exist_ok=True)
    echo = Echo()
    results = []
    idx = 0
    for h3 in (False, True):
        for mode in MODES:
            for tag, sb, cb in (("Rust->Rust", a.rust, a.rust),
                                ("Rust->Go", a.go, a.rust),
                                ("Go->Rust", a.rust, a.go)):
                name = f"{'h3' if h3 else 'h2'}/{mode}/{tag}"
                if a.only and a.only not in name:
                    continue
                idx += 1
                results.append(run_one(idx, mode, h3, sb, cb, tag, echo, a.loglevel))
    if a.dl:
        # downloadSettings 维度：mode=stream-up（下行 = 独立 GET），h2。
        # 下行的 address/port 指向本脚本的 TCP 转发器（转发到同一个 hub）——
        # 转发器被连上即证明下行走了 downloadSettings 通道（而非主通道）。
        for tag, sb, cb in (("Rust->Rust", a.rust, a.rust),
                            ("Rust->Go", a.go, a.rust),
                            ("Go->Rust", a.rust, a.go)):
            if a.only and a.only not in f"dl/stream-up/{tag}":
                continue
            idx += 1
            hub_port = 18500 + idx * 2
            fwd = Forwarder(hub_port)
            try:
                results.append(
                    run_one(idx, "stream-up", False, sb, cb, tag, echo, a.loglevel, fwd))
            finally:
                fwd.close()
    if a.xmux:
        # xmux 维度（连接复用 vs 反证）：
        # - pool：maxConnections=3（Go 缺省预设值）⇒ 复用，TCP 连接数应 < N
        # - no-reuse：hMaxRequestTimes=1 ⇒ 每条代理连接一次取用即耗尽，必须换 client
        #   （控制组，连接数 ≈ N 甚至 2N）
        # 注：xmux 缺省即池化（conf 层套预设），"完全不池化"在配置层不可表达。
        # xmux 值必须用 **Go 合法形态**（`infra/conf/common.go` `Int32Range.UnmarshalJSON`：
        # 字符串 "1-2" / 裸整数；对象 {from,to} 在 Go 是硬错 "Invalid integer range"）。
        cases = (("pool", {"maxConnections": "3"}),
                 ("no-reuse", {"hMaxRequestTimes": "1"}))
        for tag, sb, cb in (("Rust->Rust", a.rust, a.rust),
                            ("Rust->Go", a.go, a.rust),
                            ("Go->Rust", a.rust, a.go)):
            if a.only and a.only not in f"xmux/{tag}":
                continue
            probe = {}
            for label, xm in cases:
                idx += 1
                ok, conns = run_xmux_case(idx, sb, cb, tag, echo, xm,
                                          a.xmux_conns, label)
                probe[label] = conns
                results.append(ok)
            pooled, noreuse = probe["pool"], probe["no-reuse"]
            reused = pooled < noreuse
            print(f"[{'PASS' if reused else 'FAIL'}] {'xmux-cmp':9s} {tag:9s} "
                  f"pool_tcp_conns={pooled} < no-reuse_tcp_conns={noreuse} => 复用{'' if reused else '未生效'}",
                  flush=True)
            results.append(reused)
    echo.close()
    print(f"\n=== splithttp 矩阵: {sum(results)}/{len(results)} PASS ===")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
