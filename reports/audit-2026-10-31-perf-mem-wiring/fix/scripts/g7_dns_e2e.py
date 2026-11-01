"""G7 端到端验收：DNS ownLink（7qxjj）/ 客户端侧帧格式（64nmm）/ TC=1 兜底（1ksxu D7）/
dns 入站（1ksxu D5）/ per-level bufferSize 生效（s6h2j）。

全部真二进制 + 真字节流（本机 loopback + 自建 mock 上游）；端口段 28070-28089
（round4 已占 28050-28069）。
"""
import base64
import os
import socket
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "round4", "scripts"))

from mocksrv import MockDns, build_query, parse_query  # noqa: E402

RUST = os.environ.get(
    "XRAY_BIN", r"D:\Project\Xray-core-rust\target-G7DnsObs\release\xray.exe")
TMP = os.path.join(HERE, "..", "tmp")
os.makedirs(TMP, exist_ok=True)

MOCK_DNS = 28070
DOK_PORT = 28071          # D1/D2/D7：本地 DNS 服务（dokodemo-door → dns 出站）
DNS_IN_PORT = 28072       # D5：Rust 独占 dns 入站
ECHO_HTTP = 28073         # s6h2j：HTTP 目标
VLESS_SRV = 28074         # s6h2j：vless 服务端（level 1 用户）
SOCKS_PORT = 28075        # s6h2j：客户端 socks 入口

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

RESULTS = []


def record(case, ok, detail):
    RESULTS.append({"case": case, "ok": bool(ok), "detail": detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {case}: {detail}")


# ────────────────────────── 实例管理 ──────────────────────────
class Inst:
    def __init__(self, name, cfg):
        import json
        import subprocess
        self.path = os.path.join(TMP, f"{name}.json")
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        self.proc = subprocess.Popen([RUST, "run", "-c", self.path],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.lines = []
        self._thr = threading.Thread(target=self._pump, daemon=True)
        self._thr.start()

    def _pump(self):
        for raw in iter(self.proc.stdout.readline, b""):
            self.lines.append(raw.decode("utf-8", "replace").rstrip())

    def alive(self):
        return self.proc.poll() is None

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                self.proc.kill()

    def grep(self, needle):
        return [l for l in self.lines if needle in l]


# ────────────────────────── DNS 查询客户端 ──────────────────────────
def udp_dns(port, qname, qtype=1, qid=0x2222, timeout=6.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(build_query(qname, qtype, qid), ("127.0.0.1", port))
        data, _ = s.recvfrom(65535)
        return data
    except (socket.timeout, ConnectionResetError):
        return None
    finally:
        s.close()


def tcp_dns(port, qname, qtype=1, qid=0x3333, timeout=6.0):
    q = build_query(qname, qtype, qid)
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    except OSError:
        return None
    s.settimeout(timeout)
    try:
        s.sendall(struct.pack("!H", len(q)) + q)
        hdr = s.recv(2)
        if len(hdr) < 2:
            return None
        ln = struct.unpack("!H", hdr)[0]
        buf = b""
        while len(buf) < ln:
            chunk = s.recv(ln - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf if len(buf) == ln else None
    except (socket.timeout, ConnectionResetError, OSError):
        return None
    finally:
        s.close()


def _skip_name(buf, off):
    while off < len(buf):
        ln = buf[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += 1 + ln
    return off


def summarize(resp):
    """解析应答：rcode / ANCOUNT / A 记录 IP 列表（跳过压缩名与 EDNS OPT）。"""
    if resp is None:
        return {"answered": False}
    _qid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", resp[:12])
    off = 12
    for _ in range(qd):
        off = _skip_name(resp, off) + 4
    ips = []
    for _ in range(an):
        off = _skip_name(resp, off)
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", resp[off:off + 10])
        off += 10
        rdata = resp[off:off + rdlen]
        off += rdlen
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(rdata))
        elif rtype == 28 and rdlen == 16:
            ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
    return {
        "answered": True,
        "rcode": flags & 0x000F,
        "ancount": an,
        "tc": bool(flags & 0x0200),
        "ips": ips,
        "hex": resp.hex(),
    }


# ────────────────────────── 用例 ──────────────────────────
def dok_cfg(log="debug", rewrite=None, servers=None):
    dns = {"servers": servers or [{"address": "127.0.0.1", "port": MOCK_DNS}]}
    ob = {"tag": "dns-out", "protocol": "dns", "settings": {}}
    if rewrite:
        ob["settings"] = rewrite
    return {
        "log": {"loglevel": log},
        "dns": dns,
        "inbounds": [{
            "tag": "dns-in", "listen": "127.0.0.1", "port": DOK_PORT,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1", "port": MOCK_DNS, "network": "tcp,udp"},
        }],
        "outbounds": [ob],
    }


def case_d1_ownlink(mock):
    """7qxjj：本地 DNS 服务器形态（唯一出站 = dns）必须应答 A 查询。

    没有 ownLink 时 DNS app 的上游查询会被 dns 出站再劫持一次 → 回环 → 零应答。
    """
    inst = Inst("d1_ownlink", dok_cfg())
    try:
        time.sleep(1.2)
        if not inst.alive():
            record("D1_ownlink_udp_answer", False, f"instance died: {inst.lines[-5:]}")
            return
        resp = udp_dns(DOK_PORT, "c1.test")
        obs = summarize(resp)
        own = inst.grep("dns-out")
        record(
            "D1_ownlink_udp_answer",
            obs.get("answered") and obs.get("ancount") == 1 and obs.get("ips") == ["1.2.3.4"],
            f"{obs} | upstream_queries={len(mock.queries)} | log_own={own[:2]}",
        )
    finally:
        inst.stop()


def case_d2_tcp_client_udp_upstream(mock):
    """64nmm：TCP 客户端 + rewrite 到 UDP 上游必须应答。

    修前分支按「上游网络」选帧格式 → 客户端 TCP 帧被当 XUDP 解 → 零应答。
    """
    cfg = dok_cfg(rewrite={"rewriteNetwork": "udp", "rewriteAddress": "127.0.0.1",
                           "rewritePort": MOCK_DNS})
    inst = Inst("d2_tcp_client", cfg)
    try:
        time.sleep(1.2)
        if not inst.alive():
            record("D2_tcp_client_udp_upstream", False, f"instance died: {inst.lines[-5:]}")
            return
        resp = tcp_dns(DOK_PORT, "d2.test")
        obs = summarize(resp)
        record(
            "D2_tcp_client_udp_upstream",
            obs.get("answered") and obs.get("ips") == ["1.2.3.4"],
            f"{obs} | upstream_queries={len(mock.queries)}",
        )
    finally:
        inst.stop()


def case_d5_dns_inbound(mock):
    """1ksxu D5：Rust 独占 dns 入站自身可用（配了 servers 就必须答 A 查询）。"""
    cfg = {
        "log": {"loglevel": "debug"},
        "inbounds": [{
            "tag": "dns-inbound", "listen": "127.0.0.1", "port": DNS_IN_PORT,
            "protocol": "dns",
            "settings": {"servers": [f"127.0.0.1:{MOCK_DNS}"]},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }
    inst = Inst("d5_dns_inbound", cfg)
    try:
        time.sleep(1.2)
        if not inst.alive():
            record("D5_dns_inbound_answers", False, f"instance died: {inst.lines[-5:]}")
            return
        resp = udp_dns(DNS_IN_PORT, "d5.test")
        obs = summarize(resp)
        record(
            "D5_dns_inbound_answers",
            obs.get("answered") and obs.get("ips") == ["1.2.3.4"],
            f"{obs} | log_listen={inst.grep('dns inbound listening')[:1]}",
        )
    finally:
        inst.stop()


def case_d7_tc1_fallback(mock_tc1):
    """1ksxu D7：上游恒回 TC=1 且无 TCP 监听 → 必须回 Go 语义空应答（不是零应答）。"""
    inst = Inst("d7_tc1", dok_cfg())
    try:
        time.sleep(1.2)
        if not inst.alive():
            record("D7_tc1_falls_back", False, f"instance died: {inst.lines[-5:]}")
            return
        t0 = time.time()
        resp = udp_dns(DOK_PORT, "t7.test", timeout=8.0)
        obs = summarize(resp)
        obs["elapsed_s"] = round(time.time() - t0, 2)
        record(
            "D7_tc1_falls_back",
            obs.get("answered") and obs.get("rcode") == 0 and obs.get("ancount") == 0,
            f"{obs} | fallback_warn={inst.grep('tcp fallback failed')[:1]}",
        )
    finally:
        inst.stop()


class HttpEcho(threading.Thread):
    """最小 HTTP 服务：回 200 + 固定 body，供 s6h2j 穿 vless 转发。"""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(8)
        self.sock.settimeout(0.5)
        self._stop = False
        self.hits = 0

    def run(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.hits += 1
            try:
                conn.recv(4096)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nlevel")
            except OSError:
                pass
            finally:
                conn.close()

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def socks5_connect(host, port, dst_host, dst_port, user=None, password=None, timeout=5.0):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    if user:
        s.sendall(b"\x05\x01\x02")
        if s.recv(2) != b"\x05\x02":
            raise RuntimeError("socks: auth method rejected")
        u, p = user.encode(), password.encode()
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        if s.recv(2)[1] != 0:
            raise RuntimeError("socks: auth failed")
    else:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            raise RuntimeError("socks: no-auth rejected")
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(dst_host)]) + dst_host.encode()
              + struct.pack("!H", dst_port))
    reply = s.recv(10)
    if len(reply) < 2 or reply[1] != 0:
        raise RuntimeError(f"socks: connect failed {reply!r}")
    return s


def case_s6h2j_level_buffer(echo):
    """s6h2j：`levels.<n>.bufferSize` 落到生产 dispatch（可观测日志 + 真流量）。"""
    srv_cfg = {
        "log": {"loglevel": "debug"},
        "policy": {"levels": {"1": {"bufferSize": 64, "connIdle": 30}}},
        "inbounds": [{
            "tag": "vless-in", "listen": "127.0.0.1", "port": VLESS_SRV, "protocol": "vless",
            "settings": {"decryption": "none",
                         "clients": [{"id": UUID, "level": 1, "email": "lvl1@test"}]},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }
    cli_cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in", "listen": "127.0.0.1", "port": SOCKS_PORT, "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{
            "tag": "vless-out", "protocol": "vless",
            "settings": {"vnext": [{
                "address": "127.0.0.1", "port": VLESS_SRV,
                "users": [{"id": UUID, "encryption": "none", "level": 0}],
            }]},
        }],
    }
    srv = Inst("s6h2j_vless_srv", srv_cfg)
    cli = Inst("s6h2j_socks_cli", cli_cfg)
    try:
        time.sleep(1.5)
        if not (srv.alive() and cli.alive()):
            record("S6h2j_level_buffer", False,
                   f"srv_alive={srv.alive()} cli_alive={cli.alive()} {srv.lines[-3:]} {cli.lines[-3:]}")
            return
        hits_before = echo.hits
        try:
            s = socks5_connect("127.0.0.1", SOCKS_PORT, "127.0.0.1", ECHO_HTTP)
            s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            body = s.recv(4096)
            s.close()
        except (OSError, RuntimeError) as e:
            record("S6h2j_level_buffer", False, f"socks/vless round-trip failed: {e}")
            return
        time.sleep(0.6)
        bound = srv.grep("per-level policy bound to connection")
        matched = [l for l in bound if "level=1" in l and "buffer=65536" in l]
        pipes = srv.grep("per-level bufferSize")
        record(
            "S6h2j_level_buffer",
            body.startswith(b"HTTP/1.1 200") and echo.hits > hits_before and bool(matched),
            f"body={body[:20]!r} echo_hits={echo.hits - hits_before} "
            f"dispatch_log={matched[:1]} chain_log={pipes[:1]}",
        )
    finally:
        cli.stop()
        srv.stop()


def case_dns_log(access_log):
    """sex3y：生产 DNS 查询必须产生一条 dns log（Go `log.Record(&DNSLog{})`）。

    `log.dnsLog=true` + `log.access=<file>` → DNS 与 access 同汇落文件。
    """
    cfg = dok_cfg()
    cfg["log"] = {"loglevel": "debug", "dnsLog": True, "access": access_log}
    inst = Inst("sex3y_dns_log", cfg)
    try:
        time.sleep(1.2)
        if not inst.alive():
            record("sex3y_record_dns_line", False, f"instance died: {inst.lines[-3:]}")
            return
        resp = udp_dns(DOK_PORT, "logdemo.test")
        obs = summarize(resp)
        time.sleep(0.8)
        lines = []
        if os.path.exists(access_log):
            with open(access_log, encoding="utf-8", errors="replace") as f:
                lines = [l.rstrip() for l in f if l.strip()]
        hits = [l for l in lines if "got answer:" in l and "logdemo.test" in l]
        record(
            "sex3y_record_dns_line",
            obs.get("answered") and bool(hits),
            f"dns_log_lines={hits[:2]} answered={obs.get('answered')}",
        )
    finally:
        inst.stop()


def main():
    if not os.path.exists(RUST):
        print(f"missing binary: {RUST}")
        return 1
    print(f"binary={RUST}")
    mock = MockDns(MOCK_DNS, mode="normal").start()
    try:
        case_d1_ownlink(mock)
        case_d2_tcp_client_udp_upstream(mock)
        case_d5_dns_inbound(mock)
        case_dns_log(os.path.join(TMP, "dns_access.log"))
    finally:
        mock.stop()

    mock_tc1 = MockDns(MOCK_DNS, mode="truncated").start()
    try:
        case_d7_tc1_fallback(mock_tc1)
    finally:
        mock_tc1.stop()

    echo = HttpEcho(ECHO_HTTP)
    echo.start()
    try:
        case_s6h2j_level_buffer(echo)
    finally:
        echo.stop()

    print("\nSUMMARY")
    for r in RESULTS:
        print(f"  {'PASS' if r['ok'] else 'FAIL'} {r['case']}")
    return 0 if all(r["ok"] for r in RESULTS) else 2


if __name__ == "__main__":
    sys.exit(main())
