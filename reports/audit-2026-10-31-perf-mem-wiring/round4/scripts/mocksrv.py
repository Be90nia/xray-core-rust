"""共用底座：mock DNS 上游 + UDP echo + socks5 UDP 客户端 + 双侧实例管理。

端口段：UdpDnsDiff 专用 28050-28099。
"""
import json
import os
import queue
import socket
import struct
import subprocess
import threading
import time

GO = r"D:\tmp\go2617\xray.exe"
RUST = r"D:\Project\Xray-core-rust\target\release\xray.exe"
TMP = r"D:\Project\Xray-core-rust\reports\audit-2026-10-31-perf-mem-wiring\round4\tmp"
os.makedirs(TMP, exist_ok=True)

SIDE_EXE = {"go": GO, "rust": RUST}

# ────────────────────────── 端口分配（28050-28099） ──────────────────────────
PORTS = {
    "mockdns": 28060,      # mock DNS 上游（UDP）
    "echo": 28061,         # UDP echo 目标
    "go_socks": 28062,     # Go socks inbound (udp)
    "rust_socks": 28063,   # Rust socks inbound (udp)
    "go_dok": 28064,       # Go dokodemo udp
    "rust_dok": 28065,     # Rust dokodemo udp
    "go_dnsout": 28066,    # Go dns outbound (dokodemo→dns)
    "rust_dnsout": 28067,  # Rust dns outbound
    "go_vmess": 28068,
    "rust_vmess": 28069,
}


# ────────────────────────── mock DNS 上游 ──────────────────────────
def parse_query(data):
    """返回 (id, flags, qname, qtype, has_edns)。仅解析第一个 question。"""
    if len(data) < 12:
        raise ValueError("short header")
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    off = 12
    labels = []
    while off < len(data):
        ln = data[off]
        off += 1
        if ln == 0:
            break
        labels.append(data[off:off + ln].decode("latin-1"))
        off += ln
    qname = ".".join(labels)
    qtype, qclass = struct.unpack("!HH", data[off:off + 4])
    off += 4
    # additional 区：只看 OPT（type 41）
    has_edns = False
    for _ in range(ar):
        if off + 2 > len(data):
            break
        # RR: NAME（可能压缩）TYPE CLASS TTL RDLEN RDATA
        if data[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while off < len(data) and data[off] != 0:
                off += 1 + data[off]
            off += 1
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        if rtype == 41:
            has_edns = True
        off += rdlen
    return qid, flags, qname, qtype, has_edns


def build_query(qname, qtype=1, qid=0x1234, rd=True, edns=False, qclass=1):
    """构造 DNS 查询报文（可带 EDNS0 OPT）。"""
    flags = 0x0100 if rd else 0x0000
    arcount = 1 if edns else 0
    buf = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, arcount)
    for label in qname.split("."):
        if not label:
            continue
        buf += bytes([len(label)]) + label.encode("latin-1")
    buf += b"\x00"
    buf += struct.pack("!HH", qtype, qclass)
    if edns:
        buf += b"\x00"                       # root name
        buf += struct.pack("!HHIH", 41, 4096, 0, 0)  # OPT
    return buf


def _name(qname):
    out = b""
    for label in qname.split("."):
        if not label:
            continue
        out += bytes([len(label)]) + label.encode("latin-1")
    return out + b"\x00"


class MockDns:
    """mock DNS 上游实现（UDP）。

    mode:
      normal      — A → 1.2.3.4 / AAAA → 2001:db8::1，TTL=300
      truncated   — 回 TC=1 且空 answer（触发上游的截断重试逻辑）
      noanswer    — rcode=3 (NXDOMAIN)
      silent      — 不回包（测超时）
    """

    def __init__(self, port, mode="normal", ttl=300):
        self.mode = mode
        self.ttl = ttl
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.queries = []
        self.parsed = []
        self._stop = False
        self._thr = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thr.start()
        return self

    def _run(self):
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            self.queries.append(data.hex())
            try:
                qid, flags, qname, qtype, has_edns = parse_query(data)
            except Exception as e:  # noqa: BLE001
                self.parsed.append(("parse-error", str(e)))
                continue
            self.parsed.append((qid, flags, qname, qtype, has_edns))
            resp = self._build(qid, flags, qname, qtype, has_edns)
            if resp is not None:
                try:
                    self.sock.sendto(resp, addr)
                except OSError:
                    pass

    def _build(self, qid, flags, qname, qtype, has_edns):
        if self.mode == "silent":
            return None
        rcode = 0
        if self.mode == "noanswer":
            rcode = 3
        ans = b""
        ancount = 0
        if self.mode != "truncated" and rcode == 0:
            if qtype == 1:
                rdata = socket.inet_aton("1.2.3.4")
                ans += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, self.ttl, len(rdata)) + rdata
                ancount += 1
            elif qtype == 28:
                rdata = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
                ans += b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, self.ttl, len(rdata)) + rdata
                ancount += 1
            elif qtype == 5:  # CNAME
                rdata = _name("alias.example.com")
                ans += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, self.ttl, len(rdata)) + rdata
                ancount += 1
            elif qtype == 16:  # TXT
                rdata = b"\x05hello"
                ans += b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, self.ttl, len(rdata)) + rdata
                ancount += 1
        rflags = 0x8180 | rcode   # QR + AA + RD + RA
        if self.mode == "truncated":
            rflags |= 0x0200      # TC
        arcount = 1 if has_edns else 0
        head = struct.pack("!HHHHHH", qid, rflags, 1, ancount, 0, arcount)
        extra = b""
        if has_edns:
            extra = b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0)
        return head + _name(qname) + struct.pack("!HH", qtype, 1) + ans + extra

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


class MockDnsTcp:
    """mock DNS 上游（TCP，RFC 1035 §4.2.2 长度前缀帧）。"""

    def __init__(self, port, mode="normal", ttl=300):
        self.mode = mode
        self.ttl = ttl
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(8)
        self.sock.settimeout(0.3)
        self.queries = []
        self.parsed = []
        self._stop = False
        self._thr = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thr.start()
        return self

    def _run(self):
        while not self._stop:
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        buf = b""
        conn.settimeout(5.0)
        try:
            while not self._stop:
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    break
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while len(buf) >= 2:
                    ln = struct.unpack("!H", buf[:2])[0]
                    if len(buf) < 2 + ln:
                        break
                    msg = buf[2:2 + ln]
                    buf = buf[2 + ln:]
                    self.queries.append(msg.hex())
                    try:
                        qid, flags, qname, qtype, has_edns = parse_query(msg)
                    except Exception as e:  # noqa: BLE001
                        self.parsed.append(("parse-error", str(e)))
                        continue
                    self.parsed.append((qid, flags, qname, qtype, has_edns))
                    resp = self._build(qid, flags, qname, qtype, has_edns)
                    if resp is not None:
                        try:
                            conn.sendall(struct.pack("!H", len(resp)) + resp)
                        except OSError:
                            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _build(self, qid, flags, qname, qtype, has_edns):
        if self.mode == "silent":
            return None
        rcode = 3 if self.mode == "noanswer" else 0
        ans = b""
        ancount = 0
        if self.mode != "truncated" and rcode == 0:
            if qtype == 1:
                rdata = socket.inet_aton("1.2.3.4")
                ans += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, self.ttl, len(rdata)) + rdata
                ancount += 1
            elif qtype == 28:
                rdata = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
                ans += b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, self.ttl, len(rdata)) + rdata
                ancount += 1
            elif qtype == 5:
                rdata = _name("alias.example.com")
                ans += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, self.ttl, len(rdata)) + rdata
                ancount += 1
            elif qtype == 16:
                rdata = b"\x05hello"
                ans += b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, self.ttl, len(rdata)) + rdata
                ancount += 1
        rflags = 0x8180 | rcode
        if self.mode == "truncated":
            rflags |= 0x0200
        arcount = 1 if has_edns else 0
        head = struct.pack("!HHHHHH", qid, rflags, 1, ancount, 0, arcount)
        extra = b""
        if has_edns:
            extra = b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0)
        return head + _name(qname) + struct.pack("!HH", qtype, 1) + ans + extra

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


# ────────────────────────── UDP echo ──────────────────────────
class UdpEcho(threading.Thread):
    """UDP echo：记录对端地址与 payload，原样回显。"""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.port = port
        self.seen = []            # (peer_ip, peer_port, payload_hex)
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.seen.append((addr[0], addr[1], data.hex()))
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
    """完成 SOCKS5 握手 + UDP ASSOCIATE，返回 (relay_ip, relay_port, ctrl_sock)。"""
    ctrl = socket.create_connection((host, port), timeout=timeout)
    ctrl.settimeout(timeout)
    ctrl.sendall(b"\x05\x01\x00")
    resp = ctrl.recv(2)
    if len(resp) != 2 or resp[0] != 5:
        raise RuntimeError(f"socks greeting bad: {resp!r}")
    if resp[1] != 0:
        raise RuntimeError(f"socks auth required: {resp[1]}")
    ctrl.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
    reply = ctrl.recv(10)
    if len(reply) < 10:
        raise RuntimeError(f"socks associate reply short: {reply!r}")
    rep = reply[1]
    atyp = reply[3]
    if atyp == 1:
        bnd = socket.inet_ntoa(reply[4:8])
    elif atyp == 3:
        ln = reply[4]
        bnd = reply[5:5 + ln].decode("latin-1")
    elif atyp == 4:
        bnd = socket.inet_ntop(socket.AF_INET6, reply[4:20])
    else:
        raise RuntimeError(f"bad ATYP {atyp}")
    bport = struct.unpack("!H", reply[-2:])[0]
    if rep != 0:
        raise RuntimeError(f"associate rejected rep={rep}")
    if bnd in ("0.0.0.0", "::"):
        bnd = host
    return bnd, bport, ctrl, rep


def socks5_udp_frame(dst_ip, dst_port, payload, frag=0):
    return (b"\x00\x00" + bytes([frag]) + b"\x01" + socket.inet_aton(dst_ip)
            + struct.pack("!H", dst_port) + payload)


def socks5_udp_recv(sock, timeout=3.0):
    sock.settimeout(timeout)
    try:
        data, _ = sock.recvfrom(65535)
    except socket.timeout:
        return None
    except ConnectionResetError:
        # Windows：ICMP port unreachable → WSAECONNRESET（对端关闭后）
        return None
    if len(data) < 10:
        return None
    frag = data[2]
    atyp = data[3]
    if atyp == 1:
        src = socket.inet_ntoa(data[4:8])
        off = 8
    elif atyp == 3:
        ln = data[4]
        src = data[5:5 + ln].decode("latin-1")
        off = 5 + ln
    elif atyp == 4:
        src = socket.inet_ntop(socket.AF_INET6, data[4:20])
        off = 20
    else:
        src = "?"
        off = 4
    sport = struct.unpack("!H", data[off:off + 2])[0]
    return {"src": src, "sport": sport, "frag": frag, "payload": data[off + 2:]}


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

    def start(self):
        exe = SIDE_EXE[self.side]
        env = os.environ.copy()
        if self._env:
            env.update(self._env)
        self.proc = subprocess.Popen(
            [exe, "run", "-c", self.cfg_path],
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


def wait_port(port, timeout=8.0, host="127.0.0.1", tcp=False):
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
