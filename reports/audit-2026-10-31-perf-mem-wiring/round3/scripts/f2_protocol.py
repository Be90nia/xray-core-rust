"""族 2：协议行为双跑差分（客户端 → 两侧服务端，同一份字节）。

每个用例 = 一段原始字节 → 分别发给 Go 服务端与 Rust 服务端 → 比：
  连接结果（拒绝/接受/静默丢弃/崩溃）、服务端是否存活、返回字节、日志关键行。
"""
import os
import re
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import GO, RUST, TMP, kill_proc  # noqa: E402

GO_PORT = 25020
RUST_PORT = 25060
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

# 每种协议各占一个端口（Go 25020-25024 / Rust 25060-25064），互不冲突
KIND_PORT = {
    "go": {"socks": 25020, "http": 25021, "vless": 25022, "trojan": 25023, "vmess": 25024},
    "rust": {"socks": 25060, "http": 25061, "vless": 25062, "trojan": 25063, "vmess": 25064},
}


class Server:
    """起一个实例，持续抽日志。"""

    def __init__(self, side, cfg, port, name):
        self.side = side
        self.port = port
        self.path = os.path.join(TMP, name + ".json")
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(cfg)
        exe = GO if side == "go" else RUST
        self.p = subprocess.Popen(
            [exe, "run", "-c", self.path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=os.path.dirname(self.path),
        )
        self.lines = []
        self._t = threading.Thread(target=self._reader, daemon=True)
        self._t.start()
        self.ready = self._wait_ready()

    def _reader(self):
        for raw in self.p.stdout:
            self.lines.append(raw.decode("utf-8", "replace").rstrip())

    def _wait_ready(self, timeout=10.0):
        end = time.time() + timeout
        while time.time() < end:
            if self.p.poll() is not None:
                return False
            s = socket.socket()
            s.settimeout(0.4)
            try:
                s.connect(("127.0.0.1", self.port))
                return True
            except OSError:
                time.sleep(0.15)
            finally:
                s.close()
        return False

    def alive(self):
        return self.p.poll() is None

    def crash(self):
        return self.p.poll() is not None

    def log_text(self):
        return "\n".join(self.lines)

    def stop(self):
        kill_proc(self.p)


def send_raw(port, payload, wait=1.2, half_close=True, read_limit=4096):
    """连上，发字节，收集回应。返回 dict。"""
    r = {"connected": False, "sent": 0, "recv": b"", "error": None, "closed_by_peer": False}
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=4.0)
        r["connected"] = True
    except OSError as e:
        r["error"] = "connect: %s" % e
        return r
    try:
        s.settimeout(wait)
        if payload:
            s.sendall(payload)
            r["sent"] = len(payload)
        if half_close:
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        chunks = []
        end = time.time() + wait
        while time.time() < end:
            try:
                b = s.recv(read_limit)
            except socket.timeout:
                break
            except OSError as e:
                r["error"] = "recv: %s" % e
                break
            if not b:
                r["closed_by_peer"] = True
                break
            chunks.append(b)
        r["recv"] = b"".join(chunks)
    finally:
        try:
            s.close()
        except OSError:
            pass
    return r


def recv_n(port, n, timeout=4.0):
    """只收不发的场景。"""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    except OSError as e:
        return {"connected": False, "recv": b"", "error": str(e)}
    s.settimeout(timeout)
    buf = b""
    err = None
    try:
        while len(buf) < n:
            b = s.recv(n - len(buf))
            if not b:
                break
            buf += b
    except OSError as e:
        err = str(e)
    finally:
        s.close()
    return {"connected": True, "recv": buf, "error": err}


# ---------------- 配置 ----------------
def socks_cfg(port):
    return """{
  "log": {"loglevel": "debug"},
  "inbounds": [{"tag":"in-socks","listen":"127.0.0.1","port":%d,
    "protocol":"socks","settings":{"auth":"noauth","udp":false}}],
  "outbounds": [{"tag":"out-1","protocol":"freedom","settings":{}}]
}""" % port


def http_cfg(port):
    return """{
  "log": {"loglevel": "debug"},
  "inbounds": [{"tag":"in-http","listen":"127.0.0.1","port":%d,
    "protocol":"http","settings":{}}],
  "outbounds": [{"tag":"out-1","protocol":"freedom","settings":{}}]
}""" % port


def vless_cfg(port):
    return """{
  "log": {"loglevel": "debug"},
  "inbounds": [{"tag":"in-vless","listen":"127.0.0.1","port":%d,
    "protocol":"vless","settings":{"clients":[{"id":"%s"}],"decryption":"none"}}],
  "outbounds": [{"tag":"out-1","protocol":"freedom","settings":{}}]
}""" % (port, UUID)


def trojan_cfg(port):
    return """{
  "log": {"loglevel": "debug"},
  "inbounds": [{"tag":"in-trojan","listen":"127.0.0.1","port":%d,
    "protocol":"trojan","settings":{"clients":[{"password":"pw-test-123"}]}}],
  "outbounds": [{"tag":"out-1","protocol":"freedom","settings":{}}]
}""" % port


def vmess_cfg(port):
    return """{
  "log": {"loglevel": "debug"},
  "inbounds": [{"tag":"in-vmess","listen":"127.0.0.1","port":%d,
    "protocol":"vmess","settings":{"clients":[{"id":"%s","alterId":0}]}}],
  "outbounds": [{"tag":"out-1","protocol":"freedom","settings":{}}]
}""" % (port, UUID)


# ---------------- 用例定义 ----------------
# 每例：(name, cfg_kind, payload_bytes, note)
def socks_handshake_ok():
    # VER=5 NMETHODS=1 METHOD=0(NO AUTH)
    return bytes([5, 1, 0])


CASES = []


def add(name, cfg_kind, payload, note="", half_close=True, wait=1.2):
    CASES.append(
        {"name": name, "cfg": cfg_kind, "payload": payload, "note": note,
         "half_close": half_close, "wait": wait}
    )


# --- SOCKS5 ---
add("socks5_zero_len_greeting", "socks", b"", "SOCKS5 零长问候（直接 EOF）")
add("socks5_empty_method_list", "socks", bytes([5, 0]), "NMETHODS=0")
add("socks5_bad_version", "socks", bytes([4, 1, 0]), "版本号 4（非 5）")
add("socks5_unknown_method", "socks", bytes([5, 1, 0xFF]), "METHOD=0xFF（不支持）")
add("socks5_userpass_method_only", "socks", bytes([5, 1, 2]), "METHOD=2 但服务端只支持 noauth")
add("socks5_greet_then_eof", "socks", bytes([5, 1, 0]), "握手成功但立即半关闭")
add("socks5_huge_method_count", "socks", bytes([5, 255]) + bytes([0]) * 255, "NMETHODS=255")
add("socks5_request_bad_version", "socks", bytes([5, 1, 0]) + bytes([4, 1, 0, 1, 0, 0, 0, 0, 0, 0]),
    "请求阶段版本号错")
add("socks5_request_bad_cmd", "socks", bytes([5, 1, 0]) + bytes([5, 9, 0, 1, 127, 0, 0, 1, 0, 80]),
    "CMD=9（非法命令）")
add("socks5_request_bad_atyp", "socks", bytes([5, 1, 0]) + bytes([5, 1, 0, 9, 127, 0, 0, 1, 0, 80]),
    "ATYP=9（非法地址类型）")
add("socks5_request_truncated", "socks", bytes([5, 1, 0]) + bytes([5, 1, 0, 1, 127]), "请求头截断")
add("socks5_request_port_zero", "socks", bytes([5, 1, 0]) + bytes([5, 1, 0, 1, 127, 0, 0, 1, 0, 0]),
    "目标端口 0")
add("socks5_request_ipv6", "socks", bytes([5, 1, 0]) + bytes([5, 1, 0, 4]) + bytes(16) + bytes([0, 80]),
    "IPv6 地址类型")
add("socks5_request_domain_long", "socks", bytes([5, 1, 0]) + bytes([5, 1, 0, 3, 255]) + b"a" * 255 + bytes([0, 80]),
    "域名长度 255")
add("socks5_double_handshake", "socks", bytes([5, 1, 0]) + bytes([5, 1, 0]) + bytes([5, 1, 0]),
    "连续两次握手（第二个请求当普通字节）")

# --- HTTP ---
add("http_bad_request_line", "http", b"NOTHTTP\r\n\r\n", "非 HTTP 请求行")
add("http_bad_method", "http", b"BLAH / HTTP/1.1\r\nHost: a\r\n\r\n", "非法 method")
add("http_missing_host", "http", b"GET / HTTP/1.1\r\n\r\n", "无 Host 头")
add("http_bad_version", "http", b"GET / HTTP/9.9\r\nHost: a\r\n\r\n", "HTTP/9.9")
add("http_zero_len", "http", b"", "零长连接")
add("http_only_crlf", "http", b"\r\n\r\n", "只有空行")
add("http_absolute_uri", "http", b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "absolute-form URI")
add("http_long_path", "http", b"GET /" + b"a" * 8000 + b" HTTP/1.1\r\nHost: a\r\n\r\n", "超长路径")
add("http_huge_header", "http", b"GET / HTTP/1.1\r\nHost: a\r\nX: " + b"b" * 9000 + b"\r\n\r\n",
    "超长 header")
add("http_chunked_body", "http", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    "chunked body")
add("http_expect_100", "http", b"POST / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
    "Expect: 100-continue 后不继续", wait=2.0)
add("http_invalid_content_length", "http", b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: abc\r\n\r\n",
    "Content-Length 非数字")

# --- VLESS ---
def vless_hdr(uuid_bytes, cmd=1, atyp=1, addr=b"\x7f\x00\x00\x01", port=80):
    return bytes([0]) + uuid_bytes + bytes([cmd, 0]) + bytes([atyp]) + addr + port.to_bytes(2, "big")


import uuid as _uuid  # noqa: E402

UB = _uuid.UUID(UUID).bytes
add("vless_zero_len", "vless", b"", "零长")
add("vless_bad_version", "vless", bytes([0xFF]) + UB + bytes([1, 0, 1, 127, 0, 0, 1, 0, 80]),
    "版本字节 0xFF")
add("vless_bad_uuid", "vless", bytes([0]) + bytes(16) + bytes([1, 0, 1, 127, 0, 0, 1, 0, 80]),
    "UUID 全 0（错误）")
add("vless_bad_cmd", "vless", bytes([0]) + UB + bytes([9, 0, 1, 127, 0, 0, 1, 0, 80]),
    "CMD=9 非法")
add("vless_truncated_after_version", "vless", bytes([0]), "只有版本字节")
add("vless_truncated_mid", "vless", bytes([0]) + UB[:8], "UUID 截断")
add("vless_bad_atyp", "vless", bytes([0]) + UB + bytes([1, 0, 9, 127, 0, 0, 1, 0, 80]), "ATYP=9")
add("vless_addr_len_truncated", "vless", bytes([0]) + UB + bytes([1, 0, 1, 127]), "地址截断")
add("vless_double_handshake", "vless",
    bytes([0]) + UB + bytes([1, 0, 1, 127, 0, 0, 1, 0, 80]) + bytes([0]) + UB + bytes([1, 0, 1, 127, 0, 0, 1, 0, 80]),
    "同一连接内两次完整握手")

# --- Trojan ---
add("trojan_zero_len", "trojan", b"", "零长")
add("trojan_bad_password", "trojan", bytes(56) + b"\x00\x00\x01\x00\x50" + b"x" * 4,
    "错误密码 + 完整地址")
add("trojan_truncated", "trojan", bytes(20), "密码后截断")
add("trojan_only_password", "trojan", b"wrongpw", "只有密码串")

# --- VMess ---
add("vmess_zero_len", "vmess", b"", "零长")
add("vmess_garbage", "vmess", bytes(range(64)), "64 字节垃圾")
add("vmess_truncated", "vmess", bytes(10), "10 字节截断")

CFG_FN = {"socks": socks_cfg, "http": http_cfg, "vless": vless_cfg,
          "trojan": trojan_cfg, "vmess": vmess_cfg}


def main():
    results = []
    servers = {}
    # 先把所有 5 种服务端都起起来（Go 与 Rust 各一套）
    for kind in ("socks", "http", "vless", "trojan", "vmess"):
        servers[("go", kind)] = Server("go", CFG_FN[kind](KIND_PORT["go"][kind]),
                                       KIND_PORT["go"][kind], "f2_go_%s" % kind)
        servers[("rust", kind)] = Server("rust", CFG_FN[kind](KIND_PORT["rust"][kind]),
                                         KIND_PORT["rust"][kind], "f2_rs_%s" % kind)
        print("server %s/%s go_ready=%s rust_ready=%s" % (
            kind, "", servers[("go", kind)].ready, servers[("rust", kind)].ready), flush=True)
    # 端口不同（Go 25020 / Rust 25060），逐 kind 单独端口
    try:
        for c in CASES:
            row = {"case": c["name"], "note": c["note"], "cfg": c["cfg"]}
            for side in ("go", "rust"):
                srv = servers[(side, c["cfg"])]
                port = srv.port
                before = len(srv.lines)
                r = send_raw(port, c["payload"], wait=c["wait"], half_close=c["half_close"])
                time.sleep(0.35)
                row[side] = {
                    "connected": r["connected"],
                    "sent": r["sent"],
                    "recv_hex": r["recv"][:64].hex(),
                    "recv_len": len(r["recv"]),
                    "closed_by_peer": r["closed_by_peer"],
                    "error": r["error"],
                    "server_alive": srv.alive(),
                    "server_exit": srv.p.poll(),
                    "new_log": "\n".join(srv.lines[before:])[:800],
                }
            row["same"] = (
                row["go"]["recv_hex"] == row["rust"]["recv_hex"]
                and row["go"]["connected"] == row["rust"]["connected"]
                and row["go"]["server_alive"] == row["rust"]["server_alive"]
            )
            results.append(row)
            print("%-34s GO(recv=%s alive=%s) RUST(recv=%s alive=%s) %s" % (
                c["name"], row["go"]["recv_hex"][:16] or "-", row["go"]["server_alive"],
                row["rust"]["recv_hex"][:16] or "-", row["rust"]["server_alive"],
                "SAME" if row["same"] else "**DIFF**"), flush=True)
    finally:
        for s in servers.values():
            s.stop()
    import json
    with open(os.path.join(TMP, "f2_results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print("\nF2 total=%d diff=%d" % (len(results), sum(1 for r in results if not r["same"])))


if __name__ == "__main__":
    main()
