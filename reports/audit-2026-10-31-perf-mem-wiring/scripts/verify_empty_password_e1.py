#!/usr/bin/env python3
"""E1 验证：ss / trojan 入站凭据缺省空串 → 公开常量凭据可直接打通数据。

用法：
    python verify_empty_password_e1.py [rust|go]

设计（对抗性，不使用任何一款 xray 作为客户端）：
  两个协议的客户端都是**手写**的——攻击者只知道「口令是空串」这一公开常量，
  自己算 KDF/sha224 即可接入。这样证明的是「公开常量凭据可用」，而不是
  「同一份实现自己认自己」。

  ss    : EVP_BytesToKey(md5 链) + HKDF-SHA1(salt,key,"ss-subkey") + AES-128-GCM 分块
  trojan: hex(sha224(password)) + CRLF + cmd + atyp + addr + port + CRLF + payload

负向对照组：同样的客户端换成错误口令 → 必须失败（否则说明「压根没认证」，
          那成功就不能归因于空口令）。
"""
import hashlib
import hmac
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = os.path.dirname(os.path.abspath(__file__))
RUST_XRAY = r"D:\Project\Xray-core-rust\target\release\xray.exe"
GO_XRAY = r"D:\tmp\go2617\xray.exe"

# 端口运行期动态取（Windows 上 SO_REUSEADDR 会让 bind 抢到已被占用的端口，
# 于是数据被旧监听者接走——固定端口曾导致假失败）。
SS_PORT = 0
TROJAN_PORT = 0
TARGET_PORT = 0
SOCKS_PORT = 0
TARGET_BANNER = b"BANNER-EMPTY-PW-OK\n"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p

results = []


def log(msg):
    print(msg, flush=True)


def rec(tag, verdict, detail):
    results.append((tag, verdict, detail))
    log(f"[{verdict}] {tag}: {detail}")


# ---------------------------------------------------------------- target server
class TargetServer:
    """极简 TCP 目标：连上即回 banner，随后回显。"""

    def __init__(self, port):
        self.port = port
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(16)
        self.stop = False
        self.hits = 0
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.hits += 1
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            c.sendall(TARGET_BANNER)
            while True:
                d = c.recv(65536)
                if not d:
                    break
                c.sendall(d)
        except OSError:
            pass
        finally:
            c.close()

    def close(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass


# ------------------------------------------------------------- socks5 relay
class Socks5Relay:
    """最小 SOCKS5 服务器（无认证），把 CONNECT 目标原样连出去。

    替代 freedom 出站：freedom 对 trojan/ss 入站按 Go 默认 final rule 拦截
    RFC1918/loopback 目标，会让 E1 数据面永远没流量——那是路由行为，不是认证，
    会掩盖认证结论。
    """

    def __init__(self, port):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(16)
        self.stop = False
        self.connects = 0
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    @staticmethod
    def _recv_n(s, n):
        out = b""
        while len(out) < n:
            d = s.recv(n - len(out))
            if not d:
                raise ConnectionError("eof")
            out += d
        return out

    def _serve(self, c):
        try:
            ver, nm = self._recv_n(c, 2)
            self._recv_n(c, nm)
            c.sendall(b"\x05\x00")
            _, cmd, _, atyp = self._recv_n(c, 4)
            if atyp == 1:
                host = socket.inet_ntoa(self._recv_n(c, 4))
            elif atyp == 3:
                ln = self._recv_n(c, 1)[0]
                host = self._recv_n(c, ln).decode()
            else:
                host = socket.inet_ntop(socket.AF_INET6, self._recv_n(c, 16))
            port = struct.unpack(">H", self._recv_n(c, 2))[0]
            try:
                up = socket.create_connection((host, port), timeout=5)
            except OSError:
                c.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
                c.close()
                return
            self.connects += 1
            c.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            self._pipe(c, up)
        except Exception:
            try:
                c.close()
            except OSError:
                pass

    @staticmethod
    def _pipe(a, b):
        def pump(src, dst):
            try:
                while True:
                    d = src.recv(65536)
                    if not d:
                        break
                    dst.sendall(d)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        t = threading.Thread(target=pump, args=(b, a), daemon=True)
        t.start()
        pump(a, b)
        t.join(timeout=20)
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass

    def close(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass


# ------------------------------------------------------------------ ss client
def ss_evp_bytes_to_key(password: bytes, key_size: int) -> bytes:
    key = b""
    md5_sum = hashlib.md5(password).digest()
    key += md5_sum
    while len(key) < key_size:
        md5_sum = hashlib.md5(md5_sum + password).digest()
        key += md5_sum
    return key[:key_size]


def hkdf_sha1(secret: bytes, salt: bytes, info: bytes, out_len: int) -> bytes:
    prk = hmac.new(salt, secret, hashlib.sha1).digest()
    okm = b""
    t = b""
    i = 1
    while len(okm) < out_len:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha1).digest()
        okm += t
        i += 1
    return okm[:out_len]


class SsAeadWriter:
    """aead-2022-legacy 风格分块写（shadowsocks AEAD 2017 规范）。"""

    def __init__(self, sock, subkey):
        self.sock = sock
        self.aead = AESGCM(subkey)
        self.counter = 0

    def _nonce(self):
        n = self.counter.to_bytes(12, "little")
        self.counter += 1
        return n

    def write(self, data):
        ln = self.aead.encrypt(self._nonce(), struct.pack(">H", len(data)), None)
        self.sock.sendall(ln + self.aead.encrypt(self._nonce(), data, None))


class SsAeadReader:
    def __init__(self, sock, subkey):
        self.sock = sock
        self.aead = AESGCM(subkey)
        self.counter = 0
        self.buf = b""

    def _nonce(self):
        n = self.counter.to_bytes(12, "little")
        self.counter += 1
        return n

    def _need(self, n):
        while len(self.buf) < n:
            d = self.sock.recv(65536)
            if not d:
                raise ConnectionError("eof")
            self.buf += d
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read(self, n):
        out = b""
        while len(out) < n:
            ln = self.aead.decrypt(self._nonce(), self._need(2 + 16), None)
            size = struct.unpack(">H", ln)[0]
            out += self.aead.decrypt(self._nonce(), self._need(size + 16), None)
        return out


def ss_roundtrip(password: str, cipher_name="aes-128-gcm", timeout=6.0,
                 port=None) -> bytes:
    port = SS_PORT if port is None else port
    key_size = 16
    key = ss_evp_bytes_to_key(password.encode(), key_size)
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        salt = os.urandom(key_size)
        subkey = hkdf_sha1(key, salt, b"ss-subkey", key_size)
        sock.sendall(salt)
        w = SsAeadWriter(sock, subkey)
        # 请求头：ATYP 0x01 + ipv4 + port(BE)
        req = b"\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", TARGET_PORT)
        w.write(req + b"PING\n")
        rsalt = sock.recv(key_size)
        if len(rsalt) != key_size:
            raise ConnectionError("short salt")
        rsub = hkdf_sha1(key, rsalt, b"ss-subkey", key_size)
        r = SsAeadReader(sock, rsub)
        return r.read(len(TARGET_BANNER))
    finally:
        sock.close()


# --------------------------------------------------------------- trojan client
def trojan_roundtrip(password: str, timeout=6.0, port=None) -> bytes:
    port = TROJAN_PORT if port is None else port
    key = hashlib.sha224(password.encode()).hexdigest().encode()
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        # hex(sha224) 56B + CRLF + cmd(0x01 CONNECT) + atyp(0x01) + ipv4 + port + CRLF
        head = (key + b"\r\n" + b"\x01" + b"\x01"
                + socket.inet_aton("127.0.0.1") + struct.pack(">H", TARGET_PORT) + b"\r\n")
        sock.sendall(head + b"PING\n")
        out = b""
        while len(out) < len(TARGET_BANNER):
            d = sock.recv(65536)
            if not d:
                break
            out += d
        return out
    finally:
        sock.close()


# ------------------------------------------------------------------- xray proc
def write_cfg(obj):
    fd, path = tempfile.mkstemp(suffix=".json", prefix="empty_pw_")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    return path


def server_config(with_ss_users_password: bool, with_trojan_password: bool):
    ss_user = {"method": "aes-128-gcm", "email": "u1"}
    if with_ss_users_password:
        ss_user["password"] = "REAL-PW"
    tj_client = {"email": "c1"}
    if with_trojan_password:
        tj_client["password"] = "REAL-PW"
    return {
        "log": {"loglevel": "info"},
        "inbounds": [
            {"tag": "ss-in", "listen": "127.0.0.1", "port": SS_PORT,
             "protocol": "shadowsocks",
             "settings": {"method": "aes-128-gcm", "users": [ss_user]}},
            {"tag": "tj-in", "listen": "127.0.0.1", "port": TROJAN_PORT,
             "protocol": "trojan", "settings": {"clients": [tj_client]}},
        ],
        "outbounds": [{"protocol": "socks",
                       "settings": {"servers": [{"address": "127.0.0.1",
                                                  "port": SOCKS_PORT}]}}],
    }


def start_xray(exe, cfg_path, log_path, wait_port, wait=12.0):
    f = open(log_path, "wb")
    p = subprocess.Popen([exe, "run", "-c", cfg_path], stdout=f, stderr=f,
                         stdin=subprocess.DEVNULL)
    deadline = time.time() + wait
    up = False
    while time.time() < deadline:
        if p.poll() is not None:
            break
        try:
            s = socket.create_connection(("127.0.0.1", wait_port), timeout=0.4)
            s.close()
            up = True
            break
        except OSError:
            time.sleep(0.15)
    return p, f, up


def kill(p):
    try:
        p.terminate()
        p.wait(timeout=8)
    except Exception:
        try:
            p.kill()
        except Exception:
            pass


def tail(path, n=4000):
    try:
        with open(path, "rb") as f:
            return f.read()[-n:].decode("utf-8", "replace")
    except OSError:
        return ""


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "rust"
    exe = RUST_XRAY if which == "rust" else GO_XRAY
    label = "Rust 5fe98b90" if which == "rust" else "Go 26.10.17"
    log(f"=== target = {label} ({exe}) ===")

    global SS_PORT, TROJAN_PORT, TARGET_PORT, SOCKS_PORT
    SS_PORT, TROJAN_PORT, TARGET_PORT, SOCKS_PORT = (
        free_port(), free_port(), free_port(), free_port())
    log(f"ports: ss={SS_PORT} trojan={TROJAN_PORT} target={TARGET_PORT} relay={SOCKS_PORT}")
    tgt = TargetServer(TARGET_PORT)
    relay = Socks5Relay(SOCKS_PORT)
    outdir = os.path.join(HERE, "..", "tmp")
    outdir = os.path.abspath(outdir)
    os.makedirs(outdir, exist_ok=True)

    # ---- 1. 空口令配置：进程能否启动 / 监听 ----
    cfg = write_cfg(server_config(False, False))
    logpath = os.path.join(outdir, f"e1_{which}_empty.log")
    p, fh, up = start_xray(exe, cfg, logpath, SS_PORT)
    started = p.poll() is None
    rec(f"F11/F12[{which}] 空口令配置启动",
        "STARTED" if started else "REFUSED",
        f"process_alive={started} listen={up} rc={p.poll()}")
    if not started:
        rec(f"F11/F12[{which}] 拒启原因", "INFO", tail(logpath).strip().splitlines()[-3:] if tail(logpath) else "")
        kill(p)
        fh.close()
        tgt.close()
        summary()
        return
    # trojan port 是否也在监听
    try:
        s = socket.create_connection(("127.0.0.1", TROJAN_PORT), timeout=1.0)
        s.close()
        tj_up = True
    except OSError:
        tj_up = False

    # ---- 2. 客户端用公开常量空串接入 ----
    try:
        got = ss_roundtrip("")
        ok = got.startswith(b"BANNER")
        rec(f"F11[{which}] ss 空口令客户端打通数据",
            "DATA-FLOWED" if ok else "NO-DATA", repr(got))
    except Exception as e:
        rec(f"F11[{which}] ss 空口令客户端打通数据", "FAILED",
            f"{type(e).__name__}: {e}")

    if tj_up:
        try:
            got = trojan_roundtrip("")
            ok = got.startswith(b"BANNER")
            rec(f"F12[{which}] trojan 空口令客户端打通数据",
                "DATA-FLOWED" if ok else "NO-DATA", repr(got))
        except Exception as e:
            rec(f"F12[{which}] trojan 空口令客户端打通数据", "FAILED",
                f"{type(e).__name__}: {e}")
    else:
        rec(f"F12[{which}] trojan 端口监听", "NOT-LISTENING", f"port={TROJAN_PORT}")

    # ---- 3. 负向对照：错误口令必须失败 ----
    try:
        got = ss_roundtrip("WRONG-PW", timeout=4.0)
        rec(f"F11[{which}] 负向对照(错误口令)", "UNEXPECTED-PASS", repr(got))
    except Exception as e:
        rec(f"F11[{which}] 负向对照(错误口令)", "EXPECTED-FAIL",
            f"{type(e).__name__}: {e}")
    if tj_up:
        try:
            got = trojan_roundtrip("WRONG-PW", timeout=4.0)
            rec(f"F12[{which}] 负向对照(错误口令)", "UNEXPECTED-PASS", repr(got))
        except Exception as e:
            rec(f"F12[{which}] 负向对照(错误口令)", "EXPECTED-FAIL",
                f"{type(e).__name__}: {e}")

    kill(p)
    fh.close()

    # ---- 4. 真实口令配置：空口令客户端必须失败（证明确实是认证而不是放行）----
    cfg2 = write_cfg(server_config(True, True))
    logpath2 = os.path.join(outdir, f"e1_{which}_realpw.log")
    p2, fh2, up2 = start_xray(exe, cfg2, logpath2, SS_PORT)
    if p2.poll() is None:
        try:
            got = ss_roundtrip("", timeout=4.0)
            rec(f"F11[{which}] 真实口令时空口令应失败", "UNEXPECTED-PASS", repr(got))
        except Exception as e:
            rec(f"F11[{which}] 真实口令时空口令应失败", "EXPECTED-FAIL",
                f"{type(e).__name__}: {e}")
        try:
            got = ss_roundtrip("REAL-PW", timeout=4.0)
            rec(f"F11[{which}] 正控(真实口令)应成功", "DATA-FLOWED"
                if got.startswith(b"BANNER") else "NO-DATA", repr(got))
        except Exception as e:
            rec(f"F11[{which}] 正控(真实口令)应成功", "FAILED",
                f"{type(e).__name__}: {e}")
        try:
            got = trojan_roundtrip("", timeout=4.0)
            rec(f"F12[{which}] 真实口令时空口令应失败", "UNEXPECTED-PASS", repr(got))
        except Exception as e:
            rec(f"F12[{which}] 真实口令时空口令应失败", "EXPECTED-FAIL",
                f"{type(e).__name__}: {e}")
        try:
            got = trojan_roundtrip("REAL-PW", timeout=4.0)
            rec(f"F12[{which}] 正控(真实口令)应成功", "DATA-FLOWED"
                if got.startswith(b"BANNER") else "NO-DATA", repr(got))
        except Exception as e:
            rec(f"F12[{which}] 正控(真实口令)应成功", "FAILED",
                f"{type(e).__name__}: {e}")
    else:
        rec(f"[{which}] 真实口令配置启动", "REFUSED", tail(logpath2)[-300:])
    kill(p2)
    fh2.close()

    tgt.close()
    summary()


def summary():
    log("\n=== 汇总 ===")
    for t, v, d in results:
        log(f"{t:<44} {v:<16} {str(d)[:110]}")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        summary()
        sys.exit(1)
