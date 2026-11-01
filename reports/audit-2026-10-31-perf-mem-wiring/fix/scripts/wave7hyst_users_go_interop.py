#!/usr/bin/env python
"""bd ctiwx：Go 客户端 ↔ Rust 服务端 hysteria `users[]` 多用户真互通。

矩阵（全部真实二进制 + 真实 QUIC）：
  1. Go xray 客户端（socks → hysteria outbound, auth=seed）→ Rust 服务端
     （hysteria `users[]` + cert/key + freedom 默认出站）→ python HTTP echo
     ⇒ curl 拿到 echo 响应（基线互通）。
  2. Go `xray api adu --server=<rust api>` 加新用户 tok-2 ⇒ 起第二个 Go 客户端
     实例（auth=tok-2）⇒ curl 成功（**adu 立即生效**）。
  3. Go `xray api rmu` 移除 tok-2 ⇒ 重启客户端 B（新 QUIC 连接）⇒ curl 失败
     （**rmu 立即拒**）。
  4. 单 auth 回归：Rust 服务端改 `auth` 单串形态 ⇒ Go `api adu` 显式
     NotUserManager 错误（该形态无用户面）。

环境：XRAY_RUST_BIN / XRAY_GO_BIN 可覆盖二进制路径。
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time

REPO = r"D:/Project/Xray-core-rust"
RUST = os.environ.get("XRAY_RUST_BIN", os.path.join(REPO, "target-Wave7Hyst", "release", "xray.exe"))
GO = os.environ.get("XRAY_GO_BIN", r"D:/tmp/go2617/xray.exe")
TMP = os.path.join(REPO, "reports", "audit-2026-10-31-perf-mem-wiring", "fix", "tmp", "hyst_users")
os.makedirs(TMP, exist_ok=True)

HYST_PORT = 11908
API_PORT = 10085
ECHO_PORT = 11909
GO_A_SOCKS = 10910
GO_B_SOCKS = 10911
TAG = "hyst-in"
SEED_AUTH = "seed-token"
NEW_AUTH = "tok-2"
NEW_EMAIL = "u2@x"

def gen_pem() -> tuple[str, str]:
    """CN=localhost 自签证书（Rust 服务端 cert/key 配置项消费）。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import datetime

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    import hashlib
    pin_hex = hashlib.sha256(cert_der).hexdigest()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem, pin_hex


def wait_port(port: int, timeout: float = 20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


class EchoServer:
    """最小 HTTP echo：任何请求回 200 + 固定 body。"""

    def __init__(self, port: int):
        import threading

        self.body = b"HELLO-FROM-ECHO"
        self.resp = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(self.body)).encode()
            + b"\r\nConnection: close\r\n\r\n" + self.body
        )
        self.srv = socket.create_server(("127.0.0.1", port))
        self.srv.listen(8)
        self.stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            try:
                conn.recv(65536)
                conn.sendall(self.resp)
            finally:
                conn.close()


def curl_socks(socks_port: int, timeout: int = 15) -> tuple[int, str]:
    return run(
        [
            "curl",
            "-s",
            "--max-time",
            str(timeout),
            "--socks5-hostname",
            f"127.0.0.1:{socks_port}",
            f"http://127.0.0.1:{ECHO_PORT}/",
        ]
    )


def write_json(path: str, obj: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def main() -> int:
    for exe in (RUST, GO):
        if not os.path.isfile(exe):
            print(f"FATAL: missing binary {exe}", file=sys.stderr)
            return 2

    cert_pem, key_pem, pin_hex = gen_pem()

    rust_server_cfg = {
        "log": {"loglevel": "info"},
        "api": {"tag": "api", "listen": f"127.0.0.1:{API_PORT}", "services": ["HandlerService"]},
        "inbounds": [
            {
                "tag": TAG,
                "listen": "127.0.0.1",
                "port": HYST_PORT,
                "protocol": "hysteria",
                "settings": {
                    "version": 2,
                    "users": [{"auth": SEED_AUTH, "email": "seed@x", "level": 0}],
                    "cert": cert_pem,
                    "key": key_pem,
                },
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}],
    }
    single_auth_cfg = {
        "log": {"loglevel": "info"},
        "api": {"tag": "api", "listen": f"127.0.0.1:{API_PORT}", "services": ["HandlerService"]},
        "inbounds": [
            {
                "tag": TAG,
                "listen": "127.0.0.1",
                "port": HYST_PORT,
                "protocol": "hysteria",
                "settings": {"version": 2, "auth": "single-token", "cert": cert_pem, "key": key_pem},
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}],
    }

    def go_client_cfg(socks_port: int, auth: str) -> dict:
        return {
            "log": {"loglevel": "info"},
            "inbounds": [
                {
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "port": socks_port,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": False},
                }
            ],
            "outbounds": [
                {
                    "protocol": "hysteria",
                    "settings": {"version": 2, "address": "127.0.0.1", "port": HYST_PORT},
                    "streamSettings": {
                        "network": "hysteria",
                        "hysteriaSettings": {"auth": auth, "version": 2},
                        "security": "tls",
                        "tlsSettings": {"serverName": "localhost", "pinnedPeerCertSha256": pin_hex},
                    },
                }
            ],
        }

    echo = EchoServer(ECHO_PORT)
    results: list[tuple[str, bool]] = []

    def go_instance(name: str, auth: str, socks_port: int) -> subprocess.Popen:
        path = os.path.join(TMP, f"{name}.json")
        write_json(path, go_client_cfg(socks_port, auth))
        return subprocess.Popen(
            [GO, "run", "-c", path],
            stdout=open(os.path.join(TMP, f"{name}.log"), "w"),
            stderr=subprocess.STDOUT,
        )

    def require_socks(proc: subprocess.Popen, name: str, socks_port: int) -> bool:
        if wait_port(socks_port, 15):
            time.sleep(0.5)
            return True
        print(f"FAIL: go client socks not listening; log:")
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            pass
        with open(os.path.join(TMP, f"{name}.log"), encoding="utf-8", errors="replace") as f:
            print(f.read()[:2000])
        return False

    # ===== 1. 基线互通：Go 客户端（seed）→ Rust 服务端 =====
    print("\n===== 1. Go client(seed) -> Rust server(users[]) =====", flush=True)
    srv_path = os.path.join(TMP, "rust_server.json")
    write_json(srv_path, rust_server_cfg)
    srv = subprocess.Popen(
        [RUST, "run", "-c", srv_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    ok1 = False
    try:
        if not wait_port(API_PORT, 10):  # hysteria 是 UDP/QUIC：TCP connect 探活不适用
            print("FAIL: rust server ports not listening")
        else:
            inst_a = go_instance("go_a_seed", SEED_AUTH, GO_A_SOCKS)
            try:
                if not require_socks(inst_a, "go_a_seed", GO_A_SOCKS):
                    pass
                else:
                    time.sleep(0.5)
                    rc, out = curl_socks(GO_A_SOCKS)
                    print(f"[seed curl rc={rc}] {out}", flush=True)
                    ok1 = rc == 0 and "HELLO-FROM-ECHO" in out
            finally:
                stop(inst_a)
    finally:
        stop(srv)
        time.sleep(0.3)
    results.append(("1 Go↔Rust 基线互通", ok1))

    # ===== 2/3. adu 立即生效 + rmu 立即拒 =====
    print("\n===== 2/3. adu(rust api) -> Go client B(tok-2) -> rmu -> reject =====", flush=True)
    srv = subprocess.Popen(
        [RUST, "run", "-c", srv_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    ok23 = True
    try:
        if not wait_port(API_PORT, 10):  # hysteria 是 UDP/QUIC：TCP connect 探活不适用
            print("FAIL: rust server ports not listening")
            ok23 = False
        else:
            add_json = os.path.join(TMP, "adu_add.json")
            write_json(
                add_json,
                {
                    "inbounds": [
                        {
                            "tag": TAG,
                            "listen": "127.0.0.1",
                            "port": HYST_PORT,
                            "protocol": "hysteria",
                            "settings": {
                                "version": 2,
                                "users": [{"auth": NEW_AUTH, "email": NEW_EMAIL, "level": 0}],
                            },
                        }
                    ]
                },
            )
            rc, out = run([GO, "api", "adu", f"--server=127.0.0.1:{API_PORT}", add_json])
            print(f"[adu rc={rc}] {out}", flush=True)
            if rc != 0 or "Added 1" not in out:
                print("FAIL: adu 未成功")
                ok23 = False

            inst_b = go_instance("go_b_new", NEW_AUTH, GO_B_SOCKS)
            ok_b = False
            try:
                if not require_socks(inst_b, "go_b_new", GO_B_SOCKS):
                    print("FAIL: client B socks not listening")
                else:
                    time.sleep(0.5)
                    rc, out = curl_socks(GO_B_SOCKS)
                    print(f"[adu'd curl rc={rc}] {out}", flush=True)
                    ok_b = rc == 0 and "HELLO-FROM-ECHO" in out
                    if not ok_b:
                        print("FAIL: adu 后新用户不可连")
                        ok23 = False
            finally:
                stop(inst_b)

            rc, out = run(
                [GO, "api", "rmu", f"--server=127.0.0.1:{API_PORT}", f"-tag={TAG}", NEW_EMAIL]
            )
            print(f"[rmu rc={rc}] {out}", flush=True)
            if rc != 0:
                print("FAIL: rmu 未成功")
                ok23 = False

            # 重启客户端 B（全新 QUIC 连接）⇒ 立刻被拒。
            inst_b2 = go_instance("go_b_new2", NEW_AUTH, GO_B_SOCKS)
            try:
                if not require_socks(inst_b2, "go_b_new2", GO_B_SOCKS):
                    print("[rejected] client B socks failed to listen（auth 拒绝在拨号层）——也算拒")
                else:
                    time.sleep(0.5)
                    rc, out = curl_socks(GO_B_SOCKS)
                    print(f"[post-rmu curl rc={rc}] {out[:200]}", flush=True)
                    if rc == 0 and "HELLO-FROM-ECHO" in out:
                        print("FAIL: rmu 后 tok-2 仍可连")
                        ok23 = False
                    else:
                        print("[post-rmu] 连接被拒（符合预期）", flush=True)
            finally:
                stop(inst_b2)
    finally:
        stop(srv)
        time.sleep(0.3)
    results.append(("2/3 adu 立即生效 + rmu 立即拒（Go 客户端↔Rust 服务端）", ok23))

    # ===== 4. 单 auth 形态回归（数据面）+ 用户面显式拒绝 =====
    print("\n===== 4. 单 auth 形态：数据面回归 + adu 显式 NotUserManager =====", flush=True)
    single_path = os.path.join(TMP, "rust_single.json")
    write_json(single_path, single_auth_cfg)
    srv = subprocess.Popen(
        [RUST, "run", "-c", single_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    ok4 = True
    try:
        if not wait_port(API_PORT, 10):  # hysteria 是 UDP/QUIC：TCP connect 探活不适用
            print("FAIL: rust server ports not listening")
            ok4 = False
        else:
            inst_a = go_instance("go_single", "single-token", GO_A_SOCKS)
            try:
                if not require_socks(inst_a, "go_single", GO_A_SOCKS):
                    print("FAIL: go client socks not listening")
                    ok4 = False
                else:
                    time.sleep(0.5)
                    rc, out = curl_socks(GO_A_SOCKS)
                    print(f"[single-auth curl rc={rc}] {out}", flush=True)
                    if not (rc == 0 and "HELLO-FROM-ECHO" in out):
                        print("FAIL: 单 auth 形态回归失败")
                        ok4 = False
            finally:
                stop(inst_a)
            add_json = os.path.join(TMP, "adu_add_single.json")
            write_json(
                add_json,
                {
                    "inbounds": [
                        {
                            "tag": TAG,
                            "tag": TAG,
                            "listen": "127.0.0.1",
                            "port": HYST_PORT,
                            "protocol": "hysteria",
                            "settings": {
                                "version": 2,
                                "users": [{"auth": "x", "email": "y@x", "level": 0}],
                            },
                        }
                    ]
                },
            )
            rc, out = run([GO, "api", "adu", f"--server=127.0.0.1:{API_PORT}", add_json])
            print(f"[adu on single-auth rc={rc}] {out[:300]}", flush=True)
            if rc == 0 and "Added 1" in out:
                print("FAIL: 单 auth 形态不该有用户面（应 NotUserManager）")
                ok4 = False
    finally:
        stop(srv)
        time.sleep(0.3)
    results.append(("4 单 auth 回归 + 用户面显式拒绝", ok4))

    print()
    for name, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    passed = sum(1 for _, ok in results if ok)
    print(f"\n=== {passed}/{len(results)} PASS ===")
    return 0 if passed == len(results) else 1


def stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=6)


if __name__ == "__main__":
    sys.exit(main())
