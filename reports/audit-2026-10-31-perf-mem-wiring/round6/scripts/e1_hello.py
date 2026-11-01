#!/usr/bin/env python3
"""E1：ClientHello 版本/套件/ALPN 面抓取对拍（Go vs Rust）。

对每组 tlsSettings，抓两端首个 ClientHello 并解析 supported_versions /
cipher_suites / alpn / groups / keyshare / ext 顺序。

用法：python e1_hello.py
"""
import json
import pathlib
import socket
import struct
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
FIX = HERE / "fixtures"
TMP = HERE.parent / "tmp"
TMP.mkdir(parents=True, exist_ok=True)
GO = r"D:/tmp/go2617/xray.exe"
RS = r"D:/Project/Xray-core-rust/target/release/xray.exe"
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


def client_cfg(socks_port, target_port, tls_settings):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "127.0.0.1",
                            "port": target_port,
                            "users": [{"id": UUID, "encryption": "none"}],
                        }
                    ]
                },
                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_settings},
            }
        ],
    }


def wait_port(port, timeout=12.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.4):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def trigger(socks_port):
    try:
        s = socket.create_connection(("127.0.0.1", socks_port), timeout=4)
    except OSError:
        return
    s.settimeout(3)
    try:
        s.sendall(b"\x05\x01\x00")
        s.recv(2)
        host = b"test.example"
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack(">H", 443))
        try:
            s.recv(10)
        except socket.timeout:
            pass
        time.sleep(0.6)
    except OSError:
        pass
    finally:
        s.close()


CASES = {
    "hello_default": {"serverName": "test.example"},
    "hello_chrome_fp": {"serverName": "test.example", "fingerprint": "chrome"},
    "hello_min13_nofp": {"serverName": "test.example", "minVersion": "1.3"},
    "hello_min13_fp": {"serverName": "test.example", "minVersion": "1.3", "fingerprint": "chrome"},
    "hello_max12_nofp": {"serverName": "test.example", "maxVersion": "1.2"},
    "hello_alpn_h1": {"serverName": "test.example", "alpn": ["http/1.1"]},
    "hello_alpn_h2h1_fp": {"serverName": "test.example", "alpn": ["h2", "http/1.1"], "fingerprint": "chrome"},
}


def main():
    out = {}
    idx = 0
    for name, tls in CASES.items():
        out[name] = {}
        for impl_i, (impl, exe) in enumerate((("go", GO), ("rust", RS))):
            socks_port = 28500 + idx * 2 + impl_i
            hello_port = 28524 + idx * 2 + impl_i
            hello_out = TMP / f"{name}_{impl}_hello.json"
            srv = subprocess.Popen(
                [sys.executable, str(HERE / "hello_dump.py"), "--port", str(hello_port), "--out", str(hello_out)],
                cwd=str(HERE),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
            )
            time.sleep(0.4)
            cfg = TMP / f"{name}_{impl}.json"
            cfg.write_text(json.dumps(client_cfg(socks_port, hello_port, tls), indent=2), encoding="utf-8")
            proc = subprocess.Popen(
                [exe, "run", "-c", str(cfg)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
            )
            ok = wait_port(socks_port)
            if ok:
                trigger(socks_port)
            end = time.time() + 6
            while time.time() < end and not hello_out.exists():
                time.sleep(0.1)
            time.sleep(0.4)
            proc.kill()
            proc.wait()
            srv.kill()
            srv.wait()
            rec = None
            if hello_out.exists():
                try:
                    rec = json.loads(hello_out.read_text(encoding="utf-8"))
                except Exception:
                    rec = None
                hello_out.unlink()
            out[name][impl] = rec
            time.sleep(0.2)
        idx += 1
        g, r = out[name].get("go"), out[name].get("rust")
        print(f"\n=== {name} ===")
        for label, rec in (("go", g), ("rust", r)):
            if not rec:
                print(f"  [{label}] NO HELLO")
                continue
            print(
                f"  [{label}] ver={rec.get('supported_versions')} ciphers={rec.get('ciphers')[:6]}"
                f"(n={len(rec.get('ciphers') or [])}) alpn={rec.get('alpn')} "
                f"ks={rec.get('keyshare')} grease={rec.get('has_grease')} len={rec.get('record_len')}"
            )
    (TMP / "e1_hello_results.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("\nwritten", TMP / "e1_hello_results.json")


if __name__ == "__main__":
    sys.exit(main())
