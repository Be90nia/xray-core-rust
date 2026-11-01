#!/usr/bin/env python3
"""E1：证书校验矩阵（Go 26.10.17 vs Rust）——同一份 TLS 观测服务器 + 同构 vless+tls 出站配置。

每个 case：
  1) 启动 tls_srv.py（单连接）监听 28510+i
  2) 启动被测 xray（socks 入站 28500+i → vless+tls 出站指向该服务器）
  3) 用 socks5 CONNECT 触发一次拨号
  4) 汇总：服务器侧是否协商成功 + 是否收到应用层字节；客户端日志中的校验错误文本

用法：python e1_tls.py [case_filter]
"""
import json
import os
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
RS = r"D:/Project/Xray-core-rust/target-G6Tls/release/xray.exe"

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


def f(name):
    return str(FIX / name).replace("\\", "/")


CA = {"certificateFile": f("ca.pem"), "usage": "verify"}


def ca_trust():
    return {"certificates": [dict(CA)], "disableSystemRoot": True}


def client_cfg(socks_port, target_port, tls_settings):
    return {
        "log": {"loglevel": "debug"},
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
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": tls_settings,
                },
            }
        ],
    }


def wait_port(port, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.4):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def wait_file_line(path, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if path.exists() and path.read_text(encoding="utf-8", errors="replace").strip():
            return True
        time.sleep(0.1)
    return False


def socks5_probe(socks_port, host="test.example", dport=443, timeout=6.0):
    """返回 (reply_code, note)；reply_code 0 = 成功。"""
    try:
        s = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    except OSError as e:
        return None, f"connect socks failed: {e}"
    s.settimeout(timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return None, "socks greet failed"
        hb = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", dport))
        resp = s.recv(10)
        if len(resp) < 2:
            return None, f"short reply: {resp!r}"
        # 保持连接，让客户端完成 TLS 握手并发出应用层首包，再关闭
        try:
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        except OSError:
            pass
        time.sleep(0.8)
        return resp[1], resp.hex()
    except socket.timeout:
        return None, "socks reply timeout"
    except OSError as e:
        return None, f"socks io: {e}"
    finally:
        try:
            s.close()
        except Exception:
            pass


ERR_KEYS = [
    "failed to verify certificate",
    "certificate",
    "unknown authority",
    "expired",
    "unrecognized",
    "invalid",
    "tls:",
    "handshake",
    "REALITY",
    "pinnedPeerCertSha256",
]


def interesting_lines(log_text, limit=6):
    out = []
    for line in log_text.splitlines():
        low = line.lower()
        if any(k.lower() in low for k in ["cert", "verify", "tls:", "unrecognized", "expired", "hostname"]):
            out.append(line.strip()[:300])
            if len(out) >= limit:
                break
    return out


def run_case(name, cert, key, alpn, tls_settings, idx, min_ver="TLSv1.2", max_ver=""):
    """端口：socks 28500-28523 / server 28524-28547（idx*2+impl，避免复用与并发撞号）。"""
    socks_port = 0
    srv_port = 0
    results = {}
    srv = None
    for impl_i, (impl, exe) in enumerate((("go", GO), ("rust", RS))):
        socks_port = 28500 + idx * 2 + impl_i
        srv_port = 28524 + idx * 2 + impl_i
        srv_log = TMP / f"e1_tls_{name}_{impl}_srv.jsonl"
        if srv_log.exists():
            srv_log.unlink()
        # 每个 impl 一个独立 server 实例，避免连接计数错位
        if srv is not None:
            srv.kill()
            srv.wait()
        srv = subprocess.Popen(
            [
                sys.executable,
                str(HERE / "tls_srv.py"),
                "--port",
                str(srv_port),
                "--cert",
                cert,
                "--key",
                key,
                "--alpn",
                alpn,
                "--conns",
                "1",
                "--out",
                str(srv_log),
                "--min-ver",
                min_ver,
                *(["--max-ver", max_ver] if max_ver else []),
            ],
            cwd=str(HERE),
            stdout=open(TMP / f"e1_tls_{name}_{impl}_srv.out", "w", encoding="utf-8"),
            stderr=subprocess.STDOUT,
        )
        time.sleep(0.4)
        cfg_path = TMP / f"e1_tls_{name}_{impl}.json"
        log_path = TMP / f"e1_tls_{name}_{impl}.log"
        cfg_path.write_text(json.dumps(client_cfg(socks_port, srv_port, tls_settings), indent=2), encoding="utf-8")
        lf = open(log_path, "w", encoding="utf-8")
        proc = subprocess.Popen([exe, "run", "-c", str(cfg_path)], stdout=lf, stderr=subprocess.STDOUT)
        ok_port = wait_port(socks_port)
        reply = None
        if ok_port:
            reply, note = socks5_probe(socks_port)
        else:
            note = "socks never listened"
        # 等服务器侧记录与客户端日志落盘
        wait_file_line(srv_log, 6.0)
        time.sleep(0.6)
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass
        lf.close()
        srv_rec = None
        try:
            for line in srv_log.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    srv_rec = json.loads(line)
        except Exception:
            srv_rec = None
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        results[impl] = {
            "socks_reply": reply,
            "note": note if reply is None else "ok",
            "srv": srv_rec,
            "accepted": bool(srv_rec and srv_rec.get("ok") and srv_rec.get("app_bytes", 0) > 0),
            "client_errors": interesting_lines(log_text),
        }
        time.sleep(0.3)
    try:
        srv.kill()
        srv.wait()
    except Exception:
        pass
    return name, results


def main():
    flt = sys.argv[1] if len(sys.argv) > 1 else ""
    leaf = (f("leaf.pem"), f("leaf.key"))
    expired = (f("expired.pem"), f("expired.key"))
    selfsigned = (f("selfsigned.pem"), f("selfsigned.key"))
    leaf_sha = (FIX / "leaf.sha256").read_text().strip()
    expired_sha = (FIX / "expired.sha256").read_text().strip()
    self_sha = (FIX / "selfsigned.sha256").read_text().strip()

    cases = [
        # (name, server cert/key, server alpn, client tlsSettings)
        (
            "A1_custom_root",
            leaf,
            "",
            dict(ca_trust(), serverName="test.example", fingerprint="chrome"),
        ),
        (
            "A2_custom_root_rustls_path",
            leaf,
            "",
            dict(ca_trust(), serverName="test.example"),
        ),
        (
            "B1_untrusted_selfsigned",
            selfsigned,
            "",
            {"serverName": "test.example", "fingerprint": "chrome"},
        ),
        (
            "B2_untrusted_selfsigned_rustls_path",
            selfsigned,
            "",
            {"serverName": "test.example"},
        ),
        (
            "C1_expired_ca_trusted",
            expired,
            "",
            dict(ca_trust(), serverName="test.example", fingerprint="chrome"),
        ),
        (
            "C2_expired_pinned_leaf",
            expired,
            "",
            {"serverName": "test.example", "fingerprint": "chrome", "pinnedPeerCertSha256": expired_sha},
        ),
        (
            "D1_vcn_only",
            leaf,
            "",
            dict(ca_trust(), serverName="wrong.example", verifyPeerCertByName="test.example", fingerprint="chrome"),
        ),
        (
            "D1b_vcn_only_rustls_path",
            leaf,
            "",
            dict(ca_trust(), serverName="wrong.example", verifyPeerCertByName="test.example"),
        ),
        (
            "D2_vcn_plus_pin",
            leaf,
            "",
            dict(
                ca_trust(),
                serverName="wrong.example",
                verifyPeerCertByName="test.example",
                pinnedPeerCertSha256=leaf_sha,
                fingerprint="chrome",
            ),
        ),
        (
            "D3_sni_mismatch_ca_trusted",
            leaf,
            "",
            dict(ca_trust(), serverName="wrong.example", fingerprint="chrome"),
        ),
        (
            "E1_pin_wrong",
            leaf,
            "",
            {"serverName": "test.example", "fingerprint": "chrome", "pinnedPeerCertSha256": self_sha},
        ),
        (
            "F1_alpn_explicit",
            leaf,
            "h2,http/1.1",
            dict(ca_trust(), serverName="test.example", fingerprint="chrome", alpn=["h2", "http/1.1"]),
        ),
        (
            "F2_alpn_h1_only",
            leaf,
            "http/1.1",
            dict(ca_trust(), serverName="test.example", fingerprint="chrome", alpn=["http/1.1"]),
        ),
        # F3：客户端不配 alpn —— 两边默认 ALPN 是否一致（Go GetTLSConfig 默认 h2,http/1.1）
        (
            "F3_alpn_default",
            leaf,
            "h2,http/1.1",
            dict(ca_trust(), serverName="test.example", fingerprint="chrome"),
        ),
        # G1：客户端 minVersion=1.3 硬门 vs 只支持 1.2 的服务端
        (
            "G1_min13_vs_server12",
            leaf,
            "",
            dict(ca_trust(), serverName="test.example", fingerprint="chrome", minVersion="1.3"),
            "TLSv1.2",
            "TLSv1.2",
        ),
        # G2：默认客户端 vs 只支持 1.2 的服务端（降级到 TLS1.2 时的套件对拍）
        (
            "G2_default_vs_server12",
            leaf,
            "",
            dict(ca_trust(), serverName="test.example", fingerprint="chrome"),
            "TLSv1.2",
            "TLSv1.2",
        ),
        # G1b/G3b：无指纹（真 crypto/tls vs rustls 路径）下的版本硬门
        (
            "G1b_min13_no_fp",
            leaf,
            "",
            dict(ca_trust(), serverName="test.example", minVersion="1.3"),
            "TLSv1.2",
            "TLSv1.2",
        ),
        (
            "G3b_max12_no_fp",
            leaf,
            "",
            dict(ca_trust(), serverName="test.example", maxVersion="1.2"),
            "TLSv1.3",
            "",
        ),
        # G3：客户端 maxVersion=1.2 vs 只支持 1.3 的服务端
        (
            "G3_max12_vs_server13",
            leaf,
            "",
            dict(ca_trust(), serverName="test.example", fingerprint="chrome", maxVersion="1.2"),
            "TLSv1.3",
            "",
        ),
    ]
    all_out = {}
    idx = 0
    for name, certpair, alpn, tls_settings, *extra in cases:
        min_ver = extra[0] if extra else "TLSv1.2"
        max_ver = extra[1] if len(extra) > 1 else ""
        if flt and flt not in name:
            idx += 1
            continue
        nm, res = run_case(name, certpair[0], certpair[1], alpn, tls_settings, idx, min_ver, max_ver)
        all_out[nm] = res
        idx += 1
        print(f"\n=== {nm} ===")
        for impl in ("go", "rust"):
            r = res[impl]
            srv = r["srv"] or {}
            print(
                f"  [{impl}] accepted={r['accepted']} socks={r['socks_reply']} "
                f"ver={srv.get('version')} cipher={srv.get('cipher')} alpn={srv.get('alpn')} "
                f"app_bytes={srv.get('app_bytes')} srv_err={srv.get('error')}"
            )
            for line in r["client_errors"][:3]:
                print(f"      ! {line}")
    (TMP / "e1_tls_results.json").write_text(json.dumps(all_out, indent=2), encoding="utf-8")
    print("\nwritten", TMP / "e1_tls_results.json")


if __name__ == "__main__":
    sys.exit(main())
