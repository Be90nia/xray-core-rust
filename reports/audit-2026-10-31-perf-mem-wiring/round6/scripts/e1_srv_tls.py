#!/usr/bin/env python3
"""E1：服务端（入站）TLS 面语义对拍：无证书 / rejectUnknownSni / minVersion 门。

用法：python e1_srv_tls.py
"""
import json
import pathlib
import socket
import ssl
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


def f(n):
    return str(FIX / n).replace("\\", "/")


def server_cfg(port, tls_settings):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [
            {
                "tag": "in",
                "port": port,
                "listen": "127.0.0.1",
                "protocol": "vless",
                "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_settings},
            }
        ],
        "outbounds": [{"protocol": "freedom"}],
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


def tls_probe(port, sni, max_ver=None, min_ver=None, timeout=4.0):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if max_ver:
        ctx.maximum_version = max_ver
    if min_ver:
        ctx.minimum_version = min_ver
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    except OSError as e:
        return {"error": f"connect: {e}"}
    try:
        tls = ctx.wrap_socket(raw, server_hostname=sni)
        cert = tls.getpeercert()
        ver = tls.version()
        cipher = tls.cipher()[0] if tls.cipher() else None
        alpn = tls.selected_alpn_protocol()
        tls.close()
        return {"handshake": "ok", "version": ver, "cipher": cipher, "alpn": alpn, "peer_cert": cert}
    except Exception as e:
        try:
            raw.close()
        except Exception:
            pass
        return {"handshake": "failed", "error": f"{type(e).__name__}: {e}"}


CASES = {
    # 1) 入站 TLS 无证书
    "srv_no_certificates": ({"serverName": "test.example"}, lambda p: tls_probe(p, "test.example")),
    # 2) 有证书 + 客户端 SNI 不匹配（rejectUnknownSni 缺省 false）
    "srv_sni_mismatch_default": (
        {"certificates": [{"certificateFile": f("leaf.pem"), "keyFile": f("leaf.key")}]},
        lambda p: tls_probe(p, "other.example"),
    ),
    # 3) 有证书 + rejectUnknownSni=true + 客户端 SNI 不匹配
    "srv_reject_unknown_sni": (
        {
            "certificates": [{"certificateFile": f("leaf.pem"), "keyFile": f("leaf.key")}],
            "rejectUnknownSni": True,
        },
        lambda p: tls_probe(p, "other.example"),
    ),
    # 4) 服务端 minVersion=1.3 + 客户端只能 1.2
    "srv_min13_vs_client12": (
        {
            "certificates": [{"certificateFile": f("leaf.pem"), "keyFile": f("leaf.key")}],
            "minVersion": "1.3",
        },
        lambda p: tls_probe(p, "test.example", max_ver=ssl.TLSVersion.TLSv1_2),
    ),
    # 5) 服务端 maxVersion=1.2 + 默认客户端（看是否真的降到 1.2）
    "srv_max12": (
        {
            "certificates": [{"certificateFile": f("leaf.pem"), "keyFile": f("leaf.key")}],
            "maxVersion": "1.2",
        },
        lambda p: tls_probe(p, "test.example"),
    ),
}


def main():
    flt = sys.argv[1] if len(sys.argv) > 1 else ""
    out = {}
    idx = 0
    for name, (tls_settings, probe) in CASES.items():
        if flt and flt not in name:
            idx += 1
            continue
        out[name] = {}
        for impl_i, (impl, exe) in enumerate((("go", GO), ("rust", RS))):
            port = 28590 + idx * 2 + impl_i
            cfg = TMP / f"{name}_{impl}.json"
            cfg.write_text(json.dumps(server_cfg(port, tls_settings), indent=2), encoding="utf-8")
            logp = TMP / f"{name}_{impl}.log"
            lf = open(logp, "w", encoding="utf-8")
            proc = subprocess.Popen([exe, "run", "-c", str(cfg)], stdout=lf, stderr=subprocess.STDOUT)
            up = wait_port(port)
            res = {"listen": up}
            if up:
                time.sleep(0.2)
                res["probe"] = probe(port)
            time.sleep(0.4)
            lf.close()
            txt = logp.read_text(encoding="utf-8", errors="replace")
            res["log_tail"] = [l.strip()[:200] for l in txt.splitlines()[-5:]]
            proc.kill()
            proc.wait()
            # 等端口释放
            for _ in range(30):
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                    time.sleep(0.1)
                except OSError:
                    break
            out[name][impl] = res
        idx += 1
        print(f"\n=== {name} ===")
        for impl in ("go", "rust"):
            r = out[name][impl]
            pr = r.get("probe") or {}
            pc = pr.get("peer_cert")
            print(
                f"  [{impl}] listen={r['listen']} hs={pr.get('handshake')} ver={pr.get('version')} "
                f"cipher={pr.get('cipher')} cert_subject={pc and pc.get('subject')} "
                f"san={pc and pc.get('subjectAltName')} err={pr.get('error')}"
            )
            for line in r["log_tail"][-2:]:
                print(f"      . {line}")
    (TMP / "e1_srv_tls_results.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("\nwritten", TMP / "e1_srv_tls_results.json")


if __name__ == "__main__":
    sys.exit(main())
