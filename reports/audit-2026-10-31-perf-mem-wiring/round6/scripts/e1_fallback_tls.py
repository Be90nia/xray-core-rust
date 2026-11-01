#!/usr/bin/env python3
"""E1（决定性）：REALITY fallback 是否把探针转成「真正的 dest 站点」。

dest = 真实 TLS 服务器（自签 test.example 证书，与 REALITY 自签证书不同）。
探针 = 普通 TLS 客户端（不做 REALITY 认证）。
期望（Go 的「偷自己」语义）：probe 的 TLS 握手**对着 dest 完成**，看到 dest 的证书。

用法：python e1_fallback_tls.py
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
PRIV = (FIX / "reality_priv.b64").read_text().strip()


def server_cfg(listen_port, dest_port):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [
            {
                "tag": "r-in",
                "port": listen_port,
                "listen": "127.0.0.1",
                "protocol": "vless",
                "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "target": dest_port,
                        "xver": 0,
                        "serverNames": ["test.example"],
                        "privateKey": PRIV,
                        "shortIds": [""],
                    },
                },
            }
        ],
        "outbounds": [{"protocol": "freedom"}],
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


def probe_tls(port, sni, wait=8.0):
    """普通 TLS 客户端探针：能看到 dest 的证书 = fallback 真的转发了。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    except OSError as e:
        return {"result": "connect_failed", "error": str(e)}
    raw.settimeout(wait)
    try:
        tls = ctx.wrap_socket(raw, server_hostname=sni)
    except Exception as e:
        try:
            raw.close()
        except Exception:
            pass
        return {"result": "handshake_failed", "error": f"{type(e).__name__}: {e}"}
    info = {"result": "handshake_ok"}
    try:
        import hashlib

        info["version"] = tls.version()
        der = tls.getpeercert(binary_form=True)
        info["peer_cert_sha256"] = hashlib.sha256(der).hexdigest() if der else None
        want = (FIX / "selfsigned.sha256").read_text().strip()
        info["peer_cert_is_dest_site_cert"] = info["peer_cert_sha256"] == want
        info["cipher"] = tls.cipher()[0] if tls.cipher() else None
    except Exception as e:
        info["meta_error"] = str(e)
    try:
        tls.close()
    except Exception:
        pass
    return info


def main():
    out = {}
    idx = 0
    for sni_label, sni in (("sni_listed", "test.example"), ("sni_unlisted", "other.example")):
        out[sni_label] = {}
        for impl_i, (impl, exe) in enumerate((("go", GO), ("rust", RS))):
            listen_port = 28550 + idx * 2 + impl_i
            dest_port = 28570 + idx * 2 + impl_i
            rid = str(int(time.time() * 1000))[-6:]
            dest_log = TMP / f"fbtls_{sni_label}_{impl}_{rid}_dest.jsonl"
            dest = subprocess.Popen(
                [
                    sys.executable,
                    str(HERE / "tls_dest_threaded.py"),
                    "--port",
                    str(dest_port),
                    "--cert",
                    str(FIX / "selfsigned.pem"),
                    "--key",
                    str(FIX / "selfsigned.key"),
                    "--out",
                    str(dest_log),
                    "--seconds",
                    "20",
                ],
                cwd=str(HERE),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
            )
            time.sleep(0.4)
            cfg = TMP / f"fbtls_{sni_label}_{impl}_{rid}.json"
            cfg.write_text(json.dumps(server_cfg(listen_port, dest_port), indent=2), encoding="utf-8")
            logp = TMP / f"fbtls_{sni_label}_{impl}_{rid}.log"
            lf = open(logp, "w", encoding="utf-8")
            srv = subprocess.Popen([exe, "run", "-c", str(cfg)], stdout=lf, stderr=subprocess.STDOUT)
            up = wait_port(listen_port)
            res = {"listen": up}
            if up:
                time.sleep(0.2)
                res["probe"] = probe_tls(listen_port, sni)
            time.sleep(1.5)
            lf.close()
            res["dest"] = []
            if dest_log.exists():
                for line in dest_log.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.strip():
                        res["dest"].append(json.loads(line))
            txt = logp.read_text(encoding="utf-8", errors="replace")
            res["log"] = [l.strip()[:170] for l in txt.splitlines() if "REALITY" in l or "reality" in l][-4:]
            srv.kill()
            srv.wait()
            dest.kill()
            dest.wait()
            out[sni_label][impl] = res
            for _ in range(30):
                try:
                    socket.create_connection(("127.0.0.1", listen_port), timeout=0.2).close()
                    time.sleep(0.1)
                except OSError:
                    break
        idx += 1
        print(f"\n=== {sni_label} (sni={sni}) ===")
        for impl in ("go", "rust"):
            r = out[sni_label][impl]
            print(f"  [{impl}] probe={json.dumps(r.get('probe'), ensure_ascii=False)}")
            for d in r.get("dest", []):
                print(
                    f"      dest#{d.get('conn')}: ok={d.get('ok')} ver={d.get('version')} "
                    f"alpn={d.get('alpn')} app_bytes={d.get('app_bytes')} err={str(d.get('error'))[:60]}"
                )
            for line in r.get("log", []):
                print(f"      . {line}")
    (TMP / "e1_fallback_tls_results.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print("\nwritten e1_fallback_tls_results.json")


if __name__ == "__main__":
    sys.exit(main())
