#!/usr/bin/env python3
"""E1：REALITY 服务端 fallback 行为对拍（Go 26.10.17 vs Rust）。

同一份 realitySettings（dest=本地目标服务器、serverNames=["test.example"]、shortIds=[""]）
分别由 Go / Rust 起 vless+reality 入站，用同样的畸形/伪造 ClientHello 探测，
对比：dest 收到的字节、探测端看到的结果、服务端日志。

用法：python e1_reality_fb.py [case_filter]
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
                "settings": {
                    "clients": [{"id": UUID}],
                    "decryption": "none",
                },
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


def wait_log(path, patterns, timeout=15.0):
    """等服务端日志出现监听行（不用探活连接——那会白占一个 dest 连接，污染对拍）。"""
    end = time.time() + timeout
    while time.time() < end:
        try:
            txt = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            txt = ""
        if any(pt in txt for pt in patterns):
            return True
        time.sleep(0.1)
    return False




def wait_port(port, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.4):
                return True
        except OSError:
            time.sleep(0.1)
    return False



def probe_raw(port, payload, read_timeout=2.0):
    """发原始字节，读回响应。"""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=4.0)
    except OSError as e:
        return {"error": f"connect: {e}"}
    s.settimeout(read_timeout)
    try:
        s.sendall(payload)
    except OSError as e:
        return {"error": f"send: {e}"}
    data = b""
    try:
        while len(data) < 512:
            chunk = s.recv(512)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    except OSError as e:
        s.close()
        return {"recv_error": str(e), "data_len": len(data), "data_head": data[:32].hex()}
    s.close()
    return {"data_len": len(data), "data_head": data[:32].hex(), "data_ascii": data[:48].decode("latin1")}


def probe_tls(port, sni, max_ver=None, min_ver=None):
    """用 python ssl 发真实 ClientHello（TLS1.3 / 可指定版本），返回客户端结果。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if max_ver:
        ctx.maximum_version = max_ver
    if min_ver:
        ctx.minimum_version = min_ver
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=4.0)
    except OSError as e:
        return {"error": f"connect: {e}"}
    try:
        tls = ctx.wrap_socket(raw, server_hostname=sni if sni else None)
        try:
            ver = tls.version()
            cipher = tls.cipher()[0] if tls.cipher() else None
        except Exception:
            ver = cipher = None
        tls.close()
        return {"handshake": "ok", "version": ver, "cipher": cipher}
    except Exception as e:
        try:
            raw.close()
        except Exception:
            pass
        return {"handshake": "failed", "error": f"{type(e).__name__}: {e}"}


CASES = {
    "garbage_http": lambda port: probe_raw(port, b"GET / HTTP/1.0\r\nHost: test.example\r\n\r\n"),
    "tiny_3bytes": lambda port: probe_raw(port, b"\x16\x03\x01"),
    "random_bytes": lambda port: probe_raw(port, bytes(range(64))),
    "tls13_sni_listed": lambda port: probe_tls(port, "test.example", min_ver=ssl.TLSVersion.TLSv1_3),
    "tls13_sni_unlisted": lambda port: probe_tls(port, "other.example", min_ver=ssl.TLSVersion.TLSv1_3),
    "tls13_no_sni": lambda port: probe_tls(port, None, min_ver=ssl.TLSVersion.TLSv1_3),
    "tls12_sni_listed": lambda port: probe_tls(port, "test.example", max_ver=ssl.TLSVersion.TLSv1_2),
    "tls13_h2_alpn": lambda port: probe_tls_alpn(port, "test.example", ["h2", "http/1.1"]),
}


def probe_tls_alpn(port, sni, alpn):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(alpn)
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=4.0)
    except OSError as e:
        return {"error": f"connect: {e}"}
    try:
        tls = ctx.wrap_socket(raw, server_hostname=sni)
        try:
            info = {"handshake": "ok", "version": tls.version(), "alpn": tls.selected_alpn_protocol()}
        except Exception:
            info = {"handshake": "ok"}
        tls.close()
        return info
    except Exception as e:
        try:
            raw.close()
        except Exception:
            pass
        return {"handshake": "failed", "error": f"{type(e).__name__}: {e}"}


def run_case(name, probe_fn, idx, dest_unreachable=False):
    # 端口走第二泳道 28550-28599（listen 28550-28569 / dest 28570-28589）
    listen_port = 28550 + idx
    dest_port = 28570 + idx
    run_id = str(int(time.time() * 1000))[-6:]
    dest_log = TMP / f"e1_rfb_{name}_{run_id}_dest.jsonl"
    srv_log = TMP / f"e1_rfb_{name}_{{impl}}_srv.log"
    results = {}
    procs = []
    for impl, exe in (("go", GO), ("rust", RS)):
        if dest_log.exists():
            dest_log.unlink()
        if not dest_unreachable:
            dest = subprocess.Popen(
                [
                    sys.executable,
                    str(HERE / "dest_srv.py"),
                    "--port",
                    str(dest_port),
                    "--conns",
                    "4",
                    "--out",
                    str(dest_log),
                ],
                cwd=str(HERE),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            procs.append(dest)
            time.sleep(0.3)
        cfg_path = TMP / f"e1_rfb_{name}_{run_id}_{impl}.json"
        cfg_path.write_text(json.dumps(server_cfg(listen_port, dest_port), indent=2), encoding="utf-8")
        logp = TMP / f"e1_rfb_{name}_{run_id}_{impl}_srv.log"
        lf = open(logp, "w", encoding="utf-8")
        srv = subprocess.Popen([exe, "run", "-c", str(cfg_path)], stdout=lf, stderr=subprocess.STDOUT)
        procs.append(srv)
        up = wait_port(listen_port, 15.0)
        if not up:
            results[impl] = {"error": "server never listened"}
            lf.close()
            srv.kill()
            srv.wait()
            continue
        time.sleep(0.3)
        probe = probe_fn(listen_port)
        time.sleep(2.5)
        dest_recs = []
        if dest_log.exists():
            for line in dest_log.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    dest_recs.append(json.loads(line))
        lf.close()
        log_text = logp.read_text(encoding="utf-8", errors="replace")
        results[impl] = {
            "listen": up,
            "probe": probe,
            "dests": dest_recs,
            "log_tail": [l.strip()[:220] for l in log_text.splitlines()[-6:]],
        }
        srv.kill()
        srv.wait()
        if not dest_unreachable:
            try:
                procs[-2].kill()
                procs[-2].wait()
            except Exception:
                pass
        time.sleep(0.3)
    return name, results


def main():
    flt = sys.argv[1] if len(sys.argv) > 1 else ""
    out = {}
    idx = 0
    for name, fn in CASES.items():
        if flt and flt not in name:
            idx += 1
            continue
        nm, res = run_case(name, fn, idx)
        out[nm] = res
        idx += 1
        print(f"\n=== {nm} ===")
        for impl in ("go", "rust"):
            r = res.get(impl, {})
            ds = r.get("dests") or []
            summary = [
                {"n": d.get("first_len"), "head": d.get("first_head"), "banner": d.get("sent_banner")}
                for d in ds
            ]
            print(f"  [{impl}] probe={r.get('probe')} dest_conns={summary}")
            for line in r.get("log_tail", [])[-3:]:
                print(f"      . {line}")
    if not flt:
        (TMP / "e1_reality_fb_results.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
        print("\nwritten", TMP / "e1_reality_fb_results.json")


if __name__ == "__main__":
    sys.exit(main())
