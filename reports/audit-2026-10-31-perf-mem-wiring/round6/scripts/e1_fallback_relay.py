#!/usr/bin/env python3
"""E1（决定性）：REALITY fallback 是否真的把客户端流量转发给 dest，并把 dest 响应回传。

客户端视角（探针 = 攻击者）：
  A) 明文 HTTP GET → 期望拿到 dest 的 HTTP 响应（Go 的 fallback 语义）
  B) TLS1.3 ClientHello（SNI 在白名单）→ 期望拿到 dest 的 HTTP 响应（明文回落）
两边都跑同样探针，记录客户端实际收到什么。

用法：python e1_fallback_relay.py
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
HTTP_RESP = b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\nDEST-HTML-OK"


def dest_srv(port, log_path, conns=6):
    """dest：把响应写回（HTTP 200 + body），记录收到的头 64 字节。"""
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            f"""
import json,socket,sys,time
srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
srv.bind(("127.0.0.1",{port})); srv.listen(8); srv.settimeout(25)
out=open(r"{log_path}","w")
resp={HTTP_RESP!r}
for i in range({conns}):
    try: c,_=srv.accept()
    except socket.timeout:
        out.write(json.dumps({{"n":i+1,"ok":False,"err":"accept timeout"}})+"\\n"); out.flush(); break
    c.settimeout(1.5); data=b""
    try:
        while len(data)<4096:
            ch=c.recv(4096)
            if not ch: break
            data+=ch
    except socket.timeout: pass
    out.write(json.dumps({{"n":i+1,"len":len(data),"head":data[:64].hex(),"ascii":data[:48].decode("latin1")}})+"\\n"); out.flush()
    try:
        c.sendall(resp)
        time.sleep(0.2)
        c.sendall(b"")
    except OSError as e:
        out.write(json.dumps({{"n":i+1,"send_err":str(e)}})+"\\n"); out.flush()
    time.sleep(0.2)
    c.close()
out.close(); srv.close()
""",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )


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


def probe_plain(port, wait=10.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=4)
    s.settimeout(wait)
    s.sendall(b"GET / HTTP/1.0\r\nHost: test.example\r\n\r\n")
    data = b""
    t0 = time.time()
    try:
        while len(data) < 4096:
            ch = s.recv(4096)
            if not ch:
                break
            data += ch
    except socket.timeout:
        pass
    dt = time.time() - t0
    s.close()
    return {"len": len(data), "ascii": data[:80].decode("latin1"), "hex": data[:48].hex(), "seconds": round(dt, 2)}


def probe_tls(port, sni="test.example", wait=10.0):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    raw = socket.create_connection(("127.0.0.1", port), timeout=4)
    raw.settimeout(wait)
    try:
        tls = ctx.wrap_socket(raw, server_hostname=sni)
        tls.settimeout(2.0)
        data = b""
        try:
            data = tls.recv(4096)
        except Exception:
            pass
        tls.close()
        return {"handshake": "ok", "len": len(data), "ascii": data[:80].decode("latin1")}
    except Exception as e:
        raw.close()
        return {"handshake": "failed", "error": f"{type(e).__name__}: {e}"}


def main():
    out = {}
    idx = 0
    for case, probe in (("plain_http", probe_plain), ("tls13_listed_sni", probe_tls)):
        out[case] = {}
        for impl_i, (impl, exe) in enumerate((("go", GO), ("rust", RS))):
            listen_port = 28550 + idx * 2 + impl_i
            dest_port = 28570 + idx * 2 + impl_i
            rid = str(int(time.time() * 1000))[-6:]
            dest_log = TMP / f"relay_{case}_{impl}_{rid}_dest.jsonl"
            dest = dest_srv(dest_port, str(dest_log).replace("\\", "/"))
            time.sleep(0.4)
            cfg = TMP / f"relay_{case}_{impl}_{rid}.json"
            cfg.write_text(json.dumps(server_cfg(listen_port, dest_port), indent=2), encoding="utf-8")
            logp = TMP / f"relay_{case}_{impl}_{rid}.log"
            lf = open(logp, "w", encoding="utf-8")
            srv = subprocess.Popen([exe, "run", "-c", str(cfg)], stdout=lf, stderr=subprocess.STDOUT)
            up = wait_port(listen_port)
            res = {"listen": up}
            if up:
                time.sleep(0.2)
                res["probe"] = probe(listen_port, 10.0)
            time.sleep(1.5)
            lf.close()
            res["dest"] = []
            if dest_log.exists():
                for line in dest_log.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.strip():
                        res["dest"].append(json.loads(line))
            txt = logp.read_text(encoding="utf-8", errors="replace")
            res["log"] = [l.strip()[:180] for l in txt.splitlines() if "REALITY" in l or "reality" in l][-5:]
            srv.kill()
            srv.wait()
            dest.kill()
            dest.wait()
            out[case][impl] = res
            for _ in range(30):
                try:
                    socket.create_connection(("127.0.0.1", listen_port), timeout=0.2).close()
                    time.sleep(0.1)
                except OSError:
                    break
        idx += 1
        print(f"\n=== {case} ===")
        for impl in ("go", "rust"):
            r = out[case][impl]
            print(f"  [{impl}] probe={json.dumps(r.get('probe'), ensure_ascii=False)}")
            for d in r.get("dest", []):
                print(f"      dest#{d.get('n')}: len={d.get('len')} ascii={d.get('ascii')!r}")
            for line in r.get("log", []):
                print(f"      . {line}")
    (TMP / "e1_fallback_relay_results.json").write_text(json.dumps(out, indent=2), encoding="utf-8", errors="replace")
    print("\nwritten e1_fallback_relay_results.json")


if __name__ == "__main__":
    sys.exit(main())
