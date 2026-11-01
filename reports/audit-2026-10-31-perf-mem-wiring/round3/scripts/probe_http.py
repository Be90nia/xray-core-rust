"""专探：HTTP 入站错误响应对齐度（Go 400 vs Rust 静默关闭 / 反之）。"""
import os
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import GO, RUST, TMP, kill_proc  # noqa: E402

GO_PORT = 25038
RUST_PORT = 25078


class Server:
    def __init__(self, side, port, name):
        self.side = side
        self.port = port
        cfg = """{
  "log": {"loglevel": "debug"},
  "inbounds": [{"tag":"in-http","listen":"127.0.0.1","port":%d,
    "protocol":"http","settings":{}}],
  "outbounds": [{"tag":"out-free","protocol":"freedom","settings":{}}]
}""" % port
        self.path = os.path.join(TMP, name + ".json")
        open(self.path, "w", encoding="utf-8").write(cfg)
        exe = GO if side == "go" else RUST
        self.p = subprocess.Popen([exe, "run", "-c", self.path], stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, cwd=os.path.dirname(self.path))
        self.lines = []
        threading.Thread(target=self._reader, daemon=True).start()
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

    def stop(self):
        kill_proc(self.p)


def probe(port, payload, wait=1.5):
    out = {"resp": b"", "err": None, "closed": False}
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=4.0)
    except OSError as e:
        out["err"] = str(e)
        return out
    try:
        s.settimeout(wait)
        s.sendall(payload)
        buf = b""
        end = time.time() + wait
        while time.time() < end:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            except OSError as e:
                out["err"] = str(e)
                break
            if not b:
                out["closed"] = True
                break
            buf += b
        out["resp"] = buf
        return out
    finally:
        s.close()


CASES = [
    ("missing_host", b"GET / HTTP/1.1\r\n\r\n"),
    ("bad_content_length", b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: abc\r\n\r\n"),
    ("negative_content_length", b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n"),
    ("huge_content_length", b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 999999999999\r\n\r\n"),
    ("bad_version", b"GET / HTTP/9.9\r\nHost: a\r\n\r\n"),
    ("bad_method", b"BLAH / HTTP/1.1\r\nHost: a\r\n\r\n"),
    ("space_in_host", b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n"),
    ("no_crlf_end", b"GET / HTTP/1.1\r\nHost: a\r\n"),
    ("only_request_line", b"GET / HTTP/1.1\r\n"),
    ("connect_no_host", b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n"),
]


def main():
    for name, payload in CASES:
        row = {"case": name}
        for side, port in (("go", GO_PORT), ("rust", RUST_PORT)):
            srv = Server(side, port, "probe_http_%s_%s" % (side, name))
            if not srv.ready:
                row[side] = {"resp": "", "err": "not_ready"}
                srv.stop()
                continue
            r = probe(port, payload)
            time.sleep(0.2)
            row[side] = {"resp": r["resp"][:90].decode("utf-8", "replace").replace("\r\n", " | "),
                         "len": len(r["resp"]), "err": r["err"],
                         "log": "\n".join(srv.lines[-3:])[:400]}
            srv.stop()
        row["same"] = (row["go"].get("resp") == row["rust"].get("resp"))
        print("%-24s GO(%r) RUST(%r) %s" % (
            name, row["go"].get("resp", "")[:60], row["rust"].get("resp", "")[:60],
            "SAME" if row["same"] else "**DIFF**"), flush=True)
        if not row["same"]:
            print("   GO  :", repr(row["go"].get("log", "")[:260]))
            print("   RUST:", repr(row["rust"].get("log", "")[:260]))


if __name__ == "__main__":
    main()
