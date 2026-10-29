"""对拍源站（CI 裁剪版）：母本 reports/audit-2026-10-29/tmp/origin2699.py。

对拍矩阵只消费 /cl 与默认分支，其余端点（/chunked /100 /gzip /big 等）裁掉；
请求头原文照旧落 jsonl——这是「解析后真的转发了吗」的独立观测面。
用法：python origin.py <port> <logpath>
"""
import json
import socket
import sys
import threading
import time

HOST = "127.0.0.1"
PORT = 18080
LOG = None
_lock = threading.Lock()

BODY = b"hello-from-origin"


def log_req(entry):
    if not LOG:
        return
    with _lock:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")


def read_head(conn):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = conn.recv(65536)
        if not d:
            return None
        buf += d
    return buf


def body_rest(head_buf, conn):
    """把声明的 body 读掉（尽力），返回 head 之后的残留字节。"""
    head, _, rest = head_buf.partition(b"\r\n\r\n")
    text = head.decode("utf-8", "replace")
    clen = None
    chunked = False
    for line in text.split("\r\n")[1:]:
        low = line.lower()
        if low.startswith("content-length:"):
            try:
                clen = int(line.split(":", 1)[1].strip())
            except ValueError:
                clen = None
        elif low.startswith("transfer-encoding:") and "chunked" in low:
            chunked = True
    if chunked:
        buf = rest
        while True:
            while b"\r\n" not in buf:
                d = conn.recv(65536)
                if not d:
                    return b"", text
                buf += d
            size_line, _, buf = buf.partition(b"\r\n")
            try:
                n = int(size_line.split(b";")[0], 16)
            except ValueError:
                return buf, text
            need = n + 2
            while len(buf) < need:
                d = conn.recv(65536)
                if not d:
                    return b"", text
                buf += d
            buf = buf[need:]
            if n == 0:
                return buf, text
    if clen:
        buf = rest
        while len(buf) < clen:
            d = conn.recv(65536)
            if not d:
                return b"", text
            buf += d
        return buf[clen:], text
    return rest, text


def respond(path, conn):
    """返回 True = 保持连接继续服务。"""
    if path.startswith("/cl"):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n%s"
                     % (len(BODY), BODY))
        return True
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(BODY), BODY))
    return True


def handle(conn):
    try:
        conn.settimeout(30)
        keep = True
        while keep:
            buf = read_head(conn)
            if buf is None:
                return
            head = buf.split(b"\r\n\r\n", 1)[0]
            text = head.decode("utf-8", "replace")
            parts = text.split(" ")
            path = parts[1] if len(parts) > 1 else "/"
            rest, text = body_rest(buf, conn)
            log_req({
                "t": time.time(),
                "port": conn.getsockname()[1],
                "peer": "%s:%d" % conn.getpeername(),
                "head": text,
                "leftover": rest[:200].decode("latin-1"),
            })
            keep = respond(path, conn)
            if keep and b"close" in text.lower():
                keep = False
            if rest:
                # 有 pipelined 残留：交给下一轮
                conn = _Replay(conn, rest)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


class _Replay:
    """把已读出的残留字节注入回流的极简包装（pipelined 请求用）。"""

    def __init__(self, conn, data):
        self._c = conn
        self._buf = data
        self._closed = False

    def recv(self, n):
        if self._buf:
            out, self._buf = self._buf[:n], self._buf[n:]
            return out
        return self._c.recv(n)

    def sendall(self, d):
        return self._c.sendall(d)

    def settimeout(self, t):
        return self._c.settimeout(t)

    def getpeername(self):
        return self._c.getpeername()

    def getsockname(self):
        return self._c.getsockname()

    def close(self):
        if not self._closed:
            self._closed = True
            return self._c.close()


def main():
    global PORT, LOG
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])
    if len(sys.argv) > 2:
        LOG = sys.argv[2]
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(128)
    print(f"origin listening on {HOST}:{PORT} log={LOG}", flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
