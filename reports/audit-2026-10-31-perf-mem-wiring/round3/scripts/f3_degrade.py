"""族 3：错误与降级语义双跑差分。

观测点 = 最终用户可见结果（直连/阻断/超时/错误码/连接关闭）× 两侧是否一致。
所有用例共用同一份客户端字节（自写 SOCKS5 客户端），两侧服务端配置仅端口不同。
"""
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import GO, RUST, TMP, kill_proc  # noqa: E402

GO_PORT = 25030
RUST_PORT = 25070
ECHO_PORT = 25031  # 本地回显服务，两侧共用
DEAD_PORT = 25032  # 无人监听的端口（拨号失败用）


class EchoServer:
    def __init__(self, port):
        self.s = socket.socket()
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("127.0.0.1", port))
        self.s.listen(64)
        self.stop_flag = False
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _loop(self):
        self.s.settimeout(0.5)
        while not self.stop_flag:
            try:
                c, _ = self.s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            c.settimeout(10)
            while True:
                b = c.recv(65536)
                if not b:
                    break
                c.sendall(b)
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def stop(self):
        self.stop_flag = True
        try:
            self.s.close()
        except OSError:
            pass


class Server:
    def __init__(self, side, cfg_obj, port, name):
        self.side = side
        self.port = port
        self.path = os.path.join(TMP, name + ".json")
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(cfg_obj, f, indent=2)
        exe = GO if side == "go" else RUST
        self.p = subprocess.Popen([exe, "run", "-c", self.path],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  cwd=os.path.dirname(self.path))
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

    def alive(self):
        return self.p.poll() is None

    def stop(self):
        kill_proc(self.p)


# --------- 自写 SOCKS5 客户端（两侧用同一份字节） ---------
def socks5_connect(proxy_port, host, port, timeout=6.0, send_payload=b"ping\n"):
    """返回 dict: stage / socks_reply / data / error。"""
    out = {"stage": "connect", "socks_reply": None, "data": b"", "error": None,
           "elapsed": 0.0}
    t0 = time.time()
    try:
        s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    except OSError as e:
        out["stage"] = "tcp_connect_failed"
        out["error"] = str(e)
        out["elapsed"] = round(time.time() - t0, 2)
        return out
    try:
        s.settimeout(timeout)
        s.sendall(bytes([5, 1, 0]))
        resp = s.recv(2)
        if len(resp) < 2 or resp[0] != 5:
            out["stage"] = "handshake_failed"
            out["socks_reply"] = resp.hex()
            return out
        if resp[1] != 0:
            out["stage"] = "auth_rejected"
            out["socks_reply"] = resp.hex()
            return out
        out["stage"] = "authenticated"
        # CONNECT 请求
        if isinstance(host, str):
            hb = host.encode()
            req = bytes([5, 1, 0, 3, len(hb)]) + hb + struct.pack(">H", port)
        else:
            req = bytes([5, 1, 0, 1]) + host + struct.pack(">H", port)
        s.sendall(req)
        # SOCKS5 reply: VER REP RSV ATYP BND.ADDR BND.PORT（IPv4 = 10 字节）
        rep = b""
        while len(rep) < 4:
            b = s.recv(4 - len(rep))
            if not b:
                break
            rep += b
        if len(rep) < 4:
            out["stage"] = "reply_truncated"
            out["socks_reply"] = rep.hex()
            return out
        atyp = rep[3]
        addr_len = {1: 4, 4: 16}.get(atyp, 0)
        if atyp == 3:
            alen = s.recv(1)
            if not alen:
                out["stage"] = "reply_truncated"
                out["socks_reply"] = rep.hex()
                return out
            addr_len = alen[0]
        need = 4 + addr_len + 2
        while len(rep) < need:
            b = s.recv(need - len(rep))
            if not b:
                break
            rep += b
        out["socks_reply"] = rep.hex()
        out["socks_reply_code"] = rep[1]
        if rep[1] != 0:
            out["stage"] = "connect_refused"
            return out
        out["stage"] = "connected"
        try:
            s.sendall(send_payload)
            data = s.recv(4096)
            out["data"] = data
        except OSError as e:
            out["error"] = "io: %s" % e
        return out
    except OSError as e:
        out["error"] = str(e)
        return out
    finally:
        out["elapsed"] = round(time.time() - t0, 2)
        try:
            s.close()
        except OSError:
            pass


# ---------------- 配置 ----------------
def cfg(inbound_port, routing=None, outbounds=None, dns=None, loglevel="debug"):
    c = {
        "log": {"loglevel": loglevel},
        "inbounds": [{"tag": "in-socks", "listen": "127.0.0.1", "port": inbound_port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": outbounds or [{"tag": "out-free", "protocol": "freedom",
                                    "settings": {}}],
    }
    if routing is not None:
        c["routing"] = routing
    if dns is not None:
        c["dns"] = dns
    return c


CASES = []


def add(name, cfgfn, host, port, note="", payload=b"ping\n", timeout=6.0):
    CASES.append({"name": name, "cfgfn": cfgfn, "host": host, "port": port,
                  "note": note, "payload": payload, "timeout": timeout})


add("plain_freedom_ipv4", lambda p: cfg(p), "127.0.0.1", ECHO_PORT, "基线：socks→freedom→echo")
add("plain_freedom_ipv6_literal", lambda p: cfg(p), "::1", ECHO_PORT, "IPv6 字面量目标")
add("dead_target_refused", lambda p: cfg(p), "127.0.0.1", DEAD_PORT, "目标端口无人监听")
add("routing_match_to_free", lambda p: cfg(
    p, routing={"domainStrategy": "AsIs", "rules": [
        {"type": "field", "ip": ["127.0.0.1"], "outboundTag": "out-free"}]},
    outbounds=[{"tag": "out-free", "protocol": "freedom", "settings": {}}]),
    "127.0.0.1", ECHO_PORT, "路由规则命中")
add("routing_match_to_blackhole", lambda p: cfg(
    p, routing={"domainStrategy": "AsIs", "rules": [
        {"type": "field", "ip": ["127.0.0.1"], "outboundTag": "out-black"}]},
    outbounds=[{"tag": "out-free", "protocol": "freedom", "settings": {}},
               {"tag": "out-black", "protocol": "blackhole", "settings": {}}]),
    "127.0.0.1", ECHO_PORT, "路由命中 blackhole")
add("routing_match_to_nonexistent_outbound", lambda p: cfg(
    p, routing={"domainStrategy": "AsIs", "rules": [
        {"type": "field", "ip": ["127.0.0.1"], "outboundTag": "out-nope"}]},
    outbounds=[{"tag": "out-free", "protocol": "freedom", "settings": {}}]),
    "127.0.0.1", ECHO_PORT, "路由引用不存在的 outboundTag")
add("routing_no_match_default_outbound", lambda p: cfg(
    p, routing={"domainStrategy": "AsIs", "rules": [
        {"type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "out-free"}]},
    outbounds=[{"tag": "out-free", "protocol": "freedom", "settings": {}}]),
    "127.0.0.1", ECHO_PORT, "路由不命中 → 默认出站")
add("routing_domain_match_needs_dns", lambda p: cfg(
    p, routing={"domainStrategy": "AsIs", "rules": [
        {"type": "field", "domain": ["example.com"], "outboundTag": "out-free"}]},
    outbounds=[{"tag": "out-free", "protocol": "freedom", "settings": {}}]),
    "localhost", ECHO_PORT, "路由按域名匹配（localhost）")
add("dns_dead_server_domain", lambda p: cfg(
    p, dns={"servers": ["127.0.0.1:1"], "queryStrategy": "UseIP"},
    outbounds=[{"tag": "out-free", "protocol": "freedom",
                "settings": {"domainStrategy": "UseIP"}}]),
    "example.invalid", 80, "DNS 服务器不可达 + freedom UseIP")
add("dns_no_server_config", lambda p: cfg(
    p, outbounds=[{"tag": "out-free", "protocol": "freedom",
                   "settings": {"domainStrategy": "UseIP"}}]),
    "example.invalid", 80, "无 dns 配置 + freedom UseIP")
add("outbound_dial_failure_socks", lambda p: cfg(
    p, outbounds=[{"tag": "out-free", "protocol": "freedom", "settings": {}},
                  {"tag": "out-socks", "protocol": "socks",
                   "settings": {"servers": [{"address": "127.0.0.1", "port": DEAD_PORT}]}}]),
    "127.0.0.1", ECHO_PORT, "出站 socks 指向死端口")
add("outbound_dial_failure_vmess", lambda p: cfg(
    p, outbounds=[{"tag": "out-free", "protocol": "freedom", "settings": {}},
                  {"tag": "out-vmess", "protocol": "vmess",
                   "settings": {"vnext": [{"address": "127.0.0.1", "port": DEAD_PORT,
                                           "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}]),
    "127.0.0.1", ECHO_PORT, "出站 vmess 指向死端口")
add("outbound_first_is_dead_socks", lambda p: cfg(
    p, outbounds=[{"tag": "out-socks", "protocol": "socks",
                   "settings": {"servers": [{"address": "127.0.0.1", "port": DEAD_PORT}]}},
                  {"tag": "out-free", "protocol": "freedom", "settings": {}}]),
    "127.0.0.1", ECHO_PORT, "第一个出站即死（默认出站不可用）")
add("blackhole_only_outbound", lambda p: cfg(
    p, outbounds=[{"tag": "out-black", "protocol": "blackhole", "settings": {}}]),
    "127.0.0.1", ECHO_PORT, "唯一出站是 blackhole")
add("proxy_chain_freedom_to_dead", lambda p: cfg(
    p, outbounds=[{"tag": "out-socks", "protocol": "socks",
                   "settings": {"servers": [{"address": "127.0.0.1", "port": DEAD_PORT}]}},
                  {"tag": "out-chain", "protocol": "freedom",
                   "settings": {"proxySettings": {"tag": "out-socks"}}}]),
    "127.0.0.1", ECHO_PORT, "代理链：freedom → 死 socks")
add("target_unroutable_ip", lambda p: cfg(p), "192.0.2.1", 80, "不可路由目标（超时）", timeout=4.0)


def main():
    echo = EchoServer(ECHO_PORT)
    results = []
    try:
        for c in CASES:
            row = {"case": c["name"], "note": c["note"]}
            for side, port in (("go", GO_PORT), ("rust", RUST_PORT)):
                cfgobj = c["cfgfn"](port)
                srv = Server(side, cfgobj, port, "f3_%s_%s" % (side, c["name"]))
                obs = {"ready": srv.ready, "alive": srv.alive()}
                if srv.ready:
                    r = socks5_connect(port, c["host"], c["port"],
                                       timeout=c["timeout"], send_payload=c["payload"])
                    obs.update({
                        "stage": r["stage"],
                        "reply_code": r.get("socks_reply_code"),
                        "reply_hex": r.get("socks_reply"),
                        "data": r["data"][:64].hex(),
                        "error": r["error"],
                        "elapsed": r["elapsed"],
                    })
                    time.sleep(0.3)
                obs["server_alive"] = srv.alive()
                obs["server_exit"] = srv.p.poll()
                obs["log_tail"] = "\n".join(srv.lines[-8:])[:1200]
                srv.stop()
                row[side] = obs
            row["same"] = (
                row["go"].get("stage") == row["rust"].get("stage")
                and row["go"].get("reply_code") == row["rust"].get("reply_code")
                and row["go"].get("data") == row["rust"].get("data")
                and row["go"].get("server_alive") == row["rust"].get("server_alive")
            )
            results.append(row)
            print("%-38s GO(%s rc=%s) RUST(%s rc=%s) %s" % (
                c["name"], row["go"].get("stage"), row["go"].get("reply_code"),
                row["rust"].get("stage"), row["rust"].get("reply_code"),
                "SAME" if row["same"] else "**DIFF**"), flush=True)
    finally:
        echo.stop()
    with open(os.path.join(TMP, "f3_results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print("\nF3 total=%d diff=%d" % (len(results), sum(1 for r in results if not r["same"])))


if __name__ == "__main__":
    main()
