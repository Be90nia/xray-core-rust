"""hysteria UDP 三组互操作矩阵: Go<->Go 对照 / Rust client<->Go server / Go client<->Rust server.

每组双验收: TCP(经隧道取本地 HTTP 源站: /payload 大包字节+marker 一致, POST /echo 字节原样回显)
+ UDP(SOCKS5 UDP ASSOCIATE -> 本地 UDP echo, 多尺寸 payload 往返字节一致).
全部源站/回显均为 127.0.0.1 自建，零公网依赖（原公网探针已移除，见 bd fjbit）。
"""
import subprocess, time, os, json, sys, base64, hashlib, socket, struct, threading

RUST = 'dist/xray.exe'
# Go 对照二进制：允许 XRAY_GO 覆盖，否则取本机现存的第一个（xray_go.exe 为历史路径）
GO = os.environ.get('XRAY_GO') or next(
    (p for p in ('D:/tmp/xray_go.exe', 'D:/tmp/go2617/xray.exe') if os.path.exists(p)),
    'D:/tmp/xray_go.exe')
CERT = 'D:/tmp/interop_cert.pem'
KEY = 'D:/tmp/interop_key.pem'
with open(CERT) as _f:
    PIN = hashlib.sha256(base64.b64decode(
        ''.join(l for l in _f.read().splitlines() if '-----' not in l))).hexdigest()
AUTH = 'hys-udp-secret'
WORK = 'D:/tmp/interop_hy'
os.makedirs(WORK, exist_ok=True)

# 本地源站 payload: >5000B(原断言下限) + 确定性字节 + marker
PAYLOAD_MARKER = b'<<<HYSTERIA-INTEROP-MARKER>>>'
PAYLOAD = PAYLOAD_MARKER + bytes(range(256)) * 48


def hy_stream_go_srv():
    return {"network": "hysteria", "security": "tls",
            "hysteriaSettings": {"version": 2, "auth": AUTH},
            "tlsSettings": {"certificates": [{"certificateFile": CERT, "keyFile": KEY}]}}


def hy_stream_go_cli():
    return {"network": "hysteria", "security": "tls",
            "hysteriaSettings": {"version": 2, "auth": AUTH},
            "tlsSettings": {"serverName": "localhost", "pinnedPeerCertSha256": PIN}}


def build_configs(server_bin, P):
    """返回 (server_cfg, client_outbound)"""
    if server_bin == GO:
        si = {"listen": "127.0.0.1", "port": P, "protocol": "hysteria",
              "settings": {"version": 2, "users": [{"auth": AUTH}]},
              "streamSettings": hy_stream_go_srv()}
    else:  # Rust server: settings 内联 PEM（缺省自签但 Go client 需要 pin 固定证书）
        si = {"listen": "127.0.0.1", "port": P, "protocol": "hysteria",
              "settings": {"auth": AUTH, "server_name": "localhost",
                           "cert": open(CERT).read(), "key": open(KEY).read()}}
    scfg = {"log": {"loglevel": "info"}, "inbounds": [si],
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}
    if client_is_go(server_bin):
        raise ValueError("use build_client_outbound(client_bin, P) instead")
    return scfg, None


def client_is_go(server_bin):
    return False


def build_client_outbound(client_bin, P):
    if client_bin == GO:
        # Go HysteriaClientConfig: settings 平铺 version/address/port；auth 在 transport 层
        return {"protocol": "hysteria",
                "settings": {"version": 2, "address": "127.0.0.1", "port": P},
                "streamSettings": hy_stream_go_cli()}
    # Rust client: auth 在 servers[0]。Go dialer.go:327-330 语义：无 security=tls
    # 硬错拒启（2026-10-20 起 Rust 对齐）；自签证书走 Go 同款 pin（私有键 insecure
    # 已删除，bd qp0ya）。
    return {"protocol": "hysteria",
            "settings": {"servers": [{"address": "127.0.0.1", "port": P, "auth": AUTH}]},
            "streamSettings": {"network": "hysteria", "security": "tls",
                               "hysteriaSettings": {"version": 2},
                               "tlsSettings": {"serverName": "localhost",
                                               "pinnedPeerCertSha256": PIN}}}


def kill():
    # 本机 taskkill 偶发 >5s（无匹配进程时也走过 WMI 路径），超时只记不炸：
    # 真杀不掉会让后续 bind 失败并写进用例日志，不静默。
    for exe in ('xray.exe', 'xray-go.exe'):
        try:
            subprocess.run(['cmd', '/c', f'taskkill /F /IM {exe}'], capture_output=True, timeout=20)
        except subprocess.TimeoutExpired:
            print(f'  (warn: taskkill /IM {exe} 超时 20s)', flush=True)


class EchoServer:
    def __init__(self, port=0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _loop(self):
        self.sock.settimeout(0.3)
        while not self.stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
                self.sock.sendto(data, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self):
        self.stop.set()
        self.t.join(timeout=1)
        self.sock.close()


class LocalOrigin:
    """本地 HTTP 源站: GET /payload 返回带 marker 的固定大包, POST /echo 原样回显 body。

    替代原先的公网探针: 断言"经隧道把 TCP 字节原样送到源站并取回"这件事不变。
    """

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(8)
        self.stop = threading.Event()
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _loop(self):
        self.sock.settimeout(0.3)
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            conn.settimeout(10)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head, _, body = buf.partition(b"\r\n\r\n")
            parts = head.split(b" ")
            method, path = (parts[0], parts[1]) if len(parts) > 1 else (b"", b"")
            length = 0
            for line in head.split(b"\r\n")[1:]:
                k, _, v = line.partition(b":")
                if k.strip().lower() == b"content-length":
                    length = int(v.strip() or 0)
            while len(body) < length:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                body += chunk
            if path == b"/payload":
                status, resp = b"200 OK", PAYLOAD
            elif path == b"/echo" and method == b"POST":
                status, resp = b"200 OK", body
            else:
                status, resp = b"404 Not Found", b"not found"
            conn.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Length: " +
                         str(len(resp)).encode() + b"\r\nConnection: close\r\n\r\n" + resp)
        except (OSError, ValueError):
            pass
        finally:
            conn.close()

    def close(self):
        self.stop.set()
        self.t.join(timeout=1)
        self.sock.close()


def tcp_leg(socks_port, origin_port):
    """TCP 腿: 经隧道取 /payload(状态码+整包字节+marker) 并 POST /echo(4096B 原样回显)。"""
    problems = []
    bp = f"{WORK}/tcp_payload.body"
    r = subprocess.run(['curl', '-sS', '--max-time', '15', '-x', f'socks5://127.0.0.1:{socks_port}',
                        f'http://127.0.0.1:{origin_port}/payload', '-o', bp, '-w', '%{http_code}'],
                       capture_output=True, text=True, timeout=20)
    got = open(bp, 'rb').read() if os.path.exists(bp) else b''
    if r.stdout.strip() != '200':
        problems.append(f'payload http={r.stdout.strip() or r.stderr.strip()[:40]}')
    elif got != PAYLOAD:
        problems.append(f'payload {len(got)}B != {len(PAYLOAD)}B')
    send = bytes(range(256)) * 16
    sp, rp = f"{WORK}/tcp_echo.send", f"{WORK}/tcp_echo.recv"
    open(sp, 'wb').write(send)
    r = subprocess.run(['curl', '-sS', '--max-time', '15', '-x', f'socks5://127.0.0.1:{socks_port}',
                        '--data-binary', f'@{sp}', f'http://127.0.0.1:{origin_port}/echo',
                        '-o', rp, '-w', '%{http_code}'],
                       capture_output=True, text=True, timeout=20)
    recv = open(rp, 'rb').read() if os.path.exists(rp) else b''
    if r.stdout.strip() != '200':
        problems.append(f'echo http={r.stdout.strip() or r.stderr.strip()[:40]}')
    elif recv != send:
        problems.append(f'echo {len(recv)}B != {len(send)}B')
    if problems:
        return False, '; '.join(problems)[:120]
    return True, f'payload {len(PAYLOAD)}B 整包一致 + echo {len(send)}B 原样回显'


def _udp_associate(socks_port):
    """SOCKS5 UDP ASSOCIATE -> (relay_ip, relay_port, head, ctrl_sock, udp_sock)。"""
    s = socket.create_connection(("127.0.0.1", socks_port), timeout=5)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            raise RuntimeError("socks greeting failed")
        # DST 必须全零：Go 侧 ExpectedRemote 会按 DST 端口过滤来源（temp_udp_listen.go:44）
        s.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0))
        resp = b""
        while len(resp) < 4:
            chunk = s.recv(64)
            if not chunk:
                raise RuntimeError(f"associate closed early resp={resp.hex()}")
            resp += chunk
        need = {1: 10, 4: 22}.get(resp[3], 5 + resp[4] + 2)
        while len(resp) < need:
            resp += s.recv(64)
        if resp[1] != 0:
            raise RuntimeError(f"udp associate denied resp={resp.hex()[:40]}")
        atyp = resp[3]
        if atyp == 1:
            relay_ip, relay_port, head = socket.inet_ntoa(resp[4:8]), struct.unpack(">H", resp[8:10])[0], 10
        elif atyp == 4:
            relay_ip, relay_port, head = socket.inet_ntop(socket.AF_INET6, resp[4:20]), struct.unpack(">H", resp[20:22])[0], 22
        else:
            raise RuntimeError(f"unexpected atyp={atyp}")
    except BaseException:
        s.close()
        raise
    if relay_ip == "0.0.0.0":
        relay_ip = "127.0.0.1"
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(6)
    return relay_ip, relay_port, head, s, u


def socks_udp_roundtrip(socks_port, echo_port, sizes=(64, 1024)):
    """SOCKS5 UDP ASSOCIATE -> echo -> 逐字节对比. 返回 (ok, err)"""
    s = u = None
    try:
        relay_ip, relay_port, head, s, u = _udp_associate(socks_port)
        for size in sizes:
            payload = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
            pkt = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", echo_port) + payload
            u.sendto(pkt, (relay_ip, relay_port))
            data, _ = u.recvfrom(65535)
            if data[head:] != payload:
                return False, f"echo mismatch size={size} got={len(data) - head}B"
        return True, "2 sizes roundtrip byte-identical"
    except Exception as e:
        return False, str(e)[:80]
    finally:
        if u:
            u.close()
        if s:
            s.close()


def oversize_probe(socks_port, echo_port, size=4096):
    """附加信息，不判 FAIL：>Go server MaxDatagramFrameSize=1200 的回包 Go server 侧无分片逻辑
    （client.go UDPWriter 仅 client 有 TooLarge 分片），真实网络 1500 MTU 下同样发不出。

    必须排在全部判定之后单独跑：Rust 侧按 PROTOCOL_VIOLATION 拆掉整条 QUIC 连接
    （quinn oversized datagram），跑在前面会毒化 TCP/UDP 两条腿（bd fjbit）。
    """
    s = u = None
    try:
        relay_ip, relay_port, head, s, u = _udp_associate(socks_port)
        payload = bytes(range(256)) * (size // 256)
        pkt = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", echo_port) + payload
        u.sendto(pkt, (relay_ip, relay_port))
        data, _ = u.recvfrom(65535)
        return "OK" if data[head:] == payload else "mismatch"
    except Exception:
        return "dropped(go 1200 cap)"
    finally:
        if u:
            u.close()
        if s:
            s.close()


def run_one(idx, server_bin, client_bin, tag):
    P = 18500 + idx * 10
    S = P + 1
    E = P + 2
    scfg, _ = build_configs(server_bin, P)
    ccfg = {"log": {"loglevel": "info"},
            "inbounds": [{"listen": "127.0.0.1", "port": S, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [build_client_outbound(client_bin, P)]}
    scp, ccp = f'{WORK}/s{idx}.json', f'{WORK}/c{idx}.json'
    open(scp, 'w').write(json.dumps(scfg))
    open(ccp, 'w').write(json.dumps(ccfg))
    kill(); time.sleep(0.4)
    ps = subprocess.Popen([server_bin, 'run', '-c', scp], stdout=open(f'{WORK}/s{idx}.log', 'wb'),
                          stderr=subprocess.STDOUT)
    time.sleep(2.5)
    pc = subprocess.Popen([client_bin, 'run', '-c', ccp], stdout=open(f'{WORK}/c{idx}.log', 'wb'),
                          stderr=subprocess.STDOUT)
    time.sleep(1.5)
    # UDP echo roundtrip 先行（datagram 与 stream 是 QUIC 独立通道；避免 TCP relay
    # 收尾竞态干扰 associate 后的首包窗口）
    echo = EchoServer(E)
    time.sleep(0.2)
    udp_ok, udp_info = socks_udp_roundtrip(S, echo.port)
    # TCP sanity（自建本地源站，零公网依赖）；必须排在 oversize 探针之前——
    # 那条探针会打死整条 QUIC 连接，先跑会把 TCP 腿一起带走（bd fjbit）
    origin = LocalOrigin()
    try:
        tcp_ok, tcp_info = tcp_leg(S, origin.port)
    finally:
        origin.close()
    udp_info += f'; oversize4096={oversize_probe(S, echo.port)}'
    echo.close()
    flag = 'PASS' if (tcp_ok and udp_ok) else 'FAIL'
    err = '' if flag == 'PASS' else f'tcp={tcp_ok}({tcp_info}) udp={udp_ok}({udp_info})'
    if flag == 'FAIL':
        for lp in (f'{WORK}/s{idx}.log', f'{WORK}/c{idx}.log'):
            try:
                tail = open(lp, 'rb').read()[-500:].decode(errors='replace').replace('\n', ' | ')
                err += f' [{os.path.basename(lp)}:{tail[:220]}]'
            except Exception:
                pass
    else:
        err = f'{udp_info}; tcp: {tcp_info}'
    ps.terminate(); pc.terminate()
    kill()
    print(f'[{flag}] #{idx} {tag:10s} server={os.path.basename(server_bin):12s} '
          f'client={os.path.basename(client_bin):12s} tcp={tcp_ok} udp={udp_ok} {err}', flush=True)
    return flag


if __name__ == '__main__':
    results = []
    if '--only4' in sys.argv:
        results.append(run_one(4, RUST, RUST, 'Rust->Rust'))
        ok = results.count('PASS')
        print(f'=== only4: {ok}/1 PASS ===')
        sys.exit(0 if ok == 1 else 1)
    print('== A: Go -> Go (对照) ==', flush=True)
    results.append(run_one(1, GO, GO, 'Go->Go'))
    print('== B: Rust client -> Go server ==', flush=True)
    results.append(run_one(2, GO, RUST, 'Rust->Go'))
    print('== C: Go client -> Rust server ==', flush=True)
    results.append(run_one(3, RUST, GO, 'Go->Rust'))
    ok = results.count('PASS')
    print(f'\n=== hysteria UDP 互操作矩阵: {ok}/3 PASS ===')
    sys.exit(0 if ok == 3 else 1)
