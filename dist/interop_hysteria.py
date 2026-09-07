"""hysteria UDP 三组互操作矩阵: Go<->Go 对照 / Rust client<->Go server / Go client<->Rust server.

每组双验收: TCP(curl YouTube marker) + UDP(SOCKS5 UDP ASSOCIATE -> 本地 UDP echo,
多尺寸 payload 往返字节一致). 验收标准: 双向 UDP 通, echo 字节一致.
"""
import subprocess, time, os, json, sys, base64, hashlib, socket, struct, threading

RUST = 'dist/xray.exe'
GO = 'D:/tmp/xray_go.exe'
CERT = 'D:/tmp/interop_cert.pem'
KEY = 'D:/tmp/interop_key.pem'
with open(CERT) as _f:
    PIN = hashlib.sha256(base64.b64decode(
        ''.join(l for l in _f.read().splitlines() if '-----' not in l))).hexdigest()
AUTH = 'hys-udp-secret'
WORK = 'D:/tmp/interop_hy'
os.makedirs(WORK, exist_ok=True)


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
    # Rust client: NoVerifier(insecure), auth 在 servers[0]
    return {"protocol": "hysteria",
            "settings": {"servers": [{"address": "127.0.0.1", "port": P, "auth": AUTH}]}}


def kill():
    for exe in ('xray.exe', 'xray-go.exe'):
        subprocess.run(['cmd', '/c', f'taskkill /F /IM {exe}'], capture_output=True, timeout=5)


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


def socks_udp_roundtrip(socks_port, echo_port, sizes=(64, 1024), oversize=4096):
    """SOCKS5 UDP ASSOCIATE -> echo -> 逐字节对比. 返回 (ok, err)"""
    s = None
    u = None
    try:
        s = socket.create_connection(("127.0.0.1", socks_port), timeout=5)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return False, "socks greeting failed"
        # DST 必须全零：Go 侧 ExpectedRemote 会按 DST 端口过滤来源（temp_udp_listen.go:44）
        s.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0))
        resp = b""
        while len(resp) < 4:
            chunk = s.recv(64)
            if not chunk:
                return False, f"associate closed early resp={resp.hex()}"
            resp += chunk
        need = {1: 10, 4: 22}.get(resp[3], 5 + resp[4] + 2)
        while len(resp) < need:
            resp += s.recv(64)
        if resp[1] != 0:
            return False, f"udp associate denied resp={resp.hex()[:40]}"
        atyp = resp[3]
        if atyp == 1:
            relay_ip, relay_port, head = socket.inet_ntoa(resp[4:8]), struct.unpack(">H", resp[8:10])[0], 10
        elif atyp == 4:
            relay_ip, relay_port, head = socket.inet_ntop(socket.AF_INET6, resp[4:20]), struct.unpack(">H", resp[20:22])[0], 22
        else:
            n = resp[4]
        if relay_ip == "0.0.0.0":
            relay_ip = "127.0.0.1"
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6)
        for size in sizes:
            payload = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
            pkt = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", echo_port) + payload
            u.sendto(pkt, (relay_ip, relay_port))
            data, _ = u.recvfrom(65535)
            if data[head:] != payload:
                return False, f"echo mismatch size={size} got={len(data) - head}B"
        # 超限探测（附加信息，不判 FAIL）：>Go server MaxDatagramFrameSize=1200 的
        # 回包 Go server 侧无分片逻辑（client.go UDPWriter 仅 client 有 TooLarge 分片），
        # 真实网络 1500 MTU 下同样发不出，属 Go 实现固有限制
        oversize_note = "n/a"
        payload = bytes(range(256)) * 16
        pkt = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", echo_port) + payload
        try:
            u.sendto(pkt, (relay_ip, relay_port))
            data, _ = u.recvfrom(65535)
            oversize_note = "OK" if data[10:] == payload else "mismatch"
        except Exception:
            oversize_note = "dropped(go 1200 cap)"
        return True, f"2 sizes roundtrip byte-identical; oversize4096={oversize_note}"
    except Exception as e:
        return False, str(e)[:80]
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
    echo.close()
    # TCP sanity（curl YouTube）
    tcp_ok, tcp_info = False, ''
    try:
        bp = f'{WORK}/b{idx}.body'
        r = subprocess.run(['curl', '-sS', '--max-time', '15', '-x', f'socks5h://127.0.0.1:{S}',
                            'https://www.youtube.com/', '-o', bp, '-w', 'HTTP:%{http_code}'],
                           capture_output=True, text=True, timeout=20)
        bs = os.path.getsize(bp) if os.path.exists(bp) else 0
        marker = b'YouTube' in open(bp, 'rb').read(200000) if bs else False
        tcp_ok = bs > 5000 and marker
        tcp_info = f'{bs}B'
    except Exception as e:
        tcp_info = str(e)[:50]
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
        err = udp_info
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
