"""anytls / tuic 互通常态门禁（对端 = sing-box）。

Go xray 26.10.17 **没有** anytls/tuic（`grep` Go 仓只在 docs/rust-rewrite-analysis.md 命中，
讲的是别家产品；proxy/ 与 infra/conf/ 零命中），所以这两个协议不存在"Go 对拍"方向；
本脚本用唯一可得的独立实现 sing-box（1.14.3：anytls inbound/outbound + tuic v5
inbound/outbound）当对端，每协议跑两条方向：

  A. Rust client  -> sing-box server
  B. sing-box client -> Rust server

每条方向断言两件真事（都经隧道打到进程内 LocalOrigin，零外部网络）：
  - 下行：GET /payload 取 64KiB+marker，整包逐字节一致；
  - 上行：POST /echo 发 64KiB 确定性字节，回包逐字节一致。

局限（写死在报告里）：sing-box 是第三方实现，"Rust↔sing-box 通"只证协议实现互操作，
不证与 Go（无此二协议）互通。

用法：
  python dist/interop_ext.py              # 4 用例（anytls/tuic × A/B 两方向）
  python dist/interop_ext.py --negative   # 反向验证：no-server / stop-server / corrupt → 必须全红
  python dist/interop_ext.py --only tuic  # 只跑 tuic
退出码 = 0 当且仅当全部用例 PASS（negative 模式下 = 全部 FAIL 才算通过）。
"""
import argparse
import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = '.exe' if os.name == 'nt' else ''
XRAY = os.environ.get('XRAY') or os.path.join(ROOT, 'target', 'release', 'xray' + EXE)
SING_BOX = os.environ.get('SING_BOX') or \
    'D:/Program Files/v2rayN-windows-64/bin/sing_box/sing-box.exe'
WORK = os.path.join(ROOT, 'reports', 'audit-2026-10-30', 'tmp', 'TuiAnyMesh2')
os.makedirs(WORK, exist_ok=True)

CERT = os.path.join(WORK, 'cert.pem')
KEY = os.path.join(WORK, 'key.pem')
OPENSSL_CNF = """[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no
[dn]
CN = localhost
[v3_req]
subjectAltName = DNS:localhost,IP:127.0.0.1
"""

UUID = '2cd1c4a6-4b8c-4f6e-9a1d-2c3b4d5e6f70'
ANYTLS_PW = 'anytls-ext-secret'
TUIC_PW = 'tuic-ext-secret'

# 64KiB 上行回显 + 64KiB+marker 下行正文；marker 排除"错误页/空包也算过"
MARKER = b'<<<EXT-INTEROP-MARKER>>>'
ECHO = bytes(range(256)) * 256
PAYLOAD = MARKER + bytes(range(256)) * 256

# 端口段 63xxx（不与 interop_matrix 18xxx / hysteria 185xx 冲突）
# (proto, 方向, 服务端端口, 客户端 socks 端口)
CASES = [
    ('anytls', 'A', 63101, 63103),
    ('anytls', 'B', 63102, 63104),
    ('tuic', 'A', 63111, 63113),
    ('tuic', 'B', 63112, 63114),
]


def pem(path):
    with open(path) as f:
        return f.read()


def pin_of(path):
    with open(path) as f:
        der = base64.b64decode(''.join(l for l in f.read().splitlines() if '-----' not in l))
    return hashlib.sha256(der).hexdigest()


def ensure_cert():
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    cnf = CERT + '.cnf'
    with open(cnf, 'w') as f:
        f.write(OPENSSL_CNF)
    r = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', KEY, '-out', CERT, '-days', '2', '-config', cnf],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError('openssl 证书生成失败: ' + r.stderr.strip()[:300])


class LocalOrigin:
    """进程内 HTTP 源站：GET /payload 回 64KiB+marker，POST /echo 逐字节回显 body。"""

    def __init__(self, corrupt=False):
        self.corrupt = corrupt
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
            if self.corrupt:
                resp = resp[:-1] if resp else b"x"  # 短 1 字节 → 逐字节比较必须红
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


def rust_server_cfg(proto, port):
    out = [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
    if proto == 'anytls':
        ib = {"port": port, "listen": "127.0.0.1", "protocol": "anytls",
              "settings": {"cert": pem(CERT), "key": pem(KEY), "password": ANYTLS_PW}}
    else:
        ib = {"port": port, "listen": "127.0.0.1", "protocol": "tuic",
              "settings": {"uuid": UUID, "password": TUIC_PW,
                           "certificate": pem(CERT), "certificateKey": pem(KEY)}}
    return {"log": {"loglevel": "warning"}, "inbounds": [ib], "outbounds": out}


def rust_client_cfg(proto, server_port, socks_port, pin):
    if proto == 'anytls':
        co = {"protocol": "anytls",
              "settings": {"server": "127.0.0.1", "server_port": server_port,
                           "sni": "localhost", "insecure": True, "password": ANYTLS_PW}}
    else:
        co = {"protocol": "tuic",
              "settings": {"servers": [{"address": "127.0.0.1", "port": server_port,
                                        "uuid": UUID, "password": TUIC_PW,
                                        "congestion_control": "cubic"}]},
              "streamSettings": {"security": "tls",
                                 "tlsSettings": {"serverName": "localhost",
                                                 "pinnedPeerCertSha256": pin}}}
    return {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                          "settings": {}}],
            "outbounds": [co]}


def sb_server_cfg(proto, port):
    tls = {"enabled": True, "certificate_path": CERT, "key_path": KEY}
    if proto == 'anytls':
        ib = {"type": "anytls", "listen": "127.0.0.1", "listen_port": port,
              "users": [{"password": ANYTLS_PW}], "tls": tls}
    else:
        ib = {"type": "tuic", "listen": "127.0.0.1", "listen_port": port,
              "users": [{"uuid": UUID, "password": TUIC_PW}],
              "congestion_control": "cubic", "tls": {**tls, "alpn": ["h3"]}}
    return {"log": {"level": "warn"}, "inbounds": [ib], "outbounds": [{"type": "direct"}]}


def sb_client_cfg(proto, server_port, socks_port):
    tls = {"enabled": True, "server_name": "localhost", "insecure": True}
    if proto == 'anytls':
        ob = {"type": "anytls", "tag": "tun", "server": "127.0.0.1",
              "server_port": server_port, "password": ANYTLS_PW, "tls": tls}
    else:
        ob = {"type": "tuic", "tag": "tun", "server": "127.0.0.1",
              "server_port": server_port, "uuid": UUID, "password": TUIC_PW,
              "tls": {**tls, "alpn": ["h3"]}}
    return {"log": {"level": "warn"},
            "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1",
                          "listen_port": socks_port}],
            "outbounds": [ob, {"type": "direct", "tag": "direct"}],
            "route": {"rules": [{"inbound": ["socks-in"], "outbound": "tun"}]}}


def wait_port(port, deadline_s, udp=False):
    """TCP: connect 探测；UDP（QUIC 系）：bind 同端口，EADDRINUSE = 有监听者。"""
    end = time.time() + deadline_s
    while time.time() < end:
        if udp:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.bind(('127.0.0.1', port))
            except OSError:
                return True
            finally:
                s.close()
        else:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=1):
                    return True
            except OSError:
                pass
        time.sleep(0.25)
    return False


def stop(procs):
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    for p in procs:
        try:
            p.wait(timeout=5)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass


def tcp_leg(socks_port, origin_port, tag):
    """经隧道：下行取 /payload 整包比对 + 上行 POST /echo 64KiB 逐字节回显。"""
    problems = []
    bp = os.path.join(WORK, tag + '.payload.body')
    if os.path.exists(bp):
        os.remove(bp)
    r = subprocess.run(['curl', '-sS', '--max-time', '20', '-x',
                        'socks5://127.0.0.1:%d' % socks_port,
                        'http://127.0.0.1:%d/payload' % origin_port,
                        '-o', bp, '-w', '%{http_code}'],
                       capture_output=True, text=True, timeout=25)
    got = open(bp, 'rb').read() if os.path.exists(bp) else b''
    if r.stdout.strip() != '200':
        problems.append('payload http=%s' % (r.stdout.strip() or r.stderr.strip()[:40]))
    elif got != PAYLOAD:
        problems.append('payload %dB != %dB' % (len(got), len(PAYLOAD)))
    sp = os.path.join(WORK, tag + '.echo.send')
    rp = os.path.join(WORK, tag + '.echo.recv')
    with open(sp, 'wb') as f:
        f.write(ECHO)
    if os.path.exists(rp):
        os.remove(rp)
    r = subprocess.run(['curl', '-sS', '--max-time', '20', '-x',
                        'socks5://127.0.0.1:%d' % socks_port,
                        '--data-binary', '@' + sp,
                        'http://127.0.0.1:%d/echo' % origin_port,
                        '-o', rp, '-w', '%{http_code}'],
                       capture_output=True, text=True, timeout=25)
    recv = open(rp, 'rb').read() if os.path.exists(rp) else b''
    if r.stdout.strip() != '200':
        problems.append('echo http=%s' % (r.stdout.strip() or r.stderr.strip()[:40]))
    elif recv != ECHO:
        problems.append('echo %dB != %dB' % (len(recv), len(ECHO)))
    if problems:
        return False, '; '.join(problems)[:140]
    return True, 'payload %dB 整包一致 + echo %dB 逐字节回显' % (len(PAYLOAD), len(ECHO))


def run_case(proto, direction, server_port, socks_port, mode='normal'):
    """direction A = Rust client -> sing-box server；B = sing-box client -> Rust server。

    mode: normal / no-server（不起服务端）/ stop-server（起到监听后再停掉）/
          corrupt（链路正常但源站故意回坏字节，证明逐字节比较不是恒真）。
    返回 (flag, info)。
    """
    tag = '%s_%s' % (proto, direction)
    pin = pin_of(CERT)
    udp = proto == 'tuic'
    if direction == 'A':
        srv_bin, cli_bin = SING_BOX, XRAY
        scfg = sb_server_cfg(proto, server_port)
        ccfg = rust_client_cfg(proto, server_port, socks_port, pin)
    else:
        srv_bin, cli_bin = XRAY, SING_BOX
        scfg = rust_server_cfg(proto, server_port)
        ccfg = sb_client_cfg(proto, server_port, socks_port)

    scp = os.path.join(WORK, tag + '.srv.json')
    ccp = os.path.join(WORK, tag + '.cli.json')
    with open(scp, 'w') as f:
        json.dump(scfg, f)
    with open(ccp, 'w') as f:
        json.dump(ccfg, f)
    # xray 与 sing-box 都是 `run -c <file>`
    srv_cmd = [srv_bin, 'run', '-c', scp]
    cli_cmd = [cli_bin, 'run', '-c', ccp]

    origin = LocalOrigin(corrupt=(mode == 'corrupt'))
    procs = []
    try:
        if mode != 'no-server':
            slog = open(os.path.join(WORK, tag + '.srv.log'), 'wb')
            ps = subprocess.Popen(srv_cmd, stdout=slog, stderr=subprocess.STDOUT)
            slog.close()
            procs.append(ps)
            if not wait_port(server_port, 15, udp=udp):
                return False, 'server 未监听 %d (15s)' % server_port
            if mode == 'stop-server':
                stop([ps])
                procs.remove(ps)
                time.sleep(0.5)

        clog = open(os.path.join(WORK, tag + '.cli.log'), 'wb')
        pc = subprocess.Popen(cli_cmd, stdout=clog, stderr=subprocess.STDOUT)
        clog.close()
        procs.append(pc)
        if pc.poll() is not None:
            return False, 'client 启动即退出，详见 %s.cli.log' % tag
        if not wait_port(socks_port, 15):
            return False, 'client socks 未监听 %d' % socks_port
        return tcp_leg(socks_port, origin.port, tag)
    finally:
        stop(procs)
        origin.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--negative', action='store_true',
                    help='反向验证：no-server + stop-server 两模式，必须全 FAIL 才算通过')
    ap.add_argument('--only', default='', help='只跑指定协议 (anytls/tuic)')
    args = ap.parse_args()

    if not os.path.isfile(XRAY):
        print('缺少 Rust xray: %s' % XRAY)
        return 2
    if not os.path.isfile(SING_BOX):
        print('缺少 sing-box: %s' % SING_BOX)
        return 2
    ensure_cert()

    cases = [c for c in CASES if not args.only or c[0] == args.only]
    print('xray=%s\nsing-box=%s' % (XRAY, SING_BOX), flush=True)
    print('cases=%s negative=%s\n' % (len(cases), args.negative), flush=True)

    print('=== 反向验证（必须全红）===' if args.negative else '=== 正向互操作 ===',
          flush=True)
    oks = 0
    for proto, direction, server_port, socks_port in cases:
        modes = ['no-server', 'stop-server', 'corrupt'] if args.negative else ['normal']
        for mode in modes:
            ok, info = run_case(proto, direction, server_port, socks_port, mode)
            if args.negative:
                good = not ok  # 反向模式：FAIL 才是期望
                print('[%s] %s 方向%s mode=%-11s %s' %
                      ('RED-OK' if good else 'RED-BROKEN', proto, direction, mode, info),
                      flush=True)
            else:
                good = ok
                print('[%s] %s 方向%s %s' % ('PASS' if ok else 'FAIL', proto, direction, info),
                      flush=True)
            oks += 1 if good else 0
    total = len(cases) * (3 if args.negative else 1)
    print('\n=== %s: %d/%d ===' % ('反向验证' if args.negative else '正向互操作', oks, total),
          flush=True)
    return 0 if oks == total else 1


if __name__ == '__main__':
    sys.exit(main())
