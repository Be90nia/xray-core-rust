"""round5: hysteria2 / tuic v5 / anytls 第三方对端互通（对端 = sing-box 1.14.3）。

八股：每 case = 服务端 + 客户端 + 两条腿
  - TCP 腿：经隧道 GET /payload 取 64KiB+marker 整包逐字节比对；POST /echo 发 64KiB 逐字节回显
  - UDP 腿：SOCKS5 UDP ASSOCIATE → 本地 UDP echo，多尺寸（1/17/512/1200/8192）逐字节往返
零公网依赖：源站/echo 全 127.0.0.1 自建。

用法:
  python reports/audit-2026-10-31-perf-mem-wiring/round5/r5_thirdparty.py
  python ... --only tuic --udp-only
  python ... --negative           # 反向验证：服务端不起 → 必须全红
"""
import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

ROOT = 'D:/Project/Xray-core-rust'
XRAY = os.path.join(ROOT, 'target', 'release', 'xray.exe')
SING_BOX = 'D:/Program Files/v2rayN-windows-64/bin/sing_box/sing-box.exe'
WORK = os.path.join(ROOT, 'reports', 'audit-2026-10-31-perf-mem-wiring', 'round5', 'tmp')
os.makedirs(WORK, exist_ok=True)

CERT = os.path.join(WORK, 'cert.pem')
KEY = os.path.join(WORK, 'key.pem')

UUID = '2cd1c4a6-4b8c-4f6e-9a1d-2c3b4d5e6f70'
ANYTLS_PW = 'anytls-ext-secret'
TUIC_PW = 'tuic-ext-secret'
HY_AUTH = 'hy2-ext-secret'
OBFS_PW = 'obfs-ext-secret'

MARKER = b'<<<R5-THIRDPARTY>>>'
ECHO = bytes(range(256)) * 256                 # 65536
PAYLOAD = MARKER + bytes(range(256)) * 256     # 64KiB + marker
UDP_SIZES_INFO = [(b'X' * 8192)]   # >MTU：QUIC datagram 不适用，仅信息项
UDP_SIZES = [b'A',
             MARKER[:17],
             bytes(range(256)) * 2,
             (bytes(range(256)) * 4 + bytes(range(176))),
             (MARKER + bytes(range(256)) * 32)[:1200]]


def ensure_cert():
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    cnf = CERT + '.cnf'
    with open(cnf, 'w') as f:
        f.write('[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n'
                '[dn]\nCN=localhost\n[v3]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', KEY, '-out', CERT, '-days', '2', '-config', cnf],
                   check=True, capture_output=True)


def pem(p):
    with open(p) as f:
        return f.read()


# ---------------- 本地源站 ----------------

class TcpOrigin:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(8)
        self.stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        self.sock.settimeout(0.3)
        while not self.stop.is_set():
            try:
                c, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            c.settimeout(15)
            buf = b''
            while b'\r\n\r\n' not in buf:
                ch = c.recv(4096)
                if not ch:
                    return
                buf += ch
            head, _, body = buf.partition(b'\r\n\r\n')
            parts = head.split(b' ')
            method, path = parts[0], parts[1]
            n = 0
            for line in head.split(b'\r\n')[1:]:
                k, _, v = line.partition(b':')
                if k.strip().lower() == b'content-length':
                    n = int(v.strip() or 0)
            while len(body) < n:
                ch = c.recv(4096)
                if not ch:
                    break
                body += ch
            if path == b'/payload':
                resp = PAYLOAD
            elif path == b'/echo' and method == b'POST':
                resp = body
            else:
                resp = b'nf'
            c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' +
                      str(len(resp)).encode() + b'\r\nConnection: close\r\n\r\n' + resp)
        except (OSError, ValueError):
            pass
        finally:
            c.close()

    def close(self):
        self.stop.set()
        self.sock.close()


class UdpEcho:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        self.sock.settimeout(0.3)
        while not self.stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self.sock.sendto(data, addr)
            except OSError:
                pass

    def close(self):
        self.stop.set()
        self.sock.close()


# ---------------- SOCKS5 UDP ASSOCIATE ----------------

def socks5_udp_roundtrip(socks_port, echo_port, payloads, timeout=8.0):
    """返回 list[(ok, note)]，逐条 payload。每个 payload 走一次独立 UDP 收发。"""
    out = []
    tcp = socket.create_connection(('127.0.0.1', socks_port), timeout=timeout)
    try:
        tcp.sendall(b'\x05\x01\x00')
        if tcp.recv(2) != b'\x05\x00':
            return [(False, 'socks5 greeting 拒绝')]
        tcp.sendall(b'\x05\x03\x00\x01' + b'\x00\x00\x00\x00' + b'\x00\x00')
        rep = tcp.recv(10)
        if len(rep) < 10 or rep[1] != 0:
            return [(False, 'UDP ASSOCIATE 拒绝 rep=%r' % rep[:2])]
        rst_ip = socket.inet_ntoa(rep[4:8])
        rst_port = struct.unpack('!H', rep[8:10])[0]
        if rst_ip == '0.0.0.0':
            rst_ip = '127.0.0.1'
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(timeout)
        try:
            for want in payloads:
                hdr = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + \
                      struct.pack('!H', echo_port)
                try:
                    u.sendto(hdr + want, (rst_ip, rst_port))
                    data, _ = u.recvfrom(65535)
                except (socket.timeout, ConnectionResetError) as e:
                    out.append((False, '%dB 无回包(%s) relay=%s:%d'
                                % (len(want), type(e).__name__, rst_ip, rst_port)))
                    continue
                if len(data) < 10:
                    out.append((False, '%dB 回包过短 %dB' % (len(want), len(data))))
                    continue
                frag = data[2]
                atyp = data[3]
                off = 4
                if atyp == 1:
                    off += 4
                elif atyp == 4:
                    off += 16
                elif atyp == 3:
                    off += 1 + data[4]
                off += 2
                body = data[off:]
                if frag != 0:
                    out.append((False, '%dB 分片回包 frag=%d' % (len(want), frag)))
                elif body != want:
                    out.append((False, '%dB 内容不一致(得%dB)' % (len(want), len(body))))
                else:
                    out.append((True, '%dB' % len(want)))
        finally:
            u.close()
        return out
    finally:
        tcp.close()


# ---------------- 配置生成 ----------------

def sb_tls(alpn=None, cert_path=True):
    t = {'enabled': True, 'certificate_path': CERT, 'key_path': KEY} if cert_path else \
        {'enabled': True, 'server_name': 'localhost', 'insecure': True}
    if alpn:
        t['alpn'] = alpn
    return t


def rust_tls_pinned(pin=True):
    if pin:
        with open(CERT) as f:
            der = base64.b64decode(''.join(l for l in f.read().splitlines()
                                           if '-----' not in l))
        return {'serverName': 'localhost',
                'pinnedPeerCertSha256': hashlib.sha256(der).hexdigest()}
    return {'serverName': 'localhost', 'disableSystemRoot': True,
            'certificates': [{'certificateFile': CERT}]}


def srv_cfg(case):
    """返回 (bin, cfg, udp_bool)"""
    proto, side = case['proto'], case['dir']
    port = case['sport']
    if side == 'A':  # 服务端 = sing-box
        if proto == 'anytls':
            ib = {'type': 'anytls', 'listen': '127.0.0.1', 'listen_port': port,
                  'users': [{'password': ANYTLS_PW}], 'tls': sb_tls()}
        elif proto == 'tuic':
            tls = sb_tls(alpn=['h3'])
            ib = {'type': 'tuic', 'listen': '127.0.0.1', 'listen_port': port,
                  'users': [{'uuid': UUID, 'password': TUIC_PW}],
                  'congestion_control': case.get('cc', 'cubic'), 'tls': tls}
        else:  # hysteria2
            ib = {'type': 'hysteria2', 'listen': '127.0.0.1', 'listen_port': port,
                  'users': [{'password': HY_AUTH}], 'tls': sb_tls()}
            if case.get('obfs'):
                ib['obfs'] = {'type': 'salamander', 'password': OBFS_PW}
            if case.get('brutal'):
                ib['up_mbps'] = 100
                ib['down_mbps'] = 100
        return SING_BOX, {'log': {'level': 'debug'}, 'inbounds': [ib],
                          'outbounds': [{'type': 'direct'}]}, proto != 'anytls'

    # side B：服务端 = Rust
    out = [{'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow'}]}}]
    if proto == 'anytls':
        ib = {'listen': '127.0.0.1', 'port': port, 'protocol': 'anytls',
              'settings': {'cert': pem(CERT), 'key': pem(KEY), 'password': ANYTLS_PW}}
    elif proto == 'tuic':
        ib = {'listen': '127.0.0.1', 'port': port, 'protocol': 'tuic',
              'settings': {'uuid': UUID, 'password': TUIC_PW,
                           'certificate': pem(CERT), 'certificateKey': pem(KEY),
                           'congestion_control': case.get('cc', 'cubic')}}
    else:
        ss = {'network': 'hysteria', 'security': 'tls',
              'hysteriaSettings': {'version': 2, 'auth': HY_AUTH}}
        if case.get('obfs'):
            ss['finalmask'] = {'udp': [{'type': 'salamander',
                                        'settings': {'password': OBFS_PW}}]}
        ib = {'listen': '127.0.0.1', 'port': port, 'protocol': 'hysteria',
              'settings': {'version': 2, 'auth': HY_AUTH,
                           'cert': pem(CERT), 'key': pem(KEY)},
              'streamSettings': ss}
    return XRAY, {'log': {'loglevel': 'info'}, 'inbounds': [ib], 'outbounds': out}, proto != 'anytls'


def cli_cfg(case):
    proto, side = case['proto'], case['dir']
    port, sp = case['sport'], case['socks']
    if side == 'B':  # 客户端 = sing-box
        tls = sb_tls(cert_path=False)
        if proto == 'anytls':
            ob = {'type': 'anytls', 'tag': 'tun', 'server': '127.0.0.1',
                  'server_port': port, 'password': ANYTLS_PW, 'tls': tls}
        elif proto == 'tuic':
            ob = {'type': 'tuic', 'tag': 'tun', 'server': '127.0.0.1',
                  'server_port': port, 'uuid': UUID, 'password': TUIC_PW,
                  'udp_relay_mode': case.get('udp_mode', 'native'),
                  'tls': {**tls, 'alpn': ['h3']}}
            if case.get('alpn'):
                ob['tls']['alpn'] = ['h3']
        else:
            ob = {'type': 'hysteria2', 'tag': 'tun', 'server': '127.0.0.1',
                  'server_port': port, 'password': HY_AUTH, 'tls': tls}
            if case.get('obfs'):
                ob['obfs'] = {'type': 'salamander', 'password': OBFS_PW}
            if case.get('brutal'):
                ob['up_mbps'] = 100
                ob['down_mbps'] = 100
        return SING_BOX, {'log': {'level': 'debug'},
                          'inbounds': [{'type': 'socks', 'tag': 'socks-in',
                                        'listen': '127.0.0.1', 'listen_port': sp}],
                          'outbounds': [ob, {'type': 'direct', 'tag': 'direct'}],
                          'route': {'rules': [{'inbound': ['socks-in'],
                                               'outbound': 'tun'}]}}, True

    # 客户端 = Rust
    socks = {'listen': '127.0.0.1', 'port': sp, 'protocol': 'socks',
             'settings': {'udp': True}}
    if proto == 'anytls':
        co = {'protocol': 'anytls',
              'settings': {'server': '127.0.0.1', 'server_port': port,
                           'sni': 'localhost', 'insecure': True, 'password': ANYTLS_PW}}
    elif proto == 'tuic':
        s = {'address': '127.0.0.1', 'port': port, 'uuid': UUID, 'password': TUIC_PW,
             'congestion_control': case.get('cc', 'cubic'),
             'udp_relay_mode': case.get('udp_mode', 'native')}
        if case.get('alpn'):
            s['alpn'] = ['h3']
        co = {'protocol': 'tuic', 'settings': {'servers': [s]},
              'streamSettings': {'security': 'tls',
                                 'tlsSettings': rust_tls_pinned()}}
    else:
        ss = {'network': 'hysteria', 'security': 'tls',
              'tlsSettings': rust_tls_pinned(),
              'hysteriaSettings': {'version': 2, 'auth': HY_AUTH}}
        fm = {}
        if case.get('obfs'):
            fm['udp'] = [{'type': 'salamander', 'settings': {'password': OBFS_PW}}]
        if case.get('brutal'):
            fm['quicParams'] = {'congestion': 'force-brutal', 'brutalUp': '100 mbps',
                                'brutalDown': '100 mbps'}
        if case.get('alpn'):
            ss['tlsSettings'] = {**ss['tlsSettings'], 'alpn': ['h3']}
        if fm:
            ss['finalmask'] = fm
        co = {'protocol': 'hysteria',
              'settings': {'version': 2, 'address': '127.0.0.1', 'port': port,
                           'auth': HY_AUTH},
              'streamSettings': ss}
    return XRAY, {'log': {'loglevel': 'info'}, 'inbounds': [socks],
                  'outbounds': [co]}, True


# ---------------- 驱动 ----------------

def wait_port(port, deadline, udp):
    end = time.time() + deadline
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
                socket.create_connection(('127.0.0.1', port), timeout=1).close()
                return True
            except OSError:
                pass
        time.sleep(0.2)
    return False


def tcp_leg(socks_port, origin_port, tag):
    probs = []
    bp = os.path.join(WORK, tag + '.body')
    if os.path.exists(bp):
        os.remove(bp)
    r = subprocess.run(['curl', '-sS', '--max-time', '25', '-x',
                        'socks5h://127.0.0.1:%d' % socks_port,
                        'http://127.0.0.1:%d/payload' % origin_port, '-o', bp,
                        '-w', '%{http_code}'], capture_output=True, text=True, timeout=35)
    got = open(bp, 'rb').read() if os.path.exists(bp) else b''
    if r.stdout.strip() != '200':
        probs.append('down http=%s %s' % (r.stdout.strip(), r.stderr.strip()[:60]))
    elif got != PAYLOAD:
        probs.append('down %dB != %dB' % (len(got), len(PAYLOAD)))
    sp = os.path.join(WORK, tag + '.send')
    rp = os.path.join(WORK, tag + '.recv')
    with open(sp, 'wb') as f:
        f.write(ECHO)
    if os.path.exists(rp):
        os.remove(rp)
    r = subprocess.run(['curl', '-sS', '--max-time', '25', '-x',
                        'socks5h://127.0.0.1:%d' % socks_port, '--data-binary', '@' + sp,
                        'http://127.0.0.1:%d/echo' % origin_port, '-o', rp,
                        '-w', '%{http_code}'], capture_output=True, text=True, timeout=35)
    recv = open(rp, 'rb').read() if os.path.exists(rp) else b''
    if r.stdout.strip() != '200':
        probs.append('up http=%s %s' % (r.stdout.strip(), r.stderr.strip()[:60]))
    elif recv != ECHO:
        probs.append('up %dB != %dB' % (len(recv), len(ECHO)))
    if probs:
        return False, 'TCP: ' + '; '.join(probs)[:150]
    return True, 'TCP 上下 64KiB 逐字节一致'


def run_case(case, negative=False):
    tag = '%s_%s%s_%d' % (case['proto'], case['dir'],
                          ''.join('_' + k for k in ('obfs', 'brutal', 'alpn') if case.get(k)),
                          case['sport'])
    origin, uecho = TcpOrigin(), UdpEcho()
    procs, logs = [], []
    sbin, scfg, srv_udp = srv_cfg(case)
    cbin, ccfg, _ = cli_cfg(case)
    scp, ccp = os.path.join(WORK, tag + '.srv.json'), os.path.join(WORK, tag + '.cli.json')
    json.dump(scfg, open(scp, 'w'))
    json.dump(ccfg, open(ccp, 'w'))
    # 预检：sing-box 侧配置自证（写错立刻可见，而不是当互通失败）
    for binp, cfgp in ((sbin, scp), (cbin, ccp)):
        if binp == SING_BOX:
            v = subprocess.run([binp, 'check', '-c', cfgp], capture_output=True, text=True)
            if v.returncode != 0:
                origin.close(); uecho.close()
                return False, 'sing-box check 失败: ' + (v.stderr or v.stdout)[-200:]
    try:
        if not negative:
            lp = os.path.join(WORK, tag + '.srv.log')
            f = open(lp, 'wb')
            procs.append(subprocess.Popen([sbin, 'run', '-c', scp], stdout=f,
                                          stderr=subprocess.STDOUT))
            f.close()
            logs.append(lp)
            if not wait_port(case['sport'], 20, srv_udp):
                return False, '服务端未监听 %d' % case['sport']
        lp = os.path.join(WORK, tag + '.cli.log')
        f = open(lp, 'wb')
        pc = subprocess.Popen([cbin, 'run', '-c', ccp], stdout=f, stderr=subprocess.STDOUT)
        f.close()
        procs.append(pc)
        logs.append(lp)
        if not wait_port(case['socks'], 25, False):
            tail = open(lp, 'rb').read()[-300:].decode('utf8', 'replace')
            return False, '客户端 socks 未监听 %d | %s' % (case['socks'], tail.replace('\n', ' '))
        parts = []
        ok_all = True
        if not case.get('udp_only'):
            ok, note = tcp_leg(case['socks'], origin.port, tag)
            ok_all &= ok
            parts.append(note)
        if case.get('udp', True):
            res = socks5_udp_roundtrip(case['socks'], uecho.port, UDP_SIZES)
            info = socks5_udp_roundtrip(case['socks'], uecho.port, UDP_SIZES_INFO)
            bad = [n for o, n in res if not o]
            if bad:
                ok_all = False
                parts.append('UDP 红: ' + '; '.join(bad)[:120])
            else:
                parts.append('UDP %d 尺寸(1..1200B)逐字节一致' % len(res))
            parts.append('8KB:%s' % ('ok' if info[0][0] else 'no'))
        return ok_all, ' | '.join(parts)
    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=6)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        origin.close()
        uecho.close()


CASES = [
    # anytls
    dict(proto='anytls', dir='A', sport=28301, socks=28302),
    dict(proto='anytls', dir='B', sport=28303, socks=28304),
    # tuic：native 与 quic relay 两模式 × 两方向
    dict(proto='tuic', dir='A', sport=28311, socks=28312, udp_mode='native'),
    dict(proto='tuic', dir='A', sport=28313, socks=28314, udp_mode='quic', udp_only=True),
    dict(proto='tuic', dir='B', sport=28315, socks=28316, udp_mode='native'),
    dict(proto='tuic', dir='B', sport=28317, socks=28318, udp_mode='quic', udp_only=True),
    # hysteria2 基础
    dict(proto='hy2', dir='A', sport=28321, socks=28322),
    dict(proto='hy2', dir='B', sport=28323, socks=28324),
    # hysteria2 obfs salamander
    dict(proto='hy2', dir='A', sport=28325, socks=28326, obfs=True),
    dict(proto='hy2', dir='B', sport=28327, socks=28328, obfs=True),
    # hysteria2 brutal（双向带宽）
    dict(proto='hy2', dir='A', sport=28329, socks=28330, brutal=True),
    # hysteria2 alpn 显式 + tuic alpn 显式
    dict(proto='hy2', dir='B', sport=28331, socks=28332, alpn=True),
    dict(proto='tuic', dir='A', sport=28333, socks=28334, alpn=True, udp=False),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only', default='')
    ap.add_argument('--negative', action='store_true')
    ap.add_argument('--ports', default='', help='逗号分隔的 sport 白名单')
    args = ap.parse_args()
    ensure_cert()
    for p in (XRAY, SING_BOX):
        if not os.path.isfile(p):
            print('缺二进制: %s' % p)
            return 2
    print('xray=%s\nsing-box=%s' % (XRAY, SING_BOX), flush=True)
    ver = subprocess.run([SING_BOX, 'version'], capture_output=True, text=True)
    print(ver.stdout.splitlines()[0] if ver.stdout else '?', flush=True)
    cases = [c for c in CASES if not args.only or args.only in c['proto']]
    if args.ports:
        want = {int(x) for x in args.ports.split(',') if x.strip()}
        cases = [c for c in cases if c['sport'] in want]
    oks = 0
    for c in cases:
        t0 = time.time()
        ok, info = run_case(c, negative=args.negative)
        good = (not ok) if args.negative else ok
        oks += good
        print('[%s] %-9s dir=%s sock=%d obs=%s brutal=%s alpn=%s %5.1fs | %s' % (
            ('PASS' if good else 'FAIL'), c['proto'], c['dir'], c['sport'],
            bool(c.get('obfs')), bool(c.get('brutal')), bool(c.get('alpn')),
            time.time() - t0, info), flush=True)
    print('\n=== %s: %d/%d ===' % ('negative' if args.negative else '正向', oks, len(cases)))
    return 0 if oks == len(cases) else 1


if __name__ == '__main__':
    sys.exit(main())
