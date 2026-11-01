"""round5 探测二：obfs 方向性判别 + tuic native 数据报尺寸边界。

判别目标：
  1. Rust 服务端 salamander 是否根本不生效（Rust↔Rust 同算法对打若也红 = 死路径；
     若绿 = 算法/实现差异导致与 sing-box 不互操作）。
  2. tuic native 模式下 Rust 侧 UDP 数据报的可用尺寸边界（Go↔Rust 与 sb 对照）。
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import r5_thirdparty as R

W = R.WORK
R.ensure_cert()


def hys_srv(port, obfs):
    ss = {'network': 'hysteria', 'security': 'tls',
          'hysteriaSettings': {'version': 2, 'auth': R.HY_AUTH}}
    if obfs:
        ss['finalmask'] = {'udp': [{'type': 'salamander',
                                    'settings': {'password': R.OBFS_PW}}]}
    return {'log': {'loglevel': 'debug'},
            'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'hysteria',
                          'settings': {'version': 2, 'auth': R.HY_AUTH,
                                       'cert': R.pem(R.CERT), 'key': R.pem(R.KEY)},
                          'streamSettings': ss}],
            'outbounds': [{'protocol': 'freedom',
                           'settings': {'finalRules': [{'action': 'allow'}]}}]}


def hys_cli(port, socks, obfs):
    ss = {'network': 'hysteria', 'security': 'tls',
          'tlsSettings': R.rust_tls_pinned(), 'hysteriaSettings': {'version': 2,
                                                                  'auth': R.HY_AUTH}}
    if obfs:
        ss['finalmask'] = {'udp': [{'type': 'salamander',
                                    'settings': {'password': R.OBFS_PW}}]}
    return {'log': {'loglevel': 'debug'},
            'inbounds': [{'listen': '127.0.0.1', 'port': socks, 'protocol': 'socks',
                          'settings': {'udp': True}}],
            'outbounds': [{'protocol': 'hysteria',
                           'settings': {'version': 2, 'address': '127.0.0.1',
                                        'port': port, 'auth': R.HY_AUTH},
                           'streamSettings': ss}]}


def tuic_sb_cli(port, socks):
    tls = {'enabled': True, 'server_name': 'localhost', 'insecure': True, 'alpn': ['h3']}
    return {'log': {'level': 'debug'},
            'inbounds': [{'type': 'socks', 'tag': 'socks-in', 'listen': '127.0.0.1',
                          'listen_port': socks}],
            'outbounds': [{'type': 'tuic', 'tag': 'tun', 'server': '127.0.0.1',
                           'server_port': port, 'uuid': R.UUID, 'password': R.TUIC_PW,
                           'udp_relay_mode': 'native', 'tls': tls},
                          {'type': 'direct', 'tag': 'direct'}],
            'route': {'rules': [{'inbound': ['socks-in'], 'outbound': 'tun'}]}}


def tuic_rust_cli(port, socks, mode='native'):
    return {'log': {'loglevel': 'debug'},
            'inbounds': [{'listen': '127.0.0.1', 'port': socks, 'protocol': 'socks',
                          'settings': {'udp': True}}],
            'outbounds': [{'protocol': 'tuic',
                           'settings': {'servers': [{'address': '127.0.0.1', 'port': port,
                                                     'uuid': R.UUID, 'password': R.TUIC_PW,
                                                     'udp_relay_mode': mode}]},
                           'streamSettings': {'security': 'tls',
                                              'tlsSettings': R.rust_tls_pinned()}}]}


def tuic_sb_srv(port):
    tls = {'enabled': True, 'certificate_path': R.CERT, 'key_path': R.KEY, 'alpn': ['h3']}
    return {'log': {'level': 'debug'},
            'inbounds': [{'type': 'tuic', 'listen': '127.0.0.1', 'listen_port': port,
                          'users': [{'uuid': R.UUID, 'password': R.TUIC_PW}],
                          'congestion_control': 'cubic', 'tls': tls}],
            'outbounds': [{'type': 'direct'}]}


def run(name, srv, cli, sport, socks, sizes, udp=True, tcp=True):
    sp = os.path.join(W, 'p2_%s.s.json' % name)
    cp = os.path.join(W, 'p2_%s.c.json' % name)
    for binp, cfg, path in ((srv[0], srv[1], sp), (cli[0], cli[1], cp)):
        json.dump(cfg, open(path, 'w'))
        if binp == R.SING_BOX:
            v = subprocess.run([binp, 'check', '-c', path], capture_output=True, text=True)
            if v.returncode:
                print(name, 'sing-box check FAIL', (v.stderr or '')[-160:])
                return
    e, o = R.UdpEcho(), R.TcpOrigin()
    srv_udp = 'hysteria' in json.dumps(srv[1]) or 'tuic' in json.dumps(srv[1])
    ps = subprocess.Popen([srv[0], 'run', '-c', sp], stdout=open(os.path.join(W, 'p2_%s.s.log' % name), 'wb'),
                          stderr=subprocess.STDOUT)
    pc = subprocess.Popen([cli[0], 'run', '-c', cp], stdout=open(os.path.join(W, 'p2_%s.c.log' % name), 'wb'),
                          stderr=subprocess.STDOUT)
    try:
        R.wait_port(sport, 20, srv_udp)
        ok_socks = R.wait_port(socks, 25, False)
        notes = []
        if tcp:
            notes.append('TCP:%s' % (R.tcp_leg(socks, o.port, 'p2_' + name)[0] if ok_socks else 'no-socks'))
        if udp:
            res = R.socks5_udp_roundtrip(socks, e.port, sizes)
            notes.append('UDP:' + ' '.join(('%dB=%s' % (len(sizes[i]), 'ok' if r[0] else 'X'))
                                           for i, r in enumerate(res)))
        print(name, '|', ' | '.join(notes), flush=True)
    finally:
        for p in (ps, pc):
            p.terminate()
        for p in (ps, pc):
            try:
                p.wait(timeout=6)
            except Exception:
                p.kill()
        e.close()
        o.close()


SZ = [b'A' * n for n in (1, 512, 900, 1100, 1200, 1300, 1400)]
TU_SZ = [b'A' * n for n in (1, 512, 900, 1100, 1200, 1300)]

if __name__ == '__main__':
    # 1. Rust↔Rust hysteria：无 obfs（对照）/ 有 obfs（判别）
    run('hy_rr_noobfs', (R.XRAY, hys_srv(28343, False)), (R.XRAY, hys_cli(28343, 28344, False)),
        28343, 28344, SZ)
    run('hy_rr_obfs', (R.XRAY, hys_srv(28345, True)), (R.XRAY, hys_cli(28345, 28346, True)),
        28345, 28346, SZ)
    # 2. tuic native 尺寸边界：Rust cli → sb srv（已知 1200 红）
    run('tu_rs_sb_native', (R.SING_BOX, tuic_sb_srv(28347)),
        (R.XRAY, tuic_rust_cli(28347, 28348, 'native')), 28347, 28348, TU_SZ, tcp=False)
