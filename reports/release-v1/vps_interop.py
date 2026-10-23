#!/usr/bin/env python3
"""VPS 互通编排：真实公网链路（本机客户端 -> 176 VPS 服务端）的双向互通验证。

复用 dist/interop_ci.py 的配置构建器（build/build_x），只改三件事：
  服务端 listen=0.0.0.0、客户端 address=<VPS_IP>、证书路径=远端路径。

验收目标 = VPS 回环上的 HTTP echo（`python3 -m http.server`）：请求经 socks5h 由
服务端解析 127.0.0.1 → 落在 VPS 本地，因此**不依赖任何外网站点**，但走的是真
公网往返（本机 -> VPS -> VPS 回环）。

用法:
  python reports/release-v1/vps_interop.py \
      --rust-srv /tmp/vpsi/xray-rust --go-srv /tmp/xg/xray \
      --rust-cli target/release/xray.exe \
      --go-cli reports/campaign-2026-10-22/tmp/xray-go-backup.exe

方向: rust_srv->go_cli / go_srv->rust_cli / rust_srv->rust_cli（--combos 可裁剪）

红线: 只在 /tmp/vpsi 下建临时文件、只起临时端口的临时实例，**不碰**用户现役
配置/服务（176:/root/agsbx，systemd xr.service）；结束时清理自己的进程与目录。
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(ROOT, 'dist'))
import interop_ci as ic  # noqa: E402

MARKER = b'VPS_INTEROP_OK'
BASE_PROTOS = list(ic.PROTOS)
X_PROTOS = ['splithttp', 'grpc']


def sh(cmd, check=False, timeout=120):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors='ignore')
    if check and r.returncode != 0:
        raise RuntimeError('cmd failed: %s\n%s' % (' '.join(cmd), r.stderr[:400]))
    return r


class Vps:
    def __init__(self, host, port):
        self.base = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                     '-p', str(port), 'root@%s' % host]

    def run(self, cmd, timeout=120, check=False):
        return sh(self.base + [cmd], check=check, timeout=timeout)

    def put(self, local, remote):
        scp = ['scp', '-o', 'BatchMode=yes', '-P', self.base[6], local,
               'root@%s:%s' % (self.base[7].split('@')[1], remote)]
        return sh(scp, check=True)


def gen_certs(work):
    os.makedirs(work, exist_ok=True)
    cert = os.path.join(work, 'c.pem')
    key = os.path.join(work, 'k.pem')
    ic.gen_cert(cert, key)
    ic.CERT, ic.KEY = cert, key
    ic.PIN = ic.pin_of(cert)
    return cert, key


def make_configs(proto, port, sport, vps_ip, rd_cert, rd_key, echo_port):
    """返回 (server_cfg, client_cfg)；复用 interop_ci 的 build/build_x 并改远端地址。"""
    if proto in BASE_PROTOS:
        si, co = ic.build(proto, port)
    else:
        si, co = ic.build_x(proto, port)
    si = json.loads(json.dumps(si))
    co = json.loads(json.dumps(co))

    # 公网 IP 上 Go 拒绝「无 TLS 的 vless/vmess/trojan」（infra/conf 校验）；ws/splithttp/grpc
    # 三个 http 系传输补 TLS（pin 校验，SNI=localhost 与证书 CN 一致）。
    ssi = si.get('streamSettings') or {}
    if si.get('protocol') in ('vless', 'vmess', 'trojan') and ssi.get('security') in (None, '', 'none'):
        if ssi.get('network') in ('ws', 'splithttp', 'grpc', 'httpupgrade'):
            ssi['security'] = 'tls'
            ssi['tlsSettings'] = {'certificates': [{'certificateFile': rd_cert, 'keyFile': rd_key}]}
            si['streamSettings'] = ssi
            css = co.get('streamSettings') or {}
            css['security'] = 'tls'
            css['tlsSettings'] = {'serverName': 'localhost', 'pinnedPeerCertSha256': ic.PIN}
            co['streamSettings'] = css

    # 服务端：监听全网卡 + 设备上的证书路径；dest 类字段换成本机可达目标
    si['listen'] = '0.0.0.0'
    ss = si.get('streamSettings') or {}
    ts = ss.get('tlsSettings')
    if isinstance(ts, dict) and ts.get('certificates'):
        ts['certificates'] = [{'certificateFile': rd_cert, 'keyFile': rd_key}]
    rs = ss.get('realitySettings')
    if isinstance(rs, dict) and rs.get('dest'):
        rs['dest'] = '127.0.0.1:%d' % echo_port   # VPS 回环 echo（reality 用它的 TLS/明文都行，pin 校验走客户端）
    # 客户端：指向 VPS 公网地址
    def fix_addr(obj):
        if isinstance(obj, dict):
            for k, v in list(obj.items()):
                if k == 'address' and isinstance(v, str) and v in ('127.0.0.1', 'localhost'):
                    obj[k] = vps_ip
                else:
                    fix_addr(v)
        elif isinstance(obj, list):
            for v in obj:
                fix_addr(v)
    fix_addr(co)
    co['tag'] = 'proxy'
    ccfg = {'log': {'loglevel': 'debug' if os.environ.get('VPSI_DEBUG') else 'warning'},
            'inbounds': [{'listen': '127.0.0.1', 'port': sport, 'protocol': 'socks',
                          'settings': {'udp': True}}],
            'outbounds': [co]}
    scfg = {'log': {'loglevel': 'warning'}, 'inbounds': [si],
            'outbounds': [{'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow'}]}}]}
    return scfg, ccfg


def wait_local_port(port, deadline_s):
    import socket as sk
    end = time.time() + deadline_s
    while time.time() < end:
        try:
            with sk.create_connection(('127.0.0.1', port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--vps', default=os.environ.get('XRAY_VPS_HOST', ''),
                    help='VPS 主机（必填，或用环境变量 XRAY_VPS_HOST；仓库内不写死基础设施地址）')
    ap.add_argument('--ssh-port', default=os.environ.get('XRAY_VPS_SSH_PORT', '22'),
                    help='SSH 端口（或用 XRAY_VPS_SSH_PORT）')
    ap.add_argument('--remote-dir', default='/tmp/vpsi')
    ap.add_argument('--rust-srv', default='/tmp/vpsi/xray-rust')
    ap.add_argument('--go-srv', default='/tmp/xg/xray')
    ap.add_argument('--rust-cli', required=True)
    ap.add_argument('--go-cli', required=True)
    ap.add_argument('--combos', default='rust_srv->go_cli,go_srv->rust_cli,rust_srv->rust_cli')
    ap.add_argument('--protos', default=','.join(BASE_PROTOS + X_PROTOS))
    ap.add_argument('--base-port', type=int, default=12829)
    ap.add_argument('--echo-port', type=int, default=12800)
    ap.add_argument('--work', default=os.path.join(ROOT, 'target', 'vps_interop'))
    ap.add_argument('--no-tunnel', action='store_true',
                    help='直连 VPS 公网端口（需防火墙已放行；生产机默认 DROP，故默认走 ssh -L 隧道）')
    args = ap.parse_args()
    if not args.vps:
        ap.error('缺少 --vps（或设置环境变量 XRAY_VPS_HOST）')

    os.makedirs(args.work, exist_ok=True)
    vps = Vps(args.vps, args.ssh_port)
    protos = [p.strip() for p in args.protos.split(',') if p.strip()]
    combos = [c.strip() for c in args.combos.split(',') if c.strip()]

    print('== VPS interop: vps=%s remote_dir=%s protos=%d combos=%d ==' % (args.vps, args.remote_dir, len(protos), len(combos)), flush=True)
    # 预检：服务端二进制必须存在（曾因清理 /tmp 删掉导致整轮假失败）
    chk = vps.run('test -x %s && echo OK_RUST; test -x %s && echo OK_GO' % (args.rust_srv, args.go_srv), timeout=30)
    out = chk.stdout or ''
    need = []
    if any(c.startswith('rust') for c in combos) and 'OK_RUST' not in out:
        need.append(args.rust_srv)
    if any(c.startswith('go') for c in combos) and 'OK_GO' not in out:
        need.append(args.go_srv)
    if need:
        print('ABORT: remote server binary missing: %s' % need, flush=True)
        return 2

    vps.run('mkdir -p %s/www && printf %s > %s/www/marker.txt' % (args.remote_dir, MARKER.decode(), args.remote_dir), check=True)
    # VPS 回环 echo（验收目标 + reality/anytls 之类 dest 的落点）
    vps.run('pkill -f "http.server %d" 2>/dev/null; sleep 0.3' % args.echo_port)
    vps.run('cd %s/www && (setsid nohup python3 -m http.server %d --bind 127.0.0.1 '
            '</dev/null >echo.log 2>&1 &) ; sleep 1.5' % (args.remote_dir, args.echo_port))
    chk = vps.run('curl -sS -m 5 http://127.0.0.1:%d/marker.txt' % args.echo_port, timeout=20)
    if MARKER.decode() not in (chk.stdout or ''):
        print('ABORT: remote echo not up. ssh out=%r err=%r' % ((chk.stdout or '')[:100], (chk.stderr or '')[:200]), flush=True)
        return 2
    print('remote echo OK on 127.0.0.1:%d' % args.echo_port, flush=True)

    cert, key = gen_certs(os.path.join(args.work, 'certs'))
    rd_cert = args.remote_dir + '/c.pem'
    rd_key = args.remote_dir + '/k.pem'
    vps.put(cert, rd_cert)
    vps.put(key, rd_key)

    results = []
    for combo in combos:
        srv_kind, cli_kind = combo.split('->')
        srv_bin = args.rust_srv if srv_kind.startswith('rust') else args.go_srv
        cli_bin = args.rust_cli if cli_kind.startswith('rust') else args.go_cli
        for i, proto in enumerate(protos):
            port = args.base_port + i * 2
            sport = port + 1
            rdir = '%s/%s_%s_%s' % (args.remote_dir, srv_kind, cli_kind, proto)
            cli_addr = args.vps if args.no_tunnel else '127.0.0.1'
            scfg, ccfg = make_configs(proto, port, sport, cli_addr, rd_cert, rd_key, args.echo_port)
            lp = os.path.join(args.work, 's_%s_%s_%s.json' % (srv_kind, cli_kind, proto))
            lc = os.path.join(args.work, 'c_%s_%s_%s.json' % (srv_kind, cli_kind, proto))
            open(lp, 'w').write(json.dumps(scfg))
            open(lc, 'w').write(json.dumps(ccfg))
            vps.run('mkdir -p %s && rm -f %s/*.log' % (rdir, rdir))
            vps.put(lp, rdir + '/s.json')

            flag, note = 'FAIL', ''
            pc = None
            tps = None
            pid = ''
            try:
                st = vps.run('cd %s && (setsid nohup %s run -c s.json </dev/null >s.log 2>&1 & echo $!)' % (rdir, srv_bin))
                pid = (st.stdout or '').strip().splitlines()[-1] if st.stdout.strip() else ''
                # 等服务端监听（远端）
                ok = False
                for _ in range(40):
                    g = vps.run('ss -lnt | grep -c ":%d "' % port, timeout=20)
                    if (g.stdout or '').strip() not in ('', '0'):
                        ok = True
                        break
                    time.sleep(0.25)
                if not ok:
                    note = 'server not listening (remote)'
                else:
                    if not args.no_tunnel:
                        tps = subprocess.Popen(
                            ['ssh', '-o', 'BatchMode=yes', '-o', 'ExitOnForwardFailure=yes',
                             '-o', 'ServerAliveInterval=5', '-N',
                             '-p', args.ssh_port, '-L',
                             '127.0.0.1:%d:127.0.0.1:%d' % (port, port),
                             'root@%s' % args.vps],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        if not wait_local_port(port, 12):
                            note = 'ssh tunnel not up'
                    clog = open(os.path.join(args.work, 'c_%s_%s_%s.log' % (srv_kind, cli_kind, proto)), 'wb')
                    pc = subprocess.Popen([cli_bin, 'run', '-c', lc], stdout=clog, stderr=subprocess.STDOUT)
                    clog.close()
                    if not wait_local_port(sport, 15):
                        note = 'client socks not up'
                    else:
                        url = 'http://127.0.0.1:%d/marker.txt' % args.echo_port
                        r = subprocess.run(['curl', '-sS', '--max-time', '20', '-x',
                                            'socks5h://127.0.0.1:%d' % sport, url],
                                           capture_output=True, timeout=30)
                        out = r.stdout or b''
                        if MARKER in out:
                            flag = 'PASS'
                        else:
                            note = 'body=%r err=%r' % (out[:40], (r.stderr or b'')[:80])
            except Exception as e:  # noqa: BLE001
                note = str(e)[:120]
            finally:
                if 'tps' in dir() and tps is not None:
                    tps.terminate()
                    try:
                        tps.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        tps.kill()
                if pc is not None:
                    pc.terminate()
                    try:
                        pc.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        pc.kill()
                if pid:
                    vps.run('kill %s 2>/dev/null; sleep 0.2; kill -9 %s 2>/dev/null' % (pid, pid))
                if flag != 'PASS':
                    r = vps.run('cat %s/s.log 2>/dev/null | tail -25' % rdir, timeout=30)
                    note = (note or '') + ' | srv: ' + (r.stdout or '').replace('\n', ' ~ ')[:400]
                vps.run('rm -rf %s' % rdir)
            results.append((flag, combo, proto, note))
            print('[%s] %-24s %-18s %s' % (flag, combo, proto, note), flush=True)

    vps.run('pkill -f "http.server %d" 2>/dev/null' % args.echo_port)
    npass = sum(1 for r in results if r[0] == 'PASS')
    print('\n== VPS interop summary: %d/%d PASS ==' % (npass, len(results)), flush=True)
    for flag, combo, proto, note in results:
        if flag != 'PASS':
            print('  FAIL %-24s %-18s %s' % (combo, proto, note), flush=True)
    return 0 if npass == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
