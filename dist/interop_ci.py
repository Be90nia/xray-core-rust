#!/usr/bin/env python3
"""CI 互通测试 (跨平台): dist/interop_matrix.py 的 POSIX 移植, 本地脚本零改动.

- suite rust: Rust client<->Rust server, 6 协议 x 2 轮 = 12 测
- suite go:   Go client -> Rust server (官方 xray-core release 二进制), 默认 3 协议
验收口径同 run_full32/interop_matrix: socks5h curl https://www.youtube.com/ body>5000B 且含 YouTube marker.
TLS 双向统一 pinnedPeerCertSha256 (bd 5x41: allowInsecure 配置期硬错), 证书由 openssl 现场生成.
用法: python3 dist/interop_ci.py [--rust PATH] [--go PATH] [--work DIR]
           [--suites rust,go] [--go-protos vmess,trojan_tls,vless_ws] [--dry-run]
"""
import argparse
import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time

UUID = 'b831381d-6324-4d53-ad4f-8cda48b30811'
TPW = 'test-pass-12345'
SS22_KEY = base64.b64encode(b'0123456789abcdef').decode()  # 16B for 2022-blake3-aes-128-gcm
PROTOS = ['vmess', 'vless_vision_tls', 'trojan_tls', 'vless_ws', 'ss', 'ss2022']
GO_CROSS_PROTOS = ['vmess', 'trojan_tls', 'vless_ws']  # 明文 / TLS+pin / ws 各一
BASE_PORT = 18100
IS_WIN = os.name == 'nt'
EXE = '.exe' if IS_WIN else ''

CERT = KEY = None
PIN = None  # leaf DER sha256, Go/Rust client 通用

OPENSSL_CNF = """[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no
[dn]
CN = localhost
[v3_req]
subjectAltName = DNS:localhost,IP:127.0.0.1
"""


def probe_rust(root):
    for c in (os.path.join(root, 'target', 'release', 'xray' + EXE),
              os.path.join(root, 'dist', 'xray' + EXE)):
        if os.path.isfile(c):
            return c
    return None


def probe_go(root):
    for c in (os.path.join(root, 'tools', 'xray-go', 'xray'),
              'D:/Project/Xray-core/target/xray-go.exe'):  # 本机 Go 基线
        if os.path.isfile(c):
            return c
    return None


def gen_cert(cert, key):
    cnf = cert + '.cnf'
    with open(cnf, 'w') as f:
        f.write(OPENSSL_CNF)
    # -config 写法兼容 LibreSSL(macOS 自带) 与 OpenSSL; 不用 1.1.1+ 才有的 -addext
    r = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', key, '-out', cert, '-days', '2', '-config', cnf],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError('openssl 证书生成失败: ' + r.stderr.strip()[:300])


def pin_of(cert):
    with open(cert) as f:
        der = base64.b64decode(''.join(l for l in f.read().splitlines() if '-----' not in l))
    return hashlib.sha256(der).hexdigest()


def tls_cli():
    # bd 5x41: allowInsecure 已配置期硬错, 双向统一证书 pin
    return {'pinnedPeerCertSha256': PIN}


def tls_srv():
    return {'certificates': [{'certificateFile': CERT, 'keyFile': KEY}]}


def build(proto, P):
    """返回 (server_inbound, client_outbound), 配置形状与 interop_matrix.py 逐字一致."""
    if proto == 'vmess':
        si = {"port": P, "listen": "127.0.0.1", "protocol": "vmess",
              "settings": {"clients": [{"id": UUID, "alterId": 0}]}}
        co = {"protocol": "vmess", "settings": {"vnext": [
            {"address": "127.0.0.1", "port": P,
             "users": [{"id": UUID, "alterId": 0, "security": "auto"}]}]}}
    elif proto == 'vless_vision_tls':
        si = {"port": P, "listen": "127.0.0.1", "protocol": "vless",
              "settings": {"decryption": "none", "clients": [{"id": UUID, "flow": "xtls-rprx-vision"}]},
              "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_srv()}}
        co = {"protocol": "vless", "settings": {"vnext": [
            {"address": "127.0.0.1", "port": P,
             "users": [{"id": UUID, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
            "streamSettings": {"network": "tcp", "security": "tls",
                               "tlsSettings": {"serverName": "localhost", **tls_cli()}}}
    elif proto == 'vless_ws':
        si = {"port": P, "listen": "127.0.0.1", "protocol": "vless",
              "settings": {"decryption": "none", "clients": [{"id": UUID}]},
              "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}}}
        co = {"protocol": "vless", "settings": {"vnext": [
            {"address": "127.0.0.1", "port": P,
             "users": [{"id": UUID, "encryption": "none"}]}]},
            "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}}}
    elif proto == 'trojan_tls':
        si = {"port": P, "listen": "127.0.0.1", "protocol": "trojan",
              "settings": {"clients": [{"password": TPW}]},
              "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_srv()}}
        co = {"protocol": "trojan", "settings": {"servers": [
            {"address": "127.0.0.1", "port": P, "password": TPW}]},
            "streamSettings": {"network": "tcp", "security": "tls",
                               "tlsSettings": {"serverName": "localhost", **tls_cli()}}}
    elif proto == 'ss':
        si = {"port": P, "listen": "127.0.0.1", "protocol": "shadowsocks",
              "settings": {"method": "aes-256-gcm", "password": TPW, "network": "tcp"}}
        co = {"protocol": "shadowsocks", "settings": {"servers": [
            {"address": "127.0.0.1", "port": P, "method": "aes-256-gcm", "password": TPW}]}}
    elif proto == 'ss2022':
        si = {"port": P, "listen": "127.0.0.1", "protocol": "shadowsocks",
              "settings": {"method": "2022-blake3-aes-128-gcm", "password": SS22_KEY, "network": "tcp"}}
        co = {"protocol": "shadowsocks", "settings": {"servers": [
            {"address": "127.0.0.1", "port": P, "method": "2022-blake3-aes-128-gcm", "password": SS22_KEY}]}}
    else:
        raise ValueError(proto)
    return si, co


def kill_bins(*paths):
    """跨平台清扫残留进程: POSIX pkill -f 全路径, Windows taskkill 按镜像名."""
    for path in set(paths):
        try:
            if IS_WIN:
                subprocess.run(['cmd', '/c', 'taskkill /F /IM ' + os.path.basename(path)],
                               capture_output=True, timeout=5)
            else:
                subprocess.run(['pkill', '-f', re.escape(path)], capture_output=True, timeout=5)
        except Exception:
            pass


def wait_port(port, deadline_s):
    end = time.time() + deadline_s
    while time.time() < end:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def stop(ps):
    for p in ps:
        p.terminate()
    for p in ps:
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()


def log_tail(work, idx, err):
    for lp in (os.path.join(work, 's%d.log' % idx), os.path.join(work, 'c%d.log' % idx)):
        try:
            tail = open(lp, 'rb').read()[-400:].decode(errors='replace').replace('\n', ' | ')
            err += ' [%s:%s]' % (os.path.basename(lp), tail[:200])
        except Exception:
            pass
    return err


def run_one(idx, proto, server_bin, client_bin, tag, work, dry=False):
    P = BASE_PORT + idx * 2
    S = P + 1
    si, co = build(proto, P)
    scfg = {"log": {"loglevel": "warning"}, "inbounds": [si],
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}
    ccfg = {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": S, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [co]}
    scp = os.path.join(work, 's%d.json' % idx)
    ccp = os.path.join(work, 'c%d.json' % idx)
    with open(scp, 'w') as f:
        json.dump(scfg, f)
    with open(ccp, 'w') as f:
        json.dump(ccfg, f)
    label = '#%02d %s %s' % (idx, tag, proto)
    if dry:
        print('[DRY] %s server=%s client=%s ports=%d/%d' % (label, server_bin, client_bin, P, S), flush=True)
        return 'DRY'
    kill_bins(server_bin, client_bin)
    time.sleep(0.3)
    procs = []
    bs, err, flag = 0, '', 'FAIL'
    try:
        # vless_vision_tls 取证：macOS arm 上偶发 client 端握手提前断（server
        # rustls 报 tls handshake eof），RUST_LOG=trace 全量留痕（s/c log 随
        # 失败工件上传）。
        env = {**os.environ, "RUST_LOG": "trace"} if proto == "vless_vision_tls" else None
        slog = open(os.path.join(work, 's%d.log' % idx), 'wb')
        ps = subprocess.Popen([server_bin, 'run', '-c', scp], stdout=slog,
                              stderr=subprocess.STDOUT, env=env)
        slog.close()
        procs.append(ps)
        if not wait_port(P, 15):
            err = 'server 未监听 %d (15s)' % P
        else:
            clog = open(os.path.join(work, 'c%d.log' % idx), 'wb')
            pc = subprocess.Popen([client_bin, 'run', '-c', ccp], stdout=clog,
                                  stderr=subprocess.STDOUT, env=env)
            clog.close()
            procs.append(pc)
            if pc.poll() is not None:
                # client 启动即死（如端口被残留进程占用 EADDRINUSE）——立即
                # FAIL 并带日志尾，杜绝"残留旧实例代答导致假 PASS/模糊失败"。
                err = 'client 启动即退出，详见 c%d.log' % idx
            else:
                wait_port(S, 15)
                bp = os.path.join(work, 'b%d.body' % idx)
                try:
                    r = subprocess.run(['curl', '-sS', '--max-time', '15', '-x', 'socks5h://127.0.0.1:%d' % S,
                                        'https://www.youtube.com/', '-o', bp, '-w', 'HTTP:%{http_code}'],
                                       capture_output=True, text=True, timeout=20)
                    bs = os.path.getsize(bp) if os.path.exists(bp) else 0
                    marker = b'YouTube' in open(bp, 'rb').read(200000) if bs else False
                    flag = 'PASS' if (bs > 5000 and marker) else 'FAIL'
                    err = r.stderr.strip()[:60]
                except Exception as e:
                    flag, bs, err = 'FAIL', 0, str(e)[:60]
    finally:
        stop(procs)
        kill_bins(server_bin, client_bin)
    if flag == 'FAIL':
        err = log_tail(work, idx, err)
    print('[%s] %-33s HTTP body=%7dB %s' % (flag, label, bs, err), flush=True)
    return flag


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description='跨平台互通矩阵: Rust<->Rust 12 测 + Go client->Rust server 交叉')
    ap.add_argument('--rust', default=None, help='Rust 二进制路径 (默认探测 target/release/xray)')
    ap.add_argument('--go', default=None, help='Go 基线二进制路径 (官方 release 解包后的 xray)')
    ap.add_argument('--work', default=os.path.join(root, 'target', 'interop_ci'), help='工作目录')
    ap.add_argument('--suites', default='rust,go', help='rust,go 子集')
    ap.add_argument('--go-protos', default=','.join(GO_CROSS_PROTOS), help='Go 交叉协议列表')
    ap.add_argument('--dry-run', action='store_true', help='只生成证书与配置, 不起进程')
    args = ap.parse_args()

    work = os.path.abspath(args.work)
    os.makedirs(work, exist_ok=True)
    global CERT, KEY, PIN
    CERT = os.path.join(work, 'interop_cert.pem')
    KEY = os.path.join(work, 'interop_key.pem')
    try:
        gen_cert(CERT, KEY)
        PIN = pin_of(CERT)
    except (RuntimeError, OSError) as e:
        print('!! 证书生成失败 (%s), TLS 用例将失败' % e, flush=True)
        PIN = 'unavailable'

    rust = args.rust or probe_rust(root)
    go = args.go or probe_go(root)
    if 'rust' in args.suites.split(',') and not (rust and os.path.isfile(rust)):
        sys.exit('!! 未找到 Rust 二进制: %s (先 cargo build --release --bin xray 或 --rust 指定)' % rust)
    if rust:
        rust = os.path.abspath(rust)
    if go:
        go = os.path.abspath(go)

    suites = args.suites.split(',')
    go_protos = [p for p in args.go_protos.split(',') if p]
    plan = []  # (tag, proto, server_bin, client_bin)
    if 'rust' in suites:
        for rnd in (1, 2):  # 同配双轮: 6x2=12, 兼作真机 flake 检测
            for p in PROTOS:
                plan.append(('Rust/Rust r%d' % rnd, p, rust, rust))
    if 'go' in suites:
        if go and os.path.isfile(go):
            for p in go_protos:
                plan.append(('Go/Rust', p, rust, go))  # server=Rust, client=Go
        else:
            print('!! 跳过 Go 交叉: 未找到 Go 基线 (--go)', flush=True)

    print('== 互通 CI: rust=%s go=%s work=%s dry=%s ==' % (rust, go, work, args.dry_run), flush=True)
    results = [run_one(i + 1, proto, srv, cli, tag, work, dry=args.dry_run)
               for i, (tag, proto, srv, cli) in enumerate(plan)]
    if args.dry_run:
        print('\n=== 干跑 %d 用例, 配置与证书已生成 %s ===' % (len(results), work))
        return
    ok = results.count('PASS')
    print('\n=== 互通 CI: %d/%d PASS ===' % (ok, len(results)), flush=True)
    sys.exit(0 if ok == len(results) else 1)


if __name__ == '__main__':
    main()
