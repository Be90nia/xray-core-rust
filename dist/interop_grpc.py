"""grpc 深层对称互操作: Rust client<->Go server 与 Go client<->Rust server.
vless+grpc+TLS x 2 方向, 每方向同进程 3 连发 curl:
- Go client 按 (dest,streamSettings) 缓存 ClientConn => 3 请求复用同一条 h2 连接,
  对 Rust server 即单 h2 连接多 Tun stream (accept 循环多路复用).
- YouTube 响应 ~500KB+, 跨大量 32KB 读块 => 数百个 gRPC length-prefix 帧边界.
验收口径与 run_full32 一致: 每 curl body>5000B 含 YouTube marker.
端口基址 18300 起 (避开 18100 系矩阵).
"""
import subprocess, time, os, json, base64, hashlib
RUST = 'dist/xray.exe'
GO = 'D:/Project/Xray-core/target/xray-go.exe'
CERT = 'D:/tmp/interop_cert.pem'
KEY = 'D:/tmp/interop_key.pem'
# leaf DER sha256 (Go client pinnedPeerCertSha256)；从证书现算
with open(CERT) as _f:
    PIN = hashlib.sha256(base64.b64decode(
        ''.join(l for l in _f.read().splitlines() if '-----' not in l))).hexdigest()
UUID = 'b831381d-6324-4d53-ad4f-8cda48b30811'
SVC = 'GunService'
WORK = 'D:/tmp/interop_grpc'
os.makedirs(WORK, exist_ok=True)


def tls_cli(rust_client):
    return {'allowInsecure': True} if rust_client else {'pinnedPeerCertSha256': PIN}


def build(P, rust_client):
    """返回 (server_inbound, client_outbound): vless over grpc+TLS"""
    grpc = {"serviceName": SVC}
    si = {"port": P, "listen": "127.0.0.1", "protocol": "vless",
          "settings": {"clients": [{"id": UUID}], "decryption": "none"},
          "streamSettings": {"network": "grpc", "security": "tls",
                             "tlsSettings": {"certificates": [{"certificateFile": CERT, "keyFile": KEY}]},
                             "grpcSettings": dict(grpc)}}
    co = {"protocol": "vless",
          "settings": {"vnext": [{"address": "127.0.0.1", "port": P,
                                  "users": [{"id": UUID, "encryption": "none"}]}]},
          "streamSettings": {"network": "grpc", "security": "tls",
                             "tlsSettings": {"serverName": "localhost", **tls_cli(rust_client)},
                             "grpcSettings": dict(grpc)}}
    return si, co


def kill():
    subprocess.run(['cmd', '/c', 'taskkill /F /IM xray.exe'], capture_output=True, timeout=5)
    subprocess.run(['cmd', '/c', 'taskkill /F /IM xray-go.exe'], capture_output=True, timeout=5)


def curl_once(S, bp):
    r = subprocess.run(['curl', '-sS', '--max-time', '20', '-x', f'socks5h://127.0.0.1:{S}',
                        'https://www.youtube.com/', '-o', bp, '-w', 'HTTP:%{http_code}'],
                       capture_output=True, text=True, timeout=25)
    bs = os.path.getsize(bp) if os.path.exists(bp) else 0
    marker = b'YouTube' in open(bp, 'rb').read(200000) if bs else False
    return bs > 5000 and marker, bs, r.stderr.strip()[:80]


def run_one(idx, server_bin, client_bin, tag):
    P = 18300 + idx * 2
    S = P + 1
    si, co = build(P, client_bin == RUST)
    scfg = {"log": {"loglevel": "warning"}, "inbounds": [si],
            "outbounds": [{"protocol": "freedom", "settings": {}}]}
    ccfg = {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": S, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [co]}
    scp, ccp = f'{WORK}/s{idx}.json', f'{WORK}/c{idx}.json'
    open(scp, 'w').write(json.dumps(scfg))
    open(ccp, 'w').write(json.dumps(ccfg))
    kill(); time.sleep(0.3)
    ps = subprocess.Popen([server_bin, 'run', '-c', scp], stdout=open(f'{WORK}/s{idx}.log', 'wb'),
                          stderr=subprocess.STDOUT)
    time.sleep(2.5)
    pc = subprocess.Popen([client_bin, 'run', '-c', ccp], stdout=open(f'{WORK}/c{idx}.log', 'wb'),
                          stderr=subprocess.STDOUT)
    flags, sizes, err = [], [], ''
    try:
        for i in range(3):  # 同 client 进程 3 连发
            bp = f'{WORK}/b{idx}_{i}.body'
            ok, bs, e = curl_once(S, bp)
            flags.append(ok); sizes.append(bs)
            if e: err += f' #{i}:{e}'
    except Exception as e:
        err = str(e)[:80]
    flag = 'PASS' if flags and all(flags) else 'FAIL'
    if flag == 'FAIL':
        for lp in (f'{WORK}/s{idx}.log', f'{WORK}/c{idx}.log'):
            try:
                tail = open(lp, 'rb').read()[-400:].decode(errors='replace').replace('\n', ' | ')
                err += f' [{os.path.basename(lp)}:{tail[:200]}]'
            except Exception:
                pass
    ps.terminate(); pc.terminate()
    kill()
    print(f'[{flag}] #{idx:02d} {tag:12s} vless+grpc+TLS 3连发 sizes={sizes}B {err}', flush=True)
    return flag


if __name__ == '__main__':
    results = [run_one(1, GO, RUST, 'Rust->Go'),
               run_one(2, RUST, GO, 'Go->Rust')]
    ok = results.count('PASS')
    print(f'\n=== grpc 深层对称互操作: {ok}/{len(results)} PASS ===')
