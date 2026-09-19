"""本地双向互操作: SplitHTTP (XHTTP) 传输层, packet-up + stream-one 两 mode.

风格与 dist/interop_matrix.py 一致: 单文件, Windows 本机; R<->R 对照 + R->G + G->R
三个方向 × 2 mode (packet-up, stream-one) = 6 测. 验收口径与 run_full32 / interop_matrix
一致: socks5h curl https://www.youtube.com/ body>5000B 且含 YouTube marker.

Go / Rust client 均用 pinnedPeerCertSha256（bd 5x41: allowInsecure 配置期硬错）.
证书由 openssl 在本脚本 work 目录下现场生成（-config 写法兼容 LibreSSL/OpenSSL,
不依赖 1.1.1+ 才有的 -addext）.
"""
import subprocess, time, os, json, base64, hashlib

RUST = 'dist/xray.exe'
GO = 'D:/Project/Xray-core/target/xray-go.exe'
UUID = 'b831381d-6324-4d53-ad4f-8cda48b30811'
WORK = 'D:/tmp/interop_split'
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


def gen_cert():
    cnf = CERT + '.cnf'
    with open(cnf, 'w') as f:
        f.write(OPENSSL_CNF)
    r = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', KEY, '-out', CERT, '-days', '2', '-config', cnf],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError('openssl 证书生成失败: ' + r.stderr.strip()[:300])
    with open(CERT) as f:
        der = base64.b64decode(''.join(l for l in f.read().splitlines() if '-----' not in l))
    return hashlib.sha256(der).hexdigest()


PIN = gen_cert()

# 两种 mode: packet-up（默认上行+GET 长轮询）+ stream-one（单 stream）
MODES = ['packet-up', 'stream-one']


def split_srv(mode):
    return {"network": "splithttp", "security": "tls",
            "splithttpSettings": {"path": "/xhttp", "mode": mode, "host": "localhost"},
            "tlsSettings": {"certificates": [{"certificateFile": CERT, "keyFile": KEY}]}}


def split_cli(mode):
    return {"network": "splithttp", "security": "tls",
            "splithttpSettings": {"path": "/xhttp", "mode": mode, "host": "localhost"},
            "tlsSettings": {"serverName": "localhost", "pinnedPeerCertSha256": PIN}}


def build(idx, mode, server_bin, client_bin):
    """返回 (P_server, S_client_socks, server_inbound, client_outbound)."""
    P = 18400 + idx * 2
    S = P + 1
    si = {"port": P, "listen": "127.0.0.1", "protocol": "vless",
          "settings": {"clients": [{"id": UUID}], "decryption": "none"},
          "streamSettings": split_srv(mode)}
    co = {"protocol": "vless", "settings": {"vnext": [
        {"address": "127.0.0.1", "port": P,
         "users": [{"id": UUID, "encryption": "none"}]}]},
          "streamSettings": split_cli(mode)}
    return P, S, si, co


def kill():
    subprocess.run(['cmd', '/c', 'taskkill /F /IM xray.exe'], capture_output=True, timeout=5)
    subprocess.run(['cmd', '/c', 'taskkill /F /IM xray-go.exe'], capture_output=True, timeout=5)


def run_one(idx, mode, server_bin, client_bin, tag):
    P, S, si, co = build(idx, mode, server_bin, client_bin)
    scfg = {"log": {"loglevel": "warning"}, "inbounds": [si],
            "outbounds": [{"protocol": "freedom",
                           "settings": {"finalRules": [{"action": "allow"}]}}]}
    ccfg = {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": S, "protocol": "socks",
                          "settings": {"udp": True}}],
            "outbounds": [co]}
    scp = os.path.join(WORK, f's{idx}.json')
    ccp = os.path.join(WORK, f'c{idx}.json')
    open(scp, 'w').write(json.dumps(scfg))
    open(ccp, 'w').write(json.dumps(ccfg))
    kill(); time.sleep(0.3)
    ps = subprocess.Popen([server_bin, 'run', '-c', scp],
                          stdout=open(os.path.join(WORK, f's{idx}.log'), 'wb'),
                          stderr=subprocess.STDOUT)
    time.sleep(2.5)
    pc = subprocess.Popen([client_bin, 'run', '-c', ccp],
                          stdout=open(os.path.join(WORK, f'c{idx}.log'), 'wb'),
                          stderr=subprocess.STDOUT)
    bp = os.path.join(WORK, f'b{idx}.body')
    try:
        r = subprocess.run(['curl', '-sS', '--max-time', '20', '-x',
                            f'socks5h://127.0.0.1:{S}',
                            'https://www.youtube.com/', '-o', bp, '-w', 'HTTP:%{http_code}'],
                           capture_output=True, text=True, timeout=25)
        bs = os.path.getsize(bp) if os.path.exists(bp) else 0
        marker = b'YouTube' in open(bp, 'rb').read(200000) if bs else False
        flag = 'PASS' if (bs > 5000 and marker) else 'FAIL'
        err = r.stderr.strip()[:60]
    except Exception as e:
        flag, bs, err = 'FAIL', 0, str(e)[:60]
    if flag == 'FAIL':
        for lp in (os.path.join(WORK, f's{idx}.log'), os.path.join(WORK, f'c{idx}.log')):
            try:
                tail = open(lp, 'rb').read()[-400:].decode(errors='replace').replace('\n', ' | ')
                err += f' [{os.path.basename(lp)}:{tail[:200]}]'
            except Exception:
                pass
    ps.terminate(); pc.terminate()
    kill()
    print(f'[{flag}] #{idx:02d} {tag:14s} splithttp/{mode:11s} HTTP body={bs:7d}B {err}', flush=True)
    return flag


if __name__ == '__main__':
    results = []
    idx = 1
    print('== A: Rust client -> Rust server (mock 对照, mode 必通) ==', flush=True)
    for m in MODES:
        results.append(run_one(idx, m, RUST, RUST, 'Rust->Rust'))
        idx += 1
    print('== B: Rust client -> Go server ==', flush=True)
    for m in MODES:
        results.append(run_one(idx, m, GO, RUST, 'Rust->Go'))
        idx += 1
    print('== C: Go client -> Rust server ==', flush=True)
    for m in MODES:
        results.append(run_one(idx, m, RUST, GO, 'Go->Rust'))
        idx += 1

    ok = results.count('PASS')
    print(f'\n=== 互操作 SplitHTTP: {ok}/{len(results)} PASS ===')
