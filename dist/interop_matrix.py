"""本地双向互操作矩阵: Rust client<->Go server 与 Go client<->Rust server.
6 协议 x 2 方向 = 12 测. 验收口径与 run_full32 一致: curl(YouTube marker, >5000B).
Go client 26.7.28 无 allowInsecure -> pinnedPeerCertSha256; Rust client 用 allowInsecure.
"""
import subprocess, time, os, json, sys, base64, hashlib

RUST = 'dist/xray.exe'
GO = 'D:/Project/Xray-core/target/xray-go.exe'
CERT = 'D:/tmp/interop_cert.pem'
KEY = 'D:/tmp/interop_key.pem'
# leaf DER sha256 (Go client pinnedPeerCertSha256)；从证书现算，避免证书重新生成后 pin 失配
with open(CERT) as _f:
    PIN = hashlib.sha256(base64.b64decode(
        ''.join(l for l in _f.read().splitlines() if '-----' not in l))).hexdigest()
UUID = 'b831381d-6324-4d53-ad4f-8cda48b30811'
TPW = 'test-pass-12345'
SS22_KEY = base64.b64encode(b'0123456789abcdef').decode()  # 16B for 2022-blake3-aes-128-gcm
WORK = 'D:/tmp/interop_mx'
os.makedirs(WORK, exist_ok=True)

def tls_cli(rust_client):
    return {'allowInsecure': True} if rust_client else {'pinnedPeerCertSha256': PIN}

def tls_srv():
    return {'certificates': [{'certificateFile': CERT, 'keyFile': KEY}]}

def build(proto, P, rust_client):
    """返回 (server_inbound, client_outbound)"""
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
                               "tlsSettings": {"serverName": "localhost", **tls_cli(rust_client)}}}
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
                               "tlsSettings": {"serverName": "localhost", **tls_cli(rust_client)}}}
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

def kill():
    subprocess.run(['cmd', '/c', 'taskkill /F /IM xray.exe'], capture_output=True, timeout=5)
    subprocess.run(['cmd', '/c', 'taskkill /F /IM xray-go.exe'], capture_output=True, timeout=5)

def run_one(idx, proto, server_bin, client_bin, tag):
    P = 18100 + idx * 2
    S = P + 1
    si, co = build(proto, P, client_bin == RUST)
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
    bp = f'{WORK}/b{idx}.body'
    try:
        r = subprocess.run(['curl', '-sS', '--max-time', '15', '-x', f'socks5h://127.0.0.1:{S}',
                            'https://www.youtube.com/', '-o', bp, '-w', 'HTTP:%{http_code}'],
                           capture_output=True, text=True, timeout=20)
        bs = os.path.getsize(bp) if os.path.exists(bp) else 0
        marker = b'YouTube' in open(bp, 'rb').read(200000) if bs else False
        flag = 'PASS' if (bs > 5000 and marker) else 'FAIL'
        err = r.stderr.strip()[:60]
    except Exception as e:
        flag, bs, err = 'FAIL', 0, str(e)[:60]
    if flag == 'FAIL':
        for lp in (f'{WORK}/s{idx}.log', f'{WORK}/c{idx}.log'):
            try:
                tail = open(lp, 'rb').read()[-400:].decode(errors='replace').replace('\n', ' | ')
                err += f' [{os.path.basename(lp)}:{tail[:200]}]'
            except Exception:
                pass
    ps.terminate(); pc.terminate()
    kill()
    print(f'[{flag}] #{idx:02d} {tag:12s} {proto:16s} HTTP body={bs:7d}B {err}', flush=True)
    return flag

if __name__ == '__main__':
    PROTOS = ['vmess', 'vless_vision_tls', 'trojan_tls', 'vless_ws', 'ss', 'ss2022']
    results = []
    idx = 1
    print('== A: Rust client -> Go server ==', flush=True)
    for p in PROTOS:
        results.append(run_one(idx, p, GO, RUST, 'Rust->Go'))
        idx += 1
    print('== B: Go client -> Rust server ==', flush=True)
    for p in PROTOS:
        results.append(run_one(idx, p, RUST, GO, 'Go->Rust'))
        idx += 1

    ok = results.count('PASS')
    print(f'\n=== 互操作矩阵: {ok}/{len(results)} PASS ===')
