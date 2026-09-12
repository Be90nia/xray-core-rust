"""
vless ENC (xtls vless encryption, mlkem768x25519plus) xor_mode 本地双向互操作矩阵。
模式: random==2 / xorpub==1 / native==0；方向: Rust client->Go server、Go client->Rust server。
验收口径与 interop_matrix 一致: curl(YouTube marker, >5000B)。端口基址 18200。
ENC 字符串 (Go infra/conf/vless.go):
  client encryption : mlkem768x25519plus.<mode>.1rtt.<pub_b64url>
  server decryption : mlkem768x25519plus.<mode>.0s.<seed_b64url>
X25519 keypair 固定 (pub[31]=0x5f<128, 过 Go server.go:150 最高位检查):
  seed 000102..1f, pub 8f40c5ad..38285f
"""
import subprocess, time, os, json, sys, base64, hashlib

UUID = 'b831381d-6324-4d53-ad4f-8cda48b30811'
RUST = 'dist/xray.exe'
GO = 'D:/Project/Xray-core/target/xray-go.exe'
WORK = 'dist/interop_run'
CERT = 'D:/tmp/interop_cert.pem'
KEY = 'D:/tmp/interop_key.pem'
with open(CERT) as _f:
    PIN = hashlib.sha256(base64.b64decode(
        ''.join(l for l in _f.read().splitlines() if '-----' not in l))).hexdigest()

SEED_B64 = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'
PUB_B64 = 'j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF8'
MODE = {'random': 2, 'xorpub': 1, 'native': 0}


def tls_cli(rust_client):
    # bd 5x41: allowInsecure 已在配置期硬错，双向统一走证书 pin。
    return {'pinnedPeerCertSha256': PIN}


def tls_srv():
    return {'certificates': [{'certificateFile': CERT, 'keyFile': KEY}]}


def build(mode_word, P, rust_client):
    """返回 (server_inbound, client_outbound)。mode_word: native/xorpub/random"""
    dec = f'mlkem768x25519plus.{mode_word}.0s.{SEED_B64}'
    enc = f'mlkem768x25519plus.{mode_word}.1rtt.{PUB_B64}'
    si = {"port": P, "listen": "127.0.0.1", "protocol": "vless",
          "settings": {"decryption": dec, "clients": [{"id": UUID}]},
          "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_srv()}}
    co = {"protocol": "vless", "settings": {"vnext": [
        {"address": "127.0.0.1", "port": P,
         "users": [{"id": UUID, "encryption": enc}]}]},
        "streamSettings": {"network": "tcp", "security": "tls",
                           "tlsSettings": {"serverName": "localhost", **tls_cli(rust_client)}}}
    return si, co


def kill():
    subprocess.run(['cmd', '/c', 'taskkill /F /IM xray.exe'], capture_output=True, timeout=5)
    subprocess.run(['cmd', '/c', 'taskkill /F /IM xray-go.exe'], capture_output=True, timeout=5)


def run_one(idx, mode_word, server_bin, client_bin, tag):
    P = 18200 + idx * 2
    S = P + 1
    si, co = build(mode_word, P, client_bin == RUST)
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
    print(f'[{flag}] #{idx:02d} {tag:12s} enc_{mode_word:6s} HTTP body={bs:7d}B {err}', flush=True)
    return flag


if __name__ == '__main__':
    os.makedirs(WORK, exist_ok=True)
    modes = sys.argv[1:] or ['random', 'random', 'native', 'xorpub']
    plan = [('random', GO, RUST, 'Rust->Go'),
            ('random', RUST, GO, 'Go->Rust'),
            ('native', GO, RUST, 'Rust->Go'),
            ('xorpub', RUST, GO, 'Go->Rust')]
    if len(sys.argv) > 1:
        plan = [(m, GO, RUST, 'Rust->Go') for m in modes] + [(m, RUST, GO, 'Go->Rust') for m in modes]
    results = []
    idx = 1
    for mode_word, sb, cb, tag in plan:
        results.append(run_one(idx, mode_word, sb, cb, tag))
        idx += 1
    ok = results.count('PASS')
    print(f'\n=== ENC 互操作矩阵: {ok}/{len(results)} PASS ===')
