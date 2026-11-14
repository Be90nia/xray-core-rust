"""
vless ENC (xtls vless encryption, mlkem768x25519plus) xor_mode 本地双向互操作矩阵。
模式: random==2 / xorpub==1 / native==0；方向: Rust client->Go server、Go client->Rust server。
验收口径与 interop_matrix 一致: curl(YouTube marker, >5000B)。端口基址 18200。
vision 维度（bd hr3el）：flow=xtls-rprx-vision × ENC 双向（默认计划尾部两条）；上游是
TLS 目标 ⇒ 触发 vision DIRECT ⇒ 覆盖 ENC 之上的读写透传（bd tgf3v 修通项）。
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
UPSTREAM_URL = 'https://www.youtube.com/'
UPSTREAM_MARKER = b'YouTube'
UPSTREAM_MIN_BODY = 5000


def start_local_upstream():
    """--upstream local：脚本内 1KB HTTP echo（流量仍穿被测隧道，仅去掉外网依赖）。

    注意：HTTP 载荷不触发 vision DIRECT（DIRECT 只在载荷本身是 TLS 时触发），
    故本地 hermetic 形态覆盖「ENC+vision 的 padding/解包」，DIRECT 之上的透传
    由 probe_interop.py（本地 https 目标）与 CI 默认上游（https）覆盖。
    """
    import http.server
    import threading

    body = b'XRAY-ECHO-OK\n' + b'x' * (1024 - 13)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *a):
            pass

    srv = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    global UPSTREAM_URL, UPSTREAM_MARKER, UPSTREAM_MIN_BODY
    UPSTREAM_URL = 'http://127.0.0.1:%d/' % srv.server_address[1]
    UPSTREAM_MARKER = b'XRAY-ECHO-OK'
    UPSTREAM_MIN_BODY = 1000
    return srv


def tls_cli(rust_client):
    # bd 5x41: allowInsecure 已在配置期硬错，双向统一走证书 pin。
    return {'pinnedPeerCertSha256': PIN}


def tls_srv():
    return {'certificates': [{'certificateFile': CERT, 'keyFile': KEY}]}


def build(mode_word, P, rust_client, vision=False):
    """返回 (server_inbound, client_outbound)。mode_word: native/xorpub/random

    vision=True 追加 bd hr3el 覆盖的组合：`flow=xtls-rprx-vision` 与 VLESS ENC 同时
    启用（ENC 在 vision 之下，外层 TLS1.3 必备）。此时 acceptance 上游是 TLS 目标
    （默认 https://www.youtube.com/）⇒ 触发 vision DIRECT ⇒ 覆盖 ENC 之上的读写透传
    （bd tgf3v）；非 vision 用例不触发。
    """
    dec = f'mlkem768x25519plus.{mode_word}.0s.{SEED_B64}'
    enc = f'mlkem768x25519plus.{mode_word}.1rtt.{PUB_B64}'
    srv_user = {"id": UUID, **({"flow": "xtls-rprx-vision"} if vision else {})}
    cli_user = {"id": UUID, "encryption": enc,
                **({"flow": "xtls-rprx-vision"} if vision else {})}
    si = {"port": P, "listen": "127.0.0.1", "protocol": "vless",
          "settings": {"decryption": dec, "clients": [srv_user]},
          "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_srv()}}
    co = {"protocol": "vless", "settings": {"vnext": [
        {"address": "127.0.0.1", "port": P, "users": [cli_user]}]},
        "streamSettings": {"network": "tcp", "security": "tls",
                           "tlsSettings": {"serverName": "localhost", **tls_cli(rust_client)}}}
    return si, co


def kill():
    subprocess.run(['cmd', '/c', 'taskkill /F /IM xray.exe'], capture_output=True, timeout=5)
    subprocess.run(['cmd', '/c', 'taskkill /F /IM xray-go.exe'], capture_output=True, timeout=5)


def run_one(idx, mode_word, server_bin, client_bin, tag, vision=False):
    P = 18200 + idx * 2
    S = P + 1
    si, co = build(mode_word, P, client_bin == RUST, vision=vision)
    scfg = {"log": {"loglevel": "warning"}, "inbounds": [si],
            "outbounds": [{"protocol": "freedom",
                           "settings": {"finalRules": [{"action": "allow"}]}}]}
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
    if os.path.exists(bp):
        os.remove(bp)
    try:
        r = subprocess.run(['curl', '-sS', '--max-time', '15', '-x', f'socks5h://127.0.0.1:{S}',
                            UPSTREAM_URL, '-o', bp, '-w', 'HTTP:%{http_code}'],
                           capture_output=True, text=True, timeout=20)
        bs = os.path.getsize(bp) if os.path.exists(bp) else 0
        marker = UPSTREAM_MARKER in open(bp, 'rb').read(200000) if bs else False
        flag = 'PASS' if (bs > UPSTREAM_MIN_BODY and marker) else 'FAIL'
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
    label = f'{tag}{"+vision" if vision else ""}'
    print(f'[{flag}] #{idx:02d} {label:20s} enc_{mode_word:6s} HTTP body={bs:7d}B {err}', flush=True)
    return flag


if __name__ == '__main__':
    os.makedirs(WORK, exist_ok=True)
    argv = sys.argv[1:]
    for flag, name in (('--rust', 'RUST'), ('--go', 'GO')):
        if flag in argv:
            i = argv.index(flag)
            globals()[name] = argv[i + 1]
            argv = argv[:i] + argv[i + 2:]
    if '--upstream' in argv:
        i = argv.index('--upstream')
        up = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
        if up == 'local':
            srv = start_local_upstream()
            print(f'== 上游: local echo {UPSTREAM_URL} (hermetic) ==', flush=True)
        else:
            UPSTREAM_URL, UPSTREAM_MARKER = up, None
            UPSTREAM_MIN_BODY = 1000
            print(f'== 上游: {up} ==', flush=True)
    modes = argv or ['random', 'random', 'native', 'xorpub']
    plan = [('random', GO, RUST, 'Rust->Go', False),
            ('random', RUST, GO, 'Go->Rust', False),
            ('native', GO, RUST, 'Rust->Go', False),
            ('xorpub', RUST, GO, 'Go->Rust', False),
            # bd hr3el：ENC × vision 双向（bd tgf3v 修通项）
            ('native', GO, RUST, 'Rust->Go', True),
            ('native', RUST, GO, 'Go->Rust', True)]
    # 位置参数（去掉 --flag 之后仍剩下的）= 模式列表时跑全叉积；否则跑上面的基准
    # 计划（4 条既有 + 2 条 ENC×vision）。禁用原始 sys.argv 判据：它含 flag，
    # 恒非空 ⇒ 基准计划永远被展开（hr3el 首版踩过）。
    if argv:
        plan = ([(m, GO, RUST, 'Rust->Go', False) for m in modes]
                + [(m, RUST, GO, 'Go->Rust', False) for m in modes]
                + [(m, GO, RUST, 'Rust->Go', True) for m in modes]
                + [(m, RUST, GO, 'Go->Rust', True) for m in modes])
    results = []
    idx = 1
    for mode_word, sb, cb, tag, vision in plan:
        results.append(run_one(idx, mode_word, sb, cb, tag, vision=vision))
        idx += 1
    ok = results.count('PASS')
    print(f'\n=== ENC 互操作矩阵: {ok}/{len(results)} PASS ===')
