"""本地双向 REALITY wire 互操作: Rust client<->Go server 与 Go client<->Rust server.
协议 = vless + reality + 裸 TCP (trojan+reality Go 侧已 deprecate, 不用).
判据 = 本地源站 200014B (INTEROP_MARKER), body>5000B 且 marker 命中; 两侧日志无 reality 类错误.
dest 回退站点 = 本地 HTTPS (interop_cert.pem CN=localhost, 与 serverNames 一致).
只 kill 自己拉起的进程: 二进制拷贝为唯一映像名, 禁全名杀手 (保护用户 v2rayN 核心).
"""
import subprocess, time, os, json, re, sys, socket, shutil, http.server, threading, atexit

RUST_SRC = os.path.abspath('target/release/xray.exe')
GO_SRC = 'D:/Project/Xray-core/target/xray-go.exe'
CERT = 'D:/tmp/interop_cert.pem'
KEY = 'D:/tmp/interop_key.pem'
UUID = 'b831381d-6324-4d53-ad4f-8cda48b30811'
DEST_UUID = '23e69ee7-10e2-41e9-9a31-9b53df69b463'
SID = '0123456789abcdef'  # 8B hex
WORK = 'D:/tmp/interop_reality'
os.makedirs(WORK, exist_ok=True)
RUST = f'{WORK}/xray-reality-it.exe'      # 唯一映像名拷贝: 全名杀手安全
GO = f'{WORK}/xray-reality-it-go.exe'
KILL_NAMES = ['xray-reality-it.exe', 'xray-reality-it-go.exe']
# 日志错误扫描: reality 行带错误词, 或 Go "REALITY: processed invalid connection", 或 panic
BAD_LOG = re.compile(rb'(?i)reality.{0,200}?(error|fail|invalid|denied|reject|panic)|REALITY:|panic')
# Go 配置期两条已知良性告警(配置建议, 非握手错误), 白名单剔除
BENIGN = (b'The default minimal client version', b'non-443 ports')

def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p

def wait_port(port, timeout, what):
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket()
        s.settimeout(0.5)
        try:
            s.connect(('127.0.0.1', port))
            return
        except OSError:
            time.sleep(0.25)
        finally:
            s.close()
    raise RuntimeError(f'port {port} ({what}) not up in {timeout}s')

def sweep():
    for name in KILL_NAMES:
        subprocess.run(['taskkill', '/F', '/IM', name], capture_output=True, timeout=10)

atexit.register(sweep)

def x25519(binpath):
    """跑 xray x25519 子命令, 返回 (privateKey, publicKey)."""
    r = subprocess.run([binpath, 'x25519'], capture_output=True, text=True, timeout=30)
    out = r.stdout + r.stderr
    priv = re.search(r'PrivateKey:\s*(\S+)', out)
    pub = re.search(r'Password \(PublicKey\):\s*(\S+)', out)
    if not (priv and pub):
        raise RuntimeError(f'x25519 parse failed: {out[:200]}')
    return priv.group(1), pub.group(1)

ORIGIN_BODY = b'INTEROP_MARKER' + b'x' * 200000

class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(ORIGIN_BODY)))
        self.end_headers()
        self.wfile.write(ORIGIN_BODY)
    def log_message(self, *a):
        pass

def start_origin():
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

def start_dest(go_bin, work):
    """REALITY dest 回退站点: Go xray vless+tls 实例 (证书 CN=localhost 与 serverNames 一致).
    Go reality Server 每连必先 TLS 连 dest 完成 steal (xtls/reality tls.go:168),
    dest 必须是稳态 TLS 服务; Python https 线程版实测会间歇中止 steal 握手."""
    port = free_port()
    cfg = {"log": {"loglevel": "warning"},
           "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "vless",
                         "settings": {"decryption": "none", "clients": [{"id": DEST_UUID}]},
                         "streamSettings": {"network": "tcp", "security": "tls",
                                            "tlsSettings": {"certificates": [
                                                {"certificateFile": CERT, "keyFile": KEY}]}}}],
           "outbounds": [{"protocol": "freedom"}]}
    cp = f'{work}/dest.json'
    open(cp, 'w').write(json.dumps(cfg))
    lf = open(f'{work}/dest.log', 'wb')
    p = subprocess.Popen([go_bin, 'run', '-c', cp], stdout=lf, stderr=subprocess.STDOUT)
    return p, port

def ensure_cert():
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', KEY, '-out', CERT, '-days', '3650', '-subj', '/CN=localhost'],
                   check=True, capture_output=True, timeout=60)

def reality_srv_stream(priv, dest_port):
    return {"network": "tcp", "security": "reality",
            "realitySettings": {"dest": f"127.0.0.1:{dest_port}",
                                "serverNames": ["localhost"],
                                "privateKey": priv,
                                "shortIds": [SID]}}

def reality_cli_stream(pub):
    return {"network": "tcp", "security": "reality",
            "realitySettings": {"serverName": "localhost", "publicKey": pub,
                                "shortId": SID, "fingerprint": "chrome"}}

def build(P, dest_port, srv_priv, cli_pub):
    """vless+reality: server_inbound / client_outbound (两方向同形, 仅密钥/二进制不同)."""
    si = {"port": P, "listen": "127.0.0.1", "protocol": "vless",
          "settings": {"decryption": "none", "clients": [{"id": UUID}]},
          "streamSettings": reality_srv_stream(srv_priv, dest_port)}
    co = {"protocol": "vless", "settings": {"vnext": [
            {"address": "127.0.0.1", "port": P,
             "users": [{"id": UUID, "encryption": "none"}]}]},
          "streamSettings": reality_cli_stream(cli_pub)}
    return si, co

def kill_pids(*procs):
    for p in procs:
        if p and p.poll() is None:
            subprocess.run(['taskkill', '/T', '/F', '/PID', str(p.pid)],
                           capture_output=True, timeout=10)
            try:
                p.wait(timeout=10)
            except Exception:
                pass

def run_one(idx, direction, server_bin, client_bin, srv_priv, cli_pub, dest_port, origin_port):
    P, S = free_port(), free_port()
    si, co = build(P, dest_port, srv_priv, cli_pub)
    scfg = {"log": {"loglevel": "warning"}, "inbounds": [si],
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}
    ccfg = {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": S, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [co]}
    scp, ccp = f'{WORK}/s{idx}.json', f'{WORK}/c{idx}.json'
    open(scp, 'w').write(json.dumps(scfg))
    open(ccp, 'w').write(json.dumps(ccfg))
    tag = 'Rust->Go' if direction == 'A' else 'Go->Rust'
    ps = pc = None
    try:
        sl = open(f'{WORK}/s{idx}.log', 'wb')
        ps = subprocess.Popen([server_bin, 'run', '-c', scp], stdout=sl, stderr=subprocess.STDOUT)
        time.sleep(2.0)  # 服务端就绪: 固定宽限(探活 reality 端口会制造 early-eof 噪声)
        cl = open(f'{WORK}/c{idx}.log', 'wb')
        pc = subprocess.Popen([client_bin, 'run', '-c', ccp], stdout=cl, stderr=subprocess.STDOUT)
        wait_port(S, 15, f'{tag} client socks')
        bp = f'{WORK}/b{idx}.body'
        try:
            r = subprocess.run(['curl', '-sS', '--max-time', '15', '-x', f'socks5h://127.0.0.1:{S}',
                                f'http://127.0.0.1:{origin_port}/', '-o', bp, '-w', 'HTTP:%{http_code}'],
                               capture_output=True, text=True, timeout=20)
            http_code = r.stdout.strip()
            bs = os.path.getsize(bp) if os.path.exists(bp) else 0
            marker = b'INTEROP_MARKER' in open(bp, 'rb').read(200014) if bs else False
            err = r.stderr.strip()[:80]
        except Exception as e:
            http_code, bs, marker, err = '-', 0, False, str(e)[:80]
        logbad = ''
        for lp in (f'{WORK}/s{idx}.log', f'{WORK}/c{idx}.log'):
            lines = [ln for ln in open(lp, 'rb').read().splitlines()
                     if not any(b in ln for b in BENIGN)]
            hit = next((ln for ln in lines if BAD_LOG.search(ln)), None)
            if hit:
                logbad += f" [{os.path.basename(lp)}: {hit[:160].decode(errors='replace')}]"
        flag = 'PASS' if (http_code == 'HTTP:200' and bs > 5000 and marker and not logbad) else 'FAIL'
        if flag == 'FAIL' and not logbad:
            for lp in (f'{WORK}/s{idx}.log', f'{WORK}/c{idx}.log'):
                try:
                    tail = open(lp, 'rb').read()[-300:].decode(errors='replace').replace('\n', ' | ')
                    logbad += f' [{os.path.basename(lp)}:{tail[:160]}]'
                except Exception:
                    pass
        print(f'[{flag}] #{idx:02d} {tag:12s} vless+reality/tcp  HTTP={http_code} body={bs:7d}B '
              f'marker={marker}{err}{logbad}', flush=True)
        return flag
    finally:
        kill_pids(ps, pc)
        sweep()
        time.sleep(0.2)

def main():
    if not (os.path.exists(RUST_SRC) and os.path.exists(GO_SRC)):
        raise SystemExit(f'binary missing: {RUST_SRC} / {GO_SRC}')
    ensure_cert()
    shutil.copy2(RUST_SRC, RUST)
    shutil.copy2(GO_SRC, GO)
    go_priv, go_pub = x25519(GO)      # Direction A 服务端密钥 (Go x25519 生成)
    rust_priv, rust_pub = x25519(RUST)  # Direction B 服务端密钥 (Rust x25519 生成)
    origin = start_origin()
    dest_proc, dest_port = start_dest(GO, WORK)
    origin_port = origin.server_address[1]
    print(f'origin http://127.0.0.1:{origin_port}/ body={len(ORIGIN_BODY)}B; '
          f'dest=Go xray vless+tls 127.0.0.1:{dest_port} (CN=localhost)', flush=True)
    ok = []
    try:
        print('== A: Rust client -> Go server ==', flush=True)
        ok.append(run_one(1, 'A', GO, RUST, go_priv, go_pub, dest_port, origin_port))
        print('== B: Go client -> Rust server ==', flush=True)
        ok.append(run_one(2, 'B', RUST, GO, rust_priv, rust_pub, dest_port, origin_port))
    finally:
        origin.shutdown()
        kill_pids(dest_proc)
        sweep()
    n = ok.count('PASS')
    print(f'\n=== reality 互操作: {n}/{len(ok)} PASS ===', flush=True)
    return 0 if n == len(ok) else 1

if __name__ == '__main__':
    sys.exit(main())
