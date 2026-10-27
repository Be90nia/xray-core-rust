"""真节点 REALITY 双向验证（可复跑，一条命令）。

背景（2026-10-27 夜）：
  节点表 D:/tmp/vps_nodes.txt 的 #6/#26/#27（trojan + reality/raw）原先**缺 pbk/sid/fp/sni**，
  补参后 reality 才可连（补参来源：v2rayN 的 guiNDB.db → ProfileItem by Address+Port）。
  补参后实测：Rust client 3/3 通（200/147/152KB），Go client 同 3 节点 3/3 通。

用途：验证「Rust client → 真 Go server」的 REALITY 路径（dist/interop_matrix.py 不含 reality）。
用法：
  python reports/audit-2026-10-27/tmp/verify_reality_nodes.py            # 默认 Rust+Go 各跑 3 节点
  python reports/audit-2026-10-27/tmp/verify_reality_nodes.py --rust-only
判据：HTTP 200 且 body > 5000B（Cloudflare 定长下载，本机可用的可达判据）。
"""
import argparse, json, os, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(ROOT, 'dist'))
from uriclient import cfg  # noqa: E402

NODES = 'D:/tmp/vps_nodes.txt'
URL = 'https://speed.cloudflare.com/__down?bytes=200000'
BINS = {'Rust': os.path.join(ROOT, 'target/release/xray.exe'),
        'Go': 'D:/Project/Xray-core/target/xray-go.exe'}
# reality 节点下标（1-based）：补参后的 trojan + reality/raw
TARGETS = [6, 26, 27]


def run(bin_path, uri, socks_port, workdir):
    ob = cfg(uri)
    full = {"log": {"loglevel": "warning"},
            "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
                          "protocol": "socks", "settings": {"udp": True},
                          "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}}],
            "outbounds": [ob, {"tag": "direct", "protocol": "freedom", "settings": {}}]}
    cpath = os.path.join(workdir, 'c.json')
    with open(cpath, 'w') as f:
        json.dump(full, f)
    lpath = os.path.join(workdir, 'x.log')
    with open(lpath, 'wb') as lf:
        proc = subprocess.Popen([bin_path, 'run', '-c', cpath], stdout=lf, stderr=subprocess.STDOUT)
    time.sleep(2.5)
    try:
        r = subprocess.run(['curl', '-s', '-o', 'NUL', '-w', '%{http_code} %{size_download}',
                            '--max-time', '12', '-x', f'socks5h://127.0.0.1:{socks_port}', URL],
                           capture_output=True, text=True, timeout=40)
        out = r.stdout.strip()
    except Exception as e:  # noqa: BLE001
        out = f'curl-error {e}'
    proc.terminate()
    try:
        proc.wait(5)
    except Exception:  # noqa: BLE001
        proc.kill()
    errs = [l for l in open(lpath, encoding='utf-8', errors='replace').read().splitlines()
            if any(k in l.lower() for k in ('error', 'fail', 'reality', 'handshake'))]
    try:
        code, size = out.split()
        ok = code == '200' and int(size) > 5000
    except ValueError:
        ok = False
    return ok, out, (errs[-1][:120] if errs else '')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rust-only', action='store_true')
    ap.add_argument('--nodes', default=NODES)
    args = ap.parse_args()
    uris = [l.strip() for l in open(args.nodes, encoding='utf-8') if l.strip()]
    bins = {'Rust': BINS['Rust']} if args.rust_only else BINS
    results = []
    for name, binp in bins.items():
        if not os.path.exists(binp):
            print(f'[SKIP] {name}: 二进制不存在 {binp}')
            continue
        print(f'== {name} ==', flush=True)
        for i in TARGETS:
            d = tempfile.mkdtemp(prefix=f'rly_{i}_', dir='D:/tmp')
            ok, out, err = run(binp, uris[i - 1], 19000 + i, d)
            results.append(ok)
            print(f'  [{"PASS" if ok else "FAIL"}] #{i} reality/raw  {out}'
                  + (f'  | {err}' if err else ''), flush=True)
    ok_n = results.count(True)
    print(f'\n=== REALITY 真节点: {ok_n}/{len(results)} PASS ===')
    return 0 if ok_n == len(results) and results else 1


if __name__ == '__main__':
    sys.exit(main())
