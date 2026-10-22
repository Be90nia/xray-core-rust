"""全 32 节点通测,用与 test_all_v3.py/test_direct.py 相同 cfg() 路径。

用法（发版门禁 G3 要 Go/Rust 两轮，故参数化）：
    python dist/run_full32.py --bin <xray 可执行> [--uri-file <节点表>] [--work <工作目录>]

注：原实现用 `taskkill /F /IM xray.exe` 清场——会连带杀掉用户 v2rayN 的 xray
（项目红线：v2rayN 内核自动重启，勿 taskkill），且 Go/Rust 两轮连跑时会互踩。
现改为只终止自己拉起的进程。
"""
import subprocess, time, os, sys, json
sys.path.insert(0, 'dist')
from uriclient import cfg

import argparse
_ap = argparse.ArgumentParser()
_ap.add_argument('--bin', default=os.environ.get('FULL32_BIN', 'dist/xray.exe'))
_ap.add_argument('--uri-file', default=os.environ.get('FULL32_URI', 'vps测试连接.txt'))
_ap.add_argument('--work', default=os.environ.get('FULL32_WORK', 'D:/tmp/xray_real'))
_ap.add_argument('--url', default='https://www.youtube.com/')
_args = _ap.parse_args()

URI_FILE = _args.uri_file
BIN = _args.bin
WORK = _args.work
os.makedirs(WORK, exist_ok=True)

SKIP = set()

def test(idx, uri, url):
    sp = 17800 + idx
    try: ob = cfg(uri.strip(), sp)
    except Exception as e:
        return f'#{idx}\tPARSE\t{e}'
    cfgobj = {
        'log':{'loglevel':'warn'},
        'inbounds':[{'tag':'socks-in','listen':'127.0.0.1','port':sp,'protocol':'socks','settings':{'udp':True}}],
        'outbounds':[ob,{'tag':'direct','protocol':'freedom','settings':{}}],
        'routing':{'rules':[{'type':'field','port':'1-65535','outboundTag':ob.get('tag','proxy') or 'proxy'}]}
    }
    cp = f'{WORK}/f_{idx}.json'
    lp = f'{WORK}/f_{idx}.log'
    bp = f'{WORK}/f_{idx}.body'
    open(cp,'w',encoding='utf-8').write(json.dumps(cfgobj, ensure_ascii=False))
    open(bp,'wb').close()
    p = subprocess.Popen([BIN,'run','-c',cp], stdout=open(lp,'wb'), stderr=open(lp+'.err','wb'))
    time.sleep(2.5)
    code = subprocess.run(['curl','-sS','--max-time','12','-x',f'socks5h://127.0.0.1:{sp}', url, '-o', bp, '-w','HTTP:%{http_code}'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15)
    bs = os.path.getsize(bp)
    with open(bp,'rb') as f: body = f.read()
    net = ob.get('streamSettings',{}).get('network','tcp')
    sec = ob.get('streamSettings',{}).get('security','none')
    proto = ob.get('protocol','?')
    expected = b'YouTube' if 'youtube' in url else b'Google' if 'google' in url else b''
    flag = 'PASS' if (bs > 5000 and expected in body) else 'FAIL'
    err = code.stderr.strip()[:80] if code.returncode != 0 else ''
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()
    return f'[{flag}] #{idx}\t{proto}\t{sec}/{net}\tHTTP={code.stdout.strip():12s}\tbody={bs:7d}B\t{err}'

uris = [u.strip() for u in open(URI_FILE, encoding='utf-8') if u.strip() and not u.startswith('#') and not u.startswith('{')]
print(f'# 共 {len(uris)} 个节点,跳过 {sorted(SKIP)}')
print('# proto  sec/net  HTTP  body marker err')

results = []
for i, uri in enumerate(uris, 1):
    if i in SKIP: continue
    line = test(i, uri, _args.url)
    print(line, flush=True)
    results.append(line)

passes = sum(1 for l in results if l.startswith('[PASS]'))
fails = sum(1 for l in results if l.startswith('[FAIL]'))
parses = sum(1 for l in results if l.startswith('[PARSE'))
print(f'\n=== {passes}/{len(results)} PASS  {fails} FAIL  {parses} PARSE ===')
open(f'{WORK}/f_results.txt','w',encoding='utf-8').write('\n'.join(results))
