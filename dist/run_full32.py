"""全 32 节点通测,用与 test_all_v3.py/test_direct.py 相同 cfg() 路径。"""
import subprocess, time, os, sys, json
sys.path.insert(0, 'dist')
from uriclient import cfg

URI_FILE = 'vps测试连接.txt'
BIN = 'dist/xray.exe'
WORK = 'D:/tmp/xray_real'
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
    subprocess.run(['cmd','/c','taskkill /F /IM xray.exe'], capture_output=True, timeout=5)
    time.sleep(0.2)
    p = subprocess.Popen([BIN,'run','-c',cp], stdout=open(lp,'wb'), stderr=open(lp+'.err','wb'))
    time.sleep(2.5)
    code = subprocess.run(['curl','-sS','--max-time','12','-x',f'socks5h://127.0.0.1:{sp}', url, '-o', bp, '-w','HTTP:%{http_code}'], capture_output=True, text=True, timeout=15)
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
    subprocess.run(['cmd','/c','taskkill /F /IM xray.exe'], capture_output=True, timeout=5)
    return f'[{flag}] #{idx}\t{proto}\t{sec}/{net}\tHTTP={code.stdout.strip():12s}\tbody={bs:7d}B\t{err}'

uris = [u.strip() for u in open(URI_FILE, encoding='utf-8') if u.strip() and not u.startswith('#') and not u.startswith('{')]
print(f'# 共 {len(uris)} 个节点,跳过 {sorted(SKIP)}')
print('# proto  sec/net  HTTP  body marker err')

results = []
for i, uri in enumerate(uris, 1):
    if i in SKIP: continue
    line = test(i, uri, 'https://www.youtube.com/')
    print(line, flush=True)
    results.append(line)

passes = sum(1 for l in results if l.startswith('[PASS]'))
fails = sum(1 for l in results if l.startswith('[FAIL]'))
parses = sum(1 for l in results if l.startswith('[PARSE'))
print(f'\n=== {passes}/{len(results)} PASS  {fails} FAIL  {parses} PARSE ===')
open(f'{WORK}/f_results.txt','w',encoding='utf-8').write('\n'.join(results))
