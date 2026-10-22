#!/usr/bin/env python3
"""从 v2rayN 的 guiNDB.db 导出 share link 节点表（供 dist/run_full32.py 用）。

用法：
    python export_v2rayn_nodes.py --db "D:/Program Files/v2rayN-windows-64/guiConfigs/guiNDB.db" \
        --out D:/tmp/vps_nodes.txt [--include 关键词] [--limit N]

注意：
- 输出含凭据（UUID/密码）——只落本地临时目录，**禁止**提交进 git 或贴进报告。
- 导出的 URI 走 dist/uriclient.py 的标准 share-link 语法。
"""
import argparse, json, re, sqlite3, shutil, sys, tempfile, os
from urllib.parse import quote, urlencode

# v2rayN EConfigType（6.x）
CFG = {1: 'vmess', 3: 'ss', 4: 'socks', 5: 'vless', 6: 'trojan', 7: 'hysteria2',
       8: 'tuic', 9: 'wireguard', 10: 'http', 11: 'anytls', 12: 'naive'}


def jload(s, default=None):
    if not s:
        return default if default is not None else {}
    try:
        return json.loads(s)
    except Exception:
        return default if default is not None else {}


def build_link(r, cols):
    t = CFG.get(r['ConfigType'])
    if not t:
        return None
    addr = r['Address'] or ''
    port = r['Port'] or ''
    pwd = r['Password'] or ''
    user = r['Username'] or ''
    net = r['Network'] or 'tcp'
    sec = r['StreamSecurity'] or 'none'
    sni = r['Sni'] or ''
    fp = r['Fingerprint'] or ''
    pe = jload(r['ProtoExtra'])
    te = jload(r['TransportExtra'])
    # ws/httpupgrade/xhttp 的 path/host 存在 TransportExtra（DB 的 Path 列对 ws 常为空）
    path = te.get('Path') or r['Path'] or ''
    host = te.get('Host') or r['RequestHost'] or ''
    pbk = r['PublicKey'] or ''
    sid = r['ShortId'] or ''
    spx = r['SpiderX'] or ''
    flow = r['Flow'] or ''
    allow_insec = (r['AllowInsecure'] or '').lower() == 'true'
    alpn = r['Alpn'] or ''
    remark = r['Remarks'] or ''

    if t == 'vmess':
        vm = {
            'v': '2', 'ps': remark, 'add': addr, 'port': str(port), 'id': pwd,
            'aid': str(r['AlterId'] or 0), 'scy': pe.get('VmessSecurity', 'auto'),
            'net': net, 'type': te.get('RawHeaderType', 'none'),
            'host': host, 'path': path, 'tls': sec, 'sni': sni, 'fp': fp,
        }
        import base64
        raw = base64.b64encode(json.dumps(vm, ensure_ascii=False).encode()).decode()
        # 不加 '#remark'：dist/uriclient.py 的 vmess 分支直接 b64decode(u[8:])，
        # 不剥 fragment → 带后缀会把 base64 污染（remark 已在 JSON 的 ps 字段里）
        return f'vmess://{raw}'

    if t == 'vless':
        q = {'type': net, 'security': sec}
        if sec == 'tls':
            if sni: q['sni'] = sni
            if fp: q['fp'] = fp
            if allow_insec: q['allowInsecure'] = '1'
            if alpn: q['alpn'] = alpn
        if sec == 'reality':
            if sni: q['sni'] = sni
            if fp: q['fp'] = fp
            if pbk: q['pbk'] = pbk
            if sid: q['sid'] = sid
            if spx: q['spx'] = spx
        if net in ('ws', 'httpupgrade', 'xhttp'):
            if path: q['path'] = path
            if host: q['host'] = host
        if net == 'grpc':
            if path: q['serviceName'] = path
            mode = te.get('GrpcMode')
            if mode: q['mode'] = mode
        if net == 'kcp':
            q['headerType'] = te.get('KcpHeaderType', 'none')
            if path: q['seed'] = path
        if flow: q['flow'] = flow
        enc = pe.get('VlessEncryption')
        if enc and enc != 'none':
            q['encryption'] = enc
        frag = pe.get('WgMtu')
        if frag: q['fragment'] = f'{frag}-{pe.get("WgMtuF", frag)}'
        return f'vless://{quote(pwd, safe="")}@{addr}:{port}?{urlencode(q)}#{quote(remark)}'

    if t == 'trojan':
        q = {'type': net, 'security': sec}
        if sni: q['sni'] = sni
        if fp: q['fp'] = fp
        if allow_insec: q['allowInsecure'] = '1'
        if alpn: q['alpn'] = alpn
        if net in ('ws', 'httpupgrade', 'xhttp'):
            if path: q['path'] = path
            if host: q['host'] = host
        if net == 'grpc':
            if path: q['serviceName'] = path
        return f'trojan://{quote(pwd, safe="")}@{addr}:{port}?{urlencode(q)}#{quote(remark)}'

    if t == 'ss':
        import base64
        # ss 加密方法在 ProtoExtra.SsMethod（Security 列不存 ss method）
        method = pe.get('SsMethod') or r['Security'] or 'aes-256-gcm'
        body = base64.urlsafe_b64encode(f'{method}:{pwd}'.encode()).decode().rstrip('=')
        q = {'type': net}
        if sec and sec != 'none': q['security'] = sec
        if sni: q['sni'] = sni
        if fp: q['fp'] = fp
        if path: q['path'] = path
        if host: q['host'] = host
        if alpn: q['alpn'] = alpn
        return f'ss://{body}@{addr}:{port}?{urlencode(q)}#{quote(remark)}'

    if t == 'hysteria2':
        q = {}
        if sni: q['sni'] = sni
        if fp: q['fp'] = fp
        if allow_insec: q['insecure'] = '1'
        if alpn: q['alpn'] = alpn
        return f'hysteria2://{quote(pwd, safe="")}@{addr}:{port}?{urlencode(q)}#{quote(remark)}'

    if t == 'tuic':
        q = {'congestion_control': 'bbr'}
        if sni: q['sni'] = sni
        if alpn: q['alpn'] = alpn
        if allow_insec: q['allow_insecure'] = '1'
        return f'tuic://{quote(user, safe="")}:{quote(pwd, safe="")}@{addr}:{port}?{urlencode(q)}#{quote(remark)}'

    if t == 'anytls':
        q = {'security': sec}
        if sni: q['sni'] = sni
        if fp: q['fp'] = fp
        if allow_insec: q['insecure'] = '1'
        if alpn: q['alpn'] = alpn
        return f'anytls://{quote(pwd, safe="")}@{addr}:{port}?{urlencode(q)}#{quote(remark)}'

    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--include', default=None, help='只导出 Remarks 含该关键词的节点')
    ap.add_argument('--limit', type=int, default=0)
    a = ap.parse_args()

    tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
    tmp.close()
    shutil.copy2(a.db, tmp.name)
    con = sqlite3.connect(tmp.name)
    con.row_factory = sqlite3.Row
    rows = list(con.execute('SELECT * FROM ProfileItem ORDER BY IndexId'))
    con.close()
    os.unlink(tmp.name)

    out, skipped = [], 0
    for r in rows:
        if a.include and a.include not in (r['Remarks'] or ''):
            continue
        link = build_link(r, None)
        if link:
            out.append(link)
        else:
            skipped += 1
        if a.limit and len(out) >= a.limit:
            break
    with open(a.out, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out) + '\n')
    print(f'导出 {len(out)} 条 -> {a.out}（跳过不支持类型 {skipped} 条）')
    # 自检：用 dist/uriclient.py 逐条解析
    sys.path.insert(0, 'dist')
    try:
        from uriclient import cfg
        ok = 0
        for i, u in enumerate(out, 1):
            try:
                cfg(u, 17800 + i)
                ok += 1
            except Exception as e:
                print(f'  解析失败 #{i}: {str(e)[:70]}')
        print(f'解析自检: {ok}/{len(out)} OK')
    except Exception as e:
        print('（uriclient 导入失败，跳过自检）', e)


if __name__ == '__main__':
    main()
