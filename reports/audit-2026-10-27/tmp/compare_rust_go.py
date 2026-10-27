"""32/32 对照组 diff: 同一节点表、同一判据, Rust vs Go 逐节点比较.

用途（2026-10-27 收口）:
  只有 Rust 失败 -> 候选代码回归（必须查根因, 见 probe_fail 定向取证）
  两边都失败     -> 节点侧问题（死 IP / URI 缺参 / 对端 webserver 拒 ws）
用法: python reports/audit-2026-10-27/tmp/compare_rust_go.py
输出: reports/audit-2026-10-27/32-32-control-diff.md
"""
import collections, os, re

RUST = 'D:/tmp/xray_real/f_results.txt'
GO = 'D:/tmp/xray_real_go/f_results.txt'
OUT = 'reports/audit-2026-10-27/32-32-control-diff.md'


def load(path):
    if not os.path.exists(path):
        raise SystemExit(f'缺结果文件: {path}')
    d = {}
    for line in open(path, encoding='utf-8'):
        m = re.match(r'\[(PASS|FAIL|PARSE)\]\s*#(\d+)\s+(\S+)\s+(\S+)', line)
        if not m:
            continue
        flag, idx, proto, secnet = m.group(1), int(m.group(2)), m.group(3), m.group(4)
        body = 0
        bm = re.search(r'body=\s*(\d+)B', line)
        if bm:
            body = int(bm.group(1))
        d[idx] = (flag, proto, secnet, body, line.strip())
    return d


rust, go = load(RUST), load(GO)
rows, only_rust, both_fail, only_go = [], [], [], []
for i in sorted(set(rust) | set(go)):
    r = rust.get(i)
    g = go.get(i)
    rf = r[0] if r else 'MISSING'
    gf = g[0] if g else 'MISSING'
    tag = r[2] if r else (g[2] if g else '?')
    proto = r[1] if r else (g[1] if g else '?')
    rows.append((i, proto, tag, rf, gf, r[3] if r else 0, g[3] if g else 0))
    if rf != 'PASS' and gf == 'PASS':
        only_rust.append((i, proto, tag, r[4] if r else ''))
    elif rf != 'PASS' and gf != 'PASS':
        both_fail.append((i, proto, tag, rf, gf))
    elif rf == 'PASS' and gf != 'PASS':
        only_go.append((i, proto, tag, gf))

rp = sum(1 for v in rust.values() if v[0] == 'PASS')
gp = sum(1 for v in go.values() if v[0] == 'PASS')
lines = [
    '# 32/32 对照组 diff（Rust vs Go，同节点表 / 同判据）',
    '',
    f'- Rust: **{rp}/{len(rust)} PASS**',
    f'- Go  : **{gp}/{len(go)} PASS**',
    f'- 仅 Rust 失败（候选回归）: **{len(only_rust)}**',
    f'- 两边都失败（节点侧）: **{len(both_fail)}**',
    f'- 仅 Go 失败（Rust 更强）: **{len(only_go)}**',
    '',
]
if only_rust:
    lines += ['## ⚠️ 仅 Rust 失败（必须查根因）', '', '| # | 协议 | 传输 | 说明 |', '|---|---|---|---|']
    for i, proto, tag, line in only_rust:
        lines.append(f'| {i} | {proto} | {tag} | `{line[:110]}` |')
    lines.append('')
if both_fail:
    lines += ['## 两边都失败（节点侧问题，非代码回归）', '', '| # | 协议 | 传输 | Rust | Go |', '|---|---|---|---|---|']
    for i, proto, tag, rf, gf in both_fail:
        lines.append(f'| {i} | {proto} | {tag} | {rf} | {gf} |')
    lines.append('')
if only_go:
    lines += ['## 仅 Go 失败（Rust 通过）', '']
    for i, proto, tag, gf in only_go:
        lines.append(f'- #{i} {proto} {tag}: Go={gf}')
    lines.append('')
lines += ['## 全量对照', '', '| # | 协议 | 传输 | Rust | Go |', '|---|---|---|---|---|']
for i, proto, tag, rf, gf, rb, gb in rows:
    mark = '' if rf == gf else ' **≠**'
    lines.append(f'| {i} | {proto} | {tag} | {rf}{mark} | {gf} |')
open(OUT, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
print(f'Rust {rp}/{len(rust)} | Go {gp}/{len(go)} | 仅Rust失败 {len(only_rust)} | 两边失败 {len(both_fail)} | 仅Go失败 {len(only_go)}')
print('报告:', OUT)
if only_rust:
    print('⚠️ 仅 Rust 失败的节点:')
    for i, proto, tag, line in only_rust:
        print(f'  #{i} {proto} {tag}')
