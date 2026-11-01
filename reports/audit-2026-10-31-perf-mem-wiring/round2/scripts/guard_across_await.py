import os, re, sys

ROOT = 'crates'
LOCK = re.compile(r'\b(?:let\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*)(.+?)\.(lock|read|write)\(\)\s*\.await')
TMPLOCK = re.compile(r'\.(lock|read|write)\(\)\s*\.await')

def strip_code(line):
    # remove line comments and string literals roughly
    out = []
    i = 0
    while i < len(line):
        c = line[i]
        if c == '/' and i+1 < len(line) and line[i+1] == '/':
            break
        if c == '"':
            i += 1
            while i < len(line) and line[i] != '"':
                if line[i] == '\\': i += 1
                i += 1
        else:
            out.append(c)
        i += 1
    return ''.join(out)

def find_already_awaited(line):
    return TMPLOCK.search(line)

results = []
for dp, dn, fn in os.walk(ROOT):
    for f in fn:
        if not f.endswith('.rs'): continue
        p = os.path.join(dp, f)
        try:
            lines = open(p, encoding='utf-8', errors='replace').read().split('\n')
        except Exception:
            continue
        # skip tests region markers to reduce noise
        for idx, raw in enumerate(lines):
            line = strip_code(raw)
            m = LOCK.search(line)
            if not m: continue
            var = m.group(1)
            if not var: continue
            depth = 0
            for ch in line[:m.start(1)]:
                if ch in '{(': depth += 1
                elif ch in '})': depth -= 1
            start_depth = depth
            # scan forward for awaits at depth >= start_depth until drop or scope end
            d = start_depth
            balances = line.count('{') - line.count('}')
            cur = start_depth + balances
            dropped = False
            hit = None
            for j in range(idx+1, min(idx+60, len(lines))):
                L = strip_code(lines[j])
                if re.search(r'\bdrop\(\s*'+re.escape(var)+r'\s*\)', L):
                    dropped = True
                    break
                if TMPLOCK.search(L) and L.strip():
                    hit = j+1
                    break
                cur += L.count('{') - L.count('}')
                if cur < start_depth - 1 and L.strip() and not L.strip().startswith(('}', ')')):
                    break
                if cur < start_depth - 1:
                    break
            if hit and not dropped:
                results.append((p, idx+1, var, hit, lines[idx].strip()[:100], lines[hit-1].strip()[:100]))

print(len(results), 'candidate guard-across-await sites')
for r in results:
    print(f'{r[0]}:{r[1]} guard={r[2]} -> await@{r[3]}')
    print(f'    {r[4]}')
    print(f'    {r[5]}')
