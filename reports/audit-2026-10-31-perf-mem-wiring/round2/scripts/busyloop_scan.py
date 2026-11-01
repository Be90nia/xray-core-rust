import os, re
ROOT='crates'
# select! arms that pattern-match Some(x) = rx.recv() -> None => arm disabled forever
pat = re.compile(r'^\s*Some\([^)]*\)\s*=\s*\w+\.recv\(\)\s*=>')
for dp,dn,fn in os.walk(ROOT):
    for f in fn:
        if not f.endswith('.rs'): continue
        p=os.path.join(dp,f)
        lines=open(p,encoding='utf-8',errors='replace').read().split('\n')
        for i,l in enumerate(lines):
            if pat.search(l):
                # context: enclosing loop within 30 lines above, and same select whether None arm exists
                ctx='\n'.join(lines[max(0,i-15):i+16])
                print(f'{p}:{i+1}: {l.strip()}')
                print('   has_None_arm_in_select:', bool(re.search(r'^\s*None\s*=>', ctx, re.M)))
