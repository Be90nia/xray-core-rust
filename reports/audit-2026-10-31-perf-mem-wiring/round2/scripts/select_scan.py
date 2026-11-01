import os, re
ROOT='crates'
RISKY = re.compile(r'\b(read_exact|read_to_end|write_all|flush|copy_bidirectional|read_buf|read_line|lines|next_line)\b')
for dp,dn,fn in os.walk(ROOT):
    for f in fn:
        if not f.endswith('.rs'): continue
        p=os.path.join(dp,f)
        lines=open(p,encoding='utf-8',errors='replace').read().split('\n')
        i=0
        while i < len(lines):
            if 'select!' in lines[i] and not lines[i].strip().startswith('//'):
                depth=0; started=False; body=[]; j=i
                while j < len(lines):
                    L=lines[j]
                    depth += L.count('{')-L.count('}')
                    body.append((j+1,L))
                    if '{' in L: started=True
                    if started and depth<=0: break
                    j+=1
                risky=[(n,l.strip()) for n,l in body if RISKY.search(l)]
                if risky:
                    print(f'== {p}:{i+1}')
                    for n,l in body[:14]:
                        print(f'   {n}: {l.strip()[:110]}')
                    print('   RISKY:', [r[1] for r in risky])
                    print()
                i=j+1
            else:
                i+=1
