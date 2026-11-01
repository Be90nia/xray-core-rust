"""vendor/ 补丁漂移对照（bd Xray-core-rust-6dgk2）。

用途：确认 `vendor/{quinn-proto,rustls,tokio-rustls}` 与「上游 crates.io 同版本原版」
的差异集合固定且可解释——防止上游升级/本地归档污染把补丁静默冲掉，也防止文档声称
的补丁其实不在树里。

做法：
  1. 从 Cargo.lock 读 vendor 目录名对应的实际版本；
  2. 从 cargo 缓存 `~/.cargo/registry/cache/*/<name>-<ver>.crate` 解包上游原版
     （缓存缺失时用 `cargo fetch` 后再跑，或手放 .crate）；
  3. 逐文件比对（**按行归一化 CRLF**：vendor 工作副本是 CRLF 检出，上游 tar 是 LF，
     不归一会把每个文本文件都报成漂移）；
  4. 输出「vendor 独有 / 上游独有 / 内容变更(+增 -删)」。

用法: python <this> [--only rustls] [--diff <相对路径>]
退出码: 0=报告成生（漂移由人判读，不做阈值 gate）
"""
import argparse
import difflib
import os
import re
import shutil
import subprocess
import sys
import tarfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
CACHE = os.path.expanduser('~/.cargo/registry/cache')
UPSTREAM_TMP = os.path.join(REPO, 'target', 'vendor-drift-upstream')
# 上游 tar 里没有、由 cargo/我们额外放进去的元数据文件
SKIP = {'.cargo-ok', '.cargo_vcs_info.json'}


def lock_versions():
    text = open(os.path.join(REPO, 'Cargo.lock'), encoding='utf-8').read()
    out = {}
    for blk in text.split('[[package]]'):
        m = re.search(r'name = "([^"]+)"\nversion = "([^"]+)"', blk)
        if m:
            out.setdefault(m.group(1), m.group(2))
    return out


def vendor_dirs():
    root = os.path.join(REPO, 'vendor')
    return sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d)))


def find_crate(name, ver):
    for idx in os.listdir(CACHE):
        p = os.path.join(CACHE, idx, f'{name}-{ver}.crate')
        if os.path.exists(p):
            return p
    return None


def extract(name, ver):
    crate = find_crate(name, ver)
    if not crate:
        subprocess.run(['cargo', 'fetch'], cwd=REPO, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        crate = find_crate(name, ver)
    if not crate:
        return None, f'上游 .crate 未在缓存中：{name}-{ver}（先 cargo fetch）'
    dest = os.path.join(UPSTREAM_TMP, f'{name}-{ver}')
    # 上次中断可能留下半棵树：ignore_errors 保证可重跑（Windows 上 rmtree 会因
    # 目录非空/句柄占用抛 WinError 145，直接把后续对比打成残缺树）。
    shutil.rmtree(dest, ignore_errors=True)
    if os.path.isdir(dest):
        return None, f'无法清理旧的解包目录：{dest}（手工删除后重跑）'
    os.makedirs(UPSTREAM_TMP, exist_ok=True)
    with tarfile.open(crate, 'r:gz') as tf:
        tf.extractall(UPSTREAM_TMP, filter='data')
    return dest, None


def walk(root):
    out = {}
    for dirpath, _, files in os.walk(root):
        for f in files:
            p = os.path.join(dirpath, f)
            rel = os.path.relpath(p, root).replace(os.sep, '/')
            if rel not in SKIP:
                out[rel] = p
    return out


def norm(b):
    return b.replace(b'\r\n', b'\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only', help='只查这一个 vendor 目录')
    ap.add_argument('--diff', help='打印该相对路径的逐行 diff（如 src/lib.rs）')
    args = ap.parse_args()

    vers = lock_versions()
    names = [args.only] if args.only else vendor_dirs()
    rc = 0
    for name in names:
        ver = vers.get(name)
        if not ver:
            print(f'## {name}: Cargo.lock 无此包，跳过')
            continue
        up, err = extract(name, ver)
        if err:
            print(f'## {name}: {err}')
            rc = 1
            continue
        v, u = walk(os.path.join(REPO, 'vendor', name)), walk(up)
        only_v = sorted(set(v) - set(u))
        only_u = sorted(set(u) - set(v))
        common = sorted(set(v) & set(u))
        changed = []
        for rel in common:
            a, b = norm(open(u[rel], 'rb').read()), norm(open(v[rel], 'rb').read())
            if a == b:
                continue
            try:
                at = a.decode('utf-8').splitlines()
                bt = b.decode('utf-8').splitlines()
            except UnicodeDecodeError:
                changed.append((rel, 'binary differs'))
                continue
            d = list(difflib.unified_diff(at, bt, lineterm='', n=0))
            plus = sum(1 for l in d if l.startswith('+') and not l.startswith('+++'))
            minus = sum(1 for l in d if l.startswith('-') and not l.startswith('---'))
            changed.append((rel, f'+{plus} -{minus}'))
            if args.diff == rel:
                print('\n'.join(difflib.unified_diff(at, bt, f'upstream/{rel}',
                                                     f'vendor/{rel}', lineterm='', n=3)))
        print('=' * 78)
        print(f'## {name}  基线 = 上游 crates.io {ver}')
        print(f'   文件: vendor={len(v)} 上游={len(u)} 相同={len(common) - len(changed)} '
              f'变更={len(changed)}')
        print(f'   vendor 独有(我们加的): {only_v or "无"}')
        print(f'   上游独有(我们删的): {only_u or "无"}')
        for rel, stat in changed:
            print(f'   变更 {rel:<58} {stat}')
    return rc


if __name__ == '__main__':
    sys.exit(main())
