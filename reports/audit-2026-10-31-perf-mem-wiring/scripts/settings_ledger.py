"""生成 settings 键台账分母：从各 xray-proxy-* / xray-transport-* crate 的 src 里
抽取「从原始 JSON Value 取键」的站点（.get("k") / ["k"]），剔除测试代码与 HTTP 头读取。

输出 settings-ledger.tsv（列：crate / key / parse_site / file_role / 供人工补 dest+消费点）。
用法: python settings_ledger.py
"""
import os
import re

ROOT = r"D:/Project/Xray-core-rust/crates"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "settings-keys.raw.tsv")

# 明显的 HTTP 头 / wire 字段（不是 settings 键）
HEADER_KEYS = {
    "host", "content-type", "connection", "upgrade", "transfer-encoding",
    "content-length", "proxy-connection", "proxy-authorization", "grpc-status",
    "user-agent", "sec-websocket-key", "sec-websocket-protocol", "referer",
    "x-forwarded-for", "cookie", "accept", "pragma", "cache-control",
    "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-site", "sec-ch-ua",
    "access-control-allow-origin", "access-control-allow-methods",
    "x-padding", "hysteria-udp", "hysteria-cc-rx", "x-masq", "allow",
}


def strip_tests(text):
    """只砍掉文件末尾的测试模块（`#[cfg(test)]\nmod tests`），保留中段的 cfg(test) 辅助函数。"""
    last = None
    for m in re.finditer(r"#\[cfg\(test\)\]\s*\n\s*mod [a-z_0-9]+", text):
        last = m
    return text[: last.start()] if last else text


def main():
    rows = []
    for crate in sorted(os.listdir(ROOT)):
        if not crate.startswith(("xray-proxy-", "xray-transport-")):
            continue
        srcdir = os.path.join(ROOT, crate, "src")
        if not os.path.isdir(srcdir):
            continue
        for dp, _, fs in os.walk(srcdir):
            for f in sorted(fs):
                if not f.endswith(".rs"):
                    continue
                p = os.path.join(dp, f)
                rel = os.path.relpath(p, os.path.join(ROOT, crate)).replace("\\", "/")
                txt = strip_tests(open(p, encoding="utf-8", errors="replace").read())
                for i, ln in enumerate(txt.split("\n"), 1):
                    if ln.strip().startswith("//"):
                        continue
                    for m in re.finditer(r'\.get\(\s*"([A-Za-z0-9_.\-]+)"\s*\)', ln):
                        rows.append((crate, m.group(1), f"{rel}:{i}", ln.strip()[:150]))
                    # 键名经 helper 闭包传入（get_str/get_bool/get_i32/str_field 等）
                    for m in re.finditer(
                        r'\b(?:get_str2?|get_bool|get_i32|get_i64|get_u64|str_field|alpn_field)'
                        r'\([^)]*?"([A-Za-z0-9_.\-]+)"',
                        ln,
                    ):
                        rows.append((crate, m.group(1), f"{rel}:{i}", ln.strip()[:150]))
    seen = {}
    for r in rows:
        key, site = r[1], r[2]
        if key.lower() in HEADER_KEYS:
            continue
        seen.setdefault((r[0], key), []).append(site)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("crate\tkey\tsites\n")
        for (crate, key), sites in sorted(seen.items()):
            fh.write(f"{crate}\t{key}\t{';'.join(sites)}\n")
    from collections import Counter
    c = Counter(k[0] for k in seen)
    for crate in sorted(c):
        print(f"{crate}\t{len([1 for k in seen if k[0]==crate])} keys")
    print(f"TOTAL distinct (crate,key) = {len(seen)}; raw get() sites = {len(rows)}")
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
