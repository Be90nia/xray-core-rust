"""Static sweep: non-test panic candidates in protocol/parsing crates.

Cuts each .rs file at its first `#[cfg(test)]` block (tests conventionally live at the
end) and reports suspicious constructs on the surviving (production) lines.
"""
import os
import re
import sys

ROOT = "crates"
DIRS = [
    "xray-proxy-vless", "xray-proxy-vmess", "xray-proxy-trojan", "xray-proxy-ss",
    "xray-proxy-tuic", "xray-proxy-hysteria", "xray-proxy-anytls", "xray-proxy-socks",
    "xray-proxy-http", "xray-proxy-wireguard", "xray-proxy-tun", "xray-mux",
    "xray-xudp", "xray-transport", "xray-transport-kcp", "xray-transport-quic",
    "xray-transport-grpc", "xray-transport-websocket", "xray-transport-httpupgrade",
    "xray-transport-splithttp", "xray-tls", "xray-reality", "xray-app-dispatcher",
    "xray-core", "xray-app-dns", "xray-geodata", "xray-app-geodata",
]

PATTERNS = [
    (re.compile(r"\.unwrap\(\)"), "unwrap"),
    (re.compile(r"\.expect\("), "expect"),
    (re.compile(r"\bpanic!\("), "panic"),
    (re.compile(r"\bunreachable!\("), "unreachable"),
    (re.compile(r"\btodo!\("), "todo"),
    (re.compile(r"\[\s*\d+\s*\],"), "index,comma"),   # rough
]


def prod_lines(path):
    try:
        src = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return []
    cut = len(src)
    for i, l in enumerate(src):
        if "#[cfg(test)]" in l:
            cut = i
            break
    return [(i + 1, l) for i, l in enumerate(src[:cut])]


def main():
    out = []
    for d in DIRS:
        base = os.path.join(ROOT, d)
        if not os.path.isdir(base):
            continue
        for dirpath, _dirnames, files in os.walk(base):
            for f in files:
                if not f.endswith(".rs"):
                    continue
                p = os.path.join(dirpath, f)
                for ln, line in prod_lines(p):
                    s = line.strip()
                    if s.startswith("//") or s.startswith("///"):
                        continue
                    for rx, name in PATTERNS:
                        if rx.search(line):
                            out.append((name, f"{p}:{ln}", s[:150]))
                            break
    for name, loc, s in out:
        print(f"{name:14s} {loc}\n    {s}")
    print(f"\n# total {len(out)}")


if __name__ == "__main__":
    main()
