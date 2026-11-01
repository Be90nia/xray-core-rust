#!/usr/bin/env python3
"""Drift probe: keys the runtime actually reads vs keys xray-conf declares.

For each protocol family, collect the keys the runtime looks up (`get("k")` /
`contains_key("k")` / serde `rename = "k"` in that crate) and subtract the keys the
matching xray-conf settings struct declares. Any leftover = a config key the runtime
honours that the xray-conf schema does not know about (schema is a lie; harmless for
behaviour because settings pass through as raw JSON, but it means the conf schema is not
a usable validator) — and the reverse direction is the NOT-WIRED list.
"""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

FAMILIES = {
    "FreedomOutboundSettings": ["crates/xray-proxy-freedom/src"],
    "VLessInboundSettings": ["crates/xray-proxy-vless/src"],
    "VLessOutboundSettings": ["crates/xray-proxy-vless/src"],
    "VMessInboundSettings": ["crates/xray-proxy-vmess/src"],
    "VMessOutboundSettings": ["crates/xray-proxy-vmess/src"],
    "TrojanInboundSettings": ["crates/xray-proxy-trojan/src"],
    "TrojanOutboundSettings": ["crates/xray-proxy-trojan/src"],
    "ShadowsocksInboundSettings": ["crates/xray-proxy-ss/src"],
    "ShadowsocksOutboundSettings": ["crates/xray-proxy-ss/src"],
    "SocksInboundSettings": ["crates/xray-proxy-socks/src"],
    "SocksOutboundSettings": ["crates/xray-proxy-socks/src"],
    "HttpInboundSettings": ["crates/xray-proxy-http/src"],
    "HttpOutboundSettings": ["crates/xray-proxy-http/src"],
    "DokodemoDoorInboundSettings": ["crates/xray-proxy-dokodemo/src"],
    "LoopbackOutboundSettings": ["crates/xray-proxy-loopback/src"],
    "DnsOutboundSettings": ["crates/xray-proxy-dns/src"],
    "HysteriaInboundSettings": ["crates/xray-proxy-hysteria/src"],
    "HysteriaOutboundSettings": ["crates/xray-proxy-hysteria/src"],
}

GET_RE = re.compile(r'get\(\s*"([A-Za-z0-9_]+)"')
CONTAINS_RE = re.compile(r'contains_key\(\s*"([A-Za-z0-9_]+)"')
RENAME_RE = re.compile(r'rename\s*=\s*"([A-Za-z0-9_]+)"')


def main():
    with open(os.path.join(HERE, "fields.json"), encoding="utf-8") as fh:
        conf = json.load(fh)["conf"]
    declared = {}
    for st in conf:
        keys = set()
        mode = st["rename_all"]
        for f in st["fields"]:
            k = f["rename"] or f["rust"]
            if not f["rename"] and mode == "camelCase":
                parts = k.split("_")
                k = parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])
            keys.add(k)
        declared[st["struct"]] = keys

    for struct, dirs in FAMILIES.items():
        read = set()
        for d in dirs:
            for dirpath, _dirnames, filenames in os.walk(os.path.join(ROOT, d)):
                for fn in filenames:
                    if not fn.endswith(".rs"):
                        continue
                    with open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                    # strip #[cfg(test)] tail to keep runtime-only evidence
                    cut = text.find("#[cfg(test)]")
                    if cut > 0:
                        text = text[:cut]
                    read |= set(GET_RE.findall(text))
                    read |= set(CONTAINS_RE.findall(text))
                    read |= set(RENAME_RE.findall(text))
        dec = declared.get(struct, set())
        extra = sorted(k for k in read - dec if len(k) > 1)
        print(f"\n== {struct}: conf declares {len(dec)} keys, runtime reads {len(read)}")
        if extra:
            print(f"   runtime-only keys ({len(extra)}): {', '.join(extra)}")


if __name__ == "__main__":
    main()
