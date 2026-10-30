#!/usr/bin/env python3
"""Rust(CI 产物) vs Go(v2rayN 内核) 同配置交替测速。

判据来自项目铁律：Rust 测速必须带 Go 对照组、同窗交替多轮，单次数字不算数。

用法：
    python tools/speed_ab_rust_vs_go.py --rust <ci-xray.exe> --go <go-xray.exe> \
        --uri-file C:/Users/Begonia/Desktop/test.txt --rounds 3

输出：每节点每轮 MB/s + 两侧中位数 + Rust/Go 比值；最后汇总。
"""
import argparse
import json
import os
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dist"))
from uriclient import cfg  # noqa: E402  与 run_full32/32 通测同一条配置生成路径

SPEED_URL = "https://speed.cloudflare.com/__down?bytes=2097152"  # 2MB：
# 实测该路径约 1-2 MB/s，10MB 包在 15s 内跑不完会被判 0（假象）
PORT_RUST, PORT_GO = 17901, 17902


def one_round(bin_path, uri, port, work, tag, rid):
    """起内核 -> curl 10MB 测速 -> 收尸。返回 MB/s（失败 -1）。"""
    ob = cfg(uri, port)
    conf = {
        "log": {"loglevel": "warn"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [ob, {"tag": "direct", "protocol": "freedom", "settings": {}}],
        "routing": {"rules": [{"type": "field", "port": "1-65535",
                               "outboundTag": ob.get("tag", "proxy") or "proxy"}]},
    }
    cp = os.path.join(work, f"sp-{tag}-{rid}.json")
    lp = os.path.join(work, f"sp-{tag}-{rid}.log")
    with open(cp, "w", encoding="utf-8") as f:
        json.dump(conf, f, ensure_ascii=False)
    log = open(lp, "wb")
    p = subprocess.Popen([bin_path, "run", "-c", cp], stdout=log, stderr=subprocess.STDOUT)
    try:
        time.sleep(2.5)
        r = subprocess.run(
            ["curl", "-s", "--max-time", "15", "--socks5-hostname", f"127.0.0.1:{port}",
             "-o", os.devnull, "-w", "%{speed_download}", SPEED_URL],
            capture_output=True, text=True, timeout=25)
        try:
            return float(r.stdout.strip()) / 1048576
        except ValueError:
            return -1.0
    except subprocess.TimeoutExpired:
        return -1.0
    finally:
        p.terminate()          # 只杀自己拉起的（红线：禁 taskkill 全局 xray）
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
        log.close()


def median(xs):
    ok = [x for x in xs if x > 0]
    return statistics.median(ok) if ok else -1.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rust", required=True, help="Rust 内核（CI 产物）")
    ap.add_argument("--go", required=True, help="Go 内核（v2rayN 里那份，先拷出来用）")
    ap.add_argument("--uri-file", default="C:/Users/Begonia/Desktop/test.txt")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--pick", default="", help="指定节点序号，逗号分隔；默认自动抽样 8 个")
    ap.add_argument("--work", default=os.path.join(os.environ.get("TEMP", "."), "speed-ab"))
    args = ap.parse_args()

    os.makedirs(args.work, exist_ok=True)
    uris = [u.strip() for u in open(args.uri_file, encoding="utf-8")
            if u.strip() and not u.startswith(("#", "{"))]
    if args.pick:
        idxs = [int(x) for x in args.pick.split(",") if x.strip()]
    else:  # 覆盖不同协议/传输：每 4 条取 1，上限 8
        idxs = list(range(1, len(uris) + 1, 4))[:8]

    print(f"# 节点 {len(uris)} 条，抽测 {idxs}；每节点 {args.rounds} 轮 × 2 侧交替")
    print(f"# rust={args.rust}\n# go  ={args.go}")
    print("| # | proto | sec/net | Rust MB/s | Go MB/s | Rust/Go |")
    print("|---|---|---|---|---|---|")
    rows, rust_all, go_all = [], [], []
    for i in idxs:
        uri = uris[i - 1]
        r_speeds, g_speeds = [], []
        for rnd in range(1, args.rounds + 1):
            # 交替顺序并按轮翻转，抵消「先跑方占便宜」
            order = [(args.rust, PORT_RUST, "rust", r_speeds), (args.go, PORT_GO, "go", g_speeds)]
            if rnd % 2 == 0:
                order.reverse()
            for binp, port, tag, sink in order:
                mbps = one_round(binp, uri, port, args.work, tag, f"{i}-{rnd}")
                sink.append(mbps)
                print(f"[round{i}.{rnd}] {tag:4s} {mbps:7.2f} MB/s", file=sys.stderr)
        mr, mg = median(r_speeds), median(g_speeds)
        rust_all.append(mr)
        go_all.append(mg)
        proto = cfg(uri, PORT_RUST).get("protocol", "?")
        ss = cfg(uri, PORT_RUST).get("streamSettings", {})
        ratio = f"{mr / mg:.2f}x" if (mr > 0 and mg > 0) else "n/a"
        line = f"| {i} | {proto} | {ss.get('security', 'none')}/{ss.get('network', 'tcp')} | {mr:.2f} | {mg:.2f} | {ratio} |"
        rows.append(line)
        print(line, flush=True)

    MR, MG = median(rust_all), median(go_all)
    print(f"\n**汇总（节点中位数再取中位）**：Rust {MR:.2f} MB/s · Go {MG:.2f} MB/s · "
          f"比值 {(MR / MG):.2f}x" if (MR > 0 and MG > 0) else f"\n汇总：Rust {MR:.2f} / Go {MG:.2f}（有侧全失败）")
    verdict = "PASS(>=Go 的 70%)" if (MR > 0 and MG > 0 and MR / MG >= 0.7) else "FAIL(<Go 的 70%)"
    print(f"判决：{verdict}")
    return 0 if verdict.startswith("PASS") else 1


if __name__ == "__main__":
    sys.exit(main())
