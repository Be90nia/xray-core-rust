#!/usr/bin/env python3
"""MASQUE CONNECT-IP capsule residue 取证（规划 §6 门 B5，bd anygg G7）。

对给定 pcap 逐帧解析 h2 CONNECT-IP 流（`:method=CONNECT` 且 `:protocol=connect-ip`
的流）上的 DATA 帧，按 (TCP 连接, 源端口, h2 流 id) 聚合成**单向**字节流，再按
RFC 9297 胶囊协议逐条校验：每条 capsule = varint(type) + varint(length) + payload
（varint = RFC 9000/HTTP-3 变长整数）。任何一条流出现截断（类型/长度头不完整或
payload 越界）即计入 `residue_frames`——期望 **0**（门 B5.2「残留非零帧 = 0」）。

用法（门 B5 形态）::

    python tools/masque_capsule_residue.py --pcap D:/tmp/masque.pcapng
    # 期望 residue_frames=0

退出码：0 = 无残留（或 pcap 无 CONNECT-IP 流）；1 = 有残留；2 = 工具/环境错误。
tshark 路径：`--tshark` 参数 > 环境变量 `TSHARK` > `D:/Project/tools/Wireshark/tshark.exe`。

口径说明：h2 上 HTTP Datagram 的另一承载（DATAGRAM 帧）不是 capsule 流的残留，
不在本工具解析范围；本工具只校验 RFC 9297 capsule protocol 形态（Go/Rust h2
实现的承载形态）。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

DEFAULT_TSHARK = "D:/Project/tools/Wireshark/tshark.exe"


def read_varint(buf: bytes, pos: int) -> tuple[int | None, int]:
    """RFC 9000 varint：首字节高 2 位选长度（1/2/4/8 字节）。"""
    if pos >= len(buf):
        return None, pos
    first = buf[pos]
    length = 1 << (first >> 6)
    value = first & 0x3F
    if pos + length > len(buf):
        return None, pos + 1
    for i in range(1, length):
        value = (value << 8) | buf[pos + i]
    return value, pos + length


def parse_capsules(buf: bytes) -> tuple[int, str | None]:
    """逐条校验胶囊序列；返回 (完整 capsule 数, 失败描述或 None)。"""
    pos = 0
    count = 0
    while pos < len(buf):
        ctype, p = read_varint(buf, pos)
        if ctype is None:
            return count, f"truncated capsule type at offset {pos}"
        clen, p2 = read_varint(buf, p)
        if clen is None:
            return count, f"truncated capsule length at offset {p}"
        if p2 + clen > len(buf):
            return (
                count,
                f"truncated capsule payload at offset {p2} (need {clen}, have {len(buf) - p2})",
            )
        pos = p2 + clen
        count += 1
    return count, None


def run_tshark(tshark: str, pcap: str, port: int, fields: list[str], display: str) -> list[str]:
    cmd = [
        tshark,
        "-r",
        pcap,
        "-d",
        f"tcp.port=={port},http2",
        "-Y",
        display,
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "occurrence=f",
    ]
    for f in fields:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"tshark exit {proc.returncode}: {err}")
    return proc.stdout.decode("utf-8", "replace").splitlines()


def unhex(field: str) -> bytes:
    return bytes.fromhex(field.replace(":", ""))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pcap", required=True, help="pcap/pcapng 文件路径")
    ap.add_argument("--port", type=int, default=443, help="h2 承载的 TCP 端口（默认 443）")
    ap.add_argument("--tshark", default=os.environ.get("TSHARK", DEFAULT_TSHARK), help="tshark 可执行路径")
    args = ap.parse_args()

    if not os.path.isfile(args.pcap):
        print(f"error: pcap not found: {args.pcap}", file=sys.stderr)
        return 2
    if not os.path.isfile(args.tshark):
        print(f"error: tshark not found: {args.tshark}（--tshark 或 TSHARK 覆盖）", file=sys.stderr)
        return 2

    # 第一遍：CONNECT-IP 流 id（extended CONNECT + connect-ip 协议头）。
    try:
        conn_lines = run_tshark(
            args.tshark,
            args.pcap,
            args.port,
            ["http2.streamid"],
            'http2.headers.method == "CONNECT" && http2.headers.protocol == "connect-ip"',
        )
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    capsule_streams = {line.strip() for line in conn_lines if line.strip()}
    if not capsule_streams:
        print("no CONNECT-IP streams found in pcap（确认抓包覆盖了 CONNECT 握手）")
        print(json.dumps({"pcap": args.pcap, "capsule_streams": 0, "residue_frames": 0}))
        return 0

    # 第二遍：DATA 帧按 (streamid, srcport) 聚合（方向分离——胶囊序列每向独立）。
    try:
        data_lines = run_tshark(
            args.tshark,
            args.pcap,
            args.port,
            ["http2.streamid", "tcp.srcport", "http2.data.data"],
            "http2.data.data",
        )
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    flows: dict[tuple[str, str], bytearray] = {}
    for line in data_lines:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        stream_id, srcport, hexdata = parts[0].strip(), parts[1].strip(), parts[2].strip()
        if stream_id not in capsule_streams:
            continue
        try:
            flows.setdefault((stream_id, srcport), bytearray()).extend(unhex(hexdata))
        except ValueError:
            print(f"error: unparseable hex payload on stream {stream_id}", file=sys.stderr)
            return 2

    residues: list[dict] = []
    capsules_total = 0
    for (stream_id, srcport), buf in flows.items():
        count, failure = parse_capsules(bytes(buf))
        capsules_total += count
        if failure is not None:
            residues.append(
                {"stream": stream_id, "srcport": srcport, "bytes": len(buf), "residue": failure}
            )

    residue_frames = len(residues)
    print(f"capsule_streams={len(flows)} capsules={capsules_total} residue_frames={residue_frames}")
    report = {
        "pcap": args.pcap,
        "http2_port": args.port,
        "connect_ip_streams": sorted(capsule_streams),
        "capsules": capsules_total,
        "residue_frames": residue_frames,
        "residues": residues,
    }
    print(json.dumps(report, ensure_ascii=False))
    return 1 if residue_frames else 0


if __name__ == "__main__":
    sys.exit(main())
