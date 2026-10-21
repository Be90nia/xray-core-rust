#!/usr/bin/env python3
"""CI 资产门（G-18 / check-assets）：配置引用的 geo 资产必须存在。

与 Go `.github/workflows/test.yml:10-34` check-assets 的差异（刻意不同）：
- Go 从 actions/cache 恢复 `resources/`（geoip.dat/geosite.dat 由
  scheduled-assets-update 定时下载），缺失**只 sleep 90s** 等缓存传播，从不 fail；
- Rust 仓不内置 geodata（运行时按需下载，见 crates/xray-app-geodata），
  没有缓存可等 → 改为**硬门**：仓内受控配置一旦引用 geo 资产，而该文件不在
  资产目录，立即 fail（发版前挡住"配置要 geosite、包里没 dat"的必然运行期故障）。

资产目录解析与 `xray_common::platform::get_asset_dir()` 对齐：
`$XRAY_LOCATION_ASSET` 优先，否则仓内 `resources/`。

用法：
  python tools/check_geo_assets.py                 # 扫 git 受控 *.json
  python tools/check_geo_assets.py cfg/a.json ...  # 只扫指定配置
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# geoip:XX → geoip.dat；geosite:XX → geosite.dat（对齐 xray-geodata rule_parser 常量）
DEFAULT_FILES = {"geoip": "geoip.dat", "geosite": "geosite.dat"}
DEFAULT_REF = re.compile(r"^(geoip|geosite):[^:]+$")
# ext:file:code / ext-ip:file:code / ext-domain:file:code / ext-site:file:code
EXT_REF = re.compile(r"^ext(?:-ip|-domain|-site)?:([^:]+):[^:]+$")
# 只把看着像 xray 配置的 JSON 纳入（排除 *.cargo_vcs_info.json、checksums 之类）
CONFIG_KEYS = {"inbounds", "outbounds", "routing", "dns"}


def tracked_configs() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "*.json"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout
    paths = [REPO / line for line in out.splitlines() if line]
    return [p for p in paths if p.is_file()]


def referenced_assets(node, found: set[str]) -> None:
    """递归收集 JSON 里所有 geo 资产引用（字符串值）。"""
    if isinstance(node, dict):
        for value in node.values():
            referenced_assets(value, found)
    elif isinstance(node, list):
        for value in node:
            referenced_assets(value, found)
    elif isinstance(node, str):
        m = DEFAULT_REF.match(node)
        if m:
            found.add(DEFAULT_FILES[m.group(1)])
        m = EXT_REF.match(node)
        if m:
            found.add(m.group(1))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("configs", nargs="*", help="待检查配置（缺省 = git ls-files '*.json'）")
    ap.add_argument("--asset-dir", help="资产目录（缺省 $XRAY_LOCATION_ASSET 或 resources/）")
    args = ap.parse_args()

    asset_dir = Path(
        args.asset_dir or os.environ.get("XRAY_LOCATION_ASSET") or (REPO / "resources")
    )
    print(f"asset dir: {asset_dir} (exists={asset_dir.is_dir()})")

    if args.configs:
        configs = [Path(c) for c in args.configs]
    else:
        configs = tracked_configs()
    print(f"configs scanned: {len(configs)}")

    missing: list[str] = []
    checked = 0
    for cfg in configs:
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
            # 非配置 JSON（manifest/校验和）解析失败或形状不符 → 跳过，不算门失败
            print(f"skip {cfg}: not a readable config ({type(e).__name__})")
            continue
        if not isinstance(data, dict) or not CONFIG_KEYS & data.keys():
            continue
        refs: set[str] = set()
        referenced_assets(data, refs)
        if not refs:
            continue
        checked += 1
        for name in sorted(refs):
            if (asset_dir / name).is_file():
                print(f"OK   {cfg}: {name}")
            else:
                missing.append(f"{cfg} 引用 {name}，但 {asset_dir / name} 不存在")

    if missing:
        print("\nFAIL：配置引用了不存在的 geo 资产（二进制启动会退化，路由规则静默失效）")
        for line in missing:
            print(f"  - {line}")
        return 1

    if checked == 0:
        print(
            "PASS：受控配置无一引用 geo 资产（仓内不内置 geodata，运行期下载）"
            "——与 Go 的差异：无 cache 可恢复，故无 sleep，只有硬门"
        )
    else:
        print(f"PASS：{checked} 个引用 geo 资产的配置，资产齐全")
    return 0


if __name__ == "__main__":
    sys.exit(main())
