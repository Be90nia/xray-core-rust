#!/usr/bin/env python3
"""融合度五轴只读基线扫描（bd lbavl）。

只读：仅扫文件系统，不构建、不改任何文件。
口径来源（引原文，不自创）：
  轴1 方向纪律   CLAUDE.md §3.5.3「地基/骨架不引 Xray 类型」+「依赖方向单向：硬装血肉 → 骨架 → 地基」
  轴2 契约族使用 CLAUDE.md §3.5.2 五「常用白拿清单」+ 深度融合战役计划 D5「udf 契约族…有生产调用点」
  轴3 §3.5.4 七面 CLAUDE.md §3.5.4「归一化面（主仓已自造、但属通用件 → 必须提炼回 udf）」表 7 行
  轴4 依赖接地   CLAUDE.md §3.5.1「依赖方向单向」+ lbavl「依赖接地」= 声明 udf-* 生产依赖的 member 占比
  轴5 L3 闸     强约束插件模型 §L3 能力层「clippy.toml disallowed-methods 路径限定」

用法：
  python reports/audit-2026-10-28/fusion_baseline.py                     # 扫工作树
  python reports/audit-2026-10-28/fusion_baseline.py --root <快照目录>    # 扫 git archive 快照
  python reports/audit-2026-10-28/fusion_baseline.py --json              # 机器可读
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------- 扫描原语


def strip_comments(src: str) -> str:
    """剥 /* */ 与 // 注释（用于轴1：注释里的提炼出处留痕不算违规）。"""
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def strip_test_mods(src: str) -> str:
    """剥 #[cfg(test)] mod 块（brace 级），生产面计数用。"""
    out: list[str] = []
    i = 0
    while True:
        m = re.search(r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*mod\s+[\w:{}, ]+\s*\{", src[i:])
        if not m:
            out.append(src[i:])
            return "".join(out)
        out.append(src[i : i + m.start()])
        j = i + m.end()
        depth = 1
        while j < len(src) and depth > 0:
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
            j += 1
        i = j


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def production_sources(root: Path, exclude_udf: bool = True) -> dict[Path, str]:
    """crates/*/src/**/*.rs 生产面（剥 cfg(test)），排除 udf-frame 工作副本。"""
    files = {}
    for p in root.glob("crates/*/src/**/*.rs"):
        posix = p.as_posix()
        if exclude_udf and "udf-frame" in posix:
            continue
        files[p] = strip_test_mods(strip_comments(read(p)))
    return files


# ---------------------------------------------------------------- 轴1 方向纪律

XRAY_REF = re.compile(r"xray", re.I)


def axis_direction(root: Path) -> dict:
    udf = root / "crates" / "udf-frame"
    if not udf.is_dir():
        return {"axis": "方向纪律", "value": None, "status": "N/A（快照无 udf 工作副本）"}
    srcs = [p for p in udf.glob("*/src/**/*.rs")]
    hits = []
    for p in srcs:
        for line_no, line in enumerate(strip_comments(read(p)).splitlines(), 1):
            if XRAY_REF.search(line):
                hits.append(f"{p.relative_to(root).as_posix()}:{line_no}")
    toml_hits = []
    for p in udf.glob("*/Cargo.toml"):
        # 只算真实依赖条目：剥注释后仍出现 xray
        for line_no, line in enumerate(strip_comments(read(p)).splitlines(), 1):
            if XRAY_REF.search(line) and "=" in line:
                toml_hits.append(f"{p.relative_to(root).as_posix()}:{line_no}")
    violations = len(hits) + len(toml_hits)
    return {
        "axis": "方向纪律",
        "value": 100.0 if violations == 0 else None,
        "status": f"违规 {violations}（源码 {len(hits)} / 依赖条目 {len(toml_hits)}）",
        "files": len(srcs),
        "hits": hits[:10],
        "toml_hits": toml_hits[:10],
        "note": "违规>0 时不折算百分比（该轴是零容忍判据，非比例指标）",
    }


# ---------------------------------------------------------------- 轴2 契约族

# 基件矩阵 = reports/audit-2026-10-25/udf-xray-fusion.md §2.2 的 14 行（族名 → 探针正则）
FAMILIES: list[tuple[str, str]] = [
    ("FxScope（spawn 托管）", r"\bFxScope\b"),
    ("ShutdownCoordinator（停机编排）", r"\bShutdownCoordinator\b"),
    ("logx（ChannelRegistry/ChannelSink/mask_secrets）",
     r"\bChannelRegistry\b|\bChannelSink\b|\bmask_secrets\b"),
    ("skeleton::clock（Clock/SystemClock/MockClock）",
     r"\bMockClock\b|\bSystemClock\b|\bclock::Clock\b"),
    ("std_ext::scheduler", r"\bScheduler\b|std_ext::scheduler"),
    ("std_ext::json", r"std_ext::json|\bJsonMode\b"),
    ("池族 ThreadPool/PooledThreadPool/MemoryPool",
     r"\bPooledThreadPool\b|\bThreadPool\b|\bMemoryPool\b"),
    ("PoolBase/PoolManaged", r"\bPoolBase\b|\bPoolManaged\b"),
    ("ConfigPort/EnvSource", r"\bConfigPort\b|\bEnvSource\b|\bMockEnv\b"),
    ("std_ext::{hash,id}", r"\bstable64\b|\bIdGen\b"),
    ("memgov（BoundedRegistry/CountingAllocator/LeakGuard）",
     r"\bBoundedRegistry\b|\bCountingAllocator\b|\bLeakGuard\b"),
    ("std_ext::compose（combine）", r"std_ext::compose|compose::combine"),
    ("testing::{TestStore,ScriptedRuntime}", r"\bTestStore\b|\bScriptedRuntime\b"),
    ("skeleton_infra::config::ConfigFile<C>", r"\bConfigFile\b"),
]


def axis_contract_families(srcs: dict[Path, str]) -> dict:
    rows = []
    for name, pat in FAMILIES:
        rx = re.compile(pat)
        consumers = {}
        for p, s in srcs.items():
            n = len(rx.findall(s))
            if n:
                consumers[p.as_posix()] = n
        rows.append({"family": name, "taken": bool(consumers), "files": len(consumers),
                     "occ": sum(consumers.values()), "sample": list(consumers)[:3]})
    taken = sum(1 for r in rows if r["taken"])
    return {"axis": "契约族使用", "numerator": taken, "denominator": len(rows),
            "value": round(100.0 * taken / len(rows), 1), "rows": rows}


# ---------------------------------------------------------------- 轴3 §3.5.4 七面


def axis_seven_faces(root: Path, srcs: dict[Path, str]) -> dict:
    def srcread(rel: str) -> str:
        p = root / rel
        return strip_comments(read(p)) if p.exists() else ""

    conf_json = srcread("crates/xray-conf/src/json.rs")
    log_mod = srcread("crates/xray-common/src/log/mod.rs")
    serial = srcread("crates/xray-conf/src/serial.rs")
    inbound = srcread("crates/xray-core/src/inbound.rs")
    dispatcher = srcread("crates/xray-app-dispatcher/src/default.rs")
    # 停机主干的实际接线点在 shutdown_bridge.rs（instance.rs 只留注释引用）
    shutdown = srcread("crates/xray-core/src/shutdown_bridge.rs") + srcread("crates/xray-core/src/instance.rs")
    frame_ctx = srcread("crates/xray-frame/src/context.rs")
    has_table = (root / "crates/xray-core/src/arm_registry.rs").exists() or (
        root / "crates/xray-core/src/arm_builders/mod.rs").exists()

    spawn_sites = sum(len(re.findall(r"tokio::spawn\s*\(", s)) for s in srcs.values())
    fxscope_occ = sum(len(re.findall(r"\bFxScope\b", s)) for s in srcs.values())

    faces = []
    faces.append(("#1 JSON 工具壳",
                  "migrated" if "std_ext::json" in conf_json else "none",
                  "xray-conf/src/json.rs 转调 std_ext::json"))

    # 面2 无 udf 对应件：留仓是 PM 裁决（bd d95us），不是遗漏——判 0 但标注裁决出处。
    faces.append(("#2 lint 阶段编排", "none",
                  "xray-conf/src/lint.rs 仍自持（bd d95us 裁决留仓至 P4 + 标准标注）"))

    faces.append(("#3 日志 Handler 分发/双写",
                  "migrated" if "ChannelRegistry" in log_mod else "none",
                  "xray-common/src/log/mod.rs 单入口 = udf logx::ChannelRegistry"))

    # 面4：主仓消费 XrayConfigLayers = 已迁；仅框架内 ConfigPort 段路由 = 部分
    if "XrayConfigLayers" in serial:
        st4, ev4 = "migrated", "xray-conf/src/serial.rs merge_configs → XrayConfigLayers(xray_policy())"
    elif "ConfigPort" in frame_ctx:
        st4, ev4 = "partial", "xray-frame/context.rs 已走 ConfigPort/EnvSource 段路由；xray-conf 分层装载仍自持"
    else:
        st4, ev4 = "none", "xray-conf/src/serial.rs 分层装载自持（无 ConfigPort 消费）"
    faces.append(("#4 配置装配", st4, ev4))

    # 面5：inbound + outbound 两半都在 udf BoundedRegistry = 已迁；单半 = 部分
    reg_halves = sum(1 for t in (inbound, dispatcher) if "BoundedRegistry" in t)
    st5 = {2: "migrated", 1: "partial", 0: "none"}[reg_halves]
    faces.append(("#5 注册表族", st5,
                  f"udf BoundedRegistry 覆盖 {reg_halves}/2 半（inbound slots / dispatcher HandlerRegistry）"))

    faces.append(("#6 中央 match 臂",
                  "migrated" if has_table and "lookup_inbound_builder" in inbound else "none",
                  "构造表（arm_registry.rs / arm_builders/mod.rs）+ inbound/outbound 入口 lookup_*_builder 查表"))

    # 面7：停机主干已迁（ShutdownCoordinator）+ 残余裸 spawn = 部分
    faces.append(("#7 任务托管/停机",
                  "migrated" if "ShutdownCoordinator" in shutdown and spawn_sites == 0
                  else "partial" if "ShutdownCoordinator" in shutdown else "none",
                  f"Instance::close 经 ShutdownCoordinator；FxScope 生产调用 {fxscope_occ} 处，"
                  f"残余裸 tokio::spawn {spawn_sites} 处（per-site ledger 登记，未清零）"))

    score = sum(1.0 if s == "migrated" else 0.5 if s == "partial" else 0.0 for _, s, _ in faces)
    return {"axis": "§3.5.4 七面", "numerator": score, "denominator": len(faces),
            "value": round(100.0 * score / len(faces), 1), "rows": faces,
            "evidence": {"bare_tokio_spawn_prod": spawn_sites, "fxscope_prod_occ": fxscope_occ}}


# ---------------------------------------------------------------- 轴4 依赖接地 / 轴5 L3 闸


def workspace_members(root: Path) -> list[str]:
    txt = read(root / "Cargo.toml")
    m = re.search(r"members = \[(.*?)\]", txt, re.S)
    if not m:
        return []
    blk = "\n".join(line.split("#")[0] for line in m.group(1).splitlines())
    return re.findall(r'"([^"]+)"', blk)


UDF_DEP = re.compile(r"^\s*(udf-skeleton|udf-skeleton-infra|udf-std-ext)\s*=", re.M)
DISALLOWED = re.compile(r"disallowed-methods\s*=|disallowed-macros\s*=")


def axis_grounding_and_gates(root: Path) -> tuple[dict, dict]:
    members = workspace_members(root)
    grounded, gated = [], []
    for m in members:
        man = root / m / "Cargo.toml"
        txt = read(man) if man.exists() else ""
        # 生产依赖面：切到 [dev-dependencies] / [build-dependencies] 之前
        prod = re.split(r"\n\[(?:dev-|build-)dependencies\]", txt)[0]
        if UDF_DEP.search(prod):
            grounded.append(m)
        gate = root / m / "clippy.toml"
        if gate.exists() and DISALLOWED.search(read(gate)):
            gated.append(m)
    n = len(members)
    # 次口径：剔 tests/benches（非生产 member），供"生产面接地率"对照
    prod = [m for m in members if m not in ("tests", "benches")]
    a4 = {"axis": "依赖接地", "numerator": len(grounded), "denominator": n,
          "value_prod": round(100.0 * len([m for m in grounded if m in prod]) / len(prod), 1),
          "value": round(100.0 * len(grounded) / n, 1) if n else None,
          "members_ungrounded": [m for m in members if m not in grounded]}
    a5 = {"axis": "L3 静态闸", "numerator": len(gated), "denominator": n,
          "value_prod": round(100.0 * len([m for m in gated if m in prod]) / len(prod), 1),
          "value": round(100.0 * len(gated) / n, 1) if n else None,
          "members_ungated": [m for m in members if m not in gated],
          "crosstab": {
              "both": len([m for m in grounded if m in gated]),
              "udf_only": len([m for m in grounded if m not in gated]),
              "gate_only": len([m for m in gated if m not in grounded]),
              "neither": len([m for m in members if m not in grounded and m not in gated]),
          }}
    return a4, a5


# ---------------------------------------------------------------- 主流程

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None, help="扫描根（默认 = 本脚本上溯 3 级）")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[2]
    srcs = production_sources(root)

    a1 = axis_direction(root)
    a2 = axis_contract_families(srcs)
    a3 = axis_seven_faces(root, srcs)
    a4, a5 = axis_grounding_and_gates(root)

    axes = [a1, a2, a3, a4, a5]
    scored = [a["value"] for a in axes if a["value"] is not None]
    total = round(sum(scored) / len(scored), 1) if scored else None

    result = {"root": str(root), "axes": axes, "score_equal_weight": total,
              "src_files_scanned": len(srcs)}

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    print(f"root = {root}")
    print(f"生产面扫描文件 = {len(srcs)}\n")
    print(f"{'#':<3}{'轴':<16}{'值':>8}  口径")
    print("-" * 100)
    for i, a in enumerate(axes, 1):
        if "numerator" in a:
            den = f"{a['numerator']}/{a['denominator']}"
        else:
            den = a["status"]
        val = f"{a['value']:.1f}%" if a["value"] is not None else "n/a"
        if a.get("value_prod") is not None:
            val += f" (生产面 {a['value_prod']:.1f}%)"
        print(f"{i:<3}{a['axis']:<16}{val:>8}  {den}")
    print("-" * 100)
    print(f"{'总分（五轴等权）':<19}{total if total is not None else 'n/a'}")

    print("\n[轴2 契约族明细]")
    for r in a2["rows"]:
        flag = "taken " if r["taken"] else "未取  "
        print(f"  {flag}{r['family']:<48} files={r['files']:<3} occ={r['occ']}")
    print("\n[轴3 七面明细]")
    for name, st, ev in a3["rows"]:
        print(f"  {st:<9}{name:<22} {ev}")
    print("\n[轴5 交叉表]", a5["crosstab"])
    print("[轴5 无闸 member]", a5["members_ungated"])
    print("[轴4 无 udf 依赖 member]", len(a4["members_ungrounded"]))
    if a1.get("hits") or a1.get("toml_hits"):
        print("[轴1 违规]", a1["hits"], a1["toml_hits"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
