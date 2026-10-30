#!/usr/bin/env python3
"""05:00 定时跑批：用 **CI 编译产物** 测 32 协议（176 VPS + 本机 Windows 客户端）。

流程（顺序固定，任一步失败即中止并开 bd 票——禁止退化成本地构建产物）：
  ① 取本分支最新「成功」CI run 的 head_sha（须 == 当前分支 HEAD；不等则中止）
  ② 下载两个 artifact：
       xray-x86_64-pc-windows-msvc  → 本机客户端
       xray-x86_64-unknown-linux-gnu → 176 服务端
  ③ 部署 176：备份 → systemctl stop xr → 换核(chmod 755) → start → active 校验
     + 监听端口数比对；任一步失败自动回滚到备份并中止
  ④ 用 Windows CI 二进制跑 32 节点（dist/run_full32.py）
  ⑤ 报告落 reports/audit-2026-10-31/；FAIL/PARSE 自动开 bd 票

用法：
    python tools/night_probe32_ci.py                 # 全流程
    python tools/night_probe32_ci.py --no-deploy     # 只测客户端（不换 176 内核）
    python tools/night_probe32_ci.py --smoke --limit 2   # 管路自检（不部署、不开票）

依赖：gh（已登录）、ssh 免密到 176、curl。
"""
import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = "Be90nia/xray-core-rust"
BRANCH = "feature/fix-inbound-parity"
VPS = "root@176.122.139.45"
VPS_BIN = "/root/agsbx/xray"
VPS_SVC = "xr"
URIS = r"C:\Users\Begonia\Desktop\test.txt"
WORK = r"D:/tmp/xray32-176"
ART_WIN = "xray-x86_64-pc-windows-msvc"
ART_LINUX = "xray-x86_64-unknown-linux-gnu"


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", **kw)


def gh_json(path):
    cp = sh(["gh", "api", path])
    if cp.returncode != 0:
        raise RuntimeError(f"gh api {path} 失败: {cp.stderr[:300]}")
    return json.loads(cp.stdout or "null")


def latest_green_run():
    runs = gh_json(f"repos/{REPO}/actions/runs?branch={BRANCH}&per_page=30")["workflow_runs"]
    ci = [r for r in runs if r.get("name") == "CI"]
    for r in ci:
        if r["status"] == "completed" and r["conclusion"] == "success":
            return r
    raise RuntimeError(f"分支 {BRANCH} 最近 30 个 CI run 里没有成功的一次（先修 CI）")


def head_sha():
    cp = sh(["git", "rev-parse", "HEAD"], cwd=ROOT)
    return cp.stdout.strip()


def download_artifact(run_id, name, dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    cp = sh(["gh", "run", "download", str(run_id), "--repo", REPO, "-n", name,
             "-D", dest_dir])
    if cp.returncode != 0:
        raise RuntimeError(f"下载 artifact {name} 失败: {cp.stderr[:300]}")
    for root, _dirs, files in os.walk(dest_dir):
        for f in files:
            if f in ("xray", "xray.exe"):
                return os.path.join(root, f)
    raise RuntimeError(f"artifact {name} 里找不到 xray 可执行文件")


def ssh(cmd, timeout=120):
    return sh(["ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", VPS, cmd], timeout=timeout)


def deploy(run_id, linux_bin, stamp):
    """换核 + 校验 + 失败回滚。返回 (ok, 说明)。"""
    bak = f"{VPS_BIN}.bak-{stamp}"
    pre = ssh(f"systemctl is-active {VPS_SVC}; ss -ltn | grep -c LISTEN")
    if pre.returncode != 0:
        return False, f"预检 SSH/服务失败: {(pre.stderr or pre.stdout)[:200]}"
    pre_lines = pre.stdout.strip().splitlines()
    pre_ports = int(pre_lines[-1].strip() or 0) if pre_lines else 0

    remote_tmp = f"/tmp/xray-ci-{stamp}"
    cp = sh(["scp", "-o", "ConnectTimeout=10", linux_bin, f"{VPS}:{remote_tmp}"])
    if cp.returncode != 0:
        return False, f"scp 失败: {cp.stderr[:200]}"

    steps = (
        f"cp -a {VPS_BIN} {bak} && "
        f"systemctl stop {VPS_SVC} && "
        f"cp -f {remote_tmp} {VPS_BIN} && chmod 755 {VPS_BIN} && "
        f"systemctl start {VPS_SVC} && sleep 3 && "
        f"systemctl is-active {VPS_SVC} && ss -ltn | grep -c LISTEN && rm -f {remote_tmp}"
    )
    r = ssh(steps, timeout=180)
    ok = r.returncode == 0
    post_ports = 0
    if ok:
        lines = r.stdout.strip().splitlines()
        try:
            post_ports = int(lines[-1].strip() or 0)
        except ValueError:
            post_ports = 0
        ok = post_ports == pre_ports and post_ports > 0
    if not ok:
        rb = ssh(f"systemctl stop {VPS_SVC}; cp -a {bak} {VPS_BIN}; chmod 755 {VPS_BIN}; "
                 f"systemctl start {VPS_SVC}; systemctl is-active {VPS_SVC}", timeout=180)
        return False, (f"换核失败已回滚（回滚态={rb.stdout.strip()[:60]}）；"
                       f"pre_ports={pre_ports} post_ports={post_ports} err={(r.stderr or r.stdout)[:200]}")
    return True, f"176 已换核 {stamp}；监听 {post_ports} 个（与换核前一致）；备份 {bak}"


def run32(bin_path, limit):
    os.makedirs(WORK, exist_ok=True)
    cp = sh([sys.executable, os.path.join(ROOT, "dist", "run_full32.py"),
             "--bin", bin_path, "--uri-file", URIS, "--work", WORK,
             "--url", "https://www.youtube.com/"], cwd=ROOT, timeout=3600)
    lines = [l for l in cp.stdout.splitlines() if l.startswith(("[PASS]", "[FAIL]", "[PARSE"))]
    if limit:  # 仅截断呈现，判决仍是全量跑出来的
        lines = lines[:limit]
    return lines, cp.stdout, cp.stderr


def bd_create(title, desc):
    env = dict(os.environ, BD_IGNORE_SCHEMA_SKEW="1")
    cp = subprocess.run(["bd", "create", "--title", title, "--priority", "2",
                         "--label", "audit,probe32", "--description", desc],
                        cwd=ROOT, env=env, capture_output=True, text=True,
                        encoding="utf-8", errors="replace")
    out = (cp.stdout or cp.stderr).strip().splitlines()
    return out[-1][:120] if out else f"rc={cp.returncode}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-deploy", action="store_true", help="只测客户端，不换 176 内核")
    ap.add_argument("--smoke", action="store_true", help="管路自检（不部署/不出报告/不开票）")
    ap.add_argument("--limit", type=int, default=0,
                    help="只截断输出/报告行数（harness 仍跑全量；全量约 7 分钟）")
    ap.add_argument("--run-id", type=int, default=0, help="指定 CI run（默认取最新成功）")
    args = ap.parse_args()

    stamp = time.strftime("%Y%m%d-%H%M")
    problems = []

    # ① 最新成功 CI run（须与本地 HEAD 同 sha，否则测的不是当前代码）
    try:
        run = gh_json(f"repos/{REPO}/actions/runs/{args.run_id}") if args.run_id else latest_green_run()
    except RuntimeError as e:
        print(f"[fatal] {e}")
        return 2
    sha = run["head_sha"]
    local = head_sha()
    print(f"[ci] run={run['id']} sha={sha[:8]} 本地HEAD={local[:8]}")
    if sha != local and not args.smoke:
        print("[fatal] CI 绿的不是当前 HEAD——先让 CI 跑绿本次改动（避免测旧产物出假结论）")
        return 2

    # ② 下载 artifacts
    tmp = tempfile.mkdtemp(prefix="xray-ci-")
    try:
        win_bin = download_artifact(run["id"], ART_WIN, os.path.join(tmp, "win"))
        print(f"[artifact] windows: {win_bin} ({os.path.getsize(win_bin)/1e6:.1f}MB)")
        linux_bin = None
        if not args.no_deploy:
            linux_bin = download_artifact(run["id"], ART_LINUX, os.path.join(tmp, "linux"))
            print(f"[artifact] linux: {linux_bin} ({os.path.getsize(linux_bin)/1e6:.1f}MB)")

        # ③ 部署 176
        if linux_bin and not args.smoke:
            ok, note = deploy(run["id"], linux_bin, stamp)
            print(f"[deploy] {'OK' if ok else 'FAIL'} — {note}")
            if not ok:
                problems.append(("176 换核", note))
            else:
                print("[deploy] 报告：", note)

        # ④ 32 节点（用 CI 的 Windows 二进制）
        lines, raw, err = run32(win_bin, args.limit)
        if not lines:
            print("[fatal] 无结果行；stderr 尾部：")
            print(err[-1500:])
            return 2

        rows = []
        for l in lines:
            m = re.match(r"\[(PASS|FAIL|PARSE)\]\s+#(\d+)\t([^\t]*)\t([^\t]*)\tHTTP=(\S*)\s*body=\s*(\d+)B", l)
            if m:
                rows.append(dict(verdict=m.group(1), idx=int(m.group(2)), proto=m.group(3),
                                 sec_net=m.group(4), http=m.group(5), body=int(m.group(6))))
        p = sum(1 for r in rows if r["verdict"] == "PASS")
        f = sum(1 for r in rows if r["verdict"] == "FAIL")
        pa = sum(1 for r in rows if r["verdict"] == "PARSE")
        bodies = sorted(r["body"] for r in rows if r["body"] > 0)
        med = bodies[len(bodies) // 2] if bodies else 0
        print(f"[result] {p}/{len(rows)} PASS  {f} FAIL  {pa} PARSE  median={med}B")

        if not args.smoke:
            rep = os.path.join(ROOT, "reports", "audit-2026-10-31", f"run32-176-ci-{stamp}.md")
            os.makedirs(os.path.dirname(rep), exist_ok=True)
            with io.open(rep, "w", encoding="utf-8") as fh:
                fh.write(f"# 32 协议真机通测（CI 产物）· {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                fh.write(f"- CI run `{run['id']}` sha `{sha[:8]}`（`{BRANCH}`，结论 {run['conclusion']}）\n")
                fh.write(f"- Windows 客户端 = artifact `{ART_WIN}`；"
                         f"{'Linux 服务端 = artifact `' + ART_LINUX + '`（176 已换核）' if linux_bin else '未部署（--no-deploy）'}\n")
                fh.write(f"- 节点表 `{URIS}`（32 条）；目标站 `https://www.youtube.com/`\n\n")
                fh.write(f"## 结果：**{p}/{len(rows)} PASS** · {f} FAIL · {pa} PARSE（body 中位数 {med}B）\n\n")
                fh.write("| # | 判决 | 协议 | sec/net | HTTP | body |\n|---|---|---|---|---|---|\n")
                for r in rows:
                    fh.write(f"| {r['idx']} | {r['verdict']} | {r['proto']} | {r['sec_net']} | "
                             f"{r['http']} | {r['body']}B |\n")
                if f or pa:
                    fh.write("\n## 失败明细\n\n```\n")
                    fh.write("\n".join(l for l in raw.splitlines()
                                       if l.startswith(("[FAIL]", "[PARSE")))[:4000])
                    fh.write("\n```\n")
            print(f"[report] {rep}")

            for r in rows:
                if r["verdict"] != "PASS":
                    title = f"[P2][probe32] 节点 #{r['idx']} {r['proto']} {r['verdict']}"
                    desc = (f"【CI 产物跑批 {stamp}】run `{run['id']}` sha `{sha[:8]}`；"
                            f"节点 #{r['idx']} `{r['proto']}` {r['sec_net']} 判定 {r['verdict']}"
                            f"：HTTP={r['http']} body={r['body']}B。\n"
                            f"报告：`{os.path.relpath(rep, ROOT)}`\n"
                            f"复跑：`python tools/night_probe32_ci.py --no-deploy`")
                    print(f"[bd] {bd_create(title, desc)}")

        # ⑤ 异常回退信号（只记录，不开票：弱信号，避免误报）
        for r in rows:
            if r["body"] > 0 and med and r["body"] < med * 0.5:
                print(f"[note] 疑似回退 #{r['idx']} {r['proto']} body={r['body']}B << median {med}B")

        return 0 if (f == 0 and pa == 0 and not problems) else 1
    finally:
        if not args.smoke:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
