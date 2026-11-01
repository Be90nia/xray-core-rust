"""C4 实测：gRPC HandlerService 的 AddInbound / RemoveInbound 并发。

C4a  add 与 remove 并发（同一 tag）：add 返回 Ok 后端口是否真的在监听？
     —— 覆盖 start_inbound 的「insert 后 await 期间被 remove 取消仍返回 Ok」窗口。
C4b  同一 tag 并发 add ×N：重复 tag 的报错文案。
     —— 覆盖 contains() 读锁 → insert() 写锁之间的 TOCTOU（应报 existing tag，
        竞态下会报成 inbound registry full）。

用法：python verifyC4_grpc_race.py [--rounds 30] [--conc 4]
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time

REPO = r"D:/Project/Xray-core-rust"
XRAY = os.path.join(REPO, "target/release/xray.exe")
HERE = os.path.dirname(os.path.abspath(__file__))
TMP = os.path.abspath(os.path.join(HERE, "..", "tmp"))
os.makedirs(TMP, exist_ok=True)

API_PORT = 18090
API = f"127.0.0.1:{API_PORT}"


def run(args, timeout=8):
    p = subprocess.run(
        [XRAY, *args], capture_output=True, text=True, timeout=timeout, cwd=REPO
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def port_listening(port):
    s = socket.socket()
    s.settimeout(0.6)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def write_add_cfg(path, tag, port):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "inbounds": [
                    {
                        "tag": tag,
                        "listen": "127.0.0.1",
                        "port": port,
                        "protocol": "socks",
                        "settings": {"udp": False, "auth": "noauth"},
                    }
                ]
            },
            f,
        )


def start_xray(cfg_path, log_path):
    log = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen([XRAY, "run", "-c", cfg_path], stdout=log, stderr=subprocess.STDOUT, cwd=REPO)
    for _ in range(120):
        if port_listening(API_PORT):
            return proc, log
        if proc.poll() is not None:
            raise RuntimeError("xray exited early; see " + log_path)
        time.sleep(0.1)
    raise RuntimeError("api port never opened")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=30)
    ap.add_argument("--conc", type=int, default=4)
    args = ap.parse_args()

    cfg = {
        "log": {"loglevel": "info"},
        "api": {"tag": "api", "listen": API, "services": ["HandlerService"]},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 18100,
                "tag": "base",
                "protocol": "socks",
                "settings": {"udp": False, "auth": "noauth"},
            }
        ],
        "outbounds": [{"protocol": "freedom"}],
    }
    cfg_path = os.path.join(TMP, "cfg-verifyc4-api.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    proc, log = start_xray(cfg_path, os.path.join(TMP, "log-verifyc4-api-info.txt"))
    try:
        print(f"xray pid={proc.pid} api={API}")

        # ---------------- C4b：同一 tag 并发 add
        print("\n== C4b 同一 tag 并发 add（期望：其余全部报 existing tag found）")
        tag_b = "dup"
        cfg_b = os.path.join(TMP, "cfg-verifyc4-dup.json")
        write_add_cfg(cfg_b, tag_b, 18200)
        msgs = []
        for rnd in range(3):
            # 先确保干净
            run(["api", "remove-inbound", tag_b, "-s", API])
            ths = []
            outs = [None] * args.conc

            def worker(i):
                outs[i] = run(["api", "add-inbound", cfg_b, "-s", API])

            for i in range(args.conc):
                th = threading.Thread(target=worker, args=(i,))
                ths.append(th)
                th.start()
            for th in ths:
                th.join()
            for rc, out in outs:
                msgs.append((rc, out.strip().splitlines()[-1] if out.strip() else ""))
            run(["api", "remove-inbound", tag_b, "-s", API])
            time.sleep(0.2)
        concat = "\n".join(f"  rc={rc} {m}" for rc, m in msgs)
        print(concat)
        dup_bad = [m for _, m in msgs if "registry full" in m]
        dup_ok = [m for _, m in msgs if "existing tag" in m]
        print(
            f"  → existing-tag 文案 {len(dup_ok)} 条，registry-full 误报 {len(dup_bad)} 条"
        )

        # ---------------- C4a：add 与 remove 并发
        print(f"\n== C4a add / remove 并发（{args.rounds} 轮）")
        rows = []
        for i in range(args.rounds):
            tag = f"t{i}"
            port = 24000 + i
            cfg_i = os.path.join(TMP, f"cfg-verifyc4-{tag}.json")
            write_add_cfg(cfg_i, tag, port)
            stop = threading.Event()

            def remover():
                while not stop.is_set():
                    run(["api", "remove-inbound", tag, "-s", API], timeout=5)

            th = threading.Thread(target=remover)
            th.start()
            time.sleep(0.05)
            rc, out = run(["api", "add-inbound", cfg_i, "-s", API])
            time.sleep(0.05)
            stop.set()
            th.join()
            listen = port_listening(port)
            # 探测登记态：再删一次——能让「Ok 但未登记」现形
            rc2, out2 = run(["api", "remove-inbound", tag, "-s", API])
            registered = "removed inbound" in out2
            listen_after = port_listening(port)
            verdict = "normal"
            if rc == 0 and not listen:
                verdict = "FALSE_OK_STOPPED"
            elif rc == 0 and listen and not registered:
                verdict = "FALSE_OK_UNREGISTERED_LISTENER"
            elif rc == 0 and listen and listen_after and not registered:
                verdict = "FALSE_OK_LEAKED_LISTENER"
            elif rc == 0 and listen:
                verdict = "normal"
            elif rc != 0:
                verdict = "add_failed"
            rows.append((tag, rc, listen, registered, listen_after, verdict))
            print(
                f"  {tag}: add_rc={rc} listening={listen} registered={registered} "
                f"listening_after_remove={listen_after} -> {verdict}"
            )
        bad = [r for r in rows if r[5] in ("FALSE_OK_STOPPED", "FALSE_OK_UNREGISTERED_LISTENER", "FALSE_OK_LEAKED_LISTENER")]
        print(f"\n  → 假成功 {len(bad)}/{len(rows)}：{[r[0]+':'+r[5] for r in bad]}")
        print(
            "VERDICT: C4 REPRODUCED"
            if bad or dup_bad
            else "VERDICT: C4 未复现（本轮未命中窗口）"
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


if __name__ == "__main__":
    sys.exit(main())
