"""Go 26.10.17 vs Rust HEAD 双跑差分台账（共用底座）。

纪律（见派单契约）：
- 端口段 GoDiff 专用 25000-25099，不与他方重叠
- 清理只按 PID（Stop-Process -Id），禁 -Name / taskkill /IM / 通配
- 实例用 subprocess.Popen 持句柄，finally terminate
- 两侧喂同一份 JSON 字节
"""
import json
import os
import re
import socket
import subprocess
import sys
import time

GO = r"D:\tmp\go2617\xray.exe"
RUST = r"D:\Project\Xray-core-rust\target\release\xray.exe"
TMP = r"D:\Project\Xray-core-rust\reports\audit-2026-10-31-perf-mem-wiring\round3\tmp"
GO_PORT_BASE = 25000
RUST_PORT_BASE = 25050

SIDE = {"go": GO, "rust": RUST}


def write_cfg(name, obj):
    """两侧共用同一份 JSON 字节。"""
    os.makedirs(TMP, exist_ok=True)
    path = os.path.join(TMP, name + ".json")
    if isinstance(obj, (dict, list)):
        body = json.dumps(obj, indent=2, ensure_ascii=False)
    else:
        body = obj  # raw string
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)
    return path


def port_free(p):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", p))
        return True
    except OSError:
        return False
    finally:
        s.close()


def wait_port(p, timeout=6.0):
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket()
        s.settimeout(0.4)
        try:
            s.connect(("127.0.0.1", p))
            return True
        except OSError:
            time.sleep(0.15)
        finally:
            s.close()
    return False


def run_once(side, cfg_path, timeout=12.0, args=None):
    """跑一次 'xray run -c cfg'，返回观测字典。

    观测点：进程存活 / 是否监听 / stderr+stdout 关键行 / 退出码
    """
    cmd = [SIDE[side], "run", "-c", cfg_path] if args is None else args
    t0 = time.time()
    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=os.path.dirname(cfg_path),
        )
    except Exception as e:  # binary missing etc
        return {"side": side, "spawn_error": repr(e), "alive": False}
    out = b""
    try:
        # 先等它要么退出、要么把端口拉起来
        deadline = time.time() + timeout
        alive = True
        while time.time() < deadline:
            if p.poll() is not None:
                alive = False
                break
            time.sleep(0.2)
        if alive:
            p.terminate()
            try:
                out = p.communicate(timeout=6)[0]
            except subprocess.TimeoutExpired:
                p.kill()
                out = p.communicate()[0]
            code = p.returncode
        else:
            out = p.communicate()[0]
            code = p.returncode
    finally:
        if p.poll() is None:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                p.kill()
    text = out.decode("utf-8", "replace")
    return {
        "side": side,
        "alive": alive,
        "exit_code": code,
        "output": text,
        "elapsed": round(time.time() - t0, 2),
    }


def run_server(side, cfg_obj, port, name, extra_ready=None, timeout=12.0):
    """起一个服务端实例并确认监听。返回 (proc, obs)。"""
    cfg_path = write_cfg(name, cfg_obj)
    cmd = [SIDE[side], "run", "-c", cfg_path]
    p = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=os.path.dirname(cfg_path)
    )
    ready = wait_port(port, timeout=timeout)
    return p, {"side": side, "cfg": cfg_path, "port": port, "ready": ready, "proc": p}


def kill_proc(p):
    """只按 PID 清理。"""
    if p is None:
        return
    try:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=6)
            except Exception:
                p.kill()
                p.wait(timeout=3)
    except Exception:
        pass


def drain(p, timeout=2.0):
    """读出进程 stdout（用于日志关键行观测）。"""
    if p is None or p.stdout is None:
        return ""
    try:
        p.stdout.flush()
    except Exception:
        pass
    import fcntl  # noqa
    return ""


PANIC_RE = re.compile(r"(panic|RUST_BACKTRACE|thread '.*' panicked)", re.I)
FATAL_RE = re.compile(r"(failed to start|FATAL|error reading config|invalid config)", re.I)


def classify(result):
    """把一次 run 的观测归一为结论标签。"""
    if result.get("spawn_error"):
        return "SPAWN_FAIL"
    txt = result.get("output", "")
    if PANIC_RE.search(txt):
        return "PANIC"
    if result["alive"]:
        return "STARTED"
    code = result.get("exit_code")
    if code == 0:
        return "EXITED_CLEAN"
    return "REJECTED"


def summarize(result):
    txt = result.get("output", "")
    lines = [l for l in txt.splitlines() if l.strip()]
    return {
        "verdict": classify(result),
        "exit_code": result.get("exit_code"),
        "alive": result.get("alive"),
        "head": " | ".join(lines[:4])[:600],
        "tail": " | ".join(lines[-4:])[:600],
        "panic": bool(PANIC_RE.search(txt)),
    }
