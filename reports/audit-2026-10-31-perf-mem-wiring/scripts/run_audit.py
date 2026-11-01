"""Audit E2E harness: run xray.exe against crafted configs, probe behaviour.

For each fixture:
  1. start python sink server on 127.0.0.1:<sink_port> (replies PONG)
  2. start xray.exe run -c <fixture>
  3. wait until every expected listener is up (socks port)
  4. socks-probe 127.0.0.1:<socks_port> -> <target_host>:<sink_port>
  5. stop xray, print its captured log lines that contain warn/error
Prints a machine-readable verdict block per fixture.
"""
import os
import re
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRAY = r"D:/Project/Xray-core-rust/target/release/xray.exe"
FIXTURES = os.path.join(ROOT, "fixtures")
SCRIPTS = os.path.join(ROOT, "scripts")
PY = sys.executable

SINK_PORT = 19099


def wait_port(port, want_open=True, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket()
        s.settimeout(0.3)
        try:
            s.connect(("127.0.0.1", port))
            s.close()
            if want_open:
                return True
        except OSError:
            if not want_open:
                return True
        finally:
            try:
                s.close()
            except OSError:
                pass
        time.sleep(0.2)
    return False


def free_port(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def run_case(name, cfg, socks_port=19001, target_host="localhost", extra_ports=()):
    print("=" * 78)
    print(f"CASE {name}  cfg={cfg}  target={target_host}:{SINK_PORT}")
    if not free_port(socks_port):
        print(f"SKIP: socks port {socks_port} busy")
        return
    sink_log = os.path.join(ROOT, "scripts", f"sink_{name}.txt")
    sink_fh = open(sink_log, "w", encoding="utf-8")
    sink = subprocess.Popen([PY, os.path.join(SCRIPTS, "sink_server.py"), str(SINK_PORT), "40"],
                            stdout=sink_fh, stderr=subprocess.STDOUT, text=True)
    sink_fh.flush()
    first = "see " + sink_log

    log_path = os.path.join(ROOT, "scripts", f"log_{name}.txt")
    cfg_path = os.path.join(FIXTURES, cfg)
    proc = subprocess.Popen([XRAY, "run", "-c", cfg_path],
                            stdout=open(log_path, "w", encoding="utf-8", errors="replace"),
                            stderr=subprocess.STDOUT)
    up = wait_port(socks_port, True, 20.0)
    print(f"xray pid={proc.pid} socks {socks_port} listening={up} rc_poll={proc.poll()}")
    for p in extra_ports:
        print(f"extra port {p} listening={wait_port(p, True, 2.0)}")

    probe = subprocess.run([PY, os.path.join(SCRIPTS, "socks_probe.py"), "127.0.0.1",
                            str(socks_port), target_host, str(SINK_PORT), "6"],
                           capture_output=True, text=True)
    print("probe rc=%d" % probe.returncode)
    print("  " + probe.stdout.strip().replace("\n", "\n  "))
    if probe.stderr.strip():
        print("  stderr: " + probe.stderr.strip())

    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
    try:
        sink.terminate()
        sink.wait(timeout=5)
    except Exception:
        sink.kill()
    sink_fh.close()
    out = open(sink_log, encoding="utf-8").read()
    print("sink log: " + " | ".join(out.strip().splitlines()[-4:]))

    txt = open(log_path, encoding="utf-8", errors="replace").read()
    keep = [l for l in txt.splitlines()
            if re.search(r"WARN|ERROR|warn|error|falling back|skipping|跳过|失败", l)]
    print(f"--- xray log highlights ({len(keep)} lines) ---")
    for l in keep[:40]:
        print(l)
    print()


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("all", "a"):
        run_case("a_ok", "cfg_a_ok.json")
        run_case("a_fallback", "cfg_a_fallback.json")
    if which in ("all", "b"):
        run_case("b_outbound_skip", "cfg_b_outbound_skip.json", extra_ports=(19002,))
        run_case("b2_bad_uuid_expect_direct", "cfg_b2_bad_uuid_outbound.json")
    if which in ("all", "f"):
        run_case("fr_control_other_cidr", "cfg_fr_control_other_cidr.json")
        run_case("fr_geoip_cn", "cfg_fr_geoip_cn.json")
        run_case("fr_typo_cidr", "cfg_fr_typo_cidr.json")
    if which in ("all", "c"):
        run_case("c_sniff_exclude", "cfg_c_sniff_exclude.json")
