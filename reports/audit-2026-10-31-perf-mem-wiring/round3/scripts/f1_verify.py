"""复核：F1 的 16 条差异 —— 补「是否真的在监听」+ 完整错误文本。

Rust「STARTED」= 进程活着的判定太宽：真拒启但没退、或启动了但没监听，
必须补端口探测 + 完整输出。
"""
import json
import os
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import GO, RUST, TMP, kill_proc, write_cfg  # noqa: E402

PORT = 25000
SIDE = {"go": GO, "rust": RUST}


def wait_listen(p, timeout=6.0):
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


def run(side, cfg_path, port, timeout=7.0):
    p = subprocess.Popen([SIDE[side], "run", "-c", cfg_path], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, cwd=os.path.dirname(cfg_path))
    t0 = time.time()
    listening = False
    alive = True
    while time.time() - t0 < timeout:
        if p.poll() is not None:
            alive = False
            break
        listening = wait_listen(port, timeout=0.6)
        if listening:
            break
    if alive:
        kill_proc(p)
    out = b""
    try:
        out = p.stdout.read() or b""
    except Exception:
        pass
    try:
        p.stdout.close()
    except Exception:
        pass
    text = out.decode("utf-8", "replace")
    return {"alive": alive, "listening": listening, "exit": p.poll(),
            "text": text}


def err_lines(text):
    """挑出错误/警告关键行。"""
    pats = re.compile(r"(Failed to start|Error|error|WARN|failed|invalid|unsupported|unknown|"
                      r"not supported|cannot|无法|失败|不支持|未知)", re.I)
    out = [l for l in text.splitlines() if pats.search(l)]
    return out[-4:]


BASE = {
    "log": {"loglevel": "warning"},
    "inbounds": [{"tag": "in-1", "listen": "127.0.0.1", "port": PORT,
                  "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
    "outbounds": [{"tag": "out-1", "protocol": "freedom", "settings": {}}],
    "policy": {"levels": {"0": {}}},
    "routing": {"rules": [{"type": "field", "inboundTag": ["in-1"], "outboundTag": "out-1"}]},
}


def mk(mut):
    c = json.loads(json.dumps(BASE))
    mut(c)
    return c


CASES = [
    ("unknown_outbound_protocol",
     lambda c: c["outbounds"].append({"tag": "out-x", "protocol": "nosuchproto", "settings": {}})),
    ("unknown_inbound_protocol",
     lambda c: c["inbounds"].append({"tag": "in-x", "listen": "127.0.0.1", "port": PORT + 1,
                                      "protocol": "nosuchproto", "settings": {}})),
    ("vless_outbound_no_vnext",
     lambda c: c["outbounds"].append({"tag": "out-x", "protocol": "vless",
                                      "settings": {"vnext": []}})),
    ("udp_as_string", lambda c: c["inbounds"][0]["settings"].update({"udp": "false"})),
    ("settings_as_string", lambda c: c["outbounds"][0].update({"settings": "none"})),
    ("port_too_large", lambda c: c["inbounds"][0].update({"port": 70000})),
    ("dup_tag_outbound",
     lambda c: c["outbounds"].append({"tag": "out-1", "protocol": "freedom", "settings": {}})),
    ("unknown_domain_strategy",
     lambda c: c["outbounds"][0]["settings"].update({"domainStrategy": "AsIs2"})),
    ("routing_rules_not_array", lambda c: c.update({"routing": {"rules": {"type": "field"}}})),
    ("routing_rule_missing_type", lambda c: c.update({"routing": {"rules": [{"inboundTag": ["in-1"]}]}})),
    ("inbound_streamSettings_not_object",
     lambda c: c["inbounds"][0].update({"streamSettings": "tcp"})),
    ("json_not_object", lambda c: "[]"),
    ("routing_rule_unknown_domain_strategy",
     lambda c: c.update({"routing": {"domainStrategy": "Bogus", "rules": [
         {"type": "field", "outboundTag": "out-1"}]}})),
    ("routing_bad_ip_cidr", lambda c: c.update({"routing": {"rules": [
        {"type": "field", "ip": ["999.1.1.1/24"], "outboundTag": "out-1"}]}})),
    ("routing_unknown_rule_type", lambda c: c.update({"routing": {"rules": [
        {"type": "bogus", "outboundTag": "out-1"}]}})),
]


def main():
    results = []
    for i, (name, mut) in enumerate(CASES):
        cfg = mk(mut)
        payload = cfg if isinstance(cfg, str) else json.dumps(cfg, indent=2, ensure_ascii=False)
        path = write_cfg("f1v_%02d_%s" % (i, name), payload)
        row = {"case": name}
        for side in ("go", "rust"):
            r = run(side, path, PORT)
            row[side] = {"alive": r["alive"], "listening": r["listening"],
                         "exit": r["exit"], "errs": err_lines(r["text"])}
        row["go_state"] = ("REJECTED" if not row["go"]["alive"] else
                           ("LISTENING" if row["go"]["listening"] else "ALIVE_NOT_LISTENING"))
        row["rust_state"] = ("REJECTED" if not row["rust"]["alive"] else
                             ("LISTENING" if row["rust"]["listening"] else "ALIVE_NOT_LISTENING"))
        row["same"] = row["go_state"] == row["rust_state"]
        results.append(row)
        print("=== %s" % name)
        print("   GO   %-20s exit=%s" % (row["go_state"], row["go"]["exit"]))
        for l in row["go"]["errs"]:
            print("        G:", l[:190])
        print("   RUST %-20s exit=%s" % (row["rust_state"], row["rust"]["exit"]))
        for l in row["rust"]["errs"]:
            print("        R:", l[:190])
    with open(os.path.join(TMP, "f1_verify.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print("\nverified diffs=%d / %d" % (sum(1 for r in results if not r["same"]), len(results)))


if __name__ == "__main__":
    main()
