#!/usr/bin/env python3
"""CI 互通测试 (跨平台): dist/interop_matrix.py 的 POSIX 移植, 本地脚本零改动.

- suite rust:        Rust client<->Rust server, 6 协议 x 2 轮 = 12 测
- suite go:          Go client -> Rust server (官方 xray-core release 二进制), 默认 6 协议
- suite rust_to_go:  Rust client -> Go server 反向 (26zn 战役暴露盲区补缺), 默认 6 协议
- suite extra:       新协议 (splithttp/grpc/reality 必交 + hysteria2/anytls/tuic/naive 尽力),
                     每协议 3 方向 (Rust<->Rust + Go->Rust + Rust->Go) = 3N 测;
                     Go 基线不支持的 proto 自动跳过 cross 方向, 仅 Rust<->Rust 保留.

默认套件 = rust + go + rust_to_go + extra = 18 现有 + 6 反向 + 13 新协议 = 37 测
(local 26.7.28 Go: hysteria2/anytls/tuic/naive 不支持, 跳过 8 个 cross 方向)
( CI 26.9.9 Go: 可能全通, runtime 探测自动跳过)
TLS 双向统一 pinnedPeerCertSha256 (bd 5x41: allowInsecure 配置期硬错), 证书由 openssl 现场生成.
REALITY 配置需 Python `cryptography` 包 (X25519 keypair); CI workflow 已装.

用法: python3 dist/interop_ci.py [--rust PATH] [--go PATH] [--work DIR]
           [--suites rust,go,rust_to_go,extra] [--cross-protos <list>]
           [--extra-protos <list>] [--dry-run]
--go-protos 是 --cross-protos 的 deprecated alias (兼容旧 CI 调用).
"""
import argparse
import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time

UUID = 'b831381d-6324-4d53-ad4f-8cda48b30811'
TPW = 'test-pass-12345'
SS22_KEY = base64.b64encode(b'0123456789abcdef').decode()  # 16B for 2022-blake3-aes-128-gcm
PROTOS = ['vmess', 'vless_vision_tls', 'trojan_tls', 'vless_ws', 'ss', 'ss2022']
# Go 交叉：6 协议全 Go->Rust 双向校验。vless_vision_tls 曾因 rustls 贪婪 recv
# 合流裸尾致 Linux 确定性挂（bd jeu9），RecordFramer 记录对齐读修复后 VPS 连续
# 5 次 PASS（2026-09-20）恢复进默认列表；--go-protos <list> 仍可缩减。
GO_CROSS_PROTOS = PROTOS
# Rust 客户端连 Go 服务端反向：补 26zn 战役暴露盲区（只测了 Rust→Rust 与 Go→Rust，
# 缺 Rust→Go 方向验证）。同一组 6 协议复用 build() —— Go 与 Rust 服务端读同份配置。
RUST_TO_GO_PROTOS = PROTOS
# 新协议套件：splithttp/grpc/reality 三件必交付，hysteria2/anytls/tuic/naive 尽力。
# 每个 proto 各跑 Rust↔Rust + Go→Rust + Rust→Go 三方向 = 3 测。
EXTRA_PROTOS = ['splithttp', 'grpc', 'reality', 'hysteria2', 'anytls', 'tuic', 'naive']
BASE_PORT = 18100
IS_WIN = os.name == 'nt'
EXE = '.exe' if IS_WIN else ''

CERT = KEY = None
PIN = None  # leaf DER sha256, Go/Rust client 通用

OPENSSL_CNF = """[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no
[dn]
CN = localhost
[v3_req]
subjectAltName = DNS:localhost,IP:127.0.0.1
"""


def probe_rust(root):
    for c in (os.path.join(root, 'target', 'release', 'xray' + EXE),
              os.path.join(root, 'dist', 'xray' + EXE)):
        if os.path.isfile(c):
            return c
    return None


def probe_go(root):
    for c in (os.path.join(root, 'tools', 'xray-go', 'xray'),
              'D:/Project/Xray-core/target/xray-go.exe'):  # 本机 Go 基线
        if os.path.isfile(c):
            return c
    return None


def gen_cert(cert, key):
    cnf = cert + '.cnf'
    with open(cnf, 'w') as f:
        f.write(OPENSSL_CNF)
    # -config 写法兼容 LibreSSL(macOS 自带) 与 OpenSSL; 不用 1.1.1+ 才有的 -addext
    r = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', key, '-out', cert, '-days', '2', '-config', cnf],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError('openssl 证书生成失败: ' + r.stderr.strip()[:300])


def pin_of(cert):
    with open(cert) as f:
        der = base64.b64decode(''.join(l for l in f.read().splitlines() if '-----' not in l))
    return hashlib.sha256(der).hexdigest()


def tls_cli():
    # bd 5x41: allowInsecure 已配置期硬错, 双向统一证书 pin
    return {'pinnedPeerCertSha256': PIN}


def tls_srv():
    return {'certificates': [{'certificateFile': CERT, 'keyFile': KEY}]}


def build(proto, P):
    """返回 (server_inbound, client_outbound), 配置形状与 interop_matrix.py 逐字一致."""
    if proto == 'vmess':
        si = {"port": P, "listen": "127.0.0.1", "protocol": "vmess",
              "settings": {"clients": [{"id": UUID, "alterId": 0}]}}
        co = {"protocol": "vmess", "settings": {"vnext": [
            {"address": "127.0.0.1", "port": P,
             "users": [{"id": UUID, "alterId": 0, "security": "auto"}]}]}}
    elif proto == 'vless_vision_tls':
        si = {"port": P, "listen": "127.0.0.1", "protocol": "vless",
              "settings": {"decryption": "none", "clients": [{"id": UUID, "flow": "xtls-rprx-vision"}]},
              "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_srv()}}
        co = {"protocol": "vless", "settings": {"vnext": [
            {"address": "127.0.0.1", "port": P,
             "users": [{"id": UUID, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
            "streamSettings": {"network": "tcp", "security": "tls",
                               "tlsSettings": {"serverName": "localhost", **tls_cli()}}}
    elif proto == 'vless_ws':
        si = {"port": P, "listen": "127.0.0.1", "protocol": "vless",
              "settings": {"decryption": "none", "clients": [{"id": UUID}]},
              "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}}}
        co = {"protocol": "vless", "settings": {"vnext": [
            {"address": "127.0.0.1", "port": P,
             "users": [{"id": UUID, "encryption": "none"}]}]},
            "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}}}
    elif proto == 'trojan_tls':
        si = {"port": P, "listen": "127.0.0.1", "protocol": "trojan",
              "settings": {"clients": [{"password": TPW}]},
              "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_srv()}}
        co = {"protocol": "trojan", "settings": {"servers": [
            {"address": "127.0.0.1", "port": P, "password": TPW}]},
            "streamSettings": {"network": "tcp", "security": "tls",
                               "tlsSettings": {"serverName": "localhost", **tls_cli()}}}
    elif proto == 'ss':
        si = {"port": P, "listen": "127.0.0.1", "protocol": "shadowsocks",
              "settings": {"method": "aes-256-gcm", "password": TPW, "network": "tcp"}}
        co = {"protocol": "shadowsocks", "settings": {"servers": [
            {"address": "127.0.0.1", "port": P, "method": "aes-256-gcm", "password": TPW}]}}
    elif proto == 'ss2022':
        si = {"port": P, "listen": "127.0.0.1", "protocol": "shadowsocks",
              "settings": {"method": "2022-blake3-aes-128-gcm", "password": SS22_KEY, "network": "tcp"}}
        co = {"protocol": "shadowsocks", "settings": {"servers": [
            {"address": "127.0.0.1", "port": P, "method": "2022-blake3-aes-128-gcm", "password": SS22_KEY}]}}
    else:
        raise ValueError(proto)
    return si, co


# ---- 新协议 build_x: 每协议独立 return, 不破坏 build() 的对称性 (assignment 约束) ----
# 共用端口：base=BASE_PORT, 套件整体 idx 接管避免冲突；S = P+1 走 socks5h。
# streamSettings 复用 tls_cli/tls_srv (pin 双向统一证书)。
_REALITY_KEYS = None  # (priv_b64, pub_b64, short_id) 一次生成, 全套共享

def _ensure_reality_keys():
    global _REALITY_KEYS
    if _REALITY_KEYS is None:
        # X25519 keypair, 与 xray-transport-interop_test.rs reality_e2e 完全一致
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        import base64 as _b64
        sk = X25519PrivateKey.generate()
        pk = sk.public_key()
        priv_b = sk.private_bytes(serialization.Encoding.Raw,
                                  serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption())
        pub_b = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        priv_b64 = _b64.urlsafe_b64encode(priv_b).rstrip(b'=').decode()
        pub_b64 = _b64.urlsafe_b64encode(pub_b).rstrip(b'=').decode()
        _REALITY_KEYS = (priv_b64, pub_b64, '0123456789abcdef')
    return _REALITY_KEYS


def build_x(proto, P):
    """新协议 build: 返回 (server_inbound, client_outbound). 与 build() 解耦.
    每协议一份独立配置, 复用 tls_cli/tls_srv 走证书 pin 双向统一.
    支持: splithttp, grpc, reality (必交); hysteria2, anytls, tuic, naive (尽力).
    不支持的 proto 抛 NotImplementedError, main() 跳过并记录."""
    if proto == 'splithttp':
        ss_srv = {"network": "splithttp", "security": "tls",
                  "splithttpSettings": {"path": "/xhttp", "mode": "packet-up", "host": "localhost"},
                  "tlsSettings": tls_srv()}
        ss_cli = {"network": "splithttp", "security": "tls",
                  "splithttpSettings": {"path": "/xhttp", "mode": "packet-up", "host": "localhost"},
                  "tlsSettings": {"serverName": "localhost", **tls_cli()}}
        si = {"port": P, "listen": "127.0.0.1", "protocol": "vless",
              "settings": {"clients": [{"id": UUID}], "decryption": "none"},
              "streamSettings": ss_srv}
        co = {"protocol": "vless", "settings": {"vnext": [
            {"address": "127.0.0.1", "port": P,
             "users": [{"id": UUID, "encryption": "none"}]}]},
              "streamSettings": ss_cli}
    elif proto == 'grpc':
        ss_srv = {"network": "grpc", "security": "tls",
                  "grpcSettings": {"serviceName": "GunService", "host": "localhost"},
                  "tlsSettings": tls_srv()}
        ss_cli = {"network": "grpc", "security": "tls",
                  "grpcSettings": {"serviceName": "GunService", "host": "localhost"},
                  "tlsSettings": {"serverName": "localhost", **tls_cli()}}
        si = {"port": P, "listen": "127.0.0.1", "protocol": "vless",
              "settings": {"clients": [{"id": UUID}], "decryption": "none"},
              "streamSettings": ss_srv}
        co = {"protocol": "vless", "settings": {"vnext": [
            {"address": "127.0.0.1", "port": P,
             "users": [{"id": UUID, "encryption": "none"}]}]},
              "streamSettings": ss_cli}
    elif proto == 'reality':
        # REALITY 服务端必盲区：dest 不能指向 vless 端口本身（自身死循环）,
        # 必须在 build 阶段映射一个外层 fallback（本地 echo or 真实站点）.
        # 本地互操作 dest=127.0.0.1+echo_port; fallback 由 run_x_one 注入.
        priv_b64, pub_b64, sid = _ensure_reality_keys()
        # 暂用端口 P-1 当 dest, run_x_one 启动 echo 在 P-1 上; server vless 端口 = P
        ss_srv = {"network": "tcp", "security": "reality",
                  "realitySettings": {
                      "privateKey": priv_b64,
                      "serverNames": ["localhost"],
                      "shortIds": [sid],
                      "dest": "127.0.0.1:%d" % (P - 1)}}
        ss_cli = {"network": "tcp", "security": "reality",
                  "realitySettings": {
                      "serverName": "localhost",
                      "publicKey": pub_b64,
                      "shortId": sid,
                      "fingerprint": "randomizednoalpn"}}
        si = {"port": P, "listen": "127.0.0.1", "protocol": "vless",
              "settings": {"clients": [{"id": UUID}], "decryption": "none"},
              "streamSettings": ss_srv}
        co = {"protocol": "vless", "settings": {"vnext": [
            {"address": "127.0.0.1", "port": P,
             "users": [{"id": UUID, "encryption": "none"}]}]},
              "streamSettings": ss_cli}
    elif proto == 'hysteria2':
        # QUIC+TLS+auth; Rust↔Rust 同栈测试可行性高, 跨栈 REALITY 经验: Go/Rust
        # quic 互通通常 OK; 但本机 echo TCP fallback 必要 — Quic dest 行为是
        # 主动发首字节, 不像 vision/tls 是 passive. local echo 仍可 (TCP) 但
        # dest 需改 TCP 端口. 标尽力项, 失败在 doc 记录.
        auth_pw = 'hy2-secret-passphrase'
        ss_srv = {"network": "hysteria2", "security": "tls",
                  "hysteria2Settings": {"version": 2, "password": auth_pw},
                  "tlsSettings": tls_srv()}
        ss_cli = {"network": "hysteria2", "security": "tls",
                  "hysteria2Settings": {"version": 2, "password": auth_pw},
                  "tlsSettings": {"serverName": "localhost", **tls_cli()}}
        si = {"port": P, "listen": "127.0.0.1", "protocol": "vless",
              "settings": {"clients": [{"id": UUID}], "decryption": "none"},
              "streamSettings": ss_srv}
        # Rust vless outbound 不接 network=hysteria2 (crates/xray-core/src/outbound.rs:757
        # 仅 tcp/ws/grpc/splithttp/httpupgrade) — 客户端独立 hysteria outbound,
        # settings JSON 对齐 parse_hysteria_config (outbound.rs:2353): {version, servers[]}.
        # 服务端 si (vless+network=hysteria2) 由别任务修产品代码 (bd upe1 等).
        co = {"protocol": "hysteria",
              "settings": {"version": 2,
                           "servers": [{"address": "127.0.0.1", "port": P,
                                        "auth": auth_pw, "serverName": "localhost"}]}}
    elif proto == 'anytls':
        # anytls 协议对 dest 行为: 透明代理 (类似 vision); 用本地 echo 当 dest.
        auth_pw = 'anytls-secret'
        ss_srv = {"network": "anytls", "security": "tls",
                  "anytlsSettings": {"password": auth_pw},
                  "tlsSettings": tls_srv()}
        ss_cli = {"network": "anytls", "security": "tls",
                  "anytlsSettings": {"password": auth_pw},
                  "tlsSettings": {"serverName": "localhost", **tls_cli()}}
        si = {"port": P, "listen": "127.0.0.1", "protocol": "vless",
              "settings": {"clients": [{"id": UUID}], "decryption": "none"},
              "streamSettings": ss_srv}
        # Rust vless outbound 不接 network=anytls — 客户端独立 anytls outbound,
        # settings JSON 对齐 parse_anytls_config (outbound.rs:2232): 顶层 server/
        # server_port/sni/insecure/password (无 servers 数组, 不同于 hysteria/tuic).
        # anytls 协议自持 TLS (出站 dispatcher 不消费 streamSettings.network/security).
        co = {"protocol": "anytls",
              "settings": {"server": "127.0.0.1", "server_port": P,
                           "sni": "localhost", "insecure": True,
                           "password": auth_pw}}
    elif proto == 'tuic':
        # TUIC v5 over QUIC; dest 行为: UDP+TCP 代理; 需 QUIC stack 双向兼容.
        uuid = UUID
        _tuic_pw = 'tuic-pw'
        ss_srv = {"network": "tuic", "security": "tls",
                  "tuicSettings": {"users": [{"uuid": uuid, "password": _tuic_pw}]},
                  "tlsSettings": tls_srv()}
        ss_cli = {"network": "tuic", "security": "tls",
                  "tuicSettings": {"users": [{"uuid": uuid, "password": _tuic_pw}],
                                   "server": "127.0.0.1", "server_port": P,
                                   "congestion_control": "cubic"},
                  "tlsSettings": {"serverName": "localhost", **tls_cli()}}
        # TUIC inbound settings 走 v 字段顶层 uuid/password (xray-core parse_tuic_inbound_settings)
        si = {"port": P, "listen": "127.0.0.1", "protocol": "tuic",
              "settings": {"uuid": uuid, "password": _tuic_pw},
              "streamSettings": ss_srv}
        co = {"protocol": "tuic", "settings": {"servers": [
            {"address": "127.0.0.1", "port": P, "uuid": uuid, "password": _tuic_pw,
             "congestion_control": "cubic"}]},
              "streamSettings": ss_cli}
    elif proto == 'naive':
        # naive = HTTPS 前置代理 + 上层协议 (vless+tcp); dest=本地 echo 即可.
        # Go 配置上 naive 通常是 outbound; inbound 通常是 dokodemo/socks/http.
        # 本地验证: server=dokodemo+naive 配置, client=naive+VLESS over naive.
        # 暂以标准 vless+naive 简化:
        ss_srv = {"network": "naive", "security": "tls",
                  "naiveSettings": {"method": "vless", "protocol": "vless", "uuid": UUID},
                  "tlsSettings": tls_srv()}
        ss_cli = {"network": "naive", "security": "tls",
                  "naiveSettings": {"method": "vless", "protocol": "vless", "uuid": UUID,
                                    "server": "127.0.0.1", "server_port": P},
                  "tlsSettings": {"serverName": "localhost", **tls_cli()}}
        si = {"port": P, "listen": "127.0.0.1", "protocol": "vless",
              "settings": {"clients": [{"id": UUID}], "decryption": "none"},
              "streamSettings": ss_srv}
        # Rust vless outbound 不接 network=naive — 客户端独立 naive outbound,
        # settings JSON 对齐 parse_naive_config (outbound.rs:2284 → NaiveConfig::
        # from_json): 顶层 server/port/sni/username/password/fingerprint (无 servers
        # 数组, 不同于 hysteria/tuic).
        co = {"protocol": "naive",
              "settings": {"server": "127.0.0.1", "port": P,
                           "sni": "localhost", "username": "user",
                           "password": "pass", "fingerprint": "chrome"}}
    else:
        raise ValueError(proto)
    return si, co


def kill_bins(*paths):
    """跨平台清扫残留进程: POSIX pkill -f 全路径, Windows taskkill 按镜像名."""
    for path in set(paths):
        try:
            if IS_WIN:
                subprocess.run(['cmd', '/c', 'taskkill /F /IM ' + os.path.basename(path)],
                               capture_output=True, timeout=5)
            else:
                subprocess.run(['pkill', '-f', re.escape(path)], capture_output=True, timeout=5)
        except Exception:
            pass


def wait_port(port, deadline_s):
    end = time.time() + deadline_s
    while time.time() < end:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def stop(ps):
    for p in ps:
        p.terminate()
    for p in ps:
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()


def log_tail(work, idx, err):
    for lp in (os.path.join(work, 's%d.log' % idx), os.path.join(work, 'c%d.log' % idx)):
        try:
            tail = open(lp, 'rb').read()[-400:].decode(errors='replace').replace('\n', ' | ')
            err += ' [%s:%s]' % (os.path.basename(lp), tail[:200])
        except Exception:
            pass
    return err


def run_one(idx, proto, server_bin, client_bin, tag, work, dry=False):
    P = BASE_PORT + idx * 2
    S = P + 1
    si, co = build(proto, P)
    scfg = {"log": {"loglevel": "warning"}, "inbounds": [si],
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}
    ccfg = {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": S, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [co]}
    scp = os.path.join(work, 's%d.json' % idx)
    ccp = os.path.join(work, 'c%d.json' % idx)
    with open(scp, 'w') as f:
        json.dump(scfg, f)
    with open(ccp, 'w') as f:
        json.dump(ccfg, f)
    label = '#%02d %s %s' % (idx, tag, proto)
    if dry:
        print('[DRY] %s server=%s client=%s ports=%d/%d' % (label, server_bin, client_bin, P, S), flush=True)
        return 'DRY'
    kill_bins(server_bin, client_bin)
    time.sleep(0.3)
    procs = []
    bs, err, flag = 0, '', 'FAIL'
    try:
        # vless_vision_tls 取证：macOS arm 上偶发 client 端握手提前断（server
        # rustls 报 tls handshake eof），RUST_LOG=trace 全量留痕（s/c log 随
        # 失败工件上传）。
        env = {**os.environ, "RUST_LOG": "trace"} if proto == "vless_vision_tls" else None
        slog = open(os.path.join(work, 's%d.log' % idx), 'wb')
        ps = subprocess.Popen([server_bin, 'run', '-c', scp], stdout=slog,
                              stderr=subprocess.STDOUT, env=env)
        slog.close()
        procs.append(ps)
        if not wait_port(P, 15):
            err = 'server 未监听 %d (15s)' % P
        else:
            clog = open(os.path.join(work, 'c%d.log' % idx), 'wb')
            pc = subprocess.Popen([client_bin, 'run', '-c', ccp], stdout=clog,
                                  stderr=subprocess.STDOUT, env=env)
            clog.close()
            procs.append(pc)
            if pc.poll() is not None:
                # client 启动即死（如端口被残留进程占用 EADDRINUSE）——立即
                # FAIL 并带日志尾，杜绝"残留旧实例代答导致假 PASS/模糊失败"。
                err = 'client 启动即退出，详见 c%d.log' % idx
            else:
                wait_port(S, 15)
                bp = os.path.join(work, 'b%d.body' % idx)
                try:
                    r = subprocess.run(['curl', '-sS', '--max-time', '15', '-x', 'socks5h://127.0.0.1:%d' % S,
                                        'https://www.youtube.com/', '-o', bp, '-w', 'HTTP:%{http_code}'],
                                       capture_output=True, text=True, timeout=20)
                    bs = os.path.getsize(bp) if os.path.exists(bp) else 0
                    marker = b'YouTube' in open(bp, 'rb').read(200000) if bs else False
                    flag = 'PASS' if (bs > 5000 and marker) else 'FAIL'
                    err = r.stderr.strip()[:60]
                except Exception as e:
                    flag, bs, err = 'FAIL', 0, str(e)[:60]
    finally:
        stop(procs)
        kill_bins(server_bin, client_bin)
    if flag == 'FAIL':
        err = log_tail(work, idx, err)
    print('[%s] %-33s HTTP body=%7dB %s' % (flag, label, bs, err), flush=True)
    return flag


def _start_echo(port, work, idx):
    """本地 TCP echo, 真实回写所有收到的字节. REALITY dest 必盲区: 不能指回 vless
    端口, 所以 dest 指向一个 echo 当作 '外层 fallback 站点'. 跨平台."""
    import threading

    def loop():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('127.0.0.1', port))
        srv.listen(64)
        srv.settimeout(30)
        while True:
            try:
                cli, _ = srv.accept()
            except (socket.timeout, OSError):
                break
            threading.Thread(target=lambda c: _echo_serve(c), args=(cli,), daemon=True).start()

    def _echo_serve(c):
        try:
            c.settimeout(20)
            while True:
                data = c.recv(65536)
                if not data:
                    break
                c.sendall(data)
        except (socket.timeout, OSError):
            pass
        finally:
            try:
                c.close()
            except Exception:
                pass

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


def run_x_one(idx, proto, server_bin, client_bin, tag, work, dry=False):
    """新协议 run_one 镜像. REALITY 需先起 echo 在 dest 端口 (P-1)."""
    P = BASE_PORT + idx * 2
    S = P + 1
    si, co = build_x(proto, P)
    scfg = {"log": {"loglevel": "warning"}, "inbounds": [si],
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}
    ccfg = {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": S, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [co]}
    scp = os.path.join(work, 's%d.json' % idx)
    ccp = os.path.join(work, 'c%d.json' % idx)
    with open(scp, 'w') as f:
        json.dump(scfg, f)
    with open(ccp, 'w') as f:
        json.dump(ccfg, f)
    label = '#%02d %s %s' % (idx, tag, proto)
    if dry:
        print('[DRY] %s server=%s client=%s ports=%d/%d' % (label, server_bin, client_bin, P, S), flush=True)
        return 'DRY'
    kill_bins(server_bin, client_bin)
    time.sleep(0.3)
    procs = []
    bs, err, flag = 0, '', 'FAIL'
    echo_t = None
    try:
        # 多数新协议依赖网络: 走 RUST_LOG=trace 留痕 (splithttp 偶发 stuck 排查)
        env = {**os.environ, "RUST_LOG": "trace"} if proto in ('splithttp', 'grpc', 'reality') else None
        # REALITY 需要 echo 在 dest 端口 (build_x 已写死 P-1)
        if proto == 'reality':
            echo_t = _start_echo(P - 1, work, idx)
            time.sleep(0.3)  # 等 echo 起来
        slog = open(os.path.join(work, 's%d.log' % idx), 'wb')
        ps = subprocess.Popen([server_bin, 'run', '-c', scp], stdout=slog,
                              stderr=subprocess.STDOUT, env=env)
        slog.close()
        procs.append(ps)
        if not wait_port(P, 15):
            err = 'server 未监听 %d (15s)' % P
        else:
            clog = open(os.path.join(work, 'c%d.log' % idx), 'wb')
            pc = subprocess.Popen([client_bin, 'run', '-c', ccp], stdout=clog,
                                  stderr=subprocess.STDOUT, env=env)
            clog.close()
            procs.append(pc)
            if pc.poll() is not None:
                err = 'client 启动即退出，详见 c%d.log' % idx
            else:
                wait_port(S, 15)
                bp = os.path.join(work, 'b%d.body' % idx)
                try:
                    r = subprocess.run(['curl', '-sS', '--max-time', '15',
                                        '-x', 'socks5h://127.0.0.1:%d' % S,
                                        'https://www.youtube.com/', '-o', bp, '-w',
                                        'HTTP:%{http_code}'],
                                       capture_output=True, text=True, timeout=20)
                    bs = os.path.getsize(bp) if os.path.exists(bp) else 0
                    marker = b'YouTube' in open(bp, 'rb').read(200000) if bs else False
                    flag = 'PASS' if (bs > 5000 and marker) else 'FAIL'
                    err = r.stderr.strip()[:60]
                except Exception as e:
                    flag, bs, err = 'FAIL', 0, str(e)[:60]
    finally:
        stop(procs)
        kill_bins(server_bin, client_bin)
    if flag == 'FAIL':
        err = log_tail(work, idx, err)
    print('[%s] %-33s HTTP body=%7dB %s' % (flag, label, bs, err), flush=True)
    return flag


def _probe_go_supports_xproto(go_bin, work):
    """检测 Go 基线是否支持各新协议: 逐 proto 喂一份最简 server 配置, Popen 启动 2.5s
    后看进程是否仍在跑 + stdout 是否含 'Failed to start'. 返回 dict[proto] = bool.
    依赖全局 CERT/KEY/PIN 已 setup (main() 在调本函数前已 gen_cert)."""
    supported = {}
    if not (go_bin and os.path.isfile(go_bin)):
        return {p: False for p in EXTRA_PROTOS}
    if not (CERT and KEY and os.path.isfile(CERT)):
        return {p: False for p in EXTRA_PROTOS}
    for proto in EXTRA_PROTOS:
        try:
            P = 17000 + EXTRA_PROTOS.index(proto) * 4
            si, _co = build_x(proto, P)
            scfg = {"log": {"loglevel": "warning"}, "inbounds": [si],
                    "outbounds": [{"protocol": "freedom",
                                   "settings": {"finalRules": [{"action": "allow"}]}}]}
            cfgp = os.path.join(work, '_probe_%s.json' % proto)
            open(cfgp, 'w').write(json.dumps(scfg))
            # 用 Popen + 短暂 sleep + 探测, 避免 subprocess.run 在 server 持续运行时超时
            p = subprocess.Popen([go_bin, 'run', '-c', cfgp],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            time.sleep(2.0)
            alive = (p.poll() is None)
            try:
                p.terminate()
                out, _ = p.communicate(timeout=2)
            except Exception:
                p.kill()
                out = ''
            ok = alive and 'Failed to start' not in out
            supported[proto] = ok
        except Exception:
            supported[proto] = False
    return supported


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description='跨平台互通矩阵: Rust<->Rust 12 测 + Go 双向 + 新协议'
                                '\n默认套件 rust,go,rust_to_go,extra = 18 现有 + 6 反向 + 3xN 新协议.'
                                '\n--suites 可缩减子集; --cross-protos 控制两个 Go 交叉方向协议列表.'
                                '\n（--go-protos 为 deprecated alias）')
    ap.add_argument('--rust', default=None, help='Rust 二进制路径 (默认探测 target/release/xray)')
    ap.add_argument('--go', default=None, help='Go 基线二进制路径 (官方 release 解包后的 xray)')
    ap.add_argument('--work', default=os.path.join(root, 'target', 'interop_ci'), help='工作目录')
    ap.add_argument('--suites', default='rust,go,rust_to_go,extra',
                    help='rust,go,rust_to_go,extra 子集; extra 默认开含新协议套件')
    ap.add_argument('--cross-protos', default=','.join(GO_CROSS_PROTOS),
                    help='Go 交叉协议列表 (同时控制 Go->Rust 与 Rust->Go 两个方向)')
    ap.add_argument('--go-protos', default=None,
                    help='deprecated alias for --cross-protos (兼容旧 CI 调用)')
    ap.add_argument('--extra-protos', default=','.join(EXTRA_PROTOS),
                    help='新协议套件协议列表 (默认 splithttp,grpc,reality,hysteria2,anytls,tuic,naive)')
    ap.add_argument('--dry-run', action='store_true', help='只生成证书与配置, 不起进程')
    args = ap.parse_args()
    # 兼容旧 flag: --go-protos 覆盖 --cross-protos
    if args.go_protos is not None:
        args.cross_protos = args.go_protos

    work = os.path.abspath(args.work)
    os.makedirs(work, exist_ok=True)
    global CERT, KEY, PIN
    CERT = os.path.join(work, 'interop_cert.pem')
    KEY = os.path.join(work, 'interop_key.pem')
    try:
        gen_cert(CERT, KEY)
        PIN = pin_of(CERT)
    except (RuntimeError, OSError) as e:
        print('!! 证书生成失败 (%s), TLS 用例将失败' % e, flush=True)
        PIN = 'unavailable'

    rust = args.rust or probe_rust(root)
    go = args.go or probe_go(root)
    if ('rust' in args.suites.split(',') or 'rust_to_go' in args.suites.split(',')
            or 'extra' in args.suites.split(',')) and not (rust and os.path.isfile(rust)):
        sys.exit('!! 未找到 Rust 二进制: %s (先 cargo build --release --bin xray 或 --rust 指定)' % rust)
    if rust:
        rust = os.path.abspath(rust)
    if go:
        go = os.path.abspath(go)

    suites = args.suites.split(',')
    cross_protos = [p for p in args.cross_protos.split(',') if p]
    extra_protos = [p for p in args.extra_protos.split(',') if p]
    plan = []  # (tag, proto, server_bin, client_bin, is_xproto)
    if 'rust' in suites:
        for rnd in (1, 2):  # 同配双轮: 6x2=12, 兼作真机 flake 检测
            for p in PROTOS:
                plan.append(('Rust/Rust r%d' % rnd, p, rust, rust, False))
    if 'go' in suites:
        if go and os.path.isfile(go):
            for p in cross_protos:
                plan.append(('Go/Rust', p, rust, go, False))  # server=Rust, client=Go
        else:
            print('!! 跳过 Go 交叉: 未找到 Go 基线 (--go)', flush=True)
    # 阶段 1 补盲区：Rust 客户端连 Go 服务端反向 (26zn 战役暴露)
    if 'rust_to_go' in suites:
        if go and os.path.isfile(go):
            for p in RUST_TO_GO_PROTOS:
                plan.append(('Rust/Go', p, go, rust, False))  # server=Go, client=Rust
        else:
            print('!! 跳过 Rust->Go 反向: 未找到 Go 基线 (--go)', flush=True)
    # 阶段 2 新协议套件：每协议 3 测 (Rust<->Rust + Go->Rust + Rust->Go)
    if 'extra' in suites:
        go_ok = go and os.path.isfile(go)
        go_supports = {}
        if go_ok:
            # 探测每协议是否被 Go 基线支持; 失败时仅 Rust<->Rust, cross 方向静默跳过
            go_supports = _probe_go_supports_xproto(go, work)
            skipped = [p for p, ok in go_supports.items() if not ok]
            if skipped:
                print('!! Go 不支持新协议 (cross 方向跳过, Rust<->Rust 保留): %s' % skipped, flush=True)
        for xp in extra_protos:
            plan.append(('%s/Rust' % xp, xp, rust, rust, True))  # Rust<->Rust
            if go_ok and go_supports.get(xp, False):
                plan.append(('Go/Rust %s' % xp, xp, rust, go, True))  # Go->Rust
                plan.append(('Rust/Go %s' % xp, xp, go, rust, True))  # Rust->Go

    print('== 互通 CI: rust=%s go=%s work=%s dry=%s suites=%s ==' % (
        rust, go, work, args.dry_run, args.suites), flush=True)
    results = []
    for i, (tag, proto, srv, cli, is_x) in enumerate(plan):
        runner = run_x_one if is_x else run_one
        results.append(runner(i + 1, proto, srv, cli, tag, work, dry=args.dry_run))
    if args.dry_run:
        print('\n=== 干跑 %d 用例, 配置与证书已生成 %s ===' % (len(results), work))
        return
    ok = results.count('PASS')
    print('\n=== 互通 CI: %d/%d PASS ===' % (ok, len(results)), flush=True)
    sys.exit(0 if ok == len(results) else 1)


if __name__ == '__main__':
    main()
