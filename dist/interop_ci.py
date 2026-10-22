#!/usr/bin/env python3
"""CI 互通测试 (跨平台): dist/interop_matrix.py 的 POSIX 移植, 本地脚本零改动.

- suite rust:        Rust client<->Rust server, 6 协议 x 2 轮 = 12 测
- suite go:          Go client -> Rust server (官方 xray-core release 二进制), 默认 12 协议
- suite rust_to_go:  Rust client -> Go server 反向 (26zn 战役暴露盲区补缺), 默认 12 协议
- suite extra:       新协议 (splithttp/grpc/reality + hysteria2/anytls/tuic/naive),
                     每协议 3 方向 (Rust<->Rust + Go->Rust + Rust->Go) = 3N 测;
                     Go 基线不支持的 proto 自动跳过 cross 方向, 仅 Rust<->Rust 保留.

默认套件 = rust + go + rust_to_go + extra = 12+12+12+21 = 57 测 (Go 26.9.9 全支持口径;
干跑按满矩阵列清单, 实跑由 runtime 探测门控自动跳过 Go 不支持的方向)
(local 26.7.28 Go: hysteria2/anytls/tuic/naive 不支持, 实跑自动跳过相应 cross 方向)
TLS 双向统一 pinnedPeerCertSha256 (bd 5x41: allowInsecure 配置期硬错), 证书由 openssl 现场生成.
REALITY 配置需 Python `cryptography` 包 (X25519 keypair); CI workflow 已装.

用法: python3 dist/interop_ci.py [--rust PATH] [--go PATH] [--work DIR]
           [--suites rust,go,rust_to_go,extra] [--cross-protos <list>]
           [--extra-protos <list>] [--upstream URL|local] [--dry-run]
--go-protos 是 --cross-protos 的 deprecated alias (兼容旧 CI 调用).

--upstream: 每条用例环回验收 curl 的目标, 默认 https://www.youtube.com/ (CI 可达).
  --upstream local = 脚本内起一个 1KB HTTP echo server 并指向它, 验收链路 hermetic
  (流量仍穿被测隧道, 只是不依赖外网); 受审查网络/离线环境的唯一可跑形态.
  其它 URL = 换真上游, 此时不校验固定标记, 只校验 body 体积.
教训: 整套用例"均匀全超时"先查上游可达性 (本机曾 43/43 皆因 youtube 不可达),
  不是协议回归 —— 判别法: 换 --upstream local 后转绿即上游问题.
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
# 交叉套件新协议段：与 extra 套件共用 build_x/run_x_one（配置已随 extra 的 cross
# 方向在 CI 双平台验证）。naive 不加（bd 88vp: Rust 无 naive inbound）。
CROSS_X_PROTOS = ['splithttp', 'grpc', 'reality', 'hysteria2', 'anytls', 'tuic']
# Go 交叉：Go->Rust 校验（6 基础 + 6 新协议 = 12）。vless_vision_tls 曾因 rustls 贪婪
# recv 合流裸尾致 Linux 确定性挂（bd jeu9），RecordFramer 记录对齐读修复后 VPS 连续
# 5 次 PASS（2026-09-20）恢复进默认列表；--cross-protos <list> 仍可缩减。
GO_CROSS_PROTOS = PROTOS + CROSS_X_PROTOS
# Rust 客户端连 Go 服务端反向：补 26zn 战役暴露盲区（只测了 Rust→Rust 与 Go→Rust，
# 缺 Rust→Go 方向验证）。基础 6 协议复用 build()，新协议段复用 build_x()。
RUST_TO_GO_PROTOS = PROTOS + CROSS_X_PROTOS
# 新协议套件：splithttp/grpc/reality 三件必交付，hysteria2/anytls/tuic/naive。
# naive 已加回（bd 88vp 收口：xray-transport-naive inbound 已实现——rustls TLS +
# h2 CONNECT + Basic auth + padding，naiveproxy 服务端语义；Go 基线无 naive，
# 实跑 runtime 探测自动跳过 cross 方向，仅 Rust<->Rust）。
# 每个 proto 各跑 Rust↔Rust + Go→Rust + Rust→Go 三方向 = 3 测。
EXTRA_PROTOS = ['splithttp', 'grpc', 'reality', 'hysteria2', 'anytls', 'tuic', 'naive']
BASE_PORT = 18100
IS_WIN = os.name == 'nt'
EXE = '.exe' if IS_WIN else ''

CERT = KEY = None
PIN = None  # leaf DER sha256, Go/Rust client 通用

# 验收上游配置. 默认 = youtube (CI 可达); --upstream 可换 URL 或 local (脚本内 echo).
# MARKER = None 表示不校验固定标记, 只校验 body 体积.
UPSTREAM_URL = 'https://www.youtube.com/'
UPSTREAM_MARKER = b'YouTube'
UPSTREAM_MIN_BODY = 5000

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


def _pem(path):
    with open(path) as f:
        return f.read()

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
                      # ponytail: randomizednoalpn 的随机曲线池不含 X25519MLKEM768，
                      # 必撞 Rust 服务端 2ktp① 门（NoKeyShareX25519，Go 服务端同样
                      # 拒）——测例组合本身无效；chrome 指纹含 MLKEM768+X25519。
                      "fingerprint": "chrome"}}
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
        # 独立协议 inbound (xray-core "hysteria" arm: parse_hysteria_inbound_config
        # 消费 version/auth/cert/key PEM 内容); QUIC/UDP 端口, run_x_one 走 udp 探测.
        si = {"port": P, "listen": "127.0.0.1", "protocol": "hysteria",
              "settings": {"version": 2, "auth": auth_pw,
                           "cert": _pem(CERT), "key": _pem(KEY)}}
        # 客户端独立 hysteria outbound,
        # settings JSON 对齐 parse_hysteria_config (outbound.rs:2353): {version, servers[]}.
        # 2026-10-20 起 dialer 对齐 Go dialer.go:327-330：无 security=tls 硬错拒启，
        # 测例补 streamSettings（自签证书显式 insecure 信任，Go 语义同款门）。
        co = {"protocol": "hysteria",
              "settings": {"version": 2,
                           "servers": [{"address": "127.0.0.1", "port": P,
                                        "auth": auth_pw, "serverName": "localhost"}]},
              "streamSettings": {"network": "hysteria", "security": "tls",
                                 "hysteriaSettings": {"version": 2},
                                 "tlsSettings": {"serverName": "localhost", "insecure": True}}}
    elif proto == 'anytls':
        # anytls 协议对 dest 行为: 透明代理 (类似 vision); 用本地 echo 当 dest.
        auth_pw = 'anytls-secret'
        # 独立协议 inbound (xray-core "anytls" arm: parse_anytls_tls_acceptor
        # 消费 cert/key PEM 内容 + password).
        si = {"port": P, "listen": "127.0.0.1", "protocol": "anytls",
              "settings": {"cert": _pem(CERT), "key": _pem(KEY),
                           "password": auth_pw}}
        # 客户端独立 anytls outbound,
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
        # network 不写 "tuic"：tuic 是**协议**不是传输名（Go/Rust 的 transport
        # 白名单里都没有它）；配置期未知网络名会硬错（lfrg ⑤），此前靠"静默接受"
        # 才漏过。tuic 出站只读 streamSettings.tlsSettings（outbound.rs:941），
        # 传输层由协议自身 QUIC 承担。
        ss_cli = {"security": "tls",
                  "tuicSettings": {"users": [{"uuid": uuid, "password": _tuic_pw}],
                                   "server": "127.0.0.1", "server_port": P,
                                   "congestion_control": "cubic"},
                  "tlsSettings": {"serverName": "localhost", **tls_cli()}}
        # 独立协议 inbound (xray-core "tuic" arm): settings 顶层 uuid/password +
        # certificate/certificateKey PEM 内容 (parse_tuic_inbound_settings;
        # 缺省则 rcgen 自签, 与客户端 pin 不符). QUIC/UDP 端口, run_x_one 走 udp 探测.
        si = {"port": P, "listen": "127.0.0.1", "protocol": "tuic",
              "settings": {"uuid": uuid, "password": _tuic_pw,
                           "certificate": _pem(CERT), "certificateKey": _pem(KEY)}}
        co = {"protocol": "tuic", "settings": {"servers": [
            {"address": "127.0.0.1", "port": P, "uuid": uuid, "password": _tuic_pw,
             "congestion_control": "cubic"}]},
              "streamSettings": ss_cli}
    elif proto == 'naive':
        # naive = HTTPS2 CONNECT 前置代理 (naiveproxy 语义). 独立协议 inbound
        # 形态 (sing-box naive server 惯例: users name/pass + TLS); Rust 暂无
        # naive inbound (xray-transport-naive outbound-only), Rust<->Rust 用例
        # 会因 server 端 not-yet-supported skip 而失败——形态先就位, 立项后即跑.
        si = {"port": P, "listen": "127.0.0.1", "protocol": "naive",
              "settings": {"users": [{"name": "user", "pass": "pass"}]},
              "streamSettings": {"network": "tcp", "security": "tls",
                                 "tlsSettings": tls_srv()}}
        # 客户端独立 naive outbound,
        # settings JSON 对齐 parse_naive_config (outbound.rs:2284 → NaiveConfig::
        # from_json): 顶层 server/port/sni/username/password/fingerprint + 证书
        # pin (NaiveConfig 消费 pinnedPeerCertSha256, 服务端 openssl 自签证书).
        co = {"protocol": "naive",
              "settings": {"server": "127.0.0.1", "port": P,
                           "sni": "localhost", "username": "user",
                           "password": "pass", "fingerprint": "chrome",
                           "pinnedPeerCertSha256": PIN}}
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


def wait_port(port, deadline_s, udp=False):
    """TCP: connect 探测. UDP (QUIC 系协议 hysteria/tuic): bind 同端口探测——
    bind 失败 (EADDRINUSE) = 端口已被 server 占用; TCP connect 对 UDP 端口恒失败."""
    end = time.time() + deadline_s
    while time.time() < end:
        if udp:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.bind(('127.0.0.1', port))
            except OSError:
                return True  # 已被占用 = 有监听者
            finally:
                s.close()
        else:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=1):
                    return True
            except OSError:
                pass
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


def body_verdict(bp):
    """验收判据: body 体积超阈值, 有标记时还须真含标记 (排除错误页/拦截页).
    返回 (体积, 是否 PASS)."""
    bs = os.path.getsize(bp) if os.path.exists(bp) else 0
    body = open(bp, 'rb').read(200000) if bs else b''
    ok = bs > UPSTREAM_MIN_BODY and (UPSTREAM_MARKER is None or UPSTREAM_MARKER in body)
    return bs, ok


def start_local_upstream():
    """--upstream local: 起脚本内 HTTP echo (固定 1KB body, 含标记) 并把它设为验收上游.
    端口由内核选空闲口; 流量仍穿被测隧道 (server 侧 freedom 回拨 127.0.0.1), 仅去掉外网依赖.
    返回 server 供收尾 shutdown."""
    import http.server
    import threading

    # shortcut: 单进程单连接串行 HTTP/1.0 够了 (验收只管"有没有真实 body 过隧道"),
    # 要并发/keep-alive 压测时换 ThreadingHTTPServer.
    body = b'XRAY-ECHO-OK\n' + b'x' * (1024 - 13)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *a):
            pass

    srv = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    global UPSTREAM_URL, UPSTREAM_MARKER, UPSTREAM_MIN_BODY
    UPSTREAM_URL = 'http://127.0.0.1:%d/' % srv.server_address[1]
    UPSTREAM_MARKER = b'XRAY-ECHO-OK'
    UPSTREAM_MIN_BODY = 1000  # body 恰 1KB, 阈值留余量
    return srv


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
                if os.path.exists(bp):
                    os.remove(bp)  # 残留 body: curl 失败不截断, 上一轮结果会被当本轮
                try:
                    r = subprocess.run(['curl', '-sS', '--max-time', '15', '-x', 'socks5h://127.0.0.1:%d' % S,
                                        UPSTREAM_URL, '-o', bp, '-w', 'HTTP:%{http_code}'],
                                       capture_output=True, text=True, timeout=20)
                    bs, ok_body = body_verdict(bp)
                    flag = 'PASS' if ok_body else 'FAIL'
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
    """本地 TLS echo (真证书握手 + 回写应用数据). REALITY dest 必盲区: 不能指回
    vless 端口; 且 Go REALITY 服务端握手依赖 dest 返回合法 ServerHello
    (reality tls.go:357 MirrorConn.Read 镜像客户端字节给 dest)——裸 TCP echo
    会把 ClientHello 原样回显, Go 服务端校验 s2cSaved[5]!=ServerHello 后把回显
    转发给客户端, BoringSSL 报 UNEXPECTED_MESSAGE (bd civv #33 根因).
    Rust REALITY 服务端不依赖 dest, TLS 包装对其无影响. 跨平台."""
    import threading
    import ssl as _ssl

    def loop():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('127.0.0.1', port))
        srv.listen(64)
        srv.settimeout(30)
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = _ssl.TLSVersion.TLSv1_3
        # Go REALITY 服务端对认证连接逐记录模仿 dest 的握手记录大小（reality conn.go
        # "mimic recorded handshakeLen"），服务端自造 EncryptedExtensions 记录 32B
        # （server_name ack + GCM tag），dest 的 EE 记录小于它时 padding<0 直接断链
        # （payload[0]: 8, padding: -4 → 客户端 SYSCALL(5) unexpected EOF）。Windows
        # 本机 Python 的 OpenSSL EE 恰好比该预算小 4B（CI ubuntu/macos 更大，故只在
        # Windows 复现；Go/Go 同样挂，非 Rust 客户端问题）。协商 ALPN 让 EE 增
        # 9-13B 过预算；chrome 指纹客户端（btls/uTLS）均提供 h2/http1.1。
        ctx.set_alpn_protocols(['h2', 'http/1.1'])
        ctx.load_cert_chain(CERT, KEY)
        while True:
            try:
                cli, _ = srv.accept()
            except (socket.timeout, OSError):
                break
            threading.Thread(target=lambda c: _echo_serve(ctx, c), args=(cli,), daemon=True).start()

    def _echo_serve(ctx, c):
        try:
            c.settimeout(20)
            try:
                tls = ctx.wrap_socket(c, server_side=True)
            except (_ssl.SSLError, OSError):
                return
            while True:
                data = tls.recv(65536)
                if not data:
                    break
                tls.sendall(data)
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


def _probe_reality_dest_flight(port, timeout=3.0):
    """确定性回归 guard: Go REALITY 服务端对认证连接逐记录模仿 dest 的握手记录
    大小 (xtls/reality conn.go "mimic recorded handshakeLen"), 服务端自造
    EncryptedExtensions 记录 32B (server_name ack + 1B 内层 type + 16B GCM tag);
    dest 的 EE 记录 (SH+CCS 后首个 appdata 记录) 小于它时 padding<0 直接断链
    (show 日志 `payload[0]: 8, padding: -4`, 客户端 SYSCALL(5) unexpected EOF)。
    本地实测 echo 的 dest flight EE 大小, 不足 32B 即大声告警带修法——防
    echo/OpenSSL 环境漂移再次静默破坏 reality 用例 (2026-10-23 Windows 根因:
    Python 3.14/OpenSSL 3.5.7 的 EE 比预算小 4B, CI ubuntu/macos 更大不触发)."""
    raw = bytearray()
    import ssl as _ssl
    try:
        c_in, c_out = _ssl.MemoryBIO(), _ssl.MemoryBIO()
        cctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        cctx.minimum_version = _ssl.TLSVersion.TLSv1_3
        cctx.check_hostname = False
        cctx.verify_mode = _ssl.CERT_NONE
        cctx.set_alpn_protocols(['h2', 'http/1.1'])
        obj = cctx.wrap_bio(c_in, c_out, server_hostname='localhost')
        s = socket.create_connection(('127.0.0.1', port), timeout=timeout)
        try:
            s.settimeout(timeout)
            while True:
                try:
                    obj.do_handshake()
                    break
                except _ssl.SSLWantReadError:
                    pending = c_out.read()
                    if pending:
                        s.sendall(pending)
                    data = s.recv(16384)
                    if not data:
                        raise ConnectionError('dest closed during handshake')
                    c_in.write(data)
                    raw += data
                except _ssl.SSLWantWriteError:
                    pending = c_out.read()
                    if pending:
                        s.sendall(pending)
        finally:
            s.close()
    except (OSError, _ssl.SSLError, ConnectionError) as e:
        print('!! REALITY dest flight probe failed (echo 未起/握手失败): %r' % e, flush=True)
        return None
    off, ccs_seen, ee = 0, False, None
    while off + 5 <= len(raw):
        rtype = raw[off]
        rlen = int.from_bytes(raw[off + 3:off + 5], 'big')
        if rtype == 20:
            ccs_seen = True
        elif ccs_seen and rtype == 23 and ee is None:
            ee = 5 + rlen  # SH+CCS 后首个 appdata 包装记录 = EncryptedExtensions
            break
        off += 5 + rlen
    return ee


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
            ee = _probe_reality_dest_flight(P - 1)
            if ee is not None and ee < 32:
                print('!! REALITY dest flight EE=%dB < 32B mimicry budget: 认证 reality 握手'
                      '将失败 (padding<0); echo 需协商 ALPN 或加大 dest flight (见 _start_echo 注释)' % ee, flush=True)
        slog = open(os.path.join(work, 's%d.log' % idx), 'wb')
        ps = subprocess.Popen([server_bin, 'run', '-c', scp], stdout=slog,
                              stderr=subprocess.STDOUT, env=env)
        slog.close()
        procs.append(ps)
        # hysteria/tuic 是 QUIC/UDP-only 监听, TCP connect 探测恒假失败
        if not wait_port(P, 15, udp=proto in ('hysteria2', 'tuic')):
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
                if os.path.exists(bp):
                    os.remove(bp)  # 残留 body: curl 失败不截断, 上一轮结果会被当本轮
                try:
                    r = subprocess.run(['curl', '-sS', '--max-time', '15',
                                        '-x', 'socks5h://127.0.0.1:%d' % S,
                                        UPSTREAM_URL, '-o', bp, '-w',
                                        'HTTP:%{http_code}'],
                                       capture_output=True, text=True, timeout=20)
                    bs, ok_body = body_verdict(bp)
                    flag = 'PASS' if ok_body else 'FAIL'
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
    global CERT, KEY, PIN, UPSTREAM_URL, UPSTREAM_MARKER
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description='跨平台互通矩阵: Rust<->Rust 12 测 + Go 双向 + 新协议'
                                '\n默认套件 rust,go,rust_to_go,extra = 12+12+12+18 = 54 测 (Go 全支持口径).'
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
                    help='新协议套件协议列表 (默认 splithttp,grpc,reality,hysteria2,anytls,tuic)')
    ap.add_argument('--upstream', default=None,
                    help='环回验收 curl 的目标: URL 或 local (脚本内 1KB HTTP echo, 离线可跑);'
                         ' 默认 %s' % UPSTREAM_URL)
    ap.add_argument('--dry-run', action='store_true', help='只生成证书与配置, 不起进程')
    args = ap.parse_args()
    # 兼容旧 flag: --go-protos 覆盖 --cross-protos
    if args.go_protos is not None:
        args.cross_protos = args.go_protos

    work = os.path.abspath(args.work)
    os.makedirs(work, exist_ok=True)
    local_upstream = None
    if args.upstream == 'local':
        local_upstream = start_local_upstream()
        print('== 上游: local echo %s (hermetic, 不依赖外网) ==' % UPSTREAM_URL, flush=True)
    elif args.upstream:
        UPSTREAM_URL = args.upstream
        UPSTREAM_MARKER = None  # 自定义上游无固定标记, 只校验体积
        print('== 上游: %s ==' % UPSTREAM_URL, flush=True)
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
    go_ok = go and os.path.isfile(go)
    # Go 基线新协议支持探测: 交叉套件与 extra 套件共用一次结果; dry-run 不起进程,
    # 按全支持列满矩阵清单 (实跑由探测门控收敛).
    need_probe = go_ok and (
        ('extra' in suites)
        or (('go' in suites or 'rust_to_go' in suites)
            and any(p in EXTRA_PROTOS for p in cross_protos)))
    if args.dry_run:
        go_supports = {p: True for p in EXTRA_PROTOS}
    elif need_probe:
        go_supports = _probe_go_supports_xproto(go, work)
        skipped = [p for p, ok in go_supports.items() if not ok]
        if skipped:
            print('!! Go 不支持新协议 (相关 cross 方向跳过): %s' % skipped, flush=True)
    else:
        go_supports = {}
    plan = []  # (tag, proto, server_bin, client_bin, is_xproto)
    if 'rust' in suites:
        for rnd in (1, 2):  # 同配双轮: 6x2=12, 兼作真机 flake 检测
            for p in PROTOS:
                plan.append(('Rust/Rust r%d' % rnd, p, rust, rust, False))
    if 'go' in suites:
        if go_ok:
            for p in cross_protos:
                if p in EXTRA_PROTOS:
                    continue  # 新协议段统一追加在 plan 尾部 (既有序位/端口零改动)
                plan.append(('Go/Rust', p, rust, go, False))  # server=Rust, client=Go
        else:
            print('!! 跳过 Go 交叉: 未找到 Go 基线 (--go)', flush=True)
    # 阶段 1 补盲区：Rust 客户端连 Go 服务端反向 (26zn 战役暴露)
    if 'rust_to_go' in suites:
        if go_ok:
            for p in RUST_TO_GO_PROTOS:
                if p in EXTRA_PROTOS:
                    continue  # 同上, 尾部追加
                plan.append(('Rust/Go', p, go, rust, False))  # server=Go, client=Rust
        else:
            print('!! 跳过 Rust->Go 反向: 未找到 Go 基线 (--go)', flush=True)
    # 阶段 2 新协议套件：每协议 3 测 (Rust<->Rust + Go->Rust + Rust->Go)
    if 'extra' in suites:
        for xp in extra_protos:
            plan.append(('%s/Rust' % xp, xp, rust, rust, True))  # Rust<->Rust
            if go_ok and go_supports.get(xp, False):
                plan.append(('Go/Rust %s' % xp, xp, rust, go, True))  # Go->Rust
                plan.append(('Rust/Go %s' % xp, xp, go, rust, True))  # Rust->Go
    # 交叉套件新协议段 (每方向 6 基础 + 6 新 = 12): 走 build_x/run_x_one, 配置形态与
    # extra 套件 cross 方向一致 (CI 双平台已验证). Go 基线不支持则跳过 (同 extra 语义).
    if go_ok and ('go' in suites or 'rust_to_go' in suites):
        for p in CROSS_X_PROTOS:
            if not go_supports.get(p):
                continue
            if 'go' in suites and p in cross_protos:
                plan.append(('Go/Rust', p, rust, go, True))
            if 'rust_to_go' in suites and p in RUST_TO_GO_PROTOS:
                plan.append(('Rust/Go', p, go, rust, True))

    print('== 互通 CI: rust=%s go=%s work=%s dry=%s suites=%s ==' % (
        rust, go, work, args.dry_run, args.suites), flush=True)
    results = []
    try:
        for i, (tag, proto, srv, cli, is_x) in enumerate(plan):
            runner = run_x_one if is_x else run_one
            results.append(runner(i + 1, proto, srv, cli, tag, work, dry=args.dry_run))
    finally:
        if local_upstream:
            local_upstream.shutdown()
    if args.dry_run:
        print('\n=== 干跑 %d 用例, 配置与证书已生成 %s ===' % (len(results), work))
        return
    ok = results.count('PASS')
    print('\n=== 互通 CI: %d/%d PASS ===' % (ok, len(results)), flush=True)
    sys.exit(0 if ok == len(results) else 1)


if __name__ == '__main__':
    main()
