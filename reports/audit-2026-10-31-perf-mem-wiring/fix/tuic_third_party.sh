#!/bin/bash
# TUIC v5 UDP 第三方（sing-box）互通验收编排（bd j7de2 F3/F4）。
#
# 用法（Windows Git Bash）：
#   bash reports/audit-2026-10-31-perf-mem-wiring/fix/tuic_third_party.sh
#
# 流程：
#   1) WSL(ubuntu-xray) 内准备第三方对端：sing-box TUIC v5 入站 + UDP echo
#      - sing-box 二进制来源优先级：① 只读 scp 拷贝（/mnt/d/tmp/sing-box-tp，
#        来自 176.122.139.45:26617 的 /root/agsbx/sing-box，**只读拷贝**）
#        ② GitHub release 下载（v1.12.4 linux-amd64）
#      - 自签证书由 `sing-box generate tls-keypair` 生成（key+cert 同 stdout，按块拆分）
#      - ⚠ 该 sing-box 构建的 TUIC 入站**必须显式配 tls.alpn**（默认无 ALPN → 握手
#        报 no_application_protocol）
#   2) Windows 侧跑被忽略的互通用例（quic / native 两种模式）
#
# 环境变量（可选）：TUIC_TP_UUID / TUIC_TP_PASS / TUIC_TP_PORT / TUIC_TP_ECHO_PORT
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WSL_DIST="${TUIC_TP_WSL_DIST:-ubuntu-xray}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target-Wave7Tuic}"

UUID="${TUIC_TP_UUID:-11111111-2222-3333-4444-555555555555}"
PASS="${TUIC_TP_PASS:-third-party-pass}"
PORT="${TUIC_TP_PORT:-24443}"
ECHO_PORT="${TUIC_TP_ECHO_PORT:-24999}"

echo "== 1) WSL 内起第三方对端（sing-box TUIC v5 入站 + UDP echo）"
wsl -d "$WSL_DIST" -- bash -s -- "$UUID" "$PASS" "$PORT" "$ECHO_PORT" <<'WSLEOF'
set -u
DIR=/root/tp
UUID="$1"; PASS="$2"; PORT="$3"; ECHO_PORT="$4"
mkdir -p "$DIR/tls"

if [ ! -x "$DIR/sing-box" ]; then
  if [ -f /mnt/d/tmp/sing-box-tp ]; then
    echo "[setup] sing-box from scp copy (read-only)"
    cp /mnt/d/tmp/sing-box-tp "$DIR/sing-box"
  else
    echo "[setup] downloading sing-box 1.12.4 ..."
    curl -sL --max-time 600 -o "$DIR/sb.tgz" \
      "https://github.com/SagerNet/sing-box/releases/download/v1.12.4/sing-box-1.12.4-linux-amd64.tar.gz"
    tar xzf "$DIR/sb.tgz" -C "$DIR"
    cp "$DIR/sing-box-1.12.4-linux-amd64/sing-box" "$DIR/sing-box"
  fi
  chmod +x "$DIR/sing-box"
fi

if [ ! -f "$DIR/tls/cert.pem" ] || [ ! -f "$DIR/tls/key.pem" ]; then
  echo "[setup] generating self-signed keypair ..."
  ( cd "$DIR/tls" && "$DIR/sing-box" generate tls-keypair localhost > both.pem 2>/dev/null )
  python3 - <<'PY'
import re
raw = open('/root/tp/tls/both.pem').read()
def block(tag):
    m = re.search(r'-----BEGIN %s-----.*?-----END %s-----' % (tag, tag), raw, re.S)
    return m.group(0) + "\n" if m else ""
open('/root/tp/tls/key.pem', 'w').write(block('PRIVATE KEY'))
open('/root/tp/tls/cert.pem', 'w').write(block('CERTIFICATE'))
PY
fi

cat > "$DIR/config.json" <<JSON
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "0.0.0.0",
      "listen_port": ${PORT},
      "users": [ { "uuid": "${UUID}", "password": "${PASS}" } ],
      "tls": {
        "enabled": true,
        "server_name": "localhost",
        "certificate_path": "${DIR}/tls/cert.pem",
        "key_path": "${DIR}/tls/key.pem",
        "alpn": [ "tuic", "h3" ]
      }
    }
  ],
  "outbounds": [ { "type": "direct" } ]
}
JSON

cat > "$DIR/echo.py" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", port))
while True:
    data, peer = s.recvfrom(65535)
    s.sendto(data, peer)
PY

pkill -f "$DIR/sing-box run" 2>/dev/null || true
pkill -f "$DIR/echo.py" 2>/dev/null || true
sleep 0.4
setsid nohup "$DIR/sing-box" run -c "$DIR/config.json" > "$DIR/sing-box.log" 2>&1 < /dev/null &
setsid nohup python3 "$DIR/echo.py" "$ECHO_PORT" > "$DIR/echo.log" 2>&1 < /dev/null &
sleep 1.5
IP=$(hostname -I | awk '{print $1}')
echo "SINGBOX_ADDR=127.0.0.1:${PORT}"
echo "ECHO_ADDR=${IP}:${ECHO_PORT}"
echo "UUID=${UUID}"
echo "PASS=${PASS}"
WSLEOF

ADDR=$(wsl -d "$WSL_DIST" -- bash -lc "hostname -I | awk '{print \$1}'" | tr -d '\0')
ECHO_ADDR="${ADDR}:${ECHO_PORT}"
echo "== 2) Windows 侧跑互通用例（quic / native）"

export TUIC_TP_ADDR="127.0.0.1:${PORT}"
export TUIC_TP_UUID="$UUID"
export TUIC_TP_PASS="$PASS"
export TUIC_TP_ECHO="$ECHO_ADDR"
export TUIC_TP_ALPN="tuic,h3"
export CARGO_TARGET_DIR

for mode in quic native; do
  for size in 32 20000; do
    echo "---- mode=$mode size=$size"
    TUIC_TP_MODE="$mode" TUIC_TP_SIZE="$size" \
      cargo test -p xray-proxy-tuic --test third_party_udp -- --ignored --nocapture
  done
done

echo "== 3) 第三方侧日志"
wsl -d "$WSL_DIST" -- bash -lc "tail -20 /root/tp/sing-box.log" | tr -d '\0'
