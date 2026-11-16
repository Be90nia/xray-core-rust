#!/usr/bin/env bash
# Linux TUN 设备生命周期探针（CI / 真机通用，需 root）
# 背景：bd fy8i0 —— TUN arm 把 handler move 进 tokio::spawn 的 future，start() 返回即
# future 结束 ⇒ handler drop ⇒ 设备 fd 关闭 ⇒ 非持久 tun 接口被内核删除 ⇒ 网卡静默消失
# （Windows 上是 wintun adapter 被删；Linux 上是 /dev/net/tun fd 关闭后内核删接口）。
# 本探针断言：TUN 设备在进程存活期内**持续存在**（默认 60s），且进程不退出。
# 用法：
#   sudo bash tools/linux_tun_lifetime.sh [xray_bin] [hold_seconds]
# 输出末行："TUN_LIFETIME_RESULT: PASS" / "TUN_LIFETIME_RESULT: FAIL"（供 CI grep）
set -u

BIN="${1:-target/release/xray}"
HOLD="${2:-60}"
NAME="tunlife$$"
CFG="$(mktemp /tmp/tunlife.XXXXXX.json)"
LOG="$(mktemp /tmp/tunlife.XXXXXX.log)"
RES="FAIL"

cleanup() {
  [ -n "${XPID:-}" ] && kill "$XPID" 2>/dev/null
  ip link del "$NAME" 2>/dev/null
  rm -f "$CFG" "$LOG"
}
trap cleanup EXIT

cat > "$CFG" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "socks", "port": 10899, "listen": "127.0.0.1", "protocol": "socks", "settings": { "udp": true } },
    {
      "tag": "tun-in",
      "protocol": "tun",
      "settings": { "name": "$NAME", "mtu": 1500, "gateway": ["10.211.7.1/24"], "dns": ["1.1.1.1"] }
    }
  ],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
}
EOF

"$BIN" run -c "$CFG" > "$LOG" 2>&1 &
XPID=$!

# 阶段 1：高频抓设备出现（窗口可能只有几十毫秒）
APPEARED=0
START=$(date +%s.%N)
for _ in $(seq 1 200); do
  if ip -o link show "$NAME" >/dev/null 2>&1; then
    T=$(awk "BEGIN{printf \"%.3f\", $(date +%s.%N)-$START}")
    echo "device appeared at t=${T}s"
    APPEARED=1
    break
  fi
  kill -0 "$XPID" 2>/dev/null || break
  sleep 0.02
done

if [ "$APPEARED" != "1" ]; then
  echo "device never appeared (process alive=$(kill -0 "$XPID" 2>/dev/null && echo yes || echo no))"
  tail -20 "$LOG"
  RES="FAIL"
else
  # 阶段 2：持续存活断言
  for i in $(seq 1 "$HOLD"); do
    sleep 1
    if ! kill -0 "$XPID" 2>/dev/null; then
      echo "process exited at t=${i}s"
      RES="FAIL"
      break
    fi
    if ! ip -o link show "$NAME" >/dev/null 2>&1; then
      echo "device disappeared at t=${i}s (process still alive) -> fy8i0 regression"
      RES="FAIL"
      break
    fi
  done
  [ "$RES" = "FAIL" ] || { echo "device survived ${HOLD}s"; RES="PASS"; }
fi

tail -20 "$LOG"
echo "TUN_LIFETIME_RESULT: $RES"
exit $([ "$RES" = "PASS" ] && echo 0 || echo 1)
