#!/bin/bash
# xhttp_tcpnotls.sh —— no-TLS 隔离 xhttp 饿死层
# 用途: TLS 关闭后若饿死消失 = 饿死在 TLS/H2 层（握手/缓冲/帧），否则在裸 TCP
#       （88m0 收窗钉死族）—— 隔离判别
# 用法: xhttp_tcpnotls.sh <server_ip> <xhttp_port> [flows] [duration_sec]
# 缺省: 8 流 / 90s
set -euo pipefail
HOST="${1:?usage: $0 <server_ip> <xhttp_port> [flows] [duration_sec]}"
PORT="${2:?usage: $0 <server_ip> <xhttp_port> [flows] [duration_sec]}"
FLOWS="${3:-8}"
DUR="${4:-90}"
OUT="${XHTTP_NOTLS_OUT:-/tmp/xhttp-tcpnotls-$(date +%s)}"
mkdir -p "$OUT"
LOG="$OUT/notls.log"
echo "xhttp_tcpnotls: host=$HOST port=$PORT flows=$FLOWS dur=${DUR}s out=$OUT"

# 探测: 先 GET 一次（no-TLS = http://，依赖 xhttp 入站 security:none）
URL="http://$HOST:$PORT/xhttp"
SIZE=10485760  # 10MB
echo "url=$URL size=$SIZE" > "$LOG"
for i in $(seq 1 "$FLOWS"); do
  (
    # curl --no-buffer 输出即时；-w 输出 wall/speed/exit
    start=$(date +%s.%N)
    curl -sS --no-buffer --max-time "$DUR" \
      -o "$OUT/body-$i.bin" \
      -w "flow=$i http=%{http_code} time=%{time_total}s size=%{size_download} speed=%{speed_download}\n" \
      "$URL?sid=notls-$i" 2>"$OUT/err-$i.log" \
      | tee -a "$LOG"
    end=$(date +%s.%N)
    echo "flow=$i wall=$(echo "$end - $start" | bc)s" >> "$LOG"
  ) &
done
wait

# 摘要: 各流吞吐
echo "=== 各流吞吐 ==="
column -t -s $'\t' "$LOG" 2>/dev/null || cat "$LOG"
echo "raw: $OUT"
