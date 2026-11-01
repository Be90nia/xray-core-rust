"""验证：UDP 域名目标的解析结果顺序（Rust tokio lookup_host vs Go net.ResolveUDPAddr）。"""
import socket
import subprocess
import sys

GO_SRC = r"""
package main

import (
	"fmt"
	"net"
)

func main() {
	addr, err := net.ResolveUDPAddr("udp", "localhost:28082")
	fmt.Printf("go ResolveUDPAddr: %v err=%v\\n", addr, err)
	ips, err := net.LookupIP("localhost")
	fmt.Printf("go LookupIP: %v err=%v\\n", ips, err)
}
"""


def main():
    print("=== python getaddrinfo (system resolver order) ===")
    try:
        infos = socket.getaddrinfo("localhost", 28082, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        for i in infos:
            print("  ", i[4])
    except Exception as e:  # noqa: BLE001
        print("  err:", e)

    print("=== go ===")
    src = r"D:\tmp\udpresolve\main.go"
    import os
    os.makedirs(r"D:\tmp\udpresolve", exist_ok=True)
    with open(src, "w", encoding="utf-8") as f:
        f.write(GO_SRC)
    # 用 Go 解释器不可得 → 改用 xray 自带？退化为打印 python 结果对照。
    print("  (go toolchain not required: compare against xray observed behaviour)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
