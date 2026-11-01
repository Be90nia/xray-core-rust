"""诊断 dokodemo-door UDP 转发：抓两侧日志。"""
import socket
import sys
import time

from mocksrv import PORTS, Instance, UdpEcho, wait_port


def cfg(port, dst_port, network="udp"):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "dok-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": dst_port,
                                   "network": network}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }


def main():
    echo = UdpEcho(PORTS["echo"])
    echo.start()
    for side in ("go", "rust"):
        port = PORTS[f"{side}_dok"]
        inst = Instance(side, "dokdiag", cfg(port, PORTS["echo"])).start()
        time.sleep(2.0)
        print(f"--- {side} startup logs ---")
        for l in inst.drain(1.5):
            print("   ", l[:250])
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(2.0)
        u.sendto(b"diag-payload", ("127.0.0.1", port))
        try:
            data, _ = u.recvfrom(65535)
            print(f"   reply: {data!r}")
        except Exception as e:  # noqa: BLE001
            print(f"   reply error: {e}")
        time.sleep(1.0)
        print(f"--- {side} after-send logs ---")
        for l in inst.drain(1.0):
            print("   ", l[:250])
        print(f"   echo.seen={echo.seen}")
        u.close()
        inst.stop()
    echo.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
