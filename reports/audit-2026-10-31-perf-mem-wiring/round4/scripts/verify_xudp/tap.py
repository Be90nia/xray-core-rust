"""TCP tap：抓 Go 客户端 → Rust 服务端 的真实 wire 字节（对比 Go→Go）。

目的：判定 Go 默认 cone 模式下 UDP-over-VLESS 的真实 wire 格式
（Mux carrier + XUDP 帧 vs 长度前缀裸载荷），定位 Rust 服务端为何解不出。

用法：tap 监听 LPORT → 转发到 TARGETPORT，同时把 c2s/s2c 双向字节落盘。
"""
import socket
import struct
import sys
import threading
import time


def pump(src, dst, sink, tag):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            sink.write(f"{tag} {len(data)} ".encode())
            sink.write(data.hex().encode())
            sink.write(b"\n")
            sink.flush()
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main():
    lport = int(sys.argv[1])
    tport = int(sys.argv[2])
    out = sys.argv[3]
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", lport))
    srv.listen(8)
    print(f"tap {lport} -> {tport}", flush=True)
    with open(out, "wb") as sink:
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                break
            t = socket.create_connection(("127.0.0.1", tport))
            threading.Thread(target=pump, args=(c, t, sink, "C2S"), daemon=True).start()
            threading.Thread(target=pump, args=(t, c, sink, "S2C"), daemon=True).start()
            time.sleep(0.05)


if __name__ == "__main__":
    main()
