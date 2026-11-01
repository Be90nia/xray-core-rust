"""Structured mutation fuzz for vless / ss(legacy AEAD) / vmess inbounds.

vless: valid 21-byte request prefix (version+uuid+addon0+cmd+port+atyp+ipv4) with random
       byte mutations + random tails -> exercises decode_request_header + command dispatch.
ss   : real AES-128-GCM wire (password-derived key, HKDF-SHA1 subkey) with a random
       plaintext header -> exercises the shadowsocks address parser with valid crypto.
vmess: random bytes with wire-like length fields -> exercises the AEAD header reader.

Watches the server log for Rust panics and re-checks the port after every batch.
Usage: python mutate_fuzz.py <log> <target> <iters>
"""
import os
import random
import socket
import sys
import threading

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hashlib

LOG = sys.argv[1]
TARGET = sys.argv[2]
ITERS = int(sys.argv[3]) if len(sys.argv) > 3 else 1000
HOST = "127.0.0.1"

PORTS = {"vless": 19103, "ss": 19106, "vmess": 19104, "socks": 19101, "http": 19102}
UUID = bytes.fromhex("11111111222233334444555555555555")
RNG = random.Random(0xC0FFEE)


def log_size():
    try:
        return os.path.getsize(LOG)
    except OSError:
        return 0


def read_log_from(pos):
    with open(LOG, "rb") as f:
        f.seek(pos)
        return f.read().decode("utf-8", "replace")


def port_open(port):
    try:
        s = socket.create_connection((HOST, port), timeout=1)
        s.close()
        return True
    except OSError:
        return False


def ss_key(password: bytes, size: int = 16) -> bytes:
    key = b""
    md5 = hashlib.md5(password).digest()
    key += md5
    while len(key) < size:
        md5 = hashlib.md5(md5 + password).digest()
        key += md5
    return key[:size]


def ss_frame(key: bytes, plaintext: bytes) -> bytes:
    salt = bytes(RNG.getrandbits(8) for _ in range(16))
    subkey = HKDF(algorithm=hashes.SHA1(), length=16, salt=salt, info=b"ss-subkey").derive(key)
    gcm = AESGCM(subkey)
    nonce = bytearray(12)

    def next_nonce():
        n = bytes(nonce)
        for i in range(12):
            nonce[i] = (nonce[i] + 1) & 0xFF
            if nonce[i]:
                break
        return n

    out = bytearray(salt)
    ln = len(plaintext).to_bytes(2, "big")
    out += gcm.encrypt(next_nonce(), ln, None)
    if plaintext:
        out += gcm.encrypt(next_nonce(), plaintext, None)
    return bytes(out)


VLESS_VALID = b"\x00" + UUID + b"\x00" + b"\x01" + b"\x00\x50" + b"\x01\x7f\x00\x00\x01"


def gen_vless():
    b = bytearray(VLESS_VALID)
    mode = RNG.randrange(4)
    if mode == 0:
        # random mutations
        for _ in range(RNG.randrange(1, 6)):
            b[RNG.randrange(len(b))] = RNG.getrandbits(8)
    elif mode == 1:
        b = b[: RNG.randrange(1, len(b) + 1)]
    elif mode == 2:
        b += bytes(RNG.getrandbits(8) for _ in range(RNG.randrange(0, 40)))
    else:
        # addon length lie
        b[17] = RNG.getrandbits(8)
        b += bytes(RNG.getrandbits(8) for _ in range(RNG.randrange(0, 300)))
    return bytes(b)


def gen_ss():
    n = RNG.randrange(0, 40)
    pl = bytes(RNG.getrandbits(8) for _ in range(n))
    if RNG.randrange(3) == 0 and n:
        pl = b"\x03" + bytes([RNG.getrandbits(8)]) + pl[2:]   # force domain atyp
    return ss_frame(ss_key(b"fuzzpass12345678"), pl)


def gen_vmess():
    style = RNG.randrange(3)
    if style == 0:
        return bytes(RNG.getrandbits(8) for _ in range(RNG.randrange(1, 80)))
    if style == 1:
        b = bytearray(b"\x01" + bytes(RNG.getrandbits(8) for _ in range(16)))
        b += RNG.choice([b"\xff\xff\xff\xff", b"\x00\x00\x00\x00", b"\x00\x00\x10\x00"])
        return bytes(b)
    return b"\x01" + bytes(RNG.getrandbits(8) for _ in range(RNG.randrange(0, 60)))


GENS = {"vless": gen_vless, "ss": gen_ss, "vmess": gen_vmess}


def main():
    port = PORTS[TARGET]
    gen = GENS[TARGET]
    pos = log_size()
    failures = 0
    panics = 0
    for batch in range(ITERS // 100):
        socks = []
        for _ in range(100):
            payload = gen()
            try:
                s = socket.create_connection((HOST, port), timeout=2)
                s.sendall(payload)
                if RNG.randrange(2):
                    s.shutdown(socket.SHUT_WR)
                s.setblocking(False)
                socks.append(s)
            except OSError:
                failures += 1
        # drain a little then close
        for s in socks:
            try:
                s.recv(64)
            except OSError:
                pass
            s.close()
        new = read_log_from(pos)
        pos = log_size()
        if "panicked" in new.lower():
            panics += 1
            print("=== PANIC ===")
            print(new[-3000:])
        if not port_open(port):
            print(f"!! inbound {TARGET} no longer accepting after batch {batch}")
            print(new[-2000:])
            break
    print(f"{TARGET}: iters={ITERS} connect_failures={failures} panic_batches={panics} "
          f"port_open={port_open(port)}")


if __name__ == "__main__":
    main()
