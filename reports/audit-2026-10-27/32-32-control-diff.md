# 32/32 对照组 diff（Rust vs Go，同节点表 / 同判据）

- Rust: **72/93 PASS**
- Go  : **64/93 PASS**
- 仅 Rust 失败（候选回归）: **0**
- 两边都失败（节点侧）: **21**
- 仅 Go 失败（Rust 更强）: **8**

## 两边都失败（节点侧问题，非代码回归）

| # | 协议 | 传输 | Rust | Go |
|---|---|---|---|---|
| 4 | shadowsocks | none/ws | FAIL | FAIL |
| 6 | trojan | reality/raw | FAIL | FAIL |
| 8 | vless | reality/raw | FAIL | FAIL |
| 13 | shadowsocks | none/tcp | FAIL | FAIL |
| 16 | vless | tls/raw | FAIL | FAIL |
| 21 | shadowsocks | none/ws | FAIL | FAIL |
| 24 | vless | reality/raw | FAIL | FAIL |
| 26 | trojan | reality/raw | FAIL | FAIL |
| 27 | trojan | reality/raw | FAIL | FAIL |
| 41 | vless | tls/raw | FAIL | FAIL |
| 49 | vless | tls/raw | FAIL | FAIL |
| 50 | shadowsocks | none/ws | FAIL | FAIL |
| 53 | vless | reality/raw | FAIL | FAIL |
| 73 | vless | reality/raw | FAIL | FAIL |
| 74 | vless | reality/raw | FAIL | FAIL |
| 81 | shadowsocks | none/ws | FAIL | FAIL |
| 83 | vless | reality/raw | FAIL | FAIL |
| 84 | shadowsocks | none/tcp | FAIL | FAIL |
| 85 | shadowsocks | none/tcp | FAIL | FAIL |
| 90 | shadowsocks | none/ws | FAIL | FAIL |
| 92 | shadowsocks | none/ws | FAIL | FAIL |

## 仅 Go 失败（Rust 通过）

- #3 vless tls/xhttp: Go=FAIL
- #14 trojan tls/httpupgrade: Go=FAIL
- #22 tuic none/tcp: Go=FAIL
- #23 anytls none/tcp: Go=FAIL
- #34 tuic none/tcp: Go=FAIL
- #40 anytls none/tcp: Go=FAIL
- #68 anytls none/tcp: Go=FAIL
- #71 tuic none/tcp: Go=FAIL

## 全量对照

| # | 协议 | 传输 | Rust | Go |
|---|---|---|---|---|
| 1 | trojan | tls/ws | PASS | PASS |
| 2 | trojan | tls/ws | PASS | PASS |
| 3 | vless | tls/xhttp | PASS **≠** | FAIL |
| 4 | shadowsocks | none/ws | FAIL | FAIL |
| 5 | vless | tls/httpupgrade | PASS | PASS |
| 6 | trojan | reality/raw | FAIL | FAIL |
| 7 | trojan | tls/ws | PASS | PASS |
| 8 | vless | reality/raw | FAIL | FAIL |
| 9 | vmess | tls/httpupgrade | PASS | PASS |
| 10 | vless | tls/xhttp | PASS | PASS |
| 11 | vmess | tls/ws | PASS | PASS |
| 12 | vless | tls/ws | PASS | PASS |
| 13 | shadowsocks | none/tcp | FAIL | FAIL |
| 14 | trojan | tls/httpupgrade | PASS **≠** | FAIL |
| 15 | trojan | tls/raw | PASS | PASS |
| 16 | vless | tls/raw | FAIL | FAIL |
| 17 | vless | reality/xhttp | PASS | PASS |
| 18 | vless | reality/xhttp | PASS | PASS |
| 19 | vmess | tls/ws | PASS | PASS |
| 20 | vmess | tls/ws | PASS | PASS |
| 21 | shadowsocks | none/ws | FAIL | FAIL |
| 22 | tuic | none/tcp | PASS **≠** | FAIL |
| 23 | anytls | none/tcp | PASS **≠** | FAIL |
| 24 | vless | reality/raw | FAIL | FAIL |
| 25 | trojan | tls/raw | PASS | PASS |
| 26 | trojan | reality/raw | FAIL | FAIL |
| 27 | trojan | reality/raw | FAIL | FAIL |
| 28 | vmess | tls/httpupgrade | PASS | PASS |
| 29 | vless | tls/ws | PASS | PASS |
| 30 | vless | tls/xhttp | PASS | PASS |
| 31 | vmess | tls/xhttp | PASS | PASS |
| 32 | vless | tls/httpupgrade | PASS | PASS |
| 33 | trojan | tls/ws | PASS | PASS |
| 34 | tuic | none/tcp | PASS **≠** | FAIL |
| 35 | trojan | tls/xhttp | PASS | PASS |
| 36 | vless | tls/xhttp | PASS | PASS |
| 37 | vmess | tls/ws | PASS | PASS |
| 38 | vless | tls/ws | PASS | PASS |
| 39 | trojan | tls/xhttp | PASS | PASS |
| 40 | anytls | none/tcp | PASS **≠** | FAIL |
| 41 | vless | tls/raw | FAIL | FAIL |
| 42 | trojan | tls/httpupgrade | PASS | PASS |
| 43 | vless | tls/ws | PASS | PASS |
| 44 | vless | tls/httpupgrade | PASS | PASS |
| 45 | vless | tls/xhttp | PASS | PASS |
| 46 | vmess | tls/xhttp | PASS | PASS |
| 47 | trojan | tls/httpupgrade | PASS | PASS |
| 48 | vless | tls/xhttp | PASS | PASS |
| 49 | vless | tls/raw | FAIL | FAIL |
| 50 | shadowsocks | none/ws | FAIL | FAIL |
| 51 | trojan | tls/xhttp | PASS | PASS |
| 52 | trojan | tls/ws | PASS | PASS |
| 53 | vless | reality/raw | FAIL | FAIL |
| 54 | vmess | tls/httpupgrade | PASS | PASS |
| 55 | vless | tls/httpupgrade | PASS | PASS |
| 56 | vless | tls/ws | PASS | PASS |
| 57 | trojan | tls/httpupgrade | PASS | PASS |
| 58 | vless | tls/httpupgrade | PASS | PASS |
| 59 | hysteria | tls/hysteria | PASS | PASS |
| 60 | vmess | tls/xhttp | PASS | PASS |
| 61 | vmess | tls/httpupgrade | PASS | PASS |
| 62 | trojan | tls/httpupgrade | PASS | PASS |
| 63 | trojan | tls/xhttp | PASS | PASS |
| 64 | hysteria | tls/hysteria | PASS | PASS |
| 65 | vmess | tls/xhttp | PASS | PASS |
| 66 | vmess | tls/httpupgrade | PASS | PASS |
| 67 | vless | tls/httpupgrade | PASS | PASS |
| 68 | anytls | none/tcp | PASS **≠** | FAIL |
| 69 | vless | reality/xhttp | PASS | PASS |
| 70 | trojan | tls/raw | PASS | PASS |
| 71 | tuic | none/tcp | PASS **≠** | FAIL |
| 72 | vless | tls/ws | PASS | PASS |
| 73 | vless | reality/raw | FAIL | FAIL |
| 74 | vless | reality/raw | FAIL | FAIL |
| 75 | trojan | tls/xhttp | PASS | PASS |
| 76 | vless | tls/ws | PASS | PASS |
| 77 | vmess | tls/xhttp | PASS | PASS |
| 78 | vless | tls/ws | PASS | PASS |
| 79 | trojan | tls/xhttp | PASS | PASS |
| 80 | trojan | tls/httpupgrade | PASS | PASS |
| 81 | shadowsocks | none/ws | FAIL | FAIL |
| 82 | vmess | tls/ws | PASS | PASS |
| 83 | vless | reality/raw | FAIL | FAIL |
| 84 | shadowsocks | none/tcp | FAIL | FAIL |
| 85 | shadowsocks | none/tcp | FAIL | FAIL |
| 86 | trojan | tls/ws | PASS | PASS |
| 87 | vless | tls/ws | PASS | PASS |
| 88 | hysteria | tls/hysteria | PASS | PASS |
| 89 | vmess | tls/xhttp | PASS | PASS |
| 90 | shadowsocks | none/ws | FAIL | FAIL |
| 91 | vmess | tls/ws | PASS | PASS |
| 92 | shadowsocks | none/ws | FAIL | FAIL |
| 93 | vmess | tls/httpupgrade | PASS | PASS |
