"""Go<->Go 对照: 同款配置证明测试脚本/pin 无误, 锅在 Rust server."""
import sys
sys.path.insert(0, 'D:/Project/Xray-core-rust/dist')
import interop_matrix as M

GO = M.GO
results = []
idx = 1
for p in ['vless_vision_tls', 'trojan_tls', 'ss2022']:
    results.append(M.run_one(idx, p, GO, GO, 'Go->Go'))
    idx += 1
print(f'=== Go<->Go 对照: {results.count("PASS")}/{len(results)} PASS ===')
