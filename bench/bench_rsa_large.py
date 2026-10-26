"""Bổ sung số đo RSA-7680 (192 bit) và RSA-15360 (256 bit) vào results_bench.json.

Sinh khóa ở các kích thước này rất chậm nên chỉ sinh một khóa và ghi lại thời gian sinh của lần đó.
"""
import json
import os
import sys
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bench import MSG, SHA, measure   # noqa: E402

path = sys.argv[1] if len(sys.argv) > 1 else "results_bench.json"
data = json.load(open(path, encoding="utf-8"))
data["results"] = [r for r in data["results"] if r["variant"] not in ("RSA-7680", "RSA-15360")]
pss = padding.PSS(mgf=padding.MGF1(SHA), salt_length=padding.PSS.DIGEST_LENGTH)
for bits, level in ((7680, 192), (15360, 256)):
    t0 = time.perf_counter()
    k = rsa.generate_private_key(65537, bits)
    kg = (time.perf_counter() - t0) * 1e6
    sig = k.sign(MSG, pss, SHA)
    rows = [("sinh khóa (1 lần)", kg),
            ("ký (PSS)", measure(lambda: k.sign(MSG, pss, SHA), min_time=1.0, rounds=5)),
            ("kiểm tra (PSS)", measure(lambda: k.public_key().verify(sig, MSG, pss, SHA), rounds=5))]
    for op, us in rows:
        data["results"].append(dict(system="RSA", variant=f"RSA-{bits}", level=level, op=op, us=us, impl="OpenSSL"))
        print(f"RSA-{bits} {op:18} {us:14.1f} µs", flush=True)
    json.dump(data, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print("đã cập nhật", path)
