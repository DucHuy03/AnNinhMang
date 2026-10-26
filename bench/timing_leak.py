"""Thí nghiệm tấn công thời gian (Phần 2, §6.1) trên chính mã nguồn của pkc_lab.

So sánh thời gian lũy thừa modulo 2048 bit với các số mũ 512 bit có số bit 1 (trọng số Hamming) khác nhau:
  - square-and-multiply: chỉ nhân khi bit = 1  → thời gian phụ thuộc khóa bí mật
  - Montgomery ladder:   mỗi bit luôn 1 nhân + 1 bình phương → thời gian gần như không đổi
"""
import json
import os
import secrets
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pkc_lab.ntheory import modpow, random_prime   # noqa: E402

BITS_EXP = 512


def ladder_pow(base, exp, mod):
    r0, r1 = 1, base % mod
    for bit in bin(exp)[2:]:
        if bit == "1":
            r0, r1 = r0 * r1 % mod, r1 * r1 % mod
        else:
            r0, r1 = r0 * r0 % mod, r0 * r1 % mod
    return r0


def exponent_with_weight(w):
    """Số mũ đúng 512 bit, có đúng w bit 1 (bit cao nhất luôn bằng 1)."""
    positions = secrets.SystemRandom().sample(range(BITS_EXP - 1), w - 1)
    return (1 << (BITS_EXP - 1)) | sum(1 << i for i in positions)


def time_us(fn, reps=30):
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1e6)
    return statistics.median(samples)


def pearson(xs, ys):
    mx, my = statistics.mean(xs), statistics.mean(ys)
    sx = sum((x - mx) ** 2 for x in xs) ** 0.5
    sy = sum((y - my) ** 2 for y in ys) ** 0.5
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (sx * sy)


def main(out):
    n = random_prime(1024) * random_prime(1024)
    base = secrets.randbelow(n)
    rows = []
    for w in range(32, 481, 32):
        for _ in range(3):
            e = exponent_with_weight(w)
            assert modpow(base, e, n) == ladder_pow(base, e, n) == pow(base, e, n)
            rows.append(dict(weight=w, sqm_us=time_us(lambda: modpow(base, e, n)),
                             ladder_us=time_us(lambda: ladder_pow(base, e, n))))
        print(rows[-1], flush=True)
    ws = [r["weight"] for r in rows]
    summary = dict(
        r_sqm=pearson(ws, [r["sqm_us"] for r in rows]),
        r_ladder=pearson(ws, [r["ladder_us"] for r in rows]),
        sqm_min=min(r["sqm_us"] for r in rows), sqm_max=max(r["sqm_us"] for r in rows),
        ladder_min=min(r["ladder_us"] for r in rows), ladder_max=max(r["ladder_us"] for r in rows),
    )
    print(summary)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(dict(rows=rows, summary=summary), f, indent=2)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "results_timing.json")
