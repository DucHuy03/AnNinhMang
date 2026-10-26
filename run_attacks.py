"""Chạy toàn bộ demo tấn công của Phần 2 và in kết quả."""
import json
import sys
import time

from attacks.demos import ALL


def main():
    results = []
    for fn in ALL:
        t0 = time.perf_counter()
        out = fn()
        ms = (time.perf_counter() - t0) * 1000
        results.append(dict(name=fn.__name__, doc=fn.__doc__.strip(), ms=round(ms, 3), result=out))
        print(f"[OK] {fn.__name__:<20} {ms:8.3f} ms  {out}")
    if "--json" in sys.argv:
        with open(sys.argv[sys.argv.index("--json") + 1], "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    print(f"{len(results)}/{len(ALL)} demo thành công")


if __name__ == "__main__":
    main()
