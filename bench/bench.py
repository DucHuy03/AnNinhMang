"""Đo hiệu năng RSA, họ ElGamal/DH và ECC bằng thư viện cryptography (OpenSSL).

Cách đo: mỗi thao tác chạy lặp nhiều lần trong một khối; lấy trung vị thời gian/thao tác của R khối.
Kết quả ghi ra JSON để báo cáo Phần 4 sử dụng.
"""
import json
import os
import platform
import statistics
import sys
import time

from cryptography import __version__ as CRYPTO_VERSION
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, padding, rsa, x448, x25519

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pkc_lab import ecc as lab_ecc            # noqa: E402
from pkc_lab import rsa as lab_rsa            # noqa: E402

MSG = b"Cac he mat khoa cong khai: RSA, ElGamal va ECC"
SHA = hashes.SHA256()
RESULTS = []


def measure(fn, min_time=0.25, rounds=7):
    """Trả về trung vị (micro giây/thao tác)."""
    n = 1
    while True:
        t0 = time.perf_counter()
        for _ in range(n):
            fn()
        dt = time.perf_counter() - t0
        if dt >= min_time / rounds or n >= 1 << 20:
            break
        n *= 2
    samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        for _ in range(n):
            fn()
        samples.append((time.perf_counter() - t0) / n * 1e6)
    return statistics.median(samples)


def record(system, variant, level, op, us, impl="OpenSSL"):
    RESULTS.append(dict(system=system, variant=variant, level=level, op=op, us=us, impl=impl))
    print(f"{system:8} {variant:14} {level:>3} bit  {op:18} {us:12.1f} µs  ({impl})", flush=True)


def bench_rsa():
    pss = padding.PSS(mgf=padding.MGF1(SHA), salt_length=padding.PSS.DIGEST_LENGTH)
    oaep = padding.OAEP(mgf=padding.MGF1(SHA), algorithm=SHA, label=None)
    for bits, level, kg_rounds in ((2048, 112, 9), (3072, 128, 7), (4096, 152, 5)):
        record("RSA", f"RSA-{bits}", level, "sinh khóa",
               measure(lambda: rsa.generate_private_key(65537, bits), min_time=0.0, rounds=kg_rounds))
        k = rsa.generate_private_key(65537, bits)
        pub = k.public_key()
        sig = k.sign(MSG, pss, SHA)
        ct = pub.encrypt(b"k" * 32, oaep)
        record("RSA", f"RSA-{bits}", level, "ký (PSS)", measure(lambda: k.sign(MSG, pss, SHA)))
        record("RSA", f"RSA-{bits}", level, "kiểm tra (PSS)", measure(lambda: pub.verify(sig, MSG, pss, SHA)))
        record("RSA", f"RSA-{bits}", level, "mã hóa (OAEP)", measure(lambda: pub.encrypt(b"k" * 32, oaep)))
        record("RSA", f"RSA-{bits}", level, "giải mã (OAEP)", measure(lambda: k.decrypt(ct, oaep)))


def bench_dl():
    """Họ ElGamal: DSA (chữ ký), DH tạm thời (thỏa thuận khóa), ElGamal (mã hóa, Python int)."""
    for L, N, level in ((2048, 224, 112), (3072, 256, 128)):
        t0 = time.perf_counter()
        params = dsa.generate_parameters(L)
        gen_s = time.perf_counter() - t0
        pn = params.parameter_numbers()
        print(f"   (sinh tham số DSA {L}/{N}: {gen_s:.1f} s)", flush=True)
        record("ElGamal", f"DSA-{L}", level, "sinh khóa", measure(lambda: params.generate_private_key()))
        k = params.generate_private_key()
        sig = k.sign(MSG, SHA)
        record("ElGamal", f"DSA-{L}", level, "ký", measure(lambda: k.sign(MSG, SHA)))
        record("ElGamal", f"DSA-{L}", level, "kiểm tra", measure(lambda: k.public_key().verify(sig, MSG, SHA)))
        try:
            dhp = dh.DHParameterNumbers(pn.p, pn.g, pn.q).parameters()
            a, b = dhp.generate_private_key(), dhp.generate_private_key()
            bpub = b.public_key()
            record("ElGamal", f"DHE-{L}", level, "thỏa thuận khóa", measure(lambda: a.exchange(bpub)))
        except Exception as exc:  # OpenSSL chỉ nhận tham số FFC (L, N) theo SP 800-56A cho DH
            print(f"   (bỏ qua DHE-{L}: OpenSSL từ chối tham số FFC – {type(exc).__name__})", flush=True)
        # ElGamal mã hóa trong nhóm con cấp q, bằng số nguyên Python (không phải OpenSSL)
        p, g, q = pn.p, pn.g, pn.q
        x = int.from_bytes(os.urandom(N // 8), "big") % q
        y = pow(g, x, p)
        m = 123456789

        def enc():
            kk = int.from_bytes(os.urandom(N // 8), "big") % q
            return pow(g, kk, p), pow(y, kk, p) * m % p
        c1, c2 = enc()
        record("ElGamal", f"ElGamal-{L}", level, "mã hóa", measure(enc), impl="Python int")
        record("ElGamal", f"ElGamal-{L}", level, "giải mã", measure(lambda: c2 * pow(pow(c1, x, p), -1, p) % p), impl="Python int")


def bench_ecc():
    for curve, level in ((ec.SECP256R1(), 128), (ec.SECP384R1(), 192), (ec.SECP521R1(), 256)):
        name = curve.name.upper().replace("SECP", "P-").replace("R1", "")
        record("ECC", name, level, "sinh khóa", measure(lambda: ec.generate_private_key(curve)))
        k = ec.generate_private_key(curve)
        sig = k.sign(MSG, ec.ECDSA(SHA))
        other = ec.generate_private_key(curve).public_key()
        record("ECC", name, level, "ký (ECDSA)", measure(lambda: k.sign(MSG, ec.ECDSA(SHA))))
        record("ECC", name, level, "kiểm tra (ECDSA)", measure(lambda: k.public_key().verify(sig, MSG, ec.ECDSA(SHA))))
        record("ECC", name, level, "thỏa thuận khóa", measure(lambda: k.exchange(ec.ECDH(), other)))
    for mod, name, level in ((ed25519, "Ed25519", 128), (ed448, "Ed448", 224)):
        cls = mod.Ed25519PrivateKey if mod is ed25519 else mod.Ed448PrivateKey
        record("ECC", name, level, "sinh khóa", measure(cls.generate))
        k = cls.generate()
        sig = k.sign(MSG)
        record("ECC", name, level, "ký", measure(lambda: k.sign(MSG)))
        record("ECC", name, level, "kiểm tra", measure(lambda: k.public_key().verify(sig, MSG)))
    for mod, name, level in ((x25519, "X25519", 128), (x448, "X448", 224)):
        cls = mod.X25519PrivateKey if mod is x25519 else mod.X448PrivateKey
        a, b = cls.generate(), cls.generate().public_key()
        record("ECC", name, level, "thỏa thuận khóa", measure(lambda: a.exchange(b)))


def bench_lab():
    """So sánh: cài đặt minh họa thuần Python của pkc_lab."""
    k = lab_rsa.generate(3072)
    c = lab_rsa.encrypt(k.public, 0xC0FFEE)
    record("RSA", "RSA-3072", 128, "giải mã (CRT)", measure(lambda: lab_rsa.decrypt_crt(k, c), rounds=5), impl="pkc_lab")
    record("RSA", "RSA-3072", 128, "giải mã (không CRT)", measure(lambda: lab_rsa.decrypt(k, c), rounds=5), impl="pkc_lab")
    record("RSA", "RSA-3072", 128, "mã hóa", measure(lambda: lab_rsa.encrypt(k.public, 0xC0FFEE), rounds=5), impl="pkc_lab")
    C = lab_ecc.P256
    d, Q = lab_ecc.keygen(C)
    e = 0x1234567890ABCDEF
    sig = lab_ecc.ecdsa_sign(C, d, e)
    record("ECC", "P-256", 128, "ký (ECDSA)", measure(lambda: lab_ecc.ecdsa_sign(C, d, e), rounds=5), impl="pkc_lab")
    record("ECC", "P-256", 128, "kiểm tra (ECDSA)", measure(lambda: lab_ecc.ecdsa_verify(C, Q, e, sig), rounds=5), impl="pkc_lab")


def environment():
    import subprocess
    cpu = platform.processor()
    try:
        cpu = subprocess.run(["powershell", "-NoProfile", "-c", "(Get-CimInstance Win32_Processor).Name"],
                             capture_output=True, text=True, timeout=30).stdout.strip() or cpu
    except Exception:
        pass
    return dict(cpu=cpu, os=platform.platform(), python=platform.python_version(),
                cryptography=CRYPTO_VERSION, openssl=backend.openssl_version_text())


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "results_bench.json"
    env = environment()
    print(env)
    bench_rsa(); bench_dl(); bench_ecc(); bench_lab()
    with open(out, "w", encoding="utf-8") as f:
        json.dump(dict(env=env, results=RESULTS), f, ensure_ascii=False, indent=2)
    print("đã ghi", out)
