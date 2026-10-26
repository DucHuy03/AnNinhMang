"""Số học modulo dùng chung cho RSA, ElGamal và ECC (Phần 1, Chương 2).

Mã nguồn chỉ nhằm minh họa thuật toán; không dùng cho môi trường thật.
"""
import secrets
from math import gcd

__all__ = ["egcd", "modinv", "modpow", "crt", "is_probable_prime", "random_prime"]


def egcd(a, b):
    """Euclid mở rộng: trả về (g, x, y) với a*x + b*y = g = gcd(a, b)."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def modinv(a, m):
    """Nghịch đảo của a modulo m; báo lỗi nếu gcd(a, m) != 1."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} không khả nghịch modulo {m}")
    return x % m


def modpow(base, exp, mod, trace=None):
    """Lũy thừa nhanh square-and-multiply, duyệt bit từ trái sang phải.

    Nếu truyền vào list `trace`, mỗi bước (bit, giá trị sau bước) được ghi lại.
    """
    if exp < 0:
        return modpow(modinv(base, mod), -exp, mod, trace)
    x = 1
    for bit in bin(exp)[2:]:
        x = x * x % mod
        if bit == "1":
            x = x * base % mod
        if trace is not None:
            trace.append((bit, x))
    return x % mod


def crt(residues, moduli):
    """Định lý số dư Trung Hoa: nghiệm duy nhất modulo tích các modulo."""
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        x += r * Mi * modinv(Mi, m)
    return x % M


_SMALL_PRIMES = [p for p in range(3, 2000) if all(p % d for d in range(2, int(p ** 0.5) + 1))]


def is_probable_prime(n, rounds=40):
    """Kiểm tra Miller-Rabin; xác suất sai không quá 4^-rounds."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    s, t = 0, n - 1
    while t % 2 == 0:
        s, t = s + 1, t // 2
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, t, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits):
    """Sinh số nguyên tố ngẫu nhiên đúng `bits` bit (bit cao nhất và bit thấp nhất bằng 1)."""
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(n):
            return n


def lcm(a, b):
    return a // gcd(a, b) * b
