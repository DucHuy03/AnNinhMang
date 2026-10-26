"""RSA dạng "sách giáo khoa" kèm giải mã CRT (Phần 1, Chương 3).

Không có đệm OAEP/PSS nên KHÔNG an toàn để dùng thật; chỉ để minh họa và kiểm thử.
"""
import hashlib
from dataclasses import dataclass
from math import gcd

from .ntheory import lcm, modinv, random_prime


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int


@dataclass(frozen=True)
class PrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int

    @property
    def public(self):
        return PublicKey(self.n, self.e)


def from_primes(p, q, e=65537, use_lambda=True):
    """Tạo khóa từ p, q cho trước; d tính theo λ(n) (FIPS 186-5) hoặc φ(n)."""
    if p == q:
        raise ValueError("p và q phải khác nhau")
    m = lcm(p - 1, q - 1) if use_lambda else (p - 1) * (q - 1)
    if gcd(e, m) != 1:
        raise ValueError("e phải nguyên tố cùng nhau với φ(n)")
    return PrivateKey(p * q, e, modinv(e, m), p, q)


def generate(bits=2048, e=65537):
    """Sinh khóa: hai số nguyên tố bits/2, |p − q| đủ lớn, gcd(e, p − 1) = gcd(e, q − 1) = 1."""
    while True:
        p, q = random_prime(bits // 2), random_prime(bits // 2)
        if abs(p - q) < (1 << (bits // 2 - 100)):
            continue
        if gcd(e, p - 1) == 1 and gcd(e, q - 1) == 1:
            return from_primes(p, q, e)


def encrypt(pub, m):
    if not 0 <= m < pub.n:
        raise ValueError("bản rõ phải thỏa 0 <= m < n")
    return pow(m, pub.e, pub.n)


def decrypt(priv, c):
    return pow(c, priv.d, priv.n)


def decrypt_crt(priv, c):
    """Giải mã theo CRT (công thức Garner), nhanh khoảng 4 lần."""
    p, q = priv.p, priv.q
    mp = pow(c, priv.d % (p - 1), p)
    mq = pow(c, priv.d % (q - 1), q)
    h = modinv(q, p) * (mp - mq) % p
    return mq + h * q


def _h(message, n):
    return int.from_bytes(hashlib.sha256(message).digest(), "big") % n


def sign(priv, message):
    """Chữ ký RSA trên giá trị băm SHA-256 (không đệm PSS)."""
    return decrypt_crt(priv, _h(message, priv.n))


def verify(pub, message, sig):
    return pow(sig, pub.e, pub.n) == _h(message, pub.n)
