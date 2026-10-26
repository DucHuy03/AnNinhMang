"""Diffie-Hellman, mã hóa ElGamal và chữ ký ElGamal trên Z_p* (Phần 1, Chương 4).

Chỉ để minh họa: không có kiểm tra nhóm con, không có DHIES, không chống kênh bên.
"""
import secrets
from dataclasses import dataclass
from math import gcd

from .ntheory import modinv


@dataclass(frozen=True)
class Group:
    p: int          # số nguyên tố
    g: int          # phần tử sinh (của Z_p* hoặc của nhóm con cấp q)
    q: int = None   # cấp của g; mặc định p − 1

    @property
    def order(self):
        return self.q if self.q else self.p - 1


def keygen(G, x=None):
    """Trả về (x, y = g^x mod p)."""
    x = x if x is not None else secrets.randbelow(G.order - 2) + 1
    return x, pow(G.g, x, G.p)


def dh_shared(G, my_secret, their_public):
    return pow(their_public, my_secret, G.p)


def encrypt(G, y, m, k=None):
    """Bản mã (C1, C2) = (g^k, y^k · m) mod p; k phải mới cho mỗi bản tin."""
    k = k if k is not None else secrets.randbelow(G.order - 2) + 1
    return pow(G.g, k, G.p), pow(y, k, G.p) * m % G.p


def decrypt(G, x, ct):
    c1, c2 = ct
    return c2 * modinv(pow(c1, x, G.p), G.p) % G.p


def sign(G, x, m, k=None):
    """Chữ ký ElGamal gốc trên Z_p*: S1 = g^k, S2 = k^-1 (m − x·S1) mod (p − 1)."""
    n = G.p - 1
    while True:
        kk = k if k is not None else secrets.randbelow(n - 2) + 1
        if gcd(kk, n) == 1:
            break
        if k is not None:
            raise ValueError("k phải nguyên tố cùng nhau với p − 1")
    s1 = pow(G.g, kk, G.p)
    s2 = modinv(kk, n) * (m - x * s1) % n
    return s1, s2


def verify(G, y, m, sig):
    s1, s2 = sig
    if not 0 < s1 < G.p:
        return False
    return pow(G.g, m, G.p) == pow(y, s1, G.p) * pow(s1, s2, G.p) % G.p
