"""Đường cong elliptic dạng Weierstrass trên GF(p), ECDH, EC-ElGamal và ECDSA (Phần 1, Chương 2 và 5).

Chỉ để minh họa: tọa độ affine, không chạy thời gian hằng.
"""
import hashlib
import secrets
from dataclasses import dataclass

from .ntheory import modinv

O = None  # điểm vô cực


@dataclass(frozen=True)
class Curve:
    p: int
    a: int
    b: int
    G: tuple = None
    n: int = None   # cấp của G

    def contains(self, P):
        if P is O:
            return True
        x, y = P
        return (y * y - x ** 3 - self.a * x - self.b) % self.p == 0

    def neg(self, P):
        return O if P is O else (P[0], (-P[1]) % self.p)

    def add(self, P, Q):
        if P is O:
            return Q
        if Q is O:
            return P
        p = self.p
        if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
            return O
        if P == Q:
            lam = (3 * P[0] * P[0] + self.a) * modinv(2 * P[1], p) % p
        else:
            lam = (Q[1] - P[1]) * modinv(Q[0] - P[0], p) % p
        x3 = (lam * lam - P[0] - Q[0]) % p
        return x3, (lam * (P[0] - x3) - P[1]) % p

    def mul(self, k, P):
        """Double-and-add, duyệt bit từ trái sang phải."""
        if k < 0:
            return self.mul(-k, self.neg(P))
        R = O
        for bit in bin(k)[2:]:
            R = self.add(R, R)
            if bit == "1":
                R = self.add(R, P)
        return R

    def mul_ladder(self, k, P):
        """Montgomery ladder: mỗi bit luôn làm một phép cộng và một phép nhân đôi."""
        R0, R1 = O, P
        for bit in bin(k)[2:]:
            if bit == "1":
                R0, R1 = self.add(R0, R1), self.add(R1, R1)
            else:
                R0, R1 = self.add(R0, R0), self.add(R0, R1)
        return R0

    def order_of(self, P):
        k, R = 1, P
        while R is not O:
            R, k = self.add(R, P), k + 1
        return k

    def points(self):
        """Liệt kê mọi điểm (chỉ dùng cho đường cong rất nhỏ)."""
        return [(x, y) for x in range(self.p) for y in range(self.p) if self.contains((x, y))]


# Đường cong chuẩn NIST P-256 (FIPS 186-5 / SP 800-186)
P256 = Curve(
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=-3 % 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    G=(0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
       0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5),
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
)


def keygen(C, d=None):
    d = d if d is not None else secrets.randbelow(C.n - 1) + 1
    return d, C.mul(d, C.G)


def ecdh(C, d, Q_other):
    if not C.contains(Q_other) or Q_other is O:
        raise ValueError("điểm nhận được không nằm trên đường cong")
    return C.mul(d, Q_other)


def eg_encrypt(C, Q, Pm, k=None):
    k = k if k is not None else secrets.randbelow(C.n - 1) + 1
    return C.mul(k, C.G), C.add(Pm, C.mul(k, Q))


def eg_decrypt(C, d, ct):
    c1, c2 = ct
    return C.add(c2, C.neg(C.mul(d, c1)))


def hash_to_int(C, message):
    h = int.from_bytes(hashlib.sha256(message).digest(), "big")
    excess = max(0, 256 - C.n.bit_length())
    return h >> excess


def ecdsa_sign(C, d, e, k=None):
    """Ký giá trị băm e (đã là số nguyên). Trả về (r, s)."""
    while True:
        kk = k if k is not None else secrets.randbelow(C.n - 1) + 1
        R = C.mul(kk, C.G)
        r = R[0] % C.n
        s = modinv(kk, C.n) * (e + d * r) % C.n
        if r and s:
            return r, s
        if k is not None:
            raise ValueError("k cho r = 0 hoặc s = 0")


def ecdsa_verify(C, Q, e, sig):
    r, s = sig
    if not (0 < r < C.n and 0 < s < C.n):
        return False
    w = modinv(s, C.n)
    X = C.add(C.mul(e * w % C.n, C.G), C.mul(r * w % C.n, Q))
    return X is not O and X[0] % C.n == r
