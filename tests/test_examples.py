"""Tái hiện các ví dụ số của Phần 1 và kiểm tra tương thích với thư viện cryptography (OpenSSL)."""
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric import rsa as crsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from pkc_lab import ecc, elgamal, rsa
from pkc_lab.ntheory import crt, egcd, is_probable_prime, modinv, modpow


# ------------------------------------------------------------------ số học (Phần 1, Chương 2)
def test_egcd_and_inverse():
    assert modinv(7, 40) == 23 and modinv(7, 160) == 23
    g, x, y = egcd(240, 46)
    assert g == 2 and 240 * x + 46 * y == 2


def test_square_and_multiply_trace():
    trace = []
    assert modpow(88, 7, 187, trace) == 11
    assert [v for _, v in trace] == [88, 44, 11]


def test_crt_garner_example():
    assert crt([3, 0], [17, 11]) == 88


def test_miller_rabin_carmichael():
    assert pow(2, 560, 561) == 1            # kiểm tra Fermat bị lừa
    assert not is_probable_prime(561)       # Miller-Rabin thì không
    assert is_probable_prime(2 ** 127 - 1)


# ------------------------------------------------------------------ RSA (Phần 1, Chương 3)
def test_rsa_small_examples():
    k = rsa.from_primes(5, 11, e=7, use_lambda=False)
    assert k.d == 23 and rsa.encrypt(k.public, 6) == 41 and rsa.decrypt(k, 41) == 6
    k = rsa.from_primes(17, 11, e=7, use_lambda=False)
    assert rsa.encrypt(k.public, 88) == 11 and rsa.decrypt_crt(k, 11) == 88
    assert rsa.decrypt(k, rsa.encrypt(k.public, 22)) == 22   # gcd(m, n) != 1 vẫn đúng


def test_rsa_generate_sign_verify():
    k = rsa.generate(1024)
    m = 123456789
    assert rsa.decrypt_crt(k, rsa.encrypt(k.public, m)) == m == rsa.decrypt(k, rsa.encrypt(k.public, m))
    sig = rsa.sign(k, b"tieu luan")
    assert rsa.verify(k.public, b"tieu luan", sig) and not rsa.verify(k.public, b"tieu luam", sig)


def test_rsa_interop_with_openssl():
    """Khóa sinh bằng pkc_lab được OpenSSL chấp nhận; OAEP của OpenSSL giải mã được."""
    k = rsa.generate(2048)
    priv = crsa.RSAPrivateNumbers(
        p=k.p, q=k.q, d=k.d, dmp1=k.d % (k.p - 1), dmq1=k.d % (k.q - 1), iqmp=modinv(k.q, k.p),
        public_numbers=crsa.RSAPublicNumbers(k.e, k.n)).private_key()
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    assert priv.decrypt(priv.public_key().encrypt(b"hello", oaep), oaep) == b"hello"
    c = 0xC0FFEE
    raw = pow(c, k.d, k.n)
    assert rsa.decrypt_crt(k, c) == raw


# ------------------------------------------------------------------ DH / ElGamal (Phần 1, Chương 4)
def test_dh_and_elgamal_on_p71():
    G = elgamal.Group(71, 7)
    _, ya = elgamal.keygen(G, 5)
    _, yb = elgamal.keygen(G, 12)
    assert (ya, yb) == (51, 4) and elgamal.dh_shared(G, 5, yb) == elgamal.dh_shared(G, 12, ya) == 30
    ct = elgamal.encrypt(G, ya, 20, k=12)
    assert ct == (4, 32) and elgamal.decrypt(G, 5, ct) == 20


def test_elgamal_stallings_examples():
    G = elgamal.Group(19, 10)
    assert elgamal.encrypt(G, 3, 17, k=6) == (11, 5) and elgamal.decrypt(G, 5, (11, 5)) == 17
    sig = elgamal.sign(G, 16, 14, k=5)
    assert sig == (3, 4) and elgamal.verify(G, 4, 14, sig) and not elgamal.verify(G, 4, 15, sig)


# ------------------------------------------------------------------ ECC (Phần 1, Chương 2 và 5)
def test_point_arithmetic_e23():
    C = ecc.Curve(23, 1, 1)
    assert len(C.points()) + 1 == 28
    assert C.add((3, 10), (9, 7)) == (17, 20) and C.add((3, 10), (3, 10)) == (7, 12)
    D = ecc.Curve(23, 9, 17)
    assert D.mul(9, (16, 5)) == (4, 5)


def test_ecdh_stallings_and_erratum():
    C = ecc.Curve(211, 0, -4 % 211)
    G = (2, 2)
    assert C.mul(121, G) == (115, 48) and C.mul(203, G) == (130, 203)
    assert C.mul(121, (130, 203)) == C.mul(203, (115, 48)) == (161, 69)
    assert C.mul(240, G) == C.neg(G) and C.order_of(G) == 241      # đính chính: cấp là 241
    assert not C.contains((2, 3))


def test_ec_elgamal_stallings():
    C = ecc.Curve(257, 0, -4 % 257, G=(2, 2))
    Q = C.mul(101, C.G)
    ct = ecc.eg_encrypt(C, Q, (112, 26), k=41)
    assert Q == (197, 167) and ct == ((136, 128), (246, 174)) and ecc.eg_decrypt(C, 101, ct) == (112, 26)


def test_ecdsa_small_curve():
    C = ecc.Curve(17, 2, 2, G=(5, 1), n=19)
    d, Q = ecc.keygen(C, 7)
    sig = ecc.ecdsa_sign(C, d, 7, k=10)
    assert Q == (0, 6) and sig == (7, 17) and ecc.ecdsa_verify(C, Q, 7, sig)


def test_ladder_equals_double_and_add():
    C = ecc.P256
    for k in (1, 2, 3, 0xDEADBEEF, C.n - 1):
        assert C.mul(k, C.G) == C.mul_ladder(k, C.G)
    assert C.mul(C.n, C.G) is ecc.O


@pytest.mark.parametrize("direction", ["openssl_to_lab", "lab_to_openssl"])
def test_ecdsa_p256_interop(direction):
    msg = b"Cac he mat khoa cong khai"
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    sk = ec.generate_private_key(ec.SECP256R1())
    d = sk.private_numbers().private_value
    pn = sk.public_key().public_numbers()
    Q = (pn.x, pn.y)
    assert ecc.P256.mul(d, ecc.P256.G) == Q
    if direction == "openssl_to_lab":
        r, s = decode_dss_signature(sk.sign(msg, ec.ECDSA(hashes.SHA256())))
        assert ecc.ecdsa_verify(ecc.P256, Q, e, (r, s))
    else:
        r, s = ecc.ecdsa_sign(ecc.P256, d, e)
        sk.public_key().verify(encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256()))


def test_ecdh_p256_interop():
    a, b = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    shared = a.exchange(ec.ECDH(), b.public_key())
    bn = b.public_key().public_numbers()
    X = ecc.ecdh(ecc.P256, a.private_numbers().private_value, (bn.x, bn.y))
    assert X[0].to_bytes(32, "big") == shared
