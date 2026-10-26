"""Các demo tấn công của Phần 2, chạy trên tham số nhỏ do chính chương trình tạo ra.

Mỗi hàm trả về dict kết quả và tự kiểm tra rằng giá trị khôi phục được trùng với giá trị gốc.
Mục đích: minh họa vì sao cần các biện pháp phòng chống trong báo cáo.
"""
from math import gcd, isqrt

from pkc_lab import ecc, elgamal, rsa
from pkc_lab.ntheory import crt, modinv


def iroot(x, k):
    lo, hi = 0, 1 << (x.bit_length() // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        lo, hi = (mid, hi) if mid ** k <= x else (lo, mid - 1)
    return lo


def fermat_factor():
    """§2.1.1 – p, q quá gần nhau."""
    n = 1009 * 1013
    a = isqrt(n) + (isqrt(n) ** 2 < n)
    while isqrt(a * a - n) ** 2 != a * a - n:
        a += 1
    b = isqrt(a * a - n)
    assert (a - b) * (a + b) == n
    return dict(n=n, p=a - b, q=a + b)


def shared_factor():
    """§3.1 – hai modulo dùng chung một số nguyên tố."""
    n1, n2 = 101 * 113, 101 * 127
    p = gcd(n1, n2)
    assert p == 101
    return dict(n1=n1, n2=n2, p=p)


def common_modulus():
    """§3.2 – cùng n, hai số mũ e1, e2 nguyên tố cùng nhau."""
    n, e1, e2, m = 187, 3, 7, 42
    c1, c2 = pow(m, e1, n), pow(m, e2, n)
    s, t = -2, 1
    rec = pow(c1, s, n) * pow(c2, t, n) % n
    assert e1 * s + e2 * t == 1 and rec == m
    return dict(c1=c1, c2=c2, recovered=rec)


def hastad_broadcast():
    """§3.3 – e = 3, cùng bản tin gửi cho ba người, không đệm."""
    ns, m = [55, 391, 1189], 42
    cs = [pow(m, 3, n) for n in ns]
    x = crt(cs, ns)
    assert iroot(x, 3) == m
    return dict(ciphertexts=cs, crt=x, recovered=iroot(x, 3))


def wiener():
    """§3.4 – d nhỏ, khôi phục bằng liên phân số của e/n."""
    n, e = 90581, 17993
    num, den, cf = e, n, []
    while den:
        a = num // den
        cf.append(a)
        num, den = den, num - a * den
    h0, h1, k0, k1 = 0, 1, 1, 0
    for a in cf:
        h0, h1 = h1, a * h1 + h0
        k0, k1 = k1, a * k1 + k0
        k, d = h1, k1
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0 and isqrt(disc) ** 2 == disc:
            p = (s + isqrt(disc)) // 2
            assert p * (n // p) == n
            return dict(d=d, p=p, q=n // p)
    raise AssertionError("không tìm được d")


def textbook_rsa_cca():
    """§3.5 – tính đồng cấu: hỏi oracle giải mã c·r^e thay cho c."""
    k = rsa.from_primes(17, 11, e=7, use_lambda=False)
    c = rsa.encrypt(k.public, 88)
    c_star = c * pow(2, k.e, k.n) % k.n
    m_star = rsa.decrypt(k, c_star)          # oracle giải mã
    rec = m_star * modinv(2, k.n) % k.n
    assert c_star != c and rec == 88
    return dict(c=c, c_star=c_star, oracle=m_star, recovered=rec)


def crt_fault():
    """§6.3 – một chữ ký CRT bị lỗi ở nửa mod q làm lộ p."""
    k = rsa.from_primes(17, 11, e=7, use_lambda=False)
    h = 50
    sp = pow(h, k.d % 16, 17)
    sq_bad = (pow(h, k.d % 10, 11) + 1) % 11
    s_bad = sq_bad + 11 * (modinv(11, 17) * (sp - sq_bad) % 17)
    p = gcd((pow(s_bad, k.e, k.n) - h) % k.n, k.n)
    assert p == 17
    return dict(faulty_signature=s_bad, leaked_factor=p)


def pohlig_hellman():
    """§2.2.1 – cấp nhóm 70 = 2·5·7 toàn ước nhỏ."""
    p, g, y = 71, 7, 51
    parts = []
    for q in (2, 5, 7):
        gi, yi = pow(g, 70 // q, p), pow(y, 70 // q, p)
        parts.append(next(t for t in range(q) if pow(gi, t, p) == yi))
    x = crt(parts, [2, 5, 7])
    assert pow(g, x, p) == y
    return dict(residues=parts, x=x)


def small_subgroup():
    """§4.2 – nạn nhân không kiểm tra khóa công khai nhận được."""
    p, g, x_victim = 71, 7, 5
    leaks = {}
    for ell in (2, 5, 7):
        h = pow(g, 70 // ell, p)                    # phần tử cấp ell
        k = pow(h, x_victim, p)                     # nạn nhân tính "khóa chung"
        leaks[ell] = next(t for t in range(ell) if pow(h, t, p) == k)
    x = crt(list(leaks.values()), list(leaks))
    assert x == x_victim
    return dict(leaks=leaks, x=x)


def dh_mitm():
    """§4.1 – Mallory thay Y_A, Y_B bằng Y_M."""
    G = elgamal.Group(71, 7)
    _, ya = elgamal.keygen(G, 5)
    _, yb = elgamal.keygen(G, 12)
    xm, ym = elgamal.keygen(G, 9)
    k_alice, k_bob = elgamal.dh_shared(G, 5, ym), elgamal.dh_shared(G, 12, ym)
    assert k_alice == elgamal.dh_shared(G, xm, ya) and k_bob == elgamal.dh_shared(G, xm, yb)
    return dict(alice_key=k_alice, bob_key=k_bob, honest_key=elgamal.dh_shared(G, 5, yb))


def elgamal_k_reuse():
    """§4.4 – hai bản tin cùng k: biết m1 suy ra m2."""
    G = elgamal.Group(71, 7)
    c1 = elgamal.encrypt(G, 51, 20, k=12)
    c2 = elgamal.encrypt(G, 51, 33, k=12)
    rec = c2[1] * modinv(c1[1], 71) * 20 % 71
    assert c1[0] == c2[0] and rec == 33
    return dict(ct1=c1, ct2=c2, recovered=rec)


def ecdsa_nonce_reuse():
    """§5.1 – hai chữ ký ECDSA cùng k làm lộ khóa riêng."""
    C = ecc.Curve(17, 2, 2, G=(5, 1), n=19)
    d, _ = ecc.keygen(C, 7)
    (r1, s1), (r2, s2) = ecc.ecdsa_sign(C, d, 7, k=10), ecc.ecdsa_sign(C, d, 15, k=10)
    k = (7 - 15) * modinv(s1 - s2, 19) % 19
    d_rec = (s1 * k - 7) * modinv(r1, 19) % 19
    assert r1 == r2 and d_rec == d
    return dict(r=r1, s1=s1, s2=s2, k=k, d=d_rec)


def invalid_curve():
    """§5.3 – nạn nhân bỏ qua kiểm tra điểm; công thức cộng điểm không dùng b."""
    victim = ecc.Curve(17, 2, 2, G=(5, 1), n=19)
    d = 7
    residues, moduli = [], []
    for ell in (2, 3, 5):
        for b in range(17):
            if b == 2 or (4 * 8 + 27 * b * b) % 17 == 0:
                continue
            other = ecc.Curve(17, 2, b)
            cand = [P for P in other.points() if other.order_of(P) == ell]
            if cand:
                P = cand[0]
                shared = victim.mul(d, P)               # nạn nhân không kiểm tra P
                residues.append(next(t for t in range(ell) if victim.mul(t, P) == shared))
                moduli.append(ell)
                break
    d_rec = crt(residues, moduli)
    assert d_rec == d
    return dict(residues=dict(zip(moduli, residues)), d=d_rec)


ALL = [fermat_factor, shared_factor, common_modulus, hastad_broadcast, wiener, textbook_rsa_cca, crt_fault,
       pohlig_hellman, small_subgroup, dh_mitm, elgamal_k_reuse, ecdsa_nonce_reuse, invalid_curve]
