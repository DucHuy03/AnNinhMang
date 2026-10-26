# pkc_lab – Mã nguồn thực nghiệm cho tiểu luận "Các hệ mật khóa công khai: RSA, ElGamal và ECC"

Học viên: Nguyễn Đức Huy – 20261238M – Môn An ninh mạng.

Mã nguồn phục vụ Phần 4 của báo cáo, gồm ba mục đích:

1. **Cài đặt minh họa** RSA, Diffie-Hellman/ElGamal và ECC để kiểm chứng thuật toán của Phần 1.
2. **Tái hiện các demo tấn công** của Phần 2 trên tham số nhỏ do chương trình tự tạo.
3. **Đo hiệu năng** bằng thư viện chuẩn `cryptography` (OpenSSL) để kiểm chứng mô hình chi phí của Phần 3.

> ⚠️ Gói `pkc_lab` chỉ dùng để học: không có đệm OAEP/PSS, không chạy thời gian hằng, không kiểm tra đầu vào đầy đủ.
> Ứng dụng thật phải dùng thư viện đã kiểm định.

## Cấu trúc

```
MaNguon/
├── pkc_lab/            Cài đặt minh họa
│   ├── ntheory.py      Euclid mở rộng, nghịch đảo, lũy thừa nhanh, CRT, Miller-Rabin, sinh số nguyên tố
│   ├── rsa.py          Sinh khóa, mã hóa/giải mã, giải mã CRT, ký/kiểm tra (băm SHA-256)
│   ├── elgamal.py      Diffie-Hellman, mã hóa ElGamal, chữ ký ElGamal
│   └── ecc.py          Cộng điểm, double-and-add, Montgomery ladder, P-256, ECDH, EC-ElGamal, ECDSA
├── attacks/demos.py    13 demo tấn công của Phần 2 (mỗi demo tự kiểm tra kết quả)
├── bench/
│   ├── bench.py        Đo hiệu năng bằng cryptography/OpenSSL và so với pkc_lab
│   ├── bench_rsa_large.py  Bổ sung RSA-7680 / RSA-15360 (mức 192 / 256 bit)
│   └── timing_leak.py  Thí nghiệm rò rỉ thời gian: square-and-multiply so với Montgomery ladder
├── tests/              Kiểm thử pytest (ví dụ số của Phần 1, tương thích chéo với OpenSSL, demo tấn công)
├── run_attacks.py      Chạy toàn bộ demo tấn công
└── results_*.json      Kết quả đo dùng trong báo cáo
```

## Cài đặt và chạy

Yêu cầu Python ≥ 3.10.

```bash
pip install -r requirements.txt

python -m pytest -q tests            # 30 kiểm thử
python run_attacks.py                # 13 demo tấn công
python bench/bench.py results_bench.json        # đo hiệu năng (vài phút)
python bench/bench_rsa_large.py results_bench.json  # RSA-7680/15360 (sinh khóa có thể mất vài phút)
python bench/timing_leak.py results_timing.json # thí nghiệm rò rỉ thời gian
```

## Đối chiếu với báo cáo

| Báo cáo | Mã nguồn |
|---|---|
| Phần 1, Chương 2 – cơ sở toán học | `pkc_lab/ntheory.py`, `tests/test_examples.py` |
| Phần 1, Chương 3–5 – RSA, ElGamal, ECC | `pkc_lab/rsa.py`, `pkc_lab/elgamal.py`, `pkc_lab/ecc.py` |
| Phần 2 – các tấn công | `attacks/demos.py`, `bench/timing_leak.py` |
| Phần 3, Chương 5 – mô hình chi phí | `bench/bench.py` (kiểm chứng bằng số đo) |
