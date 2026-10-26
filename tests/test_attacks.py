import pytest

from attacks.demos import ALL


@pytest.mark.parametrize("demo", ALL, ids=[f.__name__ for f in ALL])
def test_attack_demo_recovers_secret(demo):
    demo()   # mỗi demo tự assert giá trị khôi phục bằng giá trị gốc
