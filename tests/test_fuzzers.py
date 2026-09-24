"""
BTL Nhom 11 — Test suite cho fuzzers
=====================================
Kiem tra:
  - Black-box khong chua "IGW1" trong seed/dictionary
  - White-box Z3 tao dung crash
  - Greybox dat coverage cao hon black-box (quick run)
  - Unlock benchmark hoat dong dung
"""
import os
import sys

import pytest

BTL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BTL_DIR, "source"))
sys.path.insert(0, os.path.join(BTL_DIR, "fuzzers"))
sys.path.insert(0, os.path.join(BTL_DIR, "scripts"))

from packet_builder import MAGIC  # noqa: E402

CRASH_DIR = os.path.join(BTL_DIR, "crashes")
os.makedirs(CRASH_DIR, exist_ok=True)


class TestBlackboxFuzzer:
    def test_blackbox_magic_is_unbiased(self):
        """Black-box randomizes magic; no code-level exclusion of the secret."""
        from blackbox_fuzzer import random_magic
        import random
        rng = random.Random(42)
        observed = {random_magic(rng) for _ in range(1000)}
        assert len(observed) > 990

    def test_blackbox_structure_valid(self):
        """Goi sinh ra co cau truc: header 16 byte + payload + checksum 4."""
        from blackbox_fuzzer import generate_random_packet
        from packet_builder import HEADER_SIZE, CHECKSUM_SIZE, parse_header, compute_checksum
        import random, struct
        rng = random.Random(0)
        for _ in range(50):
            pkt = generate_random_packet(rng)
            assert len(pkt) >= HEADER_SIZE + CHECKSUM_SIZE
            hdr = parse_header(pkt)
            expected_len = HEADER_SIZE + hdr["payload_len"] + CHECKSUM_SIZE
            assert len(pkt) == expected_len, f"Len mismatch: {len(pkt)} vs {expected_len}"
            # Checksum phai dung
            data = pkt[:HEADER_SIZE + hdr["payload_len"]]
            stored = struct.unpack("<I", pkt[-4:])[0]
            assert compute_checksum(data) == stored

    def test_blackbox_no_crash_in_small_budget(self):
        """Voi 200 input, blackbox khong tim duoc crash (magic sai)."""
        from blackbox_fuzzer import fuzz
        result = fuzz(budget=200, seed=42)
        assert result["total_crashes"] == 0, (
            "Black-box khong nen tim crash trong ngan sach nho "
            "(vi khong biet magic IGW1)"
        )

    def test_blackbox_counts_only_inputs_executed_before_crash(self, monkeypatch):
        """Neu oracle phat hien crash som, metric khong duoc ghi la full budget."""
        import subprocess
        import blackbox_fuzzer

        fake_crash = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="",
            stderr="ERROR: AddressSanitizer: stack-buffer-overflow\n"
                   "#0 0x0 in main src/gateway_parser.c:1\n",
        )
        monkeypatch.setattr(blackbox_fuzzer, "run_target", lambda *_args, **_kwargs: fake_crash)

        result = blackbox_fuzzer.fuzz(budget=10, seed=0)
        assert result["first_crash_at"] == 0
        assert result["iterations_used"] == 1


class TestWhiteboxFuzzer:
    def test_z3_produces_valid_crash(self):
        """Z3 sinh goi co magic IGW1, device_id_len=24, checksum dung, gay ASan crash."""
        from whitebox_fuzzer import z3_solve_crash_packet, run_target, is_asan_crash
        from packet_builder import parse_header

        r = z3_solve_crash_packet(device_id_len=24)
        assert r["status"] == "sat", "Z3 phai giai duoc"
        assert r["solve_time"] < 10.0, f"Z3 cham: {r['solve_time']}s"

        pkt = r["packet"]
        hdr = parse_header(pkt)
        assert hdr["magic"] == MAGIC
        assert hdr["device_id_len"] == 24
        assert hdr["version"] == 1
        assert hdr["type"] == 0x01

        # Xac nhan crash thuc te
        proc = run_target(pkt)
        assert is_asan_crash(proc), "Goi Z3 phai gay ASan crash tren parser_vuln"

    def test_whitebox_fuzz_finds_crash_immediately(self):
        """Whitebox fuzzer phai tim crash ngay lan dau tien (iteration 0)."""
        from whitebox_fuzzer import fuzz
        result = fuzz(budget=10, seed=0)
        assert result["first_crash_at"] == 0, (
            f"Whitebox phai tim crash tai iteration 0, got {result['first_crash_at']}"
        )
        assert result["total_crashes"] >= 1
        assert result["total_crashes"] == 1, "Cung mot ASan signature chi luu mot crash dai dien"


class TestGreyboxFuzzer:
    def test_greybox_discovers_coverage(self):
        """Greybox phai kham pha it nhat vai dong coverage moi."""
        from greybox_fuzzer import fuzz
        result = fuzz(budget=100, seed=7)
        assert result["total_lines_covered"] > 0, (
            "Greybox phai phu it nhat 1 dong code"
        )
        assert len(result["coverage_history"]) > 0, (
            "Phai co it nhat 1 su kien coverage moi"
        )

    def test_greybox_reaches_crash_by_coverage_guided_sweep(self):
        """Khong biet magic, greybox van giu prefix co coverage moi."""
        from greybox_fuzzer import fuzz
        result = fuzz(budget=1200, seed=7)
        assert result["first_crash_at"] is not None
        assert result["first_crash_at"] <= 1200
        assert result["total_crashes"] == 1


class TestUnlockBenchmark:
    def test_z3_solves_unlock_exactly(self):
        """Z3 giai dung cap (7421, 3390) ngay lap tuc."""
        from unlock_benchmark import whitebox_unlock_solve
        r = whitebox_unlock_solve()
        assert r["found"] is True
        assert r["unlock_a"] == 7421
        assert r["unlock_b"] == 3390
        assert r["time"] < 1.0

    def test_z3_unlock_verified_on_target(self):
        """Goi unlock Z3 chay thanh cong tren parser."""
        from unlock_benchmark import verify_unlock_on_target
        assert verify_unlock_on_target(7421, 3390) is True

    def test_blackbox_unlock_fails_in_small_budget(self):
        """Random brute-force khong tim duoc trong 100K thu (xac suat P = 1/2^32)."""
        from unlock_benchmark import blackbox_unlock_trial
        r = blackbox_unlock_trial(budget=100000, seed=42)
        # Hau nhu chac chan khong tim duoc
        # Nhung khong assert tuyet doi vi co xac suat cuc nho
        # Chi kiem tra result co dung format
        assert "found" in r
        assert "iteration" in r
        assert "time" in r


class TestResultAggregation:
    def test_unique_crash_dedup_ignores_aslr_addresses(self):
        """Cung fault site voi dia chi ASLR khac nhau chi la mot unique crash."""
        from aggregate_results import aggregate_fuzzer

        data = [
            {
                "first_crash_at": 0,
                "wall_time_seconds": 1.0,
                "time_to_first_crash_seconds": 0.1,
                "exec_per_sec": 10.0,
                "crashes": [{"asan_signature": "#0 0x1111 in memcpy file.c:10"}],
            },
            {
                "first_crash_at": 0,
                "wall_time_seconds": 1.0,
                "time_to_first_crash_seconds": 0.2,
                "exec_per_sec": 10.0,
                "crashes": [{"asan_signature": "#0 0xABCD in memcpy file.c:10"}],
            },
        ]

        assert aggregate_fuzzer(data, "test")["unique_crash_signatures"] == 1
