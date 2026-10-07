"""
BTL Nhom 11 — Test suite cho gateway_parser
=============================================
~15 test cases kiem tra parser vuln va fixed.
"""
import os
import subprocess
import sys
import tempfile

import pytest

# Setup paths
BTL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(BTL_DIR, "src")
sys.path.insert(0, os.path.join(BTL_DIR, "source"))
sys.path.insert(0, os.path.join(BTL_DIR, "fuzzers"))

from packet_builder import (  # noqa: E402
    build_packet, build_registration_packet, build_unlock_packet,
    MAGIC, TYPE_REGISTRATION, TYPE_UNLOCK,
)

def get_parser(name: str) -> str:
    for folder in ["source", "src"]:
        for ext in [".exe", ""]:
            p = os.path.join(BTL_DIR, folder, name + ext)
            if os.path.exists(p):
                return p
    return os.path.join(BTL_DIR, "source", name + (".exe" if os.name == "nt" else ""))

PARSER_VULN = get_parser("parser_vuln")
PARSER_FIXED = get_parser("parser_fixed")

def run_parser(binary: str, packet: bytes) -> subprocess.CompletedProcess:
    """Ghi goi vao file tam, chay parser, tra ve ket qua."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(packet)
        f.flush()
        tmp_name = f.name
    try:
        result = subprocess.run(
            [binary, tmp_name],
            capture_output=True, text=True, timeout=5,
        )
    finally:
        if os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except Exception:
                pass
    return result


def is_asan_crash(result: subprocess.CompletedProcess) -> bool:
    return result.returncode != 0 and "AddressSanitizer" in result.stderr


# ========== GOI HOP LE ==========

class TestValidPackets:
    def test_valid_registration(self):
        pkt = build_registration_packet(device_id=b"SENSOR01")
        r = run_parser(PARSER_VULN, pkt)
        assert r.returncode == 0
        assert "[OK] Registration" in r.stdout

    def test_valid_registration_short_id(self):
        pkt = build_registration_packet(device_id=b"AB")
        r = run_parser(PARSER_VULN, pkt)
        assert r.returncode == 0

    def test_valid_registration_max_safe_id(self):
        """device_id dung 16 byte — gioi han an toan ca ban vuln."""
        pkt = build_registration_packet(device_id=b"A" * 16)
        r = run_parser(PARSER_VULN, pkt)
        assert r.returncode == 0

    def test_valid_unlock(self):
        pkt = build_unlock_packet(unlock_a=7421, unlock_b=3390)
        r = run_parser(PARSER_VULN, pkt)
        assert r.returncode == 0
        assert "[OK] Unlock" in r.stdout


# ========== TU CHOI HEADER SAI ==========

class TestHeaderRejection:
    def test_wrong_magic(self):
        pkt = build_registration_packet(device_id=b"TEST", magic=b"XXXX")
        r = run_parser(PARSER_VULN, pkt)
        assert r.returncode != 0
        assert "[REJECT] Magic sai" in r.stderr

    def test_wrong_version(self):
        pkt = build_registration_packet(device_id=b"TEST", version=2)
        r = run_parser(PARSER_VULN, pkt)
        assert r.returncode != 0
        assert "[REJECT] Version" in r.stderr

    def test_wrong_type(self):
        pkt = build_packet(pkt_type=0x03, payload=b"")
        r = run_parser(PARSER_VULN, pkt)
        assert r.returncode != 0
        assert "[REJECT] Type" in r.stderr

    def test_wrong_flags(self):
        pkt = build_registration_packet(device_id=b"TEST", flags=1)
        r = run_parser(PARSER_VULN, pkt)
        assert r.returncode != 0
        assert "[REJECT] Flags" in r.stderr

    def test_wrong_reserved(self):
        pkt = build_registration_packet(device_id=b"TEST", reserved=0xFF)
        r = run_parser(PARSER_VULN, pkt)
        assert r.returncode != 0
        assert "[REJECT] Reserved" in r.stderr


# ========== CHECKSUM VA LENGTH ==========

class TestChecksumAndLength:
    def test_bad_checksum(self):
        pkt = build_registration_packet(device_id=b"TEST")
        # Corrupt last 4 bytes (checksum)
        pkt = pkt[:-4] + b"\xff\xff\xff\xff"
        r = run_parser(PARSER_VULN, pkt)
        assert r.returncode != 0
        assert "[REJECT] Checksum sai" in r.stderr

    def test_file_too_short(self):
        """File ngan hon header + checksum."""
        r = run_parser(PARSER_VULN, b"\x00" * 10)
        assert r.returncode != 0
        assert "[REJECT]" in r.stderr

    def test_length_mismatch(self):
        """payload_len trong header khong khop voi kich thuoc file thuc te."""
        pkt = build_registration_packet(device_id=b"TEST")
        # Cat bot 2 byte cuoi payload, giu checksum cu.
        # Parser phai reject o validation kich thuoc, truoc checksum.
        pkt = pkt[:-6] + pkt[-4:]
        r = run_parser(PARSER_VULN, pkt)
        assert r.returncode != 0
        assert "[REJECT] Kich thuoc file khong khop" in r.stderr

    def test_payload_len_less_than_device_id_len(self):
        """payload_len < device_id_len cho Registration."""
        pkt = build_packet(
            pkt_type=TYPE_REGISTRATION,
            device_id_len=10,
            payload_len=5,
            payload=b"ABCDE",
        )
        r = run_parser(PARSER_VULN, pkt)
        assert r.returncode != 0
        assert "[REJECT] payload_len" in r.stderr


# ========== ASCII VA NOI DUNG ==========

class TestContentValidation:
    def test_non_ascii_device_id(self):
        """device_id chua byte khong phai ASCII printable."""
        pkt = build_registration_packet(device_id=b"\x01\x02\x03\x04")
        r = run_parser(PARSER_VULN, pkt)
        assert r.returncode != 0
        assert "[REJECT]" in r.stderr
        assert "ASCII" in r.stderr

    def test_unlock_wrong_code(self):
        pkt = build_unlock_packet(unlock_a=1234, unlock_b=5678)
        r = run_parser(PARSER_VULN, pkt)
        assert r.returncode != 0
        assert "[REJECT] Unlock" in r.stderr


# ========== CWE-121: CRASH VS FIXED ==========

class TestCWE121:
    def test_vuln_crashes_with_long_device_id(self):
        """Ban vulnerable: device_id=24 byte gay stack-buffer-overflow."""
        pkt = build_registration_packet(device_id=b"A" * 24)
        r = run_parser(PARSER_VULN, pkt)
        assert is_asan_crash(r), (
            f"Expected ASan crash, got exit={r.returncode}, "
            f"stderr={r.stderr[:200]}"
        )

    def test_fixed_rejects_long_device_id(self):
        """Ban fixed: reject device_id > 16 ma khong crash."""
        pkt = build_registration_packet(device_id=b"A" * 24)
        r = run_parser(PARSER_FIXED, pkt)
        assert r.returncode != 0, "Fixed should reject"
        assert not is_asan_crash(r), "Fixed should NOT crash with ASan"
        assert "device_id_len qua lon" in r.stderr

    def test_fixed_accepts_max_16_id(self):
        """Ban fixed: device_id dung 16 byte van hop le."""
        pkt = build_registration_packet(device_id=b"B" * 16)
        r = run_parser(PARSER_FIXED, pkt)
        assert r.returncode == 0
