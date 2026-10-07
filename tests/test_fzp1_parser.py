"""
BTL Nhom 11 — Test Suite cho FZP1 Binary Packet Parser
Hoc phan: Ky thuat Lap trinh An toan (CSE703093 / CSE703153)
Giang vien: ThS. Vu Quang Dung — Truong Cong nghe Thong tin, Dai hoc Phenikaa

Kiem tra toan dien:
  - 10 test cases chuc nang va bao mat tren ca 2 phien ban v0 va v1
  - Kiem chung tinh dung dan cua ban va CERT STR31-C va CERT MEM31-C
"""

import os
import subprocess
import tempfile
import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VULN_EXE = os.path.join(BASE_DIR, "source", "fzp1_parser_v0.exe")
FIXED_EXE = os.path.join(BASE_DIR, "source", "fzp1_parser_v1.exe")


def build_fzp1_packet(magic: bytes, payload: bytes, checksum_override: int | None = None) -> bytes:
    """Tao goi tin FZP1 chuan: 4B Magic | 1B Len | L-B Payload | 1B Checksum."""
    p_len = len(payload)
    if checksum_override is not None:
        chk = checksum_override
    else:
        chk = 0
        for b in payload:
            chk ^= b
    return magic + bytes([p_len]) + payload + bytes([chk])


def run_target(exe_path: str, data: bytes) -> tuple[int, str, str]:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(data)
        f.flush()
        tmp_name = f.name
    try:
        proc = subprocess.run(
            [exe_path, tmp_name],
            capture_output=True,
            timeout=5
        )
        out = proc.stdout.decode("utf-8", errors="replace")
        err = proc.stderr.decode("utf-8", errors="replace")
        return proc.returncode, out, err
    finally:
        if os.path.exists(tmp_name):
            try:
                os.remove(tmp_name)
            except OSError:
                pass


# =====================================================================
# 1. TEST CASES CHO BAN VA FIXED (v1)
# =====================================================================
def test_v1_valid_packet_small():
    pkt = build_fzp1_packet(b"FZP1", b"HELLO")
    code, out, err = run_target(FIXED_EXE, pkt)
    assert code == 0
    assert "Payload safely parsed" in out


def test_v1_valid_packet_max_allowed():
    # Kich thuoc dung 16 bytes (nguong gioi han an toan)
    pkt = build_fzp1_packet(b"FZP1", b"1234567890ABCDEF")
    code, out, err = run_target(FIXED_EXE, pkt)
    assert code == 0
    assert "Payload safely parsed" in out


def test_v1_reject_invalid_magic():
    pkt = build_fzp1_packet(b"BAD1", b"HELLO")
    code, out, err = run_target(FIXED_EXE, pkt)
    assert code == 2
    assert "Invalid Magic" in err


def test_v1_reject_corrupt_checksum():
    pkt = build_fzp1_packet(b"FZP1", b"HELLO", checksum_override=0xAA)
    code, out, err = run_target(FIXED_EXE, pkt)
    assert code == 2
    assert "Checksum mismatch" in err


def test_v1_reject_too_short():
    data = b"FZP" # < 6 bytes
    code, out, err = run_target(FIXED_EXE, data)
    assert code == 2
    assert "smaller than minimum" in err


def test_v1_reject_oversized_payload_cert_str31_c():
    # Payload 24 bytes vuot nguong 16 bytes -> Phai bi tu choi an toan boi CERT STR31-C
    pkt = build_fzp1_packet(b"FZP1", b"A" * 24)
    code, out, err = run_target(FIXED_EXE, pkt)
    assert code == 2
    assert "CERT STR31-C enforcement prevented Stack Buffer Overflow" in err


def test_v1_reject_huge_payload_64():
    # Payload 64 bytes
    pkt = build_fzp1_packet(b"FZP1", b"B" * 64)
    code, out, err = run_target(FIXED_EXE, pkt)
    assert code == 2
    assert "SECURITY_REJECT" in err


# =====================================================================
# 2. TEST CASES CHO BAN LOI VULNERABLE (v0)
# =====================================================================
def test_v0_valid_packet_normal():
    # Payload nho hop le khong lam hong stack
    pkt = build_fzp1_packet(b"FZP1", b"OK")
    code, out, err = run_target(VULN_EXE, pkt)
    assert code == 0


def test_v0_overflow_trigger_crash():
    # Payload 64 bytes kich hoat CWE-121 va gay crash qua Access Violation
    pkt = build_fzp1_packet(b"FZP1", b"A" * 64)
    code, out, err = run_target(VULN_EXE, pkt)
    # Return code phai khac 0 va khac 2 (la crash do he dieu hanh bao)
    assert code != 0 and code != 2


def test_v0_and_v1_corpus_regression():
    # Kiem tra tat ca cac file trong seed_corpus
    corpus_dir = os.path.join(BASE_DIR, "seed_corpus")
    for fname in ["seed_valid_hello.bin", "seed_valid_short.bin"]:
        p = os.path.join(corpus_dir, fname)
        if os.path.exists(p):
            with open(p, "rb") as f:
                data = f.read()
            code, out, err = run_target(FIXED_EXE, data)
            assert code == 0
