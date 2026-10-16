"""
BTL Nhom 11 — Test Suite cho FZP1 Binary Packet Parser (Version 0 & Version 1)
Hoc phan: Ky thuat Lap trinh An toan (CSE703093 / CSE703153)
Giang vien: ThS. Vu Quang Dung — Truong Cong nghe Thong tin, Dai hoc Phenikaa

Kiem tra toan dien 3 lo hong thuc te:
  1. CWE-121: Stack-based Buffer Overflow (CERT STR31-C)
  2. CWE-415: Double Free (CERT MEM30-C, MEM31-C)
  3. CWE-416: Use-After-Free (CERT MEM30-C)
"""

import os
import struct
import subprocess
import tempfile
import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VULN_EXE = os.path.join(BASE_DIR, "source", "fzp1_parser_v0.exe")
FIXED_EXE = os.path.join(BASE_DIR, "source", "fzp1_parser_v1.exe")


def build_fzp1_packet(
    magic: bytes = b"FZP1",
    payload: bytes = b"",
    checksum_override: int | None = None,
    length_override: int | None = None
) -> bytes:
    """Tao goi tin FZP1 chuan: 4B Magic | 4B Len uint32 | L-B Payload | 1B Checksum."""
    p_len = len(payload) if length_override is None else length_override
    if checksum_override is not None:
        chk = checksum_override
    else:
        chk = 0
        for b in payload:
            chk ^= b
    return magic + struct.pack("<I", p_len) + payload + bytes([chk])


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
# 1. TEST CASES CHUC NANG VA RAO CAN XAC THUC TREN BAN VA (v1)
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
    data = b"FZP1" + b"\x01\x00\x00\x00" # 8 bytes < 9 bytes
    code, out, err = run_target(FIXED_EXE, data)
    assert code == 2
    assert "smaller than minimum" in err


# =====================================================================
# 2. TEST TAI HIEN LOI 1: CWE-121 (Stack-based Buffer Overflow)
# =====================================================================
def test_v0_cwe121_overflow_trigger_crash():
    # Payload 64 bytes kich hoat CWE-121 lam tran stack frame canary
    pkt = build_fzp1_packet(b"FZP1", b"A" * 64)
    code, out, err = run_target(VULN_EXE, pkt)
    # Returncode khac 0 va khac 2: la crash do he dieu hanh bao (0xC0000005)
    assert code != 0 and code != 2


def test_v1_cwe121_reject_oversized_payload_cert_str31_c():
    # Payload 24 bytes vuot nguong 16 bytes -> Phai bi tu choi an toan boi CERT STR31-C
    pkt = build_fzp1_packet(b"FZP1", b"A" * 24)
    code, out, err = run_target(FIXED_EXE, pkt)
    assert code == 2
    assert "CERT STR31-C" in err


# =====================================================================
# 3. TEST TAI HIEN LOI 2: CWE-415 (Double Free)
# =====================================================================
def test_v0_and_v1_cwe415_double_free_session_abort():
    # Goi tin chua ma 0xFF (CMD_ABORT_SESSION) kich hoat nhanh huy phien som va cleanup 2 lan
    pkt = build_fzp1_packet(b"FZP1", b"\xFF\x01\x02\x03")
    code0, out0, err0 = run_target(VULN_EXE, pkt)
    # v0 bi loi Double Free: tren Windows NTSTATUS la 0xC0000374 (Heap Corruption)
    assert code0 != 0 and code0 != 2

    code1, out1, err1 = run_target(FIXED_EXE, pkt)
    # v1 dat NULL (CERT MEM30-C & MEM31-C) nen phep cleanup lan 2 idempotent an toan
    assert code1 == 2
    assert "CERT MEM30-C" in err1


# =====================================================================
# 4. TEST TAI HIEN LOI 3: CWE-416 (Use-After-Free)
# =====================================================================
def test_v0_and_v1_cwe416_use_after_free_stream_reset():
    # Goi tin chua ma 0xFE (CMD_RESET_STREAM) kich hoat giai phong kenh stream va goi callback lo lung
    pkt = build_fzp1_packet(b"FZP1", b"\xFE\x01\x02\x03")
    code0, out0, err0 = run_target(VULN_EXE, pkt)
    # v0 bi loi Use-After-Free: tren Windows bi Heap Corruption (0xC0000374) hoac Access Violation (0xC0000005)
    assert code0 != 0 and code0 != 2

    code1, out1, err1 = run_target(FIXED_EXE, pkt)
    # v1 thuc thi callback truoc khi free va triet tieu con tro lo lung (CERT MEM30-C)
    assert code1 == 2
    assert "Safely terminating stream" in err1 or "CERT MEM30-C" in err1


# =====================================================================
# 5. TEST HOI QUY TREN SEED CORPUS
# =====================================================================
def test_v0_and_v1_corpus_regression():
    corpus_dir = os.path.join(BASE_DIR, "seed_corpus")
    for fname in ["seed_valid_hello.bin", "seed_valid_short.bin"]:
        p = os.path.join(corpus_dir, fname)
        if os.path.exists(p):
            with open(p, "rb") as f:
                data = f.read()
            code, out, err = run_target(FIXED_EXE, data)
            assert code == 0
