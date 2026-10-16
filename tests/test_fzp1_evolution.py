"""
BTL Nhom 11 — Test Suite Kiem chung Tien hoa Ma nguon FZP1 (v0 -> v0.1 -> v0.2 -> v1)
Hoc phan: Ky thuat Lap trinh An toan (CSE703093 / CSE703153) — DH Phenikaa
Giang vien: ThS. Vu Quang Dung

Kiem chung doc lap 4 moc phien ban ma nguon:
  - MOC 1 (v0): Ton tai CWE-121, CWE-415, CWE-416 (Ca 3 deu crash).
  - MOC 2 (v0.1): Da va CWE-121 (CERT STR31-C: Tu choi an toan ma 2).
                  Van ton tai CWE-415 va CWE-416 (Crash).
  - MOC 3 (v0.2): Da va CWE-121 va CWE-415 (CERT STR31-C & MEM31-C: Tu choi an toan ma 2).
                  Van ton tai CWE-416 (Crash).
  - MOC 4 (v1): Da va toan dien ca 3 loi theo chuan CERT C (100% Tu choi an toan ma 2 hoac xu ly thanh cong ma 0).
"""

import os
import struct
import subprocess
import tempfile
import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V0_EXE = os.path.join(BASE_DIR, "source", "fzp1_parser_v0.exe")
V0_1_EXE = os.path.join(BASE_DIR, "source", "fzp1_parser_v0_1.exe")
V0_2_EXE = os.path.join(BASE_DIR, "source", "fzp1_parser_v0_2.exe")
V1_EXE = os.path.join(BASE_DIR, "source", "fzp1_parser_v1.exe")


def build_fzp1_packet(magic: bytes = b"FZP1", payload: bytes = b"") -> bytes:
    p_len = len(payload)
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


def is_crash(code: int) -> bool:
    """Tren Windows MinGW: code 0 = hop le, 2 = CERT reject, cac ma khac (0xC0000005, 0xC0000374) = crash."""
    return code != 0 and code != 2


# =============================================================================
# 1. KIEM CHUNG TIEN HOA LOI 1: CWE-121 (Stack-based Buffer Overflow)
# =============================================================================
def test_evolution_cwe121_stack_overflow():
    """Payload 64 bytes vuot stack buffer 16 bytes:
    v0: CRASH
    v0.1: TU CHOI AN TOAN (Code = 2, CERT STR31-C)
    v0.2: TU CHOI AN TOAN (Code = 2, CERT STR31-C)
    v1:   TU CHOI AN TOAN (Code = 2, CERT STR31-C)
    """
    pkt = build_fzp1_packet(b"FZP1", b"A" * 64)

    code_v0, _, _ = run_target(V0_EXE, pkt)
    assert is_crash(code_v0), f"v0 phai bi crash CWE-121 nhung tra ve {code_v0}"

    code_v01, _, err_v01 = run_target(V0_1_EXE, pkt)
    assert code_v01 == 2, f"v0.1 phai tu choi an toan nhung tra ve {code_v01}"
    assert "CERT STR31-C" in err_v01

    code_v02, _, err_v02 = run_target(V0_2_EXE, pkt)
    assert code_v02 == 2, f"v0.2 phai tu choi an toan nhung tra ve {code_v02}"
    assert "CERT STR31-C" in err_v02

    code_v1, _, err_v1 = run_target(V1_EXE, pkt)
    assert code_v1 == 2, f"v1 phai tu choi an toan nhung tra ve {code_v1}"
    assert "CERT STR31-C" in err_v1


# =============================================================================
# 2. KIEM CHUNG TIEN HOA LOI 2: CWE-415 (Double Free tren lenh Abort 0xFF)
# =============================================================================
def test_evolution_cwe415_double_free():
    """Goi tin lenh 0xFF (CMD_ABORT_SESSION) gay giai phong kep:
    v0:   CRASH (0xC0000374 Heap corruption)
    v0.1: CRASH (0xC0000374 Heap corruption do chua va con tro NULL)
    v0.2: TU CHOI AN TOAN (Code = 2, CERT MEM30-C/31-C con tro ve NULL)
    v1:   TU CHOI AN TOAN (Code = 2, CERT MEM30-C/31-C con tro ve NULL)
    """
    pkt = build_fzp1_packet(b"FZP1", b"\xFF\x01\x02\x03")

    code_v0, _, _ = run_target(V0_EXE, pkt)
    assert is_crash(code_v0), f"v0 phai bi crash CWE-415 nhung tra ve {code_v0}"

    code_v01, _, _ = run_target(V0_1_EXE, pkt)
    assert is_crash(code_v01), f"v0.1 phai bi crash CWE-415 nhung tra ve {code_v01}"

    code_v02, _, _ = run_target(V0_2_EXE, pkt)
    assert code_v02 == 2, f"v0.2 phai xu ly an toan nhung tra ve {code_v02}"

    code_v1, _, _ = run_target(V1_EXE, pkt)
    assert code_v1 == 2, f"v1 phai xu ly an toan nhung tra ve {code_v1}"


# =============================================================================
# 3. KIEM CHUNG TIEN HOA LOI 3: CWE-416 (Use-After-Free tren lenh Reset 0xFE)
# =============================================================================
def test_evolution_cwe416_use_after_free():
    """Goi tin lenh 0xFE (CMD_RESET_STREAM) gay truy cap con tro lo lung:
    v0:   CRASH (0xC0000374 / 0xC0000005)
    v0.1: CRASH (0xC0000374 / 0xC0000005)
    v0.2: CRASH (0xC0000374 / 0xC0000005 do chua dao thu tu callback)
    v1:   TU CHOI AN TOAN (Code = 2, CERT MEM30-C callback truoc khi free)
    """
    pkt = build_fzp1_packet(b"FZP1", b"\xFE\x01\x02\x03")

    code_v0, _, _ = run_target(V0_EXE, pkt)
    assert is_crash(code_v0), f"v0 phai bi crash CWE-416 nhung tra ve {code_v0}"

    code_v01, _, _ = run_target(V0_1_EXE, pkt)
    assert is_crash(code_v01), f"v0.1 phai bi crash CWE-416 nhung tra ve {code_v01}"

    code_v02, _, _ = run_target(V0_2_EXE, pkt)
    assert is_crash(code_v02), f"v0.2 phai bi crash CWE-416 nhung tra ve {code_v02}"

    code_v1, _, _ = run_target(V1_EXE, pkt)
    assert code_v1 == 2, f"v1 phai xu ly an toan nhung tra ve {code_v1}"


# =============================================================================
# 4. KIEM CHUNG TINH TOAN VEN HOI QUY TREN GOI TIN HOP LE
# =============================================================================
def test_evolution_valid_telemetry_packet():
    """Goi tin telemetry hop le 16 bytes:
    Ca 4 phien ban deu phai xu ly thanh cong (Code = 0).
    """
    pkt = build_fzp1_packet(b"FZP1", b"TEMP:28C;HUM:65%")
    for exe, label in [(V0_EXE, "v0"), (V0_1_EXE, "v0.1"), (V0_2_EXE, "v0.2"), (V1_EXE, "v1")]:
        code, out, _ = run_target(exe, pkt)
        assert code == 0, f"{label} phai xu ly thanh cong goi tin hop le nhung tra ve {code}"
        assert "Payload safely parsed" in out or "Payload copied successfully" in out
