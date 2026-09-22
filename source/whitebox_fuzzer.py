"""
BTL Nhom 11 — White-box Fuzzer (Z3 SMT Solver)
================================================
Chuong 4, muc 4.6: Kiem thu hop trang.
Chuong 3: Ung dung Z3 giai path predicate.

Dung Z3 mo hinh hoa rang buoc duong di (path predicate) de sinh TRUC TIEP
goi nhi phan hop le vuot qua moi rao can (magic, version, checksum,
device_id_len=24) va kich hoat crash CWE-121.
"""
from __future__ import annotations
import json
import os
import struct
import subprocess
import tempfile
import time

from z3 import BitVec, BitVecVal, ZeroExt, Solver, sat

from packet_builder import (
    HEADER_SIZE, CHECKSUM_SIZE, HEADER_FORMAT,
    TYPE_REGISTRATION, compute_checksum,
)

BTL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARSER = os.path.join(BTL_DIR, "src", "parser_vuln")
CRASH_DIR = os.path.join(BTL_DIR, "crashes")


def z3_solve_crash_packet(device_id_len: int = 24) -> dict:
    """Dung Z3 giai nguoc path predicate de sinh goi crash.

    Path predicate:
      1. magic == "IGW1"
      2. version == 1
      3. type == 0x01 (Registration)
      4. flags == 0, reserved == 0
      5. device_id_len == 24 (trigger CWE-121)
      6. payload_len >= device_id_len
      7. Payload bytes 0..23 la ASCII uppercase (0x41..0x5A)
      8. checksum == sum(header + payload) mod 2^32
    """
    s = Solver()

    # --- Header fields ---
    # magic is fixed: "IGW1"
    magic = b"IGW1"
    version = 1
    pkt_type = TYPE_REGISTRATION
    flags = 0
    reserved = 0
    payload_len = device_id_len  # vua du de trigger

    # --- Symbolic payload bytes (device_id) ---
    payload_bytes = []
    for i in range(device_id_len):
        b = BitVec(f"payload_{i}", 8)
        s.add(b >= 0x41)  # ASCII uppercase A
        s.add(b <= 0x5A)  # ASCII uppercase Z
        payload_bytes.append(b)

    # --- Pack header concretely ---
    header = struct.pack(
        HEADER_FORMAT,
        magic, version, pkt_type, device_id_len, flags,
        payload_len, 0, 0, reserved,  # unlock_a=0, unlock_b=0
    )
    header_bytes_concrete = list(header)

    # --- Checksum constraint ---
    # checksum = sum(header_bytes + payload_bytes) mod 2^32
    # We compute header sum concretely and add symbolic payload sum
    header_sum = sum(header_bytes_concrete)

    # Sum of symbolic payload bytes (promote to 32-bit to avoid overflow)
    payload_sum = BitVecVal(0, 32)
    for b in payload_bytes:
        payload_sum = payload_sum + ZeroExt(24, b)
    total_sum = BitVecVal(header_sum, 32) + payload_sum

    # checksum is a symbolic 32-bit value
    checksum_sym = BitVec("checksum", 32)
    s.add(checksum_sym == total_sum)

    # --- Solve ---
    solve_start = time.time()
    result = s.check()
    solve_time = time.time() - solve_start

    if result != sat:
        return {"status": "unsat", "solve_time": solve_time}

    model = s.model()

    # Extract concrete payload bytes
    payload = bytes(model[b].as_long() for b in payload_bytes)

    # Extract checksum
    checksum_val = model[checksum_sym].as_long()
    checksum_bytes = struct.pack("<I", checksum_val)

    # Assemble full packet
    packet = header + payload + checksum_bytes

    # Verify checksum locally
    computed = compute_checksum(header + payload)
    assert computed == checksum_val, f"Checksum mismatch: {computed} vs {checksum_val}"

    return {
        "status": "sat",
        "solve_time": round(solve_time, 6),
        "packet": packet,
        "packet_hex": packet.hex(),
        "payload_ascii": payload.decode("ascii"),
        "checksum": f"0x{checksum_val:08x}",
    }


def get_target_binary() -> str:
    candidates = [
        os.path.join(BTL_DIR, "source", "parser_vuln.exe"),
        os.path.join(BTL_DIR, "source", "parser_vuln"),
        os.path.join(BTL_DIR, "src", "parser_vuln.exe"),
        os.path.join(BTL_DIR, "src", "parser_vuln"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return os.path.join(BTL_DIR, "source", "parser_vuln.exe" if os.name == "nt" else "parser_vuln")

def run_target(packet: bytes, timeout: float = 5.0) -> subprocess.CompletedProcess | None:
    """Ghi goi vao file tam, chay parser, tra ve ket qua."""
    target_bin = get_target_binary()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(packet)
        f.flush()
        tmp_path = f.name
    try:
        result = subprocess.run(
            [target_bin, tmp_path],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
    return result


def is_asan_crash(result: subprocess.CompletedProcess | None) -> bool:
    if result is None:
        return False
    stderr = result.stderr or ""
    return (result.returncode != 0 and "AddressSanitizer" in stderr
            and "stack-buffer-overflow" in stderr and "gateway_parser" in stderr)


def fuzz(budget: int = 5000, seed: int = 42, timeout: float = 5.0) -> dict:
    """White-box fuzzer: Z3 tao mot input dai dien va xac nhan mot unique crash.

    ``budget`` la ngan sach toi da dung chung voi black-box, khong phai yeu
    cau tao 5,000 bien the cung mot loi. Giu mot crash dai dien tranh lam
    phong dai ket qua bang hang nghin ban sao cua cung stack trace.
    """
    crashes = []
    start_time = time.time()

    # Buoc 1: Z3 giai path predicate
    z3_result = z3_solve_crash_packet(device_id_len=24)
    z3_time = z3_result.get("solve_time", 0)

    if z3_result["status"] != "sat":
        elapsed = time.time() - start_time
        return {
            "fuzzer": "whitebox",
            "seed": seed,
            "budget": budget,
            "iterations_used": 0,
            "wall_time_seconds": round(elapsed, 3),
            "exec_per_sec": 0,
            "z3_solve_time": z3_time,
            "first_crash_at": None,
            "time_to_first_crash_seconds": None,
            "total_crashes": 0,
            "crashes": [],
        }

    base_packet = z3_result["packet"]

    # Buoc 2: Chay target voi goi Z3 sinh ra
    iteration = 0
    result = run_target(base_packet, timeout=timeout)
    first_crash_time = None
    if is_asan_crash(result):
        first_crash_time = time.time() - start_time
        crash_path = os.path.join(CRASH_DIR, f"whitebox_s{seed}_crash_0.bin")
        with open(crash_path, "wb") as f:
            f.write(base_packet)

        sig_lines = [ln for ln in result.stderr.split("\n")
                     if ln.strip().startswith("#0")]
        signature = sig_lines[0].strip() if sig_lines else "unknown"

        crashes.append({
            "iteration": 0,
            "input_hex": base_packet.hex(),
            "saved_to": crash_path,
            "asan_signature": signature,
            "method": "z3_direct",
        })

    elapsed = time.time() - start_time
    return {
        "fuzzer": "whitebox",
        "seed": seed,
        "budget": budget,
        "iterations_used": 1,
        "wall_time_seconds": round(elapsed, 6),
        "exec_per_sec": round(1 / elapsed, 1) if elapsed > 0 else 0,
        "z3_solve_time": z3_time,
        "first_crash_at": crashes[0]["iteration"] if crashes else None,
        "time_to_first_crash_seconds": round(first_crash_time, 6) if first_crash_time is not None else None,
        "total_crashes": len(crashes),
        "crashes": crashes,
    }


if __name__ == "__main__":
    os.makedirs(CRASH_DIR, exist_ok=True)

    print("== Buoc 1: Z3 giai path predicate ==")
    z3r = z3_solve_crash_packet()
    print(f"  Status: {z3r['status']}")
    print(f"  Thoi gian Z3: {z3r.get('solve_time', '?')}s")
    if z3r["status"] == "sat":
        print(f"  Payload ASCII: {z3r['payload_ascii']}")
        print(f"  Checksum: {z3r['checksum']}")
        print(f"  Packet hex: {z3r['packet_hex']}")

        print("\n== Buoc 2: Xac nhan crash ==")
        r = run_target(z3r["packet"])
        print(f"  Exit code: {r.returncode if r else 'timeout'}")
        print(f"  ASan crash: {is_asan_crash(r)}")

    print("\n== Buoc 3: Chay full fuzzer (100 inputs demo) ==")
    result = fuzz(budget=100, seed=0)
    print(f"Thoi gian: {result['wall_time_seconds']}s")
    print(f"Z3 solve: {result['z3_solve_time']}s")
    print(f"Crash dau tien tai: {result['first_crash_at']}")
    print(f"Tong crash: {result['total_crashes']}")
