"""
BTL Nhom 11 — Black-box Fuzzer
===============================
Chuong 4, muc 4.5: Kiem thu hop den.

Generator cau truc-aware: tao goi nhi phan voi header, payload va checksum
hop le NHUNG chon magic 4 byte NGAU NHIEN. Khong co "IGW1" trong dictionary
hay seed, khong doc coverage, khong doc ma nguon.
"""
from __future__ import annotations
import json
import os
import random
import subprocess
import tempfile
import time

from packet_builder import (
    build_packet, HEADER_SIZE, CHECKSUM_SIZE,
    TYPE_REGISTRATION, TYPE_UNLOCK,
)

BTL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARSER = os.path.join(BTL_DIR, "src", "parser_vuln")
CRASH_DIR = os.path.join(BTL_DIR, "crashes")


def random_magic(rng: random.Random) -> bytes:
    """Sinh 4 byte ngau nhien, bao gom ca kha nang rat nho trung magic that.

    Fuzzer khong co dictionary hay secret ``IGW1``; viec cho phep trung la can
    thiet de ket qua "khong tim thay" co y nghia xac suat, khong phai bi ep.
    """
    return bytes(rng.randint(0, 255) for _ in range(4))


def generate_random_packet(rng: random.Random) -> bytes:
    """Sinh crash profile hop le va chi random hoa magic khong cong khai."""
    magic = random_magic(rng)
    device_id_len = 24
    payload = bytes(rng.randint(0x41, 0x5A) for _ in range(device_id_len))

    return build_packet(
        magic=magic,
        version=1,
        pkt_type=TYPE_REGISTRATION,
        device_id_len=device_id_len,
        flags=0,
        unlock_a=0,
        unlock_b=0,
        reserved=0,
        payload=payload,
    )


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
    """Chay black-box fuzzer voi ngan sach cho truoc."""
    rng = random.Random(seed)
    crashes = []
    first_crash_time = None
    start_time = time.time()
    iterations_used = 0

    for i in range(budget):
        iterations_used = i + 1
        packet = generate_random_packet(rng)
        result = run_target(packet, timeout=timeout)

        if is_asan_crash(result):
            if first_crash_time is None:
                first_crash_time = time.time() - start_time
            crash_id = len(crashes)
            crash_path = os.path.join(CRASH_DIR, f"blackbox_s{seed}_crash_{crash_id}.bin")
            with open(crash_path, "wb") as f:
                f.write(packet)

            # Lay ASan stack signature (dong dau tien cua stack trace)
            sig_lines = [ln for ln in result.stderr.split("\n")
                         if ln.strip().startswith("#0")]
            signature = sig_lines[0].strip() if sig_lines else "unknown"

            crashes.append({
                "iteration": i,
                "input_hex": packet.hex(),
                "saved_to": crash_path,
                "asan_signature": signature,
            })
            break

    elapsed = time.time() - start_time
    return {
        "fuzzer": "blackbox",
        "seed": seed,
        "budget": budget,
        "iterations_used": iterations_used,
        "wall_time_seconds": round(elapsed, 3),
        "exec_per_sec": round(iterations_used / elapsed, 1) if elapsed > 0 else 0,
        "first_crash_at": crashes[0]["iteration"] if crashes else None,
        "time_to_first_crash_seconds": round(first_crash_time, 6) if first_crash_time is not None else None,
        "total_crashes": len(crashes),
        "crashes": crashes,
    }


if __name__ == "__main__":
    os.makedirs(CRASH_DIR, exist_ok=True)
    result = fuzz(budget=5000, seed=42)
    print(f"=== Black-box Fuzzer: {result['budget']} inputs, seed={result['seed']} ===")
    print(f"Thoi gian: {result['wall_time_seconds']}s ({result['exec_per_sec']} exec/s)")
    print(f"Crash dau tien tai: {result['first_crash_at']}")
    print(f"Tong crash: {result['total_crashes']}")
    for c in result["crashes"][:5]:
        print(f"  Lan {c['iteration']}: {c['saved_to']}")
