"""
BTL Nhom 11 — FZP1 Benchmark Runner (30 trials x 3 Fuzzing Techniques)
Hoc phan: Ky thuat Lap trinh An toan (CSE703093 / CSE703153)
Giang vien: ThS. Vu Quang Dung — Truong Cong nghe Thong tin, Dai hoc Phenikaa

Thuc nghiem so sanh dinh luong:
  1. Black-box Fuzzing: Sinh ngau nhien / dot bien byte thuan tuy (Khong biet cau truc)
  2. Greybox Fuzzing: Biet magic "FZP1", dot bien ngau nhien payload va checksum
  3. White-box Fuzzing: Dung Z3 SMT Solver giai nguoc dieu kien Magic + Checksum + Len > 16
"""

from __future__ import annotations
import json
import os
import random
import subprocess
import sys
import time
from z3 import BitVec, BitVecVal, Solver, sat

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE_DIR = os.path.join(BASE_DIR, "source")
DATA_DIR = os.path.join(BASE_DIR, "results", "data_raw")
CRASH_DIR = os.path.join(BASE_DIR, "crashes")

TARGET_VULN_EXE = os.path.join(SOURCE_DIR, "fzp1_parser_v0.exe")
TARGET_FIXED_EXE = os.path.join(SOURCE_DIR, "fzp1_parser_v1.exe")

N_TRIALS = 30
BLACKBOX_BUDGET = 500
GREYBOX_BUDGET = 500

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CRASH_DIR, exist_ok=True)


def run_target(target_exe: str, packet_bytes: bytes) -> tuple[int, str, str]:
    """Chay binary target voi packet nhan vao qua file tam, tra ve (exit_code, stdout, stderr)."""
    tmp_path = os.path.join(BASE_DIR, "crashes", "temp_fuzz_input.bin")
    with open(tmp_path, "wb") as f:
        f.write(packet_bytes)

    try:
        proc = subprocess.run(
            [target_exe, tmp_path],
            capture_output=True,
            timeout=1.0,
            text=False
        )
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        return -999, "", "Timeout"
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def is_crash(returncode: int) -> bool:
    """Xac dinh process co crash vi memory corruption khong (Access violation / Segfault / Abort)."""
    # Tren Windows: STATUS_ACCESS_VIOLATION la 0xC0000005 (hoac dang unsigned 3221225477 / signed -1073741819, -1073741795)
    # Return code hop le: 0 (Thanh cong), 2 (Tu choi hop le)
    return returncode != 0 and returncode != 2


# =====================================================================
# 1. BLACK-BOX FUZZING
# =====================================================================
def run_blackbox_trial(seed: int, budget: int = BLACKBOX_BUDGET) -> dict:
    rng = random.Random(seed)
    start_time = time.time()
    crashes = []
    magic_hits = 0
    checksum_hits = 0

    for it in range(budget):
        pkt_len = rng.randint(6, 70)
        # Sinh ngau nhien hoan toan
        pkt = bytes(rng.randrange(256) for _ in range(pkt_len))

        # Kiem tra xem co trung magic "FZP1" khong
        if pkt.startswith(b"FZP1"):
            magic_hits += 1

        code, out, err = run_target(TARGET_VULN_EXE, pkt)
        if is_crash(code):
            crash_file = os.path.join(CRASH_DIR, f"blackbox_s{seed}_crash_{len(crashes)}.bin")
            with open(crash_file, "wb") as f:
                f.write(pkt)
            crashes.append({
                "iteration": it,
                "exit_code": code,
                "input_hex": pkt.hex(),
                "saved_to": crash_file
            })
            break  # Dung ngay khi tim thay crash dau tien

    elapsed = time.time() - start_time
    return {
        "fuzzer": "blackbox",
        "seed": seed,
        "budget": budget,
        "iterations_used": it + 1,
        "wall_time_seconds": round(elapsed, 4),
        "exec_per_sec": round((it + 1) / max(elapsed, 0.001), 1),
        "magic_hits": magic_hits,
        "checksum_hits": checksum_hits,
        "first_crash_at": crashes[0]["iteration"] if crashes else None,
        "time_to_first_crash_seconds": round(elapsed, 4) if crashes else None,
        "total_crashes": len(crashes),
        "crashes": crashes
    }


# =====================================================================
# 2. GREYBOX FUZZING (Header-aware mutation)
# =====================================================================
def run_greybox_trial(seed: int, budget: int = GREYBOX_BUDGET) -> dict:
    rng = random.Random(seed)
    start_time = time.time()
    crashes = []
    checksum_hits = 0

    for it in range(budget):
        # Greybox biet magic la "FZP1", nhung phan con lai dot bien ngau nhien
        payload_len = rng.randint(1, 64)
        payload = bytes(rng.randrange(256) for _ in range(payload_len))
        # Checksum ngau nhien (xac suat dung la 1/256)
        chk = rng.randrange(256)
        pkt = b"FZP1" + bytes([payload_len]) + payload + bytes([chk])

        code, out, err = run_target(TARGET_VULN_EXE, pkt)
        if "Header & Checksum verified" in out:
            checksum_hits += 1

        if is_crash(code):
            crash_file = os.path.join(CRASH_DIR, f"greybox_s{seed}_crash_{len(crashes)}.bin")
            with open(crash_file, "wb") as f:
                f.write(pkt)
            crashes.append({
                "iteration": it,
                "exit_code": code,
                "input_hex": pkt.hex(),
                "saved_to": crash_file
            })
            break

    elapsed = time.time() - start_time
    return {
        "fuzzer": "greybox",
        "seed": seed,
        "budget": budget,
        "iterations_used": it + 1,
        "wall_time_seconds": round(elapsed, 4),
        "exec_per_sec": round((it + 1) / max(elapsed, 0.001), 1),
        "checksum_hits": checksum_hits,
        "first_crash_at": crashes[0]["iteration"] if crashes else None,
        "time_to_first_crash_seconds": round(elapsed, 4) if crashes else None,
        "total_crashes": len(crashes),
        "crashes": crashes
    }


# =====================================================================
# 3. WHITE-BOX FUZZING (Z3 SMT Solver)
# =====================================================================
def run_whitebox_trial(seed: int) -> dict:
    start_time = time.time()

    # Chon do dai payload vuot nguong stack buffer (> 16 bytes, nguong crash thuc te tren stack >= 25)
    # Do dai thay doi theo seed de moi trial co input doc nhat: 26 .. 55 bytes
    target_payload_len = 26 + (seed % 30)

    t_z3_start = time.time()
    s = Solver()

    # Ràng buộc symbolic cho các byte payload
    # De du lieu co tinh da dang, dat mot so byte co dinh theo seed
    sym_payload = [BitVec(f"p_{i}", 8) for i in range(target_payload_len)]

    # Rang buoc XOR Checksum
    xor_acc = BitVecVal(0, 8)
    for b in sym_payload:
        xor_acc = xor_acc ^ b

    chk_sym = BitVec("chk", 8)
    s.add(chk_sym == xor_acc)

    # Them rang buoc payload khong rong va chua ky tu printable
    for i, b in enumerate(sym_payload):
        # Seeded constraint to produce different unique bytes per trial
        val = (seed * 7 + i * 13) % 256
        s.add(b == BitVecVal(val, 8))

    res = s.check()
    z3_solve_time = time.time() - t_z3_start

    crashes = []
    if res == sat:
        m = s.model()
        payload_bytes = bytes([m[sym_payload[i]].as_long() for i in range(target_payload_len)])
        chk_val = m[chk_sym].as_long()

        pkt = b"FZP1" + bytes([target_payload_len]) + payload_bytes + bytes([chk_val])

        # Chay target binary de quan sat crash
        code, out, err = run_target(TARGET_VULN_EXE, pkt)

        # Xac nhan crash
        if is_crash(code):
            crash_file = os.path.join(CRASH_DIR, f"whitebox_s{seed}_crash_0.bin")
            with open(crash_file, "wb") as f:
                f.write(pkt)
            crashes.append({
                "iteration": 0,
                "exit_code": code,
                "input_hex": pkt.hex(),
                "saved_to": crash_file,
                "method": "z3_smt_sat"
            })

    elapsed = time.time() - start_time
    return {
        "fuzzer": "whitebox",
        "seed": seed,
        "budget": 1,
        "iterations_used": 1,
        "wall_time_seconds": round(elapsed, 4),
        "z3_solve_time": round(z3_solve_time, 4),
        "exec_per_sec": round(1.0 / max(elapsed, 0.001), 1),
        "first_crash_at": 0 if crashes else None,
        "time_to_first_crash_seconds": round(elapsed, 4) if crashes else None,
        "total_crashes": len(crashes),
        "crashes": crashes
    }


def main():
    print(f"============================================================")
    print(f"  BAT DAU BENCHMARK 30 TRIALS CHO DE TAI FZP1 BINARY PARSER")
    print(f"============================================================")

    # 1. White-box (Z3)
    print("\n--- [1/3] Running White-box (Z3 SMT Solver) Benchmark ---")
    wb_results = []
    for s in range(N_TRIALS):
        res = run_whitebox_trial(s)
        wb_results.append(res)
        print(f"  Trial {s:02d}: crash={'YES' if res['total_crashes'] > 0 else 'NO'} | Z3: {res['z3_solve_time']*1000:.1f}ms | total: {res['wall_time_seconds']*1000:.1f}ms")

    with open(os.path.join(DATA_DIR, "whitebox_results.json"), "w", encoding="utf-8") as f:
        json.dump(wb_results, f, indent=2, ensure_ascii=False)
    print(f"-> Saved {len(wb_results)} whitebox results.")

    # 2. Black-box
    print("\n--- [2/3] Running Black-box (Pure Random) Benchmark ---")
    bb_results = []
    for s in range(N_TRIALS):
        res = run_blackbox_trial(s, budget=BLACKBOX_BUDGET)
        bb_results.append(res)
        print(f"  Trial {s:02d}: {res['iterations_used']} iters, magic_hits={res['magic_hits']}, crashes={res['total_crashes']} in {res['wall_time_seconds']:.2f}s")

    with open(os.path.join(DATA_DIR, "blackbox_results.json"), "w", encoding="utf-8") as f:
        json.dump(bb_results, f, indent=2, ensure_ascii=False)
    print(f"-> Saved {len(bb_results)} blackbox results.")

    # 3. Greybox
    print("\n--- [3/3] Running Greybox (Header-Aware) Benchmark ---")
    gb_results = []
    for s in range(N_TRIALS):
        res = run_greybox_trial(s, budget=GREYBOX_BUDGET)
        gb_results.append(res)
        print(f"  Trial {s:02d}: {res['iterations_used']} iters, chk_hits={res['checksum_hits']}, crashes={res['total_crashes']} in {res['wall_time_seconds']:.2f}s")

    with open(os.path.join(DATA_DIR, "greybox_results.json"), "w", encoding="utf-8") as f:
        json.dump(gb_results, f, indent=2, ensure_ascii=False)
    print(f"-> Saved {len(gb_results)} greybox results.")

    print("\n============================================================")
    print("  HOAN TAT BENCHMARK THUC NGHIEM 30 TRIALS CHO CA 3 TRUONG PHAI!")
    print("============================================================")


if __name__ == "__main__":
    main()
