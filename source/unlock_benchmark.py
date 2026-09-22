"""
BTL Nhom 11 — Unlock Benchmark (bai toan co lap rao can 32-bit code)
=====================================================================
So sanh:
  - Black-box: random 2 so u16, do so lan thu de trung (7421, 3390).
  - White-box: Z3 giai truc tiep.
"""
from __future__ import annotations
import os
import random
import struct
import subprocess
import tempfile
import time

from z3 import BitVec, Solver, sat

from packet_builder import build_unlock_packet

BTL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARSER = os.path.join(BTL_DIR, "source", "parser_vuln.exe" if os.name == "nt" else "parser_vuln")

TARGET_A = 7421
TARGET_B = 3390


def blackbox_unlock_trial(budget: int = 100000, seed: int = 0) -> dict:
    """Random brute-force: thu tung cap (unlock_a, unlock_b) ngau nhien."""
    rng = random.Random(seed)
    start = time.time()

    for i in range(budget):
        a = rng.randint(0, 0xFFFF)
        b = rng.randint(0, 0xFFFF)
        if a == TARGET_A and b == TARGET_B:
            elapsed = time.time() - start
            return {"found": True, "iteration": i, "time": round(elapsed, 6)}

    elapsed = time.time() - start
    return {"found": False, "iteration": budget, "time": round(elapsed, 6)}


def whitebox_unlock_solve() -> dict:
    """Z3 giai truc tiep rang buoc unlock_a == 7421 AND unlock_b == 3390."""
    s = Solver()
    a = BitVec("unlock_a", 16)
    b = BitVec("unlock_b", 16)
    s.add(a == TARGET_A)
    s.add(b == TARGET_B)

    start = time.time()
    result = s.check()
    elapsed = time.time() - start

    if result == sat:
        model = s.model()
        return {
            "found": True,
            "unlock_a": model[a].as_long(),
            "unlock_b": model[b].as_long(),
            "time": round(elapsed, 6),
        }
    return {"found": False, "time": round(elapsed, 6)}


def verify_unlock_on_target(unlock_a: int, unlock_b: int) -> bool:
    """Xac nhan goi Unlock hop le chay thanh cong tren parser."""
    pkt = build_unlock_packet(unlock_a=unlock_a, unlock_b=unlock_b)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(pkt)
        f.flush()
        tmp_name = f.name
    try:
        r = subprocess.run([PARSER, tmp_name], capture_output=True, text=True, timeout=5)
    finally:
        if os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except Exception:
                pass
    return r.returncode == 0 and "[OK] Unlock" in r.stdout


def run_benchmark(n_trials: int = 30, budget_per_trial: int = 500000) -> dict:
    """Chay benchmark unlock: 30 trials blackbox + 1 lan whitebox."""
    # White-box: giai 1 lan
    wb = whitebox_unlock_solve()

    # Xac nhan tren target
    if wb["found"]:
        wb["target_verified"] = verify_unlock_on_target(wb["unlock_a"], wb["unlock_b"])

    # Black-box: 30 trials
    bb_results = []
    for s in range(n_trials):
        r = blackbox_unlock_trial(budget=budget_per_trial, seed=s)
        bb_results.append(r)

    # Thong ke
    found_trials = [r for r in bb_results if r["found"]]
    success_rate = len(found_trials) / n_trials
    iterations = [r["iteration"] for r in found_trials] if found_trials else []

    # Xac suat ly thuyet
    p_per_trial = 1 / (65536 * 65536)  # 1 / 2^32
    expected_trials = int(1 / p_per_trial)

    return {
        "whitebox": wb,
        "blackbox": {
            "n_trials": n_trials,
            "budget_per_trial": budget_per_trial,
            "success_rate": success_rate,
            "found_count": len(found_trials),
            "iterations_when_found": iterations,
            "theoretical_probability": p_per_trial,
            "theoretical_expected_trials": expected_trials,
        },
    }


if __name__ == "__main__":
    print("=== Unlock Benchmark: Black-box vs Z3 ===\n")

    wb = whitebox_unlock_solve()
    print(f"White-box (Z3):")
    print(f"  Found: {wb['found']}")
    print(f"  Time: {wb['time']}s")
    if wb["found"]:
        print(f"  unlock_a={wb['unlock_a']}, unlock_b={wb['unlock_b']}")
        v = verify_unlock_on_target(wb["unlock_a"], wb["unlock_b"])
        print(f"  Target verified: {v}")

    print(f"\nBlack-box (5 trials, 100K budget each):")
    for s in range(5):
        r = blackbox_unlock_trial(budget=100000, seed=s)
        print(f"  Seed {s}: found={r['found']}, iterations={r['iteration']}, time={r['time']}s")

    p = 1 / (65536 * 65536)
    print(f"\nXac suat ly thuyet: P = 1/2^32 = {p:.3e}")
    print(f"So lan thu ky vong: {int(1/p):,}")
