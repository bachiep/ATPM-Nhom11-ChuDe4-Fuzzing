"""
BTL Nhom 11 — FZP1 Unlock Token Benchmark
Hoc phan: Ky thuat Lap trinh An toan (CSE703093 / CSE703153)
Giang vien: ThS. Vu Quang Dung — Truong Cong nghe Thong tin, Dai hoc Phenikaa

Khao sat bai toan khoa bi mat (Magic Constant / Secret Token Equality):
  verify_fzp1_unlock_token(token_a, token_b):
    if token_a == 18010 and token_b == 20529:
      return 1 // SUCCESS
    return 0

So sanh:
  - White-box (Z3 SMT Solver): Giai he phuong trinh so hoc Bit-Vector 16-bit
  - Black-box (Random Brute-force): Thu ngau nhien trong khong gian 2^32 (65536 x 65536)
"""

import json
import os
import random
import time
from z3 import BitVec, BitVecVal, Solver, sat

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "results", "data_raw")
os.makedirs(DATA_DIR, exist_ok=True)

TOKEN_A_TARGET = 18010
TOKEN_B_TARGET = 20529
N_TRIALS = 30
BUDGET_PER_TRIAL = 100_000


def solve_whitebox():
    start = time.time()
    s = Solver()
    ta = BitVec("ta", 16)
    tb = BitVec("tb", 16)
    s.add(ta == BitVecVal(TOKEN_A_TARGET, 16))
    s.add(tb == BitVecVal(TOKEN_B_TARGET, 16))

    res = s.check()
    m = s.model() if res == sat else None
    solve_time = time.time() - start
    return {
        "status": str(res),
        "time": round(solve_time, 6),
        "model": {"token_a": m[ta].as_long(), "token_b": m[tb].as_long()} if m else None,
        "iterations": 1
    }


def solve_blackbox(seed: int, budget: int = BUDGET_PER_TRIAL):
    rng = random.Random(seed)
    start = time.time()
    found = False
    tries = 0
    for i in range(1, budget + 1):
        cand_a = rng.randint(0, 65535)
        cand_b = rng.randint(0, 65535)
        if cand_a == TOKEN_A_TARGET and cand_b == TOKEN_B_TARGET:
            found = True
            tries = i
            break
    elapsed = time.time() - start
    return {
        "seed": seed,
        "found": found,
        "tries": tries if found else budget,
        "time": round(elapsed, 4)
    }


def main():
    print("=== Running FZP1 Unlock Token Benchmark ===")
    # 1. Whitebox
    wb_res = solve_whitebox()
    print(f"Whitebox (Z3): {wb_res['status']} in {wb_res['time']*1000:.2f}ms -> {wb_res['model']}")

    # 2. Blackbox (30 trials)
    bb_trials = []
    found_count = 0
    total_time = 0
    for s in range(N_TRIALS):
        r = solve_blackbox(s, BUDGET_PER_TRIAL)
        bb_trials.append(r)
        if r["found"]:
            found_count += 1
        total_time += r["time"]

    print(f"Blackbox: Found {found_count}/{N_TRIALS} trials (budget: {BUDGET_PER_TRIAL:,} tries/trial)")

    theoretical_prob = 1.0 / (65536.0 * 65536.0)
    expected_tries = int(1.0 / theoretical_prob)

    out = {
        "whitebox": wb_res,
        "blackbox": {
            "n_trials": N_TRIALS,
            "budget_per_trial": BUDGET_PER_TRIAL,
            "found_count": found_count,
            "success_rate": found_count / N_TRIALS,
            "theoretical_probability": theoretical_prob,
            "theoretical_expected_trials": expected_tries,
            "total_time_seconds": round(total_time, 4),
            "trials": bb_trials
        }
    }

    out_file = os.path.join(DATA_DIR, "unlock_results.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"Saved unlock benchmark results to {out_file}")


if __name__ == "__main__":
    main()
