"""
BTL Nhom 11 — Run Benchmark (30 trials x 3 fuzzers)
=====================================================
Chay 30 trials (seed 0..29) cho moi fuzzer, ghi raw JSON vao data/raw/.
Ghi dan (append) de khong mat du lieu neu gian doan.

Luu y: Greybox chay tuan tu vi gcov file contention.
"""
from __future__ import annotations
import json
import os
import sys
import time

BTL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BTL_DIR, "fuzzers"))

from blackbox_fuzzer import fuzz as blackbox_fuzz   # noqa: E402
from whitebox_fuzzer import fuzz as whitebox_fuzz   # noqa: E402
from greybox_fuzzer import fuzz as greybox_fuzz     # noqa: E402
from unlock_benchmark import run_benchmark as run_unlock  # noqa: E402

DATA_DIR = os.path.join(BTL_DIR, "data", "raw")
CRASH_DIR = os.path.join(BTL_DIR, "crashes")
N_TRIALS = 30
BUDGET = 5000


def save_result(filepath: str, result: dict) -> None:
    """Checkpoint atomically after each trial so an interruption is recoverable."""
    results = []
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            try:
                results = json.load(f)
            except json.JSONDecodeError:
                results = []
    results.append(result)
    temp_path = f"{filepath}.tmp"
    with open(temp_path, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    os.replace(temp_path, filepath)


def run_fuzzer_benchmark(fuzzer_name: str, fuzz_fn, filepath: str) -> None:
    """Chay N_TRIALS cho 1 fuzzer, ghi ket qua dan dan."""
    # Kiem tra so trial da chay
    existing = []
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            try:
                existing = json.load(f)
            except json.JSONDecodeError:
                existing = []
    done_seeds = {r.get("seed") for r in existing}

    print(f"\n{'='*60}")
    print(f"  {fuzzer_name.upper()} BENCHMARK: {N_TRIALS} trials, {BUDGET} inputs/trial")
    print(f"  Da chay: {len(done_seeds)} trial(s)")
    print(f"{'='*60}")

    for seed in range(N_TRIALS):
        if seed in done_seeds:
            print(f"  [SKIP] Trial {seed} da chay truoc do")
            continue

        print(f"  [RUN ] Trial {seed}/{N_TRIALS-1} ...", end=" ", flush=True)
        start = time.time()
        result = fuzz_fn(budget=BUDGET, seed=seed)
        elapsed = time.time() - start

        # Luu ngay sau moi trial
        save_result(filepath, result)

        crash_info = (f"crash@{result['first_crash_at']}"
                      if result.get('first_crash_at') is not None
                      else "no crash")
        print(f"done in {elapsed:.1f}s — {crash_info}")


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(CRASH_DIR, exist_ok=True)

    overall_start = time.time()

    # 1. Black-box
    run_fuzzer_benchmark(
        "Black-box",
        blackbox_fuzz,
        os.path.join(DATA_DIR, "blackbox_results.json"),
    )

    # 2. White-box (Z3)
    run_fuzzer_benchmark(
        "White-box (Z3)",
        whitebox_fuzz,
        os.path.join(DATA_DIR, "whitebox_results.json"),
    )

    # 3. Greybox (gcov) — tuan tu
    run_fuzzer_benchmark(
        "Greybox (gcov)",
        greybox_fuzz,
        os.path.join(DATA_DIR, "greybox_results.json"),
    )

    # 4. Unlock benchmark
    print(f"\n{'='*60}")
    print(f"  UNLOCK BENCHMARK")
    print(f"{'='*60}")
    unlock_path = os.path.join(DATA_DIR, "unlock_results.json")
    if not os.path.exists(unlock_path):
        unlock_result = run_unlock(n_trials=N_TRIALS, budget_per_trial=500000)
        with open(unlock_path, "w") as f:
            json.dump(unlock_result, f, indent=2, ensure_ascii=False)
        print(f"  Z3: found={unlock_result['whitebox']['found']}, "
              f"time={unlock_result['whitebox']['time']}s")
        print(f"  Black-box: success={unlock_result['blackbox']['success_rate']:.1%}")
    else:
        print("  [SKIP] Da chay truoc do")

    total = time.time() - overall_start
    print(f"\n{'='*60}")
    print(f"  TONG THOI GIAN: {total:.1f}s ({total/60:.1f} phut)")
    print(f"  Du lieu luu tai: {DATA_DIR}/")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
