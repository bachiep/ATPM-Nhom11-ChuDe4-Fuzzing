"""
BTL Nhom 11 — Aggregate Results
=================================
Tong hop raw JSON/CSV thanh bang Markdown va CSV.
"""
from __future__ import annotations
import json
import os
import re
import statistics
import sys

BTL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BTL_DIR, "data", "raw")
REPORT_DIR = os.path.join(BTL_DIR, "report")


def load_json(filename: str) -> list | dict:
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)


def compute_stats(values: list[float]) -> dict:
    if not values:
        return {"n": 0, "median": None, "q1": None, "q3": None, "min": None, "max": None, "mean": None}
    n = len(values)
    sorted_v = sorted(values)
    median = statistics.median(sorted_v)
    q1 = statistics.median(sorted_v[:n//2]) if n > 1 else median
    q3 = statistics.median(sorted_v[(n+1)//2:]) if n > 1 else median
    return {
        "n": n,
        "median": round(median, 4),
        "q1": round(q1, 4),
        "q3": round(q3, 4),
        "iqr": round(q3 - q1, 4),
        "min": round(min(sorted_v), 4),
        "max": round(max(sorted_v), 4),
        "mean": round(statistics.mean(sorted_v), 4),
    }


def aggregate_fuzzer(data: list[dict], name: str) -> dict:
    """Tong hop ket qua 1 fuzzer."""
    n_trials = len(data)
    successes = [d for d in data if d.get("first_crash_at") is not None]
    success_rate = len(successes) / n_trials if n_trials > 0 else 0

    # Time to first crash
    times = [d.get("time_to_first_crash_seconds", d["wall_time_seconds"])
             for d in successes]
    iters = [d["first_crash_at"] for d in successes]

    # Exec/s
    exec_rates = [d.get("exec_per_sec", 0) for d in data if d.get("exec_per_sec")]

    # Unique crashes (by ASan signature). ASan stack frames contain an ASLR
    # address, which must not turn the same fault site into 30 fake crashes.
    all_sigs = set()
    for d in data:
        for c in d.get("crashes", []):
            sig = c.get("asan_signature", "unknown")
            all_sigs.add(re.sub(r"0x[0-9a-fA-F]+", "0xADDR", sig))

    return {
        "fuzzer": name,
        "n_trials": n_trials,
        "success_count": len(successes),
        "success_rate": round(success_rate, 4),
        "time_to_crash": compute_stats(times),
        "iterations_to_crash": compute_stats([float(x) for x in iters]),
        "exec_per_sec": compute_stats(exec_rates),
        "unique_crash_signatures": len(all_sigs),
    }


def generate_markdown_table(results: list[dict]) -> str:
    """Tao bang Markdown so sanh."""
    lines = [
        "| Metric | Black-box | White-box | Greybox |",
        "|---|:---:|:---:|:---:|",
    ]

    def g(name):
        for r in results:
            if r["fuzzer"] == name:
                return r
        return {}

    bb, wb, gb = g("Black-box"), g("White-box"), g("Greybox")

    def fmt(val):
        if val is None:
            return "—"
        if isinstance(val, float):
            return f"{val:.4f}"
        return str(val)

    rows = [
        ("Trials", "n_trials"),
        ("Success rate", "success_rate"),
        ("Unique crashes", "unique_crash_signatures"),
    ]
    for label, key in rows:
        lines.append(f"| {label} | {fmt(bb.get(key))} | {fmt(wb.get(key))} | {fmt(gb.get(key))} |")

    # Time stats
    for stat in ["median", "q1", "q3", "min", "max"]:
        bb_v = bb.get("time_to_crash", {}).get(stat)
        wb_v = wb.get("time_to_crash", {}).get(stat)
        gb_v = gb.get("time_to_crash", {}).get(stat)
        lines.append(f"| Time-to-crash {stat} (s) | {fmt(bb_v)} | {fmt(wb_v)} | {fmt(gb_v)} |")

    # Exec rate
    for stat in ["median"]:
        bb_v = bb.get("exec_per_sec", {}).get(stat)
        wb_v = wb.get("exec_per_sec", {}).get(stat)
        gb_v = gb.get("exec_per_sec", {}).get(stat)
        lines.append(f"| Exec/s {stat} | {fmt(bb_v)} | {fmt(wb_v)} | {fmt(gb_v)} |")

    return "\n".join(lines)


def main():
    os.makedirs(REPORT_DIR, exist_ok=True)

    # Load data
    bb_data = load_json("blackbox_results.json")
    wb_data = load_json("whitebox_results.json")
    gb_data = load_json("greybox_results.json")

    if not bb_data and not wb_data and not gb_data:
        print("Chua co du lieu benchmark. Chay scripts/run_benchmark.py truoc.")
        return

    # Aggregate
    results = []
    if bb_data:
        results.append(aggregate_fuzzer(bb_data, "Black-box"))
    if wb_data:
        results.append(aggregate_fuzzer(wb_data, "White-box"))
    if gb_data:
        results.append(aggregate_fuzzer(gb_data, "Greybox"))

    # Print summary
    print("=" * 60)
    print("  KET QUA TONG HOP")
    print("=" * 60)
    for r in results:
        print(f"\n{r['fuzzer']}:")
        print(f"  Trials: {r['n_trials']}")
        print(f"  Success rate: {r['success_rate']:.1%}")
        print(f"  Unique crashes: {r['unique_crash_signatures']}")
        ttc = r['time_to_crash']
        if ttc['n'] > 0:
            print(f"  Time-to-crash: median={ttc['median']}s, "
                  f"IQR=[{ttc['q1']}, {ttc['q3']}]s")

    # Markdown table
    md = generate_markdown_table(results)
    print(f"\n{'='*60}")
    print(md)

    # Save
    summary_path = os.path.join(REPORT_DIR, "summary_table.md")
    with open(summary_path, "w") as f:
        f.write("# Bảng tổng hợp kết quả benchmark\n\n")
        f.write(md)
        f.write("\n")
    print(f"\nLuu tai: {summary_path}")

    # Save JSON
    json_path = os.path.join(DATA_DIR, "aggregated_results.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"Luu tai: {json_path}")


if __name__ == "__main__":
    main()
