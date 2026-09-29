"""
BTL Nhom 11 — Generate Charts (Matplotlib, 300 DPI)
=====================================================
Tao bieu do tu raw benchmark data, xuat vao report/figures/.
"""
from __future__ import annotations
import json
import os
import sys

BTL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BTL_DIR, "data", "raw")
FIG_DIR = os.path.join(BTL_DIR, "report", "figures")

# Matplotlib backend khong can display
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker as ticker  # noqa: E402

DPI = 300
COLORS = {
    "Black-box": "#e74c3c",
    "White-box": "#2ecc71",
    "Greybox": "#3498db",
}


def load_json(filename: str) -> list | dict:
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)


def chart_time_to_crash_boxplot(bb: list, wb: list, gb: list) -> None:
    """Box plot: time-to-first-crash cho 3 fuzzer."""
    data = {}
    for name, results in [("Black-box", bb), ("White-box", wb), ("Greybox", gb)]:
        times = [r.get("time_to_first_crash_seconds", r["wall_time_seconds"]) for r in results
                 if r.get("first_crash_at") is not None]
        if times:
            data[name] = times

    if not data:
        print("  [SKIP] Khong co du lieu time-to-crash")
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    labels = list(data.keys())
    box_data = [data[k] for k in labels]
    box_colors = [COLORS.get(k, "#95a5a6") for k in labels]

    bp = ax.boxplot(box_data, tick_labels=labels, patch_artist=True, widths=0.5)
    for patch, color in zip(bp["boxes"], box_colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)

    ax.set_ylabel("Thời gian đến crash đầu tiên (giây)")
    ax.set_yscale("log")
    ax.set_title("So sánh Time-to-First-Crash (30 trials)")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    path = os.path.join(FIG_DIR, "time_to_crash_boxplot.png")
    fig.savefig(path, dpi=DPI)
    plt.close(fig)
    print(f"  [OK] {path}")


def chart_success_rate(bb: list, wb: list, gb: list) -> None:
    """Bar chart: success rate 30 trials."""
    rates = {}
    for name, results in [("Black-box", bb), ("White-box", wb), ("Greybox", gb)]:
        if results:
            successes = sum(1 for r in results if r.get("first_crash_at") is not None)
            rates[name] = successes / len(results) * 100

    if not rates:
        print("  [SKIP] Khong co du lieu success rate")
        return

    fig, ax = plt.subplots(figsize=(7, 5))
    names = list(rates.keys())
    values = [rates[k] for k in names]
    colors = [COLORS.get(k, "#95a5a6") for k in names]

    bars = ax.bar(names, values, color=colors, alpha=0.8, edgecolor="black", linewidth=0.5)
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f"{val:.0f}%", ha="center", va="bottom", fontweight="bold")

    ax.set_ylabel("Tỷ lệ thành công (%)")
    ax.set_title("Tỷ lệ tìm được crash (30 trials, 5000 inputs/trial)")
    ax.set_ylim(0, 110)
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    path = os.path.join(FIG_DIR, "success_rate_bar.png")
    fig.savefig(path, dpi=DPI)
    plt.close(fig)
    print(f"  [OK] {path}")


def chart_greybox_coverage(gb: list) -> None:
    """Line chart: greybox coverage / corpus growth over iterations."""
    if not gb:
        print("  [SKIP] Khong co du lieu greybox")
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    for trial in gb[:5]:  # Chi ve 5 trial dau
        cov = trial.get("coverage_history", [])
        if cov:
            iters = [c["iteration"] for c in cov]
            totals = [c["total_covered"] for c in cov]
            ax1.plot(iters, totals, alpha=0.6, linewidth=1,
                     label=f"seed={trial['seed']}")

    ax1.set_xlabel("Iteration")
    ax1.set_ylabel("Tổng dòng đã phủ")
    ax1.set_title("Coverage Growth (Greybox)")
    ax1.legend(fontsize=8)
    ax1.grid(alpha=0.3)

    # Corpus growth
    for trial in gb[:5]:
        cg = trial.get("corpus_growth", [])
        if cg:
            iters = [c["iteration"] for c in cg]
            sizes = [c["corpus_size"] for c in cg]
            ax2.plot(iters, sizes, alpha=0.6, linewidth=1,
                     label=f"seed={trial['seed']}")

    ax2.set_xlabel("Iteration")
    ax2.set_ylabel("Kích thước corpus")
    ax2.set_title("Corpus Growth (Greybox)")
    ax2.legend(fontsize=8)
    ax2.grid(alpha=0.3)

    plt.tight_layout()
    path = os.path.join(FIG_DIR, "greybox_coverage_growth.png")
    fig.savefig(path, dpi=DPI)
    plt.close(fig)
    print(f"  [OK] {path}")


def chart_unlock_benchmark() -> None:
    """Bar chart: Unlock benchmark — random iterations vs Z3 time."""
    data = load_json("unlock_results.json")
    if not data:
        print("  [SKIP] Khong co du lieu unlock")
        return

    wb = data.get("whitebox", {})
    bb = data.get("blackbox", {})

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Left: Z3 time
    ax1.bar(["Z3 Solver"], [wb.get("time", 0) * 1000], color=COLORS["White-box"],
            alpha=0.8, edgecolor="black")
    ax1.set_ylabel("Thời gian (ms)")
    ax1.set_title("White-box: Z3 giải Unlock code")

    # Right: Black-box stats
    found = bb.get("found_count", 0)
    not_found = bb.get("n_trials", 30) - found
    ax2.bar(["Tìm được", "Không tìm được"],
            [found, not_found],
            color=[COLORS["White-box"], COLORS["Black-box"]],
            alpha=0.8, edgecolor="black")
    budget = bb.get("budget_per_trial", 0)
    ax2.set_ylabel("Số trials")
    ax2.set_title(f"Black-box: Random brute-force ({budget:,} tries/trial)")

    # Annotate probability
    prob = bb.get("theoretical_probability", 0)
    exp = bb.get("theoretical_expected_trials", 0)
    fig.text(0.5, 0.01,
             f"P(random) = 1/2³² ≈ {prob:.2e} — Kỳ vọng: {exp:,} lần thử",
             ha="center", fontsize=9, style="italic")

    plt.tight_layout(rect=[0, 0.05, 1, 1])
    path = os.path.join(FIG_DIR, "unlock_benchmark.png")
    fig.savefig(path, dpi=DPI)
    plt.close(fig)
    print(f"  [OK] {path}")


def main():
    os.makedirs(FIG_DIR, exist_ok=True)

    print("=" * 60)
    print("  TAO BIEU DO")
    print("=" * 60)

    bb = load_json("blackbox_results.json")
    wb = load_json("whitebox_results.json")
    gb = load_json("greybox_results.json")

    chart_time_to_crash_boxplot(bb, wb, gb)
    chart_success_rate(bb, wb, gb)
    chart_greybox_coverage(gb)
    chart_unlock_benchmark()

    print(f"\nBieu do luu tai: {FIG_DIR}/")


if __name__ == "__main__":
    main()
