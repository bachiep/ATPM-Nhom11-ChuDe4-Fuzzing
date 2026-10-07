"""
BTL Nhom 11 — Render Kripke Model for FZP1 Binary Parser
Hoc phan: Ky thuat Lap trinh An toan (CSE703093 / CSE703153)
Giang vien: ThS. Vu Quang Dung — Truong Cong nghe Thong tin, Dai hoc Phenikaa
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIG_DIR = os.path.join(BASE_DIR, "results", "figures")
REPORT_FIG_DIR = os.path.join(BASE_DIR, "report", "figures")
os.makedirs(FIG_DIR, exist_ok=True)
os.makedirs(REPORT_FIG_DIR, exist_ok=True)

# 1. Update TikZ code
tikz_content = r"""% Sơ đồ chuyển trạng thái Kripke: fzp1_binary_parser
% Nhóm 11 — Lưu Đức Hiệp & Hà Nguyễn Trúc Linh
\begin{tikzpicture}[
  every node/.style={draw, ellipse, inner sep=3pt, minimum size=10mm, align=center, font=\scriptsize},
  ->, >=stealth, thick, auto
]
  \node[fill=blue!20] (st_idle) at (0.0, 1.8) {st\_idle\\{\tiny safe, ready}};
  \node[fill=gray!15] (st_magic) at (-2.8, 0.0) {st\_magic\_valid\\{\tiny magic\_ok}};
  \node[fill=gray!15] (st_chk) at (2.8, 0.0) {st\_checksum\_valid\\{\tiny checksum\_ok}};
  \node[fill=red!35] (st_hazard) at (0.0, -1.8) {st\_overflow\_hazard\\{\tiny magic\_ok, chk\_ok, violation}};
  \draw (st_idle) -- (st_magic);
  \draw (st_idle) -- (st_chk);
  \draw (st_magic) -- (st_idle);
  \draw (st_magic) -- (st_hazard);
  \draw (st_chk) -- (st_idle);
  \draw (st_hazard) -- (st_idle);
\end{tikzpicture}
"""

with open(os.path.join(FIG_DIR, "kripke_model.tikz"), "w", encoding="utf-8") as f:
    f.write(tikz_content)
with open(os.path.join(REPORT_FIG_DIR, "kripke_model.tikz"), "w", encoding="utf-8") as f:
    f.write(tikz_content)

# 2. Render PNG diagram with matplotlib
fig, ax = plt.subplots(figsize=(8, 6), dpi=300)
ax.set_xlim(-4, 4)
ax.set_ylim(-3, 3)
ax.axis("off")

# Draw nodes
states = [
    ("st_idle\n[safe, ready]", 0.0, 1.8, "#d0e1fd", "#1a5fb4"),
    ("st_magic_valid\n[magic_ok]", -2.4, 0.0, "#e1f5fe", "#0288d1"),
    ("st_checksum_valid\n[checksum_ok]", 2.4, 0.0, "#e1f5fe", "#0288d1"),
    ("st_overflow_hazard\n[VIOLATION!]", 0.0, -1.8, "#fce4ec", "#c2185b")
]

for name, x, y, facecolor, edgecolor in states:
    box = dict(boxstyle="round,pad=0.6", facecolor=facecolor, edgecolor=edgecolor, linewidth=2)
    ax.text(x, y, name, ha="center", va="center", fontsize=10, fontweight="bold", bbox=box)

# Draw arrows
arrows = [
    ((0, 1.3), (-1.8, 0.3)),   # idle -> magic
    ((0, 1.3), (1.8, 0.3)),    # idle -> checksum
    ((-1.8, 0.0), (-0.4, 1.4)), # magic -> idle
    ((-1.8, -0.3), (-0.4, -1.4)), # magic -> hazard
    ((1.8, 0.0), (0.4, 1.4)),  # checksum -> idle
    ((0, -1.3), (0, 1.3))      # hazard -> idle
]

for start, end in arrows:
    ax.annotate("", xy=end, xytext=start,
                arrowprops=dict(arrowstyle="->", color="#333333", lw=1.5,
                                connectionstyle="arc3,rad=0.1"))

# Annotations
ax.text(0, 2.7, "Mô hình Kripke: FZP1 Binary Parser", ha="center", fontsize=13, fontweight="bold", color="#1f4e78")
ax.text(0, -2.6, "Vi phạm Loại trừ lẫn nhau: AG(!violation) thất bại tại st_overflow_hazard",
        ha="center", fontsize=9, style="italic", color="#c2185b", fontweight="semibold")

plt.tight_layout()
png_path = os.path.join(FIG_DIR, "kripke_model.png")
fig.savefig(png_path, dpi=300)
fig.savefig(os.path.join(REPORT_FIG_DIR, "kripke_model.png"), dpi=300)
plt.close(fig)

print("Rendered Kripke model PNG and TikZ successfully!")
