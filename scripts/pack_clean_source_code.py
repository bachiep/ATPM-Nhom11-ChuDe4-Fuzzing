import zipfile
import os
from pathlib import Path

root = Path(r"I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing")
zip_path = Path(r"I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_SourceCode.zip")

INCLUDE_FILES = [
    "README.md",
    "HUONG_DAN_KIEM_TRA_DU_AN.md",
    "pytest.ini",
]

INCLUDE_DIRS = [
    "source",
    "tests",
    "specification",
    "crashes",
    "network_capture",
    "seed_corpus",
]

INCLUDE_SCRIPTS = [
    "verify_project.py",
    "run_fzp1_benchmark.py",
    "aggregate_results.py",
    "generate_charts.py",
    "analyze_pcap_to_spec.py",
    "run_iterative_fuzz_patch_lifecycle.py",
]

with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
    for f in INCLUDE_FILES:
        p = root / f
        if p.exists():
            zf.write(p, arcname=f"Nhom11_BTL_ChuDe4_SourceCode/{f}")
            
    for d in INCLUDE_DIRS:
        dp = root / d
        if dp.exists():
            for sp in dp.rglob("*"):
                if sp.is_file():
                    if "__pycache__" in sp.parts or sp.suffix in [".pyc", ".tmp", ".bak"]:
                        continue
                    rel = sp.relative_to(root)
                    zf.write(sp, arcname=f"Nhom11_BTL_ChuDe4_SourceCode/{rel}")

    for s in INCLUDE_SCRIPTS:
        p = root / "scripts" / s
        if p.exists():
            zf.write(p, arcname=f"Nhom11_BTL_ChuDe4_SourceCode/scripts/{s}")

print(f"DONE. Size: {zip_path.stat().st_size:,} bytes")
