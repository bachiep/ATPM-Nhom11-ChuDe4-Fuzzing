"""
ĐÓNG GÓI DỰ ÁN BÁO CÁO VÀ SOURCE CODE NỘP BÀI (ZIP)
Loại trừ các file rác, .git, cache, đảm bảo sạch sẽ và toàn vẹn.
"""
import os
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ZIP_OUT = PROJECT_ROOT.parent / "Nhom11_BTL_ChuDe4_Fuzzing.zip"

EXCLUDE_DIRS = {
    ".git", "__pycache__", ".pytest_cache", ".vscode", ".idea", 
    "node_modules", "scratch", "SecLabFramework.exe_extracted", 
    "teacher_extracted_pyc", "archive_legacy_v0", "docs", "screenshots"
}
EXCLUDE_FILES = {
    "run_py314.c", "run_py314.exe", "run_py314.o",
    "seclab_master_exec.log", "extract_all_pyz.py",
    "pyinstxtractor.py", "run_authentic_seclab_all.py",
    "automate_seclab.py", "capture_tab6.py"
}
EXCLUDE_REL_PATHS = {
    Path("BaoCao_BTL_Nhom11.docx"),
}
EXCLUDE_EXTS = {".pyc", ".pyo"}

def pack():
    print(f"[*] Bắt đầu đóng gói thư mục: {PROJECT_ROOT.name}")
    print(f"[*] Tệp đích: {ZIP_OUT}")
    
    count = 0
    total_bytes = 0
    with zipfile.ZipFile(ZIP_OUT, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(PROJECT_ROOT):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for file in files:
                if file.startswith("~$") or file.startswith("_temp_"):
                    continue
                if file in EXCLUDE_FILES:
                    continue
                ext = Path(file).suffix.lower()
                if ext in EXCLUDE_EXTS:
                    continue
                
                full_path = Path(root) / file
                rel_path = full_path.relative_to(PROJECT_ROOT)
                if rel_path in EXCLUDE_REL_PATHS:
                    continue
                
                archive_name = Path(PROJECT_ROOT.name) / rel_path
                
                zf.write(full_path, archive_name)
                count += 1
                total_bytes += full_path.stat().st_size
                
    print(f"[+] Đã đóng gói thành công {count} tệp ({total_bytes:,} bytes raw) vào {ZIP_OUT.name} ({ZIP_OUT.stat().st_size:,} bytes compressed)!")

if __name__ == "__main__":
    pack()
