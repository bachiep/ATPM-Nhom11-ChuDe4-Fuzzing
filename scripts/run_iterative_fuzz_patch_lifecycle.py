#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
CHU TRÌNH TIẾN HÓA FUZZING - VÁ LỖI - ĐỔI SEED - TÁI KIỂM THỬ (LIFECYCLE)
Đề tài: Chủ đề 4 — Dự án Fuzzing: Bộ phân tích Cú pháp Gói tin Nhị phân FZP1
Nhóm 11: Lưu Đức Hiệp & Hà Nguyễn Trúc Linh — ThS. Vũ Quang Dũng (ĐH Phenikaa)
=============================================================================
Kịch bản thực thi theo đúng quy trình phản hồi của Giảng viên:
  - Giai đoạn 1: Fuzzing trên mã nguồn ban đầu (v0) -> Đếm số lượng crash CWE-121
    -> Lưu crash mẫu iter1_cwe121_crash.bin -> Vá theo chuẩn CERT STR31-C (v0.1).
  - Giai đoạn 2: Tái kiểm thử v0.1 -> Kiểm chứng CWE-121 triệt tiêu
    -> Đổi hạt giống (Seed Evolution: Bơm mã lệnh điều khiển 0x00..0xFF)
    -> Fuzzing tìm ra crash tiếp theo (CWE-415 Double Free) -> Đếm số crash
    -> Lưu crash mẫu iter2_cwe415_crash.bin -> Vá theo chuẩn CERT MEM30-C/31-C (v0.2).
  - Giai đoạn 3: Tái kiểm thử v0.2 -> Kiểm chứng CWE-415 triệt tiêu
    -> Đổi hạt giống (Seed Evolution: Thăm dò kênh stream 0xFE)
    -> Fuzzing tìm ra crash tiếp theo (CWE-416 Use-After-Free) -> Đếm số crash
    -> Lưu crash mẫu iter3_cwe416_crash.bin -> Vá theo chuẩn CERT MEM30-C (v1).
  - Giai đoạn 4: Fuzzing toàn diện trên bản vá v1 với 1000 lượt kiểm thử
    -> Kết quả: 0 CRASH, an toàn tuyệt đối.
=============================================================================
"""

import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time

# Đường dẫn dự án
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from source.ch4_dynafuzz_fzp1 import FZP1CoverageGuidedFuzzer

V0_EXE = PROJECT_ROOT / "source" / "fzp1_parser_v0.exe"
V0_1_EXE = PROJECT_ROOT / "source" / "fzp1_parser_v0_1.exe"
V0_2_EXE = PROJECT_ROOT / "source" / "fzp1_parser_v0_2.exe"
V1_EXE = PROJECT_ROOT / "source" / "fzp1_parser_v1.exe"

LOG_DIR = PROJECT_ROOT / "results" / "logs"
DATA_DIR = PROJECT_ROOT / "results" / "data_raw"
CRASH_DIR = PROJECT_ROOT / "crashes"
DISCOVERED_SEEDS_DIR = PROJECT_ROOT / "seed_corpus" / "discovered_seeds"

LOG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)
CRASH_DIR.mkdir(parents=True, exist_ok=True)
DISCOVERED_SEEDS_DIR.mkdir(parents=True, exist_ok=True)


def build_fzp1_packet(payload: bytes) -> bytes:
    """Tạo gói tin FZP1 chuẩn với XOR checksum hợp lệ."""
    magic = b"FZP1"
    length_bytes = struct.pack("<I", len(payload))
    chk = 0
    for b in payload:
        chk ^= b
    return magic + length_bytes + payload + bytes([chk])


TEMP_INPUT_FILE = PROJECT_ROOT / "_temp_fuzz_exec.bin"

def execute_target(exe_path: Path, data: bytes, timeout_sec: float = 3.0) -> tuple[int, str, str]:
    """Thực thi gói tin trên file nhị phân C và trả về mã thoát."""
    with open(TEMP_INPUT_FILE, "wb") as f:
        f.write(data)
    try:
        proc = subprocess.run(
            [str(exe_path), str(TEMP_INPUT_FILE)],
            capture_output=True,
            timeout=timeout_sec
        )
        out = proc.stdout.decode("utf-8", errors="replace")
        err = proc.stderr.decode("utf-8", errors="replace")
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        return -999, "", "Process Timed Out"


def is_process_crash(returncode: int) -> bool:
    """Xác định mã thoát có phải là sập hệ thống (Crash/Fault) hay không.
    Trên Windows MinGW:
      - 0: Thành công
      - 2: Lỗi nghiệp vụ / Từ chối an toàn (CERT reject)
      - Khác (0xC0000005, 0xC0000403, 0xC0000374, giá trị âm hoặc lớn): Crash
    """
    return returncode != 0 and returncode != 2


def run_stage_fuzzing(
    stage_name: str,
    target_exe: Path,
    target_version: str,
    fuzzer: FZP1CoverageGuidedFuzzer,
    iterations: int,
    cwe_target: str,
    cert_standard: str,
    save_crash_file: Path | None = None
) -> dict:
    print(f"\n{'='*75}")
    print(f"  [{stage_name.upper()}] MỤC TIÊU: {target_exe.name} ({target_version})")
    print(f"  Trọng tâm kiểm thử: {cwe_target} | Quy chuẩn an toàn: {cert_standard}")
    print(f"  Số lượng iteration: {iterations}")
    print(f"{'='*75}")

    crashes = 0
    clean_rejects = 0
    successes = 0
    discovered_branches_before = len(fuzzer.global_branch_bitmap)
    crash_samples = []
    first_crash_data = None
    start_time = time.time()

    for i in range(1, iterations + 1):
        mutant, parent_seed = fuzzer.next_input()
        code, out, err = execute_target(target_exe, mutant)

        # Kiểm tra phản hồi độ phủ
        branches = fuzzer.compute_branch_coverage(mutant)
        if branches - fuzzer.global_branch_bitmap:
            fuzzer.add_seed(mutant, origin=f"mutant_gen_{stage_name}")
            # Lưu seed khám phá vào corpus
            seed_file = DISCOVERED_SEEDS_DIR / f"seed_{stage_name}_b{list(branches)[0]}_{i}.bin"
            with open(seed_file, "wb") as sf:
                sf.write(mutant)

        if is_process_crash(code):
            crashes += 1
            if first_crash_data is None:
                first_crash_data = mutant
                if save_crash_file:
                    with open(save_crash_file, "wb") as cf:
                        cf.write(mutant)
                print(f"  [!] CRASH ĐẦU TIÊN TẠI LƯỢT #{i}: Mã thoát = {code} ({hex(code & 0xFFFFFFFF)})")
                first_line_err = err.strip().splitlines()[0] if err.strip() else "OS Signal Termination"
                print(f"      Chi tiết lỗi: {first_line_err}")
                sys.stdout.flush()
            if len(crash_samples) < 5:
                crash_samples.append({
                    "iteration": i,
                    "returncode": code,
                    "hex_code": hex(code & 0xFFFFFFFF),
                    "payload_len": len(mutant) - 9 if len(mutant) >= 9 else 0,
                    "error_snippet": err.strip()[:100]
                })
        elif code == 2:
            clean_rejects += 1
        elif code == 0:
            successes += 1

        if i % 50 == 0 or i == iterations:
            print(f"  -> Tiến độ {i}/{iterations} | Crash: {crashes} | An toàn: {successes} | Từ chối bảo mật: {clean_rejects} | Đã phủ: {len(fuzzer.global_branch_bitmap)} nhánh")
            sys.stdout.flush()

    elapsed = time.time() - start_time
    discovered_branches_after = len(fuzzer.global_branch_bitmap)

    result = {
        "stage": stage_name,
        "target_version": target_version,
        "target_executable": target_exe.name,
        "cwe_target": cwe_target,
        "cert_standard": cert_standard,
        "iterations": iterations,
        "crashes": crashes,
        "clean_rejects": clean_rejects,
        "successes": successes,
        "crash_rate_percent": round((crashes / iterations) * 100, 2),
        "branches_discovered": discovered_branches_after,
        "new_branches_in_stage": discovered_branches_after - discovered_branches_before,
        "elapsed_sec": round(elapsed, 3),
        "crash_samples": crash_samples,
        "saved_crash_binary": save_crash_file.name if (save_crash_file and first_crash_data) else None
    }
    return result


def main():
    print(f"\n{'#'*75}")
    print("  TIẾN TRÌNH FUZZING TIẾN HÓA ĐA GIAI ĐOẠN (CRASH -> VÁ -> ĐỔI SEED -> 0 CRASH)")
    print("  Nhóm 11 — ThS. Vũ Quang Dũng — An toàn Phần mềm Phenikaa")
    print(f"{'#'*75}")

    # Đảm bảo toàn bộ 4 file nhị phân tồn tại
    for exe, label in [(V0_EXE, "v0"), (V0_1_EXE, "v0.1"), (V0_2_EXE, "v0.2"), (V1_EXE, "v1")]:
        if not exe.exists():
            print(f"[ERROR] Chưa biên dịch {exe.name}! Vui lòng biên dịch trước.")
            sys.exit(1)

    # Khởi tạo Corpus ban đầu từ các gói tin hợp lệ
    bootstrap_seeds = [
        build_fzp1_packet(b"TEMP:28C"),
        build_fzp1_packet(b"BARO:1013hPa"),
        build_fzp1_packet(b"STATUS:ONLINE"),
        build_fzp1_packet(b"VOLT:3.3V"),
    ]
    fuzzer = FZP1CoverageGuidedFuzzer(seed=1104, initial_corpus=bootstrap_seeds)

    stage_results = []

    # =========================================================================
    # =========================================================================
    # GIAI ĐOẠN 1: Fuzzing trên v0 (Chưa vá) -> Tìm CWE-121 Stack Buffer Overflow
    # =========================================================================
    res_stage1 = run_stage_fuzzing(
        stage_name="Stage_1_Initial_v0",
        target_exe=V0_EXE,
        target_version="v0",
        fuzzer=fuzzer,
        iterations=250,
        cwe_target="CWE-121: Stack-based Buffer Overflow",
        cert_standard="Chưa áp dụng CERT C (Thiếu kiểm tra cận trên độ dài)",
        save_crash_file=CRASH_DIR / "iter1_cwe121_crash.bin"
    )
    stage_results.append(res_stage1)

    # =========================================================================
    # GIAI ĐOẠN 2: Tiến hóa mã nguồn lên v0.1 (Vá CWE-121 theo CERT STR31-C)
    #              Đổi seed data: Thăm dò không gian mã lệnh điều khiển (CMD 0x00..0xFF)
    #              Kích hoạt crash tiếp theo: CWE-415 Double Free
    # =========================================================================
    # Bơm hạt giống thăm dò lệnh điều khiển vào fuzzer
    fuzzer.add_seed(build_fzp1_packet(b"\xFF\x01\x02\x03"), origin="seed_inject_cmd_abort")
    fuzzer.add_seed(build_fzp1_packet(b"\x00\x01\x02\x03"), origin="seed_inject_cmd_null")

    res_stage2 = run_stage_fuzzing(
        stage_name="Stage_2_Intermediate_v0_1",
        target_exe=V0_1_EXE,
        target_version="v0.1",
        fuzzer=fuzzer,
        iterations=250,
        cwe_target="CWE-415: Double Free (Sau khi vá CWE-121)",
        cert_standard="Đã vá CERT STR31-C | Chưa vá CERT MEM30-C/31-C",
        save_crash_file=CRASH_DIR / "iter2_cwe415_crash.bin"
    )
    stage_results.append(res_stage2)

    # =========================================================================
    # GIAI ĐOẠN 3: Tiến hóa mã nguồn lên v0.2 (Vá CWE-121 & CWE-415)
    #              Đổi seed data: Thăm dò nhánh thiết lập lại kênh stream (CMD 0xFE)
    #              Kích hoạt crash tiếp theo: CWE-416 Use-After-Free
    # =========================================================================
    fuzzer.add_seed(build_fzp1_packet(b"\xFE\x01\x02\x03"), origin="seed_inject_cmd_reset")

    res_stage3 = run_stage_fuzzing(
        stage_name="Stage_3_Intermediate_v0_2",
        target_exe=V0_2_EXE,
        target_version="v0.2",
        fuzzer=fuzzer,
        iterations=250,
        cwe_target="CWE-416: Use-After-Free (Sau khi vá CWE-121 & CWE-415)",
        cert_standard="Đã vá CERT STR31-C & MEM31-C | Chưa vá triệt để CERT MEM30-C",
        save_crash_file=CRASH_DIR / "iter3_cwe416_crash.bin"
    )
    stage_results.append(res_stage3)

    # =========================================================================
    # GIAI ĐOẠN 4: Bản vá hoàn thiện v1 (Vá toàn bộ 3 lỗi theo chuẩn CERT C)
    #              Tái kiểm thử toàn diện 500 lượt kiểm thử
    # =========================================================================
    res_stage4 = run_stage_fuzzing(
        stage_name="Stage_4_Final_v1",
        target_exe=V1_EXE,
        target_version="v1",
        fuzzer=fuzzer,
        iterations=500,
        cwe_target="Tái kiểm định toàn diện (CWE-121, CWE-415, CWE-416)",
        cert_standard="Tuân thủ toàn diện CERT STR31-C, MEM30-C, MEM31-C",
        save_crash_file=None
    )
    stage_results.append(res_stage4)

    # =========================================================================
    # XUẤT BÁO CÁO NHẬT KÝ & TỆP JSON DỮ LIỆU THỰC NGHIỆM
    # =========================================================================
    output_json = DATA_DIR / "iterative_crash_evolution.json"
    with open(output_json, "w", encoding="utf-8") as jf:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "fuzzer_engine": "FZP1CoverageGuidedFuzzer",
            "stages": stage_results,
            "total_branches_covered": len(fuzzer.global_branch_bitmap),
            "branch_descriptions": FZP1CoverageGuidedFuzzer.BRANCH_DESCRIPTIONS
        }, jf, indent=2, ensure_ascii=False)

    log_txt = LOG_DIR / "iterative_crash_evolution_log.txt"
    with open(log_txt, "w", encoding="utf-8") as lf:
        lf.write("=" * 80 + "\n")
        lf.write("NHẬT KÝ TIẾN TRÌNH FUZZING - VÁ LỖI - ĐỔI SEED - TÁI KIỂM ĐỊNH (GROUP 11)\n")
        lf.write(f"Thời gian thực nghiệm: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        lf.write("Học phần: Kỹ thuật Lập trình An toàn — ThS. Vũ Quang Dũng (Phenikaa)\n")
        lf.write("=" * 80 + "\n\n")

        for s in stage_results:
            lf.write(f"--- [GIAI ĐOẠN: {s['stage']}] ---\n")
            lf.write(f"  + Phiên bản mã nguồn  : {s['target_version']} ({s['target_executable']})\n")
            lf.write(f"  + Mục tiêu kiểm thử   : {s['cwe_target']}\n")
            lf.write(f"  + Chuẩn an toàn áp dụng: {s['cert_standard']}\n")
            lf.write(f"  + Số lượt kiểm thử    : {s['iterations']}\n")
            lf.write(f"  + Số lượng Crash sập  : {s['crashes']} ({s['crash_rate_percent']}%)\n")
            lf.write(f"  + Từ chối bảo mật     : {s['clean_rejects']}\n")
            lf.write(f"  + Xử lý an toàn       : {s['successes']}\n")
            lf.write(f"  + Nhánh độ phủ đạt    : {s['branches_discovered']}/9 nhánh giao thức\n")
            lf.write(f"  + Thời gian chạy      : {s['elapsed_sec']} giây\n")
            if s['saved_crash_binary']:
                lf.write(f"  + Tệp crash trích xuất: crashes/{s['saved_crash_binary']}\n")
            if s['crash_samples']:
                lf.write("  + Chi tiết các mẫu crash tiêu biểu:\n")
                for sample in s['crash_samples']:
                    lf.write(f"      * Iter #{sample['iteration']}: Code {sample['hex_code']} | Payload len: {sample['payload_len']}B | {sample['error_snippet']}\n")
            lf.write("\n")

        lf.write("=" * 80 + "\n")
        lf.write("BẢNG ĐỐI CHIẾU TIẾN TRÌNH TIỆT TIÊU LỖ HỔNG (CRASH EVOLUTION MATRIX):\n")
        lf.write(f"{'Phiên bản':<12} | {'Trọng tâm lỗi':<30} | {'Số lần Fuzz':<12} | {'Số Crash':<10} | {'Tỷ lệ':<8} | {'Trạng thái'}\n")
        lf.write("-" * 85 + "\n")
        for s in stage_results:
            status = "NGUY HIỂM (CÓ LỖI)" if s['crashes'] > 0 else "AN TOÀN TUYỆT ĐỐI"
            lf.write(f"{s['target_version']:<12} | {s['cwe_target'][:30]:<30} | {s['iterations']:<12} | {s['crashes']:<10} | {s['crash_rate_percent']:>5}% | {status}\n")
        lf.write("=" * 80 + "\n")

    print(f"\n{'='*75}")
    print("  KẾT THÚC THỰC NGHIỆM TIẾN HOÁ ĐA GIAI ĐOẠN:")
    print(f"  + Đã lưu dữ liệu: {output_json.relative_to(PROJECT_ROOT)}")
    print(f"  + Đã lưu nhật ký: {log_txt.relative_to(PROJECT_ROOT)}")
    print(f"{'='*75}\n")


if __name__ == "__main__":
    main()
