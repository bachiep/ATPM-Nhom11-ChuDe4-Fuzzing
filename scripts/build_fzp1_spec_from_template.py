"""
=============================================================================
KỊCH BẢN CHUẨN HÓA SPEC EXCEL TỪ NGUYÊN BẢN TEMPLATE GIẢNG VIÊN
Học phần: Kỹ thuật Lập trình An toàn (CSE703093 / CSE703153)
Bảo tồn 100% cấu trúc, font chữ, độ rộng cột, style của template gốc:
Template_Software_Security_iot_gateway_spec.xlsx
=============================================================================
"""

import os
import shutil
from pathlib import Path
import openpyxl

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = PROJECT_ROOT.parent / "TAI_LIEU_VA_YEU_CAU" / "01_Huong_Dan_BTL_Va_Spec" / "Template_Software_Security_iot_gateway_spec.xlsx"
OUTPUT_PATH = PROJECT_ROOT / "specification" / "Nhom11_FZP1_Fuzzing_Spec.xlsx"

def build_fzp1_spec_from_template():
    if not TEMPLATE_PATH.exists():
        raise FileNotFoundError(f"Không tìm thấy template gốc: {TEMPLATE_PATH}")

    # 1. Sao chép nguyên trạng tệp template
    shutil.copy2(TEMPLATE_PATH, OUTPUT_PATH)
    print(f"[+] Đã sao chép nguyên trạng template gốc -> {OUTPUT_PATH}")

    # 2. Mở workbook đã sao chép để cập nhật nội dung các ô (giữ nguyên styles/columns)
    wb = openpyxl.load_workbook(OUTPUT_PATH)

    # Sheet 1: ThongTin
    ws_info = wb["ThongTin"]
    ws_info.cell(2, 2, value="fzp1_binary_parser")
    ws_info.cell(3, 2, value="Bộ phân tích cú pháp gói tin nhị phân FZP1 (Magic 4B, Length 1B, Payload, Checksum XOR 1B) phục vụ kiểm thử Fuzzing và kiểm chứng an toàn bộ nhớ.")

    # Sheet 2: YeuCauChucNang
    ws_req = wb["YeuCauChucNang"]
    reqs = [
        ("REQ-1", 'Hệ thống phải xác thực chính xác 4 byte Magic Number "FZP1" ở đầu gói tin trước khi xử lý', "safety", "HIGH"),
        ("REQ-2", "Bộ phân tích cú pháp FZP1 không được rơi vào deadlock trong mọi chu trình xử lý gói tin", "liveness", "HIGH"),
        ("REQ-3", "Hàm parse_fzp1_payload() không được gây tràn bộ đệm stack (CWE-121) khi kích thước payload vượt quá 16 byte", "memory", "HIGH"),
        ("REQ-4", "Vùng đệm tệp nhị phân cấp phát trên heap phải được giải phóng đúng sau khi hoàn tất xử lý (CWE-401)", "memory", "MEDIUM"),
        ("REQ-5", "Hàm đóng phiên xử lý gói tin không được giải phóng cùng một con trỏ nhiều hơn 1 lần (CWE-415 double-free)", "memory", "HIGH"),
        ("REQ-6", "Sau khi giải phóng tài nguyên vùng nhớ, hệ thống không được tiếp tục truy cập con trỏ đó (CWE-416 use-after-free)", "memory", "HIGH"),
        ("REQ-7", "Bộ tích lũy dung lượng byte dữ liệu fzp1_byte_accumulator không được tràn kiểu int 32-bit (CWE-190)", "safety", "MEDIUM"),
        ("REQ-8", "Hàm tính tỷ lệ gói tin hợp lệ fzp1_ratio không được gây lỗi chia cho không (CWE-369)", "functional", "MEDIUM"),
        ("REQ-9", "Cơ chế xác thực token mở khóa khẩn cấp fzp1_unlock_token cần được kiểm thử bằng kỹ thuật concolic fuzzing SMT Z3", "functional", "LOW"),
    ]
    for idx, (rid, desc, cat, pri) in enumerate(reqs, start=2):
        ws_req.cell(idx, 1, value=rid)
        ws_req.cell(idx, 2, value=desc)
        ws_req.cell(idx, 3, value=cat)
        ws_req.cell(idx, 4, value=pri)

    # Sheet 3: YeuCauPhiChucNang
    ws_nfr = wb["YeuCauPhiChucNang"]
    nfrs = [
        ("NFR-1", "Bộ parser FZP1 phải xử lý tối thiểu 500 gói tin/giây trên môi trường thử nghiệm", "MEDIUM"),
        ("NFR-2", "Thời gian phản hồi trung bình cho một gói tin phải dưới 50ms", "MEDIUM"),
        ("NFR-3", "Nhật ký giải mã gói tin phải được ghi đồng bộ (không mất dữ liệu) kể cả khi tiến trình bị ngắt", "HIGH"),
    ]
    for idx, (nid, desc, pri) in enumerate(nfrs, start=2):
        ws_nfr.cell(idx, 1, value=nid)
        ws_nfr.cell(idx, 2, value=desc)
        ws_nfr.cell(idx, 3, value=pri)

    # Sheet 4: RangBuoc
    ws_con = wb["RangBuoc"]
    cons = [
        ("CON-1", "Gói tin FZP1 tuân thủ cấu trúc nhị phân: 4B Magic | 1B Length | N-B Payload | 1B XOR Checksum", "MEDIUM"),
        ("CON-2", "Bộ đệm stack frame cục bộ nhận payload có kích thước cố định 16 byte", "HIGH"),
        ("CON-3", "Cặp mã mở khóa khẩn cấp thiết bị FZP1 phải là cặp số nguyên 16-bit dương", "MEDIUM"),
    ]
    for idx, (cid, desc, pri) in enumerate(cons, start=2):
        ws_con.cell(idx, 1, value=cid)
        ws_con.cell(idx, 2, value=desc)
        ws_con.cell(idx, 3, value=pri)

    # Sheet 5: MoHinhTrangThai
    ws_sm = wb["MoHinhTrangThai"]
    sms = [
        ("st_idle", "x", "safe", "st_magic_ok, st_checksum_ok"),
        ("st_magic_ok", "", "magic_ok", "st_idle, st_conflict"),
        ("st_checksum_ok", "", "checksum_ok", "st_idle"),
        ("st_conflict", "", "magic_ok, checksum_ok, violation", "st_idle"),
    ]
    for idx, (st, init, labels, trans) in enumerate(sms, start=2):
        ws_sm.cell(idx, 1, value=st)
        ws_sm.cell(idx, 2, value=init)
        ws_sm.cell(idx, 3, value=labels)
        ws_sm.cell(idx, 4, value=trans)

    # Sheet 6: ThuocTinhAnToan
    ws_safe = wb["ThuocTinhAnToan"]
    safe_formulas = [
        "AG(!violation)",
        "EF(magic_ok)",
    ]
    for idx, f in enumerate(safe_formulas, start=2):
        ws_safe.cell(idx, 1, value=f)

    # Sheet 7: LoaiTruLanNhau
    ws_mutex = wb["LoaiTruLanNhau"]
    ws_mutex.cell(2, 1, value="magic_ok")
    ws_mutex.cell(2, 2, value="checksum_ok")

    # Sheet 8: HamSinhMa
    ws_code = wb["HamSinhMa"]
    fns = [
        ("parse_fzp1_payload", "c", "buffer_copy", "raw_payload", "16", "buffer-overflow", "1234", "5678"),
        ("write_fzp1_cache", "c", "alloc_release", "", "32", "memory-leak", "1234", "5678"),
        ("close_fzp1_session", "c", "alloc_release", "", "4", "double-free", "1234", "5678"),
        ("release_fzp1_stream", "c", "alloc_release", "", "8", "use-after-free", "1234", "5678"),
        ("fzp1_ratio", "python", "divide", "issued, consumed", "16", "", "1234", "5678"),
        ("fzp1_unlock_token", "python", "magic_value", "token_a, token_b", "16", "", "18010", "20529"),
    ]
    for idx, (name, lang, kind, params, buf_sz, bug, sec1, sec2) in enumerate(fns, start=2):
        ws_code.cell(idx, 1, value=name)
        ws_code.cell(idx, 2, value=lang)
        ws_code.cell(idx, 3, value=kind)
        ws_code.cell(idx, 4, value=params)
        ws_code.cell(idx, 5, value=buf_sz)
        ws_code.cell(idx, 6, value=bug)
        ws_code.cell(idx, 7, value=sec1)
        ws_code.cell(idx, 8, value=sec2)

    # Sheet 9: KiemTraSoHoc
    ws_arith = wb["KiemTraSoHoc"]
    ws_arith.cell(2, 1, value="fzp1_byte_accumulator")
    ws_arith.cell(2, 2, value="header_bytes, payload_bytes")
    ws_arith.cell(2, 3, value="header_bytes >= 0 and payload_bytes >= 0 and header_bytes + payload_bytes > 2000000000")
    ws_arith.cell(2, 4, value="header_bytes + payload_bytes")

    # Sheet 10: TestCase
    ws_tc = wb["TestCase"]
    tcs = [
        ("TC-1", "REQ-1, REQ-2", "Tranh chấp trạng thái xác thực Magic và Checksum", "Hệ thống ở trạng thái 'st_idle'", "Kiểm chứng mô hình Kripke 4 trạng thái sinh từ đặc tả", "AG(!violation) ĐÚNG và không có trạng thái deadlock", "HIGH"),
        ("TC-2", "REQ-3", "Payload FZP1 vượt quá 16 byte gây tràn stack", "Hàm parse_fzp1_payload() sinh từ đặc tả (bug=buffer-overflow)", "Sinh mã C cho parse_fzp1_payload()\nChạy kiểm tra AST C", "Phát hiện nguy cơ buffer-overflow (CWE-120/121)", "HIGH"),
        ("TC-3", "REQ-4, REQ-5, REQ-6", "Kiểm tra vòng đời bộ nhớ của cache/session", "write_fzp1_cache(), close_fzp1_session(), release_fzp1_stream() đã sinh", "Kiểm tra mã C của cả 3 hàm quản lý heap", "Phát hiện đủ 3 loại lỗi: memory-leak (CWE-401), double-free (CWE-415), use-after-free (CWE-416)", "HIGH"),
        ("TC-4", "REQ-7", "Bộ tích lũy byte fzp1_byte_accumulator vượt giới hạn int32", "header_bytes, payload_bytes >= 0 và tổng > 2,000,000,000", "Chạy check_int32_overflow() bằng Z3 trên biểu thức header_bytes + payload_bytes", "Kết quả SAT (phát hiện nguy cơ tràn số CWE-190)", "MEDIUM"),
        ("TC-5", "REQ-8", "Chia tỷ lệ gói tin fzp1_ratio với mẫu số bằng 0", "Hàm fzp1_ratio(issued, consumed) sinh từ đặc tả", "Chạy blackbox_fuzz() 300 lần", "Tìm được ít nhất 1 crash ZeroDivisionError (CWE-369)", "MEDIUM"),
        ("TC-6", "REQ-9", "Tìm cặp mã mở khóa khẩn cấp fzp1_unlock_token bằng concolic fuzzing", "Hàm fzp1_unlock_token(token_a, token_b), magic=(18010, 20529)", "Chạy concolic_fuzz() với Z3 SMT Solver", "Tìm được đúng bộ giá trị (18010, 20529) trong 1 lần thử", "LOW"),
    ]
    for idx, (tid, req_ref, title, pre, steps, exp, pri) in enumerate(tcs, start=2):
        ws_tc.cell(idx, 1, value=tid)
        ws_tc.cell(idx, 2, value=req_ref)
        ws_tc.cell(idx, 3, value=title)
        ws_tc.cell(idx, 4, value=pre)
        ws_tc.cell(idx, 5, value=steps)
        ws_tc.cell(idx, 6, value=exp)
        ws_tc.cell(idx, 7, value=pri)

    wb.save(OUTPUT_PATH)
    print(f"[+] Hoàn tất chuẩn hóa workbook FZP1 bảo toàn 100% định dạng template gốc: {OUTPUT_PATH}")

if __name__ == "__main__":
    build_fzp1_spec_from_template()
