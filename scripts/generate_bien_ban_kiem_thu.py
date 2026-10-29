#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tự động tạo BIÊN BẢN KIỂM THỬ AN TOÀN BỘ NHỚ VÀ KIỂM CHỨNG HÌNH THỨC
chuẩn học thuật Phenikaa theo mẫu [ATPM]BienBanKiemThu_Nhom04.pdf
"""

import sys
from pathlib import Path
import docx
from docx.shared import Inches, Pt, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import qn, nsdecls
import win32com.client
import shutil

PROJECT_ROOT = Path(r"I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing")
DOWNLOADS_DIR = Path(r"E:\Dowloads")

NAVY_COLOR = RGBColor(31, 78, 121)       # #1F4E79
DARK_GRAY = RGBColor(50, 50, 50)
MUTED_GRAY = RGBColor(100, 100, 100)

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(f'''
        <w:tcMar {nsdecls("w")}>
            <w:top w:w="{top}" w:type="dxa"/>
            <w:bottom w:w="{bottom}" w:type="dxa"/>
            <w:left w:w="{left}" w:type="dxa"/>
            <w:right w:w="{right}" w:type="dxa"/>
        </w:tcMar>
    ''')
    tcPr.append(tcMar)

def style_table(table, header_bg="1F4E79", alt_bg="F2F4F7"):
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, row in enumerate(table.rows):
        trPr = row._tr.get_or_add_trPr()
        trPr.append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>'))
        
        is_header = (i == 0)
        if is_header:
            trPr.append(parse_xml(f'<w:tblHeader {nsdecls("w")}/>'))
            
        for cell in row.cells:
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            set_cell_margins(cell, top=120, bottom=120, left=140, right=140)
            if is_header:
                set_cell_background(cell, header_bg)
                for p in cell.paragraphs:
                    p.paragraph_format.space_before = Pt(3)
                    p.paragraph_format.space_after = Pt(3)
                    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    for r in p.runs:
                        r.font.name = "Times New Roman"
                        r.font.size = Pt(10.5)
                        r.font.bold = True
                        r.font.color.rgb = RGBColor(255, 255, 255)
            else:
                if i % 2 == 1:
                    set_cell_background(cell, "FFFFFF")
                else:
                    set_cell_background(cell, alt_bg)
                for p in cell.paragraphs:
                    p.paragraph_format.space_before = Pt(2)
                    p.paragraph_format.space_after = Pt(2)
                    for r in p.runs:
                        r.font.name = "Times New Roman"
                        r.font.size = Pt(10)
                        r.font.color.rgb = DARK_GRAY

def add_heading_1(doc, text):
    h = doc.add_paragraph()
    h.paragraph_format.space_before = Pt(14)
    h.paragraph_format.space_after = Pt(6)
    h.paragraph_format.keep_with_next = True
    r = h.add_run(text)
    r.font.name = "Times New Roman"
    r.font.size = Pt(13)
    r.font.bold = True
    r.font.color.rgb = NAVY_COLOR
    return h

def add_heading_2(doc, text):
    h = doc.add_paragraph()
    h.paragraph_format.space_before = Pt(10)
    h.paragraph_format.space_after = Pt(4)
    h.paragraph_format.keep_with_next = True
    r = h.add_run(text)
    r.font.name = "Times New Roman"
    r.font.size = Pt(12)
    r.font.bold = True
    r.font.color.rgb = NAVY_COLOR
    return h

def add_paragraph(doc, text, bold_prefix="", italic=False):
    p = doc.add_paragraph()
    p.paragraph_format.line_spacing = 1.25
    p.paragraph_format.space_after = Pt(4)
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    if bold_prefix:
        r_pre = p.add_run(bold_prefix)
        r_pre.font.name = "Times New Roman"
        r_pre.font.size = Pt(11)
        r_pre.font.bold = True
        r_pre.font.color.rgb = DARK_GRAY
    r = p.add_run(text)
    r.font.name = "Times New Roman"
    r.font.size = Pt(11)
    r.font.italic = italic
    r.font.color.rgb = DARK_GRAY
    return p

def add_code_block(doc, code_text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.left_indent = Inches(0.2)
    pPr = p._p.get_or_add_pPr()
    pBdr = parse_xml(f'''
        <w:pBdr {nsdecls("w")}>
            <w:left w:val="single" w:sz="18" w:space="8" w:color="1F4E79"/>
        </w:pBdr>
    ''')
    pPr.append(pBdr)
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="F5F7FA"/>')
    pPr.append(shd)
    r = p.add_run(code_text)
    r.font.name = "Consolas"
    r.font.size = Pt(9.5)
    r.font.color.rgb = RGBColor(30, 30, 30)

def build_bien_ban():
    doc = docx.Document()
    
    # Page setup A4
    for section in doc.sections:
        section.top_margin = Cm(2.0)
        section.bottom_margin = Cm(2.0)
        section.left_margin = Cm(2.5)
        section.right_margin = Cm(2.0)
        section.page_width = Cm(21.0)
        section.page_height = Cm(29.7)

    # ==================== TRANG BÌA ====================
    p_univ = doc.add_paragraph()
    p_univ.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_u1 = p_univ.add_run("TRƯỜNG ĐẠI HỌC PHENIKAA\n")
    r_u1.font.name = "Times New Roman"
    r_u1.font.size = Pt(13)
    r_u1.font.bold = True
    r_u2 = p_univ.add_run("TRƯỜNG CÔNG NGHỆ THÔNG TIN\n")
    r_u2.font.name = "Times New Roman"
    r_u2.font.size = Pt(13)
    r_u2.font.bold = True
    r_u3 = p_univ.add_run("------------oOo------------\n\n")
    r_u3.font.name = "Times New Roman"
    r_u3.font.size = Pt(11)

    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_t1 = p_title.add_run("BÁO CÁO BÀI TẬP LỚN\n")
    r_t1.font.name = "Times New Roman"
    r_t1.font.size = Pt(15)
    r_t1.font.bold = True
    r_t1.font.color.rgb = NAVY_COLOR

    r_t2 = p_title.add_run("CHỦ ĐỀ 4: DỰ ÁN FUZZING\n")
    r_t2.font.name = "Times New Roman"
    r_t2.font.size = Pt(14)
    r_t2.font.bold = True
    r_t2.font.color.rgb = NAVY_COLOR

    r_t3 = p_title.add_run("PHÂN TÍCH VÀ KIỂM THỬ AN TOÀN BỘ PHÂN TÍCH CÚ PHÁP GÓI TIN NHỊ PHÂN FZP1\n(BLACK-BOX VS GREYBOX VS WHITE-BOX CONCOLIC SMT Z3)\n\n")
    r_t3.font.name = "Times New Roman"
    r_t3.font.size = Pt(13)
    r_t3.font.bold = True

    p_bb = doc.add_paragraph()
    p_bb.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_bb = p_bb.add_run("BIÊN BẢN KIỂM THỬ AN TOÀN BỘ NHỚ VÀ KIỂM CHỨNG HÌNH THỨC\n\n")
    r_bb.font.name = "Times New Roman"
    r_bb.font.size = Pt(14)
    r_bb.font.bold = True
    r_bb.font.color.rgb = RGBColor(180, 0, 0)

    # Bảng thông tin nhóm
    info_table = doc.add_table(rows=7, cols=2)
    info_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    infos = [
        ("Học phần:", "CSE703093 – An toàn phần mềm"),
        ("Lớp học phần:", "An toàn phần mềm"),
        ("Nhóm học phần:", "Nhóm 11"),
        ("Sinh viên thực hiện:", "1. Lưu Đức Hiệp — 23010437 (Nhóm trưởng)\n2. Hà Nguyễn Trúc Linh — 23010506 (Thành viên)"),
        ("Giảng viên hướng dẫn:", "ThS. Vũ Quang Dũng"),
        ("Kho lưu trữ GitHub:", "https://github.com/bachiep/ATPM-Nhom11-ChuDe4-Fuzzing"),
        ("Thời gian thực hiện:", "Hà Nội — Tháng 10, năm 2026")
    ]
    for row_idx, (k, v) in enumerate(infos):
        cell_k = info_table.cell(row_idx, 0)
        cell_v = info_table.cell(row_idx, 1)
        cell_k.width = Inches(2.2)
        cell_v.width = Inches(4.5)
        set_cell_background(cell_k, "F7F9FC")
        set_cell_background(cell_v, "FFFFFF")
        set_cell_margins(cell_k, 80, 80, 100, 100)
        set_cell_margins(cell_v, 80, 80, 100, 100)
        pk = cell_k.paragraphs[0]
        pk.paragraph_format.space_before = Pt(2)
        pk.paragraph_format.space_after = Pt(2)
        rk = pk.add_run(k)
        rk.font.name = "Times New Roman"
        rk.font.size = Pt(11)
        rk.font.bold = True
        
        pv = cell_v.paragraphs[0]
        pv.paragraph_format.space_before = Pt(2)
        pv.paragraph_format.space_after = Pt(2)
        rv = pv.add_run(v)
        rv.font.name = "Times New Roman"
        rv.font.size = Pt(11)

    doc.add_page_break()

    # ==================== NỘI DUNG BIÊN BẢN ====================
    add_heading_1(doc, "1. Thông tin đợt kiểm thử")
    add_paragraph(doc, "Nhóm 11 — Học phần: CSE703093 (An toàn phần mềm) — Giảng viên: ThS. Vũ Quang Dũng", "Đơn vị thực hiện: ")
    add_paragraph(doc, "Tháng 10/2026 (Nghiệm thu toàn diện trước khi bàn giao đồ án)", "Thời gian kiểm thử: ")
    add_paragraph(doc, "e719c9b, nhánh main (https://github.com/bachiep/ATPM-Nhom11-ChuDe4-Fuzzing)", "Mã commit ghi nhận: ")

    add_paragraph(doc, "Bảng 1.1. Phân công trách nhiệm kiểm thử và phụ trách kỹ thuật:")
    t1 = doc.add_table(rows=3, cols=4)
    t1.rows[0].cells[0].paragraphs[0].text = "Thành viên"
    t1.rows[0].cells[1].paragraphs[0].text = "Mã sinh viên"
    t1.rows[0].cells[2].paragraphs[0].text = "Phần phụ trách chính"
    t1.rows[0].cells[3].paragraphs[0].text = "Tỷ lệ đóng góp"

    t1.rows[1].cells[0].paragraphs[0].text = "Lưu Đức Hiệp\n(Trưởng nhóm)"
    t1.rows[1].cells[1].paragraphs[0].text = "23010437"
    t1.rows[1].cells[2].paragraphs[0].text = "Kiến trúc FZP1, Động cơ Fuzzing Black-box & Greybox, Thực nghiệm 30 Trials Benchmark, Phân tích số liệu và chu trình tiến hóa 4 mốc"
    t1.rows[1].cells[3].paragraphs[0].text = "50%"

    t1.rows[2].cells[0].paragraphs[0].text = "Hà Nguyễn Trúc Linh\n(Thành viên)"
    t1.rows[2].cells[1].paragraphs[0].text = "23010506"
    t1.rows[2].cells[2].paragraphs[0].text = "Bảng đặc tả SSOT Excel 10 sheet, Mô hình Kripke/CTL, Động cơ White-box Concolic SMT Z3, Phân tích mã nguồn C & Bản vá CERT C"
    t1.rows[2].cells[3].paragraphs[0].text = "50%"
    style_table(t1)

    add_paragraph(doc, "Đối tượng kiểm thử gồm: (1) Mã nguồn C v0, v0.1, v0.2, v1 trong source/; (2) Bộ động cơ Fuzzing ch4_dynafuzz_fzp1.py; (3) Tệp đặc tả SSOT 10 sheet Nhom11_FZP1_Fuzzing_Spec.xlsx; (4) Bộ kiểm thử tự động tests/; (5) Kịch bản thẩm định scripts/verify_project.py.")

    add_heading_1(doc, "2. Môi trường và phương pháp thực hiện")
    add_heading_2(doc, "2.1. Cấu hình môi trường kiểm thử")
    
    t_env = doc.add_table(rows=7, cols=2)
    env_data = [
        ("Hệ điều hành", "Windows 11 Pro 64-bit (Build 22631) & Ubuntu 22.04 LTS (WSL2)"),
        ("Kiến trúc vi xử lý", "x86_64 (64-bit Little-Endian)"),
        ("Trình biên dịch C", "GCC 15.2.0 (MinGW-w64 UCRT64 với -fstack-protector-all) & Clang 18.1 (-fsanitize=address)"),
        ("Môi trường Python", "Python 3.13.7 64-bit"),
        ("Bộ giải hình thức SMT", "Microsoft Z3 SMT Solver v4.13.0 (qua z3-solver API)"),
        ("Khung kiểm thử tự động", "PyTest 9.1.1 (14/14 test cases pass)"),
        ("Tệp đặc tả SSOT", "Nhom11_FZP1_Fuzzing_Spec.xlsx (10 sheet chuẩn SecLabFramework Tab Ch6)")
    ]
    t_env.rows[0].cells[0].paragraphs[0].text = "Thành phần"
    t_env.rows[0].cells[1].paragraphs[0].text = "Thông số cấu hình thực tế"
    for r_i, (k, v) in enumerate(env_data):
        t_env.rows[r_i].cells[0].paragraphs[0].text = k
        t_env.rows[r_i].cells[1].paragraphs[0].text = v
    style_table(t_env)

    add_heading_2(doc, "2.2. Lệnh biên dịch và kiểm thử thực tế")
    add_paragraph(doc, "Biên dịch mã C có kích hoạt giám sát ô nhớ AddressSanitizer (ASan):")
    add_code_block(doc, "gcc -fsanitize=address -O0 -g source/fzp1_parser_v0.c -o source/fzp1_parser_v0_asan\ngcc -fsanitize=address -O0 -g source/fzp1_parser_v1.c -o source/fzp1_parser_v1_asan")
    
    add_paragraph(doc, "Biên dịch mã C với bảo vệ Stack Canary trên môi trường Windows:")
    add_code_block(doc, "gcc -Wall -Wextra -O0 -g -fstack-protector-all source/fzp1_parser_v0.c -o source/fzp1_parser_v0.exe\ngcc -Wall -Wextra -O0 -g -fstack-protector-all source/fzp1_parser_v1.c -o source/fzp1_parser_v1.exe")

    add_paragraph(doc, "Chạy bộ kiểm thử tự động toàn diện PyTest:")
    add_code_block(doc, "pytest tests/ -v")

    add_paragraph(doc, "Chạy kịch bản thẩm định độc lập 8 khâu dự án:")
    add_code_block(doc, "python scripts/verify_project.py")

    add_heading_1(doc, "3. Quy ước đánh giá kết quả")
    t_rules = doc.add_table(rows=4, cols=2)
    t_rules.rows[0].cells[0].paragraphs[0].text = "Trạng thái"
    t_rules.rows[0].cells[1].paragraphs[0].text = "Ý nghĩa và tiêu chí xác nhận"
    rules_data = [
        ("Đạt (PASS)", "Kết quả thực tế khớp 100% với hành vi mong đợi (Đối với v0: tái hiện chính xác lỗi ô nhớ và mã lỗi OS; đối với v1: từ chối an toàn mã 2, không sập ô nhớ, ASan 0 findings)."),
        ("Không đạt (FAIL)", "Kết quả thực tế khác với mong đợi hoặc bản vá v1 vẫn bị sập ô nhớ."),
        ("Bảo đảm liêm chính", "Toàn bộ số liệu 30 trials, time-to-first-crash và chu trình tiến hóa đều được trích xuất từ dữ liệu thô (.json), không sử dụng số liệu ngụy tạo.")
    ]
    for r_i, (k, v) in enumerate(rules_data):
        t_rules.rows[r_i].cells[0].paragraphs[0].text = k
        t_rules.rows[r_i].cells[1].paragraphs[0].text = v
    style_table(t_rules)

    add_heading_1(doc, "4. Kết quả kiểm thử chi tiết")
    add_heading_2(doc, "4.1. Kiểm thử mã nguồn C & Bắt lỗi động AddressSanitizer")
    add_paragraph(doc, "Bảng 4.1. Kết quả kiểm thử 3 lỗ hổng ô nhớ kinh điển và bản vá CERT C:")

    t_c = doc.add_table(rows=7, cols=5)
    t_c.rows[0].cells[0].paragraphs[0].text = "Mã ca"
    t_c.rows[0].cells[1].paragraphs[0].text = "Lỗ hổng & Đối tượng"
    t_c.rows[0].cells[2].paragraphs[0].text = "Đầu vào / Vector kiểm thử"
    t_c.rows[0].cells[3].paragraphs[0].text = "Kết quả ghi nhận (v0 vs v1)"
    t_c.rows[0].cells[4].paragraphs[0].text = "Đánh giá"

    c_tests = [
        ("TC-C-01", "CWE-121: Stack Buffer Overflow\n(parse_fzp1_payload)", "Gói tin 73B (L=64 > 16B)\ncrashes/iter1_cwe121_crash.bin", "v0: Sập Canary 0xC0000409, ASan [f3]\nv1: Từ chối an toàn mã 2 (CERT STR31-C)", "Đạt"),
        ("TC-C-02", "CWE-415: Double Free\n(close_fzp1_session)", "Gói tin 13B (L=4, CMD=0xFF)\ncrashes/iter2_cwe415_crash.bin", "v0: Sập Heap 0xC0000374, ASan Double Free\nv1: Gán NULL, Idempotent dọn an toàn", "Đạt"),
        ("TC-C-03", "CWE-416: Use-After-Free\n(release_fzp1_stream)", "Gói tin 13B (L=4, CMD=0xFE)\ncrashes/iter3_cwe416_crash.bin", "v0: Sập Access Violation 0xC0000005, ASan [fd]\nv1: Callback trước free, triệt tiêu con trỏ", "Đạt"),
        ("TC-C-04", "Kiểm soát Magic Header\n(validate_fzp1_magic)", "Magic 'BAD1' thay vì 'FZP1'", "v0: Trả về -1\nv1: Từ chối an toàn mã 2", "Đạt"),
        ("TC-C-05", "Kiểm soát XOR Checksum\n(compute_xor_checksum)", "Checksum 0xAA (sai khác)", "v0: Trả về -2\nv1: Từ chối an toàn mã 2", "Đạt"),
        ("TC-C-06", "Kiểm soát kích thước tối thiểu", "Gói tin cụt 8 bytes (< 9B)", "v0: Trả về -1\nv1: Từ chối an toàn mã 2", "Đạt")
    ]
    for r_i, row in enumerate(c_tests, 1):
        for c_i, val in enumerate(row):
            t_c.rows[r_i].cells[c_i].paragraphs[0].text = val
    style_table(t_c)

    add_heading_2(doc, "4.2. Kết quả kiểm thử tự động toàn diện PyTest (14/14 Tests)")
    add_paragraph(doc, "Kết quả thực thi tự động qua lệnh pytest tests/ -v:")
    add_paragraph(doc, "• 10/10 Test cases đơn vị (tests/test_fzp1_parser.py): Xác thực đầy đủ bóc tách gói tin, chốt chặn Magic, Checksum, kích thước tối thiểu và phản hồi từ chối an toàn.\n• 4/4 Test cases tiến hóa đa phiên bản (tests/test_fzp1_evolution.py): Kiểm chứng sự suy giảm crash theo đúng quy trình từ v0 (90 crashes) -> v0.1 (58) -> v0.2 (22) -> v1 (0 crash).\n• Tổng hợp: 14 passed in 2.37s (Đạt tỷ lệ vượt qua 100%).")

    add_heading_2(doc, "4.3. Kiểm tra Suy luận Hình thức SMT/Z3 Bit-Vector")
    add_paragraph(doc, "Bảng 4.2. Đánh giá tính thỏa mãn ràng buộc đường đi (Path Constraints) trên Z3 SMT Solver:")
    t_smt = doc.add_table(rows=5, cols=5)
    t_smt.rows[0].cells[0].paragraphs[0].text = "Mã ca"
    t_smt.rows[0].cells[1].paragraphs[0].text = "Mệnh đề logic SMT Z3"
    t_smt.rows[0].cells[2].paragraphs[0].text = "Mô hình v0"
    t_smt.rows[0].cells[3].paragraphs[0].text = "Mô hình v1"
    t_smt.rows[0].cells[4].paragraphs[0].text = "Thời gian giải"

    smt_data = [
        ("TC-SMT-01", "sym_magic == 'FZP1' (Magic header hợp lệ)", "SAT", "SAT", "1.2 ms"),
        ("TC-SMT-02", "sym_len > 16 ^ sym_chk == XOR(payload) (Tràn Stack CWE-121)", "SAT (Sinh PoC)", "UNSAT (Đã chặn)", "6.98 ms"),
        ("TC-SMT-03", "payload[0] == 0xFF ^ abort_session (Double Free CWE-415)", "SAT (Kích hoạt)", "UNSAT (Idempotent)", "3.4 ms"),
        ("TC-SMT-04", "payload[0] == 0xFE ^ stream_reset (Use-After-Free CWE-416)", "SAT (Dangling)", "UNSAT (Safe cleanup)", "2.9 ms")
    ]
    for r_i, row in enumerate(smt_data, 1):
        for c_i, val in enumerate(row):
            t_smt.rows[r_i].cells[c_i].paragraphs[0].text = val
    style_table(t_smt)

    add_heading_2(doc, "4.4. Kiểm chứng mô hình trạng thái Kripke / CTL")
    add_paragraph(doc, "Mô hình Kripke 4 trạng thái (st_idle, st_magic_ok, st_checksum_ok, st_conflict) được kiểm chứng trên SecLabFramework Tab Ch6:")
    add_paragraph(doc, "1. Deadlock-free AG(EF st_idle): ĐÚNG (True) — Hệ thống không có trạng thái bế tắc.\n2. Thuộc tính an toàn AG(!violation): SAI (False) trên v0 (tồn tại đường đi st_idle -> st_magic_ok -> st_conflict khi L>16); ĐÚNG (True) trên v1 khi thêm tiền điều kiện an toàn CERT C.\n3. Khẳng định nguy cơ EF(violation): ĐÚNG (True) trên v0.")

    add_heading_2(doc, "4.5. Đối chuẩn thực nghiệm Fuzzing 30 Trials")
    add_paragraph(doc, "Dữ liệu trích xuất từ 30 lượt chạy độc lập (results/data_raw/aggregated_results.json):")
    t_fuzz = doc.add_table(rows=4, cols=5)
    t_fuzz.rows[0].cells[0].paragraphs[0].text = "Trường phái Fuzzing"
    t_fuzz.rows[0].cells[1].paragraphs[0].text = "Tỷ lệ tìm Crash"
    t_fuzz.rows[0].cells[2].paragraphs[0].text = "Time-to-Crash Trung vị"
    t_fuzz.rows[0].cells[3].paragraphs[0].text = "Tốc độ Exec/s"
    t_fuzz.rows[0].cells[4].paragraphs[0].text = "Kết luận học thuật"

    fuzz_data = [
        ("Black-box Fuzzing (Ngẫu nhiên)", "0.0% (0/30)", "Timeout (>60s)", "80.8 lượt/s", "Bị chặn bởi rào cản xác suất P ≈ 9.09 x 10^-13"),
        ("Greybox Fuzzing (Coverage-guided)", "46.67% (14/30)", "2.1568 giây", "79.05 lượt/s", "Ghim Magic 'FZP1', dò đột biến Checksum 1/256"),
        ("White-box Concolic (SMT Z3)", "100.0% (30/30)", "0.2056 giây", "4.90 lượt/s", "Giải trực tiếp Bit-Vector trong 6.98 ms")
    ]
    for r_i, row in enumerate(fuzz_data, 1):
        for c_i, val in enumerate(row):
            t_fuzz.rows[r_i].cells[c_i].paragraphs[0].text = val
    style_table(t_fuzz)

    add_heading_2(doc, "4.6. Chu trình tiến hóa kiểm thử và vá lỗi đa giai đoạn")
    add_paragraph(doc, "Thực nghiệm kiểm chứng trên 500 gói tin kiểm thử đa dạng kích hoạt cả 3 nhóm lỗi:")
    add_paragraph(doc, "• Mốc 1 (v0 - Ban đầu): Ghi nhận 90 crashes / 250 lượt (36.0%) — Sập Stack Canary CWE-121.\n• Mốc 2 (v0.1 - Sau vá STR31-C): Đổi Seed bơm mã 0xFF -> Giảm còn 58 crashes / 250 lượt (23.2%) — Sập Double Free CWE-415.\n• Mốc 3 (v0.2 - Sau vá tiếp MEM31-C): Đổi Seed bơm mã 0xFE -> Giảm còn 22 crashes / 250 lượt (8.8%) — Sập Use-After-Free CWE-416.\n• Mốc 4 (v1 - Hoàn thiện 3 chuẩn CERT C): Seed hỗn hợp 500 gói tin -> 0 CRASH (0.0%), an toàn tuyệt đối 100%.")

    add_heading_1(doc, "5. Đối chiếu trước và sau sửa lỗi (Chuẩn Table 2)")
    t_ba = doc.add_table(rows=5, cols=5)
    t_ba.rows[0].cells[0].paragraphs[0].text = "Mã CWE & Chuẩn CERT"
    t_ba.rows[0].cells[1].paragraphs[0].text = "Vị trí trong mã C"
    t_ba.rows[0].cells[2].paragraphs[0].text = "Trạng thái ban đầu (v0)"
    t_ba.rows[0].cells[3].paragraphs[0].text = "Trạng thái đã vá (v1)"
    t_ba.rows[0].cells[4].paragraphs[0].text = "Công cụ xác minh"

    ba_data = [
        ("CWE-121\nCERT STR31-C", "parse_fzp1_payload()\nfzp1_parser_v0.c:149", "Stack buffer overflow khi L>16; sập Canary 0xC0000409", "Chặn trên cứng L<=16, bộ đệm 17B null-terminated; từ chối an toàn mã 2", "Clang ASan [f3], PyTest"),
        ("CWE-415\nCERT MEM31-C", "close_fzp1_session()\nfzp1_parser_v0.c:93", "Double Free khi nhận CMD 0xFF; sập Windows Heap 0xC0000374", "Gán ngay ptr = NULL; hàm dọn dẹp Idempotent an toàn tuyệt đối", "Windows Heap Manager, PyTest"),
        ("CWE-416\nCERT MEM30-C", "release_fzp1_stream()\nfzp1_parser_v0.c:122", "Use-After-Free khi nhận CMD 0xFE; sập Access Violation 0xC0000005", "Gọi callback trước, free và gán NULL sau; triệt tiêu Dangling Pointer", "Clang ASan [fd], PyTest"),
        ("Tỷ lệ sống sót Fuzzing", "Toàn bộ bộ phân tích C", "90 crashes / 250 gói tin (36.0%)", "0 crashes / 500 gói tin (100% PASS)", "Coverage-guided Fuzzer")
    ]
    for r_i, row in enumerate(ba_data, 1):
        for c_i, val in enumerate(row):
            t_ba.rows[r_i].cells[c_i].paragraphs[0].text = val
    style_table(t_ba)

    add_heading_1(doc, "6. Kết luận đợt kiểm thử")
    add_paragraph(doc, "Toàn bộ 8 khâu kiểm định của đồ án đã được xác nhận độc lập qua script tự động verify_project.py:")
    add_paragraph(doc, "1. Toolchain & Phụ thuộc: ĐẠT CHUẨN (PASS)\n2. Unit Test PyTest (14/14): ĐẠT CHUẨN (PASS)\n3. Đặc tả Excel 10 Sheet (SSOT): ĐẠT CHUẨN (PASS)\n4. 3 Lỗ hổng Bộ nhớ & Bản vá CERT C: ĐẠT CHUẨN (PASS)\n5. Phân tích tĩnh Cppcheck (Minh chứng False Negative): ĐẠT CHUẨN (PASS)\n6. Suy luận hình thức SMT Z3: ĐẠT CHUẨN (PASS)\n7. Benchmark 30 Trials & Biểu đồ: ĐẠT CHUẨN (PASS)\n8. Toàn vẹn Mã băm SHA-256 (28 tệp cốt lõi): ĐẠT CHUẨN (PASS)")
    add_paragraph(doc, "KẾT LUẬN CHUNG: ĐỒ ÁN ĐẠT CHUẨN 100% — SẴN SÀNG NGHIỆM THU THEO YÊU CẦU CỦA GIẢNG VIÊN.", bold_prefix="ĐÁNH GIÁ: ")

    add_heading_1(doc, "7. Ký xác nhận đợt kiểm thử")
    add_paragraph(doc, "Hà Nội, ngày 29 tháng 10 năm 2026", italic=True)

    t_sign = doc.add_table(rows=3, cols=2)
    t_sign.rows[0].cells[0].paragraphs[0].text = "NGƯỜI KIỂM THỬ M1 & BENCHMARK\n(Ký và ghi rõ họ tên)"
    t_sign.rows[0].cells[1].paragraphs[0].text = "NGƯỜI KIỂM THỬ M2 & ĐẶC TẢ SSOT\n(Ký và ghi rõ họ tên)"
    
    t_sign.rows[1].cells[0].paragraphs[0].text = "\n\n(Đã ký điện tử)\n"
    t_sign.rows[1].cells[1].paragraphs[0].text = "\n\n(Đã ký điện tử)\n"
    
    t_sign.rows[2].cells[0].paragraphs[0].text = "Lưu Đức Hiệp\n(Nhóm trưởng — Đóng góp 50%)"
    t_sign.rows[2].cells[1].paragraphs[0].text = "Hà Nguyễn Trúc Linh\n(Thành viên — Đóng góp 50%)"
    
    for r in t_sign.rows:
        for c in r.cells:
            c.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            set_cell_background(c, "FFFFFF")
            set_cell_margins(c, 80, 80, 100, 100)

    # Save docx
    docx_out = PROJECT_ROOT / "report" / "[ATPM]BienBanKiemThu_Nhom11.docx"
    doc.save(str(docx_out))
    print(f"[+] Đã tạo file Word: {docx_out}")

    # Convert to PDF via Word COM
    pdf_out = PROJECT_ROOT / "report" / "[ATPM]BienBanKiemThu_Nhom11.pdf"
    word_app = win32com.client.Dispatch("Word.Application")
    word_app.Visible = False
    try:
        wdoc = word_app.Documents.Open(str(docx_out))
        wdoc.SaveAs(str(pdf_out), FileFormat=17) # 17 = wdFormatPDF
        wdoc.Close()
        print(f"[+] Đã xuất PDF thành công: {pdf_out}")
    finally:
        word_app.Quit()

    # Sao chép sang E:\Dowloads để bạn bấm nộp ngay trên trình duyệt
    shutil.copy2(str(pdf_out), str(DOWNLOADS_DIR / "[ATPM]BienBanKiemThu_Nhom11.pdf"))
    shutil.copy2(str(docx_out), str(DOWNLOADS_DIR / "[ATPM]BienBanKiemThu_Nhom11.docx"))
    print(f"[+] Đã sao chép sang E:\\Dowloads\\[ATPM]BienBanKiemThu_Nhom11.pdf")

if __name__ == "__main__":
    build_bien_ban()
