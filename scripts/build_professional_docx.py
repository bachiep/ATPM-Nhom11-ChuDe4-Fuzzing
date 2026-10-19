"""
=============================================================================
BỘ BIÊN DỊCH BÁO CÁO BTL SANG MICROSOFT WORD (.DOCX) CHUẨN ACADEMIC PHENIKAA
Học phần: Kỹ thuật Lập trình An toàn (CSE703093 / CSE703153)
Giảng viên: ThS. Vũ Quang Dũng — Trường CNTT, Đại học Phenikaa
Nhóm 11: Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (Chủ đề 4: Fuzzing)
=============================================================================
Đặc tả định dạng:
- Khổ giấy: A4 (210 x 297 mm)
- Lề trang: Trái 2.5 cm, Phải 2.0 cm, Trên 2.0 cm, Dưới 2.0 cm
- Font chữ: Times New Roman (chuẩn Báo cáo Đồ án ĐH Phenikaa & report_guide.pdf)
- Cỡ chữ: 12pt văn bản thường, dãn dòng 1.25, cách đoạn 4pt
- Tiêu đề: Màu Navy chuẩn (#1F4E79), đánh số phân cấp rõ ràng
- Bảng biểu: Header Navy, viền mảnh, sọc xen kẽ (Zebra striping), lặp header
- Code block: Consolas 9.5pt, nền xám nhạt, viền xanh bên trái
- Hình ảnh: Căn giữa, chú thích in nghiêng
- Trang bìa: Trang bìa đồ án trang trọng chuẩn Đại học Phenikaa
=============================================================================
"""

import os
import re
import sys
from pathlib import Path
import docx
from docx.shared import Inches, Pt, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import qn, nsdecls

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parent.parent

NAVY_COLOR = RGBColor(31, 78, 121)       # #1F4E79
BLUE_ACCENT = RGBColor(46, 117, 182)     # #2E75B6
DARK_GRAY = RGBColor(68, 84, 106)        # #44546A
MUTED_GRAY = RGBColor(89, 89, 89)        # #595959
CODE_COLOR = RGBColor(160, 32, 32)       # Dark Red for inline code

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

def set_table_borders(table, color="D0D5DD", sz="4"):
    tblPr = table._tbl.tblPr
    borders = parse_xml(f'''
        <w:tblBorders {nsdecls("w")}>
            <w:top w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>
            <w:bottom w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>
            <w:left w:val="none"/>
            <w:right w:val="none"/>
            <w:insideH w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>
            <w:insideV w:val="none"/>
        </w:tblBorders>
    ''')
    tblPr.append(borders)

def clean_latex(text: str) -> str:
    """Chuyển đổi cú pháp LaTeX đơn giản sang ký tự Unicode tương đương."""
    subs = [
        (r"\$v_0\$", "v₀"),
        (r"\$v_1\$", "v₁"),
        (r"v_0", "v₀"),
        (r"v_1", "v₁"),
        (r"\\le", "≤"),
        (r"\\ge", "≥"),
        (r"\\approx", "≈"),
        (r"\\times", "×"),
        (r"\\neg", "¬"),
        (r"\\implies", "⟹"),
        (r"\\in", "∈"),
        (r"\\subset", "⊂"),
        (r"\\cdot", "·"),
        (r"\\text\{([^\}]+)\}", r"\1"),
        (r"\\quad", "  "),
        (r"\$", ""),
    ]
    res = text
    for p, r in subs:
        res = re.sub(p, r, res)
    return res

def add_formatted_runs(paragraph, text: str, font_name="Times New Roman", font_size=13, default_color=None, bold_all=False, italic_all=False):
    """Phân tích chuỗi markdown có **bold**, *italic*, `code`, và toán học LaTeX sang các Run định dạng chuẩn."""
    # Pattern phân tách tokens: inline code `...`, bold **...**, italic *...*
    token_pattern = re.compile(r"(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)")
    parts = token_pattern.split(text)

    for part in parts:
        if not part:
            continue
        if part.startswith("`") and part.endswith("`") and len(part) >= 2:
            code_content = part[1:-1]
            run = paragraph.add_run(code_content)
            run.font.name = "Consolas"
            run.font.size = Pt(font_size * 0.9)
            run.font.color.rgb = CODE_COLOR
            run.font.bold = True
        elif part.startswith("**") and part.endswith("**") and len(part) >= 4:
            bold_content = clean_latex(part[2:-2])
            run = paragraph.add_run(bold_content)
            run.font.name = font_name
            run.font.size = Pt(font_size)
            run.font.bold = True
            if italic_all:
                run.font.italic = True
            if default_color:
                run.font.color.rgb = default_color
        elif part.startswith("*") and part.endswith("*") and len(part) >= 2:
            italic_content = clean_latex(part[1:-1])
            run = paragraph.add_run(italic_content)
            run.font.name = font_name
            run.font.size = Pt(font_size)
            run.font.italic = True
            if bold_all:
                run.font.bold = True
            if default_color:
                run.font.color.rgb = default_color
        else:
            normal_content = clean_latex(part)
            run = paragraph.add_run(normal_content)
            run.font.name = font_name
            run.font.size = Pt(font_size)
            run.font.bold = bold_all
            run.font.italic = italic_all
            if default_color:
                run.font.color.rgb = default_color

def create_phenikaa_cover_page(doc):
    """Tạo trang bìa phong cách học thuật chuẩn Trường Công nghệ Thông tin - Đại học Phenikaa."""
    p_univ = doc.add_paragraph()
    p_univ.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_univ.paragraph_format.space_before = Pt(0)
    p_univ.paragraph_format.space_after = Pt(2)
    r1 = p_univ.add_run("TRƯỜNG ĐẠI HỌC PHENIKAA\n")
    r1.font.name = "Times New Roman"
    r1.font.size = Pt(13)
    r1.font.bold = True
    r2 = p_univ.add_run("TRƯỜNG CÔNG NGHỆ THÔNG TIN")
    r2.font.name = "Times New Roman"
    r2.font.size = Pt(13)
    r2.font.bold = True
    r2.font.color.rgb = NAVY_COLOR

    p_line = doc.add_paragraph()
    p_line.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_line.paragraph_format.space_after = Pt(36)
    r_line = p_line.add_run("———————————————")
    r_line.font.name = "Times New Roman"
    r_line.font.size = Pt(12)
    r_line.font.bold = True
    r_line.font.color.rgb = DARK_GRAY

    # Tiêu đề báo cáo
    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_before = Pt(18)
    p_title.paragraph_format.space_after = Pt(10)
    r_btl = p_title.add_run("BÁO CÁO ĐỒ ÁN MÔN HỌC")
    r_btl.font.name = "Times New Roman"
    r_btl.font.size = Pt(22)
    r_btl.font.bold = True
    r_btl.font.color.rgb = NAVY_COLOR

    p_sub = doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_sub.paragraph_format.space_after = Pt(4)
    r_hp = p_sub.add_run("HỌC PHẦN: KỸ THUẬT LẬP TRÌNH AN TOÀN (SOFTWARE SECURITY)\n")
    r_hp.font.name = "Times New Roman"
    r_hp.font.size = Pt(13)
    r_hp.font.bold = True
    r_code = p_sub.add_run("Mã học phần: CSE703093 / CSE703153")
    r_code.font.name = "Times New Roman"
    r_code.font.size = Pt(12)
    r_code.font.italic = True

    # Khung đề tài
    p_box = doc.add_paragraph()
    p_box.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_box.paragraph_format.space_before = Pt(28)
    p_box.paragraph_format.space_after = Pt(8)
    r_box1 = p_box.add_run("CHỦ ĐỀ 4: DỰ ÁN FUZZING\n")
    r_box1.font.name = "Times New Roman"
    r_box1.font.size = Pt(16)
    r_box1.font.bold = True
    r_box1.font.color.rgb = RGBColor(192, 0, 0)

    p_topic = doc.add_paragraph()
    p_topic.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_topic.paragraph_format.space_after = Pt(36)
    r_top1 = p_topic.add_run("PHÂN TÍCH VÀ KIỂM THỬ AN TOÀN BỘ PHÂN TÍCH CÚ PHÁP GÓI TIN NHỊ PHÂN FZP1\n")
    r_top1.font.name = "Times New Roman"
    r_top1.font.size = Pt(14)
    r_top1.font.bold = True
    r_top1.font.color.rgb = NAVY_COLOR
    r_top2 = p_topic.add_run("Đối sánh Định lượng 3 Trường phái: Black-box, Greybox và White-box Concolic SMT Z3")
    r_top2.font.name = "Times New Roman"
    r_top2.font.size = Pt(12)
    r_top2.font.italic = True

    # Bảng thông tin nhóm
    table = doc.add_table(rows=5, cols=2)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(table, color="FFFFFF") # Không viền

    info_data = [
        ("Giảng viên hướng dẫn:", "ThS. Vũ Quang Dũng"),
        ("Nhóm thực hiện:", "Nhóm 11"),
        ("Thành viên nhóm:", "1. Lưu Đức Hiệp (Nhóm trưởng — Đóng góp: 50%)\n2. Hà Nguyễn Trúc Linh (Thành viên — Đóng góp: 50%)"),
        ("Mã sinh viên & Lớp:", "[Bảo mật theo quy định]"),
        ("Kho lưu trữ GitHub:", "https://github.com/bachiep/ATPM-Nhom11-ChuDe4-Fuzzing")
    ]

    for row_idx, (label, val) in enumerate(info_data):
        cell_lbl = table.cell(row_idx, 0)
        cell_val = table.cell(row_idx, 1)
        cell_lbl.width = Inches(2.2)
        cell_val.width = Inches(4.5)

        p_lbl = cell_lbl.paragraphs[0]
        p_lbl.paragraph_format.space_after = Pt(4)
        r_l = p_lbl.add_run(label)
        r_l.font.name = "Times New Roman"
        r_l.font.size = Pt(11.5)
        r_l.font.bold = True

        p_v = cell_val.paragraphs[0]
        p_v.paragraph_format.space_after = Pt(4)
        r_v = p_v.add_run(val)
        r_v.font.name = "Times New Roman"
        r_v.font.size = Pt(11.5)

    # Chân trang bìa
    p_bottom = doc.add_paragraph()
    p_bottom.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_bottom.paragraph_format.space_before = Pt(50)
    p_bottom.paragraph_format.space_after = Pt(0)
    r_bot = p_bottom.add_run("HÀ NỘI — THÁNG 10/2026")
    r_bot.font.name = "Times New Roman"
    r_bot.font.size = Pt(12)
    r_bot.font.bold = True
    r_bot.font.color.rgb = DARK_GRAY

    doc.add_page_break()

def setup_header_footer(doc):
    """Thiết lập Header và Footer học thuật."""
    section = doc.sections[0]
    section.different_first_page_header_footer = True

    # Header trang 2 trở đi
    header = section.header
    p_hdr = header.paragraphs[0]
    p_hdr.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    r_hdr = p_hdr.add_run("Học phần Kỹ thuật Lập trình An toàn — BTL Nhóm 11: FZP1 Fuzzing Benchmark")
    r_hdr.font.name = "Times New Roman"
    r_hdr.font.size = Pt(9)
    r_hdr.font.italic = True
    r_hdr.font.color.rgb = MUTED_GRAY

    # Footer trang 2 trở đi
    footer = section.footer
    p_ftr = footer.paragraphs[0]
    p_ftr.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_ftr = p_ftr.add_run("Trường Công nghệ Thông tin — Đại học Phenikaa")
    r_ftr.font.name = "Times New Roman"
    r_ftr.font.size = Pt(9)
    r_ftr.font.color.rgb = MUTED_GRAY

def style_academic_table(table, header_bg="1F4E79"):
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(table, color="D0D5DD", sz="4")

    for i, row in enumerate(table.rows):
        trPr = row._tr.get_or_add_trPr()
        trPr.append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>')) # Không ngắt đôi hàng giữa trang

        if i == 0:
            trPr.append(parse_xml(f'<w:tblHeader {nsdecls("w")}/>')) # Lặp header khi sang trang

        for cell in row.cells:
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            set_cell_margins(cell, top=120, bottom=120, left=150, right=150)

            if i == 0:
                set_cell_background(cell, header_bg)
                for p in cell.paragraphs:
                    p.paragraph_format.space_before = Pt(4)
                    p.paragraph_format.space_after = Pt(4)
                    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    for run in p.runs:
                        run.font.name = "Times New Roman"
                        run.font.bold = True
                        run.font.size = Pt(10.5)
                        run.font.color.rgb = RGBColor(255, 255, 255)
            else:
                if i % 2 == 1:
                    set_cell_background(cell, "F8F9FA")
                else:
                    set_cell_background(cell, "FFFFFF")
                for p in cell.paragraphs:
                    p.paragraph_format.space_before = Pt(3)
                    p.paragraph_format.space_after = Pt(3)
                    for run in p.runs:
                        run.font.name = "Times New Roman"
                        run.font.size = Pt(10)

def convert_markdown_to_academic_docx(md_path: Path, docx_path: Path, has_cover_page: bool = True):
    doc = docx.Document()

    # Cấu hình lề trang theo chuẩn luận văn Phenikaa (Trái 2.5cm, Phải 2.0cm, Trên 2.0cm, Dưới 2.0cm)
    for section in doc.sections:
        section.top_margin = Cm(2.0)
        section.bottom_margin = Cm(2.0)
        section.left_margin = Cm(2.5)
        section.right_margin = Cm(2.0)
        section.page_width = Cm(21.0)
        section.page_height = Cm(29.7)

    # Cấu hình phông chữ mặc định Times New Roman, cỡ 13, dãn dòng 1.5 theo quy định học thuật Phenikaa
    style_normal = doc.styles['Normal']
    style_normal.font.name = 'Times New Roman'
    style_normal.font.size = Pt(13)
    style_normal.paragraph_format.line_spacing = 1.5
    style_normal.paragraph_format.space_after = Pt(6)

    if has_cover_page:
        create_phenikaa_cover_page(doc)
        setup_header_footer(doc)
        skip_md_cover = True
    else:
        skip_md_cover = False

    with open(md_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    in_code_block = False
    code_lines = []
    in_table = False
    table_data = []

    for line in lines:
        raw_line = line.strip()

        # Kết thúc bỏ qua phần bìa markdown khi gặp "CAM KẾT LIÊM CHÍNH HỌC THUẬT"
        if has_cover_page and "CAM KẾT LIÊM CHÍNH HỌC THUẬT" in raw_line:
            skip_md_cover = False

        if skip_md_cover:
            continue

        # Xử lý khối code
        if raw_line.startswith("```"):
            if in_code_block:
                in_code_block = False
                p = doc.add_paragraph()
                p.paragraph_format.left_indent = Inches(0.3)
                p.paragraph_format.space_before = Pt(4)
                p.paragraph_format.space_after = Pt(4)
                p.paragraph_format.line_spacing = 1.15
                
                # Nền xám và viền trái cho khối code
                pPr = p._p.get_or_add_pPr()
                pBdr = parse_xml(f'''
                    <w:pBdr {nsdecls("w")}>
                        <w:left w:val="single" w:sz="18" w:space="8" w:color="1F4E79"/>
                    </w:pBdr>
                ''')
                pPr.append(pBdr)
                shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="F4F6F8"/>')
                pPr.append(shd)

                code_text = "\n".join(code_lines)
                run = p.add_run(code_text)
                run.font.name = "Consolas"
                run.font.size = Pt(9.0)
                run.font.color.rgb = RGBColor(30, 30, 70)
                code_lines = []
            else:
                in_code_block = True
                code_lines = []
            continue

        if in_code_block:
            code_lines.append(line.rstrip())
            continue

        # Xử lý hình ảnh ![caption](path)
        if raw_line.startswith("![") and "](" in raw_line and raw_line.endswith(")"):
            caption = raw_line[2:raw_line.find("](")]
            rel_img_path = raw_line[raw_line.find("](") + 2 : -1]
            full_img_path = (PROJECT_ROOT / "results" / rel_img_path).resolve()
            if not full_img_path.exists():
                full_img_path = (PROJECT_ROOT / "report" / rel_img_path).resolve()
            if not full_img_path.exists():
                full_img_path = (PROJECT_ROOT / rel_img_path).resolve()

            if full_img_path.exists():
                try:
                    p_img = doc.add_paragraph()
                    p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    p_img.paragraph_format.space_before = Pt(10)
                    p_img.paragraph_format.space_after = Pt(3)
                    run_img = p_img.add_run()
                    run_img.add_picture(str(full_img_path), width=Inches(5.8))

                    p_cap = doc.add_paragraph()
                    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    p_cap.paragraph_format.space_after = Pt(10)
                    r_cap = p_cap.add_run(f"Hình: {caption}")
                    r_cap.font.name = "Times New Roman"
                    r_cap.font.size = Pt(10)
                    r_cap.font.italic = True
                    r_cap.font.color.rgb = DARK_GRAY
                except Exception as e:
                    print(f"[-] Lỗi chèn ảnh {full_img_path}: {e}")
            else:
                # Khung chờ minh chứng thực tế chuyên nghiệp, không tự vẽ hoặc giả mạo ảnh
                tbl_ph = doc.add_table(rows=1, cols=1)
                tbl_ph.alignment = WD_TABLE_ALIGNMENT.CENTER
                cell_ph = tbl_ph.cell(0, 0)
                set_cell_background(cell_ph, "FFFDF5")
                set_cell_margins(cell_ph, top=140, bottom=140, left=180, right=180)
                p_ph = cell_ph.paragraphs[0]
                p_ph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p_ph.paragraph_format.space_before = Pt(4)
                p_ph.paragraph_format.space_after = Pt(4)
                p_ph.paragraph_format.line_spacing = 1.25

                r1 = p_ph.add_run("📷 [KHUNG CHỜ CHÈN ẢNH MINH CHỨNG THỰC TẾ]\n")
                r1.font.name = "Times New Roman"
                r1.font.size = Pt(11)
                r1.font.bold = True
                r1.font.color.rgb = RGBColor(180, 80, 0)

                r2 = p_ph.add_run(f"Nội dung minh chứng: {caption}\n")
                r2.font.name = "Times New Roman"
                r2.font.size = Pt(10.5)
                r2.font.bold = True
                r2.font.color.rgb = DARK_GRAY

                r3 = p_ph.add_run(
                    f"Đường dẫn tệp cần bổ sung: report/{rel_img_path}\n"
                    f"(Ghi chú: Sinh viên tự thực hiện thao tác và chụp màn hình thực tế trên máy tính, "
                    f"lưu ảnh định dạng PNG vào đường dẫn trên. Hệ thống biên soạn sẽ tự động nhận diện và chèn ảnh thật vào vị trí này)."
                )
                r3.font.name = "Times New Roman"
                r3.font.size = Pt(9.5)
                r3.font.italic = True
                r3.font.color.rgb = MUTED_GRAY

                set_table_borders(tbl_ph, color="E0A96D", sz="6")

                p_space = doc.add_paragraph()
                p_space.paragraph_format.space_after = Pt(6)
            continue

        # Xử lý bảng Markdown
        if raw_line.startswith("|") and raw_line.endswith("|"):
            cols = [c.strip() for c in raw_line[1:-1].split("|")]
            if all(c.startswith(":") or c.startswith("-") for c in cols if c):
                continue
            table_data.append(cols)
            in_table = True
            continue
        else:
            if in_table and table_data:
                num_rows = len(table_data)
                num_cols = max(len(r) for r in table_data)
                t = doc.add_table(rows=num_rows, cols=num_cols)
                for r_idx, row in enumerate(table_data):
                    for c_idx, val in enumerate(row):
                        if c_idx < num_cols:
                            cell = t.cell(r_idx, c_idx)
                            p = cell.paragraphs[0]
                            p.text = "" # Xóa text mặc định
                            add_formatted_runs(p, val, font_name="Times New Roman", font_size=9.5, bold_all=(r_idx == 0))
                style_academic_table(t)
                p_after = doc.add_paragraph()
                p_after.paragraph_format.space_before = Pt(6)
                table_data = []
                in_table = False

        if not raw_line:
            continue

        # Ngắt trang trước mỗi phần chính lớn (PHẦN 2, 3, 4, 5, 6, 7, 8)
        if raw_line.startswith("# PHẦN ") and has_cover_page:
            doc.add_page_break()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(16)
            p.paragraph_format.space_after = Pt(8)
            p.paragraph_format.keep_with_next = True
            title_text = raw_line[2:]
            r = p.add_run(title_text)
            r.font.name = "Times New Roman"
            r.font.size = Pt(17)
            r.font.bold = True
            r.font.color.rgb = NAVY_COLOR
            continue

        # Các cấp đề mục
        if raw_line.startswith("# "):
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(16)
            p.paragraph_format.space_after = Pt(6)
            p.paragraph_format.keep_with_next = True
            r = p.add_run(clean_latex(raw_line[2:]))
            r.font.name = "Times New Roman"
            r.font.size = Pt(16.5)
            r.font.bold = True
            r.font.color.rgb = NAVY_COLOR
        elif raw_line.startswith("## "):
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(14)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.keep_with_next = True
            r = p.add_run(clean_latex(raw_line[3:]))
            r.font.name = "Times New Roman"
            r.font.size = Pt(15)
            r.font.bold = True
            r.font.color.rgb = BLUE_ACCENT
        elif raw_line.startswith("### "):
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(10)
            p.paragraph_format.space_after = Pt(3)
            p.paragraph_format.keep_with_next = True
            heading_text = raw_line[4:]
            add_formatted_runs(p, heading_text, font_name="Times New Roman", font_size=14, default_color=DARK_GRAY, bold_all=True)
        elif raw_line.startswith("#### "):
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(8)
            p.paragraph_format.space_after = Pt(2)
            p.paragraph_format.keep_with_next = True
            heading_text = raw_line[5:]
            add_formatted_runs(p, heading_text, font_name="Times New Roman", font_size=13, default_color=DARK_GRAY, bold_all=True, italic_all=True)
        elif raw_line.startswith("- ") or raw_line.startswith("* "):
            p = doc.add_paragraph(style='List Bullet')
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.line_spacing = 1.5
            p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            content = raw_line[2:]
            add_formatted_runs(p, content, font_name="Times New Roman", font_size=13)
        elif re.match(r"^\d+\.\s+", raw_line):
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Inches(0.25)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.line_spacing = 1.5
            p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            add_formatted_runs(p, raw_line, font_name="Times New Roman", font_size=13)
        elif raw_line.startswith("> "):
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Inches(0.3)
            p.paragraph_format.space_before = Pt(4)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.line_spacing = 1.5
            add_formatted_runs(p, raw_line[2:], font_name="Times New Roman", font_size=12.5, default_color=DARK_GRAY, italic_all=True)
        elif raw_line == "---":
            # Dòng phân cách nhẹ
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(6)
            p.paragraph_format.space_after = Pt(6)
            r = p.add_run("· · · · · · · · · · · · · · · · · ·")
            r.font.name = "Times New Roman"
            r.font.size = Pt(10)
            r.font.color.rgb = MUTED_GRAY
        else:
            p = doc.add_paragraph()
            p.paragraph_format.line_spacing = 1.5
            p.paragraph_format.space_after = Pt(6)
            p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            add_formatted_runs(p, raw_line, font_name="Times New Roman", font_size=13)

    doc.save(str(docx_path))
    print(f"[+] Hoàn tất xuất Word học thuật: {docx_path}")

def main():
    import shutil

    # 1. Báo cáo BTL chính thức
    report_md = PROJECT_ROOT / "report" / "BaoCao_BTL_Nhom11.md"
    report_docx = PROJECT_ROOT / "report" / "BaoCao_BTL_Nhom11.docx"
    convert_markdown_to_academic_docx(report_md, report_docx, has_cover_page=True)

    # 2. Cập nhật bản PDF song song qua Word COM
    try:
        import win32com.client
        word_app = win32com.client.Dispatch('Word.Application')
        word_app.Visible = False
        try:
            report_pdf = PROJECT_ROOT / "report" / "BaoCao_BTL_Nhom11.pdf"
            wdoc = word_app.Documents.Open(str(report_docx))
            wdoc.SaveAs(str(report_pdf), FileFormat=17)
            wdoc.Close()
            print(f"[+] Đã cập nhật PDF đồng bộ từ bản Word: {report_pdf}")
        finally:
            word_app.Quit()
    except Exception as e:
        print(f"[-] Bỏ qua xuất PDF qua COM: {e}")

if __name__ == "__main__":
    main()
