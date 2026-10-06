# MASTER DIRECTIVE: TÁI THIẾT KẾ ĐỒ ÁN MỚI 100% (CHỦ ĐỀ 4 - DỰ ÁN FUZZING)
**Học phần:** Kỹ thuật Lập trình An toàn (CSE703093 / CSE703153) — ThS. Vũ Quang Dũng (ĐH Phenikaa)  
**Đề tài chính thức:** **Chủ đề 4: Dự án Fuzzing (Parser có Magic Bytes / Checksum)**  
**Nhóm sinh viên:** Nhóm 11 — Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (Tỷ lệ đóng góp: 50% - 50%)  
*(Bảo mật: Tuyệt đối để trống Mã số sinh viên và Khóa/Lớp trên mọi tài liệu, trang bìa và cam đoan)*  
**Nguyên tắc tối thượng:** **CLEAN SLATE 100% — LÀM MỚI HOÀN TOÀN, TUYỆT ĐỐI KHÔNG DÙNG LẠI FILE CŨ**  
**Phương pháp luận:** **SPEC RIÊNG CỦA NHÓM $\rightarrow$ TOOL HỖ TRỢ 70% CÔNG VIỆC $\rightarrow$ SINH VIÊN HOÀN THIỆN 30% CHIỀU SÂU**

---

### PHẦN 1: BẢN CHẤT YÊU CẦU CỦA GIẢNG VIÊN & ĐỊNH HƯỚNG CỐT TỬ

1. **Ý nghĩa thực sự của "Tool đã hỗ trợ 70% công việc":**
   - Thầy Vũ Quang Dũng chỉ rõ rằng công cụ của Thầy (`SecLabFramework.exe`) đã gánh vác tới 70% khối lượng kỹ thuật nặng nhọc của một đồ án an toàn phần mềm:
     * Tự động kiểm chứng hình thức mô hình Kripke & CTL (tìm deadlock, vi phạm mutual exclusion, sinh mã TikZ LaTeX vector).
     * Tự động sinh mã nguồn C chứa các lỗi an toàn bộ nhớ từ đặc tả (CWE-121 Buffer Overflow, CWE-401 Leak, CWE-415 Double Free, CWE-416 Use-After-Free).
     * Tự động trích xuất AST và giải SMT Z3 Bit-Vector kiểm tra tràn số nguyên int32.
     * Tự động sinh khung hàm mục tiêu và chạy các thuật toán Fuzzing (Boundary, Blackbox, Mutation, Coverage-guided, Concolic SMT).
   - **30% phần việc còn lại là trách nhiệm cốt lõi của sinh viên (yếu tố quyết định điểm A+):**
     * Tự tay xây dựng file đặc tả Excel cho bài toán của riêng nhóm mình.
     * Thực hiện chiến dịch Fuzzing thực nghiệm định lượng cho **Chủ đề 4** (so sánh Black-box vs White-box vượt qua rào cản Magic Bytes).
     * Xây dựng bản vá an toàn chuẩn **CERT C** (STR31-C, MEM30-C, MEM31-C) khắc phục triệt để lỗi mã C do tool sinh ra.
     * Giải trình sâu cơ chế bộ nhớ mức thấp (Stack frame, Heap arena, Non-blocking lifecycle) để trả lời phản biện của Thầy.
     * Hoàn thiện báo cáo học thuật chỉn chu bảo vệ đồ án.

2. **Làm lại file Excel Đặc tả mới của riêng Nhóm 11:**
   - **THAM KHẢO** file mẫu `Template_Software_Security_iot_gateway_spec.xlsx` và cẩm nang `Huong_dan_tao_Spec_file_dang_excel.pdf` để hiểu quy chuẩn 10 sheet, tên cột và kiểu dữ liệu.
   - **TỰ THIẾT KẾ MỚI HOÀN TOÀN** file đặc tả của riêng Nhóm 11 phục vụ trực tiếp cho bài toán Parser của Chủ đề 4: có magic bytes `IGW1`, kiểm tra checksum, copy bộ đệm cố định, quản lý phiên và rào cản concolic. Đảm bảo mọi sheet dữ liệu $\ge 5$ dòng theo Checklist Chương 5 của Thầy.

3. **Cách ly bản cũ, bắt đầu mới 100%:**
   - Mã C cũ (`gateway_parser_v0.c`, `gateway_parser_v1.c`), spec cũ và các script fuzzer tự chế của phiên trước là bản đi theo lối mòn tự làm ngoài tool. Codex phải di chuyển toàn bộ vào thư mục `archive_legacy_v0/` để cách ly hoàn toàn, không dùng lại!

---

### PHẦN 2: BẢN ĐỒ TÀI NGUYÊN GỐC (SSOT)

* **Thư mục dự án:** `I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\`
* **Thư mục tài nguyên chuẩn của Thầy:** `I:\1_taiLieuDaiHoc\ATPM\TAI_LIEU_VA_YEU_CAU\`
  * `01_Huong_Dan_BTL_Va_Spec/`:
    - `Huong_dan_tao_Spec_file_dang_excel.pdf`: Cẩm nang 28 trang và Checklist Chương 5 của Thầy Dũng.
    - `Template_Software_Security_iot_gateway_spec.xlsx`: File đặc tả Excel 10 sheet của Thầy (để tham khảo cấu trúc).
    - `Template_Report_iot_gateway_auth.docx`: Mẫu báo cáo tích hợp do Tool xuất ra (để tham khảo cấu trúc).
  * `02_Yeu_Cau_Va_Luu_Y_Giang_Vien/`:
    - `YEU_CAU_VA_LUU_Y_GIANG_VIEN_KHO_TINH.md`: Cẩm nang trả lời các câu hỏi vấn đáp chuyên sâu của Thầy.
  * `04_Cong_Cu_Giang_Vien/`:
    - `SecLabFramework.exe` (104.8 MB): Phiên bản nâng cấp v27 của Thầy (đang mở trực tiếp trên màn hình máy người dùng dưới tên *Educational Security Suite — sec_lab_framework*).
* **Git Remote:** `https://github.com/bachiep/ATPM-Nhom11-ChuDe4-Fuzzing.git` (nhánh `main`).

---

### PHẦN 3: CẨM NANG TOÀN DIỆN VỀ CÔNG CỤ `SecLabFramework.exe` (v27)
*(Codex hãy đọc kỹ để hiểu toàn bộ cơ chế, từ đó tự suy nghĩ và quyết định lựa chọn những tính năng nào)*

Công cụ của Thầy là bộ phần mềm bảo mật tích hợp (**Educational Security Suite - sec_lab_framework v27**), đóng gói Python 3.14 (PyInstaller) tích hợp `customtkinter`, `z3-solver`, `pycparser`, `matplotlib`, `python-docx`.

#### 1. Hệ thống 6 Tab Giao diện Đồ họa (GUI):
* **Tab 1 — `Ch1: Kripke & Verification`:**
  - Nạp mô hình trạng thái ($S, S_0, R, L$), kiểm tra khả năng tiếp cận (BFS/DFS), phát hiện **Deadlock**, kiểm tra **Loại trừ lẫn nhau (Mutual Exclusion)**, kiểm chứng công thức CTL (`AG(!violation)`, `EF(main_locked)`), và **xuất đồ thị vector TikZ LaTeX** chèn vào báo cáo.
* **Tab 2 — `Ch2: Memory & Static C Check`:**
  - Quét tĩnh các hàm không an toàn (`strcpy`, `strcat`, `sprintf`, `gets`), phát hiện lỗi vòng đời bộ nhớ (`memory-leak`, `double-free`, `use-after-free`), và tính toán **Struct Alignment & Padding** (32-bit vs 64-bit).
* **Tab 3 — `Ch3: AST/CFG/SMT/BMC`:**
  - Trích xuất AST qua `pycparser`, dựng Control Flow Graph (CFG), giải ràng buộc số học Bit-Vector bằng **Z3 Solver** (tìm nghiệm tràn số int32), và Bounded Model Checking (BMC).
* ⭐ **Tab 4 — `Ch4: Coverage & Fuzzing` (TRỌNG TÂM CHỦ ĐỀ 4):**
  - Quản lý chiến dịch Fuzzing đa kỹ thuật:
    1. `Coverage Tracker`: Đo độ phủ nhánh thực thi (edge coverage).
    2. `Black-box Fuzzer`: Sinh payload ngẫu nhiên tìm crash chia 0 (`ZeroDivisionError` trong `risky_divide`).
    3. `Mutation Fuzzer`: Đột biến dữ liệu (bit-flip, byte-flip, arithmetic mutation).
    4. `White-box / Concolic Fuzzer`: Kết hợp trace thực thi với Z3 SMT giải ngược Magic Values phức tạp (`x==1234, y==5678`).
    5. `Sinh test + C wrap`: Bọc hàm C sang `ctypes` để sinh test case tự động và xuất bộ kiểm thử `pytest`.
    6. `Chiến dịch Fuzzing tuần tự`: Chạy tự động chuỗi `Boundary` $\rightarrow$ `Black-box` $\rightarrow$ `Mutation` $\rightarrow$ `Coverage-guided` $\rightarrow$ `White-box/Concolic`.
    7. `Xuất báo cáo chi tiết`: Xuất file PDF/DOCX chứa bảng so sánh kỹ thuật, biểu đồ coverage và số liệu crash.
* **Tab 5 — `Ch5: Secure C/C++ Programming`:**
  - 7 chuyên đề thực hành lập trình C an toàn theo chuẩn CERT C (kiểm tra biên, giải phóng heap, số nguyên, con trỏ, capstone).
* ⭐ **Tab 6 — `Ch6: Spec -> Kripke -> Code -> CWE/CVE` (CỖ MÁY TỰ ĐỘNG HÓA TÍCH HỢP):**
  - Nhận đầu vào là file Excel Đặc tả 10 sheet (hoặc JSON), tự động thực hiện:
    1. Đọc 10 sheet (`ThongTin`, `YeuCauChucNang`, `MoHinhTrangThai`, `HamSinhMa`, `TestCase`...).
    2. Tự động kiểm chứng Kripke và xuất mã TikZ LaTeX.
    3. Tự động sinh mã C chứa lỗi (`parse_device_id`, `write_log_entry`, `close_session`, `release_session_buffer`).
    4. Tự động sinh mã Python cho Fuzzing (`token_ratio`, `device_unlock_code`).
    5. Tự động kiểm chứng Z3 SMT cho bài toán tràn số `telemetry_byte_counter`.
    6. Tự động ánh xạ CWE/CVE và **xuất file Word Báo cáo Tích hợp (.docx)**!

#### 2. Hệ thống Lệnh Dòng Lệnh (CLI):
```powershell
.\SecLabFramework.exe                                    # 1. Chạy GUI
.\SecLabFramework.exe --cli                              # 2. Demo nhanh console
.\SecLabFramework.exe --cli-ch1                          # 3. Kripke/CTL Chương 1
.\SecLabFramework.exe --cli-ch2                          # 4. Quét lỗi bộ nhớ C Chương 2
.\SecLabFramework.exe --cli-ch5                          # 5. Luyện tập CERT C Chương 5
.\SecLabFramework.exe --cli-cwrap file.c --san auto --export dir  # 6. Wrap C, sinh test case mọi kiểu fuzzing
.\SecLabFramework.exe --cli-fuzz file.c --func f --iterations 1000 --san asan --export dir # 7. Fuzzing đa kỹ thuật + ASan
.\SecLabFramework.exe --cli-ch6-import PATH --iterations 500 --export rpt.txt              # 8. Import source code chạy pipeline Ch1-5
```
*(Nếu console PowerShell bị lỗi font tiếng Việt, hãy chạy trước: `$env:PYTHONIOENCODING="utf-8"; $env:PYTHONUTF8="1"; chcp 65001`)*.

---

### PHẦN 4: LỘ TRÌNH 4 BƯỚC TRIỂN KHAI CHO CODEX

Codex hãy tự suy nghĩ, phối hợp các tính năng của Tool và thực thi tuần tự:

#### BƯỚC 1: XÂY DỰNG FILE EXCEL ĐẶC TẢ MỚI CHO NHÓM 11
1. Cách ly toàn bộ file cũ vào thư mục `archive_legacy_v0/`.
2. Tạo file đặc tả mới của nhóm: `specification/Nhom11_IoT_Security_Parser_Spec.xlsx` (tham khảo định dạng từ `Template_Software_Security_iot_gateway_spec.xlsx`, nhưng viết mới 100% nội dung cho Parser Chủ đề 4: magic bytes `IGW1`, checksum 32-bit, buffer 16 bytes, đảm bảo $\ge 5$ dòng mỗi sheet dữ liệu).

#### BƯỚC 2: NẠP VÀO TOOL (`SecLabFramework.exe`) ĐỂ TOOL LÀM 70% CÔNG VIỆC
1. Nạp file Spec mới vào Tab **`Ch6: Spec -> Kripke -> Code -> CWE/CVE`** của `SecLabFramework.exe`.
2. Thu hoạch kết quả do Tool tự động sinh ra:
   - Mã C parser mới có lỗi bộ nhớ (lưu vào `source/gateway_parser_v0.c`).
   - Sơ đồ chuyển trạng thái Kripke và mã vector TikZ LaTeX.
   - Kết quả phân tích AST và Z3 SMT.
   - File Word báo cáo tích hợp gốc lưu tại `results/BaoCao_Goc_Tu_Tool.docx`.

#### BƯỚC 3: THỰC HIỆN 30% CÔNG VIỆC CỐT LÕI CỦA SINH VIÊN (CHỦ ĐỀ 4 FUZZING)
1. **Chiến dịch Fuzzing thực nghiệm Chủ đề 4 (Tab Ch4 & CLI `--cli-fuzz`):**
   - Chạy **Black-box Fuzzing**: Chứng minh tỷ lệ tìm ra 4 byte Magic Bytes `IGW1` hoặc Checksum ngẫu nhiên là 0%.
   - Chạy **White-box / Concolic Fuzzing (Z3 SMT)**: Chứng minh bộ giải SMT tìm ra Magic Value `(7421, 3390)` trong 1 lần thử duy nhất (~14ms).
   - Đo lường định lượng 30 trials thực nghiệm (iterations, time-to-crash, edge coverage), lưu log JSON thô vào `results/data_raw/`.
2. **Bản vá An toàn mới `source/gateway_parser_v1.c` chuẩn CERT C:**
   - **CERT STR31-C**: Thay `strcpy` bằng `snprintf` có kiểm tra bound.
   - **CERT MEM31-C**: Giải phóng bộ đệm heap ngay khi đóng phiên.
   - **CERT MEM30-C**: Gán `ptr = NULL` ngay sau khi `free()`.
3. **Phân tích Kiến trúc Bộ nhớ Mức thấp:**
   - **Stack Frame:** Sơ đồ ghi đè Return Address (RIP) và Saved Frame Pointer (RBP).
   - **Heap Arena:** Chunk metadata và Dangling Pointer dẫn đến Use-After-Free/Double-free.
   - **Non-blocking Worker:** Vòng đời cấp phát tạm trên Stack frame, giải phóng tức thì.
   - **Static vs Dynamic:** Cppcheck bỏ lọt lỗi do input động; AddressSanitizer (ASan) bắt chính xác qua **Shadow Bytes (0xfb - Stack Redzone)**.

#### BƯỚC 4: HỢP NHẤT BÁO CÁO, THẨM ĐỊNH & BÀN GIAO
1. Hợp nhất 70% kết quả tự động từ Tool với 30% phân tích chuyên sâu của sinh viên thành Báo cáo chính thức: `report/BaoCao_BTL_Nhom11.pdf` (biên dịch bằng Word COM script).
2. Kiểm định toàn diện bằng `scripts/verify_project.py` đạt **10/10 PASS** (100% tỷ lệ vượt qua).
3. Đóng gói `Nhom11_BTL_ChuDe4_Fuzzing.zip`, commit sạch sẽ và push lên `origin main`.

---
Codex, bạn đã nắm trọn vẹn cẩm nang về Tool và định hướng đồ án. Hãy tự suy nghĩ, lập kế hoạch hành động chi tiết và bắt đầu triển khai từ Bước 1!
