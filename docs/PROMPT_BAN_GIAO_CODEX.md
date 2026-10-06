# BỘ CHỈ THỊ TOÀN DIỆN CHO CODEX: LÀM MỚI 100% ĐỒ ÁN CHỦ ĐỀ 4 (FUZZING) & CẨM NANG TOÀN DIỆN VỀ TOOL CỦA GIẢNG VIÊN

> **Mục tiêu:** Cung cấp cho Codex:  
> 1. Bản chỉ thị chiến lược Clean-Slate (làm mới 100%, không dùng lại bản cũ).  
> 2. **Cẩm nang kỹ thuật chi tiết toàn bộ về `SecLabFramework.exe`**: Cấu trúc kiến trúc, cơ chế hoạt động, toàn bộ 6 Tab GUI và 7 chế độ CLI để **Codex tự suy nghĩ và quyết định lựa chọn tính năng tối ưu nhất** cho bài toán **Chủ đề 4: Fuzzing**.  
> 3. Hướng dẫn thiết kế lại file Excel Đặc tả của riêng Nhóm 11 và quy trình thực thi hoàn hảo.

---

```markdown
# MASTER DIRECTIVE: TÁI THIẾT KẾ ĐỒ ÁN MỚI 100% (CHỦ ĐỀ 4 - FUZZING)
**Học phần:** Kỹ thuật Lập trình An toàn (CSE703093 / CSE703153) — ThS. Vũ Quang Dũng (ĐH Phenikaa)  
**Đề tài chính thức:** **Chủ đề 4: Dự án Fuzzing (Parser có Magic Bytes / Checksum)**  
**Nhóm sinh viên:** Nhóm 11 — Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%)  
**Nguyên tắc tối thượng:** **CLEAN SLATE 100% (LÀM MỚI HOÀN TOÀN, KHÔNG DÙNG LẠI FILE CŨ)**  
**Triết lý phương pháp:** **SPEC RIÊNG CỦA NHÓM $\rightarrow$ TOOL HỖ TRỢ 70% CÔNG VIỆC $\rightarrow$ SINH VIÊN HOÀN THIỆN 30% CHIỀU SÂU**

---

## PHẦN I: TỔNG QUAN VỀ TRIẾT LÝ & ĐỊNH HƯỚNG CỦA GIẢNG VIÊN

1. 💡 **Ý nghĩa thực sự của "Tool đã hỗ trợ 70% công việc":**
   - Thầy Vũ Quang Dũng nhấn mạnh rằng **công cụ của Thầy (`SecLabFramework.exe`) đã tự động hóa tới 70% khối lượng kỹ thuật nền tảng**:
     * Tự động kiểm chứng Kripke & CTL, phát hiện Deadlock, sinh mã TikZ LaTeX.
     * Tự động sinh mã C chứa lỗi an toàn bộ nhớ từ đặc tả.
     * Tự động trích xuất AST và giải SMT Z3 Bit-Vector kiểm tra tràn số.
     * Tự động sinh khung hàm và chạy các thuật toán Fuzzing (Boundary, Blackbox, Mutation, Coverage, Concolic).
   - **30% công việc còn lại là của Sinh viên**:
     * Tự tay xây dựng file đặc tả Excel cho bài toán của riêng mình.
     * Thực hiện chiến dịch Fuzzing thực nghiệm định lượng cho **Chủ đề 4** (so sánh Black-box vs White-box vượt qua Magic Bytes).
     * Viết bản vá an toàn chuẩn **CERT C** (STR31-C, MEM30-C, MEM31-C).
     * Giải trình sâu cơ chế bộ nhớ (Stack vs Heap, stack frame overwrite, shadow memory AddressSanitizer) để trả lời phản biện của Thầy.
     * Biên dịch báo cáo học thuật chỉn chu để bảo vệ đồ án.

2. 📋 **Làm lại file Excel Đặc tả mới của riêng Nhóm 11:**
   - **THAM KHẢO** file mẫu `Template_Software_Security_iot_gateway_spec.xlsx` và hướng dẫn `Huong_dan_tao_Spec_file_dang_excel.pdf` để hiểu cấu trúc 10 sheet.
   - **TỰ THIẾT KẾ MỚI HOÀN TOÀN** file đặc tả của riêng Nhóm 11 phục vụ cho bài toán Parser của Chủ đề 4: có magic bytes `IGW1`, kiểm tra checksum, copy bộ đệm cố định, quản lý phiên và rào cản concolic. Đảm bảo mọi sheet dữ liệu $\ge 5$ dòng.

3. ⛔ **Tuyệt đối không dùng lại các file cũ của phiên trước:**
   - Mã C cũ (`gateway_parser_v0.c`, `gateway_parser_v1.c`), spec cũ và script fuzzer cũ của phiên trước là bản đi theo lối mòn tự biên ngoài tool. Codex hãy cách ly toàn bộ vào `archive_legacy_v0/` và bắt đầu mới tinh từ đầu!

---

## PHẦN II: CẨM NANG TOÀN DIỆN VỀ CÔNG CỤ `SecLabFramework.exe` (v27)
*(Codex hãy đọc kỹ cấu trúc này để tự suy nghĩ và quyết định nên khai thác những tính năng nào)*

Công cụ của Thầy là một bộ phần mềm toàn diện (**Educational Security Suite - sec_lab_framework v27**), được đóng gói bằng Python 3.14 (PyInstaller) tích hợp `customtkinter`, `z3-solver`, `pycparser`, `matplotlib`, `python-docx`.

### 1. KIẾN TRÚC 6 TAB TRÊN GIAO DIỆN ĐỒ HỌA (GUI)

* **Tab 1 — `Ch1: Kripke & Verification`:**
  - *Chức năng:* Nạp mô hình máy trạng thái (Kripke Structure) gồm tập trạng thái $S$, trạng thái khởi tạo $S_0$, quan hệ chuyển $R$, và hàm gán nhãn $L$.
  - *Khả năng:*
    + Khám phá không gian trạng thái (BFS/DFS).
    + Phát hiện **Deadlock** (trạng thái cụt không có lối ra).
    + Kiểm tra thuộc tính **Loại trừ lẫn nhau (Mutual Exclusion)** giữa 2 mệnh đề nguyên tử (ví dụ: `main_locked` $\land$ `log_locked`).
    + Kiểm chứng công thức CTL: `AG(!violation)`, `EF(main_locked)`, `AF(safe)`.
    + **Xuất đồ thị:** Sinh mã vector **TikZ (LaTeX)** chuẩn để chèn vào báo cáo hoặc xuất ảnh matplotlib.

* **Tab 2 — `Ch2: Memory & Static C Check`:**
  - *Chức năng:* Phân tích tĩnh và động mã nguồn C.
  - *Khả năng:*
    + Quét tĩnh các hàm nguy hiểm: `strcpy`, `strcat`, `sprintf`, `gets` (CWE-120/121).
    + Quét lỗi quản lý bộ nhớ: `memory-leak` (CWE-401), `double-free` (CWE-415), `use-after-free` (CWE-416).
    + Tính toán **Struct Alignment & Padding** (tính kích thước struct, byte độn trên kiến trúc 32-bit và 64-bit).

* **Tab 3 — `Ch3: AST/CFG/SMT/BMC`:**
  - *Chức năng:* Biểu diễn hình thức mã nguồn và giải ràng buộc toán học.
  - *Khả năng:*
    + Trích xuất C AST (Abstract Syntax Tree) qua `pycparser`.
    + Dựng đồ thị luồng điều khiển (Control Flow Graph - CFG).
    + Giải ràng buộc số học SMT Bit-Vector bằng **Z3 Solver** (tìm nghiệm tràn số nguyên int32).
    + Bounded Model Checking (BMC) giải cuộn vòng lặp và vi phạm bất biến.

* ⭐ **Tab 4 — `Ch4: Coverage & Fuzzing` (TRỌNG TÂM CHỦ ĐỀ 4):**
  - *Chức năng:* Chiến dịch Fuzzing đa kỹ thuật từ cơ bản đến nâng cao.
  - *Các phân hệ con:*
    1. **Coverage Tracker:** Đo độ phủ nhánh thực thi (edge coverage) khi chạy qua hàm.
    2. **Black-box Fuzzer:** Sinh đầu vào ngẫu nhiên, phát hiện ngoại lệ (ví dụ: `ZeroDivisionError` trong hàm `risky_divide`).
    3. **Mutation Fuzzer:** Đột biến dữ liệu (bit-flip, byte-flip, arithmetic mutation) trên seed corpus.
    4. **White-box / Concolic Fuzzer:** Thực thi concolic (kết hợp trace cụ thể + bộ giải Z3 SMT) để giải ngược các nhánh điều kiện phức tạp (ví dụ: Magic Values `x==1234, y==5678`).
    5. **Sinh test + C wrap:** Dùng `ctypes` tự động bọc (wrap) hàm C để sinh test case tự động và xuất bộ kiểm thử `pytest`.
    6. **Chiến dịch Fuzzing tự động đa giai đoạn:** Chạy tuần tự theo luồng chuẩn:  
       `Boundary` $\rightarrow$ `Black-box` $\rightarrow$ `Mutation` $\rightarrow$ `Coverage-guided` $\rightarrow$ `White-box/Concolic`.
    7. **Xuất báo cáo chi tiết:** Bấm nút `Xuất báo cáo chi tiết (PDF/DOCX)` để trích xuất toàn bộ bảng so sánh kỹ thuật, biểu đồ coverage và số liệu crash.

* **Tab 5 — `Ch5: Secure C/C++ Programming`:**
  - *Chức năng:* 7 chuyên đề thực hành lập trình C an toàn theo chuẩn CERT C (kiểm tra biên chuỗi, cấp phát heap, kiểu số nguyên, struct alignment, capstone).

* ⭐ **Tab 6 — `Ch6: Spec -> Kripke -> Code -> CWE/CVE` (CỖ MÁY TỰ ĐỘNG HÓA TÍCH HỢP):**
  - *Chức năng:* Nhận đầu vào là file Excel Đặc tả 10 sheet (hoặc JSON), tự động thực hiện toàn bộ quy trình:
    1. Đọc 10 sheet: `ThongTin`, `YeuCauChucNang`, `YeuCauPhiChucNang`, `RangBuoc`, `MoHinhTrangThai`, `ThuocTinhAnToan`, `LoaiTruLanNhau`, `HamSinhMa`, `KiemTraSoHoc`, `TestCase`.
    2. Tự động kiểm chứng Kripke và xuất mã TikZ LaTeX.
    3. Tự động sinh mã nguồn C chứa lỗi bộ nhớ (`parse_device_id`, `write_log_entry`, `close_session`, `release_session_buffer`).
    4. Tự động sinh mã Python cho Fuzzing (`token_ratio`, `device_unlock_code`).
    5. Tự động kiểm chứng Z3 SMT cho bài toán tràn số `telemetry_byte_counter`.
    6. Tự động ánh xạ ma trận CWE/CVE.
    7. **Tự động xuất file Word Báo cáo Tích hợp (.docx)** chứa toàn bộ các kết quả trên!

---

### 2. HỆ THỐNG LỆNH DÒNG LỆNH (CLI) CỦA TOOL

Ngoài giao diện GUI, Tool còn hỗ trợ đầy đủ các lệnh CLI mạnh mẽ có thể chạy trực tiếp từ PowerShell/CMD:

```powershell
# 1. Chạy GUI tương tác mặc định:
.\SecLabFramework.exe

# 2. Demo nhanh dòng lệnh:
.\SecLabFramework.exe --cli

# 3. Kiểm chứng tương tác Kripke/CTL Chương 1:
.\SecLabFramework.exe --cli-ch1

# 4. Kiểm tra lỗi bộ nhớ C & Struct Alignment Chương 2:
.\SecLabFramework.exe --cli-ch2

# 5. Luyện tập lập trình an toàn CERT C Chương 5:
.\SecLabFramework.exe --cli-ch5

# 6. Ctypes Wrapper cho C: Wrap hàm C, sinh test case mọi kiểu fuzzing, CFG/Call Graph, xuất pytest:
.\SecLabFramework.exe --cli-cwrap file.c --san auto --export thu_muc_xuat

# 7. CHIẾN DỊCH FUZZING TỰ ĐỘNG (RẤT QUAN TRỌNG CHO CHỦ ĐỀ 4):
# Phân tích hàm, tham số, magic value, chạy mọi kiểu fuzzing (boundary/blackbox/mutation/coverage/whitebox),
# in quy trình từng bước ra console và kết hợp AddressSanitizer:
.\SecLabFramework.exe --cli-fuzz file.c --func ten_ham --iterations 1000 --san asan --export results_dir

# 8. NHẬP MÃ NGUỒN CÓ SẴN (CHƯƠNG 6 IMPORT):
# Nhập 1 file hoặc cả thư mục project, chạy lại toàn bộ pipeline kiểm chứng tĩnh + động Ch1-Ch5:
.\SecLabFramework.exe --cli-ch6-import PATH --iterations 500 --export report.txt
```

*(Lưu ý về mã trang Windows Console: Nếu chạy CLI trên PowerShell gặp lỗi ký tự tiếng Việt, hãy chạy trước: `$env:PYTHONIOENCODING="utf-8"; $env:PYTHONUTF8="1"; chcp 65001`)*.

---

## PHẦN III: HƯỚNG DẪN CODEX TỰ SUY NGHĨ & LỰA CHỌN TÍNH NĂNG CHO CHỦ ĐỀ 4

Dựa trên cấu trúc toàn diện của Tool ở trên, Codex hãy **suy nghĩ logic và kết hợp các tính năng sau** để tạo ra đồ án Chủ đề 4 hoàn hảo nhất:

1. **Bước 1 — Dùng Tab Ch6 để nạp Spec mới và khởi tạo đồ án:**
   - Tạo file Excel đặc tả mới của nhóm: `specification/Nhom11_IoT_Security_Parser_Spec.xlsx` (được thiết kế riêng cho bài toán Chủ đề 4: Fuzzing, tuân thủ $\ge 5$ dòng/bảng).
   - Nạp vào Tab **`Ch6`** của Tool $\rightarrow$ Tool sẽ làm 70% công việc nền tảng: sinh mã C parser có lỗi bộ đệm, sinh mô hình Kripke TikZ LaTeX, sinh điều kiện SMT và xuất khung báo cáo tích hợp gốc `.docx`.

2. **Bước 2 — Dùng Tab Ch4 & lệnh `--cli-fuzz` để thực hiện trọng tâm Chủ đề 4 (Fuzzing Project):**
   - Lấy mã C parser mới sinh từ Tool đặt vào `source/gateway_parser_v0.c`.
   - Khai thác tính năng của **Tab Ch4** hoặc lệnh `.\SecLabFramework.exe --cli-fuzz source/gateway_parser_v0.c --san asan`:
     * Sử dụng **Black-box Fuzzer** để chứng minh sự bất lực của Fuzzing ngẫu nhiên trước rào cản Magic Bytes (`1 / 2^32` xác suất).
     * Sử dụng **White-box / Concolic Fuzzer** để chứng minh sức mạnh của bộ giải Z3 SMT khi giải ngược chính xác Magic Bytes/Checksum chỉ trong 1 lần thử (~14ms).
     * Khai thác **Coverage Tracker** để vẽ biểu đồ tăng trưởng độ phủ nhánh (coverage growth).
     * Bật **AddressSanitizer (ASan)** để bắt lỗi tràn bộ đệm CWE-121 khi payload vượt qua rào cản Magic Bytes.

3. **Bước 3 — Dùng Tab Ch2 / Ch5 để phân tích chuyên sâu & viết bản vá an toàn:**
   - Dùng kiến thức Ch5 để viết bản vá an toàn mới `source/gateway_parser_v1.c` tuân thủ các quy tắc **CERT C**:
     * **CERT STR31-C**: Thay thế `strcpy` bằng `snprintf` có kiểm soát độ dài biên.
     * **CERT MEM31-C**: Giải phóng toàn bộ bộ nhớ log khi đóng phiên.
     * **CERT MEM30-C**: Gán `ptr = NULL` ngay sau khi `free()` để triệt tiêu Dangling Pointer và lỗi UAF/Double-free.
   - Giải trình cơ chế kiến trúc bộ nhớ mức thấp:
     * Cấu trúc **Stack Frame**: Vị trí Return Address (RIP) và Saved Frame Pointer (RBP) bị ghi đè ra sao.
     * Cơ chế **Heap Arena**: Chunk metadata bị phá hủy thế nào khi double free.
     * Mô hình **Non-blocking Worker**: Vòng đời gói tin xử lý tạm thời trên Stack và giải phóng ngay, không giữ trạng thái rò rỉ.
     * Phản biện Static vs Dynamic: Cppcheck bỏ lọt lỗi vì tainted payload phụ thuộc runtime; ASan phát hiện chính xác qua Shadow Bytes (`0xfb` Redzone).

4. **Bước 4 — Hợp nhất Báo cáo học thuật & Thẩm định 10/10 PASS:**
   - Ghép 70% kết quả tự động từ Tool với 30% phân tích chuyên sâu (cơ chế bộ nhớ, bản vá CERT C, benchmark 30 trials thực nghiệm của Chủ đề 4).
   - Xuất tệp PDF chính thức `report/BaoCao_BTL_Nhom11.pdf` bằng Word COM script.
   - Thẩm định toàn diện bằng `scripts/verify_project.py` đạt **10/10 PASS** và đóng gói `Nhom11_BTL_ChuDe4_Fuzzing.zip`.

---

## PHẦN IV: NGUYÊN TẮC BẢO MẬT & TRUNG THỰC DỮ LIỆU
* **Bảo mật:** Luôn để trống MSSV và Khóa/Lớp trên mọi trang bìa, bảng phân công và cam đoan.
* **Tên thành viên:** Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%).
* **Số liệu thực tế:** Dữ liệu benchmark Fuzzing 30 trials phải lưu trữ bằng các file JSON thô trong `results/data_raw/`, tuyệt đối trung thực, không bịa đặt.

---
Codex, bạn đã có toàn bộ cẩm nang về Tool và định hướng đồ án. Hãy tự suy nghĩ, lập kế hoạch hành động chi tiết và bắt đầu triển khai từ Bước 1!
```
