# BỘ CHỈ THỊ TOÀN DIỆN CHO CODEX: TÁI THIẾT KẾ ĐỒ ÁN TỪ GỐC (TOOL-FIRST PARADIGM)

> **Mục tiêu:** Cung cấp cho Codex bản chỉ dẫn tối thượng để xây dựng lại đồ án một cách chuẩn mực, **tuyệt đối không đi vào lối mòn tự biên tự diễn**, làm chủ 100% công cụ của giảng viên (`SecLabFramework.exe`), và đáp ứng trọn vẹn các yêu cầu khắt khe nhất của ThS. Vũ Quang Dũng (ĐH Phenikaa).

---

```markdown
# MASTER DIRECTIVE: TÁI THIẾT KẾ & HOÀN THIỆN ĐỒ ÁN AN TOÀN PHẦN MỀM (NHÓM 11)
**Học phần:** Kỹ thuật Lập trình An toàn (CSE703093 / CSE703153) — ThS. Vũ Quang Dũng (ĐH Phenikaa)  
**Nhóm sinh viên:** Nhóm 11 — Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%)  
**Nguyên tắc cốt tử:** **TOOL-FIRST & STRICT VERIFICATION** ("Tool hỗ trợ 70%, mọi thứ từ Tool ra; 30% là phân tích cơ chế bộ nhớ và bản vá CERT C").

---

## PHẦN I: CẢNH BÁO CÁC LỐI MÒN & LỖI SAI CẦN TUYỆT ĐỐI TRÁNH

Các phiên làm việc trước đây từng mắc phải một số sai lầm về phương pháp luận khiến giảng viên không hài lòng. Codex **TUYỆT ĐỐI KHÔNG ĐƯỢC LẶP LẠI**:

1. ❌ **LỐI MÒN 1: Tự viết mã/kịch bản Fuzzing rời rạc bên ngoài thay vì dùng Tool của Thầy.**
   - *Sai lầm cũ:* Tự viết script python fuzzer riêng, chạy benchmark riêng trước khi đưa vào tool.
   - *Quy chuẩn mới:* Toàn bộ quy trình phải xuất phát từ **`SecLabFramework.exe`** (đang mở trên máy). Mọi hàm C, hàm Python, ca kiểm thử, sơ đồ Kripke và báo cáo sơ bộ DOCX đều phải do Tool sinh ra từ file Đặc tả Excel.
2. ❌ **LỐI MÒN 2: Hiểu sai bản chất các file mẫu.**
   - *Cần phân định rõ:*
     * `Template_Software_Security_iot_gateway_spec (2).xlsx` là **FILE INPUT** (Đặc tả 10 sheet nạp vào tool).
     * `Template_Report_iot_gateway_auth (2).docx` là **FILE OUTPUT** (Báo cáo tích hợp mẫu do Tool tự động xuất ra sau khi chạy). Tuyệt đối không nhầm đây là file Word trống cần điền thủ công.
3. ❌ **LỐI MÒN 3: Báo cáo lý thuyết chung chung, né tránh cơ chế bộ nhớ mức thấp.**
   - Thầy Dũng là giảng viên cực kỳ khắt khe về kỹ thuật hệ thống. Báo cáo không được viết kiểu "hàm này an toàn hơn hàm kia". Phải giải trình chi tiết:
     * Dữ liệu nằm ở **Stack hay Heap**?
     * Return Address và Saved Frame Pointer (EBP/RBP) bị ghi đè như thế nào khi buffer overflow?
     * Sau khi `free()`, con trỏ có bị dangling pointer không? Heap arena quản lý chunk bộ nhớ ra sao?
     * Hàm xử lý xong có lưu lại không hay giải phóng ngay? Vòng đời non-blocking của Worker là gì?
4. ❌ **LỐI MÒN 4: Vi phạm checklist hình thức của Thầy.**
   - Toàn bộ các sheet dữ liệu trong Excel Spec bắt buộc phải có $\ge 5$ dòng dữ liệu (theo Checklist Chương 5 của `Huong_dan_tao_Spec_file_dang_excel.pdf`).
   - Tuyệt đối không đổi tên 10 Tab chuẩn (`ThongTin`, `YeuCauChucNang`, `MoHinhTrangThai`...) vì code của Tool đọc cố định các tên này.

---

## PHẦN II: KHÔNG GIAN LÀM VIỆC & BẢN ĐỒ TÀI LIỆU SSOT

* **Thư mục dự án chính:** `I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\`
* **Thư mục tài nguyên & công cụ gốc của Thầy:** `I:\1_taiLieuDaiHoc\ATPM\TAI_LIEU_VA_YEU_CAU\`
  * `01_Huong_Dan_BTL_Va_Spec/`:
    - `Huong_dan_tao_Spec_file_dang_excel.pdf`: Cẩm nang 28 trang của Thầy Dũng.
    - `Template_Software_Security_iot_gateway_spec.xlsx`: File đặc tả mẫu 10 sheet.
    - `Template_Report_iot_gateway_auth.docx`: Mẫu báo cáo tích hợp do tool xuất.
  * `02_Yeu_Cau_Va_Luu_Y_Giang_Vien/`:
    - `YEU_CAU_VA_LUU_Y_GIANG_VIEN_KHO_TINH.md`: Bộ câu hỏi vấn đáp và cẩm nang chiều sâu kỹ thuật.
    - `HANDOFF_CHUYEN_GIAO_PHIEN_MOI.md`: Biên bản bàn giao kỹ thuật.
  * `04_Cong_Cu_Giang_Vien/`:
    - `SecLabFramework.exe` (104.8 MB): Phiên bản v27 nâng cấp của Thầy (đang mở trực tiếp trên màn hình máy người dùng dưới tên *Educational Security Suite — sec_lab_framework*).
* **Git Repository:** Nhánh `main`, commit sạch, remote: `https://github.com/bachiep/ATPM-Nhom11-ChuDe4-Fuzzing.git`.

---

## PHẦN III: QUY TRÌNH THỰC THI 4 BƯỚC (TOOL-FIRST WORKFLOW)

Codex hãy triển khai công việc theo đúng trình tự 4 bước sau:

### BƯỚC 1: KHAI THÁC TOOL `SecLabFramework.exe` ("LẤY 70% TỪ TOOL RA")
1. **Tại Tab `Ch6: Spec -> Kripke -> Code -> CWE/CVE`:**
   - Sử dụng file đặc tả Excel 10 sheet chuẩn mực của nhóm tại `specification/Nhom11_SecureGate_IoT_Gateway_Spec.xlsx` (đã được tối ưu $\ge 5$ dòng/bảng).
   - Nạp file Spec vào Tool và kích hoạt xuất Báo cáo Tích hợp (Export DOCX).
   - Trích xuất toàn bộ artifact do Tool sinh ra:
     * Mã nguồn C chứa 4 lỗi bộ nhớ: `parse_device_id` (CWE-121), `write_log_entry` (CWE-401), `close_session` (CWE-415), `release_session_buffer` (CWE-416).
     * Mã TikZ LaTeX vẽ sơ đồ chuyển trạng thái Kripke (`free`, `main_holds`, `log_holds`, `conflict`).
     * Biểu thức số học SMT Z3 kiểm tra tràn số int32 (`telemetry_byte_counter`).
2. **Tại Tab `Ch4: Coverage & Fuzzing`:**
   - Kích hoạt quy trình Fuzzing tuần tự: `Boundary` $\rightarrow$ `Black-box` $\rightarrow$ `Mutation` $\rightarrow$ `Coverage-guided` $\rightarrow$ `White-box / Concolic`.
   - Thu thập trace tìm crash: `ZeroDivisionError` trong hàm `token_ratio`, và Concolic solver giải ngược Magic Value `(7421, 3390)` trong hàm `device_unlock_code`.
   - Bấm `Xuất báo cáo chi tiết (PDF/DOCX)` từ Tab Ch4 để lấy bảng so sánh kỹ thuật.

### BƯỚC 2: XÂY DỰNG PHẦN 30% CHIỀU SÂU KỸ THUẬT CỦA SINH VIÊN
1. **Thiết kế Bản vá An toàn (Safe Fixes) chuẩn CERT C:**
   - Đối chiếu với mã v0 do tool sinh ra, hoàn thiện file `source/gateway_parser_v1.c`:
     * Vá CWE-121 bằng **CERT STR31-C**: Thay `strcpy` bằng `strncpy`/`snprintf` với độ dài cận trên rõ ràng, kiểm tra null-terminator.
     * Vá CWE-401 bằng **CERT MEM31-C**: Giải phóng toàn bộ bộ đệm log ngay khi kết thúc vòng đời xử lý.
     * Vá CWE-415 & CWE-416 bằng **CERT MEM30-C**: Gán `ptr = NULL` ngay sau khi `free()`, kiểm tra `ptr != NULL` trước khi truy cập.
2. **Biện giải cơ chế kiến trúc bộ nhớ mức thấp:**
   - Vẽ và phân tích sơ đồ Stack Frame của hàm `parse_device_id`:
     ```
     [High Memory]  Parameters (raw_id)
                    Return Address (RIP/EIP)  <-- Bị ghi đè khi tràn
                    Saved Frame Pointer (RBP) <-- Bị ghi đè khi tràn
                    Local buffer[16]          <-- Điểm tràn memcpy/strcpy
     [Low Memory]   ...
     ```
   - Giải thích cơ chế Heap Arena: Sau khi `free(buf)`, glibc/Windows Heap đưa chunk vào bin/freelist. Nếu không gán `buf = NULL`, con trỏ trở thành Dangling Pointer, truy cập lại sẽ gây Use-After-Free (CWE-416) hoặc Double Free làm hỏng metadata của Heap chunk.
   - Giải thích tính năng Worker non-blocking: Gateway nhận gói tin $\rightarrow$ cấp phát buffer tạm trên Stack $\rightarrow$ xác thực magic bytes $\rightarrow$ giải phóng ngay lập tức trong frame, không giữ trạng thái rác gây rò rỉ.
3. **Phản biện Static vs Dynamic Analysis:**
   - Chứng minh thực nghiệm: Cppcheck phân tích AST tĩnh trên luồng điều khiển, bỏ lọt lỗi CWE-121 vì kích thước payload phụ thuộc dữ liệu mạng runtime.
   - Minh chứng AddressSanitizer (ASan): Bắt chính xác crash nhờ cơ chế **Shadow Bytes (0xfb - Stack Redzone)**.

### BƯỚC 3: TỔNG HỢP BÁO CÁO TOÀN DIỆN & BIÊN DỊCH PDF
1. Hợp nhất nội dung:
   - Phần 70% từ Tool (Báo cáo DOCX của Thầy, mã TikZ LaTeX, trace Fuzzing).
   - Phần 30% phân tích chuyên sâu của sinh viên (kiến trúc bộ nhớ, CERT C, benchmark thực nghiệm 30 trials, đối chiếu static vs dynamic).
2. Biên dịch ra báo cáo PDF chính thức `report/BaoCao_BTL_Nhom11.pdf` bằng Word COM script (`scripts/export_all_docs.py`).
3. Đảm bảo chất lượng trình bày: bảng biểu rõ ràng, font chuẩn Times New Roman, đồ thị trực quan sắc nét.

### BƯỚC 4: THẨM ĐỊNH TOÀN DIỆN & ĐÓNG GÓI BÀN GIAO
1. Cập nhật mã băm SHA-256 trong `scripts/verify_project.py` (nếu file PDF hoặc Spec có cập nhật).
2. Chạy kịch bản thẩm định:
   ```bash
   python scripts/verify_project.py
   pytest tests/
   ```
   **Bắt buộc 10/10 khâu kiểm định đạt PASS (100%)**.
3. Đóng gói file nộp bài chuẩn: `I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing.zip`.
4. Git commit sạch sẽ với thông điệp rõ ràng theo chuẩn Conventional Commits và push lên `origin main`.

---

## PHẦN IV: CÁC NGUYÊN TẮC BẢO MẬT BẮT BUỘC
* **Tuyệt đối để trống:** Mã số sinh viên (MSSV) và Khóa/Lớp trên mọi trang bìa, bảng phân công và tài liệu cam đoan.
* **Tên thành viên:** Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (tỷ lệ đóng góp 50% - 50%).
* **Số liệu thực nghiệm:** Dựa 100% trên dữ liệu thực tế (file JSON thô và log ASan), không bịa đặt số liệu.

---
Hãy bắt đầu tiếp nhận không gian làm việc và báo cáo kế hoạch thực thi từng bước!
```
