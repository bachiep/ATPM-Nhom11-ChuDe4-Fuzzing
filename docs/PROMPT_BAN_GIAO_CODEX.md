# BỘ CHỈ THỊ TOÀN DIỆN CHO CODEX: TÁI THIẾT ĐỒ ÁN MỚI 100% (CLEAN-SLATE & TOOL-FIRST)
**Học phần:** Kỹ thuật Lập trình An toàn (CSE703093 / CSE703153) — ThS. Vũ Quang Dũng (ĐH Phenikaa)  
**Đề tài BTL:** **Chủ đề 4: Dự án Fuzzing (Parser có Magic Bytes / Checksum)**  
**Nhóm sinh viên:** Nhóm 11 — Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%)  
**Mục tiêu tối thượng:** **LÀM MỚI HOÀN TOÀN 100% — TUYỆT ĐỐI KHÔNG DÙNG LẠI CÁC FILE CŨ ĐÃ TẠO**. Bản cũ chỉ là bài học kinh nghiệm để tránh lối mòn; bản mới phải chuẩn mực, sắc bén và đáp ứng trọn vẹn yêu cầu khắt khe của Giảng viên.

---

```markdown
# MASTER DIRECTIVE: TÁI KHỞI ĐỘNG ĐỒ ÁN MỚI 100% (CHỦ ĐỀ 4 - FUZZING)

Chào Codex, bạn được giao nhiệm vụ **tái thiết kế và xây dựng lại từ đầu (Clean Slate 100%)** toàn bộ Đồ án Bài tập lớn An toàn Phần mềm cho Nhóm 11.

---

## I. NGUYÊN TẮC CỐT TỬ: TUYỆT ĐỐI KHÔNG TÁI SỬ DỤNG BẢN CŨ

1. ⛔ **KHÔNG DÙNG LẠI BẤT KỲ FILE CŨ NÀO:**
   - KHÔNG dùng lại mã nguồn C cũ (`gateway_parser_v0.c`, `gateway_parser_v1.c`).
   - KHÔNG dùng lại file đặc tả cũ (`Nhom11_SecureGate_IoT_Gateway_Spec.xlsx`).
   - KHÔNG dùng lại báo cáo PDF hay các file nháp cũ.
   - *Lý do:* Bản cũ đã đi theo lối mòn tự biên tự diễn kịch bản rời rạc ngoài tool, không phản ánh đúng tinh thần của môn học. Chúng ta làm mới hoàn toàn để đạt độ hoàn thiện cao nhất!
2. 🎯 **BẢN MỚI XUẤT PHÁT TỪ ĐÂU?**
   - Xuất phát trực tiếp từ **File Mẫu Gốc của Thầy**: [`TAI_LIEU_VA_YEU_CAU/01_Huong_Dan_BTL_Va_Spec/Template_Software_Security_iot_gateway_spec.xlsx`](file:///I:/1_taiLieuDaiHoc/ATPM/TAI_LIEU_VA_YEU_CAU/01_Huong_Dan_BTL_Va_Spec/Template_Software_Security_iot_gateway_spec.xlsx).
   - Xuất phát trực tiếp từ **Công cụ v27 của Thầy**: [`SecLabFramework.exe`](file:///I:/1_taiLieuDaiHoc/ATPM/TAI_LIEU_VA_YEU_CAU/04_Cong_Cu_Giang_Vien/SecLabFramework.exe) (đang mở trên màn hình dưới tên *Educational Security Suite — sec_lab_framework*).

---

## II. TRIẾT LÝ QUY CHUẨN: "TOOL HỖ TRỢ 70% BÁO CÁO & ĐỊNH HƯỚNG CHUẨN"

Thầy Vũ Quang Dũng đã chỉ rõ:
1. **Tool hỗ trợ 70% Báo cáo:**
   - Khi nạp file đặc tả của bài vào Tab `Ch6: Spec -> Kripke -> Code -> CWE/CVE` của `SecLabFramework.exe`, Tool sẽ **tự động sinh ra 70% khung sườn báo cáo dạng Word (.docx)** gồm 7 chương: Đặc tả yêu cầu $\rightarrow$ Mô hình Kripke (kèm mã TikZ LaTeX) $\rightarrow$ Mã C sinh tự động (CWE-121, CWE-401, CWE-415, CWE-416) $\rightarrow$ SMT Z3 int32 check $\rightarrow$ Dynamic Fuzzing $\rightarrow$ Bảng phân loại CWE/CVE $\rightarrow$ Test cases truy vết.
   - Báo cáo chính thức phải được xây dựng dựa trên chính file Word mà Tool xuất ra!
2. **Từ Tool định hình Hướng làm việc chuẩn:**
   - Tool quy định chính xác kiến trúc một parser chuẩn an toàn: có kiểm tra Magic Bytes (`IGW1`), có kiểm tra checksum, có copy dữ liệu vào bộ đệm cố định, và có cơ chế non-blocking worker.
3. **Đề tài chính thức: CHỦ ĐỀ 4 — DỰ ÁN FUZZING:**
   - Trọng tâm nghiên cứu là **So sánh định lượng Fuzzing** (Black-box vs White-box / Concolic SMT) để tìm ra rào cản Magic Bytes/Checksum và kích hoạt lỗi tràn bộ đệm (CWE-121 Stack Buffer Overflow).

---

## III. BẢN ĐỒ TÀI NGUYÊN GỐC (SSOT)

* **Thư mục làm việc chính:** `I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\`
* **Thư mục tài nguyên chuẩn của Thầy:** `I:\1_taiLieuDaiHoc\ATPM\TAI_LIEU_VA_YEU_CAU\`
  * `01_Huong_Dan_BTL_Va_Spec/`:
    - `Huong_dan_tao_Spec_file_dang_excel.pdf`: Cẩm nang 28 trang và Checklist Chương 5 của Thầy Dũng.
    - `Template_Software_Security_iot_gateway_spec.xlsx`: File đặc tả Excel 10 sheet gốc của Thầy.
    - `Template_Report_iot_gateway_auth.docx`: Mẫu báo cáo tích hợp gốc do chính Tool xuất ra.
  * `02_Yeu_Cau_Va_Luu_Y_Giang_Vien/`:
    - `YEU_CAU_VA_LUU_Y_GIANG_VIEN_KHO_TINH.md`: Cẩm nang giải trình kỹ thuật chuyên sâu (Stack/Heap, CERT C, ASan).
  * `04_Cong_Cu_Giang_Vien/`:
    - `SecLabFramework.exe` (104.8 MB): Phiên bản v27 nâng cấp (đang mở trên máy).
* **Git Remote:** `https://github.com/bachiep/ATPM-Nhom11-ChuDe4-Fuzzing.git` (nhánh `main`).

---

## IV. LỘ TRÌNH 4 BƯỚC XÂY DỰNG LẠI DỰ ÁN MỚI 100%

### BƯỚC 1: XÂY DỰNG ĐẶC TẢ MỚI & NẠP VÀO TOOL (`SecLabFramework.exe`)
1. **Lưu trữ bản cũ:** Di chuyển toàn bộ các file cũ của lần làm trước vào thư mục `archive_legacy_v0/` để cách ly hoàn toàn, đảm bảo không bị lẫn lộn.
2. **Khởi tạo Spec mới tinh cho Nhóm 11:**
   - Dựa trên template gốc của Thầy `Template_Software_Security_iot_gateway_spec.xlsx`, tạo file đặc tả mới: `specification/Nhom11_IoT_Gateway_Auth_Spec_v2.xlsx`.
   - Chuẩn hóa đúng 10 sheets, mỗi sheet dữ liệu đảm bảo $\ge 5$ dòng để vượt qua Checklist Chương 5 của Thầy.
3. **Nạp vào Tool và Xuất 70% Báo cáo gốc:**
   - Mở Tab **`Ch6: Spec -> Kripke -> Code -> CWE/CVE`** trên ứng dụng `SecLabFramework.exe`.
   - Nạp file Spec mới vừa tạo.
   - Chạy quy trình phân tích và bấm **Xuất Báo cáo Tích hợp (Export DOCX)**.
   - Thu thập artifacts mới toanh do Tool sinh ra:
     * Mã C parser mới (hàm `parse_device_id` bị CWE-121, `write_log_entry` bị CWE-401, `close_session` bị CWE-415, `release_session_buffer` bị CWE-416).
     * Mã TikZ LaTeX mô hình trạng thái Kripke.
     * File Word báo cáo gốc lưu tại `results/BaoCao_Goc_Tu_Tool.docx`.

### BƯỚC 2: XÂY DỰNG KỊCH BẢN FUZZING CHỦ ĐỀ 4 TỪ MÃ MỚI
1. **Thiết lập Target Parser mới:**
   - Đặt mã C mới sinh từ Tool vào `source/gateway_parser_v0.c`.
2. **Vận hành Fuzzing trên Tab `Ch4: Coverage & Fuzzing` của Tool:**
   - Chạy chuỗi kiểm thử Fuzzing trên giao diện Tool:
     * `Coverage Tracker`: Đo độ phủ nhánh thực thi.
     * `Black-box Fuzzer`: Fuzz ngẫu nhiên tìm crash chia 0 (`token_ratio`).
     * `Mutation Fuzzer`: Đột biến header.
     * `White-box / Concolic Fuzzer`: Dùng SMT Z3 giải ngược Magic Value `(7421, 3390)` trong hàm `device_unlock_code`.
   - Xuất báo cáo Fuzzing từ Tab Ch4 để lấy biểu đồ và số liệu chính thức.
3. **Thực nghiệm Định lượng 30 trials (So sánh Black-box vs White-box):**
   - Đo đạc chính xác:
     * Black-box Fuzzing: Tỷ lệ thành công 0% trước 4 byte Magic Bytes/Checksum.
     * White-box Fuzzing (Z3 SMT): Giải ngược thành công trong 1 lần thử duy nhất (~14ms).
   - Lưu trữ toàn bộ log JSON thực nghiệm mới vào `results/data_raw/`.

### BƯỚC 3: PHÁT TRIỂN 30% CHIỀU SÂU KỸ THUẬT & BẢN VÁ CERT C
1. **Bản vá an toàn mới `source/gateway_parser_v1.c`:**
   - Vá CWE-121 bằng **CERT STR31-C** (ràng buộc độ dài bộ đệm, dùng `snprintf`).
   - Vá CWE-401 bằng **CERT MEM31-C** (giải phóng toàn bộ heap buffer khi đóng phiên).
   - Vá CWE-415 & CWE-416 bằng **CERT MEM30-C** (gán `ptr = NULL` ngay sau khi `free`).
2. **Phân tích Kiến trúc Bộ nhớ Mức thấp (Thỏa mãn yêu cầu khắt khe của Thầy Dũng):**
   - **Stack Frame:** Phân tích chi tiết tại sao dữ liệu ghi đè **Saved Frame Pointer (RBP)** và **Return Address (RIP)** dẫn đến hijacking luồng thực thi.
   - **Heap Arena:** Giải thích cơ chế chunk allocation, freelist và tại sao Dangling Pointer dẫn đến Use-After-Free làm hỏng heap metadata.
   - **Non-blocking Worker:** Giải thích lifecycle gói tin được cấp phát tạm trên Stack và giải phóng ngay trong frame, không để rò rỉ bộ nhớ.
3. **Đối chiếu Static Analysis vs Dynamic Analysis:**
   - Chứng minh Cppcheck bỏ lọt CWE-121 do phụ thuộc input mạng runtime.
   - Chứng minh **AddressSanitizer (ASan)** bắt crash chuẩn xác qua **Shadow Bytes (0xfb - Stack Redzone)**.

### BƯỚC 4: HỢP NHẤT BÁO CÁO PDF, THẨM ĐỊNH & NỘP BÀI
1. **Hợp nhất Báo cáo chính thức:**
   - Khung sườn 70% lấy từ file Word do Tool sinh ra ở Bước 1.
   - Ghép 30% nội dung phân tích chuyên sâu (kiến trúc bộ nhớ, bản vá CERT C, benchmark Fuzzing Chủ đề 4) từ Bước 2 và 3.
   - Biên dịch ra `report/BaoCao_BTL_Nhom11.pdf` bằng Word COM script.
2. **Thẩm định Kỹ thuật 10/10 PASS:**
   - Cập nhật mã băm SHA-256 mới và chạy kịch bản kiểm tra:
     ```bash
     python scripts/verify_project.py
     pytest tests/
     ```
     Bảo đảm toàn bộ các khâu đều đạt PASS 100%.
3. **Đóng gói & Commit:**
   - Đóng gói file nộp bài chuẩn: `Nhom11_BTL_ChuDe4_Fuzzing.zip`.
   - Git commit sạch sẽ với thông điệp rõ ràng theo chuẩn Conventional Commits và push lên `origin main`.

---

## V. CÁC NGUYÊN TẮC BẢO MẬT BẮT BUỘC
* **Tuyệt đối để trống:** Mã số sinh viên (MSSV) và Khóa/Lớp trên mọi trang bìa, bảng phân công và tài liệu cam đoan.
* **Tên thành viên:** Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%).
* **Số liệu trung thực:** Dựa 100% trên dữ liệu thực tế từ Tool và log ASan thực nghiệm.

---
Codex, hãy bắt đầu thực thi theo lộ trình Clean Slate mới 100% này và báo cáo kế hoạch cho người dùng!
```
