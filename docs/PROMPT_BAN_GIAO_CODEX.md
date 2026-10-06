# BỘ PROMPT CHUYỂN GIAO CHO CODEX (PROMPT BÀN GIAO TOÀN DIỆN)

> **Hướng dẫn sử dụng:** Bạn chỉ cần sao chép toàn bộ khối lệnh Markdown dưới đây và dán vào cửa sổ chat với **Codex** (hoặc để Codex thực thi tự động). Prompt này đã chứa đầy đủ 100% ngữ cảnh, nguyên tắc, tài liệu, quy chuẩn của giảng viên và lộ trình từng bước.

```markdown
# CHỈ THỊ NHIỆM VỤ: TIẾP NHẬN & HOÀN THIỆN ĐỒ ÁN AN TOÀN PHẦN MỀM (NHÓM 11)

Chào Codex, bạn đang tiếp nhận vai trò Senior Security Engineer & Formal Methods Specialist hỗ trợ Nhóm 11 hoàn thiện Bài tập lớn học phần **Kỹ thuật Lập trình An toàn** (CSE703093 / CSE703153) - Giảng viên: **ThS. Vũ Quang Dũng (ĐH Phenikaa)**.

Toàn bộ workspace đã được chuẩn hóa, dọn dẹp sạch sẽ và định hình theo đúng triết lý của giảng viên: **"Tool của thầy đã hỗ trợ 70% rồi, mọi thứ phải được làm từ tool ra; nhiệm vụ của các em là dùng tool cho tốt, báo cáo cặn kẽ và giải trình 30% chiều sâu kỹ thuật"**.

---

## 1. THÔNG TIN KHÔNG GIAN LÀM VIỆC & TÀI LIỆU CỐT LÕI
* **Thư mục dự án chính:** `I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\`
* **Thư mục tài liệu & công cụ chuẩn:** `I:\1_taiLieuDaiHoc\ATPM\TAI_LIEU_VA_YEU_CAU\`
  * `01_Huong_Dan_BTL_Va_Spec/`: Hướng dẫn BTL, mẫu báo cáo Word, tài liệu tạo Spec Excel 28 trang của Thầy Dũng.
  * `02_Yeu_Cau_Va_Luu_Y_Giang_Vien/`: Handoff chi tiết và cẩm nang yêu cầu giảng viên khó tính.
  * `04_Cong_Cu_Giang_Vien/`: Bộ công cụ của Thầy:
    - **`SecLabFramework.exe` (104.8 MB):** Phiên bản nâng cấp v27 của Thầy (đang mở trực tiếp trên màn hình máy người dùng dưới tên *Educational Security Suite — sec_lab_framework*).
    - **`Template_Software_Security_iot_gateway_spec (2).xlsx`:** Mẫu đặc tả Excel 10 sheet chuẩn mực của Thầy.
    - **`Template_Report_iot_gateway_auth (2).docx`:** Mẫu báo cáo tích hợp 7 phần do chính Tool xuất ra.
* **Tài liệu handoff chi tiết:** Đọc ngay file `docs/HANDOFF_CHUYEN_GIAO_PHIEN_MOI.md` và `docs/YEU_CAU_VA_LUU_Y_GIANG_VIEN_KHO_TINH.md`.
* **Git Remote:** `https://github.com/bachiep/ATPM-Nhom11-ChuDe4-Fuzzing.git` (nhánh `main`, cây làm việc sạch).

---

## 2. TRIẾT LÝ DỰ ÁN: CƠ CHẾ 70% - 30%
1. **70% do Tool đảm nhiệm (`SecLabFramework.exe`):**
   * **Tab Ch6 (`Spec -> Kripke -> Code -> CWE/CVE`):** Nạp Spec Excel 10 sheet $\rightarrow$ Tự động phân tích Kripke, kiểm tra Deadlock/Mutual exclusion, sinh mã vẽ vector TikZ LaTeX $\rightarrow$ Tự động sinh mã C chứa lỗi (CWE-121, CWE-401, CWE-415, CWE-416) $\rightarrow$ Trích xuất AST & gọi Z3 SMT giải bài toán tràn số int32 $\rightarrow$ Tự động xuất Báo cáo Word (`.docx`).
   * **Tab Ch4 (`Coverage & Fuzzing`):** Chạy chuỗi Fuzzing tự động đa kỹ thuật: *Boundary $\rightarrow$ Black-box (ZeroDivisionError) $\rightarrow$ Mutation $\rightarrow$ Coverage-guided (gcov) $\rightarrow$ White-box / Concolic (SMT giải ngược Magic Value)*.
2. **30% do Sinh viên phân tích chuyên sâu (Yếu tố quyết định điểm A+):**
   * **Bản chất quản lý bộ nhớ:** Giải thích rành mạch dữ liệu lưu tại **Stack hay Heap**? Con trỏ sau `free()` có bị dangling pointer không? Tại sao `strcpy` ghi đè Return Address? Vòng đời xử lý non-blocking của Worker thế nào?
   * **Bản vá an toàn CERT C:** Xây dựng bản vá `gateway_parser_v1.c` tuân thủ nghiêm ngặt **CERT STR31-C, MEM30-C, MEM31-C**.
   * **Đối soát thực nghiệm 30 trials:** Dữ liệu benchmark khách quan (thời gian tìm crash, số iterations) lấy từ file JSON thô trong `results/data_raw/`, tuyệt đối không bịa đặt.
   * **Phản biện Static vs Dynamic:** Chứng minh tại sao Cppcheck bỏ lọt lỗi buffer overflow động runtime, và tại sao **AddressSanitizer (ASan)** là công cụ phát hiện chuẩn xác nhất.

---

## 3. CÁC NGUYÊN TẮC BẤT BIẾN (STRICT CONSTRAINTS)
1. **Bảo mật thông tin sinh viên:** Mọi báo cáo, bìa, bảng phân công TUYỆT ĐỐI ĐỂ TRỐNG Mã sinh viên (MSSV) và Khóa/Lớp. Tên thành viên: Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%).
2. **Chuẩn hóa Git & Báo cáo:** Không commit file Word nháp hay markdown nháp lên Git; chỉ lưu và theo dõi duy nhất tệp PDF chính thức `report/BaoCao_BTL_Nhom11.pdf`.
3. **Thẩm định kỹ thuật:** Kịch bản `scripts/verify_project.py` phải luôn đạt **10/10 PASS** (khớp mã băm SHA-256, 30/30 unit tests pass).

---

## 4. NHIỆM VỤ CỤ THỂ BẠN CẦN THỰC HIỆN NGAY:

### Nhiệm vụ 1: Khai thác Tab Ch6 & Tab Ch4 từ `SecLabFramework.exe`
- Nạp file đặc tả `Template_Software_Security_iot_gateway_spec (2).xlsx` (hoặc bản nâng cao $\ge 5$ dòng của nhóm tại `specification/Nhom11_SecureGate_IoT_Gateway_Spec.xlsx`) vào Tool của Thầy.
- Trích xuất toàn bộ artifacts mà Tool sinh ra:
  * Mã C sinh lỗi (`parse_device_id`, `write_log_entry`, `close_session`, `release_session_buffer`).
  * Mã TikZ LaTeX vẽ sơ đồ Kripke.
  * Log Fuzzing và kết quả Concolic Execution giải Magic Values.
  * Xuất file Word báo cáo tích hợp từ Tool ra `results/`.

### Nhiệm vụ 2: Tích hợp Báo cáo Toàn diện (Ghép 70% của Tool + 30% Phân tích chuyên sâu)
- Lấy nội dung báo cáo sinh ra từ Tool làm khung sườn 70%.
- Bổ sung 30% phân tích cốt lõi:
  * Lý giải chi tiết cơ chế bộ nhớ Stack vs Heap, buffer layout, thanh ghi con trỏ frame.
  * Đưa bản vá an toàn `gateway_parser_v1.c` đạt chuẩn CERT C vào đối chiếu song song với mã sinh từ tool.
  * Bảng số liệu đối soát 30 trials thực nghiệm và log AddressSanitizer shadow memory.
  * Bộ câu hỏi phản biện vấn đáp bảo vệ đồ án (dựa trên cẩm nang giảng viên khó tính).
- Biên dịch ra tệp PDF chính thức `report/BaoCao_BTL_Nhom11.pdf` bằng Word COM (`scripts/export_all_docs.py`).

### Nhiệm vụ 3: Thẩm định & Đóng gói Bàn giao
- Cập nhật mã băm SHA-256 của file PDF và Spec trong `scripts/verify_project.py`.
- Chạy `python scripts/verify_project.py` và `pytest tests/` bảo đảm **10/10 PASS**.
- Đóng gói file nộp bài `I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing.zip`.
- Git commit sạch sẽ theo chuẩn conventional commits và push lên `origin main`.

Hãy bắt đầu phân tích và báo cáo kế hoạch thực thi từng bước cho người dùng!
```
