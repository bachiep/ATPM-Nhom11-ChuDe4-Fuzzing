# BỘ CHỈ THỊ TOÀN DIỆN CHO CODEX: CHỦ ĐỀ 4 - DỰ ÁN FUZZING (QUY TRÌNH TOOL-FIRST 70/30)

> **Mục tiêu:** Cung cấp cho Codex bản chỉ dẫn chuẩn xác 100% theo định hướng của Giảng viên ThS. Vũ Quang Dũng:  
> 1. **Đề tài chính thức:** **Chủ đề 4 — Dự án Fuzzing** (So sánh định lượng Black-box vs White-box/Concolic trên parser có magic bytes).  
> 2. **Triết lý cốt lõi:** **Tool hỗ trợ 70% Báo cáo** — Bắt buộc phải nạp file Spec của nhóm vào Tool (`SecLabFramework.exe`), lấy đó làm kim chỉ nam định hình hướng làm việc chuẩn, trích xuất mã nguồn và báo cáo gốc từ Tool.  
> 3. **30% Chuyên sâu của Sinh viên:** Xây dựng kịch bản Fuzzing thực nghiệm Chủ đề 4, phân tích cơ chế bộ nhớ mức thấp (Stack/Heap), viết bản vá an toàn chuẩn CERT C, và hoàn thiện Báo cáo PDF điểm tối đa.

---

```markdown
# MASTER DIRECTIVE DÀNH CHO CODEX: CHỦ ĐỀ 4 - DỰ ÁN FUZZING
**Học phần:** Kỹ thuật Lập trình An toàn (CSE703093 / CSE703153) — ThS. Vũ Quang Dũng (ĐH Phenikaa)  
**Đề tài BTL:** **Chủ đề 4: Dự án Fuzzing (Parser có Magic Bytes / Checksum)**  
**Nhóm sinh viên:** Nhóm 11 — Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%)  
**Phương pháp luận:** **TOOL-FIRST PARADIGM** (Nạp Spec vào Tool $\rightarrow$ Tool sinh 70% Báo cáo & Hướng chuẩn $\rightarrow$ Xây dựng Kịch bản Fuzzing & Phân tích chuyên sâu 30%).

---

## I. ĐỊNH HƯỚNG BẢN CHẤT TỪ GIẢNG VIÊN & VAI TRÒ CỦA TOOL

Thầy Vũ Quang Dũng đã làm rõ nguyên lý then chốt của môn học:
1. **"Tool đã hỗ trợ 70% Báo cáo":**
   - Công cụ **`SecLabFramework.exe`** (đang mở trên máy) chính là "cỗ máy sinh báo cáo". Khi nạp file đặc tả Excel 10 sheet của nhóm vào Tab `Ch6: Spec -> Kripke -> Code -> CWE/CVE`, Tool sẽ **tự động xuất ra một file Word báo cáo hoàn chỉnh** (`Template_Report_...docx`) gồm 7 chương:
     * Đặc tả yêu cầu hệ thống.
     * Mô hình Kripke, kiểm chứng CTL, mã vẽ vector TikZ LaTeX.
     * Mã nguồn C sinh tự động chứa lỗi bộ nhớ (CWE-121 Buffer Overflow, CWE-401, CWE-415, CWE-416).
     * Trích xuất AST & giải SMT Z3 kiểm tra tràn số int32.
     * Dynamic Fuzzing trên các hàm Python sinh ra (`token_ratio`, `device_unlock_code`).
     * Ma trận ánh xạ CWE/CVE tổng hợp.
     * Bảng Test Case truy vết đặc tả.
   - **Đây chính là 70% khối lượng báo cáo mà Tool làm hộ sinh viên!** Sinh viên không phải tự bịa cấu trúc báo cáo hay tự viết mã khung từ đầu.

2. **"Từ Tool định hình Hướng làm việc chuẩn xác":**
   - Công cụ của Thầy là **Quy chuẩn Chuẩn mực (Specification of Requirements)**. Bằng cách quan sát cấu trúc Tool và dữ liệu Tool xuất ra, ta biết chính xác giảng viên muốn sinh viên làm gì:
     * Hệ thống phải có mô hình trạng thái Kripke (khóa chia sẻ giữa Worker chính và Worker ghi log).
     * Hàm phân tích cú pháp (Parser) nhận chuỗi/gói tin đầu vào, copy vào bộ đệm cố định gây nguy cơ tràn bộ đệm (CWE-121).
     * Phải có điều kiện rào cản ngữ nghĩa dạng **Magic Bytes / Magic Values / Checksum** để làm nổi bật sự vượt trội của White-box / Concolic Fuzzing so với Black-box Fuzzing!

3. **Chủ đề Bài tập lớn: CHỦ ĐỀ 4 — DỰ ÁN FUZZING:**
   - Theo đề cương BTL (`BTL_01_HuongDan_DeTai.pdf`, trang 15-16), Chủ đề 4 yêu cầu:
     * Chọn một hàm/chương trình parser có điều kiện "magic byte" / checksum.
     * Dùng kỹ thuật Fuzzing chạy cả **Black-box Fuzzing** và **White-box Fuzzing (Z3 SMT)**.
     * **So sánh định lượng:** Đo số lần thử (iterations), thời gian tìm crash (time-to-crash), chứng minh tại sao Black-box bị "chặn đứng" trước rào cản Magic Bytes/Checksum, trong khi White-box (Z3 Solver) giải ngược trong 1 tích tắc.
     * Phân tích lỗi an toàn bộ nhớ phát hiện được khi vượt qua rào cản (CWE-121 Stack Buffer Overflow).

---

## II. BẢN ĐỒ TÀI NGUYÊN & KHÔNG GIAN LÀM VIỆC (SSOT)

* **Thư mục dự án chính:** `I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\`
* **Thư mục tài nguyên chuẩn của Giảng viên:** `I:\1_taiLieuDaiHoc\ATPM\TAI_LIEU_VA_YEU_CAU\`
  * `01_Huong_Dan_BTL_Va_Spec/`:
    - `Huong_dan_tao_Spec_file_dang_excel.pdf`: Cẩm nang 28 trang và Checklist Chương 5 của Thầy Dũng.
    - `Template_Software_Security_iot_gateway_spec.xlsx`: File đặc tả Excel 10 sheet mẫu của Thầy.
    - `Template_Report_iot_gateway_auth.docx`: File Báo cáo Word mẫu do chính Tool xuất ra.
  * `02_Yeu_Cau_Va_Luu_Y_Giang_Vien/`:
    - `YEU_CAU_VA_LUU_Y_GIANG_VIEN_KHO_TINH.md`: Cẩm nang trả lời các câu hỏi vấn đáp chuyên sâu của Thầy.
    - `HANDOFF_CHUYEN_GIAO_PHIEN_MOI.md`: Biên bản bàn giao kỹ thuật.
  * `04_Cong_Cu_Giang_Vien/`:
    - `SecLabFramework.exe`: **Công cụ chính thức v27** (đang mở trên màn hình với tên *Educational Security Suite — sec_lab_framework*).
* **Git Repository:** Nhánh `main`, commit sạch sẽ, remote: `https://github.com/bachiep/ATPM-Nhom11-ChuDe4-Fuzzing.git`.

---

## III. QUY TRÌNH 4 BƯỚC THỰC THI CHO CODEX

Codex hãy triển khai theo đúng trình tự sau để hoàn thành đồ án:

### BƯỚC 1: NẠP FILE ĐẶC TẢ CỦA NHÓM VÀO TOOL (`SecLabFramework.exe`)
1. **Chuẩn bị đầu vào:**
   - Sử dụng file đặc tả Excel 10 sheet của nhóm: `specification/Nhom11_SecureGate_IoT_Gateway_Spec.xlsx` (đã chuẩn hóa $\ge 5$ dòng dữ liệu mỗi bảng theo Checklist Chương 5).
2. **Thao tác trên Tool:**
   - Mở Tab **`Ch6: Spec -> Kripke -> Code -> CWE/CVE`** trên ứng dụng `SecLabFramework.exe`.
   - Chọn đường dẫn nạp file `Nhom11_SecureGate_IoT_Gateway_Spec.xlsx`.
   - Kích hoạt tiến trình phân tích tự động: Spec $\rightarrow$ Kripke $\rightarrow$ Sinh Code C $\rightarrow$ CWE/CVE.
   - Nhấn **Xuất Báo cáo Tích hợp (Export DOCX)** để lấy file Word chứa **70% nội dung báo cáo** do chính Tool sinh ra!
3. **Trích xuất Artifacts gốc từ Tool:**
   - Lưu trữ mã C sinh ra: hàm `parse_device_id` (CWE-121), `write_log_entry` (CWE-401), `close_session` (CWE-415), `release_session_buffer` (CWE-416).
   - Lưu trữ mã TikZ LaTeX mô hình Kripke và công thức CTL.
   - Lưu file Word sinh ra vào `results/` làm căn cứ nghiệm thu.

### BƯỚC 2: XÂY DỰNG KỊCH BẢN FUZZING CHỦ ĐỀ 4 TỪ KẾT QUẢ TOOL
1. **Thiết lập mục tiêu Fuzzing (Target Parser):**
   - Target Parser (`gateway_parser_v0.c`): Nhận gói tin nhị phân có Magic Bytes `IGW1` (4 bytes) + Checksum (4 bytes) + Payload độ dài tùy biến.
   - Hàm `parse_device_id` lấy payload copy bằng `strcpy`/`memcpy` vào bộ đệm cố định 16 bytes (lỗi CWE-121).
2. **Vận hành Chuỗi Fuzzing trên Tab `Ch4: Coverage & Fuzzing` của Tool:**
   - Chạy tuần tự các chế độ trên giao diện Tool:
     * `Coverage Tracker`: Đo độ phủ nhánh thực thi.
     * `Black-box Fuzzer`: Fuzz ngẫu nhiên tìm ngoại lệ (ZeroDivisionError / Crash).
     * `Mutation Fuzzer`: Đột biến payload.
     * `White-box / Concolic Fuzzer`: Dùng SMT Z3 giải ngược Magic Value `(7421, 3390)` trong hàm mở khóa (`device_unlock_code`).
   - Nhấn **Xuất báo cáo chi tiết (PDF/DOCX)** tại Tab Ch4 để lấy biểu đồ so sánh kỹ thuật.
3. **Thực nghiệm Benchmark 30 trials (Dữ liệu định lượng Chủ đề 4):**
   - Chạy 30 lượt đối đầu giữa:
     * **Black-box Fuzzing:** Xác suất ngẫu nhiên vượt qua 4 bytes Magic (`1 / 2^32`) gần như bằng 0 $\rightarrow$ Thất bại 100%.
     * **Greybox Fuzzing (gcov coverage-guided):** Mất trung bình 45,000+ iterations mới đột biến trúng.
     * **White-box Fuzzing (Z3 SMT):** Giải phương trình Bit-Vector tìm ra magic bytes trong **1 lần thử duy nhất (~14ms)**!
   - Ghi lại số liệu thực nghiệm đầy đủ trong `results/data_raw/` (không bịa đặt số liệu).

### BƯỚC 3: BỔ SUNG 30% CHIỀU SÂU KỸ THUẬT & BẢN VÁ AN TOÀN CERT C
1. **Xây dựng Bản vá An toàn (Safe Fixes) `source/gateway_parser_v1.c`:**
   - Vá CWE-121 theo chuẩn **CERT STR31-C**: Kiểm tra cận độ dài trước khi sao chép, dùng `snprintf` an toàn.
   - Vá CWE-401 theo chuẩn **CERT MEM31-C**: Giải phóng vùng nhớ log ngay khi đóng phiên.
   - Vá CWE-415 & CWE-416 theo chuẩn **CERT MEM30-C**: Gán `ptr = NULL` ngay sau khi `free()`, kiểm tra con trỏ hợp lệ trước khi truy xuất.
2. **Phân tích Kiến trúc Bộ nhớ Mức thấp (Thỏa mãn yêu cầu khắt khe của Thầy Dũng):**
   - Giải thích cơ chế Stack vs Heap:
     * Hàm `parse_device_id` lưu buffer trên **Stack Frame**. Khi tràn bộ đệm, dữ liệu ghi đè **Saved Frame Pointer (RBP)** và **Return Address (RIP)**, dẫn đến chiếm quyền điều khiển luồng thực thi khi hàm `ret`.
     * Quản lý Heap Arena: Con trỏ sau `free()` không được gán NULL sẽ tạo ra Dangling Pointer, truy cập lại gây Use-After-Free làm hỏng metadata của Heap Chunk (tấn công heap exploitation).
     * Vòng đời non-blocking của Worker: Gateway xử lý theo sự kiện, gói tin vào $\rightarrow$ parse tạm thời trên Stack $\rightarrow$ xác thực xong giải phóng ngay, không duy trì buffer treo trên heap gây rò rỉ.
3. **Phản biện Static vs Dynamic Analysis:**
   - Giải thích tại sao Cppcheck (Static Analysis) bỏ lọt lỗi CWE-121: Do kích thước payload phụ thuộc dữ liệu mạng runtime.
   - Chứng minh AddressSanitizer (ASan) phát hiện chính xác: Nhờ cơ chế **Shadow Bytes (0xfb - Stack Redzone)** bắt ngay điểm ghi ngoài biên.

### BƯỚC 4: HỢP NHẤT BÁO CÁO TOÀN DIỆN, THẨM ĐỊNH & BÀN GIAO
1. **Hợp nhất Báo cáo chính thức:**
   - Lấy 70% nội dung khung sườn từ tệp Word do Tool sinh ra ở Bước 1.
   - Ghép 30% phân tích chuyên sâu (cơ chế bộ nhớ, bản vá CERT C, benchmark Fuzzing 30 trials của Chủ đề 4) từ Bước 2 và 3.
   - Biên dịch ra file PDF chính thức: `report/BaoCao_BTL_Nhom11.pdf` bằng Word COM script (`scripts/export_all_docs.py`).
2. **Kiểm tra Thẩm định Kỹ thuật:**
   - Cập nhật SHA-256 trong `scripts/verify_project.py` và chạy:
     ```bash
     python scripts/verify_project.py
     pytest tests/
     ```
     **Đảm bảo 10/10 khâu kiểm định đạt PASS (100%)**.
3. **Đóng gói & Commit:**
   - Đóng gói file nộp bài: `Nhom11_BTL_ChuDe4_Fuzzing.zip`.
   - Git commit sạch sẽ và push lên `origin main`.

---

## IV. CÁC NGUYÊN TẮC BẢO MẬT BẮT BUỘC
* **Tuyệt đối để trống:** Mã sinh viên (MSSV) và Khóa/Lớp trên trang bìa, bảng phân công và tài liệu cam đoan.
* **Tên thành viên:** Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%).
* **Số liệu trung thực:** Toàn bộ số liệu thời gian, độ phủ, crash count phải dựa 100% trên log thực tế và file JSON thô.

---
Codex, hãy tiếp nhận không gian làm việc và báo cáo lộ trình thực thi chi tiết cho người dùng!
```
