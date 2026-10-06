# BỘ CHỈ THỊ TOÀN DIỆN CHO CODEX: CHỦ ĐỀ 4 - FUZZING (LÀM MỚI 100% THEO ĐÚNG ĐỊNH HƯỚNG GIẢNG VIÊN)

> **Mục tiêu tối thượng:** Bàn giao cho Codex bản chỉ thị chuẩn xác 100% theo đúng tinh thần của ThS. Vũ Quang Dũng:  
> 1. **"Tool đã hỗ trợ 70% công việc":** Tool `SecLabFramework.exe` tự động hóa ~70% khối lượng kỹ thuật nền tảng (kiểm chứng Kripke, sinh mã C lỗi, phân tích AST SMT, dựng khung fuzzing). Sinh viên làm 30% còn lại (thiết kế đặc tả của riêng mình, thực nghiệm đối đầu Fuzzing Chủ đề 4, viết bản vá an toàn CERT C, giải trình sâu về bộ nhớ và hoàn thiện báo cáo).  
> 2. **Xây dựng lại file Excel Đặc tả mới 100%:** THAM KHẢO cấu trúc template của Thầy để hiểu format 10 sheet, nhưng **TỰ XÂY DỰNG LẠI FILE EXCEL DỰA TRÊN ĐẶC TẢ CỦA RIÊNG CHÚNG TA** cho bài toán Chủ đề 4: Fuzzing.  
> 3. **Tuyệt đối không dùng lại các file cũ** (code cũ, spec cũ, report cũ) của phiên trước vì đó là bản đi theo lối mòn tự chế ngoài tool.

---

```markdown
# MASTER DIRECTIVE: TÁI THIẾT KẾ ĐỒ ÁN MỚI 100% (CHỦ ĐỀ 4 - FUZZING)
**Học phần:** Kỹ thuật Lập trình An toàn (CSE703093 / CSE703153) — ThS. Vũ Quang Dũng (ĐH Phenikaa)  
**Đề tài chính thức:** **Chủ đề 4: Dự án Fuzzing (Parser có Magic Bytes / Checksum)**  
**Nhóm sinh viên:** Nhóm 11 — Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%)  
**Phương pháp cốt lõi:** **SPEC RIÊNG CỦA NHÓM $\rightarrow$ TOOL HỖ TRỢ 70% CÔNG VIỆC $\rightarrow$ SINH VIÊN HOÀN THIỆN 30% CHIỀU SÂU**

---

## I. ĐÍNH CHÍNH & LÀM RÕ TRIẾT LÝ CỦA GIẢNG VIÊN

Codex cần nắm bắt chính xác ý định sư phạm của thầy Vũ Quang Dũng:

1. 💡 **Bản chất "Tool hỗ trợ 70% công việc":**
   - Giảng viên KHÔNG nói "tool viết 70% báo cáo". Ý của Thầy là: **Công cụ của Thầy (`SecLabFramework.exe`) đã gánh vác tới 70% khối lượng công việc kỹ thuật nặng nhọc của một đồ án an toàn**:
     * Tự động kiểm chứng hình thức mô hình Kripke & CTL (tìm deadlock, vi phạm mutual exclusion, sinh mã TikZ).
     * Tự động sinh mã nguồn C chứa các lỗi an toàn bộ nhớ từ đặc tả (CWE-121 Buffer Overflow, CWE-401 Leak, CWE-415 Double Free, CWE-416 UAF).
     * Tự động trích xuất AST và kiểm chứng điều kiện số học bằng SMT Z3 Bit-Vector solver.
     * Tự động dựng khung các hàm mục tiêu cho Fuzzing (`divide`, `magic_value`).
   - **30% phần việc còn lại là trách nhiệm cốt lõi của sinh viên:**
     * Tự thiết kế file đặc tả hệ thống của riêng nhóm.
     * Triển khai kịch bản thực nghiệm Fuzzing chuyên sâu cho **Chủ đề 4** (đo lường định lượng Black-box vs White-box).
     * Viết bản vá an toàn chuẩn **CERT C** khắc phục các lỗi mà tool chỉ ra.
     * Giải trình cơ chế kiến trúc bộ nhớ mức thấp (Stack frame, Heap arena, Non-blocking lifecycle) để trả lời phản biện của Thầy.
     * Viết báo cáo toàn diện, chuyên nghiệp để bảo vệ đồ án.

2. 📋 **Làm lại file Excel Đặc tả của riêng Nhóm 11 (Tham khảo từ mẫu của Thầy):**
   - **THAM KHẢO** file mẫu `Template_Software_Security_iot_gateway_spec.xlsx` và cẩm nang `Huong_dan_tao_Spec_file_dang_excel.pdf` để hiểu chuẩn 10 sheet, tên cột và kiểu dữ liệu.
   - **TỰ THIẾT KẾ MỚI HOÀN TOÀN** nội dung đặc tả của riêng Nhóm 11 phục vụ trực tiếp cho bài toán **Chủ đề 4: Fuzzing**:
     * Hệ thống Parser xử lý gói tin có **Magic Bytes** (`IGW1`), độ dài payload, và checksum.
     * Khóa cấu hình chia sẻ giữa các worker (mô hình Kripke).
     * Các hàm sinh mã C gây lỗi bộ đệm và hàm Python rào cản Magic Value để fuzzing.
     * Đảm bảo mọi sheet dữ liệu đều đạt $\ge 5$ dòng theo đúng Checklist Chương 5 của Thầy.

3. ⛔ **Tuyệt đối không dùng lại các file cũ của phiên trước:**
   - Các file `gateway_parser_v0.c`, `gateway_parser_v1.c`, file spec cũ và các script fuzzer tự chế của phiên trước là bản đi theo lối mòn tự làm ngoài tool. Codex phải cách ly/lưu trữ các file này vào `archive_legacy_v0/` và bắt đầu mới tinh 100%!

---

## II. BẢN ĐỒ TÀI NGUYÊN GỐC (SSOT)

* **Thư mục dự án:** `I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\`
* **Thư mục tài nguyên chuẩn của Thầy:** `I:\1_taiLieuDaiHoc\ATPM\TAI_LIEU_VA_YEU_CAU\`
  * `01_Huong_Dan_BTL_Va_Spec/`:
    - `Huong_dan_tao_Spec_file_dang_excel.pdf`: Cẩm nang 28 trang và Checklist Chương 5 của Thầy Dũng.
    - `Template_Software_Security_iot_gateway_spec.xlsx`: File đặc tả mẫu 10 sheet của Thầy (để tham khảo cấu trúc).
    - `Template_Report_iot_gateway_auth.docx`: Mẫu báo cáo tích hợp do Tool xuất ra (để tham khảo mẫu).
  * `02_Yeu_Cau_Va_Luu_Y_Giang_Vien/`:
    - `YEU_CAU_VA_LUU_Y_GIANG_VIEN_KHO_TINH.md`: Cẩm nang trả lời các câu hỏi vấn đáp chuyên sâu của Thầy.
  * `04_Cong_Cu_Giang_Vien/`:
    - `SecLabFramework.exe` (104.8 MB): Phiên bản nâng cấp v27 của Thầy (đang mở trực tiếp trên màn hình máy người dùng dưới tên *Educational Security Suite — sec_lab_framework*).
* **Git Repository:** Nhánh `main`, remote: `https://github.com/bachiep/ATPM-Nhom11-ChuDe4-Fuzzing.git`.

---

## III. QUY TRÌNH 4 BƯỚC TRIỂN KHAI CHO CODEX

Codex hãy triển khai theo đúng trình tự khoa học sau:

### BƯỚC 1: XÂY DỰNG FILE EXCEL ĐẶC TẢ MỚI CHO NHÓM 11
1. **Cách ly bản cũ:** Di chuyển toàn bộ mã nguồn và đặc tả cũ vào thư mục `archive_legacy_v0/`.
2. **Thiết kế file Excel Đặc tả mới của nhóm:**
   - Tạo file: `specification/Nhom11_IoT_Security_Parser_Spec.xlsx`.
   - Tham khảo cấu trúc 10 sheet từ `Template_Software_Security_iot_gateway_spec.xlsx`, nhưng viết lại toàn bộ nội dung cho hệ thống Parser của Nhóm 11:
     * `ThongTin`: Thông tin hệ thống IoT Security Parser của Nhóm 11.
     * `YeuCauChucNang`: 10+ yêu cầu từ Mutual Exclusion, Liveness, Memory Safety đến Fuzzing rào cản Magic Value.
     * `YeuCauPhiChucNang`: $\ge 5$ yêu cầu hiệu năng, độ trễ và tính toàn vẹn gói tin.
     * `RangBuoc`: $\ge 5$ ràng buộc về mutex nhẹ, giới hạn buffer 16 bytes, magic bytes 4 bytes, checksum 32-bit.
     * `MoHinhTrangThai`: Các trạng thái Kripke của Parser (`free`, `main_holds`, `log_holds`, `conflict`).
     * `ThuocTinhAnToan`: Công thức CTL `AG(!violation)`, `EF(main_locked)`...
     * `LoaiTruLanNhau`: Cặp mệnh đề loại trừ giữa worker chính và worker ghi log.
     * `HamSinhMa`: Định nghĩa chính xác các hàm:
       - `parse_device_id` (C, buffer_copy, size 16, bug `buffer-overflow`)
       - `write_log_entry` (C, alloc_release, size 32, bug `memory-leak`)
       - `close_session` (C, alloc_release, size 4, bug `double-free`)
       - `release_session_buffer` (C, alloc_release, size 8, bug `use-after-free`)
       - `token_ratio` (Python, divide, chia cho 0)
       - `device_unlock_code` (Python, magic_value, secret values `7421, 3390`)
     * `KiemTraSoHoc`: Biểu thức kiểm tra tràn số `telemetry_byte_counter`.
     * `TestCase`: 6+ ca kiểm thử truy vết từ REQ đến các khâu kiểm chứng.

### BƯỚC 2: NẠP VÀO TOOL (`SecLabFramework.exe`) ĐỂ TOOL LÀM 70% CÔNG VIỆC
1. **Thao tác trên Tool:**
   - Mở Tab **`Ch6: Spec -> Kripke -> Code -> CWE/CVE`** trên ứng dụng `SecLabFramework.exe`.
   - Nạp file `specification/Nhom11_IoT_Security_Parser_Spec.xlsx` vừa tạo.
   - Nhấn chạy phân tích toàn diện.
2. **Thu hoạch kết quả do Tool tự động sinh ra:**
   - Lấy mã C parser do Tool sinh ra (đặt vào `source/gateway_parser_v0.c`).
   - Lấy mô hình Kripke và mã vector TikZ LaTeX.
   - Lấy kết quả kiểm tra AST và Z3 SMT số học.
   - Lấy file Word báo cáo tích hợp gốc do Tool xuất ra, lưu vào `results/`.

### BƯỚC 3: THỰC HIỆN 30% CÔNG VIỆC CỐT LÕI CỦA SINH VIÊN (CHỦ ĐỀ 4 FUZZING)
1. **Thực nghiệm Fuzzing chuyên sâu cho Chủ đề 4:**
   - Tại Tab **`Ch4: Coverage & Fuzzing`** của Tool và kết hợp kịch bản thực nghiệm:
     * Chạy **Black-box Fuzzing**: Chứng minh xác suất ngẫu nhiên vượt qua 4 bytes Magic Bytes `IGW1` hoặc Checksum (`1 / 2^32`) là bất khả thi $\rightarrow$ Tỷ lệ thành công 0%.
     * Chạy **White-box / Concolic Fuzzing (Z3 SMT)**: Giải ngược phương trình Bit-Vector và tìm ra magic value `(7421, 3390)` chỉ trong **1 lần thử (~14ms)**!
     * Đo lường định lượng 30 trials thực nghiệm: Thời gian tìm crash (time-to-crash), số iterations, độ phủ nhánh (coverage growth). Lưu toàn bộ dữ liệu thô vào `results/data_raw/`.
2. **Xây dựng Bản vá An toàn `source/gateway_parser_v1.c` chuẩn CERT C:**
   - Vá CWE-121 theo **CERT STR31-C**: Dùng `snprintf` có kiểm tra bound, đảm bảo null-terminator.
   - Vá CWE-401 theo **CERT MEM31-C**: Giải phóng bộ đệm log ngay khi xử lý xong.
   - Vá CWE-415 & CWE-416 theo **CERT MEM30-C**: Gán `ptr = NULL` ngay sau khi `free()`, kiểm tra trước khi sử dụng.
3. **Phân tích Kiến trúc Bộ nhớ Mức thấp (Thỏa mãn yêu cầu khắt khe của Thầy Dũng):**
   - **Stack Frame:** Phân tích chi tiết vị trí Return Address (RIP) và Saved Frame Pointer (RBP) bị ghi đè ra sao khi `strcpy` tràn buffer 16 bytes.
   - **Heap Arena:** Phân tích cơ chế freelist/bins của glibc/Windows Heap và tại sao Dangling Pointer dẫn đến Use-After-Free làm hỏng metadata của heap chunk.
   - **Non-blocking Worker:** Phân tích vòng đời xử lý gói tin tạm thời trên Stack frame, giải phóng ngay lập tức để không rò rỉ tài nguyên.
   - **Static vs Dynamic:** Giải thích tại sao Cppcheck bỏ lọt lỗi buffer overflow động, và chứng minh AddressSanitizer (ASan) bắt lỗi chính xác qua **Shadow Bytes (0xfb - Stack Redzone)**.

### BƯỚC 4: HOÀN THIỆN BÁO CÁO, THẨM ĐỊNH & ĐÓNG GÓI
1. **Hoàn thiện Báo cáo chính thức:**
   - Kết hợp 70% kết quả từ Tool sinh ra với 30% phân tích chuyên sâu của sinh viên (kiến trúc bộ nhớ, CERT C, benchmark 30 trials Fuzzing).
   - Xuất tệp PDF chính thức: `report/BaoCao_BTL_Nhom11.pdf` bằng Word COM script.
2. **Kiểm định Kỹ thuật 10/10 PASS:**
   - Cập nhật kịch bản kiểm tra `scripts/verify_project.py` và chạy:
     ```bash
     python scripts/verify_project.py
     pytest tests/
     ```
     Đảm bảo 10/10 khâu kiểm định đạt PASS 100%.
3. **Đóng gói & Commit:**
   - Đóng gói file nộp bài: `Nhom11_BTL_ChuDe4_Fuzzing.zip`.
   - Git commit sạch sẽ theo chuẩn Conventional Commits và push lên `origin main`.

---

## IV. CÁC NGUYÊN TẮC BẢO MẬT BẮT BUỘC
* **Tuyệt đối để trống:** Mã số sinh viên (MSSV) và Khóa/Lớp trên mọi trang bìa, bảng phân công và cam đoan.
* **Tên thành viên:** Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%).
* **Số liệu trung thực:** Số liệu đo đạc Fuzzing phải xuất phát từ log thực tế và file JSON thô, tuyệt đối không bịa đặt.

---
Codex, hãy tiếp nhận nhiệm vụ, bắt đầu từ Bước 1 và báo cáo kế hoạch cho người dùng!
```
