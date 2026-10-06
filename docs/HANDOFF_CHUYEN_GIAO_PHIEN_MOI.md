# BIÊN BẢN CHUYỂN GIAO PHIÊN LÀM VIỆC (SESSION HANDOFF)
**Dự án:** Bài tập lớn An toàn Phần mềm — Đề tài 4: SecureGate IoT Gateway Fuzzing & Formal Verification  
**Học phần:** Kỹ thuật Lập trình An toàn (CSE703093 / CSE703153) — ThS. Vũ Quang Dũng (ĐH Phenikaa)  
**Nhóm sinh viên:** Nhóm 11 — Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%)  
**Ngày lập biên bản:** 06/10/2026  
**Mục đích:** Bàn giao toàn bộ ngữ cảnh, trạng thái kỹ thuật và nhiệm vụ trọng tâm cho phiên làm việc mới khi tiếp nhận **2 TOOL MỚI** từ giảng viên.

---

## 1. TÌNH HÌNH DỰ ÁN & VẤN ĐỀ MỚI XUẤT HIỆN

### 1.1 Hiện trạng kỹ thuật tính đến trước phiên mới
* **Kho mã nguồn:** Git Repository sạch (`clean working tree`), nhánh `main`, commit mới nhất `e7df7bd`:
  `docs(spec): expand specification sheets to 5+ rows and update validation hashes`  
  Remote: `https://github.com/bachiep/ATPM-Nhom11-ChuDe4-Fuzzing.git` (đã push).
* **Kết quả kiểm định hiện tại:** Kịch bản `scripts/verify_project.py` đạt **10/10 PASS** (Khâu 1 đến 8 đều đạt chuẩn, PyTest 30/30 passed, mã băm SHA-256 khớp 100%).
* **Tệp đặc tả Excel:** `specification/Nhom11_SecureGate_IoT_Gateway_Spec.xlsx` đủ 10 sheet chuẩn, toàn bộ các sheet dữ liệu đều đạt $\ge 5$ dòng theo đúng Checklist Chương 5 của `Huong_dan_tao_Spec_file_dang_excel.pdf`.
* **Báo cáo chính thức:** `report/BaoCao_BTL_Nhom11.pdf` (15 trang) đã được biên dịch sạch, không còn file nháp trên Git.
* **Tệp nộp bài:** `Nhom11_BTL_ChuDe4_Fuzzing.zip` (2.01 MB) đặt tại thư mục gốc `I:\1_taiLieuDaiHoc\ATPM\`.

### 1.2 Biến chuyển mới: Ý kiến của Giảng viên & 2 Tool mới
Giảng viên vừa xem xét và đưa ra nhận xét chấn chỉnh quan trọng:
1. **Bài chưa ổn nếu làm rời rạc ngoài tool:** Thầy nhấn mạnh *"Tool của thầy đã hỗ trợ tới 70% rồi, và mọi thứ phải được làm từ tool ra. Nhiệm vụ của các em là dùng tool cho tốt và báo cáo cho giảng viên"*.
2. **Cung cấp thêm 2 tool mới:** Giảng viên đã bàn giao thêm 2 công cụ mới để phục vụ quá trình làm bài và kiểm định.
3. **Yêu cầu phân tích sâu:** Không sinh kịch bản ngẫu nhiên; phải giải thích cặn kẽ tại sao lại làm như thế, cơ chế lưu trữ dữ liệu vào Stack/Heap, gọi xong có lưu không hay chờ xử lý sau, và làm rõ sự khác biệt của đề tài Fuzzing/Binary Gateway so với các nhóm làm dự án code thông thường.

---

## 2. BẢN ĐỒ TÀI LIỆU VÀ TỆP TIN CỐT LÕI

| Tệp tin / Thư mục | Đường dẫn tuyệt đối | Vai trò trong hệ thống |
|---|---|---|
| **Cẩm nang yêu cầu Giảng viên** | `I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\YEU_CAU_VA_LUU_Y_GIANG_VIEN_KHO_TINH.md` | **TÀI LIỆU KIM CHỈ NAM**: Quy định chi tiết mọi lưu ý khắt khe, triết lý "làm từ tool ra", phân tích bộ nhớ và bộ câu hỏi vấn đáp. |
| **Tệp đặc tả Excel SSOT** | `I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\specification\Nhom11_SecureGate_IoT_Gateway_Spec.xlsx` | Tệp Excel 10 sheet nạp vào công cụ của giảng viên. |
| **Mã nguồn Target Parser C** | `I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\source\gateway_parser_v0.c` & `v1.c` | Bản lỗi CWE-121 v0 và bản vá CERT C v1. |
| **Bộ Fuzzing** | `I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\source\blackbox_fuzzer.py`, `greybox_fuzzer.py`, `whitebox_fuzzer.py` | 3 công cụ fuzzer: Black-box, Greybox gcov, White-box Z3 SMT. |
| **Script kiểm định toàn diện** | `I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\scripts\verify_project.py` | Kịch bản chạy 8 khâu kiểm tra tự động và đối soát SHA-256. |
| **Báo cáo chính thức PDF** | `I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\report\BaoCao_BTL_Nhom11.pdf` | Tệp PDF chính thức duy nhất nộp cho giảng viên. |
| **Tài liệu hướng dẫn của thầy** | `I:\1_taiLieuDaiHoc\ATPM\Huong_dan_tao_Spec_file_dang_excel.pdf` | Hướng dẫn 28 trang và Checklist Chương 5 của thầy Dũng. |
| **Tool trước đó của thầy** | `I:\1_taiLieuDaiHoc\ATPM\SpecVerificationLab.exe` | Ứng dụng GUI hỗ trợ xử lý Spec nạp tệp Excel 10 sheet. |

---

## 3. CHECKLIST HÀNH ĐỘNG DÀNH CHO AGENT Ở PHIÊN MỚI

Khi người dùng mở phiên làm việc mới và cung cấp **2 tool mới**, Agent mới cần thực hiện tuần tự các bước sau:

- [ ] **Bước 1: Tiếp nhận & Nhận diện 2 Tool mới**
  * Kiểm tra vị trí của 2 tool mới trong thư mục `I:\1_taiLieuDaiHoc\ATPM\`.
  * Xác định định dạng (Executable `.exe`, Python package, Script, hay Web UI).
  * Đọc file `README`, file hướng dẫn hoặc chạy `--help` để hiểu rõ mục đích và đầu vào/đầu ra của 2 tool này.
- [ ] **Bước 2: Xác định vị trí 2 Tool mới trong Pipeline 70% của Giảng viên**
  * Tool mới làm nhiệm vụ gì? (Phân tích AST C? Tự động hóa Fuzzing? Sinh harness? Kiểm tra ràng buộc SMT? Hay Xuất báo cáo nghiệm thu tự động?).
  * Xác định xem tệp `Nhom11_SecureGate_IoT_Gateway_Spec.xlsx` hoặc mã nguồn C `gateway_parser_v0.c` cần được nạp vào tool mới như thế nào.
- [ ] **Bước 3: Chạy dữ liệu dự án qua 2 Tool mới ("Mọi thứ làm từ Tool ra")**
  * Thực thi 2 tool mới với dữ liệu của SecureGate IoT Gateway.
  * Thu thập toàn bộ artifact sinh ra: log, kết quả quét, mã sinh ra, đồ thị hoặc báo cáo DOCX/PDF từ tool.
  * Lưu trữ artifact vào `results/` hoặc thư mục quy định.
- [ ] **Bước 4: Diễn giải & Tích hợp vào Báo cáo**
  * Đọc kỹ tài liệu `YEU_CAU_VA_LUU_Y_GIANG_VIEN_KHO_TINH.md` để nắm rõ các yêu cầu về:
    * Giải thích cơ chế lưu trữ (Stack vs Heap, buffer allocation, non-blocking lifecycle).
    * Lý do kỹ thuật tại sao thiết kế như vậy, không sinh kịch bản rác.
    * Phân biệt rõ đề tài Gateway Fuzzing với đề tài kiểm thử ứng dụng của các nhóm khác.
  * Cập nhật các phát hiện mới từ 2 tool vào báo cáo chính thức `report/BaoCao_BTL_Nhom11.pdf`.
- [ ] **Bước 5: Đồng bộ Kiểm tra & Bàn giao Hoàn chỉnh**
  * Cập nhật mã băm SHA-256 trong `scripts/verify_project.py` nếu có file báo cáo hoặc spec thay đổi.
  * Chạy `python scripts/verify_project.py` và `pytest tests/` bảo đảm đạt **10/10 PASS**.
  * Đóng gói lại `Nhom11_BTL_ChuDe4_Fuzzing.zip`.
  * Git commit sạch theo chuẩn conventional commits và push lên `origin main`.
  * Báo cáo kết quả đầy đủ cho người dùng.

---

## 4. QUY TẮC BẢO MẬT & BẢO TOÀN DỮ LIỆU
* **Tuyệt đối không để lộ thông tin cá nhân:** Mã sinh viên (MSSV) và Khóa/Lớp để trống. Tên thành viên: Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%).
* **Không lưu file nháp trên Git:** Chỉ giữ `BaoCao_BTL_Nhom11.pdf` trong thư mục `report/`. Bản Word và Markdown backup được lưu an toàn tại `scratch/doc_backups/`.
* **Giữ vững phong cách kỹ thuật:** Tuân thủ chuẩn CERT C, toán học SMT Z3 Bit-Vector, và kiểm định thực nghiệm 30 trials không bịa đặt số liệu.
