# BIÊN BẢN CHUYỂN GIAO PHIÊN LÀM VIỆC (SESSION HANDOFF)
**Học phần:** Kỹ thuật Lập trình An toàn (CSE703093 / CSE703153) — ThS. Vũ Quang Dũng (ĐH Phenikaa)  
**Nhóm sinh viên:** Nhóm 11 — Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%)  
**Ngày lập biên bản:** 06/10/2026  
**Nguyên tắc cốt lõi:**  
- **Tư duy cởi mở, không gò ép:** Đề tài IoT Gateway trước đó chỉ là bài tập thử nghiệm và tích lũy kinh nghiệm phương pháp. Sẵn sàng bắt đầu một dự án mới hoàn toàn nếu 2 công cụ mới của giảng viên định hình một bài toán/hệ thống khác.  
- **Không cần tạo Repo mới:** Triển khai trực tiếp trên workspace hiện tại.  
- **Mọi thứ xuất phát từ Tool giảng viên ("Tool hỗ trợ 70%"):** Đề tài, luồng dữ liệu, đặc tả, mã nguồn và kết quả báo cáo sẽ được định hình trực tiếp từ 2 tool mới của thầy.

---

## 1. TÌNH HÌNH DỰ ÁN & ĐỊNH HƯỚNG MỚI

### 1.1 Kinh nghiệm tích lũy từ phiên trước
* **Kỹ năng cốt lõi đã làm chủ:**
  - Quy chuẩn tệp đặc tả Excel 10 sheet theo Checklist Chương 5 (`Huong_dan_tao_Spec_file_dang_excel.pdf`).
  - Phân tích an toàn bộ nhớ C (Stack vs Heap, CERT C STR31-C, MEM30-C, AddressSanitizer).
  - Mô hình hóa hình thức (Kripke model, Z3 SMT Bit-Vector solver).
  - Tự động hóa kiểm định và xuất báo cáo PDF chuẩn mực qua script.
* **Workspace hiện tại:** Đã được dọn dẹp sạch sẽ, cấu trúc tài liệu quy chuẩn tại `TAI_LIEU_VA_YEU_CAU/`.

### 1.2 Biến chuyển mới: Ý kiến của Giảng viên & 2 Tool mới
Giảng viên vừa chấn chỉnh định hướng:
1. **"Tool đã hỗ trợ 70%, mọi thứ phải được làm từ tool ra":** Không tự biên tự diễn kịch bản rời rạc bên ngoài; phải nắm bắt cách vận hành tool của thầy, nạp đúng định dạng và lấy kết quả từ tool để đưa vào báo cáo.
2. **Cung cấp thêm 2 tool mới:** Sẵn sàng tiếp nhận 2 tool mới để phân tích chức năng và luồng xử lý.
3. **Sẵn sàng tái thiết lập dự án mới:** Không gò ép đề tài vào IoT Gateway nếu 2 tool mới hướng tới một mô hình/hệ thống mục tiêu khác. Bài toán nào tối ưu nhất cho pipeline của thầy sẽ được chọn làm dự án chính thức.

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
- [ ] **Bước 2: Xác định vai trò & bài toán mục tiêu từ 2 Tool mới**
  * Tool mới làm nhiệm vụ gì? (Phân tích tĩnh/động AST C? Sinh ca kiểm thử tự động? Kiểm tra mô hình hình thức SMT/Kripke? Hay sinh/quét mã?).
  * Xác định cấu trúc đầu vào mà 2 tool yêu cầu (file Spec Excel, mã C nguồn, hay giao thức/hệ thống cụ thể nào).
  * **Quyết định bài toán:** Nếu 2 tool hoạt động tốt nhất trên một hệ thống/nghiệp vụ khác (ví dụ: giao thức nhúng, hệ thống quản lý quyền truy cập, parser mới...), chúng ta sẵn sàng khởi tạo đặc tả và mã nguồn mới hoàn toàn bám sát tool.
- [ ] **Bước 3: Vận hành Pipeline từ 2 Tool mới ("Mọi thứ làm từ Tool ra")**
  * Chạy trực tiếp 2 tool với hệ thống mục tiêu.
  * Thu thập toàn bộ artifact sinh ra: log runtime, bảng phân tích AST, trace kiểm thử, đồ thị trạng thái, hay báo cáo tự động từ tool.
  * Toàn bộ dữ liệu thực nghiệm và bằng chứng phải trích xuất 100% từ tool thầy cung cấp.
- [ ] **Bước 4: Thiết kế Báo cáo & Phân tích Chuyên sâu**
  * Đọc kỹ tài liệu `YEU_CAU_VA_LUU_Y_GIANG_VIEN_KHO_TINH.md` để giải trình cặn kẽ:
    * Cơ chế lưu trữ dữ liệu (Stack vs Heap, vòng đời con trỏ, buffer allocation).
    * Lý do kỹ thuật tại sao hệ thống được thiết kế như vậy, không tạo kịch bản bừa bãi.
    * Giải thích bản chất từng trạng thái, chuyển trạng thái và ràng buộc an toàn.
  * Tích hợp toàn diện các bằng chứng từ tool vào báo cáo chính thức.
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
