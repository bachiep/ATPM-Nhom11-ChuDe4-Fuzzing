# BIÊN BẢN CHUYỂN GIAO PHIÊN LÀM VIỆC CHI TIẾT (COMPREHENSIVE HANDOFF)
**Học phần:** Kỹ thuật Lập trình An toàn (CSE703093 / CSE703153) — ThS. Vũ Quang Dũng (ĐH Phenikaa)  
**Nhóm sinh viên:** Nhóm 11 — Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%)  
**Ngày lập biên bản:** 06/10/2026 (Phiên cập nhật toàn diện sau khi tiếp nhận gói công cụ mới)  
**Mục tiêu tối thượng:** Bàn giao toàn bộ ngữ cảnh kỹ thuật, giải mã trọn vẹn bộ công cụ mới của giảng viên, phân loại rành mạch file cũ - file mới, làm sáng tỏ triết lý *"Tool hỗ trợ 70%, mọi thứ từ Tool ra"*, và định hình lộ trình hành động chuẩn mực để đạt điểm tối đa.

---

## 1. BẢNG PHÂN LOẠI & GIẢI MÃ TOÀN BỘ TÀI NGUYÊN TẠI `04_Cong_Cu_Giang_Vien/`

Sau khi kiểm tra sâu cấu trúc nhị phân, bytecode Python và nội dung giải nén, đây là danh mục chi tiết, phân định rõ ràng giữa **TỆP CŨ** và **TỆP MỚI**:

| Tên tệp tin | Dung lượng | Thời gian cập nhật | Phân loại | Bản chất & Vai trò kỹ thuật trong môn học |
|---|---|---|---|---|
| **`SecLabFramework.exe`** | **104.8 MB** | **06/10/2026 19:48** | ⭐ **TOOL MỚI (CHỦ LỰC)** | **Phiên bản nâng cấp toàn diện v27 của Giảng viên.** Bytecode `main` lớn tới 61.7 KB (gấp 13 lần bản cũ). Tích hợp đầy đủ cả GUI và CLI cho cả 6 chương: kiểm chứng Kripke/CTL, phân tích tĩnh/động lỗi bộ nhớ C, sinh mã an toàn/không an toàn, Ctypes wrapper sinh test case mọi kiểu fuzzing, và import toàn bộ source code dự án có sẵn. |
| **`SpecVerificationLab.exe`** | 104.3 MB | 15/09/2026 17:18 | 📦 **TOOL CŨ** | Bản tiền nhiệm chỉ có script `main` 4.6 KB, chức năng nạp Spec Excel cơ bản. Đã được thay thế hoàn toàn bởi `SecLabFramework.exe`. |
| **`Template_Software_Security_iot_gateway_spec (2).xlsx`** | **13.5 KB** | **06/10/2026 19:48** | ⭐ **SPEC MẪU CỦA THẦY** | **File Excel đặc tả 10 sheet chuẩn do chính Thầy Dũng cung cấp làm mẫu.** Đề tài trong mẫu chính là `iot_gateway_auth`! Chứa đủ 9 REQ, 4 trạng thái Kripke, các hàm C sinh lỗi (`parse_device_id`, `write_log_entry`, `close_session`, `release_session_buffer`), và 6 Test Case truy vết. |
| **`Template_Report_iot_gateway_auth (2).docx`** | **38.2 KB** | **06/10/2026 19:48** | ⭐ **OUTPUT BÁO CÁO TỪ TOOL** | **Bằng chứng sống động nhất cho triết lý "Mọi thứ từ Tool ra".** Đây là file Word Báo cáo Tích hợp 7 chương được chính Tool của Thầy tự động sinh ra khi nạp đặc tả `iot_gateway_auth`, chứa cả mã vector TikZ LaTeX của mô hình Kripke. |
| **`specs.zip`** | **9.4 KB** | **06/10/2026 19:48** | ⭐ **BỘ ĐẶC TẢ JSON MẪU** | Chứa 7 file đặc tả dạng JSON (`iot_gateway_spec.json`, `auth_rate_limit_spec.json`, `session_manager_spec.json`...). Cấu trúc `iot_gateway_spec.json` khớp 1-1 với file Excel đặc tả của Thầy. |
| **`verification.zip`** | **15.7 KB** | **06/10/2026 19:48** | ⭐ **BỘ MÔ HÌNH HÌNH THỨC** | Chứa 15 mô hình Kripke / automata kinh điển (`dining_philosophers_deadlock.json`, `mutex_fixed.json`, `readers_writers.json`, `session_login_lifecycle.json`...). |
| **`softsec-toolkit (1).zip`** | **45.2 KB** | **06/10/2026 19:48** | 📚 **MÃ NGUỒN THỰC HÀNH** | Chứa toàn bộ bài lab thực hành từ Chương 1 đến Chương 4 (`kripke.py`, lỗi bộ nhớ C, Z3 SMT, Concolic execution, Fuzzing). |
| **`Ứng dụng hỗ trợ xử lý Spec...updated.zip`** | 103.5 MB | 06/10/2026 19:48 | 📦 **BẢN NÉN CŨ** | Gói zip chứa bản cũ `SpecVerificationLab.exe`. Giữ lại để đối chiếu lịch sử. |

---

## 2. GIẢI MÃ TRIẾT LÝ GIẢNG VIÊN: "TOOL HỖ TRỢ 70%, MỌI THỨ TỪ TOOL RA"

### 2.1 Bản chất 70% của Tool là gì?
Giảng viên nhấn mạnh bài chưa ổn nếu sinh kịch bản ngoài tool vì **Tool của thầy (`SecLabFramework.exe`) đã là một cỗ máy tự động hóa khép kín**:
1. **Đầu vào duy nhất:** Tệp đặc tả chuẩn (Excel 10 sheet hoặc JSON).
2. **Khâu 1 (Chương 1 — Kripke/CTL):** Tool tự động phân tích không gian trạng thái, kiểm tra Deadlock, phát hiện vi phạm Loại trừ lẫn nhau (Mutual exclusion), và xuất thẳng mã vẽ đồ thị hình học vector **TikZ (LaTeX)**.
3. **Khâu 2 (Chương 2 — C Code Generation):** Tool tự động đọc bảng `HamSinhMa` trong Spec để sinh mã C chứa đúng 4 loại lỗi bộ nhớ:
   - `strcpy(buffer, raw_id)` $\rightarrow$ **CWE-121 (Stack Buffer Overflow)**.
   - `malloc(...)` không `free(...)` $\rightarrow$ **CWE-401 (Memory Leak)**.
   - `free(buf); free(buf);` $\rightarrow$ **CWE-415 (Double Free)**.
   - `free(buf); buf[0] = 1;` $\rightarrow$ **CWE-416 (Use-After-Free)**.
4. **Khâu 3 (Chương 3 — AST & SMT Solver):** Tool trích xuất điều kiện số học và gọi **Z3 Solver** kiểm tra khả năng tràn số int32 (`telemetry_byte_counter`).
5. **Khâu 4 (Chương 4 — Dynamic Fuzzing):** Tool sinh các hàm Python (`token_ratio`, `device_unlock_code`) và tự chạy:
   - **Black-box Fuzzing:** Tìm ngoại lệ `ZeroDivisionError`.
   - **Concolic Execution (White-box Fuzzing):** Dùng SMT giải ngược giá trị bí mật (magic value: `7421, 3390`) trong $\le 15$ vòng lặp.
6. **Khâu 5 (Chương 5 — Báo cáo tự động):** Tool xuất toàn bộ kết quả trên thành tệp Word `.docx` hoàn chỉnh (`Template_Report_...docx`).

### 2.2 Phần 30% quyết định điểm A+ của Sinh viên là gì?
Nếu 70% là bấm nút cho Tool chạy, thì 30% sinh viên cần làm để thầy công nhận là:
1. **Thiết kế Spec chuẩn mực & có ý nghĩa thực tiễn cao:** Không lấy bừa kịch bản vô nghĩa; phải thiết kế đặc tả hệ thống có logic nghiệp vụ rõ ràng (khóa cấu hình giữa 2 worker, xác thực gói tin, cơ chế non-blocking). Bảng đặc tả phải đạt $\ge 5$ dòng ở tất cả các bảng dữ liệu để vượt qua Checklist Chương 5.
2. **Phân tích cơ chế bộ nhớ tận gốc rễ (Memory Internals):**
   - Trả lời rõ ràng: Dữ liệu lưu vào **Stack hay Heap**?
   - Tại sao `strcpy` đè lên Return Address của Stack frame?
   - Con trỏ sau khi `free` có trỏ vào đâu? Cơ chế dangling pointer trong Heap arena ra sao?
   - Worker gọi hàm xong có lưu dữ liệu lại không hay giải phóng ngay? Vòng đời xử lý non-blocking là gì?
3. **Bản vá an toàn (Safe Implementation) đạt chuẩn CERT C:**
   - Mã lỗi do tool sinh ra là minh chứng cho lỗ hổng.
   - Nhóm phải xây dựng bản vá hoàn chỉnh: **CERT STR31-C** (dùng `strncpy`/`snprintf` có bound check), **CERT MEM30-C / MEM31-C** (gán `ptr = NULL` sau khi `free`, kiểm tra `NULL` trước khi dùng).
4. **Kiểm định thực nghiệm khách quan (30 trials Benchmark):**
   - Không bịa đặt số liệu. Chạy thực tế 30 lượt so sánh Black-box vs Greybox (gcov coverage) vs White-box (Z3 SMT).
   - Chứng minh tại sao White-box/Concolic tìm được magic value trong 14ms (1 lần thử), trong khi Black-box thất bại 100%.
5. **Đối soát & Phản biện sắc bén:**
   - Lý giải tại sao Cppcheck (Static Analysis) bỏ lọt lỗi tràn buffer động, và tại sao **AddressSanitizer (ASan)** là công cụ phát hiện chuẩn xác nhất trong môi trường thực thi.

---

## 3. KHÁM PHÁ CÁC TÍNH NĂNG CLI MỚI CỦA `SecLabFramework.exe`

Qua trích xuất bytecode, `SecLabFramework.exe` cung cấp một hệ thống lệnh CLI cực kỳ mạnh mẽ mà nhóm có thể khai thác triệt để:

```bash
# 1. Chạy giao diện đồ họa đầy đủ (GUI)
.\SecLabFramework.exe

# 2. Kiểm chứng tương tác Chương 1 (Kripke / CTL)
.\SecLabFramework.exe --cli-ch1

# 3. Kiểm tra tương tác Chương 2 (Quét lỗi bộ nhớ C & Struct Alignment)
.\SecLabFramework.exe --cli-ch2

# 4. Luyện tập tương tác Chương 5 (Lập trình C/C++ an toàn theo 7 chuyên đề)
.\SecLabFramework.exe --cli-ch5

# 5. Ctypes Wrapper cho C/C++ (Sinh test case mọi kiểu fuzzing, CFG/Call Graph, xuất pytest)
.\SecLabFramework.exe --cli-cwrap file.c --san auto --export thu_muc_xuat

# 6. Chiến dịch Fuzzing tự động đa kỹ thuật (Boundary, Blackbox, Mutation, Coverage, Whitebox)
.\SecLabFramework.exe --cli-fuzz file.c --func ten_ham --iterations 1000 --san asan --export results_dir

# 7. Nhập mã nguồn dự án có sẵn để chạy toàn bộ Pipeline Ch1 -> Ch5
.\SecLabFramework.exe --cli-ch6-import PATH --iterations 500 --export report.txt
```

> **Lưu ý kỹ thuật Windows Console Encoding:** Khi chạy CLI trên Windows PowerShell, nếu gặp lỗi `UnicodeEncodeError (charmap / cp1252)`, hãy dùng lệnh sau để mở GUI hoặc chuyển mã trang sang UTF-8:
> ```powershell
> $env:PYTHONIOENCODING="utf-8"; $env:PYTHONUTF8="1"; chcp 65001
> ```

---

## 4. CHECKLIST HÀNH ĐỘNG CHO PHIÊN LÀM VIỆC TIẾP THEO

Khi bước vào phiên làm việc mới, Agent chỉ cần thực hiện đúng 5 bước sau:

- [ ] **Bước 1: Nạp Đặc tả vào `SecLabFramework.exe`**
  * Nạp file đặc tả [`Template_Software_Security_iot_gateway_spec (2).xlsx`](file:///I:/1_taiLieuDaiHoc/ATPM/TAI_LIEU_VA_YEU_CAU/04_Cong_Cu_Giang_Vien/Template_Software_Security_iot_gateway_spec%20(2).xlsx) (hoặc bản mở rộng $\ge 5$ dòng của nhóm tại `specification/`) vào `SecLabFramework.exe`.
  * Chạy tính năng xuất báo cáo tích hợp để sinh ra tệp Word `.docx` mới nhất từ Tool.
- [ ] **Bước 2: Thu thập Bằng chứng Sinh ra từ Tool ("Artifacts")**
  * Trích xuất mã C sinh ra bởi tool (`parse_device_id`, `write_log_entry`, `close_session`, `release_session_buffer`).
  * Trích xuất mã TikZ LaTeX sơ đồ trạng thái Kripke.
  * Trích xuất log chạy Fuzzing (`token_ratio` ZeroDivisionError) và Concolic Execution (giải mã `7421, 3390`).
  * Lưu toàn bộ kết quả vào thư mục `results/` làm bằng chứng đối soát thực tế.
- [ ] **Bước 3: Chạy Chiến dịch Fuzzing & Ctypes Wrap nâng cao của Tool**
  * Thực thi lệnh:
    `.\SecLabFramework.exe --cli-fuzz source/gateway_parser_v0.c --export results/fuzz_seclab/`
  * Thu thập bảng phân tích Call Graph, CFG và nhật ký tìm lỗi crash từ chính Tool của thầy.
- [ ] **Bước 4: Cập nhật & Biên dịch Báo cáo BTL Toàn diện**
  * Ghép nối các phần do Tool sinh ra (70%) với phần lập luận phân tích sâu của sinh viên (30%):
    - Cơ chế quản lý bộ nhớ Stack vs Heap, vòng đời con trỏ.
    - Bản vá an toàn chuẩn CERT C (STR31-C, MEM30-C, MEM31-C).
    - Bảng số liệu benchmark thực nghiệm 30 trials.
    - Bộ câu hỏi vấn đáp bảo vệ đồ án (dựa trên tài liệu `YEU_CAU_VA_LUU_Y_GIANG_VIEN_KHO_TINH.md`).
  * Biên dịch sạch ra `report/BaoCao_BTL_Nhom11.pdf` bằng script Word COM `scripts/export_all_docs.py`.
- [ ] **Bước 5: Thẩm định Tự động & Đóng gói Nộp bài**
  * Cập nhật mã băm SHA-256 mới trong `scripts/verify_project.py`.
  * Chạy `python scripts/verify_project.py` và `pytest tests/` bảo đảm **10/10 PASS**.
  * Đóng gói bản nộp `Nhom11_BTL_ChuDe4_Fuzzing.zip`.
  * Commit sạch sẽ lên Git remote `main` (không để lộ MSSV, tuân thủ conventional commits).

---

## 5. BẢO MẬT & QUY TẮC BẤT BIẾN
1. **Thông tin sinh viên:** Luôn để trống MSSV và Khóa/Lớp trên mọi tài liệu báo cáo và cam đoan (bảo vệ quyền riêng tư). Tên 2 thành viên: Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%).
2. **Không commit file nháp lên Git:** Chỉ commit mã nguồn, script, đặc tả Excel và tệp PDF chính thức `report/BaoCao_BTL_Nhom11.pdf`.
3. **Tuyệt đối trung thực về số liệu:** Mọi số liệu thời gian (time-to-crash), iteration, coverage đều trích xuất trực tiếp từ các file JSON thô và công cụ thực thi của Thầy, không suy đoán bịa đặt.
