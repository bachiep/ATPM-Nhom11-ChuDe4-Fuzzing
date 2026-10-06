# CẨM NANG YÊU CẦU & LƯU Ý BẮT BUỘC CỦA GIẢNG VIÊN KHÓ TÍNH
**Học phần:** Kỹ thuật Lập trình An toàn (Software Security) — CSE703093 / CSE703153  
**Giảng viên hướng dẫn:** ThS. Vũ Quang Dũng (Trường Công nghệ Thông tin — Đại học Phenikaa)  
**Đề tài 4:** Phân tích Cú pháp Gói tin Nhị phân SecureGate IoT Gateway (Fuzzing & Formal Verification)  
**Nhóm thực hiện:** Nhóm 11 — Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%)  
**Ngày cập nhật:** Tháng 10/2026 (Phiên bản đồng bộ theo chỉ đạo mới nhất của Giảng viên)

---

## I. TỔNG HỢP CHỈ ĐẠO CỐT LÕI MỚI NHẤT CỦA GIẢNG VIÊN

> ### ⚡ LỜI NHẮC NHỞ CỦA GIẢNG VIÊN:
> 1. *"Tool của thầy đã hỗ trợ tới 70% khối lượng công việc rồi! Mọi kết quả, mã nguồn sinh ra, mô hình hóa và báo cáo PHẢI ĐƯỢC XUẤT PHÁT VÀ LÀM TỪ TOOL RA."*
> 2. *"Nhiệm vụ trọng tâm của các em là: **DÙNG TOOL CHO THẬT TỐT, HIỂU SÂU BẢN CHẤT CÁC KẾT QUẢ TOOL SINH RA VÀ BÁO CÁO CHÍNH XÁC CHO THẦY**."*
> 3. *"Mọi kịch bản đặc tả không được sinh ra ngẫu nhiên hàng loạt mà không có giải thích. Phải diễn giải tại sao lại làm như thế, các phần sinh ra lưu vào bộ nhớ như thế nào, lưu vào stack hay heap, gọi xong có lưu không hay chờ xử lý sau, được kiểm soát thế nào."*
> 4. *"Không cần phải sinh ra quá dài dòng, mà cần ĐỘ CHÍNH XÁC VÀ CHẮT CHIU. Không sinh kịch bản rác!"*
> 5. *"Bài của các nhóm khác là làm về dự án code ứng dụng của họ và kiểm thử, còn bài của chúng ta HOÀN TOÀN KHÁC BIỆT: là kiểm định tầng biên nhị phân, giải rào cản bằng Fuzzing thông minh và chứng minh hình thức!"*

---

## II. TRIẾT LÝ: TẠI SAO PHẢI "LÀM TỪ TOOL RA" (TOOL-CENTRIC APPROACH)?

### 1. Bản chất sự hỗ trợ 70% của Tool giảng viên
Giảng viên xây dựng bộ công cụ (`SpecVerificationLab` và các công cụ bổ sung) không phải để sinh viên "bấm nút cho vui", mà công cụ đóng vai trò là **Hạt nhân Tự động hóa (Automation Kernel)**:
* **Khâu 1 (Đặc tả $\to$ Mô hình):** Đọc file Excel 10-sheet làm Nguồn Chân lý Đơn nhất (SSOT), tự động chuyển đổi thành Cấu trúc Kripke $M = (S, S_0, R, L)$.
* **Khâu 2 (Model Checking):** Tự động duyệt ma trận kề, kiểm tra thuộc tính CTL $AG(\neg \text{violation})$, phát hiện phản ví dụ (Counterexample Trace) chứng minh lỗi tương tranh/race condition.
* **Khâu 3 (AST & SMT Solver):** Tự động bóc tách cây cú pháp trừu tượng (AST), đo độ phức tạp McCabe, thiết lập hệ phương trình Bit-Vector nạp vào Z3 SMT Solver để tìm nghiệm và chứng minh nguy cơ tràn số nguyên CWE-190.
* **Khâu 4 (Code Generation & Fuzzing):** Tự động sinh mã nguồn C (gắn assertion) và mã Python, tự động thực thi Fuzzing tìm crash (CWE-369 chia cho 0, Concolic giải cặp khóa bí mật).
* **Khâu 5 (Báo cáo Tích hợp):** Xuất toàn bộ ma trận liên kết và danh mục lỗi CWE/CVE thành tài liệu báo cáo chính thức.

### 2. Trách nhiệm 30% còn lại của Nhóm sinh viên
* **Thiết kế Input Đặc tả chuẩn xác:** Xây dựng tệp Excel đúng 10 sheets, mỗi bảng $\ge 5$ dòng, khớp số liệu với bài toán IoT Gateway.
* **Diễn giải cơ chế vận hành:** Giải thích cặn kẽ tại sao trạng thái lại chuyển đổi như vậy, dữ liệu lưu trữ ở đâu trên kiến trúc phần cứng, vòng đời cấp phát và giải phóng ra sao.
* **Thực nghiệm đối sánh chuyên sâu:** Xây dựng Target Parser thực tế (`gateway_parser_v0.c` vs `v1.c`), chạy benchmark 30 trials độc lập so sánh 3 trường phái Fuzzer (Black-box, Greybox gcov, White-box Z3), phân tích shadow bytes AddressSanitizer (`[f3]`), và chứng minh điểm mù của Cppcheck.

---

## III. YÊU CẦU DIỄN GIẢI KỸ THUẬT: CƠ CHẾ LƯU TRỮ VÀ KIỂM SOÁT BỘ NHỚ

Giảng viên đặc biệt yêu cầu nhóm phải trả lời tường minh bài toán quản lý tài nguyên bộ nhớ:

### 1. Dữ liệu lưu vào đâu?
* **Header và Metadata:** Lưu trên **Stack Frame** của hàm `parse_and_process()` dưới dạng cấu trúc cố định 16 bytes (`GatewayHeader hdr`).
* **Chuỗi Định danh `device_id`:** Lưu tại biến mảng cục bộ trên **Stack Frame**:
  - *Tại bản lỗi `v0`:* Khai báo `char device_id[16];`. Khi gói tin có `device_id_len = 24`, lệnh `memcpy` ghi vượt 8 bytes đè lên Stack Right Redzone (ASan bắt lỗi tại offset 112 trong frame).
  - *Tại bản vá `v1`:* Khai báo `char device_id[17];` và chặn cứng `if (hdr.device_id_len > 16) return 1;`.
* **Luồng Payload và Toàn bộ Gói tin:** Được cấp phát động trên **Heap** (`uint8_t *buf = malloc(file_size)`).

### 2. Vòng đời dữ liệu: Có lưu lâu dài không hay chờ xử lý sau?
* **Mô hình xử lý Non-blocking / Run-to-Completion:**
  - Gói tin nhị phân IGW1 sau khi nhận từ socket được giải mã ngay lập tức.
  - Sau khi kiểm tra Magic `'IGW1'`, Version, Flags, Reserved và xác thực Checksum 32-bit:
    * Nếu hợp lệ: Trích xuất thông tin thiết bị, ghi log kiểm toán, và **giải phóng ngay lập tức vùng đệm Heap** (`free(buf)`).
    * Nếu không hợp lệ: Lập tức in thông báo từ chối (`[REJECT]`), **thu hồi bộ nhớ Heap ngay lập tức** trước khi trả về mã lỗi (`return 1`), triệt tiêu hoàn toàn rò rỉ bộ nhớ (CWE-401).
* **Không lưu trữ tồn đọng:** Hệ thống gateway không lưu trữ buffer nhị phân thô vào hàng đợi vô hạn để tránh nguy cơ cạn kiệt tài nguyên (Memory Exhaustion / DoS).

---

## IV. SỰ KHÁC BIỆT CỐT LÕI GIỮA BÀI CỦA CHÚNG TA VÀ CÁC NHÓM KHÁC

Khi trình bày với giảng viên, nhóm phải nêu bật được định vị học thuật:

| Tiêu chí so sánh | Các nhóm làm về "Dự án Code ứng dụng" | Đề tài 4 của Nhóm 11 (Fuzzing & IoT Gateway) |
|---|---|---|
| **Bản chất bài toán** | Kiểm thử chức năng (Functional Testing / QA) trên ứng dụng Web/CRUD cấp cao (Java, C#, JS). | **Kỹ thuật Lập trình An toàn tầng thấp (Low-level Security Engineering)** trên firmware C của thiết bị nhúng IoT. |
| **Bề mặt tấn công** | Nhập liệu form, gửi request HTTP, kiểm tra logic người dùng. | **Biên giới nhị phân thô (Untrusted Binary Stream)** qua socket TCP/UDP — nơi hacker khai thác Remote Code Execution (RCE). |
| **Bản chất lỗi** | Lỗi validate dữ liệu, lỗi logic nghiệp vụ, ngoại lệ cấp cao. | **Lỗi an toàn bộ nhớ (Memory Safety CWE-121)**: Tràn ngăn xếp, ghi đè frame pointer, phá hủy stack canary, lỗi số học CWE-190. |
| **Phương pháp kiểm thử** | Viết test case thủ công (Ad-hoc), kiểm thử đơn vị thông thường. | **Smart Fuzzing đa trường phái**: Black-box, Greybox phản hồi độ phủ `gcov`, và White-box giải ngược SMT Z3 Bit-Vector. |
| **Kiểm chứng hình thức** | Hầu như không có, chỉ dùng công cụ quét tĩnh thông thường. | **Mô hình hóa hình thức 10-sheet SSOT**: Model Checking Kripke/CTL, SMT Solver giải ngược không gian trạng thái $2^{32}$. |

---

## V. CHECKLIST KIỂM TRA BẮT BUỘC CHO FILE ĐẶC TẢ EXCEL (CHƯƠNG 5)

Tệp đặc tả `specification/Nhom11_SecureGate_IoT_Gateway_Spec.xlsx` phải duy trì 100% các tiêu chí sau:

1. **Cấu trúc Workbook:**
   - Đủ đúng 10 sheets, tên chính xác từng ký tự:
     `ThongTin`, `YeuCauChucNang`, `YeuCauPhiChucNang`, `RangBuoc`, `MoHinhTrangThai`, `ThuocTinhAnToan`, `LoaiTruLanNhau`, `HamSinhMa`, `KiemTraSoHoc`, `TestCase`.
   - **Tuyệt đối không sửa tên 10 tab sheet** (không thêm hậu tố `_Nhom11` vào tên tab vì tool đọc cứng tên sheet).
   - Không còn bất kỳ dòng dữ liệu mẫu nào của hệ thống thư viện mượn trả sách.

2. **Quy chuẩn số dòng ($\ge 5$ dòng dữ liệu cho mỗi bảng):**
   - `ThongTin`: Có `name` và `description` ghi rõ định danh Nhóm 11.
   - `YeuCauChucNang`: $\ge 5$ dòng (hiện có 9 dòng), phủ đủ 4 danh mục: `safety`, `liveness`, `memory`, `functional`.
   - `YeuCauPhiChucNang`: $\ge 5$ dòng có số đo định lượng cụ thể (500 pkt/s, $<5$ms, log đồng bộ, RAM $\le 2$MB, drop $\le 0.01\%$).
   - `RangBuoc`: $\ge 5$ dòng; độ dài dữ liệu khớp với `KichThuocBuffer=16` trong `HamSinhMa`.
   - `MoHinhTrangThai`: Có 4 trạng thái, có nhãn `violation`, không có deadlock ngoài ý muốn.
   - `ThuocTinhAnToan`: $\ge 5$ công thức CTL bao phủ cả an toàn $AG(\neg \text{violation})$, khả đạt $EF$, và vòng đời $AG(\dots \to AF(\text{safe}))$.
   - `LoaiTruLanNhau`: $\ge 5$ dòng, dòng 1 bắt buộc là cặp khóa chính (`reg_processing` $\perp$ `unlock_processing`), toàn bộ nhãn phải có trong cột `Nhan`.
   - `HamSinhMa`: Đủ 4 loại lỗi C (`buffer-overflow`, `memory-leak`, `double-free`, `use-after-free`) và 2 hàm Python (`divide`, `magic_value`).
   - `KiemTraSoHoc`: $\ge 5$ dòng dùng đúng ngưỡng chuẩn (32767, 65535, 2 tỷ), khai báo cả `DieuKien` và `BieuThucTran`.
   - `TestCase`: $\ge 5$ dòng (hiện có 8 dòng), truy vết có thật tới `REQ`, `NFR`, `CON`, mỗi bước trên 1 dòng riêng (Alt+Enter).

---

## VI. QUY TẮC LIÊM CHÍNH, BẢO MẬT & ĐỊNH DẠNG BÀN GIAO

1. **Bảo mật thông tin sinh viên:**
   - Trong bảng phân công thành viên: Để trống Mã sinh viên (MSSV) và Khóa/Lớp theo đúng yêu cầu bảo mật cá nhân.
   - Chỉ giữ Họ tên: **Lưu Đức Hiệp** (Nhóm trưởng) & **Hà Nguyễn Trúc Linh** (Thành viên), phân chia đóng góp **50% - 50%**.
2. **Loại bỏ hoàn toàn tệp nháp & dấu vết thừa:**
   - Không đưa lên Git các file soạn thảo thô (`HUONG_DAN_KIEM_TRA_DU_AN.*`, `BaoCao_BTL_Nhom11.docx`, `BaoCao_BTL_Nhom11.md`).
   - Thư mục `report/` chỉ duy nhất lưu trữ tệp PDF chính thức: **`report/BaoCao_BTL_Nhom11.pdf`**.
3. **Mã băm SHA-256 toàn vẹn:**
   - Mọi thay đổi trong file Excel hoặc file PDF phải được tính lại SHA-256 và cập nhật vào `scripts/verify_project.py` để Khâu 8 luôn đạt **100% MATCH**.
4. **Quy chuẩn Git:**
   - Commit messages tuân thủ chuẩn Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`).
   - Tuyệt đối không commit file sinh tạm runtime (`.pytest_cache`, `__pycache__`, `.gcda`, `.gcno`).

---

## VII. BỘ CÂU HỎI VẤN ĐÁP KHÓ TÍNH CỦA GIẢNG VIÊN & ĐÁP ÁN CHUẨN

* **Hỏi 1:** *"Tại sao các em không lấy một dự án web có sẵn ra test mà lại tự làm bộ Parser này?"*  
  **Đáp:** Thưa thầy, dự án web cấp cao có Garbage Collector nên không thể khảo sát được lỗi an toàn bộ nhớ ở tầng sâu hệ thống. Đề tài của nhóm hướng tới cổng giao tiếp nhị phân của IoT Gateway viết bằng C — nơi tiếp nhận dữ liệu mạng thô và có nguy cơ bị khai thác chiếm quyền điều khiển (RCE CWE-121). Đây là bài toán an toàn phần mềm thực tế mà các tổ chức lớn như Google OSS-Fuzz đang tập trung giải quyết.

* **Hỏi 2:** *"Tại sao Cppcheck không phát hiện được lỗi tràn buffer ở v0 trong khi AddressSanitizer lại bắt được?"*  
  **Đáp:** Thưa thầy, Cppcheck phân tích tĩnh trên cây AST cú pháp nên bị giới hạn bởi 'điểm mù' dữ liệu bẩn thời gian thực (Tainted Input False Negative). Chiều dài `device_id_len` nằm trong payload gói tin do hacker gửi đến tại runtime, Cppcheck không thể biết trước giá trị này nên cho qua. Ngược lại, Dynamic Fuzzing kết hợp AddressSanitizer giám sát vùng shadow bytes của ngăn xếp trong quá trình thực thi nên lập tức phát hiện truy cập vượt biên tại offset 112 với nhãn `[f3]`.

* **Hỏi 3:** *"Các kịch bản trong file Excel các em sinh ra để làm gì, có tác dụng gì trong pipeline của thầy?"*  
  **Đáp:** Thưa thầy, file Excel đóng vai trò là Nguồn Chân lý Đơn nhất (SSOT). Mỗi dòng trong 10 sheet đều phục vụ trực tiếp cho các module kiểm chứng trong tool của thầy: Sheet `MoHinhTrangThai` và `ThuocTinhAnToan` dùng để dựng đồ thị Kripke và kiểm chứng CTL Model Checking chứng minh không deadlock và phát hiện race hazard; Sheet `HamSinhMa` dùng để trích xuất AST và đo độ phức tạp McCabe; Sheet `KiemTraSoHoc` đưa vào Z3 SMT Solver để chứng minh nguy cơ tràn số nguyên CWE-190; và Sheet `TestCase` thiết lập ma trận truy vết chuẩn IEEE 829.
