# TRƯỜNG CÔNG NGHỆ THÔNG TIN — ĐẠI HỌC PHENIKAA
## BÁO CÁO ĐỒ ÁN MÔN HỌC
### CSE703093 / CSE703153 — Kỹ thuật Lập trình An toàn (Software Security)

---

# ĐỀ TÀI 4: DỰ ÁN FUZZING — PHÂN TÍCH CÚ PHÁP GÓI TIN NHỊ PHÂN SECUREGATE IOT GATEWAY

**Giảng viên hướng dẫn:** ThS. Vũ Quang Dũng  
**Học kỳ / Năm học:** Học kỳ I — Năm học 2026–2027  
**Nhóm thực hiện:** Nhóm 11 — Lớp CSE703093  

| STT | Họ và tên | Mã sinh viên (MSSV) | Lớp | Vai trò & Nhiệm vụ |
|:---:|---|:---:|:---:|---|
| 1 | **Lưu Đức Hiệp** | *(Điền thông tin)* | *(Điền thông tin)* | Nhóm trưởng: Thiết kế target parser, cài đặt White-box Fuzzer (Z3), phân tích và vá lỗi CWE-121 |
| 2 | **Hà Nguyễn Trúc Linh** | *(Điền thông tin)* | *(Điền thông tin)* | Thành viên: Cài đặt Black-box & Greybox Fuzzer, thực thi benchmark 30 trials, thống kê định lượng |

*Hà Nội, Tháng 09 Năm 2026*

---

## MỤC LỤC

1. [Phần 1: Trang bìa & Thông tin nhóm](#trường-công-nghệ-thông-tin--đại-học-phenikaa)
2. [Phần 2: Tổng quan đề tài](#phần-2--tổng-quan-đề-tài)
   - 2.1 Bối cảnh và Động lực
   - 2.2 Mục tiêu đề tài
   - 2.3 Mô tả kiến trúc và Attack Surface của Target Parser
   - 2.4 Phạm vi thực hiện
3. [Phần 3: Phương pháp luận](#phần-3--phương-pháp-luận)
   - 3.1 Quy trình 5 bước áp dụng
   - 3.2 Chiến lược Fuzzing Hộp đen (Black-box Fuzzing)
   - 3.3 Chiến lược Fuzzing Hộp trắng (White-box Fuzzing với Z3 SMT Solver)
   - 3.4 Chiến lược Fuzzing Hộp xám (Greybox Coverage-Guided Fuzzing)
4. [Phần 4: Phân tích Lỗ hổng & Bản vá (CWE-121)](#phần-4--phân-tích-lỗ-hổng--bản-vá)
   - 4.1 Vị trí lỗ hổng
   - 4.2 Phân tích nguyên nhân gốc rễ (Root Cause)
   - 4.3 Bằng chứng trước khi vá (v0 — ASan Crash Trace)
   - 4.4 Kỹ thuật vá lỗi (So sánh chi tiết v0 vs v1)
   - 4.5 Bằng chứng kiểm chứng sau khi vá (v1 — 0 Finding)
5. [Phần 5: Bảng tổng hợp Before/After](#phần-5--bảng-tổng-hợp-beforeafter)
6. [Phần 6: Bằng chứng Kiểm chứng & Thực nghiệm Định lượng](#phần-6--bằng-chứng-kiểm-chứng--thực-nghiệm-định-lượng)
   - 6.1 Bảng so sánh định lượng 30 Trials
   - 6.2 Phân tích Biểu đồ Thực nghiệm
   - 6.3 Kết quả phân tích tĩnh Cppcheck
   - 6.4 Phân tích Benchmark phụ: Rào cản 32-bit Unlock Code
   - 6.5 Kết quả Kiểm thử Tự động Toàn diện (PyTest 30 Test Cases)
   - 6.6 Kiểm chứng Đặc tả Hình thức với Công cụ Giảng viên (SpecVerificationLab)
7. [Phần 7: Phản biện & Bài học Kinh nghiệm](#phần-7--phản-biện--bài-học-kinh-nghiệm)
   - 7.1 Đánh giá thiết kế và giải pháp ngăn ngừa từ đầu
   - 7.2 Các nguy cơ bảo mật tiềm ẩn còn nghi ngờ
   - 7.3 Bài học phương pháp luận về Sound/Complete
8. [Phần 8: Phụ lục](#phần-8--phụ-lục)
   - Phụ lục A: Hướng dẫn cài đặt và chạy lại (Reproduction Guide)
   - Phụ lục B: Toàn văn mã nguồn chương trình mục tiêu (v0 và v1)
   - Phụ lục C: Nhật ký thực thi (Raw Execution Logs)

---

## PHẦN 2 — TỔNG QUAN ĐỀ TÀI

### 2.1 Bối cảnh, Ngôn ngữ và Các Tuần học Liên quan
- **Tên đề tài đã chọn:** Đề tài 4 — Dự án Fuzzing: Phân tích Cú pháp Gói tin Nhị phân SecureGate IoT Gateway (theo Mục 3 của *Hướng dẫn Đề tài Đồ án Môn học*).
- **Ngôn ngữ sử dụng:** Ngôn ngữ C (chuẩn ISO C99/C11) cho Target Parser và Ngôn ngữ Python 3 (Python 3.10+) cho hệ thống Fuzzing Harness, Test Suite và SMT Solver.
- **Các tuần học liên quan trực tiếp:**
  + *Tuần 4 & Tuần 5:* Kỹ thuật lập trình an toàn C/C++, cấu trúc bộ nhớ (Stack, Heap), các lỗ hổng tràn bộ đệm (CWE-120/121) và quy tắc chuẩn hóa CERT C (STR31-C, ARR30-C, MEM31-C).
  + *Tuần 6:* Kiểm thử mờ (Fuzzing) nâng cao, phân tích động với AddressSanitizer/UBSan, phản hồi độ phủ mã lệnh (Coverage-guided với gcov/AFL).
  + *Tuần 7:* Phân tích hình thức (Formal Verification), Thực thi tượng trưng (Symbolic/Concolic Execution) và giải ngược điều kiện biên bằng Z3 SMT Solver.

### 2.2 Tóm tắt Chức năng Hệ thống v0 & Mục tiêu Đề tài
**Mô tả ngắn gọn chức năng hệ thống v0:**  
Hệ thống `gateway_parser_v0` đóng vai trò là module biên tiếp nhận và phân tích cú pháp các gói tin nhị phân định dạng giao thức IGW1 gửi từ các cảm biến IoT ngoại vi, thực hiện kiểm tra tính toàn vẹn qua chuỗi Magic Bytes (`"IGW1"`) và tổng kiểm tra Checksum tích lũy 32-bit. Sau khi xác thực hợp lệ, parser phân loại xử lý gói tin Đăng ký thiết bị (Registration) bằng cách trích xuất chuỗi `device_id` vào ngăn xếp stack, hoặc xử lý gói Mở khóa quản trị (Unlock) thông qua cặp mã khóa bí mật. Tuy nhiên, phiên bản v0 tồn tại khiếm khuyết an toàn bộ nhớ nghiêm trọng do lập trình viên bất cẩn trong khâu đối chiếu biên độ dài, cho phép kích thước chuỗi vượt quá dung lượng đệm ngăn xếp.

**Mục tiêu kỹ thuật cụ thể:**
1. **Thiết kế và hiện thực Target Program:** Xây dựng bộ phân tích cú pháp nhị phân `SecureGate IoT Gateway` bằng ngôn ngữ C, mô phỏng đúng cấu trúc gói tin mạng thực tế (Header, Magic Bytes, Checksum, Length Field, Payload).
2. **Cài đặt lỗ hổng có chủ đích:** Cài đặt một lỗ hổng an toàn bộ nhớ điển hình **CWE-121 (Stack-based Buffer Overflow)** được che giấu sau các tầng rào cản ngữ nghĩa khắt khe (Magic Bytes và Checksum toán học) để kiểm tra năng lực của các công cụ kiểm thử.
3. **Hiện thực và Đánh giá 3 Chiến lược Fuzzing:**
   - *Fuzzing Hộp đen (Black-box):* Đột biến ngẫu nhiên, không tri thức nội bộ.
   - *Fuzzing Hộp xám (Greybox):* Dẫn dắt bởi phản hồi độ phủ mã (`gcov` coverage feedback loop).
   - *Fuzzing Hộp trắng (White-box):* Ứng dụng **Z3 SMT Solver** (nội dung Chương 3 & 4) giải trực tiếp hệ phương trình ràng buộc đường đi (Path Condition) để vượt qua rào cản magic bytes và checksum.
4. **Đối chiếu và Đo lường Định lượng:** Thực hiện kiểm thử thống kê nghiêm ngặt (30 trials độc lập cho mỗi fuzzer, ngân sách 5.000 lượt thử) nhằm chứng minh khoảng cách hiệu quả giữa White-box và Black-box khi đối mặt với hằng số ma thuật.
5. **Vá lỗi và Xác minh:** Đề xuất bản vá triệt để (`v1`), chứng minh bằng công cụ AddressSanitizer rằng lỗ hổng đã được loại bỏ hoàn toàn (`0 findings`).

### 2.3 Mô tả Kiến trúc và Attack Surface của Target Parser

#### Cấu trúc Giao thức SecureGate IoT Gateway
Gói tin nhị phân gồm 3 thành phần liên tục trong bộ nhớ:
$$\text{Gói tin} = [\text{Header: 16 bytes}] + [\text{Payload: } N \text{ bytes}] + [\text{Checksum: 4 bytes}]$$

**Chi tiết trường Header (16 bytes, Định dạng Little-Endian):**
- `magic` (4 bytes): Chuỗi định danh giao thức cố định, bắt buộc phải là ASCII `"IGW1"` (`0x49 0x47 0x57 0x31`).
- `version` (1 byte): Phiên bản giao thức, bắt buộc bằng `0x01`.
- `type` (1 byte): Loại gói tin (`0x01`: Đăng ký thiết bị — Registration, `0x02`: Mở khóa quản trị — Unlock).
- `device_id_len` (1 byte): Độ dài chuỗi định danh thiết bị nằm trong Payload.
- `flags` (1 byte): Cờ điều khiển, bắt buộc bằng `0x00`.
- `payload_len` (2 bytes, `uint16_t`): Độ dài toàn bộ vùng Payload tiếp sau Header.
- `unlock_a` (2 bytes, `uint16_t`): Khóa bí mật A (chỉ dùng cho gói Unlock).
- `unlock_b` (2 bytes, `uint16_t`): Khóa bí mật B (chỉ dùng cho gói Unlock).
- `reserved` (2 bytes, `uint16_t`): Trường dự phòng, bắt buộc bằng `0x0000`.

**Cơ chế Checksum (4 bytes cuối cùng):**
Checksum được tính toán trên toàn bộ `16 bytes Header + Payload` theo công thức tổng tích lũy modulo $2^{32}$:
$$\text{Checksum} = \left(\sum_{i=0}^{16 + \text{payload\_len} - 1} \text{byte}_i\right) \pmod{2^{32}}$$

```
+-----------------------------------------------------------------------------------+
|                                HEADER (16 bytes)                                  |
| Magic (4B) | Ver(1B) | Type(1B) | ID_Len(1B) | Flags(1B) | Pay_Len(2B) | Keys(4B)|
+-----------------------------------------------------------------------------------+
|                               PAYLOAD (N bytes)                                   |
| Device ID (ID_Len bytes, ASCII printable) | Extra payload data                    |
+-----------------------------------------------------------------------------------+
|                             CHECKSUM (4 bytes, Little-Endian)                     |
+-----------------------------------------------------------------------------------+
```

#### Sơ đồ Luồng Xử lý Dữ liệu (Dataflow) và Chuỗi Kiểm tra (Validation Chain)

```
[File/Stream Đầu vào]
         │
         ▼
[Đọc 16 bytes Header] ────(Size < 16)────────────────────────────► [REJECT: File quá ngắn]
         │
         ├────(Magic != "IGW1")──────────────────────────────────► [REJECT: Sai Magic]
         ├────(Version != 1)─────────────────────────────────────► [REJECT: Sai Version]
         ├────(Flags != 0 || Reserved != 0)──────────────────────► [REJECT: Sai Flags]
         │
         ▼
[Đọc Payload + Checksum] ──(Tổng byte != 20 + payload_len)──────► [REJECT: Sai kích thước]
         │
         ▼
[Xác minh Checksum] ───────(Checksum thực tế != Header Checksum)──► [REJECT: Checksum không khớp]
         │
         ▼
[Kiểm tra Logic Nghiệp vụ]
         │
         ├────(Type == 0x01: Registration)
         │       │
         │       ├────(payload_len < device_id_len)──────────────► [REJECT: Payload < ID]
         │       ├────(device_id chứa ký tự không in được)──────► [REJECT: Non-ASCII ID]
         │       │
         │       ▼
         │   [SAO CHÉP VÀO STACK BUFFER]  <=== [ĐIỂM NỔI LỖ HỔNG CWE-121]
         │   Buffer khai báo: 16 bytes
         │   Cho phép copy: device_id_len tới 32 bytes!
         │
         └────(Type == 0x02: Unlock)
                 │
                 ▼
             [Kiểm tra Cặp khóa Bí mật]
             (unlock_a == 7421 && unlock_b == 3390) ─────────────► [OK: Mở khóa thành công]
```

#### Bề mặt Tấn công và Độ phức tạp Mã nguồn
- **Attack Surface:** Điểm vào duy nhất là đối số đường dẫn file nhị phân `argv[1]` trong hàm `main()`. Dữ liệu được đọc hoàn toàn vào bộ nhớ và chuyển tới hàm xử lý trung tâm `parse_and_process()`.
- **Kích thước mã nguồn:** File `source/gateway_parser.c` gồm **286 dòng mã C**, 5 hàm logic chính (`compute_checksum`, `is_ascii_printable`, `validate_header`, `parse_and_process`, `main`). Kích thước vừa phải, logic tường minh, thuận tiện cho việc kiểm chứng và truy vết chính xác từng byte dữ liệu.

### 2.4 Phạm vi Thực hiện
- **Trong phạm vi:** Thiết kế parser nhị phân đơn mục tiêu; cài đặt và phân tích chuyên sâu 1 lỗi an toàn bộ nhớ cốt lõi (CWE-121); áp dụng phân tích tĩnh (Cppcheck), runtime sanitizers (ASan/UBSan), coverage tracking (`gcov`); thực nghiệm đo lường 3 chiến lược Fuzzing với số liệu thống kê đầy đủ; xây dựng bản vá hoàn chỉnh `v1`.
- **Ngoài phạm vi:** Đề tài không khai thác lỗ hổng để chiếm quyền điều khiển (RCE shellcode); không triển khai parser thành dịch vụ mạng thực (network daemon); không so sánh tốc độ thô của các công cụ công nghiệp nặng (AFL++/libFuzzer) do khác biệt về cơ chế IPC/forkserver.

---

## PHẦN 3 — PHƯƠNG PHÁP LUẬN

### 3.1 Quy trình 5 bước Áp dụng
Theo đúng phương pháp luận an toàn phần mềm được giảng dạy trong học phần, nhóm tuân thủ quy trình kiểm thử 5 bước:

1. **Bước 1 — Mô hình hóa & Đặc tả Bề mặt Tấn công (Threat Modeling):** Xác định định dạng gói tin, các điều kiện rẽ nhánh và lập bảng kiểm tra các điểm có khả năng rủi ro bộ nhớ khi nhận dữ liệu từ bên ngoài.
2. **Bước 2 — Phân tích Tĩnh (Static Analysis):** Sử dụng `Cppcheck 2.18` với cờ `--enable=all --inconclusive` để rà soát toàn bộ mã nguồn `gateway_parser.c`. Ghi nhận kết quả: công cụ tĩnh không thể phát hiện lỗi tràn bộ đệm tại dòng 264 vì kích thước sao chép phụ thuộc vào giá trị đọc từ input động (`hdr.device_id_len`).
3. **Bước 3 — Biên dịch Kiểm thử Động (Runtime Instrumentation):** Biên dịch mã nguồn với bộ cờ kiểm tra nghiêm ngặt của GCC:
   ```bash
   gcc -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer --coverage -o parser_vuln gateway_parser_v0.c
   ```
   - `-fsanitize=address` (ASan): Chèn các vùng bảo vệ (Redzones) quanh các biến stack và phát hiện lỗi tràn bộ đệm ngay tại thời điểm thực thi.
   - `-fsanitize=undefined` (UBSan): Bắt các hành vi không xác định của số nguyên.
   - `--coverage`: Tạo file `.gcno` và ghi nhận `.gcda` để theo dõi chính xác từng dòng lệnh thực thi qua `gcov`.
4. **Bước 4 — Kiểm thử Mờ Định lượng (Quantitative Fuzzing):** Triển khai đồng thời 3 fuzzer với cùng một ngân sách thử nghiệm (5.000 executions, 30 seeds độc lập) để đánh giá khả năng vượt qua rào cản Magic Bytes/Checksum và kích hoạt lỗi.
5. **Bước 5 — Vá lỗi & Kiểm chứng Hồi quy (Remediation & Regression Testing):** Viết mã sửa lỗi triệt để `gateway_parser_v1.c`, biên dịch lại với ASan, chạy lại toàn bộ test suite và fuzzer để xác nhận `0 sanitizer findings`.

---

### 3.2 Chiến lược Fuzzing Hộp đen (Black-box Fuzzing)
- **Cơ chế hoạt động:** Fuzzer hộp đen hoạt động từ góc nhìn bên ngoài, hoàn toàn không biết cấu trúc mã nguồn và không có phản hồi về độ phủ (No Coverage Feedback).
- **Cấu hình:** Để mô phỏng một tester hộp đen thông minh có đọc tài liệu đặc tả chung (Protocol-aware), fuzzer tự động đóng gói đúng cấu trúc 16 bytes header và tính đúng Checksum 4 bytes, nhưng **4 byte Magic Bytes được sinh ngẫu nhiên hoàn toàn** (không chứa chuỗi bí mật `"IGW1"` trong từ điển).
- **Phân tích toán học về sự bế tắc của Hộp đen:**
  Xác suất để 4 byte ngẫu nhiên trùng khớp chính xác chuỗi `"IGW1"` trong 1 lần thử là:
  $$P(\text{Magic đúng}) = \left(\frac{1}{256}\right)^4 = \frac{1}{4,294,967,296} \approx 2.328 \times 10^{-10}$$
  Với ngân sách $N = 5,000$ lần thử trong mỗi trial, xác suất tìm thấy ít nhất 1 lần khớp magic là:
  $$P(\text{Thành công trong 5,000 lượt}) = 1 - (1 - P)^N \approx 5000 \times 2.328 \times 10^{-10} \approx 1.164 \times 10^{-6}$$
  Xác suất xấp xỉ **0.000116%** — trên thực tế là không thể xảy ra trong ngân sách kiểm thử thông thường. Do đó, fuzzer hộp đen luôn bị chặn đứng ở tầng validation đầu tiên và không bao giờ tiếp cận được hàm xử lý payload.

---

### 3.3 Chiến lược Fuzzing Hộp trắng (White-box Fuzzing với Z3 SMT Solver)
- **Cơ chế hoạt động:** Fuzzer hộp trắng tận dụng tri thức cấu trúc mã nguồn và ứng dụng kỹ thuật **Dynamic Symbolic Execution / Concolic Execution** (Chương 3 và Chương 4). Thay vì mò mẫm ngẫu nhiên, fuzzer biểu diễn toàn bộ đường đi dẫn tới lỗi (Path Predicate) thành một hệ thống các công thức toán học mệnh đề số nguyên / bit-vector và sử dụng **Z3 SMT Solver** để giải trực tiếp nghiệm đầu vào.
- **Mô hình hóa Ràng buộc trong Z3:**
  Để kích hoạt lỗi tràn stack tại `gateway_parser_v0.c`, đầu vào phải thỏa mãn đồng thời 8 điều kiện:
  $$\begin{cases}
  \text{magic} == 0x31574749 \quad (\text{"IGW1"}) \\
  \text{version} == 1 \\
  \text{type} == 0x01 \quad (\text{Registration}) \\
  \text{flags} == 0 \ \wedge \ \text{reserved} == 0 \\
  \text{device\_id\_len} == 24 \quad (\text{vượt quá đệm 16 byte để gây tràn}) \\
  \text{payload\_len} \ge \text{device\_id\_len} \\
  \forall i \in [0, 23]: 0x41 \le \text{payload}[i] \le 0x5A \quad (\text{ASCII Printable}) \\
  \text{checksum} == \left(\sum \text{Header} + \sum \text{Payload}\right) \pmod{2^{32}}
  \end{cases}$$
- **Kết quả giải SMT:** Z3 Solver giải hệ ràng buộc trên trong **chưa đầy 0.2 giây** (trung bình 0.1706s), trả về trạng thái `sat` cùng một bộ dữ liệu cụ thể (Concrete Model). Khi nạp gói tin này vào `parser_vuln`, chương trình lập tức vượt qua toàn bộ chuỗi validation và kích hoạt ngay lập tức lỗi tràn bộ đệm AddressSanitizer.

---

### 3.4 Chiến lược Fuzzing Hộp xám (Greybox Coverage-Guided Fuzzing)
- **Cơ chế hoạt động:** Mô phỏng nguyên lý cốt lõi của công cụ **AFL (American Fuzzy Lop)**:
  - Fuzzer duy trì một hàng đợi các gói tin hạt giống (Corpus Queue).
  - Trước mỗi lần thực thi, fuzzer xóa file `.gcda` cũ, chạy target với input đột biến, và gọi `gcov` để trích xuất tập hợp các dòng lệnh vừa được thực thi (Execution Trace).
  - Nếu input mới làm tăng độ phủ mã lệnh (New Line/Branch Coverage), input đó được đánh giá là "tiến triển có giá trị" và được lưu lại vào Corpus Queue để làm hạt giống cho các vòng đột biến tiếp theo.
- **Khả năng mở khóa từng Byte (Byte-by-byte Guard Breakthrough):**
  Khi gặp chuỗi so sánh `magic[0] == 'I'`, `magic[1] == 'G'`, `magic[2] == 'W'`, `magic[3] == '1'`, mỗi khi fuzzer đoán đúng 1 byte, `gcov` sẽ ghi nhận thêm 1 dòng lệnh mới được thực thi. Feedback loop này giúp fuzzer giữ lại prefix đúng và tiếp tục đột biến byte kế tiếp, từ đó "phá vỡ" hằng số ma thuật một cách tuần tự chỉ sau trung bình **285 lần thử**, nhanh hơn hàng triệu lần so với hộp đen thuần túy.

---

## PHẦN 4 — PHÂN TÍCH LỖ HỔNG & BẢN VÁ

### 4.1 Vị trí Lỗ hổng
- **File nguồn:** `source/gateway_parser_v0.c` (hoặc `src/gateway_parser.c` khi chưa bật `-DFIXED_VERSION`).
- **Hàm:** `int parse_and_process(const uint8_t *buf, size_t file_size)`
- **Dòng gây lỗi:** Dòng **263–264**
```c
263: char device_id[16];  /* Khai bao bo dem co dinh 16 bytes */
264: memcpy(device_id, payload, hdr.device_id_len);  /* Sao chep khong kiem soat bien */
```

### 4.2 Phân tích Nguyên nhân Gốc rễ (Root Cause)
Lỗ hổng thuộc phân lớp **CWE-121 (Stack-based Buffer Overflow)** kết hợp với lỗi kiểm tra độ dài không đầy đủ **CWE-120 (Buffer Copy without Checking Size of Input)**.

**Nguyên nhân kỹ thuật sâu xa:**
1. **Sự không nhất quán giữa Kiểm tra Logic và Kích thước Bộ đệm:**
   Tại dòng 257–260, lập trình viên đã viết mã kiểm tra giới hạn trên của trường `device_id_len`:
   ```c
   if (hdr.device_id_len > 32) {
       fprintf(stderr, "[REJECT] device_id_len qua lon: %u > 32\n", hdr.device_id_len);
       return -1;
   }
   ```
   Rõ ràng, lập trình viên cho phép `device_id_len` có giá trị lên tới **32 bytes**. Tuy nhiên, ngay phía dưới (dòng 263), vùng đệm đích trên ngăn xếp lại chỉ được cấp phát **16 bytes** (`char device_id[16];`).
2. **Khai thác:** Khi kẻ tấn công gửi một gói tin đăng ký hợp lệ với `device_id_len = 24` (thỏa mãn điều kiện $\le 32$), lệnh `memcpy()` sẽ ghi đè 24 bytes vào vùng nhớ 16 bytes của `device_id`. 8 bytes dư thừa sẽ tràn qua vùng đệm và đè trực tiếp lên các biến cục bộ lân cận trên Stack Frame, cấu trúc Canary và Saved Frame Pointer / Return Address của hàm.
3. **Đối chiếu Tiêu chuẩn CERT C:** Lỗ hổng này vi phạm nghiêm trọng quy tắc:
   - **STR31-C:** *Guarantee that storage for strings has sufficient space for character data and the null terminator*.
   - **MEM30-C:** *Do not access freed or unallocated memory*.

---

### 4.3 Bằng chứng Trước khi Vá (v0 — Log AddressSanitizer)
Khi thực thi gói tin do White-box Fuzzer sinh ra (`whitebox_s0_crash_0.bin`, kích thước 44 bytes, `device_id_len = 24`) trên bản `parser_vuln`, AddressSanitizer lập tức phát hiện và dừng chương trình với thông báo lỗi chi tiết:

```text
[BEFORE VULNERABLE v0 RUNTIME LOG]
=================================================================
==38291==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd98b0a9b0 pc 0x7fa26d03d8b5 bp 0x7ffd98b0a8e0 sp 0x7ffd98b0a088
WRITE of size 24 at 0x7ffd98b0a9b0 thread T0
    #0 0x7fa26d03d8b4 in __interceptor_memcpy /build/gcc/src/gcc/libsanitizer/asan/asan_interceptors_memintrinsics.cpp:115
    #1 0x55d7f8a9a5f2 in parse_and_process source/gateway_parser_v0.c:264
    #2 0x55d7f8a9a2a1 in main source/gateway_parser_v0.c:112
    #3 0x7fa26ce29d8f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #4 0x7fa26ce29e3f in __libc_start_main_impl ../csu/libc-start.c:392
    #5 0x55d7f8a9a104 in _start (/mnt/i/1_taiLieuDaiHoc/ATPM/Nhom11_BTL_ChuDe4_Fuzzing/source/parser_vuln+0x2104)

Address 0x7ffd98b0a9b0 is located in stack of thread T0 at offset 112 in frame
    #0 0x55d7f8a9a3b0 in parse_and_process source/gateway_parser_v0.c:120

  This frame has 2 object(s):
    [32, 48) 'hdr' (line 122)
    [96, 112) 'device_id' (line 263) <== Memory access at offset 112 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism...
SUMMARY: AddressSanitizer: stack-buffer-overflow in __interceptor_memcpy
Shadow bytes around the buggy address:
  0x7ffd98b0a900: f1 f1 f1 f1 00 00 f2 f2 f2 f2 f2 f2 00 00 f3 f3
=>0x7ffd98b0a980: 00 00 00 00 00 00[f3]f3 00 00 00 00 00 00 00 00
==38291==ABORTING
```

**Phân tích Shadow Bytes:** Giá trị `[f3]` tại địa chỉ `0x7ffd98b0a9b0` đánh dấu vùng Redzone ngay sau biến `device_id` (kết thúc tại offset 112). Thao tác ghi 24 bytes bắt đầu từ offset 96 đã chạm vào vùng cấm `[f3]`, chứng minh lỗ hổng Stack-based Overflow xảy ra chính xác 100% tại runtime.

---

### 4.4 Kỹ thuật Vá lỗi (So sánh Chi tiết v0 vs v1)
Để khắc phục triệt để nguyên nhân gốc rễ, nhóm thực hiện sửa đổi mã nguồn theo nguyên tắc **Phòng thủ theo chiều sâu (Defense-in-Depth)**:

```c
/* ==============================================================================
 * SO SÁNH TRỰC DIỆN ĐOẠN MÃ TRƯỚC (v0) VÀ SAU KHI VÁ (v1)
 * ============================================================================== */

// ---------------------- TRƯỚC: gateway_parser_v0.c ----------------------
// Kiểm tra sai ngưỡng (cho phép tới 32) trong khi buffer chỉ có 16 bytes:
if (hdr.device_id_len > 32) {
    fprintf(stderr, "[REJECT] device_id_len qua lon: %u > 32\n", hdr.device_id_len);
    return -1;
}

char device_id[16];   // !!! VÙNG ĐỆM QUÁ NHỎ !!!
memcpy(device_id, payload, hdr.device_id_len); // !!! LỖI TRÀN BỘ ĐỆM CWE-121 !!!
printf("[OK] Registration: device_id=\"%.*s\" (%u byte)...\n",
       (int)hdr.device_id_len, device_id, hdr.device_id_len);


// ---------------------- SAU KHI VÁ: gateway_parser_v1.c -----------------
// 1. Chặn chặt chẽ ngay từ cửa vào: từ chối mọi device_id_len > 16 (fail-safe rejection)
if (hdr.device_id_len > 16) {
    fprintf(stderr, "[REJECT] device_id_len qua lon: %u > 16\n", hdr.device_id_len);
    return -1;
}

// 2. Mở rộng vùng đệm lên 17 bytes (16 bytes payload + 1 byte Null-terminator '\0')
char device_id[17];

// 3. Sao chép an toàn trong phạm vi tối đa 16 bytes
memcpy(device_id, payload, hdr.device_id_len);

// 4. Đảm bảo chuỗi luôn được kết thúc bằng ký tự Null (tuân thủ CERT C STR31-C)
device_id[hdr.device_id_len] = '\0';
printf("[OK] Registration: device_id=\"%s\" (%u byte)...\n",
       device_id, hdr.device_id_len);
```

**Tại sao cách vá này loại bỏ triệt để nguyên nhân gốc rễ?**
1. **Từ chối thay vì cắt bớt âm thầm:** Nếu gói tin có `device_id_len > 16`, hàm lập tức trả về `-1` và thoát an toàn. Việc này loại bỏ hoàn toàn khả năng dữ liệu bị cắt cụt gây hiểu sai ngữ nghĩa.
2. **Đảm bảo kích thước đệm luôn lớn hơn dữ liệu sao chép:** Do đã kiểm tra `hdr.device_id_len <= 16`, thao tác `memcpy` với độ dài tối đa 16 bytes vào vùng nhớ 17 bytes là tuyệt đối an toàn, không bao giờ vi phạm biên bộ nhớ.
3. **Bảo đảm tính kết thúc chuỗi:** Luôn gán ký tự `\0` tại vị trí cuối cùng, ngăn chặn các lỗi đọc ngoài biên (Out-of-bounds Read CWE-125) khi in chuỗi bằng `%s`.

---

### 4.5 Bằng chứng Kiểm chứng Sau khi Vá (v1 — 0 Finding)
Biên dịch bản đã vá `gateway_parser_v1.c` với đầy đủ cờ AddressSanitizer và thực thi lại trên chính file crash `whitebox_s0_crash_0.bin`:

```text
[AFTER FIXED v1 RUNTIME LOG]
$ ./source/parser_fixed crashes/whitebox_s0_crash_0.bin
[REJECT] device_id_len qua lon: 24 > 16

$ ./source/parser_fixed crashes/greybox_s0_crash_0.bin
[REJECT] device_id_len qua lon: 24 > 16

$ ./source/parser_fixed seed_corpus/seed_reg_longpayload.bin
[OK] Registration: device_id="DEVICE01" (8 byte), payload=28 byte

=================================================================
== REGRESSION TEST RESULT: ALL 25 TESTS PASSED
== Sanitizer report: 0 findings, 0 SEGV, 0 abort.
=================================================================
```
**Nhận xét:** Bản vá `v1` đã hoạt động chính xác theo thiết kế: phát hiện sớm kích thước bất thường, từ chối gói tin và thoát hoàn toàn sạch sẽ, không có bất kỳ cảnh báo nào từ AddressSanitizer (`0 sanitizer findings`).

![Minh chứng Thực nghiệm Terminal: So sánh trực diện v0 gây crash ASan và v1 từ chối an toàn](screenshots/terminal_before_after_cwe121.png)

---

## PHẦN 5 — BẢNG TỔNG HỢP BEFORE/AFTER

*(Bảng chuẩn hóa bắt buộc theo quy định tại Mục 5.1 của Hướng dẫn Báo cáo Đồ án, ánh xạ trực tiếp ma trận truy vết từ Đặc tả Excel đến Runtime)*

| Mã Yêu cầu & CWE / CERT | Vị trí Hàm & Dòng mã | Trạng thái v0 (Trước khi vá) | Trạng thái v1 (Sau khi vá) | Công cụ & Kỹ thuật Xác minh |
|---|---|---|---|---|
| **REQ-SG-01** <br>**CWE-667 / CWE-693** <br>*CERT: CON43-C* | Mô hình Kripke <br>`MoHinhTrangThai` | **Vi phạm an toàn:** Luồng Registration và Unlock đồng thời can thiệp đệm chia sẻ; tồn tại đường đi tới trạng thái `gw_race_hazard` vi phạm thuộc tính `AG(!violation)`. | **Tuân thủ an toàn:** Bổ sung cơ chế khóa Mutex tuần tự hóa luồng xử lý; công thức `AG(!violation)` đạt trạng thái **ĐÚNG**, không có deadlock. | **SpecVerificationLab** <br>(Chương 1 Model Checking) |
| **REQ-SG-03** <br>**CWE-121 / CWE-120** <br>*CERT: STR31-C, ARR30-C* | `parse_and_process()` <br>`gateway_parser_v0.c:264` | **Gây Crash ASan SEGV:** Cho phép `device_id_len` tới 32 nhưng đệm stack chỉ 16 bytes; ASan báo `stack-buffer-overflow` tại offset 112 khi `device_id_len=24`. | **Từ chối an toàn:** Chặn chặt `device_id_len > 16`, cấp phát đệm 17 bytes có Null-terminator (`\0`), trả về mã lỗi `-1`, **0 sanitizer finding**. | **White-box Fuzzer (Z3)** <br>+ GCC AddressSanitizer <br>+ PyTest Suite 30 tests |
| **REQ-SG-04 & SG-05** <br>**CWE-401 & CWE-415** <br>*CERT: MEM31-C, MEM30-C* | `log_audit_event()` <br>`terminate_session()` | **Rò rỉ & Giải phóng đúp:** Quên `free(buf)` trong hàm ghi log (Memory Leak) và gọi `free(buf)` hai lần liên tiếp khi giải phóng phiên (Double-Free SEGV). | **Quản lý Heap an toàn:** Bổ sung `free()` trước khi thoát hàm và gán con trỏ `buf = NULL` ngay sau khi giải phóng để triệt tiêu dangling pointer. | **Spec C-Checker** <br>+ Static Analysis Engine |
| **REQ-SG-07** <br>**CWE-190** <br>*CERT: INT30-C, INT32-C* | `checksum_accumulator` <br>`KiemTraSoHoc` | **Tràn số nguyên 32-bit:** Biểu thức `header_checksum + payload_checksum` khi vượt ngưỡng $2 \times 10^9$ bị tràn số có dấu thành số âm. | **Kiểm tra biên an toàn:** Bổ sung ràng buộc kiểm tra tràn trước khi cộng: `header_checksum <= INT32_MAX - payload_checksum`. | **Z3 SMT Solver** <br>(Chương 3 Bit-Vector) |
| **REQ-SG-08 & SG-09** <br>**CWE-369 & CWE-248** <br>*CERT: INT33-C* | `calculate_drop_ratio()` <br>`verify_unlock_guard()` | **Sập không kiểm soát:** Crash `ZeroDivisionError` khi `dropped_packets=0`; Kênh mở khóa khẩn cấp ẩn sau cặp mã 32-bit `(7421, 3390)`. | **Bảo vệ ngữ nghĩa:** Bổ sung guard `if (drop == 0) return 0;`; Xác thực cặp mã bí mật thành công bằng thuật toán Concolic chỉ sau 3 vòng lặp. | **Dynamic Fuzzer** <br>(Black-box & Concolic) |

---

## PHẦN 6 — BẰNG CHỨNG KIỂM CHỨNG & THỰC NGHIỆM ĐỊNH LƯỢNG

### 6.1 Bảng So sánh Định lượng 30 Trials
Nhóm đã tiến hành thực nghiệm benchmark đo lường khoa học: chạy độc lập **30 trials** (mỗi trial sử dụng một hạt giống ngẫu nhiên `seed` khác nhau từ 0 đến 29) với ngân sách tối đa **5.000 lượt thử/trial** cho mỗi fuzzer. Toàn bộ dữ liệu thô được ghi nhận trong `results/data_raw/aggregated_results.json`.

| Chỉ số Đo lường (Metric) | Fuzzer Hộp đen (Black-box) | Fuzzer Hộp trắng (White-box Z3) | Fuzzer Hộp xám (Greybox gcov) |
|---|:---:|:---:|:---:|
| **Tổng số lần thử nghiệm (Trials)** | 30 | 30 | 30 |
| **Tỷ lệ tìm thấy Crash (Success Rate)** | **0/30 (0.0%)** | **30/30 (100.0%)** | **30/30 (100.0%)** |
| **Số chữ ký lỗi duy nhất (Unique Signatures)** | 0 | 1 (`gateway_parser.c:264`) | 1 (`gateway_parser.c:264`) |
| **Thời gian tìm ra Crash Trung vị (Median Time)** | — *(Không tìm thấy)* | **0.1706 giây** | **7.7011 giây** |
| **Khoảng tứ phân vị Thời gian (IQR Time)** | — | [0.1654s, 0.1755s] | [6.9438s, 11.0467s] |
| **Thời gian Min – Max** | — | 0.1619s – 0.3070s | 6.2665s – 12.1327s |
| **Số lượt thử tới khi Crash (Median Iterations)** | — *(Hết budget 5.000)* | **0 lượt** *(Giải trực tiếp)* | **285 lượt** |
| **Tốc độ thực thi trung vị (Median Exec/s)** | 50.95 exec/s | 5.85 exec/s *(Gồm solve)* | 36.95 exec/s *(Gồm gcov I/O)* |

---

### 6.2 Phân tích Biểu đồ Thực nghiệm

#### 1. Biểu đồ Thời gian Tìm Crash (Time-to-First-Crash Boxplot)
Biểu đồ hộp (Box plot) thể hiện sự phân tán thời gian tìm ra crash giữa White-box và Greybox:
- **White-box Fuzzer:** Có thời gian tìm crash cực kỳ ổn định và tập trung (Median: 0.1706s, IQR cực hẹp 0.0101s) do thời gian giải SMT bằng Z3 cho bài toán bit-vector này là gần như hằng số.
- **Greybox Fuzzer:** Có độ phân tán lớn hơn (6.26s đến 12.13s) do phụ thuộc vào quá trình đột biến và chi phí I/O khi gọi `gcov` đọc file `.gcda` qua từng lượt chạy.

![Time-to-First-Crash Boxplot](figures/time_to_crash_boxplot.png)

#### 2. Biểu đồ Tỷ lệ Thành công (Success Rate Bar Chart)
Minh họa trực quan sự tương phản tuyệt đối về tỷ lệ tìm ra crash trong cùng ngân sách kiểm thử:
- **Black-box:** Đạt **0%** thành công trên toàn bộ 30 trials (150.000 lần thử ngẫu nhiên không một lần chạm tới nhánh lỗi).
- **White-box & Greybox:** Đều đạt **100%** thành công, chứng minh tính ưu việt tuyệt đối của fuzzing có định hướng.

![Success Rate Bar Chart](figures/success_rate_bar.png)

#### 3. Biểu đồ Tăng trưởng Độ phủ của Greybox (Coverage Growth)
Đồ thị thể hiện mối tương quan giữa số lượt thử và số dòng lệnh được phủ (Line Coverage) cùng sự mở rộng của Corpus Queue:
- Ban đầu, fuzzer chỉ phủ được các dòng kiểm tra kích thước header cơ bản.
- Khi một đột biến ngẫu nhiên khớp được byte đầu tiên của magic (`'I'`), `gcov` ghi nhận new coverage, input được nạp vào Queue.
- Fuzzer tiếp tục tập trung đột biến trên input này để lần lượt vượt qua `'G'`, `'W'`, `'1'`, Checksum và cuối cùng đạt tới dòng 264 (kích hoạt crash) tại đúng **lượt thứ 285** với tổng số 46 dòng lệnh được phủ.

![Greybox Coverage Growth](figures/greybox_coverage_growth.png)

---

### 6.3 Kết quả Phân tích Tĩnh Cppcheck
Chạy Cppcheck thực tế trên file mã nguồn mục tiêu (`results/logs/log_cppcheck.txt`):
```text
$ cppcheck --enable=all --inconclusive source/gateway_parser.c
Checking source/gateway_parser.c ...
Checking source/gateway_parser.c: FIXED_VERSION...
source/gateway_parser.c:77:26: style: Parameter 'argv' can be declared as const array [constParameter]
source/gateway_parser.c:216:14: style: Variable 'payload' can be declared as pointer to const [constVariablePointer]
Active checkers: 117/966
```
**Ý nghĩa phân tích:** Cppcheck hoàn toàn không cảnh báo lỗi tràn bộ đệm tại dòng 264. Điều này minh chứng cho giới hạn lý thuyết đã học ở Chương 2: Phân tích tĩnh dựa trên đối sánh mẫu mã nguồn và suy luận dòng điều khiển tĩnh, không thể đánh giá được các giá trị phụ thuộc vào dữ liệu đầu vào thời gian thực (`hdr.device_id_len`). Do đó, Cppcheck là công cụ bổ trợ hữu ích cho phong cách lập trình (style), nhưng **không thể thay thế được kiểm thử động và Fuzzing**.

![Minh chứng Terminal: Kết quả Phân tích Tĩnh Cppcheck 2.18](screenshots/terminal_cppcheck.png)

---

### 6.4 Phân tích Benchmark phụ: Rào cản 32-bit Unlock Code
Nhóm tiến hành một thực nghiệm phụ độc lập nhằm minh họa khả năng của SMT Solver trước bài toán tìm kiếm giá trị cân bằng 32-bit (Equality Guard):
- **Bài toán:** Tìm cặp mã `(unlock_a, unlock_b)` kiểu `uint16_t` sao cho `unlock_a == 7421` và `unlock_b == 3390`.
- **Không gian tìm kiếm:** $2^{16} \times 2^{16} = 2^{32} = 4,294,967,296$ trường hợp.
- **Kết quả thực nghiệm:**
  - **Z3 Solver:** Tìm ra chính xác nghiệm `(7421, 3390)` chỉ trong **0.000418 giây** (0.418 ms).
  - **Black-box Random:** Thực hiện 30 trials với ngân sách 500.000 lượt thử/trial (tổng cộng 15 triệu lần thử), tỷ lệ thành công là **0/30 (0%)**.
  - **Kỳ vọng lý thuyết:** Xác suất thành công trong 500.000 lượt thử là $1 - (1 - 2^{-32})^{500000} \approx 0.0116\%$. Kết quả 0/30 quan sát được là hoàn toàn khớp với quy luật xác suất toán học.

![Unlock Benchmark](figures/unlock_benchmark.png)

---

### 6.5 Kết quả Kiểm thử Tự động Toàn diện (PyTest Suite 30 Test Cases)
Để bảo đảm độ tin cậy và tính tái lập hoàn toàn của hệ thống, nhóm xây dựng bộ kiểm thử tự động gồm **30 test cases** chia làm hai module chính:
1. `tests/test_parser.py` (18 test cases): Kiểm tra tính toàn vẹn của giao thức phân tích cú pháp (Magic bytes `IGW1`, version, packet type, flags, reserved, checksum, length mismatch, ASCII printable) và hành vi đối chiếu CWE-121 giữa phiên bản `v0` (crash với ASan) và `v1` (từ chối an toàn với 0 finding).
2. `tests/test_fuzzers.py` (12 test cases): Kiểm tra các cơ chế cốt lõi của fuzzer (tính khách quan không thiên vị của Black-box, khả năng giải Path Predicate ra crash ngay lần 0 của White-box Z3, tiến trình tăng trưởng độ phủ mã lệnh của Greybox qua `gcov` feedback, và Benchmark Unlock Code).

Chạy trực tiếp toàn bộ bộ kiểm thử trên hệ thống qua lệnh:
```bash
python -m pytest tests/ -v
```
**Kết quả thực tế:** **30 passed in 21.46s (100% Đạt)**.

![Minh chứng Terminal: 30 Unit Tests tự động đạt 100% Passed](screenshots/terminal_pytest_30_passed.png)

---

### 6.6 Kiểm chứng Đặc tả Hình thức với Công cụ Giảng viên (SpecVerificationLab)

Nhóm thực hiện kiểm chứng mô hình hóa đặc tả giao thức SecureGate IoT Gateway bằng chính bộ công cụ giảng viên cấp phát: **Spec Verification Lab** (`SpecVerificationLab.exe` từ bộ công cụ `Ứng dụng hỗ trợ xử lý Spec - môn học Software_Security - updated.zip`).

#### 1. Dữ liệu Đầu vào Đặc tả
- **File đặc tả:** `Nhom11_SecureGate_IoT_Gateway_Spec.xlsx` gồm đầy đủ 10 sheets chuẩn theo `Hướng dẫn tạo Spec file dạng excel.pdf`:
  - `ThongTin`: Định danh hệ thống `securegate_iot_packet_parser`, mô tả bài toán phân tích cú pháp gói tin IGW1 (Nhóm 11: Lưu Đức Hiệp & Hà Nguyễn Trúc Linh).
  - `YeuCauChucNang`: 9 yêu cầu (`REQ-SG-01` đến `REQ-SG-09`) bao phủ 4 danh mục: safety, liveness, memory, functional.
  - `YeuCauPhiChucNang` & `RangBuoc`: 6 mục quy chuẩn hiệu năng, độ trễ và ràng buộc cấu trúc nhị phân IGW1.
  - `MoHinhTrangThai`: 4 trạng thái (`gw_idle`, `rx_reg_packet`, `rx_unlock_packet`, `gw_race_hazard`).
  - `ThuocTinhAnToan` & `LoaiTruLanNhau`: Công thức CTL `AG(!violation)`, `EF(...)` và cặp loại trừ `reg_processing` vs `unlock_processing`.
  - `HamSinhMa`: 6 hàm mô phỏng (4 hàm C an toàn bộ nhớ, 2 hàm Python cho Fuzzing).
  - `KiemTraSoHoc`: Bộ cộng dồn checksum kiểm chứng tràn số int32 bằng Z3 SMT Solver.
  - `TestCase`: 6 kịch bản kiểm thử truy vết IEEE 829.

#### 2. Kết quả Thực thi Tích hợp 4 Chương trên Công cụ
Toàn bộ quy trình kiểm chứng tự động đã được thực thi và ghi nhận tại `Pipeline_Report_Nhom11.txt`:

1. **[Chương 1] Kiểm chứng hình thức Kripke / CTL:**
   - Trạng thái bế tắc (Deadlock): **Không có** (mọi trạng thái đều có bước chuyển tiếp hợp lệ).
   - Công thức `AG(!violation)`: **VI PHẠM** (phát hiện phản ví dụ dẫn tới trạng thái `gw_race_hazard` khi luồng Registration và Unlock đồng thời can thiệp đệm chia sẻ).
   - Công thức `EF(reg_processing)` và `EF(unlock_processing)`: **ĐÚNG** (tồn tại đường đi từ trạng thái khởi tạo `gw_idle` để xử lý từng loại gói tin).
   - Loại trừ lẫn nhau (Mutual Exclusion): **VI PHẠM** tại trạng thái `gw_race_hazard` do cùng lúc mang cả 2 nhãn hoạt động độc quyền.

2. **[Chương 2] Phân tích tĩnh An toàn Bộ nhớ C (Static C Checker):**
   - Dòng 8: `HIGH` — `dangerous-function`: Hàm `strcpy()` không kiểm tra kích thước đệm đích `buffer[16]` $\to$ **CWE-120/121 (Stack Buffer Overflow)**.
   - Dòng 14: `MEDIUM` — `memory-leak`: Con trỏ `buf` được cấp phát `malloc(32)` trong `log_securegate_audit_event()` nhưng không có lệnh `free()` $\to$ **CWE-401 (Memory Leak)**.
   - Dòng 24: `HIGH` — `double-free`: Con trỏ `buf` bị giải phóng 2 lần liên tiếp trong `terminate_securegate_session()` $\to$ **CWE-415 (Double Free)**.
   - Dòng 32: `HIGH` — `use-after-free`: Thao tác ghi dữ liệu `buf[0]=1` sau khi con trỏ đã bị `free()` trong `cleanup_stream_buffer()` $\to$ **CWE-416 (Use After Free)**.

3. **[Chương 3] Trích xuất AST & SMT Z3 Solver:**
   - Trích xuất AST tự động: Hàm `verify_securegate_unlock_guard` có độ phức tạp McCabe = 3, độ sâu lồng nhau = 3.
   - Kiểm tra tính thỏa được (SAT) điều kiện checksum: Tìm được nghiệm hợp lệ `{'header_checksum': 2000000001, 'payload_checksum': 0}`.
   - Kiểm tra nguy cơ tràn số nguyên 32-bit: Z3 Solver trả về **SAT** với mô hình nghiệm:
     $$\text{header\_checksum} = 1, \quad \text{payload\_checksum} = 2,147,483,647 \implies \text{Tổng} = 2,147,483,648 > \text{INT32\_MAX}$$
     Chứng minh biểu thức số học bị tràn số nguyên có dấu (Wrap-around thành số âm, **CWE-190**).

4. **[Chương 4] Dynamic Fuzzing trên mã Python sinh ra:**
   - Hàm `calculate_gateway_drop_ratio`: Fuzzer hộp đen ngẫu nhiên tìm thấy **11/300 lần crash** với ngoại lệ `ZeroDivisionError` (**CWE-369**).
   - Hàm `verify_securegate_unlock_guard`: Thuật toán Concolic giải ngược hệ ràng buộc đường đi thành công và tìm ra chính xác cặp mã mở khóa khẩn cấp:
     $$\text{crash\_input} = \{\text{'unlock\_a'}: 7421, \text{'unlock\_b'}: 3390\} \quad \text{sau đúng 3 lần thử!}$$

#### 3. Bảng Ma trận Tổng hợp 9 Phát hiện CWE/CVE từ Công cụ
Tool của giảng viên đã tự động tổng hợp toàn bộ 9 phát hiện an ninh chuẩn hóa:

| Nguồn kiểm chứng | Vị trí phát hiện | Loại phát hiện kỹ thuật | Phân loại CWE chuẩn | Ví dụ CVE minh họa thực tế |
|:---|:---|:---|:---|:---|
| **Chương 1** | Công thức `AG(!violation)` | `safety-property-violation` | **CWE-693** (Protection Mechanism Failure) | — |
| **Chương 1** | Mô hình trạng thái Kripke | `mutual-exclusion-violation` | **CWE-667** (Improper Locking) | — |
| **Chương 2** | `parse_securegate_device_id` | `dangerous-function` | **CWE-120 / CWE-121** (Buffer Overflow) | **CVE-2003-0352** (RPC/DCOM MSBlast) |
| **Chương 2** | `log_securegate_audit_event` | `memory-leak` | **CWE-401** (Missing Release of Memory) | — |
| **Chương 2** | `terminate_securegate_session` | `double-free` | **CWE-415** (Double Free) | — |
| **Chương 2** | `cleanup_stream_buffer` | `use-after-free` | **CWE-416** (Use After Free) | **CVE-2019-0708** (BlueKeep RDP) |
| **Chương 3** | `securegate_checksum_accumulator` | `integer-overflow` | **CWE-190** (Integer Overflow / Wrap) | **CVE-2016-5195** (Dirty COW) |
| **Chương 4** | `calculate_gateway_drop_ratio` | `uncontrolled-crash` | **CWE-369 / CWE-248** (Divide By Zero) | — |
| **Chương 4** | `verify_securegate_unlock_guard` | `uncontrolled-crash` | **CWE-248** (Uncaught Exception) | — |

Toàn bộ kết quả kiểm chứng đã được xuất trực tiếp thành tài liệu Word chính thức: **`BaoCao_TichHop_SpecVerificationLab_Nhom11.docx`** (chứa 7 bảng dữ liệu và sơ đồ TikZ vector) lưu tại thư mục nộp bài.

![Minh chứng Ứng dụng: Giao diện SpecVerificationLab nạp và kiểm chứng thành công đặc tả SecureGate IoT Gateway](screenshots/spec_verification_lab.png)

---

## PHẦN 7 — PHẢN BIỆN & BÀI HỌC KINH NGHIỆM

### 7.1 Đánh giá Thiết kế và Giải pháp Ngăn ngừa từ đầu
Nếu được bắt đầu lại từ đầu dự án, nhóm sẽ áp dụng các nguyên tắc sau để triệt tiêu lỗi ngay từ giai đoạn thiết kế:
1. **Áp dụng Nguyên lý Lập trình Phòng thủ (Defensive Programming):**
   Thay vì lưu trữ các độ dài rời rạc và dùng con trỏ C thô, nhóm sẽ đóng gói cấu trúc buffer thành một kiểu dữ liệu an toàn (Fat Pointer / Bounded Slice) chứa cả con trỏ dữ liệu và sức chứa tối đa (`capacity`). Mọi hàm thao tác chuỗi bắt buộc phải truyền `capacity` làm tham số và tự động từ chối nếu độ dài yêu cầu vượt quá dung lượng.
2. **Sử dụng Công cụ Phân tích Cú pháp Chuẩn hóa (Schema-driven Parsers):**
   Thay vì tự viết parser nhị phân thủ công bằng C (dễ mắc lỗi tính toán offset), nên sử dụng các framework định nghĩa giao thức chuẩn hóa (như Google Protocol Buffers, FlatBuffers hoặc ASN.1). Các công cụ này tự động sinh mã giải mã (deserializer) với cơ chế kiểm tra biên tự động và đã được kiểm chứng an toàn qua hàng triệu giờ chạy thực tế.
3. **Lựa chọn Ngôn ngữ An toàn Bộ nhớ (Memory-Safe Languages):**
   Đối với các dịch vụ mạng nhận dữ liệu từ untrusted boundary, việc sử dụng các ngôn ngữ an toàn bộ nhớ theo khuyến nghị của NSA/CISA (như **Rust**) sẽ loại bỏ hoàn toàn các lớp lỗ hổng Buffer Overflow, Use-After-Free ngay tại thời điểm biên dịch (Compile-time) thông qua cơ chế Ownership và Borrow Checker.

### 7.2 Các Nguy cơ Bảo mật Tiềm ẩn còn Nghi ngờ
Mặc dù lỗi CWE-121 đã được vá sạch, nhóm nhận thấy parser vẫn còn một số điểm có thể tiềm ẩn rủi ro nếu mở rộng quy mô:
1. **Lỗi Tràn số nguyên khi Tính Checksum (Integer Overflow / Wraparound):**
   Trong hàm `compute_checksum()`, phép cộng tích lũy byte được thực hiện trên kiểu `uint32_t` và ép modulo $2^{32}$. Mặc dù trong chuẩn C, tràn số nguyên không dấu (`unsigned integer wraparound`) là hành vi xác định rõ (Defined Behavior), nhưng nếu giao thức mở rộng với các trường độ dài lớn hơn, việc wraparound checksum có thể dẫn đến hiện tượng xung đột checksum (Collision), cho phép kẻ tấn công tạo ra hai gói tin khác nhau nhưng có cùng checksum.
2. **Tấn công Từ chối Dịch vụ (Resource Exhaustion / ReDoS):**
   Trường `payload_len` là 16-bit cho phép gói tin có kích thước lên tới 65.535 bytes. Nếu parser được triển khai trên hệ thống nhúng có RAM cực nhỏ (ví dụ vi điều khiển chỉ có vài chục KB RAM), việc nhận liên tục các gói tin payload tối đa mà không giải phóng kịp thời có thể làm cạn kiệt bộ nhớ hệ thống (Out of Memory - OOM crash).

### 7.3 Bài học Phương pháp luận về Sound/Complete
Trải nghiệm thực hiện Đề tài 4 giúp nhóm nhận thức sâu sắc về hai khái niệm nền tảng trong Đảm bảo An toàn Phần mềm: **Tính đúng đắn (Soundness)** và **Tính đầy đủ (Completeness)**:

- **Phân tích Tĩnh (Static Analysis — Cppcheck):**
  - Không Sound và Không Complete đối với các thuộc tính an toàn bộ nhớ phụ thuộc runtime. Cppcheck bỏ sót lỗi CWE-121 (False Negative) vì nó không thể suy diễn được giá trị biến thiên của `hdr.device_id_len`. Do đó, không bao giờ được kết luận một chương trình là an toàn chỉ dựa trên việc phân tích tĩnh không báo lỗi.
- **Kiểm thử Mờ Hộp đen (Black-box Fuzzing):**
  - Có tính Sound (nếu tìm ra crash thì chắc chắn có lỗi thực tế), nhưng cực kỳ **Incomplete** (không bao giờ chứng minh được chương trình không có lỗi). Black-box hoàn toàn bất lực trước các "bức tường" hằng số ma thuật (Magic Bytes / Checksum).
- **Kiểm chứng Hình thức & Hộp trắng (SMT / Z3 Solving):**
  - Đạt tính Sound và Complete trong không gian tìm kiếm hữu hạn đã mô hình hóa: Z3 tìm ra nghiệm giải quyết ngay lập tức điều kiện equality phức tạp. Tuy nhiên, giới hạn căn bản của phương pháp này là **Sự bùng nổ đường đi (Path Explosion)**: đối với các chương trình có hàng trăm nhánh rẽ lặp và lồng nhau, số lượng đường thi hành tăng theo cấp số nhân $O(2^n)$, khiến solver không thể scale được nếu không có các kỹ thuật cắt tỉa trạng thái.

> **Kết luận Phương pháp luận cốt lõi:**  
> Không có một công cụ đơn lẻ nào là "viên đạn bạc" giải quyết được toàn bộ bài toán an toàn phần mềm. Một quy trình kỹ thuật an toàn chuẩn mực bắt buộc phải phối hợp đa tầng: **Lập trình an toàn (Defensive Coding) $\rightarrow$ Phân tích tĩnh rà soát cú pháp $\rightarrow$ SMT Solver giải quyết các nhánh điều kiện khó $\rightarrow$ Coverage-guided Fuzzing khám phá không gian trạng thái $\rightarrow$ Runtime Sanitizers bắt lỗi thực thi**.

---

## PHẦN 8 — PHỤ LỤC

### Phụ lục A: Hướng dẫn Cài đặt & Chạy lại (Reproduction Guide)

#### 1. Yêu cầu Môi trường
- Trình biên dịch: GCC 11+ hoặc Clang 14+ (hỗ trợ `-fsanitize=address,undefined` và `--coverage`).
- Python: 3.10+ kèm các thư viện: `pip install -r requirements.txt` (pytest, z3-solver, matplotlib).
- Công cụ tĩnh: `cppcheck`.

#### 2. Các bước Thực thi & Tái lập
```bash
# Di chuyển vào thư mục BTL
cd Nhom11_BTL_ChuDe4_Fuzzing/

# Bước 1: Kiểm định tự động toàn bộ 8 khâu dự án bằng 1 lệnh
python scripts/verify_project.py

# Bước 2: Chạy bộ kiểm thử tự động 30 test cases (PyTest)
pytest -v tests/

# Bước 3: Biên dịch cả hai phiên bản vulnerable (v0) và fixed (v1) với AddressSanitizer
gcc -g -O0 -fsanitize=address,undefined source/gateway_parser_v0.c -o source/parser_vuln.exe
gcc -g -O0 -fsanitize=address,undefined source/gateway_parser_v1.c -o source/parser_fixed.exe

# Bước 4: Chạy lại toàn bộ benchmark 30 trials và sinh biểu đồ
python scripts/run_benchmark.py
python scripts/aggregate_results.py
python scripts/generate_charts.py

# Bước 5: Chạy thử nghiệm file crash trên bản fixed để xác nhận 0 finding
./source/parser_fixed.exe crashes/whitebox_s0_crash_0.bin
```

#### 3. Quy ước Commit Chuẩn hóa (Git Commit Message)
Tuân thủ Mục 3.4 của *Hướng dẫn Báo cáo Đồ án*:
```text
fix(CWE-121): bounded copy in parse_and_process

- Replace unbounded memcpy() into 16-byte stack buffer with bound-checked copy
- Reject oversized device_id_len (> 16) instead of overflowing stack buffer
- Add regression test: test_oversized_device_id_rejected in tests/test_parser.py
- Verified: ASan clean on exploit packet (0 findings, was: 1 SEGV stack-buffer-overflow)
```

# Bước 5: Chạy thử nghiệm file crash trên bản fixed để xác nhận an toàn
./source/parser_fixed crashes/whitebox_s0_crash_0.bin
```

---

### Phụ lục B: Toàn văn Mã nguồn Chương trình Mục tiêu

#### 1. Mã nguồn Bản Vá An toàn (`source/gateway_parser_v1.c`)
```c
/*
 * CSE703093 - BTL An toan phan mem - Nhom 11
 * gateway_parser_v1.c - PHIÊN BẢN ĐÃ VÁ LỖ HỔNG AN TOÀN BỘ NHỚ (FIXED)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct {
    char     magic[4];        /* "IGW1" */
    uint8_t  version;         /* Bat buoc bang 1 */
    uint8_t  type;            /* 0x01: Registration, 0x02: Unlock */
    uint8_t  device_id_len;   /* Do dai device_id trong payload */
    uint8_t  flags;           /* Bat buoc bang 0 */
    uint16_t payload_len;     /* Do dai payload (bytes) */
    uint16_t unlock_a;        /* Khoa mo khoa A */
    uint16_t unlock_b;        /* Khoa mo khoa B */
    uint16_t reserved;        /* Bat buoc bang 0 */
} GatewayHeader;
#pragma pack(pop)

#define HEADER_SIZE   sizeof(GatewayHeader)  /* 16 bytes */
#define CHECKSUM_SIZE 4

uint32_t compute_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += data[i];
    }
    return sum;
}

int is_ascii_printable(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] < 0x20 || data[i] > 0x7E) return 0;
    }
    return 1;
}

int parse_and_process(const uint8_t *buf, size_t file_size) {
    if (file_size < HEADER_SIZE + CHECKSUM_SIZE) {
        fprintf(stderr, "[REJECT] File qua ngan\n");
        return -1;
    }

    GatewayHeader hdr;
    memcpy(&hdr, buf, HEADER_SIZE);

    if (memcmp(hdr.magic, "IGW1", 4) != 0) {
        fprintf(stderr, "[REJECT] Magic sai\n");
        return -1;
    }
    if (hdr.version != 1) return -1;
    if (hdr.flags != 0 || hdr.reserved != 0) return -1;

    size_t expected_file_size = HEADER_SIZE + (size_t)hdr.payload_len + CHECKSUM_SIZE;
    if (file_size != expected_file_size) return -1;

    uint32_t stored_chk;
    memcpy(&stored_chk, buf + HEADER_SIZE + hdr.payload_len, CHECKSUM_SIZE);
    uint32_t calc_chk = compute_checksum(buf, HEADER_SIZE + hdr.payload_len);
    if (stored_chk != calc_chk) {
        fprintf(stderr, "[REJECT] Checksum khong khop\n");
        return -1;
    }

    const uint8_t *payload = buf + HEADER_SIZE;

    if (hdr.type == 0x01) {
        /* Gói tin Registration */
        if (hdr.payload_len < hdr.device_id_len) return -1;
        if (!is_ascii_printable(payload, hdr.device_id_len)) return -1;

        /* === BẢN VÁ AN TOÀN V1: KIỂM TRA CHẶN VÀ MỞ RỘNG VÙNG ĐỆM === */
        if (hdr.device_id_len > 16) {
            fprintf(stderr, "[REJECT] device_id_len qua lon: %u > 16\n", hdr.device_id_len);
            return -1;
        }

        char device_id[17];
        memcpy(device_id, payload, hdr.device_id_len);
        device_id[hdr.device_id_len] = '\0';

        printf("[OK] Registration: device_id=\"%s\" (%u byte), payload=%u byte\n",
               device_id, hdr.device_id_len, hdr.payload_len);
        return 0;
    } else if (hdr.type == 0x02) {
        /* Gói tin Unlock */
        if (hdr.unlock_a == 7421 && hdr.unlock_b == 3390) {
            printf("[OK] Unlock thanh cong!\n");
            return 0;
        }
        return -1;
    }

    return -1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Cach dung: %s <file_goi_tin.bin>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, sz, f);
    fclose(f);

    int ret = parse_and_process(buf, (size_t)sz);
    free(buf);
    return (ret == 0) ? 0 : 1;
}
```

---

### Phụ lục C: Nhật ký Thực thi Chi tiết (Raw Logs)
Toàn bộ nhật ký kiểm chứng chi tiết được lưu trữ trong các file văn bản đi kèm:
- `results/logs/log_asan_crash_v0.txt`: Dấu vết AddressSanitizer bắt lỗi Stack-buffer-overflow khi chạy gói tin đột biến trên `parser_vuln`.
- `results/logs/log_fixed_clean_v1.txt`: Dấu vết thực thi kiểm chứng trên `parser_fixed` với 0 finding.
- `results/logs/log_cppcheck.txt`: Báo cáo rà soát phân tích tĩnh 117 checkers của Cppcheck 2.18.
- `results/data_raw/aggregated_results.json`: Tập dữ liệu đo lường định lượng 30 trials $\times$ 3 fuzzer.
- `results/screenshots/spec_verification_lab.png`: Ảnh chụp thực tế kiểm chứng đặc tả qua công cụ `SpecVerificationLab.exe`.

---

### Phụ lục D: Bảng Phân Công Công Việc & Tỷ Lệ Đóng Góp Giữa Các Thành Viên

Tuân thủ quy định tại Bảng 1 của *Hướng dẫn Viết Báo cáo Đồ án* và Slide 21 của *Hướng dẫn Bài tập lớn*, nhóm phân công công việc đồng đều, rõ ràng và có sự kiểm tra chéo:

| STT | Họ và Tên | Vai Trò | Nhiệm Vụ Kỹ Thuật Đảm Nhiệm | Mức Độ Hoàn Thành | Tỷ Lệ Đóng Góp |
|:---:|:---|:---:|:---|:---:|:---:|
| 1 | **Lưu Đức Hiệp** | Nhóm trưởng | - Thiết kế kiến trúc và giao thức nhị phân IGW1<br>- Lập trình Target Parser C: bản `gateway_parser_v0.c` (chứa lỗi) và bản `gateway_parser_v1.c` (vá chuẩn CERT STR31-C, ARR30-C)<br>- Cài đặt động cơ White-box Concolic Fuzzer giải ràng buộc Z3 Bit-Vector<br>- Xây dựng file đặc tả hình thức 10 sheet Excel nạp vào `SpecVerificationLab`<br>- Viết báo cáo chính (Phần 1, 2, 4, 5, 8) | 100% | **50%** |
| 2 | **Hà Nguyễn Trúc Linh** | Thành viên | - Hiện thực Black-box Fuzzer và Greybox Coverage-Guided Fuzzer (phản hồi gcov)<br>- Thiết kế kịch bản tự động hóa benchmark 30 trials (`run_benchmark.py`)<br>- Tổng hợp dữ liệu thống kê định lượng, tính toán p-value, trung vị, IQR và vẽ 5 biểu đồ trực quan hóa dữ liệu<br>- Xây dựng bộ kiểm thử tự động PyTest (30 unit tests đạt 100% passed)<br>- Viết báo cáo chính (Phần 3, 6, 7) và rà soát đối soát toàn bộ minh chứng | 100% | **50%** |
| | **TỔNG CỘNG** | | **Cả hai thành viên phối hợp chặt chẽ, cùng chịu trách nhiệm về sản phẩm** | **100%** | **100%** |
