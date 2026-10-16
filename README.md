# FZP1 Binary Parser — Fuzzing Benchmark & Memory Safety Audit
## Đồ án Môn học: An toàn Phần mềm (CSE703093 / CSE703153) — Chủ đề 4: Dự án Fuzzing
**Trường Đại học Phenikaa — Khoa Công nghệ Thông tin**  
**Giảng viên hướng dẫn:** ThS. Vũ Quang Dũng  

---

### 1. Thông tin Nhóm 11
**Kho lưu trữ GitHub chính thức:** [https://github.com/bachiep/ATPM-Nhom11-ChuDe4-Fuzzing](https://github.com/bachiep/ATPM-Nhom11-ChuDe4-Fuzzing)

| STT | Họ và Tên | Mã Sinh Viên | Khóa | Vai Trò | Tỷ lệ Đóng góp | GitHub Account |
|:---:|:---|:---:|:---:|:---:|:---:|:---:|
| 1 | **Lưu Đức Hiệp** | *[Bảo mật]* | *[Bảo mật]* | Trưởng nhóm | 50% | [@bachiep](https://github.com/bachiep) |
| 2 | **Hà Nguyễn Trúc Linh** | *[Bảo mật]* | *[Bảo mật]* | Thành viên | 50% | [@tomchienxuu](https://github.com/tomchienxuu) |

---

### 2. Tệp Đặc tả Excel 10 Sheet (Single Source of Truth — SSOT)

* **Vị trí tệp trong dự án:** [`specification/Nhom11_FZP1_Fuzzing_Spec.xlsx`](file:///I:/1_taiLieuDaiHoc/ATPM/Nhom11_BTL_ChuDe4_Fuzzing/specification/Nhom11_FZP1_Fuzzing_Spec.xlsx)
* **Nguồn gốc & Bản quyền Đặc tả (Câu hỏi thường gặp của Giảng viên):**
  * **Về cấu trúc khung (Schema/Format 10 sheet):** Kế thừa 100% định dạng, font chữ, độ rộng cột từ template chuẩn của Thầy (`Template_Software_Security_iot_gateway_spec.xlsx`) để đảm bảo nạp và tương thích hoàn toàn với bộ công cụ kiểm chứng của bộ môn (`SpecVerificationLab.exe` và `SecLabFramework.exe` Tab Ch6).
  * **Về nội dung học thuật & dữ liệu đặc tả:** **100% do Nhóm 11 tự xây dựng độc lập** cho giao thức nhị phân **FZP1** (`4B Magic "FZP1"` + `4B Length uint32 LE` + `Payload` + `1B XOR Checksum`), hoàn toàn không sao chép nội dung bài toán mẫu IoT Gateway hay Smart Meter của Thầy.

---

### 3. Cẩm nang Báo cáo Tiến độ (4 Trụ cột Cốt lõi)

Khi trao đổi hoặc bảo vệ tiến độ với Giảng viên, bạn cần nắm chắc 4 nội dung cốt lõi sau:

#### Trụ cột 1: Mô hình Hình thức Kripke & Kiểm chứng CTL
* **4 Trạng thái Kripke:**
  1. `st_idle`: Trạng thái chờ khởi tạo (`safe, session_closed`).
  2. `st_magic_ok`: Đã xác thực đúng 4 byte Magic `"FZP1"` (`magic_ok, header_valid`).
  3. `st_checksum_ok`: Đã xác thực đúng Checksum 1B (`checksum_ok, session_active`).
  4. `st_conflict`: Trạng thái xung đột nguy cơ tràn bộ đệm (`magic_ok, checksum_ok, violation`).
* **Kết quả Kiểm chứng CTL (Computation Tree Logic):**
  * **Hệ thống Deadlock-free:** Mọi trạng thái đều có bước chuyển hợp lệ đi ra (không bị bế tắc chu trình).
  * $AG(\neg \text{violation})$: **VI PHẠM (False)** — Thuật toán Model Checking phát hiện tồn tại đường đi từ `st_idle -> st_magic_ok -> st_conflict` kích hoạt trạng thái nguy hiểm. Đây chính là giá trị của kiểm chứng hình thức: phát hiện sớm rủi ro an toàn bộ nhớ.
  * $EF(\text{violation})$: **ĐÚNG (True)** — Khẳng định trạng thái nguy hiểm là khả dĩ đạt tới khi dữ liệu đầu vào thỏa mãn đồng thời cả Magic và Checksum.
  * **Sheet `LoaiTruLanNhau`:** Khai báo đủ 5 cặp tài liệu hóa. Cặp khóa chính `('magic_ok', 'checksum_ok')` tại dòng đầu được công cụ của Thầy tự động phát hiện xung đột tại `st_conflict`.

#### Trụ cột 2: 3 Lỗ hổng Bộ nhớ Thực tế và Bản vá Chuẩn CERT C
Nhóm cài đặt trực tiếp và đối soát trong mã nguồn C giữa bản lỗi `v0` ([`fzp1_parser_v0.c`](file:///I:/1_taiLieuDaiHoc/ATPM/Nhom11_BTL_ChuDe4_Fuzzing/source/fzp1_parser_v0.c)) và bản vá an toàn `v1` ([`fzp1_parser_v1.c`](file:///I:/1_taiLieuDaiHoc/ATPM/Nhom11_BTL_ChuDe4_Fuzzing/source/fzp1_parser_v1.c)):

| Mã Lỗ hổng | Cơ chế Phát sinh tại Bản lỗi $v_0$ | Chuẩn CERT C Áp dụng | Cơ chế Khắc phục tại Bản vá $v_1$ |
|:---|:---|:---:|:---|
| **CWE-121** (Stack Buffer Overflow) | `memcpy` payload tùy ý vào `stack_buf[16]` trên Stack Frame mà không kiểm tra độ dài. | **CERT STR31-C** | Chặn trên nghiêm ngặt `payload_len <= 16`, khai báo mảng 17B luôn có ký tự kết thúc `\0`. |
| **CWE-415** (Double Free) | Lệnh hủy phiên khẩn cấp `0xFF` (`CMD_ABORT_SESSION`) giải phóng con trỏ `g_session` 2 lần mà không gán `NULL`. | **CERT MEM30-C, MEM31-C** | Gán ngay lập tức `con trỏ = NULL` sau khi giải phóng, biến thao tác dọn dẹp thành idempotent an toàn. |
| **CWE-416** (Use-After-Free) | Lệnh reset kênh `0xFE` (`CMD_RESET_STREAM`) giải phóng `g_session` trước, sau đó lại gọi `stream_callback` qua con trỏ lơ lửng. | **CERT MEM30-C** | Gọi hàm callback trước khi giải phóng bộ nhớ, sau đó giải phóng và gán ngay `g_session = NULL`. |

#### Trụ cột 3: Đo lường Đối sánh 3 Trường phái Fuzzing (Benchmark 30 Trials)
Nhóm thực hiện 30 lượt thử nghiệm thực tế độc lập ([`run_fzp1_benchmark.py`](file:///I:/1_taiLieuDaiHoc/ATPM/Nhom11_BTL_ChuDe4_Fuzzing/scripts/run_fzp1_benchmark.py)) và ghi nhận số liệu khách quan:

| Trường phái Fuzzing | Tỷ lệ Tìm thấy Crash (Success Rate) | Thời gian / Vòng lặp Trung vị | Bản chất Kỹ thuật & Rào cản Toán học |
|:---|:---:|:---:|:---|
| **Black-box Fuzzing** (Ngẫu nhiên mù quáng) | **0% (0 / 30 trials)** | Hết ngân sách 500 pkts | Xác suất đoán trúng ngẫu nhiên cùng lúc Magic 4B và Checksum 1B là $P = (1/256)^5 \approx 9.09 \times 10^{-13}$ (~1.1 nghìn tỷ lần thử). |
| **Greybox Fuzzing** (Ghim Magic, đột biến payload) | **46.67% (14 / 30 trials)** | 2.16 giây (~160.5 vòng lặp) | Ghim sẵn Magic `"FZP1"` giúp vượt qua tầng 1, xác suất trúng Checksum giảm về $1/256 \approx 0.39\%$. |
| **White-box Concolic** (SMT Z3 Bit-Vector) | **100% (30 / 30 trials)** | **6.98 ms** (1 vòng lặp duy nhất) | Z3 giải ngược hệ phương trình ràng buộc $\text{chk} = \bigoplus p_i \land L \ge 64$, tổng hợp trực tiếp payload gây tràn stack. |

#### Trụ cột 4: Minh chứng Điểm mù Phân tích Tĩnh (Cppcheck False Negative)
* Khi quét file `v0` bằng Cppcheck khắt khe nhất (`--enable=all --inconclusive --std=c99`), Cppcheck báo **0 cảnh báo, 0 lỗi**.
* **Nguyên nhân:** Biến độ dài `len` nhận dữ liệu từ luồng nhị phân lúc chạy (runtime tainted input), cây cú pháp AST không thể xác định giá trị lúc biên dịch.
* **Kết luận học thuật:** Phân tích tĩnh có điểm mù lớn với luồng dữ liệu động; bắt buộc phải kết hợp **Dynamic Fuzzing** và **AddressSanitizer (ASan) / Hardware Canary**.

---

### 4. Cấu trúc Thư mục Dự án

```text
ATPM-Nhom11-ChuDe4-Fuzzing/
├── README.md                            # Cẩm nang tổng quan và hướng dẫn báo cáo tiến độ
├── HUONG_DAN_KIEM_TRA_DU_AN.md          # Hướng dẫn kiểm tra nhanh 60 giây cho người chấm
├── specification/
│   └── Nhom11_FZP1_Fuzzing_Spec.xlsx   # Đặc tả hình thức SSOT 10 sheet chuẩn SecLab
├── source/
│   ├── fzp1_parser_v0.c                 # Parser C chứa 3 lỗi bộ nhớ thực tế (CWE-121, 415, 416)
│   ├── fzp1_parser_v1.c                 # Bản vá an toàn chuẩn CERT STR31-C, MEM30-C, MEM31-C
│   ├── fzp1_parser_v0.exe               # Binary thực thi chứa lỗi
│   ├── fzp1_parser_v1.exe               # Binary thực thi an toàn
│   └── ch4_dynafuzz_fzp1.py             # Module 3 engine Fuzzing (Black-box, Greybox, White-box Z3)
├── tests/
│   ├── test_fzp1_parser.py              # 10 Unit tests tự động PyTest cho v0 và v1 (10/10 PASS)
│   └── test_fzp1_evolution.py           # 4 Evolution tests xác minh chu trình tiến hóa v0 -> v0.1 -> v0.2 -> v1 (4/4 PASS)
├── network_capture/                     # Chuỗi gói tin nhị phân PCAP và nhật ký phân tích ánh xạ đặc tả
├── seed_corpus/                         # Tập tệp nhị phân hạt giống (valid, invalid magic, bad chk)
├── crashes/                             # Các tệp nhị phân kích hoạt crash thực tế
├── results/
│   ├── data_raw/                        # Dữ liệu JSON thô của 30 lượt benchmark độc lập
│   ├── figures/                         # Biểu đồ Boxplot, Bar chart, Kripke model (300 DPI)
│   ├── logs/                            # Nhật ký ASan, Cppcheck, pipeline verification
│   └── screenshots/                     # Ảnh chụp thực tế giao diện công cụ gốc của Thầy
├── scripts/
│   ├── verify_project.py                # Kịch bản tự động kiểm tra 8 khâu (Đạt chuẩn 100% PASS)
│   ├── run_fzp1_benchmark.py            # Kịch bản thực thi benchmark 30 trials độc lập
│   ├── aggregate_results.py             # Kịch bản tổng hợp số liệu thống kê thực nghiệm
│   ├── generate_charts.py               # Kịch bản vẽ biểu đồ trực quan hóa
│   ├── build_professional_docx.py       # Kịch bản biên dịch báo cáo Word & PDF chuẩn Phenikaa
│   └── pack_submission.py               # Kịch bản đóng gói ZIP nộp bài tinh gọn
└── report/
    ├── BaoCao_BTL_Nhom11.pdf            # Báo cáo đồ án chính thức (Chuẩn Academic Phenikaa)
    ├── BaoCao_BTL_Nhom11.docx           # Bản Word biên soạn đồng bộ
    └── BaoCao_BTL_Nhom11.md             # Mã nguồn Markdown báo cáo
```

---

### 5. Hướng dẫn Lệnh Demo Nhanh khi Giảng viên Yêu cầu

#### 1. Chạy Bộ Thẩm định Toàn diện 8 Khâu (Khuyến nghị dùng để Demo với Thầy):
```bash
python scripts/verify_project.py
```
*Kết quả:* Tự động kiểm tra độc lập 8 khâu (Môi trường, Pytest 10/10, Excel 10 Sheet, 3 Lỗi bộ nhớ, Cppcheck, Z3 SMT, Benchmark 30 trials, SHA-256 Manifest) và báo **PASS 100%**.

#### 2. Chạy Bộ Kiểm thử PyTest (14 Test Cases: 10 Đơn vị + 4 Tiến hóa):
```bash
pytest tests/ -v
```
*Kết quả:* **14 passed in ~2.3s**, xác thực đầy đủ cả 3 lỗi sập ở `v0`, chu trình vá tiến hóa qua `v0.1`, `v0.2`, và cơ chế từ chối an toàn ở `v1`.

#### 3. Kích hoạt Crash Thực tế trên Từng Lỗ hổng:
* **CWE-121 (Stack Overflow):**
  ```bash
  .\source\fzp1_parser_v0.exe .\crashes\whitebox_s0_crash_0.bin   # Sập (0xC0000403 Canary Overrun)
  .\source\fzp1_parser_v1.exe .\crashes\whitebox_s0_crash_0.bin   # Từ chối an toàn CERT STR31-C (Exit Code 2)
  ```
* **CWE-415 (Double Free):**
  ```bash
  .\source\fzp1_parser_v0.exe .\crashes\crash_cwe415.bin           # Sập (0xC0000374 Heap Corruption)
  .\source\fzp1_parser_v1.exe .\crashes\crash_cwe415.bin           # Xử lý an toàn CERT MEM30-C (Exit Code 2)
  ```
* **CWE-416 (Use-After-Free):**
  ```bash
  .\source\fzp1_parser_v0.exe .\crashes\crash_cwe416.bin           # Sập (0xC0000005 Access Violation)
  .\source\fzp1_parser_v1.exe .\crashes\crash_cwe416.bin           # Xử lý an toàn CERT MEM30-C (Exit Code 2)
  ```

---

### 6. Giấy phép & Tuyên bố Bản quyền
Dự án được xây dựng và phục vụ cho mục đích học tập, nghiên cứu khoa học trong khuôn khổ học phần **Kỹ thuật Lập trình An toàn** tại Trường Đại học Phenikaa. Toàn bộ mã nguồn C, module Fuzzer, tệp đặc tả FZP1 và tài liệu báo cáo do Nhóm 11 tự tay hiện thực 100%.
