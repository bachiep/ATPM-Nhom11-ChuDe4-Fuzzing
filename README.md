# FZP1 Binary Parser — Fuzzing Benchmark & Memory Safety Audit
## Đồ án Môn học: An toàn Phần mềm (CSE703093 / CSE703153) — Chủ đề 4: Dự án Fuzzing
**Trường Đại học Phenikaa — Khoa Công nghệ Thông tin**  
**Giảng viên hướng dẫn:** ThS. Vũ Quang Dũng  

---

### Thông tin Nhóm 11
**Kho lưu trữ GitHub chính thức:** [https://github.com/bachiep/ATPM-Nhom11-ChuDe4-Fuzzing](https://github.com/bachiep/ATPM-Nhom11-ChuDe4-Fuzzing)

| STT | Họ và Tên | Mã Sinh Viên | Khóa | Vai Trò | Tỷ lệ Đóng góp | GitHub Account |
|:---:|:---|:---:|:---:|:---:|:---:|:---:|
| 1 | **Lưu Đức Hiệp** | *[Bảo mật]* | *[Bảo mật]* | Trưởng nhóm | 50% | [@bachiep](https://github.com/bachiep) |
| 2 | **Hà Nguyễn Trúc Linh** | *[Bảo mật]* | *[Bảo mật]* | Thành viên | 50% | [@tomchienxuu](https://github.com/tomchienxuu) |

---

### Tổng quan Đề tài & Bản chất Khác biệt
Đề tài 4 tập trung vào **Tầng biên mạng nhị phân mức thấp (Low-level Binary Network Perimeter)**, trực tiếp giải mã luồng byte thô không tin cậy của giao thức định dạng tự thiết kế **FZP1** (`4B Magic "FZP1"` + `1B Length` + `Payload` + `1B XOR Checksum`), hoàn toàn khác biệt với các đề tài kiểm thử ứng dụng web/CRUD cấp cao:
- **Ứng dụng Web / Query CRUD (Các đề tài khác):** Dữ liệu văn bản có cấu trúc (JSON, form-data, SQL query) chạy trên runtime có Garbage Collection (NodeJS, Spring, Django). Trọng tâm là lỗi logic nghiệp vụ.
- **Tầng Biên Nhị phân FZP1 (Đề tài 4):** Không có framework hay GC bảo bọc; mã C trực tiếp quản lý bộ nhớ vật lý, tính toán số học con trỏ (`pointer arithmetic`) và đối mặt trực tiếp với các lỗi phá hủy bộ nhớ (**Memory Corruption CWE-121**).
- **Rào cản Toán học của Magic và Checksum:** Black-box fuzzing ngẫu nhiên đối mặt không gian tìm kiếm $2^{40} \approx 1.099 \times 10^{12}$ tổ hợp ($P \approx 9.09 \times 10^{-13}$), trong khi White-box Concolic Z3 giải ngược hệ phương trình Bit-Vector và kích hoạt lỗi trong $\approx 7.4$ ms.

---

### Kiến trúc Bộ nhớ & Vòng đời Dữ liệu (Memory Lifecycle)
- **Gói tin Thô trên Heap (`malloc`):** Toàn bộ tệp nhị phân được nạp động vào Heap để không làm cạn kiệt tài nguyên Stack.
- **Xử lý trên Stack Frame (`stack_buf`):** Sao chép payload vào biến mảng cục bộ trên Stack để xử lý với độ trễ vi giây.
- **Mô hình Vận hành Run-to-Completion:** Sau khi giải mã và xác thực (dù thành công hay bị từ chối), bộ nhớ Heap luôn được giải phóng ngay lập tức (`free(file_buf); file_buf = NULL;`), triệt tiêu hoàn toàn rò rỉ bộ nhớ (CWE-401) và con trỏ lơ lửng (CWE-416).
- **Lỗ hổng CWE-121 & Bản vá CERT STR31-C:** Tại bản $v_0$, `stack_buf[16]` bị ghi đè bởi `memcpy` khi `payload_len >= 25` (ghi đè Stack Right Redzone `[f3]`). Bản $v_1$ chặn cứng `len > 16`, khai báo mảng 17 byte có Null-terminator (CERT STR31-C), đạt **0 AddressSanitizer findings**.

---

### Cấu trúc Thư mục Dự án
```text
ATPM-Nhom11-ChuDe4-Fuzzing/
├── README.md                            # Hướng dẫn toàn diện và cẩm nang nghiệm thu
├── HUONG_DAN_KIEM_TRA_DU_AN.md          # Hướng dẫn nhanh 60 giây tái lập kết quả
├── specification/
│   └── Nhom11_FZP1_Fuzzing_Spec.xlsx   # Đặc tả hình thức 10 sheet Excel (SSOT)
├── source/
│   ├── fzp1_parser_v0.c                 # Parser mục tiêu chứa lỗi CWE-121 có chủ đích
│   ├── fzp1_parser_v1.c                 # Bản vá an toàn chuẩn CERT STR31-C / MEM31-C
│   ├── fzp1_parser_v0.exe               # Binary thực thi chứa lỗi
│   └── fzp1_parser_v1.exe               # Binary thực thi an toàn
├── tests/
│   └── test_fzp1_parser.py              # 10 Unit tests tự động Pytest (100% Passed)
├── seed_corpus/                         # Tập tệp nhị phân mồi (valid, invalid magic, bad chk)
├── crashes/                             # Các payload nhị phân kích hoạt crash qua 30 trials
├── results/
│   ├── data_raw/                        # Dữ liệu JSON thô 30 trials benchmark
│   ├── figures/                         # Biểu đồ Boxplot, Bar chart, Kripke model (300 DPI)
│   └── logs/                            # Forensic logs (ASan v0, clean v1, Cppcheck, pipeline)
├── scripts/
│   ├── verify_project.py                # Kịch bản tự động kiểm tra 8 khâu (Audit 10/10 PASS)
│   ├── run_fzp1_benchmark.py            # Kịch bản thực thi benchmark 30 trials độc lập
│   ├── aggregate_results.py             # Kịch bản tổng hợp số liệu thống kê thực nghiệm
│   ├── generate_charts.py               # Kịch bản vẽ đồ thị trực quan hóa (Matplotlib)
│   └── export_all_docs.py               # Kịch bản biên dịch báo cáo Word sang PDF
└── report/
    ├── BaoCao_BTL_Nhom11.pdf            # Báo cáo chính thức 19 trang (Đầy đủ 8 phần chuẩn theo report_guide.pdf)
    ├── BaoCao_BTL_Nhom11.docx           # Bản Word biên soạn kèm theo
    └── BaoCao_BTL_Nhom11.md             # Mã nguồn Markdown báo cáo
```

---

### Hướng dẫn Cài đặt & Chạy Thực nghiệm

#### 1. Yêu cầu Môi trường
- Hệ điều hành: Windows / Linux
- Trình biên dịch C: `gcc` hoặc `clang` hỗ trợ C99
- Python: Version `>= 3.10`
- Cài đặt thư viện Python:
  ```bash
  pip install pytest z3-solver openpyxl python-docx matplotlib pypdf
  ```

#### 2. Kiểm tra Dự án Tự động Toàn diện (Khuyến nghị cho Giảng viên)
Chạy kịch bản kiểm tra tự động 8 khâu tích hợp sẵn:
```bash
python scripts/verify_project.py
```
*Kịch bản sẽ tự động đối soát: Môi trường, Unit Tests, Đặc tả Excel 10 Sheet, ASan Before/After, Cppcheck, SMT Z3, Dữ liệu thực nghiệm 30 Trials và Mã băm SHA-256 toàn vẹn.*

#### 3. Chạy Bộ Kiểm thử PyTest (10 Test Cases)
```bash
pytest tests/test_fzp1_parser.py -v
```
*Kết quả: 10/10 passed (100%) trong < 0.5 giây.*

#### 4. Biên dịch và Xác minh Bản Vá CWE-121
```bash
# Biên dịch cả hai phiên bản bằng GCC
gcc -Wall -Wextra -O0 -g -fstack-protector-all source/fzp1_parser_v0.c -o source/fzp1_parser_v0.exe
gcc -Wall -Wextra -O0 -g -fstack-protector-all source/fzp1_parser_v1.c -o source/fzp1_parser_v1.exe

# Kích hoạt lỗi trên bản v0 (Sập tiến trình do ghi đè stack canary)
.\source\fzp1_parser_v0.exe crashes\whitebox_s0_crash_0.bin

# Kiểm chứng bản vá an toàn v1 (Từ chối an toàn, 0 lỗi bộ nhớ)
.\source\fzp1_parser_v1.exe crashes\whitebox_s0_crash_0.bin
```

---

### Giấy phép & Tuyên bố Bản quyền
Dự án được xây dựng và phục vụ cho mục đích học tập, nghiên cứu khoa học trong khuôn khổ học phần **Kỹ thuật Lập trình An toàn** tại Trường Đại học Phenikaa. Toàn bộ mã nguồn, dữ liệu thực nghiệm và tài liệu báo cáo do hai thành viên nhóm tự tay hiện thực 100%.
