# SecureGate IoT Gateway — Binary Parser Fuzzing Benchmark
## Đồ án Môn học: An toàn Phần mềm (CSE703093 / CSE703153) — Chủ đề 4: Dự án Fuzzing
**Trường Đại học Phenikaa — Khoa Công nghệ Thông tin**  
**Giảng viên hướng dẫn:** ThS. Vũ Quang Dũng  

---

### Thông tin Nhóm 11
| STT | Họ và Tên | Mã Sinh Viên | Vai Trò | Tỷ lệ Đóng góp | GitHub Account |
|:---:|:---|:---:|:---:|:---:|:---:|
| 1 | **Lưu Đức Hiệp** | 22010174 | Trưởng nhóm | 50% | [@bachiep](https://github.com/bachiep) |
| 2 | **Hà Nguyễn Trúc Linh** | 22010198 | Thành viên | 50% | [@tomchienxuu](https://github.com/tomchienxuu) |

---

### Tổng quan Đề tài
Dự án tập trung nghiên cứu, thiết kế và đánh giá an toàn giao thức truyền thông nhị phân **SecureGate IGW1** thông qua ba phương pháp Fuzzing tiêu chuẩn:
1. **Black-box Fuzzing (Hộp đen):** Đột biến byte ngẫu nhiên (Bit-flip, Byte-scramble).
2. **Greybox Fuzzing (Hộp xám):** Dẫn hướng độ phủ thực thi (Coverage-guided) tích hợp bitmap phản hồi từ `gcov`.
3. **White-box Fuzzing (Hộp trắng):** Thực thi biểu trưng (Concolic / Symbolic Execution) sử dụng Z3 SMT Solver (Bit-Vector) để giải các rào cản ngữ nghĩa (Magic Bytes "IGW1" và Checksum 32-bit).

Mục tiêu mã nguồn gồm 2 phiên bản theo đúng quy chuẩn Mục 3.3 của giảng viên:
- `source/gateway_parser_v0.c`: Phiên bản cơ sở tồn tại lỗ hổng **CWE-121 (Stack-based Buffer Overflow)** do sao chép không kiểm tra biên `device_id_len`.
- `source/gateway_parser_v1.c`: Phiên bản đã vá an toàn theo chuẩn **CERT STR31-C** và **ARR30-C**, từ chối an toàn mọi gói tin vượt ngưỡng và đạt **0 AddressSanitizer findings**.

---

### Cấu trúc Thư mục Dự án
```text
ATPM-Nhom11-ChuDe4-Fuzzing/
├── .gitignore
├── README.md
├── HUONG_DAN_KIEM_TRA_DU_AN.md      # Cẩm nang nghiệm thu toàn diện dự án
├── HUONG_DAN_KIEM_TRA_DU_AN.pdf     # Bản PDF in ấn chính thức
├── specification/
│   └── Nhom11_SecureGate_IoT_Gateway_Spec.xlsx  # Đặc tả hình thức 10 sheet Excel
├── source/
│   ├── gateway_parser_v0.c          # Chương trình mục tiêu chứa lỗi CWE-121
│   ├── gateway_parser_v1.c          # Bản vá an toàn chuẩn CERT C
│   ├── gateway_parser.c             # Mã nguồn tổng hợp
│   ├── parser_vuln.exe              # Binary thực thi chứa lỗi
│   ├── parser_fixed.exe             # Binary thực thi an toàn
│   ├── blackbox_fuzzer.py           # Động cơ Fuzzing hộp đen
│   ├── greybox_fuzzer.py            # Động cơ Fuzzing hộp xám dẫn hướng độ phủ
│   ├── whitebox_fuzzer.py           # Động cơ Fuzzing hộp trắng SMT Z3
│   ├── packet_builder.py            # Module xây dựng cấu trúc gói tin IGW1
│   └── unlock_benchmark.py          # Benchmark vượt rào cản Magic Guard
├── tests/
│   ├── test_parser.py               # 15 Unit tests kiểm tra parser logic & CWE-121
│   └── test_fuzzers.py              # 15 Unit tests kiểm tra 3 động cơ Fuzzer
├── seed_corpus/                     # 4 tệp seed nhị phân mồi ban đầu
├── crashes/                         # 60 payload nhị phân kích hoạt crash qua 30 trials
├── results/
│   ├── data_raw/                    # Dữ liệu JSON thô 30 trials benchmark
│   ├── figures/                     # 5 biểu đồ trực quan hóa số liệu
│   ├── logs/                        # Forensic logs (ASan v0, clean v1, Cppcheck)
│   └── screenshots/                 # Minh chứng kiểm chứng công cụ & terminal
├── scripts/
│   ├── verify_project.py            # Kịch bản tự động kiểm tra 8 khâu (Audit script)
│   ├── run_benchmark.py             # Kịch bản thực thi benchmark 30 trials
│   ├── aggregate_results.py         # Kịch bản tổng hợp số liệu thống kê
│   ├── generate_charts.py           # Kịch bản vẽ đồ thị trực quan hóa
│   └── export_all_docs.py           # Kịch bản xuất báo cáo sang Word & PDF
└── report/
    ├── BaoCao_BTL_Nhom11.pdf        # Báo cáo chính thức 8 chương (Bắt buộc)
    ├── BaoCao_BTL_Nhom11.docx       # Bản Word có thể chỉnh sửa
    ├── BaoCao_BTL_Nhom11.md         # Mã nguồn văn bản báo cáo
    └── BaoCao_TichHop_SpecVerificationLab.docx # Báo cáo kiểm chứng từ SpecVerificationLab
```

---

### Hướng dẫn Cài đặt & Chạy Thực nghiệm

#### 1. Yêu cầu Môi trường
- Hệ điều hành: Windows / Linux
- Trình biên dịch C: `gcc` hỗ trợ `-fsanitize=address`
- Python: Version `>= 3.10`
- Cài đặt thư viện Python:
  ```bash
  pip install pytest z3-solver openpyxl python-docx matplotlib scipy
  ```

#### 2. Kiểm tra Dự án Tự động Toàn diện (Khuyến nghị cho Giảng viên)
Chạy kịch bản kiểm tra tự động 8 khâu tích hợp sẵn:
```bash
python scripts/verify_project.py
```
*Kịch bản sẽ tự động đối soát: Môi trường, 30 Unit Tests, Đặc tả Excel 10 Sheet, ASan Before/After, Cppcheck, SMT Z3 và Mã băm SHA-256 toàn vẹn.*

#### 3. Chạy Bộ Kiểm thử PyTest (30 Test Cases)
```bash
pytest -v
```
*Kết quả: 30/30 passed (100%) trong ~11 giây.*

#### 4. Biên dịch và Xác minh Bản Vá CWE-121
```bash
# Biên dịch bản v0 (chứa lỗi) và v1 (đã vá)
gcc -g -o source/parser_vuln source/gateway_parser_v0.c
gcc -g -o source/parser_fixed source/gateway_parser_v1.c

# Thử nghiệm kích hoạt lỗi với payload khai thác
./source/parser_vuln crashes/whitebox_s0_crash_0.bin    # Gây crash Buffer Overflow
./source/parser_fixed crashes/whitebox_s0_crash_0.bin   # Từ chối an toàn (0 finding)
```

---

### Giấy phép & Tuyên bố Bản quyền
Dự án được xây dựng và phục vụ cho mục đích học tập, nghiên cứu khoa học trong khuôn khổ học phần **An toàn Phần mềm** tại Trường Đại học Phenikaa. Toàn bộ mã nguồn, dữ liệu thực nghiệm và tài liệu báo cáo do hai thành viên nhóm tự tay hiện thực 100%.
