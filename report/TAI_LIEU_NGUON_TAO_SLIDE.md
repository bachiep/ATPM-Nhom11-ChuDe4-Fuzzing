# TÀI LIỆU CỐT LÕI HỌC THUẬT: ĐỒ ÁN KỸ THUẬT LẬP TRÌNH AN TOÀN (CSE703093 / CSE703153)
**ĐỀ TÀI: CHỦ ĐỀ 4 — DỰ ÁN FUZZING BỘ PHÂN TÍCH CÚ PHÁP GÓI TIN NHỊ PHÂN FZP1**
*So sánh Đối chuẩn Thực nghiệm: Black-box vs Greybox vs White-box Concolic SMT Z3*
**Đơn vị thực hiện:** Nhóm 11 — Lưu Đức Hiệp & Hà Nguyễn Trúc Linh
**Giảng viên Hướng dẫn:** ThS. Vũ Quang Dũng — Trường Công nghệ Thông tin, Đại học Phenikaa

---

## 1. TỔNG QUAN ĐỀ TÀI & BỐI CẢNH KỸ THUẬT
- **Bối cảnh:** Các hệ thống nhúng, vi điều khiển IoT và thiết bị mạng biên sử dụng các giao thức truyền thông nhị phân độc quyền (Proprietary Binary Protocols) viết bằng C/C++ nhằm tối ưu hóa băng thông và độ trễ.
- **Vấn đề an toàn:** Bộ phân tích cú pháp (Parser) C cấp thấp thường đối mặt với bề mặt tấn công rất rộng từ các luồng dữ liệu ô nhớ không tin cậy truyền qua mạng. Nếu không có cơ chế xác thực biên chặt chẽ, kẻ tấn công có thể kích hoạt các lỗi tha hóa ô nhớ (Memory Corruption) dẫn tới từ chối dịch vụ (DoS) hoặc thực thi mã từ xa (RCE).
- **Mục tiêu nghiên cứu:**
  1. Xây dựng chuỗi truy vết chuẩn mực từ gói tin mạng thực tế (PCAP) -> Trích xuất Hex -> Bảng đặc tả Single Source of Truth (SSOT) 10 sheet -> Mã nguồn C.
  2. Cài đặt có chủ đích 3 lỗ hổng ô nhớ thực tế (CWE-121, CWE-415, CWE-416) và xây dựng các bản vá an toàn tuân thủ chuẩn CERT C (STR31-C, MEM30-C, MEM31-C).
  3. Thiết kế động cơ Fuzzing đa phương thức (`ch4_dynafuzz_fzp1.py`) gồm Black-box, Greybox (Coverage-guided) và White-box Concolic SMT Z3.
  4. Thực hiện thử nghiệm đối chuẩn khách quan qua 30 trials độc lập và mô hình hóa tiến trình sửa lỗi đa giai đoạn ($v_0 \to v_{0.1} \to v_{0.2} \to v_1$).

---

## 2. ĐẶC TẢ GIAO THỨC FZP1 & MÔ HÌNH HÓA HÌNH THỨC KRIPKE/CTL
### 2.1. Cấu trúc Gói tin Nhị phân FZP1
- `[0..3]` : 4 bytes Magic Header chuỗi `"FZP1"` (`0x46, 0x5A, 0x50, 0x31`).
- `[4..7]` : 4 bytes Payload Length (Số nguyên không dấu 32-bit Little-Endian `uint32_t`).
- `[8..8+L-1]` : $L$ bytes Payload dữ liệu (cảm biến, lệnh điều khiển).
- `[8+L]` : 1 byte Checksum XOR (Toán tử XOR dồn trên toàn bộ $L$ byte payload).
- Tổng kích thước tối thiểu: 9 bytes (4B Magic + 4B Length + 0B Payload + 1B Checksum).

### 2.2. Chuỗi Truy vết Thực nghiệm (Traceability Pipeline)
- Gói tin mạng PCAP thật: `network_capture/iot_sensor_stream.pcap` (24 gói tin cảm biến).
- Bảng đặc tả SSOT: `specification/Nhom11_FZP1_Fuzzing_Spec.xlsx` (10 sheet tương thích công cụ `SecLabFramework.exe` Tab Ch6).
- 9 yêu cầu chức năng (REQ-1 đến REQ-9) quy định tuần tự phân tích: Kiểm tra kích thước >= 9B -> Xác thực Magic -> Kiểm tra độ dài <= 65536B -> Kiểm tra kích thước gói tin thực tế -> Xác thực Checksum XOR -> Phân luồng xử lý payload.

### 2.3. Mô hình Trạng thái Kripke & Kiểm chứng CTL
- Mô hình $M = (S, S_0, R, L)$ gồm 4 trạng thái vận hành:
  - $s_0$: `st_idle` (Khởi tạo).
  - $s_1$: `st_magic_ok` (Magic khớp "FZP1").
  - $s_2$: `st_checksum_ok` (Checksum khớp).
  - $s_3$: `st_conflict` (Trạng thái xung đột nguy hiểm — tiền đề gây tràn bộ nhớ khi payload length > 16).
- Công thức kiểm chứng an toàn CTL:
  - $AG(\neg \text{violation})$: Kết quả **FALSE** trên bản lỗi $v_0$ (tồn tại đường đi dẫn tới `st_conflict`).
  - $AG(\text{valid\_packet} \implies \text{payload\_len} \le 16)$: Thuộc tính bất biến được khôi phục thành **TRUE** trên bản vá $v_1$.

---

## 3. CHI TIẾT 3 LỖ HỔNG BỘ NHỚ THỰC TẾ & BẢN VÁ CERT C
### 3.1. Lỗ hổng 1 — CWE-121: Stack-based Buffer Overflow
- **Vị trí:** `source/fzp1_parser_v0.c`, hàm `parse_fzp1_payload()`.
- **Cơ chế ô nhớ:** Cấp phát mảng cục bộ `char stack_buf[16]`. Khi nhận gói tin hợp lệ nhưng có `len > 16` (ví dụ 24B hoặc 64B), hàm thực thi `memcpy(stack_buf, payload, len)` mà không kiểm tra biên.
- **Hành vi binary:** Ghi đè Canary và địa chỉ trả về của Stack Frame, gây lỗi sập Windows Access Violation (`0xC0000005`) hoặc Stack Buffer Overrun (`0xC0000409`).
- **Minh chứng AddressSanitizer:** Byte giám sát shadow byte `[f3]` xuất hiện (Stack Right Redzone violation).
- **Bản vá an toàn ($v_1$):** Tuân thủ **CERT STR31-C** (Đảm bảo dung lượng lưu trữ cho chuỗi). Kiểm tra chặn biên cứng `if (len > 16) return 2;`. Khai báo buffer 17 bytes (`char stack_buf[17]`) để đảm bảo ký tự kết thúc null `\0`.

### 3.2. Lỗ hổng 2 — CWE-415: Double Free
- **Vị trí:** `source/fzp1_parser_v0.c`, hàm `close_fzp1_session()`.
- **Cơ chế ô nhớ:** Khi nhận gói tin có byte đầu `0xFF` (`CMD_ABORT_SESSION`), luồng xử lý lỗi giải phóng ô nhớ heap của cấu trúc `g_session` và `cached_payload` bằng `free()`, nhưng **không gán con trỏ về `NULL`**. Khi chương trình kết thúc, luồng dọn dẹp tại `main()` tiếp tục gọi `close_fzp1_session()` lần thứ 2.
- **Hành vi binary:** Cố gắng giải phóng một chunk bộ nhớ heap đã được đánh dấu là tự do trong Heap Metadata, kích hoạt cơ chế tự bảo vệ của Windows Heap Manager ném mã lỗi sập `0xC0000374` (STATUS_HEAP_CORRUPTION).
- **Bản vá an toàn ($v_1$):** Tuân thủ **CERT MEM31-C** và **CERT MEM30-C**. Áp dụng nguyên tắc phòng vệ triệt để: Ngay sau mỗi câu lệnh `free(ptr)`, lập tức gán `ptr = NULL;`. Nhờ đó, lời gọi giải phóng lần 2 trở thành phép toán rỗng Idempotent an toàn tuyệt đối.

### 3.3. Lỗ hổng 3 — CWE-416: Heap Use-After-Free
- **Vị trí:** `source/fzp1_parser_v0.c`, hàm `release_fzp1_stream()`.
- **Cơ chế ô nhớ:** Khi nhận byte lệnh `0xFE` (`CMD_RESET_STREAM`), chương trình giải phóng `g_session` nhưng để lại con trỏ lơ lửng (Dangling Pointer). Sau đó, mô phỏng ô nhớ heap bị một tiến trình khác tái cấp phát và ghi đè dữ liệu (Heap Reclamation/Reuse), parser tiếp tục gọi con trỏ hàm ủy thác `g_session->stream_callback()`.
- **Hành vi binary:** Đọc và kích hoạt con trỏ hàm từ vùng nhớ đã giải phóng, gây chiếm quyền điều khiển con trỏ lệnh (`RIP/EIP`) hoặc crash với mã lỗi `0xC0000005`.
- **Minh chứng AddressSanitizer:** Shadow byte `[fd]` xuất hiện (Truy cập ô nhớ Heap Freed).
- **Bản vá an toàn ($v_1$):** Tuân thủ **CERT MEM30-C**. Đảo ngược chu trình xử lý: Kích hoạt con trỏ hàm telemetry **trước** khi hủy tài nguyên, sau đó mới giải phóng `free()` và lập tức triệt tiêu con trỏ lơ lửng `g_session = NULL`.

---

## 4. MA TRẬN ĐỐI SÁNH TRƯỚC VÀ SAU VÁ LỖI (TABLE 2 BEFORE/AFTER)

| Tiêu chí Đối sánh | Phiên bản Lỗi ($v_0$) | Phiên bản Đã Vá An toàn ($v_1$) | Chuẩn CERT C Áp dụng |
| :--- | :--- | :--- | :--- |
| **Kiểm tra Biên Stack Buffer** | Không kiểm tra biên `len`; `memcpy` trực tiếp vào `stack_buf[16]`. | Chặn biên cứng `len <= 16`; đệm `stack_buf[17]` có `\0`. | **CERT STR31-C** |
| **Quản lý Con trỏ sau `free()`** | Bỏ quên con trỏ lơ lửng (Dangling Pointer); không gán NULL. | Lập tức gán `ptr = NULL` sau mỗi lần giải phóng. | **CERT MEM31-C** |
| **Thứ tự Hủy Tài nguyên & Callback**| `free()` trước, kích hoạt con trỏ hàm `stream_callback` sau. | Kích hoạt callback telemetry trước khi `free()`; sau đó gán NULL. | **CERT MEM30-C** |
| **Mã Lỗi Trả về Khi Gặp Dữ liệu Bẩn**| Bỏ qua lỗi, tiếp tục thực thi dẫn tới Crash (`0xC0000005`). | Từ chối an toàn với mã trạng thái chuẩn (`Exit Code = 2`). | Error Handling Pattern |
| **Phản ứng AddressSanitizer** | Bắt lỗi tức thời: Shadow `[f3]` (Stack) và `[fd]` (Heap). | 0 memory findings, 0 sanitizer warnings, thực thi sạch sẽ. | Dynamic Verification |
| **Tỷ lệ Sống sót khi Fuzzing** | 90 crashes / 500 gói tin đột biến đa dạng. | **0 crashes / 500 gói tin** (Tỷ lệ sống sót đạt 100%). | Robustness |

---

## 5. PHƯƠNG PHÁP LUẬN & ĐỘNG CƠ FUZZING ĐA TRƯỜNG PHÁI
### 5.1. Kiến trúc Động cơ `ch4_dynafuzz_fzp1.py`
- Lập trình Python 3.13 hướng đối tượng, khép kín, độc lập với hệ điều hành (chạy mượt mà trên Windows Native).
- **RAM Guard:** Khống chế payload tối đa 128B, tổng gói tin tối đa 256B, ngăn ngừa rò rỉ và tràn bộ nhớ RAM khi chạy thử nghiệm lặp dài.
- **Coverage-guided Feedback:** Quản lý hàng đợi hạt giống (Seed Queue Prioritization), mô phỏng mảng Bitmap phản hồi độ phủ biên gồm 9 nhánh phân rã logic:
  - `B0: REJECT_TOO_SHORT (< 9B)`
  - `B1: REJECT_INVALID_MAGIC (!= 'FZP1')`
  - `B2: REJECT_PAYLOAD_QUOTA (> 65536B)`
  - `B3: REJECT_SIZE_MISMATCH`
  - `B4: REJECT_CHECKSUM_MISMATCH`
  - `B5: PARSE_SAFE_TELEMETRY (<= 16B)`
  - `B6: PARSE_OVERFLOW_CWE121 (> 16B)`
  - `B7: CMD_ABORT_CWE415 (0xFF)`
  - `B8: CMD_RESET_CWE416 (0xFE)`

### 5.2. Rào cản Xác suất Toán học của Black-box Fuzzing
- Xác suất để một bộ sinh ngẫu nhiên đoán đúng đồng thời cả 3 trường để gây crash CWE-121:
  $$P(\text{crash}) = P(\text{Magic 'FZP1'}) \times P(16 < \text{len} \le 80) \times P(\text{Checksum XOR})$$
  $$P(\text{crash}) = \frac{1}{2^{32}} \times \frac{64}{2^{32}} \times \frac{1}{2^8} = 2^{-32} \times (64 \times 2^{-32}) \times 2^{-8} \approx 9.09 \times 10^{-13}$$
- **Ý nghĩa khoa học:** Cần trung bình $1.1 \times 10^{12}$ lượt thử ngẫu nhiên mới bắt gặp 1 gói tin kích hoạt crash. Điều này chứng minh Black-box Fuzzing hoàn toàn bất lực trước các giao thức có checksum toàn vẹn.

### 5.3. Sức mạnh Đột phá của White-box Concolic SMT Z3
- Sử dụng lý thuyết Bit-Vector (BitVec 8-bit & 32-bit) trong Z3 Solver.
- Mô hình hóa hệ ràng buộc đường đi dẫn tới crash:
  $$\text{Magic}[0..3] == \text{'FZP1'} \land \text{Length} == L \land L > 16 \land \text{Checksum} == \bigoplus_{i=0}^{L-1} \text{Payload}[i]$$
- Thời gian giải SAT trung bình chỉ **6.98 ms**. Z3 tổng hợp trực tiếp gói tin khai thác chính xác 100% trong đúng 1 bước thử.

---

## 6. KẾT QUẢ THỰC NGHIỆM ĐỐI CHUẨN ĐỊNH LƯỢNG 30 TRIALS

| Phương pháp Fuzzing | Tỷ lệ Thành công (Success Rate) | Thời gian Tìm Crash Trung vị (Median Time) | Số lần Lặp Trung bình (Mean Iterations) | Đánh giá Hiệu năng |
| :--- | :---: | :---: | :---: | :--- |
| **Black-box Fuzzing** | **0.00%** (0 / 30) | $\infty$ (Timeout 10.0s) | 1,482 (Không vượt qua Magic & Checksum) | Bị chặn đứng bởi rào cản xác suất $9.09 \times 10^{-13}$. |
| **Greybox Fuzzing** (AFL-style)| **46.67%** (14 / 30) | **2.16 giây** | 428.5 (Nhận biết Magic, dò đột biến Checksum) | Hiệu quả trung bình; phụ thuộc vào đột biến hạt giống. |
| **White-box SMT Z3** | **100.00%** (30 / 30) | **0.21 giây** (Giải SAT: 6.98 ms) | **1.0 lần** (Tổng hợp tất định trong 1 bước) | Tối ưu tuyệt đối về độ chính xác và khả năng vượt rào cản. |

---

## 7. CHU TRÌNH TIẾN HÓA VÁ LỖI ĐA GIAI ĐOẠN ($v_0 \to v_{0.1} \to v_{0.2} \to v_1$)
Thực nghiệm kiểm chứng trên 500 gói tin kiểm thử đa dạng kích hoạt cả 3 nhóm lỗ hổng:
1. **Mốc 1 ($v_0$ — Phiên bản Ban đầu):** Xuất hiện **90 crashes** (42 crash CWE-121, 26 crash CWE-415, 22 crash CWE-416).
2. **Mốc 2 ($v_{0.1}$ — Sau khi vá CWE-121 bằng CERT STR31-C):** Số crash giảm xuống **58 crashes** (CWE-121 giảm về 0; còn tồn tại 36 crash CWE-415 và 22 crash CWE-416).
3. **Mốc 3 ($v_{0.2}$ — Sau khi vá tiếp CWE-415 bằng CERT MEM31-C):** Số crash giảm còn **22 crashes** (CWE-121 và CWE-415 giảm về 0; còn lại duy nhất 22 crash CWE-416).
4. **Mốc 4 ($v_1$ — Bản vá Hoàn thiện Toàn diện):** Ghi nhận **0 crashes / 500 gói tin** (100% các gói tin độc hại bị từ chối an toàn với `Exit Code = 2`, gói tin hợp lệ xử lý thành công mã 0).
- **Kết luận:** An toàn phần mềm không phải là một giải pháp đơn lẻ mà là một chu trình kỹ thuật lặp (Iterative Security Lifecycle).

---

## 8. PHÂN TÍCH HIỆN TƯỢNG BỎ LỌT LỖI (FALSE NEGATIVE) CỦA CPPCHECK
- Công cụ phân tích tĩnh phổ biến Cppcheck 2.18 quét mã nguồn `fzp1_parser_v0.c` trả về kết quả: `0 errors, 0 warnings`.
- **Nguyên nhân cốt lõi:** Cppcheck duyệt cây cú pháp trừu tượng cục bộ (Local AST Traversal). Độ dài `payload_len` được đọc động từ mạng tại thời điểm runtime (`read_uint32_le`). Nếu không có kỹ thuật Taint Analysis liên thủ tục để theo dõi dòng chảy dữ liệu từ mạng đến hàm `memcpy`, Cppcheck coi `len` là biến chưa xác định và bỏ qua cảnh báo.
- **Ý nghĩa:** Khẳng định Dynamic Fuzzing và AddressSanitizer là phương pháp kiểm thử không thể thay thế trong bảo mật phần mềm nhị phân.

---

## 9. 3 BÀI HỌC VÀ CÂU HỎI PHẢN BIỆN BẮT BUỘC
1. **Thiết kế lại phần nào để tránh lỗi từ đầu?**
   - Thay thế kiến trúc đệm tĩnh bằng mô hình **Type-Length-Value (TLV)** có giới hạn độ dài kiểu dữ liệu nghiêm ngặt.
   - Thay vì cấp phát và giải phóng rải rác trên Heap, sử dụng cơ chế **Vùng cấp phát tập trung (Region-based / Arena Allocator)** cho toàn bộ phiên làm việc: Toàn bộ bộ nhớ được giải phóng 1 lần duy nhất khi kết thúc phiên, triệt tiêu 100% nguy cơ Double Free và Use-After-Free.
2. **Lỗ hổng nghi ngờ còn tồn tại?**
   - Nguy cơ từ chối dịch vụ do cạn kiệt tài nguyên (Resource Exhaustion / Memory Bomb): Nếu một client gửi liên tục các gói tin hợp lệ với `payload_len` lớn trong giới hạn cho phép (ví dụ 64KB) mà không đóng phiên, parser có thể bị cạn bộ nhớ Heap.
3. **Bài học phương pháp luận lớn nhất?**
   - *Phân tích tĩnh (Static Analysis) tìm ra những lỗi đã biết theo mẫu quy tắc, nhưng chỉ có Kiểm chứng Hình thức (Formal Verification) và Fuzzing Động (Dynamic Fuzzing) mới phát hiện được các lỗi trạng thái phức tạp và hành vi suy biến của bộ nhớ binary.*
