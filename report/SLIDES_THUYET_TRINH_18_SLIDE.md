# HỆ THỐNG 18 SLIDE BÁO CÁO BẢO VỆ ĐỒ ÁN AN TOÀN PHẦN MỀM
**Học phần:** Kỹ thuật Lập trình An toàn (Software Security — CSE703093 / CSE703153)  
**Chủ đề 4:** Dự án Fuzzing — Phân tích và Kiểm thử An toàn Bộ phân tích Cú pháp Gói tin Nhị phân FZP1 (*Black-box vs Greybox vs White-box Concolic SMT Z3*)  
**Đơn vị thực hiện:** Nhóm 11 — Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (50% - 50%)  
**Giảng viên Hướng dẫn:** ThS. Vũ Quang Dũng — Trường Công nghệ Thông tin, Đại học Phenikaa  
**Phong cách Thị giác:** Nền sáng học thuật (Light Academic Theme — Trắng ngà/Xám nhạt `#F8FAFC`, chữ Xanh Slate `#0F172A`, điểm nhấn Xanh Navy `#1E3A8A` và Xanh Ngọc `#059669`).

---

## SLIDE 1: TRANG TIÊU ĐỀ & GIỚI THIỆU ĐỒ ÁN
* **Bố cục thị giác (Visual Layout):** Nền trắng sáng `#FFFFFF`, viền trên Xanh Hải quân Phenikaa (`#1E3A8A`), Logo trường ở góc trên, Tiêu đề trung tâm in hoa đậm, khung thông tin thành viên và GVHD trang trọng ở góc dưới.
* **Tiêu đề Slide:** **BÁO CÁO BẢO VỆ ĐỒ ÁN KỸ THUẬT LẬP TRÌNH AN TOÀN**
* **Nội dung học thuật:**
  * **Đề tài (Chủ đề 4):** Nghiên cứu, Thiết kế và Đánh giá Thực nghiệm Bộ Phân tích Cú pháp Gói tin Nhị phân FZP1 (*Black-box vs Greybox vs White-box Concolic SMT Z3*).
  * **Sinh viên thực hiện:** Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (Nhóm 11 — Đóng góp 50% - 50%).
  * **Giảng viên hướng dẫn:** ThS. Vũ Quang Dũng — Trường Công nghệ Thông tin, Đại học Phenikaa.
  * **Thời gian:** Hà Nội — Tháng 10/2026.
* **Điểm nhấn:** Bộ kịch bản kiểm định tự động 8 khâu đạt chuẩn nghiệm thu tuyệt đối (**PASS 100%**).
* **Lời thoại thuyết trình (Speaker Notes — 60s):**  
  *"Kính thưa Thầy và Hội đồng thẩm định, hôm nay Nhóm 11 xin được bảo vệ Đồ án môn học Kỹ thuật Lập trình An toàn với Chủ đề 4: Phân tích và kiểm thử an toàn bộ phân tích cú pháp gói tin nhị phân FZP1. Đồ án của nhóm tập trung vào 3 trụ cột kỹ thuật: Chuỗi truy vết thực tế từ gói tin mạng PCAP sang bảng đặc tả SSOT và mã nguồn C; Cài đặt và triệt tiêu 3 lỗ hổng bộ nhớ kinh điển theo chuẩn CERT C; và Đối chuẩn thực nghiệm định lượng giữa 3 trường phái Fuzzing: Black-box, Greybox và White-box giải ngược hình thức SMT Z3."*

---

## SLIDE 2: TỔNG QUAN BỐI CẢNH & BỀ MẶT TẤN CÔNG
* **Bố cục thị giác:** Chia 2 cột cân xứng: Cột trái trình bày bối cảnh mạng nhúng/IoT; Cột phải vẽ sơ đồ bề mặt tấn công từ luồng socket mạng vào vùng nhớ ngăn xếp (Stack) và đống (Heap).
* **Tiêu đề Slide:** **Bối Cảnh Nghiên Cứu & Bề Mặt Tấn Công Giao Thức Nhị Phân**
* **Nội dung học thuật:**
  * **Đặc thù giao thức nhị phân:** Được sử dụng phổ biến trong vi điều khiển, thiết bị mạng và cảm biến IoT nhờ ưu thế tối ưu hóa băng thông và độ trễ, nhưng viết bằng C/C++ cấp thấp nên thiếu cơ chế bảo vệ ô nhớ tự động.
  * **Bề mặt tấn công (Attack Surface):** Mọi byte nhận từ luồng mạng không tin cậy (Untrusted Network Input) đều có thể bị kẻ tấn công thao túng cấu trúc để kích hoạt lỗi ô nhớ.
  * **Rủi ro an ninh mạng:** Các lỗi tha hóa ô nhớ (Memory Corruption) dẫn tới tê liệt dịch vụ (DoS) hoặc chiếm quyền điều khiển luồng thực thi (RCE).
* **Điểm nhấn:** Đặt trọng tâm nghiên cứu vào việc kiểm soát an toàn ô nhớ ngay từ tầng phân tích cú pháp (Parser Level).
* **Lời thoại thuyết trình (Speaker Notes — 60s):**  
  *"Trong các hệ thống nhúng và mạng cảm biến IoT, bộ phân tích gói tin nhị phân là chốt chặn phòng thủ đầu tiên. Khi một gói tin được gửi tới, parser phải bóc tách từng byte dữ liệu. Nếu lập trình viên tính toán sai kích thước hoặc giải phóng tài nguyên bất cẩn, kẻ tấn công có thể kiểm soát con trỏ lệnh. Mục tiêu của nhóm là làm rõ bề mặt tấn công này và xây dựng các chốt chặn an toàn triệt để."*

---

## SLIDE 3: CHUỖI TRUY VẾT GÓI TIN THỰC TẾ (TRACEABILITY PIPELINE)
* **Bố cục thị giác:** Sơ đồ dòng chảy 4 bước nằm ngang (Horizontal Flowchart): `PCAP Thực tế` $\to$ `Hex Dump Log` $\to$ `Đặc tả SSOT Excel 10 Sheet` $\to$ `Parser C & Kiểm thử`.
* **Tiêu đề Slide:** **Chuỗi Truy Vết Dữ Liệu Thực Nghiệm (Traceability Pipeline)**
* **Nội dung học thuật:**
  * **Bắt gói tin mạng thật:** Tệp `network_capture/iot_sensor_stream.pcap` ghi lại 24 khung truyền UDP thực tế của cảm biến môi trường.
  * **Trích xuất Hex Dump:** Gói tin số 1 chứa Payload hợp lệ 16B (`TEMP:28C;HUM:65%`); Gói tin số 5 chứa mã lệnh khẩn cấp `0xFF` (`CMD_ABORT_SESSION`).
  * **Đặc tả SSOT 10 Sheet:** `Nhom11_FZP1_Fuzzing_Spec.xlsx` chuẩn hóa 9 yêu cầu chức năng (REQ-1 đến REQ-9), tương thích hoàn toàn với công cụ `SecLabFramework.exe` Tab Ch6 của giảng viên.
  * **Hiện thực hóa mã nguồn:** Ánh xạ chính xác từng yêu cầu REQ vào các nhánh rẽ trong mã nguồn C.
* **Điểm nhấn:** Bảo đảm tính trung thực học thuật 100% — Toàn bộ kịch bản kiểm thử xuất phát từ dữ liệu mạng có thật, được mã băm SHA-256 bảo vệ toàn vẹn.
* **Lời thoại thuyết trình (Speaker Notes — 60s):**  
  *"Nhóm 11 xây dựng đồ án với tính truy vết rất cao: Nhóm không tự nghĩ ra cấu trúc dữ liệu trên lý thuyết mà xuất phát từ tệp bắt gói tin Wireshark PCAP thực tế. Từ gói tin thật, nhóm trích xuất bảng Hex, ánh xạ thành tệp đặc tả SSOT 10 sheet chuẩn SecLab, và chuyển hóa thành mã nguồn bộ phân tích cú pháp C."*

---

## SLIDE 4: ĐỊNH DẠNG GÓI TIN FZP1 & RÀO CẢN NGỮ NGHĨA ĐA TẦNG
* **Bố cục thị giác:** Dải băng phân tách trường byte (Byte Stripe Layout) với màu sắc phân biệt: Header (Xanh Dương), Length (Tím nhạt), Payload (Vàng nhạt), Checksum (Xanh lá).
* **Tiêu đề Slide:** **Cấu Trúc Gói Tin FZP1 & Thách Thức Kiểm Thử Tự Động**
* **Nội dung học thuật:**
  * **[0..3] Magic Header (4B):** Chuỗi định danh bắt buộc `"FZP1"` (`0x46, 0x5A, 0x50, 0x31`).
  * **[4..7] Payload Length (4B):** Số nguyên không dấu 32-bit Little-Endian quy định kích thước dữ liệu $L$.
  * **[8..8+L-1] Payload (L-B):** Dữ liệu cảm biến hoặc mã điều khiển phiên (`0xFF`, `0xFE`).
  * **[8+L] XOR Checksum (1B):** Giá trị kiểm tra tính toàn vẹn: $\text{Checksum} = \bigoplus_{i=0}^{L-1} \text{Payload}[i]$.
  * **Rào cản ngữ nghĩa:** Kích thước tối thiểu 9B. Nếu sai Magic hoặc sai Checksum, gói tin bị loại bỏ ngay từ đầu, tạo ra 'bức tường' ngăn Fuzzer tiếp cận thân hàm.
* **Điểm nhấn:** Tổng kích thước gói tin: $\text{Total Size} = L + 9\text{ bytes}$.
* **Lời thoại thuyết trình (Speaker Notes — 60s):**  
  *"Gói tin FZP1 có kích thước tối thiểu 9 bytes, được bảo vệ bởi 2 chốt chặn: Magic Header 4 bytes và Checksum XOR 1 byte. Nếu một bộ sinh ngẫu nhiên không tính toán lại trường Checksum khớp chính xác với Payload, gói tin sẽ bị từ chối ngay tại dòng lệnh đầu tiên và không bao giờ chạm tới được các đoạn mã xử lý nghiệp vụ bên trong."*

---

## SLIDE 5: MÔ HÌNH HÓA TRẠNG THÁI KRIPKE & THUỘC TÍNH CTL
* **Bố cục thị giác:** Cột trái hiển thị sơ đồ chuyển trạng thái Kripke 4 trạng thái; Cột phải phân tích kết quả kiểm chứng hình thức bằng công thức CTL.
* **Tiêu đề Slide:** **Mô Hình Hóa Trạng Thái Kripke & Kiểm Chứng Thuộc Tính CTL**
* **Nội dung học thuật:**
  * **Cấu trúc Mô hình Kripke $M = (S, S_0, R, L)$:**
    - Trạng thái $s_0$ (`st_idle`): Trạng thái nghỉ sẵn sàng nhận gói tin.
    - Trạng thái $s_1$ (`st_magic_ok`): Xác thực thành công Header.
    - Trạng thái $s_2$ (`st_checksum_ok`): Xác thực thành công tính toàn vẹn Checksum.
    - Trạng thái $s_3$ (`st_conflict`): Trạng thái xung đột nguy hiểm (tiền đề dẫn tới lỗi tràn bộ nhớ).
  * **Kiểm chứng Thuộc tính An toàn CTL:**
    - Thuộc tính an toàn $AG(\neg \text{violation})$: **VI PHẠM (False)** trên $v_0$ (tồn tại đường đi từ $s_0$ kích hoạt đồng thời Magic và Checksum dẫn tới $s_3$).
    - Thuộc tính bất biến trên bản vá $v_1$: $AG(\text{valid\_packet} \implies \text{payload\_len} \le 16)$ đạt trạng thái **ĐÚNG (True)**.
* **Điểm nhấn:** Chứng minh bằng toán học rằng lỗi sập không phải ngẫu nhiên mà là thuộc tính khả đạt trong không gian trạng thái của hệ thống.
* **Lời thoại thuyết trình (Speaker Notes — 60s):**  
  *"Để bảo đảm tính chặt chẽ học thuật, nhóm đã mô hình hóa bộ phân tích bằng đồ thị Kripke. Thuộc tính logic CTL chỉ ra rằng ở phiên bản lỗi v0, thuộc tính an toàn AG(not violation) bị vi phạm, chứng minh trạng thái xung đột bộ nhớ là khả dĩ đạt tới từ trạng thái khởi tạo."*

---

## SLIDE 6: LỖ HỔNG TRỌNG TÂM 1 — CWE-121 (STACK BUFFER OVERFLOW)
* **Bố cục thị giác:** Đồ họa phân tích khung ngăn xếp (Stack Frame), minh họa mảng `stack_buf[16]` bị ghi đè dữ liệu vượt biên phá vỡ Stack Canary và địa chỉ trả về (`RIP`).
* **Tiêu đề Slide:** **Lỗ Hổng Trọng Tâm 1: CWE-121 (Tràn Bộ Đệm Ngăn Xếp)**
* **Nội dung học thuật:**
  * **Vị trí trong mã nguồn:** Hàm `parse_fzp1_payload()` trong `source/fzp1_parser_v0.c`.
  * **Cơ chế ô nhớ:** Cấp phát mảng cục bộ `char stack_buf[16]`. Thực thi `memcpy(stack_buf, payload, len)` mà không có lệnh kiểm tra chặn biên `len <= 16`.
  * **Hành vi binary:** Khi nhận gói tin hợp lệ có độ dài lớn hơn 16 bytes (ví dụ 24B, 64B), dữ liệu tràn ra ngoài phá hủy Canary $\to$ Gây sập với mã lỗi Windows `0xC0000005` (Access Violation) hoặc `0xC0000409`.
  * **Bằng chứng AddressSanitizer:** Ký hiệu shadow byte **`[f3]`** xuất hiện (Stack Right Redzone violation).
* **Điểm nhấn:** Log AddressSanitizer xác thực chính xác tại địa chỉ `0x7ffd98b0a9b0`.
* **Lời thoại thuyết trình (Speaker Notes — 60s):**  
  *"Lỗ hổng đầu tiên là CWE-121 tại hàm parse_fzp1_payload. Do tin tưởng độ dài khai báo trong gói tin, hàm đã sao chép dữ liệu vượt quá kích thước 16 bytes của stack_buf. AddressSanitizer đã bắt trọn lỗi này với mã shadow byte f3, chứng minh vùng đệm bảo vệ bên phải stack frame đã bị xâm phạm."*

---

## SLIDE 7: LỖ HỔNG TRỌNG TÂM 2 — CWE-415 (DOUBLE FREE)
* **Bố cục thị giác:** Sơ đồ khối minh họa chu trình thu hồi ô nhớ Heap: Lời gọi `free(1)` tại nhánh xử lý lỗi và lời gọi `free(2)` tại hàm dọn dẹp `main()`.
* **Tiêu đề Slide:** **Lỗ Hổng Trọng Tâm 2: CWE-415 (Giải Phóng Ô Nhớ Kép)**
* **Nội dung học thuật:**
  * **Vị trí & Lệnh kích hoạt:** Hàm `close_fzp1_session()`, kích hoạt khi nhận byte lệnh `0xFF` (`CMD_ABORT_SESSION`).
  * **Cơ chế ô nhớ:** Nhánh xử lý hủy phiên khẩn cấp gọi `free(g_session->cached_payload)` và `free(g_session)` nhưng **quên không gán con trỏ về `NULL`**. Khi chương trình kết thúc, luồng dọn dẹp trong `main()` tiếp tục gọi giải phóng lần 2.
  * **Hành vi hệ điều hành:** Windows Heap Manager phát hiện chunk ô nhớ đã được đánh dấu giải phóng trước đó $\to$ Ném ngay mã lỗi sập nghiêm trọng `0xC0000374` (STATUS_HEAP_CORRUPTION).
* **Điểm nhấn:** Minh chứng rủi ro kinh điển khi không áp dụng nguyên tắc phòng thủ Idempotent Pointer Reset.
* **Lời thoại thuyết trình (Speaker Notes — 60s):**  
  *"Lỗ hổng thứ hai là Double Free. Khi nhận lệnh 0xFF yêu cầu hủy phiên khẩn cấp, hệ thống giải phóng cấu trúc session nhưng để lại con trỏ trỏ vào vùng nhớ cũ. Khi luồng cleanup của hàm main chạy lại, thao tác free lần thứ hai trên cùng một địa chỉ đã kích hoạt cơ chế tự vệ của Heap Manager và làm sập tiến trình."*

---

## SLIDE 8: LỖ HỔNG TRỌNG TÂM 3 — CWE-416 (USE-AFTER-FREE)
* **Bố cục thị giác:** Sơ đồ 3 giai đoạn ô nhớ Heap: (1) Cấp phát & Ủy nhiệm hàm $\to$ (2) Giải phóng để lại Dangling Pointer $\to$ (3) Heap Reuse & Kích hoạt con trỏ hàm lơ lửng.
* **Tiêu đề Slide:** **Lỗ Hổng Trọng Tâm 3: CWE-416 (Truy Cập Ô Nhớ Sau Khi Giải Phóng)**
* **Nội dung học thuật:**
  * **Vị trí & Lệnh kích hoạt:** Hàm `release_fzp1_stream()`, kích hoạt khi nhận mã lệnh `0xFE` (`CMD_RESET_STREAM`).
  * **Cơ chế ô nhớ:** Giải phóng `g_session` nhưng không gán NULL. Sau đó, mô phỏng ô nhớ bị tiến trình khác cấp phát đè (Heap Reuse), parser tiếp tục gọi con trỏ hàm ủy nhiệm `g_session->stream_callback()`.
  * **Hậu quả an toàn:** Cho phép kẻ tấn công chiếm quyền điều khiển con trỏ lệnh (`RIP/EIP`) hoặc gây sập với mã lỗi `0xC0000005`.
  * **Bằng chứng AddressSanitizer:** Byte giám sát **`[fd]`** xuất hiện (Truy cập ô nhớ Heap Freed).
* **Điểm nhấn:** Minh họa trực quan nguy cơ tiềm tàng của con trỏ hàm (Function Pointer) trong các cấu trúc C.
* **Lời thoại thuyết trình (Speaker Notes — 60s):**  
  *"Lỗ hổng thứ ba là Use-After-Free tại hàm reset stream. Sau khi giải phóng cấu trúc g_session, con trỏ không bị vô hiệu hóa. Khi một luồng khác tái cấp phát ô nhớ này, parser lại kích hoạt con trỏ hàm stream_callback thông qua con trỏ lơ lửng, tạo điều kiện cho các cuộc tấn công kiểm soát luồng điều khiển."*

---

## SLIDE 9: BẢN VÁ AN TOÀN HOÀN THIỆN THEO CHUẨN CERT C ($v_1$)
* **Bố cục thị giác:** 3 Khung Thẻ (Cards) màu Xanh Ngọc nhạt (`#ECFDF5`), viền xanh lá, mỗi khung thể hiện một chuẩn CERT C kèm đoạn mã vá tương ứng.
* **Tiêu đề Slide:** **Triệt Tiêu Lỗ Hổng: Bản Vá An Toàn $v_1$ Tuân Thủ Chuẩn SEI CERT C**
* **Nội dung học thuật:**
  * **1. Vá CWE-121 — Chuẩn CERT STR31-C:**
    - Thiết lập chặn biên cứng: `if (len > 16) return 2;`.
    - Khai báo đệm 17 bytes (`MAX_PAYLOAD_ALLOWED + 1`) bảo đảm luôn có byte kết thúc null `\0`.
  * **2. Vá CWE-415 — Chuẩn CERT MEM31-C:**
    - Nguyên tắc phòng thủ: Ngay sau khi `free(ptr)`, lập tức gán `ptr = NULL;`. Phép dọn dẹp kép trở thành Idempotent an toàn.
  * **3. Vá CWE-416 — Chuẩn CERT MEM30-C:**
    - Đảo ngược thứ tự: Thực thi con trỏ hàm telemetry **trước** khi hủy tài nguyên, sau đó mới `free()` và gán con trỏ về NULL.
* **Điểm nhấn:** Trả về mã lỗi từ chối an toàn có kiểm soát (`Exit Code = 2`), không làm sập chương trình.
* **Lời thoại thuyết trình (Speaker Notes — 60s):**  
  *"Để vá toàn diện 3 lỗ hổng trên ở phiên bản v1, nhóm đã áp dụng nghiêm ngặt các tiêu chuẩn của SEI CERT C: STR31-C để chặn biên bộ đệm chuỗi, MEM31-C để triệt tiêu con trỏ lơ lửng sau khi free, và MEM30-C để đảo ngược thứ tự hủy tài nguyên. Kết quả là bản v1 từ chối dữ liệu bẩn an toàn với mã lỗi 2 mà không xảy ra bất kỳ sự cố sập nào."*

---

## SLIDE 10: MA TRẬN ĐỐI SÁNH TRƯỚC / SAU (TABLE 2 BEFORE / AFTER)
* **Bố cục thị giác:** Bảng đối chiếu 2 cột theo chuẩn `report_guide.pdf`: Tiêu đề Xanh Hải quân, các hàng dữ liệu so le màu trắng / xám nhạt đạt độ tương phản cao.
* **Tiêu đề Slide:** **Bảng Đối Sánh Toàn Diện: Phiên Bản Lỗi ($v_0$) vs Bản Vá An Toàn ($v_1$)**
* **Nội dung học thuật:**

| Tiêu chí Đánh giá | Bản Lỗi Ban Đầu ($v_0$) | Bản Vá An Toàn Hoàn Thiện ($v_1$) | Chuẩn Quốc Tế Áp Dụng |
| :--- | :--- | :--- | :--- |
| **Kiểm soát Biên Stack** | Không kiểm tra `len` $\to$ Ghi đè Canary. | Chặn biên `len <= 16`, đệm 17B có `\0`. | **CERT STR31-C** |
| **Quản lý Con trỏ Heap** | Quên gán NULL $\to$ Lơ lửng (Dangling). | Lập tức gán `ptr = NULL` sau mỗi lần free. | **CERT MEM31-C** |
| **Thứ tự Thu hồi Bộ nhớ**| Free trước, gọi hàm callback sau. | Gọi callback trước, thu hồi và gán NULL sau. | **CERT MEM30-C** |
| **Mã lỗi Phản hồi** | Sập không kiểm soát (`0xC0000005`). | Từ chối an toàn (`Exit Code = 2`). | Error Handling Pattern |
| **AddressSanitizer** | Bắt lỗi tức thời: Shadow `[f3]` & `[fd]`. | 0 findings, 0 warnings, thực thi sạch sẽ. | Dynamic Verification |
| **Tỷ lệ Sống sót Fuzzing**| 90 crashes / 500 gói tin. | **0 crashes / 500 gói tin (100% PASS).** | Robustness |

* **Speaker Notes (60s):**  
  *"Bảng đối sánh Table 2 tổng kết sự khác biệt bản chất giữa v0 và v1. Không chỉ dừng lại ở việc ngăn chặn crash, bản vá v1 đã chuyển đổi toàn bộ cơ chế từ sập bất thường sang từ chối an toàn có kiểm soát, đáp ứng 100% các tiêu chí an toàn phần mềm nghiêm ngặt nhất."*

---

## SLIDE 11: ĐỘNG CƠ FUZZING ĐA TRƯỜNG PHÁI (`ch4_dynafuzz_fzp1.py`)
* **Bố cục thị giác:** Sơ đồ kiến trúc 3 khối module Fuzzing (Black-box, Greybox, White-box) kết nối với Harness điều khiển trên nền tảng Windows Native.
* **Tiêu đề Slide:** **Thiết Kế Động Cơ Fuzzing Đa Trường Phái & Cơ Chế Định Hướng Độ Phủ**
* **Nội dung học thuật:**
  * **Đặc tính kỹ thuật:** Xây dựng bằng Python 3.13 hướng đối tượng, hỗ trợ Windows Native không phụ thuộc Linux/WSL.
  * **Bộ đệm an toàn RAM Guard:** Khống chế payload tối đa 128B, tổng gói tin tối đa 256B, triệt tiêu nguy cơ rò rỉ hoặc tràn bộ nhớ khi chạy lặp dài.
  * **Cơ chế Coverage-guided:**
    - Quản lý hàng đợi hạt giống ưu tiên (**Seed Queue Prioritization**).
    - Mô phỏng mảng Bitmap phản hồi độ phủ biên (Edge Coverage Feedback) gồm **9 nhánh logic** (B0: Quá ngắn, B1: Sai Magic, B4: Sai Checksum, B6: Tràn Stack, B7: Abort, B8: Reset).
* **Điểm nhấn:** Hạt giống mới kích hoạt nhánh sâu tự động lưu vào `seed_corpus/discovered_seeds/`.
* **Lời thoại thuyết trình (Speaker Notes — 60s):**  
  *"Để kiểm thử bộ phân tích cú pháp, nhóm đã thiết kế động cơ ch4_dynafuzz với 3 module độc lập. Điểm nhấn là bộ Greybox Fuzzer có khả năng quản lý hàng đợi hạt giống và theo dõi độ phủ 9 nhánh rẽ logic, tự động lưu lại các mẫu dữ liệu mới kích hoạt đường đi sâu hơn trong mã nguồn C."*

---

## SLIDE 12: RÀO CẢN TOÁN HỌC CỦA BLACK-BOX FUZZING
* **Bố cục thị giác:** Công thức xác suất LaTeX nổi bật ở giữa slide trong khung màu xanh dương nhạt; Đồ thị minh họa không gian tìm kiếm khổng lồ $2^{32}$.
* **Tiêu đề Slide:** **Rào Cản Toán Học Của Kiểm Thử Hộp Đen (Black-Box Fuzzing)**
* **Nội dung học thuật:**
  * **Công thức xác suất đồng thời:** Để một gói tin ngẫu nhiên vượt qua cả 3 chốt chặn gây crash CWE-121:
    $$P(\text{crash}) = P(\text{Magic 'FZP1'}) \times P(16 < \text{len} \le 80) \times P(\text{Checksum XOR})$$
    $$P(\text{crash}) = \frac{1}{2^{32}} \times \frac{64}{2^{32}} \times \frac{1}{2^8} \approx 9.09 \times 10^{-13}$$
  * **Hệ quả thực tế:**
    - Số lần thử kỳ vọng: $E = \frac{1}{P} \approx 1.1 \times 10^{12}$ lượt thử ngẫu nhiên.
    - Với tốc độ 1,000 gói tin/giây, Black-box Fuzzing cần trung bình **34.8 năm** để ngẫu nhiên bắt gặp một lần sập!
  * **Kết luận:** Kiểm thử hộp đen hoàn toàn bất lực trước các giao thức có trường Checksum bảo vệ toàn vẹn.
* **Speaker Notes (60s):**  
  *"Tại sao Black-box Fuzzing lại thất bại hoàn toàn? Phân tích xác suất cho thấy cơ hội để sinh ngẫu nhiên đồng thời đúng Magic 4 byte, độ dài lớn hơn 16 và Checksum XOR 1 byte là xấp xỉ 9 nhân 10 mũ trừ 13. Về mặt toán học, fuzzer hộp đen cần hơn 1 nghìn tỷ lần thử mới có thể tìm thấy lỗi, lý giải vì sao tỷ lệ thành công của nó là 0%."*

---

## SLIDE 13: SỨC MẠNH ĐỘT PHÁ CỦA WHITE-BOX CONCOLIC SMT Z3
* **Bố cục thị giác:** Sơ đồ luồng giải ngược SMT: Thu thập ràng buộc đường đi $\to$ Hệ phương trình Bit-Vector $\to$ Z3 Solver $\to$ Exploit Packet.
* **Tiêu đề Slide:** **White-Box Concolic Fuzzing: Giải Ngược Hình Thức Bằng SMT Z3**
* **Nội dung học thuật:**
  * **Nguyên lý hoạt động:** Mô hình hóa đường đi dẫn tới lỗi dưới dạng hệ phương trình ràng buộc bit-vector trên không gian số thực:
    $$\text{Magic} == \text{'FZP1'} \land \text{Length} > 16 \land \text{Checksum} == \bigoplus_{i=0}^{L-1} \text{Payload}[i]$$
  * **Hiệu năng giải ngược:**
    - Động cơ Z3 5.1.0 giải thành công trạng thái thỏa mãn (SAT) chỉ trong **6.98 mili-giây**.
    - Tổng hợp trực tiếp gói tin khai thác (Exploit Packet) chuẩn xác 100% trong **đúng 1 bước duy nhất**.
  * **Ý nghĩa:** Biến một bài toán mò kim đáy bể với xác suất $10^{-13}$ thành một bài toán giải đại số tất định tức thời.
* **Speaker Notes (60s):**  
  *"Ngược lại với Black-box, White-box Fuzzing kết hợp solver SMT Z3 đã mô hình hóa toàn bộ điều kiện đường đi thành hệ phương trình logic. Thay vì đoán mò, Z3 suy luận ngược và tìm ra nghiệm thỏa mãn chỉ trong 6.98 mili-giây, tổng hợp thành công gói tin kích hoạt crash với độ chính xác tuyệt đối 100%."*

---

## SLIDE 14: KẾT QUẢ THỰC NGHIỆM ĐỐI CHUẨN 30 TRIALS
* **Bố cục thị giác:** Cột trái hiển thị biểu đồ Boxplot phân bố thời gian tìm crash; Cột phải hiển thị biểu đồ Cột so sánh tỷ lệ thành công (Success Rate Bar Chart).
* **Tiêu đề Slide:** **Kết Quả Đối Chuẩn Định Lượng Qua 30 Lần Chạy Độc Lập**
* **Nội dung học thuật:**

| Phương pháp Fuzzing | Tỷ lệ Thành công | Thời gian Tìm Crash (Trung vị) | Số lần Lặp Trung bình | Đánh giá Thực nghiệm |
| :--- | :---: | :---: | :---: | :--- |
| **Black-box Fuzzing** | **0.00%** (0 / 30) | $\infty$ (Timeout 10.0s) | 1,482 lượt thử | Hoàn toàn bất lực trước rào cản Checksum. |
| **Greybox Fuzzing** | **46.67%** (14 / 30) | **2.16 giây** | 428.5 lượt thử | Hiệu quả khá tốt nhờ đột biến hạt giống định hướng. |
| **White-box SMT Z3** | **100.00%** (30 / 30) | **0.21 giây** | **1.0 lần duy nhất** | Vượt trội tuyệt đối về tốc độ và tính tất định. |

* **Speaker Notes (60s):**  
  *"Thực nghiệm đối chuẩn 30 trials độc lập đã chứng minh tính ưu việt của White-box: đạt tỷ lệ thành công 100% với thời gian trung vị chỉ 0.21 giây. Greybox Fuzzer nhận biết cấu trúc đạt 46.67% thành công trong 2.16 giây, trong khi Black-box thuần túy chạm ngưỡng timeout 10 giây ở cả 30 lần chạy."*

---

## SLIDE 15: CHU TRÌNH TIẾN HÓA ĐA GIAI ĐOẠN ($v_0 \to v_1$)
* **Bố cục thị giác:** Biểu đồ phân rã số lượng crash giảm dần qua 4 mốc: $90 \to 58 \to 22 \to 0$ tương ứng với 4 phiên bản C.
* **Tiêu đề Slide:** **Chu Trình Tiến Hóa Vá Lỗi Đa Giai Đoạn & Triệt Tiêu Sự Cố Sập**
* **Nội dung học thuật:**
  * **Mốc 1 ($v_0$ — Bản ban đầu):** Ghi nhận **90 crashes** (42 CWE-121, 26 CWE-415, 22 CWE-416).
  * **Mốc 2 ($v_{0.1}$ — Sau khi vá CERT STR31-C):** Số crash giảm còn **58 crashes** (CWE-121 giảm về 0; còn CWE-415 và 416).
  * **Mốc 3 ($v_{0.2}$ — Sau khi vá tiếp CERT MEM31-C):** Số crash giảm còn **22 crashes** (Chỉ còn lại duy nhất CWE-416).
  * **Mốc 4 ($v_1$ — Bản hoàn thiện toàn diện):** Đạt **0 crashes / 500 gói tin** (100% các gói tin bất thường được xử lý an toàn).
  * **Bài học:** Khẳng định an toàn phần mềm là một chu trình kỹ thuật lặp (Iterative Engineering Lifecycle).
* **Speaker Notes (60s):**  
  *"Theo đúng định hướng của Thầy hướng dẫn, nhóm đã minh chứng quá trình vá lỗi là một chu trình tiến hóa đa giai đoạn. Qua từng phiên bản v0.1 và v0.2, từng loại lỗ hổng lần lượt được triệt tiêu, cho đến khi phiên bản v1 hoàn toàn miễn nhiễm trước toàn bộ 500 gói tin kiểm thử độc hại."*

---

## SLIDE 16: PHÂN TÍCH HIỆN TƯỢNG BỎ LỌT LỖI CỦA CPPCHECK (FALSE NEGATIVE)
* **Bố cục thị giác:** So sánh đối đầu giữa Phân tích tĩnh (Static AST) và Phân tích động (Dynamic Fuzzing + AddressSanitizer).
* **Tiêu đề Slide:** **Giới Hạn Của Phân Tích Tĩnh: Bài Học Từ Hiện Tượng Bỏ Lọt Lỗi Của Cppcheck**
* **Nội dung học thuật:**
  * **Kết quả thực tế:** Cppcheck 2.18 quét `fzp1_parser_v0.c` trả về kết quả: `0 error, 0 warning` $\to$ Bỏ lọt hoàn toàn lỗi CWE-121 (False Negative).
  * **Nguyên nhân kỹ thuật:** Cppcheck chỉ phân tích cú pháp tĩnh cục bộ (Local AST). Biến `len` được đọc động từ luồng mạng tại thời điểm runtime (`read_uint32_le`).
  * **Khoảng trống bảo mật:** Nếu không có cơ chế phân tích dữ liệu bẩn liên hàm (Inter-procedural Taint Analysis), công cụ tĩnh không thể biết trước `len > 16` khi biên dịch.
  * **Kết luận:** Khẳng định vai trò sống còn và không thể thay thế của Dynamic Fuzzing và AddressSanitizer.
* **Speaker Notes (60s):**  
  *"Một phát hiện thú vị trong đề tài là công cụ phân tích tĩnh Cppcheck đã hoàn toàn bỏ lọt lỗi tràn bộ đệm ở bản v0. Nguyên nhân là do biến độ dài được đọc động từ mạng. Điều này chứng minh rằng các công cụ quét mã tĩnh không thể thay thế được kiểm thử mờ động và AddressSanitizer trong thực tế."*

---

## SLIDE 17: PHẢN BIỆN HỌC THUẬT & 3 BÀI HỌC CỐT LÕI
* **Bố cục thị giác:** 3 Khung Card học thuật trả lời trực diện 3 câu hỏi bắt buộc trong Hướng dẫn làm báo cáo của Giảng viên.
* **Tiêu đề Slide:** **Phản Biện Học Thuật: Trả Lời 3 Câu Hỏi Bắt Buộc Của Đề Tài**
* **Nội dung học thuật:**
  * **1. Thiết kế lại phần nào để tránh lỗi từ đầu?**
    - Áp dụng kiến trúc đóng gói **Type-Length-Value (TLV)** với kích thước kiểu dữ liệu nghiêm ngặt.
    - Sử dụng cơ chế cấp phát tập trung **Arena / Region-based Memory Allocator** cho toàn phiên: Giải phóng 1 lần duy nhất khi đóng phiên, triệt tiêu 100% nguy cơ Double Free và Use-After-Free.
  * **2. Lỗ hổng nghi ngờ còn tồn tại?**
    - Nguy cơ cạn kiệt tài nguyên (Resource Exhaustion / DoS): Gửi liên tục các gói tin lớn hợp lệ trong ngưỡng cho phép (64KB) mà không đóng phiên làm cạn kiệt bộ nhớ Heap.
  * **3. Bài học phương pháp luận lớn nhất?**
    - *Kiểm thử hộp đen chỉ tìm thấy lỗi bề mặt; kiểm chứng hình thức SMT và phân tích động mới là chìa khóa thâm nhập vào các trạng thái suy biến sâu của hệ thống.*
* **Speaker Notes (60s):**  
  *"Tại Mục 7 của báo cáo, nhóm đã đúc rút 3 bài học phản biện sâu sắc: Để tránh lỗi từ đầu, ta nên dùng bộ cấp phát vùng Arena Allocator để triệt tiêu lỗi quản lý Heap; cần cảnh giác trước nguy cơ tấn công cạn kiệt tài nguyên; và bài học lớn nhất là chỉ có sự kết hợp giữa suy luận hình thức và kiểm thử mờ mới bảo đảm an toàn toàn diện."*

---

## SLIDE 18: TỔNG KẾT, NGHIỆM THU & PHIÊN HỎI ĐÁP (Q&A)
* **Bố cục thị giác:** Bảng tóm tắt nghiệm thu 8 khâu đạt `PASS 100%` với các huy hiệu xanh lá cây; Thông tin liên hệ kho lưu trữ GitHub và mã QR báo cáo.
* **Tiêu đề Slide:** **Tổng Kết Đồ Án & Sẵn Sàng Trả Lời Phản Biện**
* **Nội dung học thuật:**
  * **Kết quả nghiệm thu kỹ thuật:**
    - 8 / 8 Khâu kiểm định tự động đạt chuẩn tuyệt đối (**PASS 100%**).
    - 14 / 14 Ca kiểm thử tự động PyTest vượt qua trong 7.36 giây.
    - Bản vá hoàn thiện $v_1$ sống sót 100% trước 500 gói tin tấn công.
  * **Sản phẩm bàn giao:** Báo cáo đồ án 57 trang (chuẩn Times New Roman 13pt, dãn dòng 1.5), kho mã nguồn sạch sẽ trên GitHub, gói nén 5.67 MB sẵn sàng nộp.
  * **Nhóm 11 xin chân thành cảm ơn Thầy và Hội đồng!** Sẵn sàng tiếp nhận các câu hỏi phản biện.
* **Speaker Notes (60s):**  
  *"Toàn bộ mã nguồn, dữ liệu thực nghiệm 30 trials và báo cáo 57 trang của Nhóm 11 đã được đồng bộ và kiểm định đạt PASS 100%. Nhóm xin chân thành cảm ơn sự hướng dẫn tận tình của ThS. Vũ Quang Dũng trong suốt học phần và xin kính mời Thầy cùng Hội đồng đặt câu hỏi cho nhóm. Xin trân trọng cảm ơn!"*
