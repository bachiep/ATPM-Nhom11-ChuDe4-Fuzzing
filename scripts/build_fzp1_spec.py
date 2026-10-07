import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
import os

wb = openpyxl.Workbook()
wb.remove(wb.active)

header_font = Font(name='Calibri', size=11, bold=True, color='FFFFFF')
header_fill = PatternFill(start_color='1F4E78', end_color='1F4E78', fill_type='solid')
thin_border = Border(
    left=Side(style='thin', color='D9D9D9'),
    right=Side(style='thin', color='D9D9D9'),
    top=Side(style='thin', color='D9D9D9'),
    bottom=Side(style='thin', color='D9D9D9')
)

def style_sheet(ws, headers, data):
    ws.append(headers)
    for col_num, h in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_num)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal='center', vertical='center')
    
    for row_data in data:
        ws.append(row_data)
        
    for row in ws.iter_rows(min_row=2, max_row=len(data)+1, min_col=1, max_col=len(headers)):
        for cell in row:
            cell.border = thin_border
            cell.alignment = Alignment(vertical='center')

# 1. Sheet: ThongTin
ws1 = wb.create_sheet('ThongTin')
style_sheet(ws1, ['Truong', 'GiaTri'], [
    ['name', 'fzp1_binary_parser'],
    ['description', 'Bộ phân tích cú pháp file nhị phân FZP1 phục vụ kiểm thử Fuzzing và kiểm chứng hình thức']
])

# 2. Sheet: YeuCauChucNang (9 requirements, all 4 categories)
ws2 = wb.create_sheet('YeuCauChucNang')
style_sheet(ws2, ['ID', 'MoTa', 'DanhMuc', 'MucUuTien'], [
    ['REQ-FZ-01', 'Hệ thống phải xác thực chính xác 4 byte Magic Number "FZP1" ở đầu tệp nhị phân trước khi giải mã', 'safety', 'HIGH'],
    ['REQ-FZ-02', 'Bộ phân tích cú pháp FZP1 không được rơi vào bế tắc (deadlock-free) trong mọi chu trình xử lý tệp', 'liveness', 'HIGH'],
    ['REQ-FZ-03', 'Hàm parse_fzp1_payload() khi giải mã payload phải sao chép an toàn vào bộ đệm stack cố định 16 byte', 'memory', 'HIGH'],
    ['REQ-FZ-04', 'Bộ đệm tệp nhị phân cấp phát trên heap phải được giải phóng đúng sau khi phân tích hoàn tất', 'memory', 'MEDIUM'],
    ['REQ-FZ-05', 'Hàm đóng phiên giải mã tệp không được giải phóng bộ nhớ hai lần (CWE-415 double-free)', 'memory', 'HIGH'],
    ['REQ-FZ-06', 'Con trỏ bộ đệm sau khi giải phóng không được tái sử dụng (CWE-416 use-after-free)', 'memory', 'HIGH'],
    ['REQ-FZ-07', 'Bộ tích lũy dung lượng byte đã xử lý không được vượt giới hạn tràn số nguyên 32-bit (CWE-190)', 'safety', 'MEDIUM'],
    ['REQ-FZ-08', 'Hàm tính toán tỷ lệ tệp hợp lệ calculate_fzp1_ratio() không được gây lỗi chia cho không', 'functional', 'MEDIUM'],
    ['REQ-FZ-09', 'Cơ chế xác thực khóa bí mật verify_fzp1_unlock_token() phải kiểm tra chính xác cặp token 16-bit', 'functional', 'LOW']
])

# 3. Sheet: YeuCauPhiChucNang (5 NFRs with quantitative metrics)
ws3 = wb.create_sheet('YeuCauPhiChucNang')
style_sheet(ws3, ['ID', 'MoTa', 'MucUuTien'], [
    ['NFR-FZ-01', 'Bộ parser FZP1 phải đạt thông lượng xử lý tối thiểu 1000 tệp nhị phân mỗi giây trên CPU thử nghiệm', 'MEDIUM'],
    ['NFR-FZ-02', 'Thời gian phân tích hợp lệ và kiểm tra checksum mỗi tệp trung bình dưới 2ms', 'MEDIUM'],
    ['NFR-FZ-03', 'Nhật ký kiểm toán giải mã tệp nhị phân phải được ghi đồng bộ nguyên tử không làm mất log', 'HIGH'],
    ['NFR-FZ-04', 'Mức tiêu thụ bộ nhớ RAM tối đa của bộ parser FZP1 không vượt quá 32KB', 'MEDIUM'],
    ['NFR-FZ-05', 'Tỷ lệ lỗi không xác định (unhandled exceptions) trong quá trình fuzzing phải là 0%', 'LOW']
])

# 4. Sheet: RangBuoc (5 constraints)
ws4 = wb.create_sheet('RangBuoc')
style_sheet(ws4, ['ID', 'MoTa', 'MucUuTien'], [
    ['CON-FZ-01', 'Tệp nhị phân phải tuân thủ nghiêm ngặt cấu trúc FZP1: 4B Magic | 1B Length | N-B Payload | 1B XOR Checksum', 'HIGH'],
    ['CON-FZ-02', 'Vùng đệm xử lý payload cục bộ trên stack frame có kích thước cố định 16 byte (Buffer_Size = 16)', 'HIGH'],
    ['CON-FZ-03', 'Mã mở khóa khẩn cấp FZP1 phải là cặp số nguyên 16-bit dương cố định', 'MEDIUM'],
    ['CON-FZ-04', 'Tổng chiều dài toàn bộ tệp nhị phân đầu vào không được vượt quá 256 byte', 'HIGH'],
    ['CON-FZ-05', 'Toàn bộ mã nguồn C xử lý phân tích cú pháp FZP1 phải biên dịch sạch theo chuẩn ISO C99', 'MEDIUM']
])

# 5. Sheet: MoHinhTrangThai (4 states, no deadlocks, violation label)
ws5 = wb.create_sheet('MoHinhTrangThai')
style_sheet(ws5, ['TrangThai', 'KhoiTao', 'Nhan', 'ChuyenDenCacTrangThai'], [
    ['st_idle', 'x', 'safe, ready', 'st_magic_valid, st_checksum_valid'],
    ['st_magic_valid', '', 'magic_ok', 'st_idle, st_overflow_hazard'],
    ['st_checksum_valid', '', 'checksum_ok', 'st_idle'],
    ['st_overflow_hazard', '', 'magic_ok, checksum_ok, violation', 'st_idle']
])

# 6. Sheet: ThuocTinhAnToan (Atomic propositions supported by SecLab CTLChecker)
ws6 = wb.create_sheet('ThuocTinhAnToan')
style_sheet(ws6, ['CongThucCTL'], [
    ['AG(!violation)'],
    ['EF(magic_ok)'],
    ['EF(checksum_ok)'],
    ['EF(violation)'],
    ['AF(safe)']
])

# 7. Sheet: LoaiTruLanNhau (Single primary mutual exclusion pair per SecLab schema)
ws7 = wb.create_sheet('LoaiTruLanNhau')
style_sheet(ws7, ['MenhDe1', 'MenhDe2'], [
    ['magic_ok', 'checksum_ok']
])

# 8. Sheet: HamSinhMa (6 functions covering all required bug classes)
ws8 = wb.create_sheet('HamSinhMa')
style_sheet(ws8, ['Ten', 'NgonNgu', 'Loai', 'ThamSo', 'KichThuocBuffer', 'Loi', 'GiaTriBiMat1', 'GiaTriBiMat2'], [
    ['parse_fzp1_payload', 'c', 'buffer_copy', 'raw_payload', 16, 'buffer-overflow', '1234', '5678'],
    ['alloc_fzp1_cache', 'c', 'alloc_release', '', 32, 'memory-leak', '1234', '5678'],
    ['close_fzp1_session', 'c', 'alloc_release', '', 4, 'double-free', '1234', '5678'],
    ['release_fzp1_stream', 'c', 'alloc_release', '', 8, 'use-after-free', '1234', '5678'],
    ['calculate_fzp1_ratio', 'python', 'divide', 'valid_files, total_files', 16, '', '1234', '5678'],
    ['verify_fzp1_unlock_token', 'python', 'magic_value', 'token_a, token_b', 16, '', '18010', '20529']
])

# 9. Sheet: KiemTraSoHoc (5 rows with Z3 thresholds)
ws9 = wb.create_sheet('KiemTraSoHoc')
style_sheet(ws9, ['Ten', 'BienSoNguyen', 'DieuKien', 'BieuThucTran'], [
    ['fzp1_checksum_accumulator', 'header_sum, payload_sum', 'header_sum >= 0 and payload_sum >= 0 and header_sum <= 32767 and payload_sum <= 32767', 'header_sum + payload_sum'],
    ['fzp1_file_counter', 'rx_files, tx_files', 'rx_files >= 0 and tx_files >= 0 and rx_files <= 65535 and tx_files <= 65535', 'rx_files + tx_files'],
    ['fzp1_byte_accumulator', 'header_bytes, payload_bytes', 'header_bytes >= 0 and payload_bytes >= 0 and header_bytes <= 2147483647 and payload_bytes <= 2147483647', 'header_bytes + payload_bytes'],
    ['fzp1_duration_timer', 'parse_time_ms, verify_time_ms', 'parse_time_ms >= 0 and verify_time_ms >= 0 and parse_time_ms <= 65535 and verify_time_ms <= 65535', 'parse_time_ms + verify_time_ms'],
    ['fzp1_drop_counter', 'corrupt_magic_drops, bad_checksum_drops', 'corrupt_magic_drops >= 0 and bad_checksum_drops >= 0 and corrupt_magic_drops <= 32767 and bad_checksum_drops <= 32767', 'corrupt_magic_drops + bad_checksum_drops']
])

# 10. Sheet: TestCase (8 IEEE 829 test cases)
ws10 = wb.create_sheet('TestCase')
style_sheet(ws10, ['ID', 'YeuCauLienQuan', 'TieuDe', 'DieuKienTienQuyet', 'CacBuoc', 'KetQuaMongDoi', 'MucUuTien'], [
    ['TC-FZ-01', 'REQ-FZ-01, REQ-FZ-02', 'Kiểm chứng xung đột giữa giải mã Magic và Checksum', "Hệ thống ở trạng thái 'st_idle'", '1. Luồng phân tích nạp magic header\n2. Luồng kiểm tra checksum nạp tệp\n3. Kiểm tra công thức CTL', 'AG(!violation) ĐÚNG và không có trạng thái deadlock', 'HIGH'],
    ['TC-FZ-02', 'REQ-FZ-03, CON-FZ-02', 'Kiểm thử lỗi tràn bộ đệm stack khi payload_len > 16 byte', 'Hàm parse_fzp1_payload() sinh từ đặc tả', '1. Nạp tệp FZP1 có payload_len=24 byte\n2. Thực thi hàm sao chép strcpy\n3. Quan sát vi phạm ô nhớ', 'Phát hiện cảnh báo dangerous-function (CWE-121 Stack Buffer Overflow)', 'HIGH'],
    ['TC-FZ-03', 'REQ-FZ-04, REQ-FZ-05, REQ-FZ-06', 'Kiểm tra chu kỳ cấp phát và giải phóng tài nguyên heap', 'Các hàm alloc_fzp1_cache, close_fzp1_session, release_fzp1_stream', '1. Gộp toàn bộ mã C của các hàm quản lý tài nguyên\n2. Chạy bộ phân tích bộ nhớ tĩnh Memory Analyzer\n3. Kiểm tra vòng đời con trỏ', 'Phát hiện đủ 3 lớp lỗ hổng bộ nhớ: Rò rỉ (CWE-401), Free 2 lần (CWE-415), UAF (CWE-416)', 'HIGH'],
    ['TC-FZ-04', 'REQ-FZ-07', 'Kiểm chứng nguy cơ tràn số nguyên 32-bit trên bộ đếm byte', 'Hai biến header_bytes và payload_bytes >= 0', '1. Thiết lập ràng buộc SMT Z3 Bit-Vector 32-bit\n2. Thực thi hàm check_int32_overflow()\n3. Trích xuất nghiệm SAT', 'Z3 Solver trả về kết quả SAT cùng nghiệm minh chứng nguy cơ tràn số nguyên', 'MEDIUM'],
    ['TC-FZ-05', 'REQ-FZ-08', 'Fuzzing hộp đen hàm tính tỷ lệ tệp hợp lệ', 'Hàm Python calculate_fzp1_ratio(valid_files, total_files)', '1. Chạy blackbox_fuzz() ngẫu nhiên 300 lượt\n2. Sinh ngẫu nhiên tham số đầu vào\n3. Kiểm tra ngoại lệ ZeroDivisionError', 'Tìm thấy ít nhất 1 đầu vào có total_files=0 kích hoạt ZeroDivisionError', 'MEDIUM'],
    ['TC-FZ-06', 'REQ-FZ-09, CON-FZ-03', 'Kiểm thử Concolic giải ngược cặp token mở khóa khẩn cấp', 'Hàm Python verify_fzp1_unlock_token(token_a, token_b)', '1. Thu thập điều kiện nhánh qua Symbolic Execution\n2. Chạy concolic_fuzz() với Z3 SMT Solver\n3. Trích xuất cặp nghiệm thỏa mãn', 'Thuật toán Concolic giải hệ phương trình tìm ra token_a=18010, token_b=20529 sau 1 bước', 'LOW'],
    ['TC-FZ-07', 'NFR-FZ-01, NFR-FZ-02, CON-FZ-01', 'Kiểm định thông lượng phân tích tệp nhị phân FZP1', 'Tập dữ liệu kiểm thử 1000 tệp nhị phân chuẩn', '1. Nạp tập seed corpus 1000 tệp FZP1\n2. Đo thời gian phân tích và kiểm tra checksum\n3. Tính toán thông lượng trung bình', 'Hệ thống đạt thông lượng >= 1000 tệp/s (NFR-FZ-01) và thời gian phản hồi < 2ms (NFR-FZ-02)', 'MEDIUM'],
    ['TC-FZ-08', 'NFR-FZ-04, CON-FZ-04, CON-FZ-05', 'Kiểm tra mức tiêu thụ RAM và biên dịch theo chuẩn C99', 'Môi trường thực thi parser biên dịch bằng Clang -O2', '1. Biên dịch mã nguồn với -std=c99 -Wall -Wextra\n2. Nạp tệp nhị phân có kích thước cực đại 256 byte\n3. Giám sát dung lượng RAM tiêu thụ', 'Dung lượng RAM tiêu thụ không vượt quá 32KB (NFR-FZ-04) và mã nguồn biên dịch sạch cảnh báo', 'LOW']
])

out_dir = r'I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\specification'
os.makedirs(out_dir, exist_ok=True)
out_path = os.path.join(out_dir, 'Nhom11_FZP1_Fuzzing_Spec.xlsx')
wb.save(out_path)
print('Successfully saved specification to:', out_path)
