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

# 1. ThongTin
ws1 = wb.create_sheet('ThongTin')
style_sheet(ws1, ['Truong', 'GiaTri'], [
    ['name', 'packet_security_parser'],
    ['description', 'He thong phan tich goi tin mang va quan ly phien an toan tren thiet bi nhung']
])

# 2. YeuCauChucNang (8 requirements)
ws2 = wb.create_sheet('YeuCauChucNang')
style_sheet(ws2, ['ID', 'MoTa', 'DanhMuc', 'MucUuTien'], [
    ['REQ-1', 'He thong phai co lap tien trinh xu ly goi tin va luong ghi log, khong de xay ra xung dot khoa', 'safety', 'HIGH'],
    ['REQ-2', 'Trang thai xu ly khong duoc roi vao be tac (deadlock-free) trong moi chu trinh van hanh', 'liveness', 'HIGH'],
    ['REQ-3', 'Ham phan tich ma dinh danh goi tin phai sao chep an toan vao bo dem co dinh 16 byte', 'memory', 'HIGH'],
    ['REQ-4', 'Bo dem nhat ky kiem toan phai duoc giai phong dung sau khi hoan tat phien lam viec', 'memory', 'MEDIUM'],
    ['REQ-5', 'Ham dong phien khong duoc giai phong bo nho hai lan (double-free)', 'memory', 'HIGH'],
    ['REQ-6', 'Con tro bo dem sau khi giai phong khong duoc phep tai su dung (use-after-free)', 'memory', 'HIGH'],
    ['REQ-7', 'Bo dem dung luong byte goi tin khong duoc vuot gioi han tran so nguyen int32', 'functional', 'MEDIUM'],
    ['REQ-8', 'Ham tinh ty le goi tin rot khong duoc gay loi chia cho khong (ZeroDivisionError)', 'functional', 'MEDIUM']
])

# 3. YeuCauPhiChucNang (4 NFRs)
ws3 = wb.create_sheet('YeuCauPhiChucNang')
style_sheet(ws3, ['ID', 'MoTa', 'MucUuTien'], [
    ['NFR-1', 'Thoi gian phan hoi trung binh khi phan tich tieu de goi tin khong vuot qua 5ms', 'MEDIUM'],
    ['NFR-2', 'Dung luong bo nho RAM chiem dung tinh cua module parser phai duoi 64KB', 'HIGH'],
    ['NFR-3', 'Nhat ky kiem toan he thong phai duoc ghi dong bo nguyen tu de chong mat du lieu', 'HIGH'],
    ['NFR-4', 'He thong phai co kha nang tu phuc hoi trang thai an toan trong vong 10ms sau su co', 'MEDIUM']
])

# 4. RangBuoc (4 constraints)
ws4 = wb.create_sheet('RangBuoc')
style_sheet(ws4, ['ID', 'MoTa', 'MucUuTien'], [
    ['CON-1', 'Toan bo parser loi chi duoc su dung thu vien chuan C (ISO C99), khong phu thuoc thu vien ngoai', 'HIGH'],
    ['CON-2', 'Vung dem xu ly tieu de cuc bo tren stack co kich thuoc co dinh 16 byte', 'HIGH'],
    ['CON-3', 'Ma xac thuc bao mat phien lam viec phai la cap so nguyen 16-bit co dinh', 'MEDIUM'],
    ['CON-4', 'He thong phai tuong thich va ho tro bien dich tren ca kien truc x86_64 va ARM32', 'MEDIUM']
])

# 5. MoHinhTrangThai
ws5 = wb.create_sheet('MoHinhTrangThai')
style_sheet(ws5, ['TrangThai', 'KhoiTao', 'Nhan', 'ChuyenDenCacTrangThai'], [
    ['s_idle', 'x', 'safe', 's_rx, s_log'],
    ['s_rx', '', 'rx_locked', 's_idle, s_conflict'],
    ['s_log', '', 'log_locked', 's_idle'],
    ['s_conflict', '', 'rx_locked, log_locked, violation', 's_idle']
])

# 6. ThuocTinhAnToan
ws6 = wb.create_sheet('ThuocTinhAnToan')
style_sheet(ws6, ['CongThucCTL'], [
    ['AG(!violation)'],
    ['EF(rx_locked)'],
    ['AG(EF(safe))']
])

# 7. LoaiTruLanNhau
ws7 = wb.create_sheet('LoaiTruLanNhau')
style_sheet(ws7, ['MenhDe1', 'MenhDe2'], [
    ['rx_locked', 'log_locked']
])

# 8. HamSinhMa (6 functions covering CWE-121, 401, 415, 416, divide, magic_value)
ws8 = wb.create_sheet('HamSinhMa')
style_sheet(ws8, ['Ten', 'NgonNgu', 'Loai', 'ThamSo', 'KichThuocBuffer', 'Loi', 'GiaTriBiMat1', 'GiaTriBiMat2'], [
    ['parse_packet_header', 'c', 'buffer_copy', 'raw_header', 16, 'buffer-overflow', None, None],
    ['record_audit_log', 'c', 'alloc_release', None, 32, 'memory-leak', None, None],
    ['close_packet_session', 'c', 'alloc_release', None, 4, 'double-free', None, None],
    ['release_payload_cache', 'c', 'alloc_release', None, 8, 'use-after-free', None, None],
    ['calc_packet_loss', 'python', 'divide', 'lost_packets, total_packets', 16, None, None, None],
    ['verify_security_token', 'python', 'magic_value', 'token_a, token_b', 16, None, 4129, 8763]
])

# 9. KiemTraSoHoc (SMT int32 overflow)
ws9 = wb.create_sheet('KiemTraSoHoc')
style_sheet(ws9, ['Ten', 'BienSoNguyen', 'DieuKien', 'BieuThucTran'], [
    ['packet_byte_counter', 'rx_bytes, queued_bytes', 'rx_bytes >= 0 and queued_bytes >= 0', 'rx_bytes + queued_bytes']
])

# 10. TestCase (6 IEEE 829 test cases)
ws10 = wb.create_sheet('TestCase')
style_sheet(ws10, ['ID', 'YeuCauLienQuan', 'TieuDe', 'DieuKienTienQuyet', 'CacBuoc', 'KetQuaMongDoi', 'MucUuTien'], [
    ['TC-1', 'REQ-1, REQ-2', 'Kiem tra loai tru lan nhau giua luong nhan va luong log', "He thong o trang thai 's_idle'", '1. Luong nhan xin khoa s_rx\n2. Luong log xin khoa s_log\n3. Kiem tra CTL', 'AG(!violation) DUNG va khong co deadlock', 'HIGH'],
    ['TC-2', 'REQ-3', 'Kiem tra tran bo dem stack voi tieu de goi tin > 16 byte', 'Ham parse_packet_header() sinh tu dac ta', '1. Truyen chuoi tieu de 32 byte\n2. Sao chep bang strcpy\n3. Quan sat crash', 'Phat hien loi dangerous-function (CWE-121 Stack Buffer Overflow)', 'HIGH'],
    ['TC-3', 'REQ-4, REQ-5, REQ-6', 'Kiem tra vong doi quan ly bo nho dong', 'Cac ham record_audit_log, close_packet_session, release_payload_cache', '1. Gop ma nguon C\n2. Quet bang Memory Analyzer\n3. Kiem tra con tro', 'Phat hien day du 3 loai loi: memory-leak (CWE-401), double-free (CWE-415), use-after-free (CWE-416)', 'HIGH'],
    ['TC-4', 'REQ-7', 'Kiem tra tran so nguyen tren bo dem byte du lieu', 'rx_bytes, queued_bytes >= 0', '1. Thiet lap rang buoc SMT Z3\n2. Kiem tra bieu thuc rx_bytes + queued_bytes > INT32_MAX', 'Ket qua SAT (xac nhan co the tran so nguyen int32)', 'MEDIUM'],
    ['TC-5', 'REQ-8', 'Black-box Fuzzing tren ham tinh ty le goi tin rot', 'Ham calc_packet_loss(lost_packets, total_packets)', '1. Chay blackbox_fuzz() 300 lan\n2. Phat sinh ngau nhien tham so', 'Phat hien it nhat 1 crash ZeroDivisionError khi total_packets=0', 'MEDIUM'],
    ['TC-6', 'REQ-3', 'White-box Concolic Fuzzing giai ma token bao mat bi mat', 'Ham verify_security_token(token_a, token_b)', '1. Thu thap path constraints\n2. Dung Z3 SMT Solver dao nguoc dieu kien\n3. Giai token bi mat', 'Z3 giai thanh cong token_a=4129, token_b=8763 sau 1 iteration (~12ms)', 'HIGH']
])

out_dir = r'I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\specification'
os.makedirs(out_dir, exist_ok=True)
out_path = os.path.join(out_dir, 'Nhom11_Packet_Security_Parser_Spec.xlsx')
wb.save(out_path)
print('Successfully saved:', out_path)
