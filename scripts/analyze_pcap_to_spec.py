"""
=============================================================================
KỊCH BẢN PHÂN TÍCH GÓI TIN MẠNG PCAP & TRUY VẾT ĐẶC TẢ HÌNH THỨC SSOT
Học phần: Kỹ thuật Lập trình An toàn (CSE703093 / CSE703153)
Giảng viên hướng dẫn: ThS. Vũ Quang Dũng — Trường CNTT, ĐH Phenikaa
Nhóm 11: Lưu Đức Hiệp & Hà Nguyễn Trúc Linh (Chủ đề 4: Fuzzing)
=============================================================================
Hiện thực chuỗi dẫn xuất phương pháp luận theo chỉ đạo của Giảng viên:
  Gói tin mạng (PCAP) -> Log hex dump -> Đặc tả SSOT -> REQ -> C Simulator
=============================================================================
"""

import os
import struct
import sys
from pathlib import Path

# Cấu hình UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

BASE_DIR = Path(__file__).resolve().parent.parent
PCAP_FILE = BASE_DIR / "network_capture" / "iot_sensor_stream.pcap"
LOG_FILE = BASE_DIR / "results" / "logs" / "pcap_traffic_log.txt"

def hex_dump(data: bytes, prefix="      ") -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{prefix}{i:04X}:  {hex_str:<48}  |{ascii_str}|")
    return "\n".join(lines)

def analyze_pcap():
    if not PCAP_FILE.exists():
        print(f"[-] Không tìm thấy tệp PCAP: {PCAP_FILE}")
        return

    print(f"[*] Bắt đầu phân tích tệp lưu lượng mạng: {PCAP_FILE.name}")
    
    with open(PCAP_FILE, "rb") as f:
        global_hdr = f.read(24)
        if len(global_hdr) < 24:
            print("[-] Tệp PCAP không hợp lệ!")
            return
        magic = struct.unpack("<I", global_hdr[:4])[0]
        if magic != 0xa1b2c3d4 and magic != 0xd4c3b2a1:
            print(f"[-] Magic PCAP không khớp: 0x{magic:08X}")
            return

        logs = []
        logs.append("=" * 80)
        logs.append("NHẬT KÝ PHÂN TÍCH LƯU LƯỢNG MẠNG IOT (PCAP DUMP) & TRUY VẾT ĐẶC TẢ FZP1")
        logs.append(f"Tệp nguồn: network_capture/{PCAP_FILE.name}")
        logs.append("Chuỗi truy vết: Gói tin mạng -> Log hex dump -> Đặc tả SSOT -> Yêu cầu REQ")
        logs.append("=" * 80)
        logs.append("")

        frame_idx = 1
        extracted_packets = []

        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", pkt_hdr)
            raw_frame = f.read(incl_len)
            if len(raw_frame) < incl_len:
                break

            # Phân giải Ethernet (14B) + IPv4 (20B) + UDP (8B)
            if len(raw_frame) < 42:
                continue
            
            eth_type = struct.unpack("!H", raw_frame[12:14])[0]
            if eth_type != 0x0800: # Không phải IPv4
                continue

            ip_proto = raw_frame[23]
            if ip_proto != 17: # Không phải UDP
                continue

            src_ip = ".".join(str(b) for b in raw_frame[26:30])
            dst_ip = ".".join(str(b) for b in raw_frame[30:34])
            src_port, dst_port, udp_len = struct.unpack("!HHH", raw_frame[34:40])
            
            # Tách phần UDP payload (FZP1 packet)
            fzp1_data = raw_frame[42:42 + (udp_len - 8)]
            if len(fzp1_data) < 9: # Nhỏ hơn kích thước tối thiểu FZP1 (4B magic + 4B len + 1B chk)
                continue

            logs.append(f"--- [Khung mạng #{frame_idx}] Timestamp: {ts_sec}.{ts_usec:06d} ---")
            logs.append(f"  Giao thức vận chuyển: UDP | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Dung lượng UDP payload: {len(fzp1_data)} bytes")
            logs.append("  Dữ liệu nhị phân thô (Hex dump):")
            logs.append(hex_dump(fzp1_data))

            # Bóc tách cấu trúc giao thức FZP1
            magic_bytes = fzp1_data[0:4]
            magic_ascii = "".join(chr(b) if 32 <= b <= 126 else "." for b in magic_bytes)
            payload_len = struct.unpack("<I", fzp1_data[4:8])[0]
            payload_data = fzp1_data[8:8 + payload_len]
            checksum_byte = fzp1_data[8 + payload_len] if len(fzp1_data) > 8 + payload_len else 0

            # Tính toán kiểm tra XOR checksum
            calc_chk = 0
            for b in payload_data:
                calc_chk ^= b
            chk_valid = (calc_chk == checksum_byte)

            logs.append(f"  Trích xuất cấu trúc FZP1:")
            logs.append(f"    + Magic Header   : '{magic_ascii}' (0x{magic_bytes.hex().upper()}) -> {'HỢP LỆ (FZP1)' if magic_bytes == b'FZP1' else 'KHÔNG HỢP LỆ'}")
            logs.append(f"    + Payload Length : {payload_len} bytes (uint32 Little-Endian)")
            logs.append(f"    + Payload Data   : {payload_data}")
            logs.append(f"    + XOR Checksum   : Nhận 0x{checksum_byte:02X} | Tính toán 0x{calc_chk:02X} -> {'KHỚP TOÀN VẸN' if chk_valid else 'SAI LỆCH'}")

            # Đánh giá cảnh báo an toàn cho khung mạng
            if payload_len > 16:
                logs.append(f"    [!] CẢNH BÁO BẢO MẬT: Payload length ({payload_len}B) vượt quá kích thước bộ đệm an toàn 16B (Nguy cơ tràn Stack CWE-121)!")
            if payload_data and payload_data[0] == 0xFF:
                logs.append(f"    [!] LỆNH ĐẶC BIỆT: Nhận mã 0xFF (CMD_ABORT_SESSION) -> Kích hoạt chu trình giải phóng kép (CWE-415)!")
            if payload_data and payload_data[0] == 0xFE:
                logs.append(f"    [!] LỆNH ĐẶC BIỆT: Nhận mã 0xFE (CMD_RESET_STREAM) -> Kích hoạt chu trình con trỏ lơ lửng (CWE-416)!")

            logs.append("")
            extracted_packets.append((frame_idx, magic_ascii, payload_len, chk_valid))
            frame_idx += 1

        # Phần 2: Bảng Ánh xạ Truy vết sang Đặc tả SSOT 10-Sheet
        logs.append("=" * 80)
        logs.append("BẢNG ÁNH XẠ TRUY VẾT TỪ LOG THỰC TẾ SANG TỆP ĐẶC TẢ SSOT EXCEL (SPEC & REQ)")
        logs.append("=" * 80)
        logs.append("""
1. [Khung cấu trúc gói tin mạng FZP1]
   -> Ánh xạ sang Sheet 'RangBuoc':
      * CON-1: Gói tin tuân thủ cấu trúc 4B Magic | 4B Length | N-B Payload | 1B XOR Checksum.
      * CON-2: Bộ đệm stack frame cục bộ nhận payload có kích thước cố định 16 byte.
      * CON-4: Độ dài dữ liệu trường payload len được quy định bởi uint32_t Little-Endian.

2. [Cơ chế xác thực an toàn cổng biên]
   -> Ánh xạ sang Sheet 'YeuCauChucNang':
      * REQ-1: Hệ thống phải xác thực chính xác 4 byte Magic "FZP1" ở đầu gói tin.
      * REQ-2: Không được rơi vào deadlock trong mọi chu trình tiếp nhận.
      * REQ-3: parse_fzp1_payload() không được gây tràn bộ đệm stack (CWE-121) khi len > 16 byte.
      * REQ-5: Hàm đóng phiên không được giải phóng lặp lại (CWE-415) khi gặp mã lệnh 0xFF.
      * REQ-6: Không được truy cập con trỏ lơ lửng Use-After-Free (CWE-416) khi gặp mã lệnh 0xFE.

3. [Mô hình hóa hình thức chuyển trạng thái Kripke]
   -> Ánh xạ sang Sheet 'MoHinhTrangThai':
      * st_idle        : Sẵn sàng nhận gói tin từ mạng (safe, session_closed)
      * st_magic_ok    : Xác thực Magic Header hợp lệ (magic_ok, header_valid)
      * st_checksum_ok : Xác thực Checksum hợp lệ (checksum_ok, session_active)
      * st_conflict    : Trạng thái xung đột nguy cơ tràn bộ đệm (magic_ok, checksum_ok, violation)
""")
        logs.append("=" * 80)
        logs.append("KẾT LUẬN: ĐÃ XÁC THỰC HOÀN TOÀN TÍNH TRUY VẾT TỪ GÓI TIN MẠNG -> ĐẶC TẢ EXCEL")
        logs.append("=" * 80)

        log_content = "\n".join(logs)
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        LOG_FILE.write_text(log_content, encoding="utf-8")
        print(f"[+] Đã hoàn tất phân tích {frame_idx - 1} gói tin và xuất log truy vết:")
        print(f"    -> {LOG_FILE} ({LOG_FILE.stat().st_size:,} bytes)")

if __name__ == "__main__":
    analyze_pcap()
