"""
Kịch bản sinh tệp bắt gói tin mạng PCAP mô phỏng luồng dữ liệu IoT gửi về Gateway
Học phần: Kỹ thuật Lập trình An toàn (CSE703093 / CSE703153)
Định dạng gói tin: Ethernet / IPv4 / UDP (Port 8888) -> FZP1 Binary Packet
"""

import os
import struct
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_PCAP = BASE_DIR / "network_capture" / "iot_sensor_stream.pcap"

def build_fzp1_packet(payload: bytes) -> bytes:
    """Tạo gói tin FZP1: 4B Magic | 4B Len uint32 | Payload | 1B XOR Checksum"""
    magic = b"FZP1"
    length = len(payload)
    chk = 0
    for b in payload:
        chk ^= b
    return magic + struct.pack("<I", length) + payload + bytes([chk])

def calc_ip_checksum(header: bytes) -> int:
    """Tính checksum 16-bit cho header IPv4"""
    if len(header) % 2 == 1:
        header += b"\x00"
    total = 0
    for i in range(0, len(header), 2):
        w = (header[i] << 8) + header[i + 1]
        total += w
    while (total >> 16) > 0:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

def build_ethernet_ip_udp(payload: bytes, src_ip="192.168.1.105", dst_ip="192.168.1.1", src_port=5000, dst_port=8888) -> bytes:
    """Xây dựng khung mạng Ethernet + IPv4 + UDP bọc quanh payload FZP1"""
    # 1. Ethernet header (14 bytes)
    dst_mac = b"\x00\x1A\x2B\x3C\x4D\x5E"
    src_mac = b"\x54\x32\x04\xAA\xBB\xCC"
    eth_type = struct.pack("!H", 0x0800) # IPv4
    eth_hdr = dst_mac + src_mac + eth_type

    # 2. UDP header (8 bytes)
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) # Checksum 0 = disabled

    # 3. IPv4 header (20 bytes)
    ip_ver_ihl = 0x45
    ip_tos = 0x00
    ip_total_len = 20 + udp_len
    ip_id = 0x1234
    ip_flags_offset = 0x0000
    ip_ttl = 64
    ip_proto = 17 # UDP
    ip_chk = 0
    src_parts = [int(x) for x in src_ip.split(".")]
    dst_parts = [int(x) for x in dst_ip.split(".")]
    src_bytes = bytes(src_parts)
    dst_bytes = bytes(dst_parts)

    ip_hdr_pre = struct.pack("!BBHHHBBH4s4s",
                             ip_ver_ihl, ip_tos, ip_total_len, ip_id,
                             ip_flags_offset, ip_ttl, ip_proto, ip_chk,
                             src_bytes, dst_bytes)
    ip_chk = calc_ip_checksum(ip_hdr_pre)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
                         ip_ver_ihl, ip_tos, ip_total_len, ip_id,
                         ip_flags_offset, ip_ttl, ip_proto, ip_chk,
                         src_bytes, dst_bytes)

    return eth_hdr + ip_hdr + udp_hdr + payload

def generate_pcap():
    print(f"[*] Bắt đầu sinh luồng lưu lượng mạng PCAP: {OUTPUT_PCAP}")
    
    # Global PCAP Header (24 bytes)
    # magic=0xa1b2c3d4, v_maj=2, v_min=4, zone=0, sigfigs=0, snaplen=65535, net=1 (Ethernet)
    pcap_global_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    # Danh mục các gói tin FZP1 mô phỏng truyền tải từ nút cảm biến IoT
    sensor_telemetries = [
        b"TEMP:28C;HUM:65%",               # Gói tin đo nhiệt độ/độ ẩm định kỳ (16B)
        b"BARO:1013hPa",                   # Gói tin đo áp suất khí quyển (12B)
        b"STATUS:ONLINE",                  # Gói tin báo hiệu heartbeat cảm biến (13B)
        b"VOLT:3.3V;BAT:98",               # Gói tin điện áp nguồn pin (16B)
        b"\xFF\x01\x02\x03",               # Lệnh điều khiển khẩn cấp CMD_ABORT_SESSION
        b"\xFE\x00\x01\x00",               # Lệnh bảo trì kênh truyền CMD_RESET_STREAM
        b"ATTACK_OVERFLOW_BUFFER_PAYLOAD!", # Gói tin bất thường kích thước lớn từ node bị can thiệp (32B > 16B)
    ]

    base_time = int(time.time())
    with open(OUTPUT_PCAP, "wb") as f:
        f.write(pcap_global_hdr)
        for i, payload in enumerate(sensor_telemetries):
            fzp1_pkt = build_fzp1_packet(payload)
            net_frame = build_ethernet_ip_udp(fzp1_pkt, src_ip=f"192.168.1.{100 + i}")
            
            # Packet Header: ts_sec, ts_usec, incl_len, orig_len
            pkt_hdr = struct.pack("<IIII", base_time + i, i * 150000, len(net_frame), len(net_frame))
            f.write(pkt_hdr)
            f.write(net_frame)

    print(f"[+] Đã ghi thành công {len(sensor_telemetries)} khung mạng vào: {OUTPUT_PCAP} ({OUTPUT_PCAP.stat().st_size:,} bytes)")

if __name__ == "__main__":
    generate_pcap()
