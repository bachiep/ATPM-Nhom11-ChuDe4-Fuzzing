"""
BTL Nhom 11 — Module xay dung goi nhi phan SecureGate
=====================================================
Dung chung boi ca 3 fuzzer, test suite va benchmark.
"""
from __future__ import annotations
import struct


# --- Constants ---
HEADER_FORMAT = "<4sBBBBHHHH"  # little-endian, 16 byte
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 16
CHECKSUM_SIZE = 4
MAGIC = b"IGW1"
TYPE_REGISTRATION = 0x01
TYPE_UNLOCK = 0x02


def compute_checksum(data: bytes) -> int:
    """Tinh checksum: tong cac byte modulo 2^32."""
    return sum(data) & 0xFFFFFFFF


def build_packet(
    magic: bytes = MAGIC,
    version: int = 1,
    pkt_type: int = TYPE_REGISTRATION,
    device_id_len: int = 8,
    flags: int = 0,
    payload_len: int | None = None,
    unlock_a: int = 0,
    unlock_b: int = 0,
    reserved: int = 0,
    payload: bytes = b"",
) -> bytes:
    """Xay dung goi nhi phan day du voi checksum tu dong.

    Neu payload_len la None, tu dong tinh tu len(payload).
    Tra ve bytes gom: header (16) + payload + checksum (4).
    """
    if payload_len is None:
        payload_len = len(payload)

    # Pack header
    header = struct.pack(
        HEADER_FORMAT,
        magic,          # 4s
        version,        # B
        pkt_type,       # B
        device_id_len,  # B
        flags,          # B
        payload_len,    # H (u16 LE)
        unlock_a,       # H
        unlock_b,       # H
        reserved,       # H
    )
    assert len(header) == HEADER_SIZE

    # Checksum covers header + payload (not checksum itself)
    data = header + payload
    checksum = compute_checksum(data)
    checksum_bytes = struct.pack("<I", checksum)

    return data + checksum_bytes


def build_registration_packet(
    device_id: bytes,
    extra_payload: bytes = b"",
    **kwargs,
) -> bytes:
    """Tao goi Registration voi device_id va payload bo sung."""
    payload = device_id + extra_payload
    return build_packet(
        pkt_type=TYPE_REGISTRATION,
        device_id_len=len(device_id),
        payload=payload,
        **kwargs,
    )


def build_unlock_packet(
    unlock_a: int = 7421,
    unlock_b: int = 3390,
    **kwargs,
) -> bytes:
    """Tao goi Unlock voi cap ma mo khoa."""
    return build_packet(
        pkt_type=TYPE_UNLOCK,
        device_id_len=0,
        unlock_a=unlock_a,
        unlock_b=unlock_b,
        payload=b"",
        **kwargs,
    )


def parse_header(data: bytes) -> dict:
    """Parse 16 byte header thanh dict (tien ich cho debug/test)."""
    if len(data) < HEADER_SIZE:
        raise ValueError(f"Data qua ngan: {len(data)} < {HEADER_SIZE}")
    fields = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    return {
        "magic": fields[0],
        "version": fields[1],
        "type": fields[2],
        "device_id_len": fields[3],
        "flags": fields[4],
        "payload_len": fields[5],
        "unlock_a": fields[6],
        "unlock_b": fields[7],
        "reserved": fields[8],
    }


if __name__ == "__main__":
    # Demo: tao goi Registration hop le
    pkt = build_registration_packet(device_id=b"DEVICE01")
    hdr = parse_header(pkt)
    print(f"Registration packet: {len(pkt)} byte")
    print(f"  Header: {hdr}")
    print(f"  Hex: {pkt.hex()}")

    # Demo: tao goi Unlock hop le
    pkt2 = build_unlock_packet()
    hdr2 = parse_header(pkt2)
    print(f"\nUnlock packet: {len(pkt2)} byte")
    print(f"  Header: {hdr2}")
    print(f"  Hex: {pkt2.hex()}")

    # Demo: tao goi crash (device_id 24 byte)
    crash_pkt = build_registration_packet(device_id=b"A" * 24)
    print(f"\nCrash packet (device_id=24): {len(crash_pkt)} byte")
    print(f"  Hex: {crash_pkt.hex()}")
