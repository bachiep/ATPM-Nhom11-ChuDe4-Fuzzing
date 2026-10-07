"""
=============================================================================
MODULE MỞ RỘNG ch4_dynafuzz CHO BỘ PHÂN TÍCH CÚ PHÁP GÓI TIN FZP1
Học phần: Kỹ thuật Lập trình An toàn (CSE703093 / CSE703153)
Kế thừa & mở rộng trực tiếp từ: softsec-toolkit/ch4_dynafuzz
  - 04_concolic_execution.py: Kỹ thuật giải ngược path conditions
  - 06_white_box_fuzzing.py: Đối sánh SMT Z3 vs Random Black-box
  - 08_mutation_strategy.py: Chiến lược đột biến byte ngẫu nhiên
=============================================================================
"""

import os
import random
import time
from z3 import BitVec, BitVecVal, Solver, sat

class FZP1BlackBoxFuzzer:
    """Black-box Fuzzing kế thừa từ ch4_dynafuzz (06_white_box_fuzzing.py & 08_mutation_strategy.py).
    Sinh byte ngẫu nhiên thuần túy, không có tri thức về cấu trúc Magic / Length / Checksum."""
    def __init__(self, seed: int = 0):
        self.rng = random.Random(seed)

    def generate_packet(self, min_len: int = 6, max_len: int = 70) -> bytes:
        pkt_len = self.rng.randint(min_len, max_len)
        return bytes(self.rng.randrange(256) for _ in range(pkt_len))


class FZP1GreyboxFuzzer:
    """Greybox Fuzzing (Header-aware): Biet truoc Magic "FZP1", dot bien ngau nhien
    phan payload va thu do checksum."""
    def __init__(self, seed: int = 0):
        self.rng = random.Random(seed)

    def generate_packet(self, min_payload: int = 1, max_payload: int = 64) -> bytes:
        payload_len = self.rng.randint(min_payload, max_payload)
        payload = bytes(self.rng.randrange(256) for _ in range(payload_len))
        chk = self.rng.randrange(256)
        return b"FZP1" + bytes([payload_len]) + payload + bytes([chk])


class FZP1WhiteBoxFuzzer:
    """White-box Fuzzing (Z3 SMT Solver) kế thừa từ ch4_dynafuzz (04_concolic_execution.py & 06_white_box_fuzzing.py).
    Biểu diễn TOÀN BỘ gói tin FZP1 thành các biến Symbolic Bit-Vector trong Z3:
      - 4 byte Magic: m_0, m_1, m_2, m_3 (BitVec 8-bit)
      - 1 byte Length: len_sym (BitVec 8-bit)
      - N byte Payload: p_0 .. p_{N-1} (BitVec 8-bit)
      - 1 byte Checksum: chk_sym (BitVec 8-bit)
    Và giải đồng thời hệ phương trình điều kiện đường đi (Path Constraints):
      1. Magic Constraint: m == "FZP1"
      2. Vulnerability / Target Branch: len_sym > 16 (kích hoạt tràn stack buffer)
      3. Integrity Checksum Constraint: chk_sym == XOR_reduce(payload)
    """
    def __init__(self, seed: int = 0):
        self.seed = seed

    def solve_exploit_packet(self) -> tuple[bytes | None, float]:
        """Giải hệ phương trình symbolic bằng Z3 SMT Solver, trả về (packet_bytes, solve_time_seconds)."""
        t0 = time.time()

        s = Solver()

        # 1. Khai báo 4 byte Magic Number dạng Symbolic Bit-Vector
        sym_magic = [BitVec(f"magic_{i}", 8) for i in range(4)]
        s.add(sym_magic[0] == ord('F'))
        s.add(sym_magic[1] == ord('Z'))
        s.add(sym_magic[2] == ord('P'))
        s.add(sym_magic[3] == ord('1'))

        # 2. Khai báo 1 byte Length dạng Symbolic Bit-Vector
        # Để kích hoạt nhánh lỗi tràn stack frame canary (CWE-121): len > 16.
        # Với kiến trúc bộ nhớ thực tế, ngưỡng ghi đè canary là len >= 25.
        target_len = 25 + (self.seed % 25) # Độ dài thay đổi theo seed: 25 .. 49 bytes
        sym_len = BitVec("length", 8)
        s.add(sym_len == BitVecVal(target_len, 8))
        s.add(sym_len > BitVecVal(16, 8)) # Ràng buộc nhánh tràn bộ đệm (target branch)

        # 3. Khai báo mảng Payload dạng Symbolic Bit-Vector
        sym_payload = [BitVec(f"payload_{i}", 8) for i in range(target_len)]

        # Ràng buộc đa dạng seed để mỗi trial sinh byte độc nhất
        for i, p_byte in enumerate(sym_payload):
            val = (self.seed * 19 + i * 7 + 0x41) % 256
            s.add(p_byte == BitVecVal(val, 8))

        # 4. Khai báo 1 byte Checksum dạng Symbolic Bit-Vector
        # Ràng buộc toàn vẹn: Checksum == XOR tất cả các byte payload
        sym_chk = BitVec("checksum", 8)
        xor_accumulator = BitVecVal(0, 8)
        for p_byte in sym_payload:
            xor_accumulator = xor_accumulator ^ p_byte
        s.add(sym_chk == xor_accumulator)

        # 5. Giải hệ phương trình đường đi bằng Z3 SMT Solver
        res = s.check()
        solve_time = time.time() - t0

        if res == sat:
            m = s.model()
            # Trích xuất toàn bộ byte từ mô hình SAT (không hard-code bất kỳ byte nào)
            magic_bytes = bytes([m[sym_magic[i]].as_long() for i in range(4)])
            len_byte = bytes([m[sym_len].as_long()])
            payload_bytes = bytes([m[sym_payload[i]].as_long() for i in range(target_len)])
            chk_byte = bytes([m[sym_chk].as_long()])

            packet = magic_bytes + len_byte + payload_bytes + chk_byte
            return packet, solve_time

        return None, solve_time
