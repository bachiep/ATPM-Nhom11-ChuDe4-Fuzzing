"""
=============================================================================
MODULE MỞ RỘNG ch4_dynafuzz CHO BỘ PHÂN TÍCH CÚ PHÁP GÓI TIN FZP1
Học phần: Kỹ thuật Lập trình An toàn (CSE703093 / CSE703153)
Cấu trúc gói tin FZP1:
  [0..3] : 4 bytes Magic Header "FZP1"
  [4..7] : 4 bytes Payload Length uint32_t (Little-Endian)
  [8..8+L-1] : L bytes Payload
  [8+L]  : 1 byte XOR Checksum
=============================================================================
"""

import os
import random
import struct
import time
from z3 import BitVec, BitVecVal, Solver, sat

class FZP1BlackBoxFuzzer:
    """Black-box Fuzzing: Sinh byte ngẫu nhiên thuần túy, không biết cấu trúc FZP1."""
    def __init__(self, seed: int = 0):
        self.rng = random.Random(seed)

    def generate_packet(self, min_len: int = 9, max_len: int = 80) -> bytes:
        pkt_len = self.rng.randint(min_len, max_len)
        return bytes(self.rng.randrange(256) for _ in range(pkt_len))


class FZP1GreyboxFuzzer:
    """Greybox Fuzzing (Header-aware): Biết Magic 'FZP1', đột biến ngẫu nhiên
    trường length (uint32), payload và dò đoán checksum."""
    def __init__(self, seed: int = 0):
        self.rng = random.Random(seed)

    def generate_packet(self, min_payload: int = 1, max_payload: int = 64) -> bytes:
        payload_len = self.rng.randint(min_payload, max_payload)
        payload = bytes(self.rng.randrange(256) for _ in range(payload_len))
        chk = self.rng.randrange(256)
        len_bytes = struct.pack("<I", payload_len)
        return b"FZP1" + len_bytes + payload + bytes([chk])


class FZP1WhiteBoxFuzzer:
    """White-box Fuzzing (Z3 SMT Solver):
    Mô hình hóa các ràng buộc đường đi (Path Constraints) dẫn đến nhánh lỗi CWE-121:
      1. Magic Constraint: data[0..3] == "FZP1"
      2. Vulnerability / Target Branch: length > 16 (vượt stack buffer 16 bytes)
      3. Integrity Checksum Constraint: chk == XOR_reduce(payload)
    Z3 tự động tổng hợp toàn bộ các trường byte thỏa mãn đồng thời cả 3 ràng buộc.
    """
    def __init__(self, seed: int = 0):
        self.seed = seed

    def solve_exploit_packet(self) -> tuple[bytes | None, float]:
        t0 = time.time()
        s = Solver()
        s.set("random_seed", self.seed)

        # 1. 4 bytes Magic Number: 'FZP1'
        sym_magic = [BitVec(f"magic_{i}", 8) for i in range(4)]
        s.add(sym_magic[0] == ord('F'))
        s.add(sym_magic[1] == ord('Z'))
        s.add(sym_magic[2] == ord('P'))
        s.add(sym_magic[3] == ord('1'))

        # 2. 4 bytes Length: length > 16 (Target crash branch CWE-121)
        # Tren kien truc x86_64, de ghi de duoc return address va gay crash that,
        # do dai payload can >= 64 bytes (vuot qua stack buffer 16B va compiler shadow store).
        target_len = 64 + (self.seed % 16) # Do dai tu 64 den 79 bytes (deu > 16)
        sym_len = BitVec("length", 32)
        s.add(sym_len == BitVecVal(target_len, 32))
        s.add(sym_len > BitVecVal(16, 32))

        # 3. Payload: mang target_len byte symbolic
        sym_payload = [BitVec(f"payload_{i}", 8) for i in range(target_len)]
        # Ràng buộc nhẹ byte đầu tiên theo seed để tăng tính đa dạng input
        s.add(sym_payload[0] == BitVecVal((0x41 + self.seed * 3) % 256, 8))

        # 4. Checksum: XOR reduce trên toàn bộ payload
        sym_chk = BitVec("checksum", 8)
        xor_acc = BitVecVal(0, 8)
        for p in sym_payload:
            xor_acc = xor_acc ^ p
        s.add(sym_chk == xor_acc)

        # 5. Giải hệ ràng buộc
        res = s.check()
        solve_time = time.time() - t0

        if res == sat:
            m = s.model()
            magic_bytes = bytes([m[sym_magic[i]].as_long() for i in range(4)])
            len_bytes = struct.pack("<I", target_len)
            payload_bytes = bytes([m[sym_payload[i]].as_long() for i in range(target_len)])
            chk_byte = bytes([m[sym_chk].as_long()])
            packet = magic_bytes + len_bytes + payload_bytes + chk_byte
            return packet, solve_time

        return None, solve_time


class FZP1CoverageGuidedFuzzer:
    """Coverage-guided Fuzzing cho giao thức FZP1:
    - Quản lý hàng đợi hạt giống (Seed Queue & Corpus Prioritization)
    - Phản hồi độ phủ nhánh biên (Branch/Edge Bitmap Feedback):
        B0: REJECT_TOO_SHORT (<9B)
        B1: REJECT_INVALID_MAGIC (!= 'FZP1')
        B2: REJECT_PAYLOAD_QUOTA (>65536)
        B3: REJECT_SIZE_MISMATCH
        B4: REJECT_CHECKSUM_MISMATCH
        B5: PARSE_SAFE_TELEMETRY (len <= 16)
        B6: PARSE_OVERFLOW_CWE121 (len > 16)
        B7: CMD_ABORT_CWE415 (payload[0] == 0xFF)
        B8: CMD_RESET_CWE416 (payload[0] == 0xFE)
    - Thuật toán tiến hóa: Khi phát hiện nhánh mới (New Branch Hit),
      lưu hạt giống vào hàng đợi và ưu tiên lai ghép / đột biến sâu hơn.
    """

    BRANCH_DESCRIPTIONS = {
        0: "REJECT_TOO_SHORT (< 9 bytes)",
        1: "REJECT_INVALID_MAGIC (!= 'FZP1')",
        2: "REJECT_PAYLOAD_QUOTA (> 65536 bytes)",
        3: "REJECT_SIZE_MISMATCH (Expected != Actual)",
        4: "REJECT_CHECKSUM_MISMATCH (XOR Checksum Invalid)",
        5: "PARSE_SAFE_TELEMETRY (Payload <= 16 bytes, Valid Path)",
        6: "PARSE_OVERFLOW_CWE121 (Payload > 16 bytes, Stack Crash)",
        7: "CMD_ABORT_CWE415 (Payload[0] == 0xFF, Double Free)",
        8: "CMD_RESET_CWE416 (Payload[0] == 0xFE, Use-After-Free)",
    }

    def __init__(self, seed: int = 42, initial_corpus: list[bytes] | None = None):
        self.rng = random.Random(seed)
        self.global_branch_bitmap = set()
        self.seed_queue: list[dict] = []
        self.total_executions = 0
        self.branch_discovery_history: list[dict] = []

        # Khởi tạo corpus ban đầu
        if initial_corpus:
            for pkt in initial_corpus:
                self.add_seed(pkt, origin="initial_corpus")
        else:
            # Seed tối thiểu mặc định
            default_seed = b"FZP1\x05\x00\x00\x00HELLO\x08"
            self.add_seed(default_seed, origin="default_bootstrap")

    @staticmethod
    def compute_branch_coverage(data: bytes) -> set[int]:
        """Phân tích các nhánh/biên logic giao thức FZP1 mà gói tin kích hoạt."""
        branches = set()
        if len(data) < 9:
            branches.add(0)
            return branches

        if data[:4] != b"FZP1":
            branches.add(1)
            return branches

        payload_len = struct.unpack("<I", data[4:8])[0]
        if payload_len > 65536:
            branches.add(2)
            return branches

        expected_total = payload_len + 9
        if expected_total != len(data):
            branches.add(3)
            return branches

        payload = data[8:8 + payload_len]
        expected_chk = data[8 + payload_len]
        computed_chk = 0
        for b in payload:
            computed_chk ^= b

        if computed_chk != expected_chk:
            branches.add(4)
            return branches

        # Vượt qua toàn bộ rào cản ngữ nghĩa -> Vào phân tích payload
        if payload_len > 0 and payload[0] == 0xFF:
            branches.add(7) # Kích hoạt lệnh abort (CWE-415)
        elif payload_len > 0 and payload[0] == 0xFE:
            branches.add(8) # Kích hoạt lệnh reset stream (CWE-416)
        elif payload_len > 16:
            branches.add(6) # Kích hoạt tràn stack buffer (CWE-121)
        else:
            branches.add(5) # Đường đi an toàn tiêu chuẩn

        return branches

    def add_seed(self, packet: bytes, origin: str = "mutation") -> bool:
        """Kiểm tra và nạp seed vào queue nếu đóng góp nhánh thực thi mới."""
        branches = self.compute_branch_coverage(packet)
        new_branches = branches - self.global_branch_bitmap
        is_interesting = len(new_branches) > 0 or len(self.seed_queue) == 0

        if is_interesting:
            self.global_branch_bitmap.update(branches)
            seed_info = {
                "id": len(self.seed_queue),
                "data": packet,
                "branches": list(branches),
                "new_branches": list(new_branches),
                "origin": origin,
                "exec_count": 0,
                "len": len(packet),
            }
            self.seed_queue.append(seed_info)
            self.branch_discovery_history.append({
                "exec": self.total_executions,
                "seed_id": seed_info["id"],
                "total_branches": len(self.global_branch_bitmap),
                "new_branches": list(new_branches),
            })
            return True
        return False

    def mutate(self, seed_data: bytes, strategy: str = "adaptive") -> bytes:
        """Đột biến có định hướng:
        - Bit/Byte flip
        - Đột biến trường Length (Little-Endian)
        - Đột biến byte lệnh điều khiển (0xFF, 0xFE, 0x01..0x10)
        - Tính toán lại Checksum để đẩy sâu vào các nhánh nội tại
        """
        data = bytearray(seed_data)
        op = self.rng.choice(["byte_flip", "boundary_len", "inject_cmd", "random_insert", "shuffle"])

        if op == "byte_flip" and len(data) > 0:
            idx = self.rng.randrange(len(data))
            data[idx] ^= (1 << self.rng.randrange(8))

        elif op == "boundary_len" and len(data) >= 8:
            # Đột biến độ dài quanh các mốc nhạy cảm: 0, 16, 17, 32, 64, 80
            new_len = self.rng.choice([0, 8, 16, 17, 24, 32, 64, 80, 128])
            data[4:8] = struct.pack("<I", new_len)
            current_payload_len = max(0, len(data) - 9)
            if new_len > current_payload_len:
                data.extend(bytes(self.rng.randrange(256) for _ in range(new_len - current_payload_len)))
            elif new_len < current_payload_len:
                data = data[:8 + new_len] + data[-1:]

        elif op == "inject_cmd" and len(data) >= 9:
            # Bơm mã lệnh điều khiển vào byte đầu payload
            cmd = self.rng.choice([0xFF, 0xFE, 0x00, 0x01, 0xAA])
            if len(data) == 9: # chưa có payload
                data.insert(8, cmd)
                cur_len = struct.unpack("<I", data[4:8])[0]
                data[4:8] = struct.pack("<I", cur_len + 1)
            else:
                data[8] = cmd

        elif op == "random_insert":
            idx = self.rng.randint(0, len(data))
            val = self.rng.randrange(256)
            data.insert(idx, val)

        elif op == "shuffle" and len(data) > 8:
            idx = self.rng.randint(8, len(data))
            data[idx:idx] = bytes(self.rng.randrange(256) for _ in range(self.rng.randint(1, 8)))

        # Với xác suất 75%, sửa lại Magic 'FZP1' và Checksum để tập trung kiểm thử logic sâu
        if self.rng.random() < 0.75:
            if len(data) >= 4:
                data[0:4] = b"FZP1"
            if len(data) >= 9:
                payload_len = struct.unpack("<I", data[4:8])[0]
                # Ngăn ngừa tràn RAM: Khống chế payload_len tối đa 128 bytes trong Fuzzing
                if payload_len > 128:
                    payload_len = self.rng.choice([16, 17, 24, 32, 64, 80])
                    data[4:8] = struct.pack("<I", payload_len)

                actual_payload = data[8:8 + payload_len]
                # Nếu payload ngắn hơn payload_len thì padding an toàn
                if len(actual_payload) < payload_len:
                    pad_len = payload_len - len(actual_payload)
                    data.extend(bytes([0x41] * pad_len))
                elif len(actual_payload) > payload_len:
                    data = data[:8 + payload_len + 1]
                
                # Tính lại XOR checksum hợp lệ
                chk = 0
                for b in data[8:8 + payload_len]:
                    chk ^= b
                if len(data) > 8 + payload_len:
                    data[8 + payload_len] = chk
                else:
                    data.append(chk)
                data = data[:8 + payload_len + 1]

        # Khống chế tổng kích thước gói tin tối đa 256 bytes
        if len(data) > 256:
            data = data[:256]

        return bytes(data)

    def next_input(self) -> tuple[bytes, dict]:
        """Lấy seed ưu tiên từ queue, đột biến và tăng bộ đếm thực thi."""
        self.total_executions += 1
        # Chọn seed theo xác suất ưu tiên seed kích hoạt nhiều nhánh sâu
        weights = [len(s["branches"]) * 2 for s in self.seed_queue]
        chosen_seed = self.rng.choices(self.seed_queue, weights=weights, k=1)[0]
        chosen_seed["exec_count"] += 1

        mutant = self.mutate(chosen_seed["data"])
        return mutant, chosen_seed

