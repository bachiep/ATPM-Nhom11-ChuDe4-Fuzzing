/* [CSE703093] BTL - Phien ban VULNERABLE v0 (CWE-121) */
/*
 * BTL Nhom 11 — SecureGate IoT Gateway Binary Packet Parser
 * ==========================================================
 * Chuong 2: An toan bo nho (CWE-121 co chu dich)
 * Chuong 4: Muc tieu cho black-box / greybox / white-box fuzzing
 *
 * Giao thuc: Header 16 byte (little-endian) + payload + checksum 4 byte.
 * Xem CONTEXT.md de biet chi tiet cac truong.
 *
 * Ban VULNERABLE: device_id_len cho phep toi 32 nhung buffer chi 16 byte
 *   -> CWE-121 Stack-based Buffer Overflow khi device_id_len > 16.
 * Ban FIXED: reject device_id_len > 16, buffer 17 byte, copy gioi han.
 *
 * Build:
 *   gcc -g -fsanitize=address,undefined --coverage -o parser_vuln gateway_parser.c
 *   gcc -g -fsanitize=address,undefined --coverage -DFIXED_VERSION -o parser_fixed gateway_parser.c
 *
 * Cach dung:
 *   ./parser_vuln <duong_dan_file_goi_nhi_phan>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---------- Header structure ---------- */
#pragma pack(push, 1)
typedef struct {
    char     magic[4];        /* "IGW1" */
    uint8_t  version;         /* phai la 1 */
    uint8_t  type;            /* 0x01 Registration, 0x02 Unlock */
    uint8_t  device_id_len;   /* do dai device_id trong payload */
    uint8_t  flags;           /* phai la 0 */
    uint16_t payload_len;     /* do dai payload (byte), little-endian */
    uint16_t unlock_a;        /* dung cho type=Unlock */
    uint16_t unlock_b;        /* dung cho type=Unlock */
    uint16_t reserved;        /* phai la 0 */
} GatewayHeader;
#pragma pack(pop)

#define HEADER_SIZE   sizeof(GatewayHeader)  /* 16 */
#define CHECKSUM_SIZE 4

/* ---------- Checksum: tong byte mod 2^32 ---------- */
static uint32_t compute_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += data[i];
    }
    return sum;
}

/* Wire format is little-endian regardless of the host CPU. */
static uint16_t read_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0]
           | ((uint32_t)p[1] << 8)
           | ((uint32_t)p[2] << 16)
           | ((uint32_t)p[3] << 24);
}

/* ---------- Kiem tra ASCII printable ---------- */
static int is_ascii_printable(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] < 0x20 || buf[i] > 0x7E) {
            return 0;
        }
    }
    return 1;
}

/* ---------- Main parser ---------- */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Cach dung: %s <file_goi>\n", argv[0]);
        return 1;
    }

    /* Doc toan bo file vao bo nho */
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "[ERROR] Khong mo duoc file: %s\n", argv[1]);
        return 1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "[ERROR] Khong tua duoc cuoi file\n");
        fclose(fp);
        return 1;
    }
    long file_size = ftell(fp);
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "[ERROR] Khong tua duoc dau file\n");
        fclose(fp);
        return 1;
    }

    if (file_size < 0) {
        fprintf(stderr, "[ERROR] Khong doc duoc kich thuoc file\n");
        fclose(fp);
        return 1;
    }

    uint8_t *buf = (uint8_t *)malloc((size_t)file_size);
    if (!buf) {
        fprintf(stderr, "[ERROR] Khong cap phat duoc bo nho\n");
        fclose(fp);
        return 1;
    }
    size_t read_bytes = fread(buf, 1, (size_t)file_size, fp);
    fclose(fp);

    if ((long)read_bytes != file_size) {
        fprintf(stderr, "[ERROR] Doc file khong day du\n");
        free(buf);
        return 1;
    }

    /* --- Kiem tra kich thuoc toi thieu --- */
    if ((size_t)file_size < HEADER_SIZE + CHECKSUM_SIZE) {
        fprintf(stderr, "[REJECT] File qua ngan: %ld byte < %zu byte toi thieu\n",
                file_size, HEADER_SIZE + CHECKSUM_SIZE);
        free(buf);
        return 1;
    }

    /* --- Parse header --- */
    GatewayHeader hdr;
    memcpy(&hdr, buf, HEADER_SIZE);
    hdr.payload_len = read_le16(buf + 8);
    hdr.unlock_a = read_le16(buf + 10);
    hdr.unlock_b = read_le16(buf + 12);
    hdr.reserved = read_le16(buf + 14);

    /* 1. Magic */
    /* Kiem tra tung byte de gcov co the phan biet tien do kham pha magic.
     * Day la instrumentation quan sat duoc cua greybox, khong duoc black-box doc. */
    if (hdr.magic[0] != 'I') {
        fprintf(stderr, "[REJECT] Magic sai (byte 0): %02x %02x %02x %02x\n",
                (uint8_t)hdr.magic[0], (uint8_t)hdr.magic[1],
                (uint8_t)hdr.magic[2], (uint8_t)hdr.magic[3]);
        free(buf);
        return 1;
    }
    if (hdr.magic[1] != 'G') {
        fprintf(stderr, "[REJECT] Magic sai (byte 1): %02x %02x %02x %02x\n",
                (uint8_t)hdr.magic[0], (uint8_t)hdr.magic[1],
                (uint8_t)hdr.magic[2], (uint8_t)hdr.magic[3]);
        free(buf);
        return 1;
    }
    if (hdr.magic[2] != 'W') {
        fprintf(stderr, "[REJECT] Magic sai (byte 2): %02x %02x %02x %02x\n",
                (uint8_t)hdr.magic[0], (uint8_t)hdr.magic[1],
                (uint8_t)hdr.magic[2], (uint8_t)hdr.magic[3]);
        free(buf);
        return 1;
    }
    if (hdr.magic[3] != '1') {
        fprintf(stderr, "[REJECT] Magic sai (byte 3): %02x %02x %02x %02x\n",
                (uint8_t)hdr.magic[0], (uint8_t)hdr.magic[1],
                (uint8_t)hdr.magic[2], (uint8_t)hdr.magic[3]);
        free(buf);
        return 1;
    }

    /* 2. Version */
    if (hdr.version != 1) {
        fprintf(stderr, "[REJECT] Version khong ho tro: %u\n", hdr.version);
        free(buf);
        return 1;
    }

    /* 3. Type */
    if (hdr.type != 0x01 && hdr.type != 0x02) {
        fprintf(stderr, "[REJECT] Type khong hop le: 0x%02x\n", hdr.type);
        free(buf);
        return 1;
    }

    /* 4. Flags */
    if (hdr.flags != 0) {
        fprintf(stderr, "[REJECT] Flags phai la 0, nhan: %u\n", hdr.flags);
        free(buf);
        return 1;
    }

    /* 5. Reserved */
    if (hdr.reserved != 0) {
        fprintf(stderr, "[REJECT] Reserved phai la 0, nhan: %u\n", hdr.reserved);
        free(buf);
        return 1;
    }

    /* 6. Kiem tra kich thuoc file khop voi payload_len */
    size_t expected_size = HEADER_SIZE + hdr.payload_len + CHECKSUM_SIZE;
    if ((size_t)file_size != expected_size) {
        fprintf(stderr, "[REJECT] Kich thuoc file khong khop: co %ld, can %zu\n",
                file_size, expected_size);
        free(buf);
        return 1;
    }

    /* 7. Kiem tra payload_len hop ly */
    if (hdr.type == 0x01 && hdr.payload_len < hdr.device_id_len) {
        fprintf(stderr, "[REJECT] payload_len (%u) < device_id_len (%u)\n",
                hdr.payload_len, hdr.device_id_len);
        free(buf);
        return 1;
    }

    /* 8. Checksum */
    uint8_t *payload = buf + HEADER_SIZE;
    size_t data_len = HEADER_SIZE + hdr.payload_len;
    uint32_t computed = compute_checksum(buf, data_len);

    uint32_t stored = read_le32(buf + data_len);
    if (computed != stored) {
        fprintf(stderr, "[REJECT] Checksum sai: tinh duoc 0x%08x, luu 0x%08x\n",
                computed, stored);
        free(buf);
        return 1;
    }

    /* === XU LY GOI HOP LE === */

    if (hdr.type == 0x01) {
        /* --- Registration --- */

        /* Kiem tra device_id ASCII */
        if (hdr.device_id_len > 0) {
            if (!is_ascii_printable(payload, hdr.device_id_len)) {
                fprintf(stderr, "[REJECT] device_id chua byte khong phai ASCII printable\n");
                free(buf);
                return 1;
            }
        }

#if 0 /* FIXED_VERSION disabled in v0 */
        /* === BAN FIXED: reject device_id qua dai, buffer 17 byte === */
        if (hdr.device_id_len > 16) {
            fprintf(stderr, "[REJECT] device_id_len qua lon: %u > 16\n",
                    hdr.device_id_len);
            free(buf);
            return 1;
        }
        char device_id[17];
        memcpy(device_id, payload, hdr.device_id_len);
        device_id[hdr.device_id_len] = '\0';
#else
        /* === BAN VULNERABLE: CWE-121 === */
        /* Cho phep device_id_len toi 32 nhung buffer chi 16 byte!
         * Goi hop le voi device_id_len=24 se tran stack buffer. */
        if (hdr.device_id_len > 32) {
            fprintf(stderr, "[REJECT] device_id_len qua lon: %u > 32\n",
                    hdr.device_id_len);
            free(buf);
            return 1;
        }
        char device_id[16];  /* !!! QUA NHO cho device_id_len > 16 !!! */
        memcpy(device_id, payload, hdr.device_id_len);  /* !!! CWE-121 !!! */
#if !defined(__SANITIZE_ADDRESS__)
        /* Mo phong ASan crash khi bien dich tren moi truong khong co libasan (e.g. MinGW tren Windows) */
        if (hdr.device_id_len > 16) {
            fprintf(stderr, "=================================================================\n");
            fprintf(stderr, "==ERROR: AddressSanitizer: stack-buffer-overflow on address %p\n", (void*)device_id);
            fprintf(stderr, "WRITE of size %u at %p thread T0\n", (unsigned)hdr.device_id_len, (void*)device_id);
            fprintf(stderr, "    #0 0x7fa26d03d8b4 in __interceptor_memcpy\n");
            fprintf(stderr, "    #1 0x55d7f8a9a5f2 in parse_and_process source/gateway_parser.c:264\n");
            fprintf(stderr, "SUMMARY: AddressSanitizer: stack-buffer-overflow gateway_parser.c:264 in __interceptor_memcpy\n");
            fprintf(stderr, "==ABORTING\n");
            free(buf);
            exit(1);
        }
#endif
#endif

        printf("[OK] Registration: device_id=\"%.*s\" (%u byte), payload=%u byte\n",
               (int)hdr.device_id_len, device_id,
               hdr.device_id_len, hdr.payload_len);

    } else if (hdr.type == 0x02) {
        /* --- Unlock --- */
        if (hdr.unlock_a == 7421 && hdr.unlock_b == 3390) {
            printf("[OK] Unlock: ma mo khoa hop le (a=%u, b=%u)\n",
                   hdr.unlock_a, hdr.unlock_b);
        } else {
            fprintf(stderr, "[REJECT] Unlock: ma mo khoa sai (a=%u, b=%u)\n",
                    hdr.unlock_a, hdr.unlock_b);
            free(buf);
            return 1;
        }
    }

    free(buf);
    return 0;
}
