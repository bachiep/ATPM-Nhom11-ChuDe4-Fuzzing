/*
 * BTL Nhom 11 — FZP1 Binary Packet Parser (Version 1: Patched & Safe)
 * Hoc phan: Ky thuat Lap trinh An toan (CSE703093 / CSE703153)
 * Giang vien: ThS. Vu Quang Dung — Truong Cong nghe Thong tin, Dai hoc Phenikaa
 *
 * Dinh dang goi tin FZP1:
 *   [0..3] : 4 bytes Magic Header "FZP1" (0x46, 0x5A, 0x50, 0x31)
 *   [4]    : 1 byte Payload Length (L: 0..255)
 *   [5..5+L-1] : L bytes Payload
 *   [5+L]  : 1 byte XOR Checksum (XOR reduce over all payload bytes)
 *
 * Ban va an toan tuan thu chuan CERT C:
 *   - CERT STR31-C: Kiem tra chan tren payload_len <= STACK_BUFFER_SIZE truoc khi sao chep.
 *     Neu payload_len vuot qua kich thuoc vung dem cho phep (16 bytes), lap tuc tu choi,
 *     khong sao chep, ngan chan hoan toan Stack-based Buffer Overflow (CWE-121).
 *   - CERT MEM31-C & MEM30-C: Giai phong con tro Heap truoc khi ket thuc luong xu ly va
 *     gan ptr = NULL de chong Dangling Pointer / Use-After-Free (CWE-416).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define FZP1_MAGIC "FZP1"
#define FZP1_MAGIC_LEN 4
#define FZP1_HEADER_MIN_SIZE 6  /* 4B magic + 1B len + 0B payload + 1B checksum */
#define MAX_PAYLOAD_ALLOWED 16  /* Kich thuoc toi da duoc phep cua payload tren stack */
#define STACK_BUFFER_SIZE (MAX_PAYLOAD_ALLOWED + 1) /* 17 bytes: 16 bytes du lieu + 1 byte null terminator */

/* Tinh XOR Checksum tren mang du lieu */
static uint8_t compute_xor_checksum(const uint8_t *data, size_t len) {
    uint8_t chk = 0;
    for (size_t i = 0; i < len; i++) {
        chk ^= data[i];
    }
    return chk;
}

/* Ham giai ma va sao chep payload (DA VA AN TOAN TUAN THU CERT STR31-C) */
static int parse_fzp1_payload(const uint8_t *payload, uint8_t len) {
    /* Khai bao bo dem cuc bo tren stack voi kich thuoc an toan co cho cho null-terminator */
    char stack_buf[STACK_BUFFER_SIZE];

    printf("[INFO] Parsing payload of length %u into stack buffer (max_allowed=%d)...\n", len, MAX_PAYLOAD_ALLOWED);

    /* TUAN THU CERT STR31-C: Kiem tra chan tren chat che truoc khi goi memcpy */
    if (len > MAX_PAYLOAD_ALLOWED) {
        fprintf(stderr, "[SECURITY_REJECT] Payload length %u exceeds maximum allowed buffer %d. (CERT STR31-C enforcement prevented Stack Buffer Overflow CWE-121)\n",
                len, MAX_PAYLOAD_ALLOWED);
        return -3;
    }

    /* Sao chep du lieu an toan trong pham vi da duoc xac thuc */
    memcpy(stack_buf, payload, len);
    stack_buf[len] = '\0'; /* Luon dam bao ket thuc chuoi an toan */

    printf("[SUCCESS] Payload safely parsed and verified (first byte: 0x%02X)\n", (uint8_t)stack_buf[0]);
    return 0;
}

/* Ham xu ly chinh toan bo goi tin FZP1 */
int process_fzp1_packet(const uint8_t *data, size_t total_size) {
    if (data == NULL) {
        fprintf(stderr, "[ERROR] Null data pointer provided.\n");
        return -1;
    }

    /* Kiem tra kich thuoc toi thieu cua goi tin */
    if (total_size < FZP1_HEADER_MIN_SIZE) {
        fprintf(stderr, "[REJECT] Packet size %zu is smaller than minimum %d bytes.\n", total_size, FZP1_HEADER_MIN_SIZE);
        return -1;
    }

    /* 1. Xac thuc 4 byte Magic Number "FZP1" */
    if (memcmp(data, FZP1_MAGIC, FZP1_MAGIC_LEN) != 0) {
        fprintf(stderr, "[REJECT] Invalid Magic: expected 'FZP1', got '%c%c%c%c'\n",
                data[0], data[1], data[2], data[3]);
        return -1;
    }

    /* 2. Doc do dai payload (1 byte) */
    uint8_t payload_len = data[4];

    /* Kiem tra tinh toan ven kich thuoc file thuc te */
    size_t expected_total_size = (size_t)payload_len + FZP1_HEADER_MIN_SIZE;
    if (total_size != expected_total_size) {
        fprintf(stderr, "[REJECT] Size mismatch: expected %zu bytes, received %zu bytes.\n",
                expected_total_size, total_size);
        return -1;
    }

    /* 3. Doc va kiem tra XOR Checksum */
    const uint8_t *payload_ptr = data + 5;
    uint8_t expected_checksum = data[5 + payload_len];
    uint8_t computed_checksum = compute_xor_checksum(payload_ptr, payload_len);

    if (computed_checksum != expected_checksum) {
        fprintf(stderr, "[REJECT] Checksum mismatch: expected 0x%02X, computed 0x%02X\n",
                expected_checksum, computed_checksum);
        return -2;
    }

    printf("[INFO] Header & Checksum verified valid! (Payload length: %u bytes)\n", payload_len);

    /* 4. Goi ham xu ly payload an toan */
    return parse_fzp1_payload(payload_ptr, payload_len);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <fzp1_binary_packet_file>\n", argv[0]);
        return 1;
    }

    const char *filepath = argv[1];
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        fprintf(stderr, "[ERROR] Cannot open file: %s\n", filepath);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 1024) {
        fprintf(stderr, "[ERROR] Invalid file size: %ld bytes (must be 1..1024)\n", fsize);
        fclose(fp);
        return 1;
    }

    /* Cap phat bo dem Heap de doc file */
    uint8_t *file_buf = (uint8_t *)malloc((size_t)fsize);
    if (!file_buf) {
        fprintf(stderr, "[ERROR] Memory allocation failed on heap.\n");
        fclose(fp);
        return 1;
    }

    size_t bytes_read = fread(file_buf, 1, (size_t)fsize, fp);
    fclose(fp);

    if (bytes_read != (size_t)fsize) {
        fprintf(stderr, "[ERROR] Failed to read complete file content.\n");
        free(file_buf);
        file_buf = NULL;
        return 1;
    }

    printf("[MAIN] Processing FZP1 file '%s' (%zu bytes)...\n", filepath, bytes_read);

    int result = process_fzp1_packet(file_buf, bytes_read);

    /* Giai phong bo nho heap tuan thu CERT MEM31-C & MEM30-C */
    free(file_buf);
    file_buf = NULL;

    printf("[MAIN] Finished processing with code: %d\n", result);
    return (result == 0) ? 0 : 2;
}
