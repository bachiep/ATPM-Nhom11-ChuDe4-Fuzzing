/*
 * BTL Nhom 11 — FZP1 Binary Packet Parser (Version 1: Patched & Safe)
 * Hoc phan: Ky thuat Lap trinh An toan (CSE703093 / CSE703153)
 * Giang vien: ThS. Vu Quang Dung — Truong Cong nghe Thong tin, Dai hoc Phenikaa
 *
 * Dinh dang goi tin FZP1:
 *   [0..3] : 4 bytes Magic Header "FZP1" (0x46, 0x5A, 0x50, 0x31)
 *   [4..7] : 4 bytes Payload Length uint32_t (Little-Endian)
 *   [8..8+L-1] : L bytes Payload
 *   [8+L]  : 1 byte XOR Checksum (XOR reduce over all payload bytes)
 *
 * CAC BAN VA AN TOAN TUAN THU NGHIEM NGAT CHUAN CERT C:
 *   1. Khac phuc CWE-121 (CERT STR31-C):
 *      Kiem tra chan tren payload_len <= MAX_PAYLOAD_ALLOWED (16 bytes) truoc khi memcpy.
 *      Mo rong stack_buf len 17 bytes de dam bao luon co ky tu ket thuc chuoi an toan '\0'.
 *   2. Khac phuc CWE-415 (CERT MEM30-C & MEM31-C):
 *      Sau khi free(cached_payload) va free(g_session), dat ngay lap tuc con tro ve NULL
 *      de triet tieu hoan toan con tro lo lung (Dangling Pointer), ngan ngua Double Free.
 *   3. Khac phuc CWE-416 (CERT MEM30-C — "Do not access a closed or freed resource"):
 *      Trong release_fzp1_stream(), callback thong bao duoc goi TRUOC KHI giai phong bo nho.
 *      Sau khi free(), con tro duoc dat ve NULL ngay lap tuc; moi truy cap deu kiem tra an toan.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#define FZP1_MAGIC "FZP1"
#define FZP1_MAGIC_LEN 4
#define FZP1_HEADER_MIN_SIZE 9  /* 4B magic + 4B len + 0B payload + 1B checksum */
#define MAX_PAYLOAD_ALLOWED 16  /* Kich thuoc toi da duoc phep cua payload */
#define STACK_BUFFER_SIZE (MAX_PAYLOAD_ALLOWED + 1) /* 17 bytes: 16B data + 1B '\0' */

/* Cau truc quan ly phien va kenh luong stream FZP1 tren Heap */
typedef struct {
    uint8_t *cached_payload;
    uint32_t cached_len;
    void (*stream_callback)(const char *);
} fzp1_session_t;

static fzp1_session_t *g_session = NULL;

static void default_stream_callback(const char *msg) {
    printf("[STREAM_CB] %s\n", msg);
}

/* Doc so nguyen khong dau 32-bit Little-Endian an toan */
static uint32_t read_uint32_le(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* Tinh XOR Checksum tren mang du lieu */
static uint8_t compute_xor_checksum(const uint8_t *data, size_t len) {
    uint8_t chk = 0;
    for (size_t i = 0; i < len; i++) {
        chk ^= data[i];
    }
    return chk;
}

/* Khoi tao session cache tren heap an toan */
static int init_fzp1_session(const uint8_t *payload, uint32_t len) {
    if (!g_session) {
        g_session = (fzp1_session_t *)malloc(sizeof(fzp1_session_t));
        if (!g_session) return -1;
        g_session->cached_payload = NULL;
        g_session->cached_len = 0;
        g_session->stream_callback = default_stream_callback;
    }
    if (len > 0) {
        /* Giai phong cache cu neu co truoc khi cap phat moi */
        if (g_session->cached_payload != NULL) {
            free(g_session->cached_payload);
            g_session->cached_payload = NULL;
        }
        g_session->cached_payload = (uint8_t *)malloc((size_t)len);
        if (!g_session->cached_payload) return -1;
        memcpy(g_session->cached_payload, payload, (size_t)len);
        g_session->cached_len = len;
    }
    return 0;
}

/*
 * KHAC PHUC CWE-415 (TUAN THU CERT MEM30-C & MEM31-C):
 * Ham dong phien lam viec co tinh chat idempotent (goi nhieu lan khong gay loi).
 * Dat ngay lap tuc cac con tro ve NULL sau khi giai phong.
 */
void close_fzp1_session(void) {
    if (g_session != NULL) {
        if (g_session->cached_payload != NULL) {
            printf("[SESSION] Safely freeing cached session payload at %p...\n", (void *)g_session->cached_payload);
            free(g_session->cached_payload);
            /* CERT MEM30-C & MEM31-C: Reset con tro ve NULL */
            g_session->cached_payload = NULL;
        }
        printf("[SESSION] Safely freeing session context at %p...\n", (void *)g_session);
        free(g_session);
        /* CERT MEM30-C & MEM31-C: Reset con tro ve NULL */
        g_session = NULL;
    }
}

/*
 * KHAC PHUC CWE-416 (TUAN THU CERT MEM30-C):
 * "Do not access a closed or freed resource"
 * Thuc thi moi hanh vi telemetry / callback TRUOC KHI giai phong tai nguyen.
 * Sau khi giai phong, dat g_session = NULL ngay lap tuc de khong con dangling pointer.
 */
static int release_fzp1_stream(void) {
    if (g_session != NULL) {
        printf("[STREAM] Safely processing stream release...\n");
        /* CERT MEM30-C: Goi callback truoc khi giai phong bo nho */
        if (g_session->stream_callback != NULL) {
            g_session->stream_callback("[SECURE_TELEMETRY] Stream channel cleanly terminated.");
        }
        
        if (g_session->cached_payload != NULL) {
            free(g_session->cached_payload);
            g_session->cached_payload = NULL;
        }
        free(g_session);
        g_session = NULL; /* CERT MEM31-C: Reset con tro ve NULL */
        return 0;
    }
    return 0;
}

/*
 * KHAC PHUC CWE-121 (TUAN THU CERT STR31-C):
 * "Guarantee that storage for strings has sufficient space for character data and null terminator"
 * Kiem tra chan tren len <= MAX_PAYLOAD_ALLOWED (16 bytes).
 * Khai bao stack_buf 17 bytes de luon chua du null-terminator '\0'.
 */
static int parse_fzp1_payload(const uint8_t *payload, uint32_t len) {
    /* CERT STR31-C: Chan tren nghiem ngat */
    if (len > MAX_PAYLOAD_ALLOWED) {
        fprintf(stderr, "[SECURITY_REJECT] Payload length %u exceeds max allowed %d. (CERT STR31-C)\n",
                len, MAX_PAYLOAD_ALLOWED);
        return 2;
    }

    char stack_buf[STACK_BUFFER_SIZE]; /* 17 bytes: 16 data + 1 '\0' */

    printf("[INFO] Parsing payload of length %u into safe stack buffer (size=%d)...\n",
           len, STACK_BUFFER_SIZE);

    memcpy(stack_buf, payload, (size_t)len);
    stack_buf[len] = '\0'; /* Dam bao Null-terminated chuoi */

    printf("[SUCCESS] Payload safely parsed: first byte=0x%02X\n", (uint8_t)stack_buf[0]);
    return 0;
}

/* Ham xu ly chinh toan bo goi tin FZP1 an toan */
int process_fzp1_packet(const uint8_t *data, size_t total_size) {
    if (data == NULL) {
        fprintf(stderr, "[ERROR] Null data pointer provided.\n");
        return 2;
    }

    /* Kiem tra kich thuoc toi thieu cua goi tin */
    if (total_size < FZP1_HEADER_MIN_SIZE) {
        fprintf(stderr, "[REJECT] Packet size %zu is smaller than minimum %d bytes.\n",
                total_size, FZP1_HEADER_MIN_SIZE);
        return 2;
    }

    /* 1. Xac thuc 4 byte Magic Number "FZP1" */
    if (memcmp(data, FZP1_MAGIC, FZP1_MAGIC_LEN) != 0) {
        fprintf(stderr, "[REJECT] Invalid Magic: expected 'FZP1', got '%c%c%c%c'\n",
                data[0], data[1], data[2], data[3]);
        return 2;
    }

    /* 2. Doc do dai payload */
    uint32_t payload_len = read_uint32_le(data + 4);

    /* Chan chan tren payload length tranh tran so hoc */
    if (payload_len > 65536) {
        fprintf(stderr, "[REJECT] Payload length %u exceeds maximum protocol quota 65536.\n", payload_len);
        return 2;
    }

    uint32_t expected_total_size = payload_len + FZP1_HEADER_MIN_SIZE;
    if ((size_t)expected_total_size != total_size) {
        fprintf(stderr, "[REJECT] Size mismatch: expected %u bytes, received %zu bytes.\n",
                expected_total_size, total_size);
        return 2;
    }

    /* 3. Doc va kiem tra XOR Checksum */
    const uint8_t *payload_ptr = data + 8;
    uint8_t expected_checksum = data[8 + payload_len];
    uint8_t computed_checksum = compute_xor_checksum(payload_ptr, (size_t)payload_len);

    if (computed_checksum != expected_checksum) {
        fprintf(stderr, "[REJECT] Checksum mismatch: expected 0x%02X, computed 0x%02X\n",
                expected_checksum, computed_checksum);
        return 2;
    }

    printf("[INFO] Header & Checksum verified valid! (Payload length: %u bytes)\n", payload_len);

    /* 4. Khoi tao phien cache payload */
    if (init_fzp1_session(payload_ptr, payload_len) != 0) {
        return 2;
    }

    /*
     * Xu ly an toan lenh huy phien 0xFF (CMD_ABORT_SESSION):
     * Goi close_fzp1_session() va thoat voi ma 2 ma khong gay loi Double Free.
     */
    if (payload_len > 0 && payload_ptr[0] == 0xFF) {
        fprintf(stderr, "[SECURITY_REJECT] Abort command 0xFF detected! Safely closing session (CERT MEM30-C)...\n");
        close_fzp1_session();
        return 2;
    }

    /*
     * Xu ly an toan lenh reset stream 0xFE (CMD_RESET_STREAM):
     * Goi release_fzp1_stream() va thoat voi ma 2 ma khong gay loi Use-After-Free.
     */
    if (payload_len > 0 && payload_ptr[0] == 0xFE) {
        fprintf(stderr, "[SECURITY_REJECT] Reset stream command 0xFE detected! Safely terminating stream (CERT MEM30-C)...\n");
        release_fzp1_stream();
        return 2;
    }

    /* 5. Goi ham xu ly payload an toan voi kiem tra gioi han CERT STR31-C */
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

    if (fsize <= 0 || fsize > 65536) {
        fprintf(stderr, "[ERROR] Invalid file size: %ld bytes (must be 1..65536)\n", fsize);
        fclose(fp);
        return 1;
    }

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

    /* TUAN THU CERT MEM31-C & MEM30-C: Giai phong va gan NULL */
    free(file_buf);
    file_buf = NULL;

    /* Dong phien lam viec an toan (idempotent, khong bao gio bi double free) */
    close_fzp1_session();

    printf("[MAIN] Finished processing with code: %d\n", result);
    return (result == 0) ? 0 : 2;
}
