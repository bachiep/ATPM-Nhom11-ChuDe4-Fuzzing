/*
 * BTL Nhom 11 — FZP1 Binary Packet Parser (Version 0: Vulnerable)
 * Hoc phan: Ky thuat Lap trinh An toan (CSE703093 / CSE703153)
 * Giang vien: ThS. Vu Quang Dung — Truong Cong nghe Thong tin, Dai hoc Phenikaa
 *
 * Dinh dang goi tin FZP1:
 *   [0..3] : 4 bytes Magic Header "FZP1" (0x46, 0x5A, 0x50, 0x31)
 *   [4..7] : 4 bytes Payload Length uint32_t (Little-Endian)
 *   [8..8+L-1] : L bytes Payload
 *   [8+L]  : 1 byte XOR Checksum (XOR reduce over all payload bytes)
 *
 * 3 LO HONG AN TOAN BO NHO THUC TE (MEMORY CORRUPTION) DUOC CAI DAT CO CHU DICH:
 *   1. CWE-121: Stack-based Buffer Overflow tai parse_fzp1_payload()
 *      Stack buffer co dinh 16B, memcpy sao chep len byte (> 16B) gay tran stack frame va canary.
 *   2. CWE-415: Double Free tai close_fzp1_session()
 *      Giai phong cached_payload va g_session nhung quen khong reset con tro ve NULL,
 *      dan den giai phong 2 lan khi cleanup tren nhanh loi abort (CMD 0xFF).
 *   3. CWE-416: Use-After-Free tai release_fzp1_stream()
 *      Giai phong g_session tren heap nhung quen khong gan NULL, sau do goi con tro ham
 *      stream_callback thong qua con tro lo lung sau khi o nho bi tai cap phat (CMD 0xFE).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#define FZP1_MAGIC "FZP1"
#define FZP1_MAGIC_LEN 4
#define FZP1_HEADER_MIN_SIZE 9  /* 4B magic + 4B len + 0B payload + 1B checksum */
#define STACK_BUFFER_SIZE 16

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

/* Doc so nguyen khong dau 32-bit Little-Endian */
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

/* Khoi tao session cache tren heap */
static int init_fzp1_session(const uint8_t *payload, uint32_t len) {
    if (!g_session) {
        g_session = (fzp1_session_t *)malloc(sizeof(fzp1_session_t));
        if (!g_session) return -1;
        g_session->cached_payload = NULL;
        g_session->cached_len = 0;
        g_session->stream_callback = default_stream_callback;
    }
    if (len > 0) {
        g_session->cached_payload = (uint8_t *)malloc((size_t)len);
        if (!g_session->cached_payload) return -1;
        memcpy(g_session->cached_payload, payload, (size_t)len);
        g_session->cached_len = len;
    }
    return 0;
}

/*
 * LOI 2 — CWE-415: Double Free
 * Ham dong phien lam viec va giai phong bo nho heap.
 * Trong v0: quen khong gan g_session->cached_payload = NULL va g_session = NULL sau khi free().
 * Neu ham duoc goi 2 lan (vi du: error handler abort dong phien, sau do main() cleanup lai),
 * se gay ra loi Double Free Crash bi ASan va Heap Manager bat (0xC0000374).
 */
void close_fzp1_session(void) {
    if (g_session != NULL) {
        if (g_session->cached_payload != NULL) {
            printf("[SESSION] Freeing cached session payload at %p...\n", (void *)g_session->cached_payload);
            free(g_session->cached_payload);
            /* LOI CWE-415: THIEU DONG GAN CON TRO VE NULL */
            /* g_session->cached_payload = NULL; */
        }
        printf("[SESSION] Freeing session context at %p...\n", (void *)g_session);
        free(g_session);
        /* LOI CWE-415: THIEU DONG GAN CON TRO VE NULL */
        /* g_session = NULL; */
    }
}

/*
 * LOI 3 — CWE-416: Use-After-Free
 * Ham release_fzp1_stream() giai phong kenh stream session khi gap ma lenh CMD_RESET_STREAM (0xFE).
 * Trong v0: sau khi giai phong free(g_session->cached_payload) va free(g_session),
 * con tro g_session khong duoc gan ve NULL (dangling pointer).
 * Sau do, mot vung nho khac duoc cap phat tren Heap de ghi log tai nguyen (Heap reuse),
 * va parser tiep tuc goi con tro ham stream_callback thong qua con tro lo lung g_session.
 * -> Gay ra loi Heap Use-After-Free / Access Violation (0xC0000005) hoac bi ASan bat.
 */
static int release_fzp1_stream(void) {
    if (g_session != NULL) {
        printf("[STREAM] Releasing stream session at %p...\n", (void *)g_session);
        if (g_session->cached_payload != NULL) {
            free(g_session->cached_payload);
        }
        free(g_session);
        /* LOI CWE-416: THIEU DONG GAN g_session = NULL */
        
        /* Mo phong tai cap phat Heap (Heap reuse / reclamation boi tieu trinh khac) */
        void *reclaimed = malloc(sizeof(fzp1_session_t));
        if (reclaimed) {
            memset(reclaimed, 0, sizeof(fzp1_session_t));
        }

        /* USE-AFTER-FREE: Truy cap con tro ham stream_callback thong qua con tro lo lung g_session! */
        printf("[STREAM] Invoking stream callback through dangling pointer %p...\n", (void *)g_session);
        g_session->stream_callback("[TELEMETRY] Stream channel successfully reset.");
        
        if (reclaimed) free(reclaimed);
        return 0;
    }
    return -1;
}

/*
 * LOI 1 — CWE-121: Stack-based Buffer Overflow
 * Khai bao stack_buf co dinh 16 bytes.
 * Khi len > 16 (vi du 24 bytes hoac 64 bytes), memcpy ghi de stack frame va canary.
 */
static int parse_fzp1_payload(const uint8_t *payload, uint32_t len) {
    char stack_buf[STACK_BUFFER_SIZE];

    printf("[INFO] Parsing payload of length %u into stack buffer (size=%d)...\n", len, STACK_BUFFER_SIZE);

    /* LOI CWE-121: Thieu kiem tra chan tren len <= STACK_BUFFER_SIZE */
    memcpy(stack_buf, payload, (size_t)len);

    if (len < STACK_BUFFER_SIZE) {
        stack_buf[len] = '\0';
    }

    printf("[SUCCESS] Payload copied successfully (first byte: 0x%02X)\n", (uint8_t)stack_buf[0]);
    return 0;
}

/* Ham xu ly chinh toan bo goi tin FZP1 */
int process_fzp1_packet(const uint8_t *data, size_t total_size) {
    if (data == NULL) {
        fprintf(stderr, "[ERROR] Null data pointer provided.\n");
        return -1;
    }

    /* Kiem tra kich thuoc toi thieu cua goi tin (4B magic + 4B len + 0B payload + 1B checksum) */
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

    /* 2. Doc do dai payload (4 bytes Little-Endian uint32_t) */
    uint32_t payload_len = read_uint32_le(data + 4);
    uint32_t expected_total_size = payload_len + FZP1_HEADER_MIN_SIZE;
    if ((size_t)expected_total_size != total_size) {
        fprintf(stderr, "[REJECT] Size mismatch: expected %u bytes, received %zu bytes.\n",
                expected_total_size, total_size);
        return -1;
    }

    /* 3. Doc va kiem tra XOR Checksum (tai vi tri 8 + payload_len) */
    const uint8_t *payload_ptr = data + 8;
    uint8_t expected_checksum = data[8 + payload_len];
    uint8_t computed_checksum = compute_xor_checksum(payload_ptr, (size_t)payload_len);

    if (computed_checksum != expected_checksum) {
        fprintf(stderr, "[REJECT] Checksum mismatch: expected 0x%02X, computed 0x%02X\n",
                expected_checksum, computed_checksum);
        return -2;
    }

    printf("[INFO] Header & Checksum verified valid! (Payload length: %u bytes)\n", payload_len);

    /* 4. Khoi tao phien cache payload */
    if (init_fzp1_session(payload_ptr, payload_len) != 0) {
        return -1;
    }

    /*
     * Kich hoat nhanh tai hien CWE-415 (Double Free):
     * Neu payload bat dau bang byte dac biet 0xFF ('CMD_ABORT_SESSION'),
     * parser coi day la goi tin yeu cau huy phien som va goi close_fzp1_session().
     * Sau do khi return ma loi ve main(), main() tiep tuc goi close_fzp1_session() lan 2!
     */
    if (payload_len > 0 && payload_ptr[0] == 0xFF) {
        fprintf(stderr, "[TRIGGER] Abort command 0xFF detected! Early closing session...\n");
        close_fzp1_session();
        return -5;
    }

    /*
     * Kich hoat nhanh tai hien CWE-416 (Use-After-Free):
     * Neu payload bat dau bang byte dac biet 0xFE ('CMD_RESET_STREAM'),
     * parser goi release_fzp1_stream() de giai phong kenh stream, nhung sau do truy cap con tro lo lung!
     */
    if (payload_len > 0 && payload_ptr[0] == 0xFE) {
        fprintf(stderr, "[TRIGGER] Reset stream command 0xFE detected! Releasing stream...\n");
        return release_fzp1_stream();
    }

    /* 5. Goi ham xu ly payload tren stack (Kich hoat CWE-121 neu payload_len > 16) */
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
        return 1;
    }

    printf("[MAIN] Processing FZP1 file '%s' (%zu bytes)...\n", filepath, bytes_read);

    int result = process_fzp1_packet(file_buf, bytes_read);

    /* Don dep file buffer tren heap */
    free(file_buf);
    file_buf = NULL;

    /*
     * Dong phien lam viec:
     * Neu process_fzp1_packet() da goi close_fzp1_session() truoc do (do ma 0xFF),
     * lenh goi nay se gay ra CWE-415 (Double Free)!
     */
    close_fzp1_session();

    printf("[MAIN] Finished processing with code: %d\n", result);
    return (result == 0) ? 0 : 2;
}
