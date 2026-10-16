/*
 * BTL Nhom 11 — FZP1 Binary Packet Parser (Version 0.1: Patched CWE-121, Vulnerable to CWE-415 & CWE-416)
 * Hoc phan: Ky thuat Lap trinh An toan (CSE703093 / CSE703153)
 * Giang vien: ThS. Vu Quang Dung — Truong Cong nghe Thong tin, Dai hoc Phenikaa
 *
 * MOC TIEN HOA 1 (Sau khi Fuzzing tim ra Crash 1 - CWE-121 Stack Buffer Overflow):
 *   - Da va CWE-121 theo chuan CERT STR31-C: Kiem tra chan tren len <= MAX_PAYLOAD_ALLOWED (16 bytes).
 *   - Van ton tai CWE-415 (Double Free khi gap ma lenh 0xFF).
 *   - Van ton tai CWE-416 (Use-After-Free khi gap ma lenh 0xFE).
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

typedef struct {
    uint8_t *cached_payload;
    uint32_t cached_len;
    void (*stream_callback)(const char *);
} fzp1_session_t;

static fzp1_session_t *g_session = NULL;

static void default_stream_callback(const char *msg) {
    printf("[STREAM_CB] %s\n", msg);
}

static uint32_t read_uint32_le(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint8_t compute_xor_checksum(const uint8_t *data, size_t len) {
    uint8_t chk = 0;
    for (size_t i = 0; i < len; i++) {
        chk ^= data[i];
    }
    return chk;
}

static int init_fzp1_session(const uint8_t *payload, uint32_t len) {
    if (!g_session) {
        g_session = (fzp1_session_t *)malloc(sizeof(fzp1_session_t));
        if (!g_session) return -1;
        g_session->cached_payload = NULL;
        g_session->cached_len = 0;
        g_session->stream_callback = default_stream_callback;
    }
    if (len > 0) {
        if (g_session->cached_payload != NULL) {
            free(g_session->cached_payload);
        }
        g_session->cached_payload = (uint8_t *)malloc((size_t)len);
        if (!g_session->cached_payload) return -1;
        memcpy(g_session->cached_payload, payload, (size_t)len);
        g_session->cached_len = len;
    }
    return 0;
}

/* LOI CWE-415: Van chua gan NULL sau khi giai phong */
void close_fzp1_session(void) {
    if (g_session != NULL) {
        if (g_session->cached_payload != NULL) {
            printf("[SESSION] Freeing cached session payload at %p...\n", (void *)g_session->cached_payload);
            free(g_session->cached_payload);
        }
        printf("[SESSION] Freeing session context at %p...\n", (void *)g_session);
        free(g_session);
        /* CHUA VA: Thieu g_session = NULL de gay CWE-415 khi abort */
    }
}

/* LOI CWE-416: Van truy cap stream_callback sau khi giai phong */
static int release_fzp1_stream(void) {
    if (g_session != NULL) {
        printf("[STREAM] Releasing stream session at %p...\n", (void *)g_session);
        if (g_session->cached_payload != NULL) {
            free(g_session->cached_payload);
        }
        free(g_session);
        
        void *reclaimed = malloc(sizeof(fzp1_session_t));
        if (reclaimed) {
            memset(reclaimed, 0, sizeof(fzp1_session_t));
        }

        printf("[STREAM] Invoking stream callback through dangling pointer %p...\n", (void *)g_session);
        g_session->stream_callback("[TELEMETRY] Stream channel successfully reset.");
        
        if (reclaimed) free(reclaimed);
        return 0;
    }
    return -1;
}

/* DA VA CWE-121 (TUAN THU CERT STR31-C) */
static int parse_fzp1_payload(const uint8_t *payload, uint32_t len) {
    if (len > MAX_PAYLOAD_ALLOWED) {
        fprintf(stderr, "[SECURITY_REJECT] Payload length %u exceeds max allowed %d. (CERT STR31-C)\n",
                len, MAX_PAYLOAD_ALLOWED);
        return 2;
    }

    char stack_buf[STACK_BUFFER_SIZE];
    printf("[INFO] Parsing payload of length %u into safe stack buffer (size=%d)...\n", len, STACK_BUFFER_SIZE);

    memcpy(stack_buf, payload, (size_t)len);
    stack_buf[len] = '\0';

    printf("[SUCCESS] Payload safely parsed: first byte=0x%02X\n", (uint8_t)stack_buf[0]);
    return 0;
}

int process_fzp1_packet(const uint8_t *data, size_t total_size) {
    if (data == NULL) {
        fprintf(stderr, "[ERROR] Null data pointer provided.\n");
        return -1;
    }

    if (total_size < FZP1_HEADER_MIN_SIZE) {
        fprintf(stderr, "[REJECT] Packet size %zu is smaller than minimum %d bytes.\n",
                total_size, FZP1_HEADER_MIN_SIZE);
        return -2;
    }

    if (memcmp(data, FZP1_MAGIC, FZP1_MAGIC_LEN) != 0) {
        fprintf(stderr, "[REJECT] Invalid Magic: expected 'FZP1', got '%c%c%c%c'\n",
                data[0], data[1], data[2], data[3]);
        return -2;
    }

    uint32_t payload_len = read_uint32_le(data + 4);
    if (payload_len > 65536) {
        fprintf(stderr, "[REJECT] Payload length %u exceeds protocol quota 65536.\n", payload_len);
        return -2;
    }

    uint32_t expected_total_size = payload_len + FZP1_HEADER_MIN_SIZE;
    if ((size_t)expected_total_size != total_size) {
        fprintf(stderr, "[REJECT] Size mismatch: expected %u bytes, received %zu bytes.\n",
                expected_total_size, total_size);
        return -2;
    }

    const uint8_t *payload_ptr = data + 8;
    uint8_t expected_checksum = data[8 + payload_len];
    uint8_t computed_checksum = compute_xor_checksum(payload_ptr, (size_t)payload_len);

    if (computed_checksum != expected_checksum) {
        fprintf(stderr, "[REJECT] Checksum mismatch: expected 0x%02X, computed 0x%02X\n",
                expected_checksum, computed_checksum);
        return -2;
    }

    if (init_fzp1_session(payload_ptr, payload_len) != 0) {
        return -1;
    }

    /* Kich hoat CWE-415 khi payload bat dau bang byte 0xFF */
    if (payload_len > 0 && payload_ptr[0] == 0xFF) {
        fprintf(stderr, "[TRIGGER] Abort command 0xFF detected! Early closing session...\n");
        close_fzp1_session();
        return -5;
    }

    /* Kich hoat CWE-416 khi payload bat dau bang byte 0xFE */
    if (payload_len > 0 && payload_ptr[0] == 0xFE) {
        fprintf(stderr, "[TRIGGER] Reset stream command 0xFE detected! Releasing stream...\n");
        return release_fzp1_stream();
    }

    /* Da va an toan CWE-121 */
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

    free(file_buf);
    file_buf = NULL;

    close_fzp1_session();

    if (result == 2) {
        printf("[MAIN] Finished with security rejection (CERT STR31-C enforced).\n");
        return 2;
    } else if (result != 0) {
        printf("[MAIN] Finished with validation error code: %d\n", result);
        return 2;
    }

    printf("[MAIN] File processing completed successfully with 0 errors.\n");
    return 0;
}
