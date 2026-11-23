/*
 * Phase 13.1a interop fixture: length-prefixed TCP protocol.
 *
 * Compiled twice:
 *   gcc -O1 -fno-inline -fno-builtin -g -DREFERENCE interop.c -o interop_ref
 *   gcc -O1 -fno-inline -fno-builtin -g -DCANDIDATE interop.c -o interop_cand
 *
 * Protocol: 4-byte big-endian length + payload. The receiver echoes back the
 * same length-prefixed message. Both server and client emit a JSON identity
 * line containing the real /proc/self/exe and /proc/self/maps lines.
 *
 * The candidate has one explicitly labeled synthetic defect: it truncates a
 * payload larger than CANDIDATE_TRUNCATE (2048) down to CANDIDATE_TRUNCATE
 * (2048) bytes before echoing. This is a deliberate fixture defect used to
 * exercise the four-way interop matrix; it is NOT an organically discovered
 * vulnerability.
 *
 * Modes:
 *   server <port>          - listen on port, accept one connection, echo
 *   client <host> <port> <case>
 *
 * Cases:
 *   empty        - zero-length payload, expect echo of zero bytes
 *   short        - 5-byte payload "hello", expect echo of 5 bytes
 *   max_4096     - 4096-byte payload, expect full echo (candidate truncates)
 *   malformed_length - send length 0xFFFFFFFF, expect server rejection
 *   truncated    - send length 10 with only 5 bytes, expect server rejection
 *   oversize_common - send length 4097 with 4096 bytes, expect server rejection
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#define MAX_PAYLOAD 4096
#define CANDIDATE_TRUNCATE 2048

/* Read a file into a malloc'd NUL-terminated buffer. Returns NULL on failure.
   /proc files report st_size == 0, so read in chunks until EOF instead of
   trusting the reported size. */
static char *read_file(const char *path, size_t *out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    size_t cap = 4096;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return NULL; }
    for (;;) {
        if (len + 1 >= cap) {
            size_t new_cap = cap * 2;
            char *grown = realloc(buf, new_cap);
            if (!grown) { free(buf); close(fd); return NULL; }
            buf = grown;
            cap = new_cap;
        }
        ssize_t n = read(fd, buf + len, cap - len - 1);
        if (n < 0) { free(buf); close(fd); return NULL; }
        if (n == 0) break;
        len += (size_t)n;
    }
    close(fd);
    buf[len] = '\0';
    if (out_len) *out_len = len;
    return buf;
}

/* Emit a single JSON identity line with exe path and maps content. Escapes
   non-printable bytes as \\xHH so output is valid UTF-8. /proc/self/exe is a
   symlink, so use readlink() to obtain the target path, not read(). */
static void emit_identity(void) {
    char exe_buf[4096];
    ssize_t exe_len = readlink("/proc/self/exe", exe_buf, sizeof(exe_buf) - 1);
    if (exe_len < 0) exe_len = 0;
    exe_buf[exe_len] = '\0';

    size_t maps_len = 0;
    char *maps = read_file("/proc/self/maps", &maps_len);

    printf("{\"exe\":");
    if (exe_len > 0) {
        printf("\"");
        for (ssize_t i = 0; i < exe_len; i++) {
            unsigned char c = (unsigned char)exe_buf[i];
            if (c == '"') printf("\\\"");
            else if (c == '\\') printf("\\\\");
            else if (c == '\n') printf("\\n");
            else if (c == '\r') printf("\\r");
            else if (c == '\t') printf("\\t");
            else if (c < 0x20 || c >= 0x7F) printf("\\x%02x", c);
            else putchar(c);
        }
        printf("\"");
    } else {
        printf("null");
    }
    printf(",\"maps\":");
    if (maps) {
        printf("\"");
        for (size_t i = 0; i < maps_len; i++) {
            unsigned char c = (unsigned char)maps[i];
            if (c == '"') printf("\\\"");
            else if (c == '\\') printf("\\\\");
            else if (c == '\n') printf("\\n");
            else if (c == '\r') printf("\\r");
            else if (c == '\t') printf("\\t");
            else if (c < 0x20 || c >= 0x7F) printf("\\x%02x", c);
            else putchar(c);
        }
        printf("\"");
        free(maps);
    } else {
        printf("null");
    }
    printf("}\n");
    fflush(stdout);
}

/* Send a length-prefixed message: 4-byte BE length + payload. */
static int send_message(int sock, const uint8_t *payload, uint32_t len) {
    uint8_t hdr[4];
    hdr[0] = (len >> 24) & 0xFF;
    hdr[1] = (len >> 16) & 0xFF;
    hdr[2] = (len >> 8) & 0xFF;
    hdr[3] = len & 0xFF;
    if (send(sock, hdr, 4, 0) != 4) return -1;
    if (len > 0 && send(sock, payload, len, 0) != (ssize_t)len) return -1;
    return 0;
}

/* Receive a length-prefixed message. Returns payload length or -1 on error. */
static int recv_message(int sock, uint8_t *buf, uint32_t max_len) {
    uint8_t hdr[4];
    ssize_t n = recv(sock, hdr, 4, MSG_WAITALL);
    if (n != 4) return -1;
    uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                   ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
    if (len > max_len) return -1;
    if (len > 0) {
        n = recv(sock, buf, len, MSG_WAITALL);
        if (n != (ssize_t)len) return -1;
    }
    return (int)len;
}

/* Build a payload for the given case name. Returns payload length. */
static uint32_t build_payload(const char *case_name, uint8_t *buf, uint32_t max_len) {
    if (strcmp(case_name, "empty") == 0) {
        return 0;
    } else if (strcmp(case_name, "short") == 0) {
        const char *msg = "hello";
        uint32_t len = 5;
        memcpy(buf, msg, len);
        return len;
    } else if (strcmp(case_name, "max_4096") == 0) {
        uint32_t len = MAX_PAYLOAD;
        for (uint32_t i = 0; i < len; i++) buf[i] = (uint8_t)(i & 0xFF);
        return len;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s server <port> | client <host> <port> <case>\n", argv[0]);
        return 2;
    }

    const char *mode = argv[1];

    if (strcmp(mode, "server") == 0) {
        if (argc < 3) return 2;
        int port = atoi(argv[2]);

        int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_sock < 0) { perror("socket"); return 1; }
        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons((uint16_t)port);
        if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind"); close(listen_sock); return 1;
        }
        if (listen(listen_sock, 1) < 0) {
            perror("listen"); close(listen_sock); return 1;
        }
        socklen_t addr_len = sizeof(addr);
        getsockname(listen_sock, (struct sockaddr *)&addr, &addr_len);
        int actual_port = ntohs(addr.sin_port);
        printf("PORT=%d\n", actual_port);
        fflush(stdout);

        emit_identity();

        int conn = accept(listen_sock, NULL, NULL);
        if (conn < 0) { perror("accept"); close(listen_sock); return 1; }

        uint8_t buf[MAX_PAYLOAD + 1];
        int len = recv_message(conn, buf, MAX_PAYLOAD);
        if (len < 0) {
            printf("SERVER_DONE reject\n");
            fflush(stdout);
            close(conn);
            close(listen_sock);
            return 1;
        }

#ifdef CANDIDATE
        /* Synthetic defect: truncate payloads larger than CANDIDATE_TRUNCATE. */
        if ((uint32_t)len > CANDIDATE_TRUNCATE) {
            len = CANDIDATE_TRUNCATE;
        }
#endif

        if (send_message(conn, buf, (uint32_t)len) < 0) {
            printf("SERVER_DONE reject\n");
            fflush(stdout);
            close(conn);
            close(listen_sock);
            return 1;
        }

        close(conn);
        close(listen_sock);
        printf("SERVER_DONE ok\n");
        return 0;
    }

    if (strcmp(mode, "client") == 0) {
        if (argc < 5) {
            fprintf(stderr, "usage: %s client <host> <port> <case>\n", argv[0]);
            return 2;
        }
        const char *host = argv[2];
        int port = atoi(argv[3]);
        const char *case_name = argv[4];

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { perror("socket"); return 1; }
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
            fprintf(stderr, "client: invalid address\n");
            close(sock);
            return 1;
        }
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("connect");
            close(sock);
            return 1;
        }

        emit_identity();

        uint8_t buf[MAX_PAYLOAD + 1];
        uint32_t payload_len = build_payload(case_name, buf, MAX_PAYLOAD);

        /* malformed_length: send length 0xFFFFFFFF (server must reject). */
        if (strcmp(case_name, "malformed_length") == 0) {
            uint8_t hdr[4] = {0xFF, 0xFF, 0xFF, 0xFF};
            if (send(sock, hdr, 4, 0) != 4) {
                printf("CLIENT_DONE reject\n");
                return 1;
            }
            close(sock);
            printf("CLIENT_DONE reject\n");
            return 1;
        }

        /* truncated: send length 10 with only 5 bytes of payload. */
        if (strcmp(case_name, "truncated") == 0) {
            uint8_t hdr[4] = {0, 0, 0, 10};
            if (send(sock, hdr, 4, 0) != 4) {
                printf("CLIENT_DONE reject\n");
                return 1;
            }
            if (send(sock, buf, 5, 0) != 5) {
                printf("CLIENT_DONE reject\n");
                return 1;
            }
            close(sock);
            printf("CLIENT_DONE reject\n");
            return 1;
        }

        /* oversize_common: send length 4097 with 4096 bytes of payload. */
        if (strcmp(case_name, "oversize_common") == 0) {
            uint8_t hdr[4];
            uint32_t len = MAX_PAYLOAD + 1;
            hdr[0] = (len >> 24) & 0xFF;
            hdr[1] = (len >> 16) & 0xFF;
            hdr[2] = (len >> 8) & 0xFF;
            hdr[3] = len & 0xFF;
            if (send(sock, hdr, 4, 0) != 4) {
                printf("CLIENT_DONE reject\n");
                return 1;
            }
            if (send(sock, buf, MAX_PAYLOAD, 0) != MAX_PAYLOAD) {
                printf("CLIENT_DONE reject\n");
                return 1;
            }
            close(sock);
            printf("CLIENT_DONE reject\n");
            return 1;
        }

        /* Normal cases: send length-prefixed payload, receive echo, compare. */
        if (send_message(sock, buf, payload_len) < 0) {
            printf("CLIENT_DONE reject\n");
            return 1;
        }
        uint8_t resp[MAX_PAYLOAD + 1];
        int resp_len = recv_message(sock, resp, MAX_PAYLOAD);
        if (resp_len < 0) {
            printf("CLIENT_DONE reject\n");
            return 1;
        }
        int match = (resp_len == (int)payload_len) && (memcmp(buf, resp, (size_t)resp_len) == 0);
        printf("CLIENT_DONE ok match=%d sent=%u recv=%d\n", match, payload_len, resp_len);
        close(sock);
        return match ? 0 : 1;
    }

    fprintf(stderr, "unknown mode: %s\n", mode);
    return 2;
}
