/*
 * Phase 13.2 TLS echo client fixture.
 *
 * Compiled against reference and candidate OpenSSL prefixes:
 *   gcc -O1 -fno-inline -fno-builtin -g -I<prefix>/include \
 *       -L<prefix>/lib -Wl,-rpath,<prefix>/lib \
 *       tls_echo_client.c -o tls_echo_client -lssl -lcrypto
 *
 * Protocol: TLS 1.3 echo client. Connects to 127.0.0.1, verifies the server
 * with a supplied CA file, sends a message, checks the echo, and exits.
 * Emits a JSON identity line containing the real /proc/self/exe and
 * /proc/self/maps lines.
 *
 * Usage: tls_echo_client <host> <port> <ca_file> <case>
 *   case: "tls13_echo" or "wrong_ca"
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
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define MAX_MSG 4096

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
   non-printable bytes as \xHH so output is valid UTF-8. /proc/self/exe is a
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

/* Print OpenSSL errors to stderr. */
static void print_ssl_errors(const char *prefix) {
    unsigned long err;
    while ((err = ERR_get_error())) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        fprintf(stderr, "%s: %s\n", prefix, buf);
    }
}

/* Initialize OpenSSL library. */
static void init_openssl(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

/* Create SSL_CTX for client. */
static SSL_CTX *create_client_ctx(const char *ca_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        print_ssl_errors("SSL_CTX_new");
        return NULL;
    }

    /* Set minimum TLS version to 1.3. */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    /* Load CA certificate for verification. */
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) <= 0) {
        print_ssl_errors("SSL_CTX_load_verify_locations");
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Enable certificate verification. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    return ctx;
}

/* Read a length-prefixed message from SSL connection. Returns length or -1. */
static int ssl_recv_message(SSL *ssl, uint8_t *buf, uint32_t max_len) {
    uint8_t hdr[4];
    int n = SSL_read(ssl, hdr, 4);
    if (n != 4) return -1;
    uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                   ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
    if (len > max_len) return -1;
    if (len > 0) {
        size_t total = 0;
        while (total < len) {
            n = SSL_read(ssl, buf + total, len - total);
            if (n <= 0) return -1;
            total += (size_t)n;
        }
    }
    return (int)len;
}

/* Send a length-prefixed message over SSL connection. Returns 0 on success. */
static int ssl_send_message(SSL *ssl, const uint8_t *buf, uint32_t len) {
    uint8_t hdr[4];
    hdr[0] = (len >> 24) & 0xFF;
    hdr[1] = (len >> 16) & 0xFF;
    hdr[2] = (len >> 8) & 0xFF;
    hdr[3] = len & 0xFF;
    if (SSL_write(ssl, hdr, 4) != 4) return -1;
    if (len > 0 && SSL_write(ssl, buf, len) != (int)len) return -1;
    return 0;
}

/* Build a payload for the given case name. Returns payload length.
   tls13_echo sends a 4096-byte payload to exercise the TLS record path; it is
   not a synthetic defect probe. */
static uint32_t build_payload(const char *case_name, uint8_t *buf, uint32_t max_len) {
    if (strcmp(case_name, "tls13_echo") == 0) {
        uint32_t len = 4096;
        if (len > max_len) len = max_len;
        for (uint32_t i = 0; i < len; i++) buf[i] = (uint8_t)(i & 0xFF);
        return len;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s client <host> <port> <ca_file> <case>\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "client") != 0) {
        fprintf(stderr, "unknown mode: %s\n", argv[1]);
        return 2;
    }

    const char *host = argv[2];
    int port = atoi(argv[3]);
    const char *ca_file = argv[4];
    const char *case_name = argv[5];

    init_openssl();

    SSL_CTX *ctx = create_client_ctx(ca_file);
    if (!ctx) {
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); SSL_CTX_free(ctx); return 1; }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        fprintf(stderr, "client: invalid address\n");
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    emit_identity();

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        print_ssl_errors("SSL_new");
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }
    SSL_set_fd(ssl, sock);

    /* Set SNI hostname for certificate verification. */
    SSL_set_tlsext_host_name(ssl, host);

    /* Connect and perform TLS handshake. */
    if (SSL_connect(ssl) <= 0) {
        print_ssl_errors("SSL_connect");
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    /* Verify certificate. */
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        fprintf(stderr, "Certificate verification failed: %s\n",
                X509_verify_cert_error_string(verify_result));
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    uint8_t buf[MAX_MSG + 1];
    uint32_t payload_len = build_payload(case_name, buf, MAX_MSG);

    if (ssl_send_message(ssl, buf, payload_len) < 0) {
        printf("CLIENT_DONE reject\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    uint8_t resp[MAX_MSG + 1];
    int resp_len = ssl_recv_message(ssl, resp, MAX_MSG);
    if (resp_len < 0) {
        printf("CLIENT_DONE reject\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    int match = (resp_len == (int)payload_len) && (memcmp(buf, resp, (size_t)resp_len) == 0);
    printf("CLIENT_DONE ok match=%d sent=%u recv=%d\n", match, payload_len, resp_len);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return match ? 0 : 1;
}