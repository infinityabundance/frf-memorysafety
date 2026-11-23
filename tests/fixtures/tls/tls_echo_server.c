/*
 * Phase 13.2 TLS echo server fixture.
 *
 * Compiled against reference and candidate OpenSSL prefixes:
 *   gcc -O1 -fno-inline -fno-builtin -g -I<prefix>/include \
 *       -L<prefix>/lib -Wl,-rpath,<prefix>/lib \
 *       tls_echo_server.c -o tls_echo_server -lssl -lcrypto
 *
 * Protocol: TLS 1.3 echo server. Accepts one connection, reads a message,
 * echoes it back, and exits. Emits a JSON identity line containing the real
 * /proc/self/exe and /proc/self/maps lines.
 *
 * Usage: tls_echo_server <port> <cert_file> <key_file>
 *   port=0 means OS-assigned port; actual port printed as PORT=<n>
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

/* Create SSL_CTX for server. */
static SSL_CTX *create_server_ctx(const char *cert_file, const char *key_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        print_ssl_errors("SSL_CTX_new");
        return NULL;
    }

    /* Set minimum TLS version to 1.3. */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    /* Load certificate. */
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        print_ssl_errors("SSL_CTX_use_certificate_file");
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Load private key. */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        print_ssl_errors("SSL_CTX_use_PrivateKey_file");
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Verify private key matches certificate. */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

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

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s server <port> <cert_file> <key_file>\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "server") != 0) {
        fprintf(stderr, "unknown mode: %s\n", argv[1]);
        return 2;
    }

    int port = atoi(argv[2]);
    const char *cert_file = argv[3];
    const char *key_file = argv[4];

    init_openssl();

    SSL_CTX *ctx = create_server_ctx(cert_file, key_file);
    if (!ctx) {
        return 1;
    }

    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) { perror("socket"); SSL_CTX_free(ctx); return 1; }
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(listen_sock); SSL_CTX_free(ctx); return 1;
    }
    if (listen(listen_sock, 1) < 0) {
        perror("listen"); close(listen_sock); SSL_CTX_free(ctx); return 1;
    }
    socklen_t addr_len = sizeof(addr);
    getsockname(listen_sock, (struct sockaddr *)&addr, &addr_len);
    int actual_port = ntohs(addr.sin_port);
    printf("PORT=%d\n", actual_port);
    fflush(stdout);

    emit_identity();

    int conn = accept(listen_sock, NULL, NULL);
    if (conn < 0) { perror("accept"); close(listen_sock); SSL_CTX_free(ctx); return 1; }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        print_ssl_errors("SSL_new");
        close(conn);
        close(listen_sock);
        SSL_CTX_free(ctx);
        return 1;
    }
    SSL_set_fd(ssl, conn);

    if (SSL_accept(ssl) <= 0) {
        print_ssl_errors("SSL_accept");
        SSL_free(ssl);
        close(conn);
        close(listen_sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    uint8_t buf[MAX_MSG + 1];
    int len = ssl_recv_message(ssl, buf, MAX_MSG);
    if (len < 0) {
        printf("SERVER_DONE reject\n");
        fflush(stdout);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(conn);
        close(listen_sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    if (ssl_send_message(ssl, buf, (uint32_t)len) < 0) {
        printf("SERVER_DONE reject\n");
        fflush(stdout);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(conn);
        close(listen_sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(conn);
    close(listen_sock);
    SSL_CTX_free(ctx);

    printf("SERVER_DONE ok\n");
    return 0;
}