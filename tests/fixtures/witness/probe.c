/*
 * Phase 11.2 execution witness probe.
 *
 * A small C program with a non-inlined global function witness_probe(int)
 * that prints canonical JSON containing /proc/self/exe, its real argv (read
 * from /proc/self/cmdline), and its /proc/self/maps lines.
 *
 * Compiled with: gcc -O0 -g -fno-inline -o witness_probe probe.c
 * The function must not be inlined so nm/objdump can find it exactly.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void json_string(const char *s, size_t n) {
    putchar('"');
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':
            fputs("\\\"", stdout);
            break;
        case '\\':
            fputs("\\\\", stdout);
            break;
        case '\n':
            fputs("\\n", stdout);
            break;
        case '\r':
            fputs("\\r", stdout);
            break;
        case '\t':
            fputs("\\t", stdout);
            break;
        default:
            if (c < 0x20) {
                printf("\\u%04x", c);
            } else {
                putchar(c);
            }
        }
    }
    putchar('"');
}

__attribute__((noinline)) void witness_probe(int argc) {
    (void)argc;

    char exe[4096];
    ssize_t exe_len = readlink("/proc/self/exe", exe, sizeof(exe));
    if (exe_len < 0) {
        exe_len = 0;
    }

    char cmdline[8192];
    ssize_t cmd_len = 0;
    int cfd = open("/proc/self/cmdline", O_RDONLY);
    if (cfd >= 0) {
        cmd_len = read(cfd, cmdline, sizeof(cmdline));
        close(cfd);
        if (cmd_len < 0) {
            cmd_len = 0;
        }
    }

    size_t maps_cap = 1u << 20;
    char *maps = malloc(maps_cap);
    size_t maps_len = 0;
    int mfd = open("/proc/self/maps", O_RDONLY);
    if (mfd >= 0 && maps != NULL) {
        ssize_t got;
        while (maps_len < maps_cap &&
               (got = read(mfd, maps + maps_len, maps_cap - maps_len)) > 0) {
            maps_len += (size_t)got;
        }
        close(mfd);
    }
    if (maps == NULL) {
        maps = "";
        maps_len = 0;
    }

    printf("{\"argv\":[");
    size_t start = 0;
    int first = 1;
    for (size_t i = 0; i < (size_t)cmd_len; i++) {
        if (cmdline[i] == '\0') {
            if (!first) {
                putchar(',');
            }
            first = 0;
            json_string(cmdline + start, i - start);
            start = i + 1;
        }
    }
    printf("],\"exe\":");
    json_string(exe, (size_t)exe_len);
    printf(",\"maps\":[");
    start = 0;
    first = 1;
    for (size_t i = 0; i < maps_len; i++) {
        if (maps[i] == '\n') {
            if (!first) {
                putchar(',');
            }
            first = 0;
            json_string(maps + start, i - start);
            start = i + 1;
        }
    }
    printf("],\"schema\":\"frf-etp.execution-witness.v1\",");
    printf("\"spec\":\"frf-etp-execution-witness-v1\"}\n");

    free(maps);
}

int main(int argc, char **argv) {
    (void)argv;
    witness_probe(argc);
    return 0;
}
