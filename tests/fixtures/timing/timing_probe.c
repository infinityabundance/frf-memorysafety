/*
 * Phase 12.2a timing probe.
 *
 * Three non-inlined functions with distinct execution-path profiles:
 *   - secret_branch(int secret): real secret-dependent branch; prints or
 *     returns a branch-taken marker.
 *   - constant_time(int secret): arithmetic/masked path with no secret-dependent
 *     branch (must be verified with objdump that no conditional branch exists).
 *   - length_sensitive(const char *s, size_t n): loop whose iteration count
 *     depends on the representation length.
 *
 * Compiled with: gcc -O1 -fno-inline -fno-builtin -g timing_probe.c -o timing_probe
 * The functions must not be inlined so nm/objdump can find them exactly.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile unsigned int branch_sink;

__attribute__((noinline)) int secret_branch(int secret) {
    int branch_taken = 0;
    if (secret) {
        branch_taken = 1;
        /* Additional work in the taken path so the Ir divergence is measurable.
         * The volatile sink prevents the compiler from eliminating the loop. */
        unsigned int acc = 0;
        for (int i = 0; i < 3; i++) {
            acc += (unsigned int)(secret + i);
        }
        branch_sink = acc;
    }
    return branch_taken;
}

__attribute__((noinline)) int constant_time(int secret) {
    unsigned int acc = 0;
    unsigned int mask = (unsigned int)(secret - 1) * 0u;
    /* Arithmetic selection without a secret-dependent branch. */
    unsigned int s = (unsigned int)secret;
    unsigned int m = 0u - (s & 1u);
    acc += s & (~m + 1u);
    acc += s & (m);
    acc ^= acc >> 27;
    acc *= 0x7feb352du;
    acc ^= acc >> 27;
    return (int)(acc & 0xFFFFFFFFu);
}

__attribute__((noinline)) int length_sensitive(const char *s, size_t n) {
    int total = 0;
    for (size_t i = 0; i < n; i++) {
        total += (unsigned char)s[i];
    }
    return total;
}

__attribute__((noinline)) int length_sensitive_fixed(size_t n) {
    /* Fixed 64-byte buffer with known content. */
    static const char buf[64] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    };
    int total = 0;
    for (size_t i = 0; i < n && i < 64; i++) {
        total += (unsigned char)buf[i];
    }
    return total;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        return 2;
    }
    const char *mode = argv[1];
    long value = strtol(argv[2], NULL, 10);

    if (strcmp(mode, "branch") == 0) {
        int result = secret_branch((int)value);
        printf("mode=%s branch_taken=%d result=%d\n", mode, result, result);
    } else if (strcmp(mode, "ct") == 0) {
        int result = constant_time((int)value);
        printf("mode=%s result=%d\n", mode, result);
    } else if (strcmp(mode, "length") == 0) {
        size_t n = (size_t)value;
        int result = length_sensitive_fixed(n);
        printf("mode=%s iterations=%zu result=%d\n", mode, n, result);
    } else {
        return 2;
    }
    return 0;
}
