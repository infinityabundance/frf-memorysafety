/*
 * Phase 12.3a cross-property fixture: allocation/ownership repair.
 *
 * Two non-inlined variants:
 *   - faulty_repair(size_t n, int fail_inject): adds fallible allocation but has one
 *     failure/relocation path that does not cleanse secret material before returning
 *     or freeing.
 *   - fixed_repair(size_t n, int fail_inject): cleanses secret material on every path,
 *     including allocation failure, partial initialization, failed ownership transfer,
 *     relocation, and normal free; uses a volatile/explicit wipe helper.
 *
 * The program takes a mode (`faulty`/`fixed`) and an allocation-failure injection
 * count, and emits a stable event trace (ALLOC, ALLOC_FAIL, INIT, USE, TRANSFER_FAIL,
 * RELOCATE, CLEANSE, FREE) plus a result.
 *
 * fail_inject semantics:
 *   0  no injected failure (normal path)
 *   1  the initial allocation fails (no secret material exists yet)
 *   2  the relocation allocation fails after secret material exists
 *
 * Two additional control modes demonstrate that the valgrind instrument is alive:
 *   - `leak`   deliberately leaks an allocation (valgrind leak detection control)
 *   - `uninit` deliberately reads uninitialized memory (valgrind uninit control)
 *
 * Compiled with: gcc -O1 -fno-inline -fno-builtin -g secret_buffer.c -o secret_buffer
 * The functions must not be inlined so nm/objdump can find them exactly.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile uint8_t *secret_ptr = NULL;
static volatile size_t secret_len = 0;

__attribute__((noinline)) void volatile_wipe(void) {
    if (secret_ptr) {
        for (size_t i = 0; i < secret_len; i++) {
            secret_ptr[i] = 0x00;
        }
        secret_len = 0;
    }
}

__attribute__((noinline)) int faulty_repair(size_t n, int fail_inject) {
    uint8_t *buf = NULL;

    // Initial allocation with failure injection.
    if (fail_inject == 1) {
        printf("ALLOC_FAIL\n");
        return 1;  // No secret material exists yet.
    }
    buf = malloc(n);
    if (!buf) {
        printf("ALLOC_FAIL\n");
        return 1;  // No secret material exists yet.
    }
    printf("ALLOC\n");

    // Initialize with secret content.
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t)(i & 0xFF);
    }
    secret_ptr = buf;
    secret_len = n;
    printf("INIT\n");

    // Use the secret.
    printf("USE\n");

    // Relocation attempt: allocate a new buffer and move the secret.
    if (fail_inject == 2) {
        printf("ALLOC_FAIL\n");
        // FAULTY: does not cleanse the original secret buffer before freeing.
        free(buf);
        secret_ptr = NULL;
        secret_len = 0;
        printf("FREE\n");
        return 1;
    }
    uint8_t *newbuf = malloc(n);
    if (!newbuf) {
        printf("ALLOC_FAIL\n");
        // FAULTY: does not cleanse the original secret buffer before freeing.
        free(buf);
        secret_ptr = NULL;
        secret_len = 0;
        printf("FREE\n");
        return 1;
    }
    printf("RELOCATE\n");
    memcpy(newbuf, buf, n);
    // Wipe the old buffer before releasing it.
    volatile_wipe();
    free(buf);
    secret_ptr = newbuf;
    secret_len = n;

    // Ownership transfer attempt.
    if (n % 3 == 0) {
        printf("TRANSFER_FAIL\n");
        // FAULTY: does not cleanse the relocated secret buffer before returning.
        free(newbuf);
        secret_ptr = NULL;
        secret_len = 0;
        printf("FREE\n");
        return 1;
    }

    // Normal path: cleanse before freeing.
    volatile_wipe();
    free(newbuf);
    secret_ptr = NULL;
    secret_len = 0;
    printf("CLEANSE\n");
    printf("FREE\n");
    return 0;
}

__attribute__((noinline)) int fixed_repair(size_t n, int fail_inject) {
    uint8_t *buf = NULL;

    // Initial allocation with failure injection.
    if (fail_inject == 1) {
        printf("ALLOC_FAIL\n");
        return 1;  // No secret material exists yet.
    }
    buf = malloc(n);
    if (!buf) {
        printf("ALLOC_FAIL\n");
        return 1;  // No secret material exists yet.
    }
    printf("ALLOC\n");

    // Initialize with secret content.
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t)(i & 0xFF);
    }
    secret_ptr = buf;
    secret_len = n;
    printf("INIT\n");

    // Use the secret.
    printf("USE\n");

    // Relocation attempt: allocate a new buffer and move the secret.
    if (fail_inject == 2) {
        printf("ALLOC_FAIL\n");
        // FIXED: cleanse the original secret buffer before freeing.
        volatile_wipe();
        free(buf);
        secret_ptr = NULL;
        secret_len = 0;
        printf("CLEANSE\n");
        printf("FREE\n");
        return 1;
    }
    uint8_t *newbuf = malloc(n);
    if (!newbuf) {
        printf("ALLOC_FAIL\n");
        // FIXED: cleanse the original secret buffer before freeing.
        volatile_wipe();
        free(buf);
        secret_ptr = NULL;
        secret_len = 0;
        printf("CLEANSE\n");
        printf("FREE\n");
        return 1;
    }
    printf("RELOCATE\n");
    memcpy(newbuf, buf, n);
    // Wipe the old buffer before releasing it.
    volatile_wipe();
    free(buf);
    secret_ptr = newbuf;
    secret_len = n;

    // Ownership transfer attempt.
    if (n % 3 == 0) {
        printf("TRANSFER_FAIL\n");
        // FIXED: cleanse the relocated secret buffer before returning.
        volatile_wipe();
        free(newbuf);
        secret_ptr = NULL;
        secret_len = 0;
        printf("CLEANSE\n");
        printf("FREE\n");
        return 1;
    }

    // Normal path: cleanse before freeing.
    volatile_wipe();
    free(newbuf);
    secret_ptr = NULL;
    secret_len = 0;
    printf("CLEANSE\n");
    printf("FREE\n");
    return 0;
}

/* Control: deliberately leak an allocation so valgrind leak detection fires. */
__attribute__((noinline)) int leak_control(size_t n) {
    uint8_t *buf = malloc(n);
    if (!buf) {
        printf("ALLOC_FAIL\n");
        return 1;
    }
    printf("ALLOC\n");
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t)(i & 0xFF);
    }
    printf("INIT\n");
    // Deliberately do not free buf: this is a leak.
    printf("result=0\n");
    return 0;
}

/* Control: deliberately read uninitialized memory so valgrind uninit detection fires. */
__attribute__((noinline)) int uninit_control(void) {
    // Stack variable that valgrind definitely knows is uninitialized.
    volatile uint8_t x;
    /* Force a read of x so valgrind tracks it as uninitialized. */
    printf("x = %d\n", x);
    (void)x;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        return 2;
    }
    const char *mode = argv[1];
    long value = strtol(argv[2], NULL, 10);
    int fail_inject = 0;
    if (argc >= 4) {
        fail_inject = atoi(argv[3]);
    }

    if (strcmp(mode, "faulty") == 0) {
        int result = faulty_repair((size_t)value, fail_inject);
        printf("result=%d\n", result);
    } else if (strcmp(mode, "fixed") == 0) {
        int result = fixed_repair((size_t)value, fail_inject);
        printf("result=%d\n", result);
    } else if (strcmp(mode, "leak") == 0) {
        int result = leak_control((size_t)value);
        printf("result=%d\n", result);
    } else if (strcmp(mode, "uninit") == 0) {
        int result = uninit_control();
        printf("result=%d\n", result);
    } else {
        return 2;
    }
    return 0;
}