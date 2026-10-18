/* Test-only AddressSanitizer canary: write through a freed heap pointer. */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    volatile int *value = malloc(sizeof(*value));
    if (value == NULL) {
        return 2;
    }
    *value = 1;
    free((void *)value);
    *value = 2;
    printf("asan bad fixture %d\n", *value);
    return 0;
}
