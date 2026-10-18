/* Test-only LeakSanitizer canary: allocate and never free. */
#include <stdlib.h>

static volatile char *leaked;

int main(void) {
    leaked = malloc(64);
    if (leaked == NULL) {
        return 2;
    }
    leaked[0] = 1;
    return 0;
}
