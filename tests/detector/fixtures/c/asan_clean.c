/* Test-only AddressSanitizer harmless control: valid heap lifetime. */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *value = malloc(sizeof(*value));
    if (value == NULL) {
        return 2;
    }
    *value = 7;
    int observed = *value;
    free(value);
    printf("asan clean control %d\n", observed);
    return 0;
}
