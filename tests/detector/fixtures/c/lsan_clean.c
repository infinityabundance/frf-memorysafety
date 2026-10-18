/* Test-only LeakSanitizer harmless control: allocate and free. */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *value = malloc(64);
    if (value == NULL) {
        return 2;
    }
    value[0] = 1;
    int observed = value[0];
    free(value);
    printf("lsan clean control %d\n", observed);
    return 0;
}
