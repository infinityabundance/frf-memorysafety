/*
 * Phase 4.2 output-bound control: emits roughly 350 KiB, which exceeds the
 * harness capture limit and must be rejected rather than parsed or verified.
 */
#include <stdio.h>
#include <string.h>

int main(void) {
    char padding[512];
    memset(padding, 'x', sizeof(padding) - 1);
    padding[sizeof(padding) - 1] = '\0';
    for (unsigned long index = 0; index < 600; index++) {
        printf("{\"record\":\"event\",\"thread\":\"t0\",\"seq\":%lu,"
               "\"kind\":\"use\",\"object\":\"obj\",\"token\":\"tok0\","
               "\"access\":\"read\",\"detail\":\"%s\"}\n",
               index, padding);
    }
    return 0;
}
