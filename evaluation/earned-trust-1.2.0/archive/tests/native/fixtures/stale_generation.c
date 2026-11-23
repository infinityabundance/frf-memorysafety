/*
 * Phase 4.2 negative fixture: reallocate advances the generation, then the old
 * owning token is used.
 */
#include <stdio.h>

static void event(const char *thread, unsigned long seq, const char *fields) {
    printf("{\"record\":\"event\",\"thread\":\"%s\",\"seq\":%lu,%s}\n",
           thread, seq, fields);
}

int main(void) {
    event("t0", 0,
          "\"kind\":\"create\",\"object\":\"obj\",\"token\":\"tok0\","
          "\"owner\":\"task-a\",\"generation\":0");
    event("t0", 1, "\"kind\":\"init_complete\",\"object\":\"obj\",\"token\":\"tok0\"");
    event("t0", 2,
          "\"kind\":\"reallocate\",\"object\":\"obj\",\"from_token\":\"tok0\","
          "\"token\":\"tok1\",\"owner\":\"task-a\",\"generation\":1");
    event("t0", 3,
          "\"kind\":\"use\",\"object\":\"obj\",\"token\":\"tok0\",\"access\":\"read\"");
    event("t0", 4, "\"kind\":\"init_complete\",\"object\":\"obj\",\"token\":\"tok1\"");
    event("t0", 5, "\"kind\":\"free\",\"object\":\"obj\",\"token\":\"tok1\"");
    return 0;
}
