/*
 * Phase 4.2 negative fixture: conflicting non-atomic accesses on two logical
 * threads with no synchronizes-with edge. The schedule is scripted.
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
          "\"kind\":\"use\",\"object\":\"obj\",\"token\":\"tok0\",\"access\":\"write\"");
    event("t1", 0,
          "\"kind\":\"use\",\"object\":\"obj\",\"token\":\"tok0\",\"access\":\"read\"");
    event("t1", 1, "\"kind\":\"free\",\"object\":\"obj\",\"token\":\"tok0\"");
    return 0;
}
