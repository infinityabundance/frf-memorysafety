/*
 * Phase 4.2 positive fixture: create, initialize, use, transfer, use, free.
 * The event stream is a scripted deterministic schedule, not an observation of
 * an operating-system scheduler.
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
    event("t0", 3,
          "\"kind\":\"transfer\",\"object\":\"obj\",\"from_token\":\"tok0\","
          "\"to_token\":\"tok1\",\"to_owner\":\"task-b\"");
    event("t0", 4,
          "\"kind\":\"use\",\"object\":\"obj\",\"token\":\"tok1\",\"access\":\"read\"");
    event("t0", 5, "\"kind\":\"free\",\"object\":\"obj\",\"token\":\"tok1\"");
    return 0;
}
