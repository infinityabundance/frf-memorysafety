/*
 * Phase 4.2 negative fixture: a second mutable borrow while the first is live.
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
          "\"kind\":\"borrow_mutable\",\"object\":\"obj\","
          "\"from_token\":\"tok0\",\"token\":\"m0\"");
    event("t0", 3,
          "\"kind\":\"borrow_mutable\",\"object\":\"obj\","
          "\"from_token\":\"tok0\",\"token\":\"m1\"");
    event("t0", 4, "\"kind\":\"borrow_end\",\"object\":\"obj\",\"token\":\"m0\"");
    event("t0", 5, "\"kind\":\"free\",\"object\":\"obj\",\"token\":\"tok0\"");
    return 0;
}
