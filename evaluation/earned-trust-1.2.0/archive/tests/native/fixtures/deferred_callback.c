/*
 * Phase 4.2 negative fixture: a deferred callback fires after the object was
 * freed and then uses the stale token.
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
    event("t0", 2, "\"kind\":\"free\",\"object\":\"obj\",\"token\":\"tok0\"");
    event("t0", 3,
          "\"kind\":\"callback_enter\",\"object\":\"obj\",\"token\":\"tok0\","
          "\"callback\":\"on_done\"");
    event("t0", 4,
          "\"kind\":\"use\",\"object\":\"obj\",\"token\":\"tok0\",\"access\":\"read\"");
    event("t0", 5,
          "\"kind\":\"callback_exit\",\"object\":\"obj\",\"token\":\"tok0\","
          "\"callback\":\"on_done\",\"outcome\":\"ok\"");
    return 0;
}
