/*
 * Phase 4.2 positive control: conflicting accesses on an atomic object.
 * Explicit synchronizes-with edges order the lifecycle metadata writes, so the
 * only cross-thread conflict is atomic-versus-atomic and is permitted.
 */
#include <stdio.h>

static void event(const char *thread, unsigned long seq, const char *fields) {
    printf("{\"record\":\"event\",\"thread\":\"%s\",\"seq\":%lu,%s}\n",
           thread, seq, fields);
}

static void sync_edge(const char *from_thread, unsigned long from_seq,
                      const char *to_thread, unsigned long to_seq) {
    printf("{\"record\":\"sync\",\"from_thread\":\"%s\",\"from_seq\":%lu,"
           "\"to_thread\":\"%s\",\"to_seq\":%lu}\n",
           from_thread, from_seq, to_thread, to_seq);
}

int main(void) {
    event("t0", 0,
          "\"kind\":\"create\",\"object\":\"obj\",\"token\":\"tok0\","
          "\"owner\":\"task-a\",\"generation\":0");
    event("t0", 1, "\"kind\":\"init_complete\",\"object\":\"obj\",\"token\":\"tok0\"");
    event("t1", 0,
          "\"kind\":\"use\",\"object\":\"obj\",\"token\":\"tok0\","
          "\"access\":\"atomic_write\"");
    event("t0", 2,
          "\"kind\":\"use\",\"object\":\"obj\",\"token\":\"tok0\","
          "\"access\":\"atomic_read\"");
    event("t0", 3, "\"kind\":\"free\",\"object\":\"obj\",\"token\":\"tok0\"");
    sync_edge("t0", 1, "t1", 0);
    sync_edge("t1", 0, "t0", 2);
    return 0;
}
