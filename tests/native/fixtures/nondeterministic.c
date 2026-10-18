/*
 * Phase 4.2 nondeterminism control: otherwise legal events carry pid and clock
 * values in `detail`. Identical executable input therefore produces different
 * canonical transcripts and must be marked unresolved on replay.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <time.h>
#include <unistd.h>

static void event(const char *thread, unsigned long seq, const char *fields) {
    printf("{\"record\":\"event\",\"thread\":\"%s\",\"seq\":%lu,%s}\n",
           thread, seq, fields);
}

int main(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long pid = (long)getpid();
    long long stamp = (long long)now.tv_nsec;

    printf("{\"record\":\"event\",\"thread\":\"t0\",\"seq\":0,"
           "\"kind\":\"create\",\"object\":\"obj\",\"token\":\"tok0\","
           "\"owner\":\"task-a\",\"generation\":0,\"detail\":\"pid=%ld;mono_ns=%lld\"}\n",
           pid, stamp);
    event("t0", 1, "\"kind\":\"init_complete\",\"object\":\"obj\",\"token\":\"tok0\"");
    printf("{\"record\":\"event\",\"thread\":\"t0\",\"seq\":2,"
           "\"kind\":\"use\",\"object\":\"obj\",\"token\":\"tok0\","
           "\"access\":\"write\",\"detail\":\"pid=%ld;mono_ns=%lld\"}\n",
           pid, stamp);
    event("t0", 3,
          "\"kind\":\"transfer\",\"object\":\"obj\",\"from_token\":\"tok0\","
          "\"to_token\":\"tok1\",\"to_owner\":\"task-b\"");
    event("t0", 4,
          "\"kind\":\"use\",\"object\":\"obj\",\"token\":\"tok1\",\"access\":\"read\"");
    event("t0", 5, "\"kind\":\"free\",\"object\":\"obj\",\"token\":\"tok1\"");
    return 0;
}
