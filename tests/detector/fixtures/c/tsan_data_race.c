/* Test-only ThreadSanitizer canary: unsynchronized access to a global after a
   common barrier. The barrier makes both threads alive at the same time, and
   the subsequent plain increments are concurrent. */
#define _POSIX_C_SOURCE 200112L

#include <pthread.h>

static pthread_barrier_t barrier;
static int shared;

static void *worker(void *argument) {
    (void)argument;
    int barrier_result = pthread_barrier_wait(&barrier);
    if (barrier_result != 0 && barrier_result != PTHREAD_BARRIER_SERIAL_THREAD) {
        return NULL;
    }
    shared += 1;
    return NULL;
}

int main(void) {
    pthread_t thread;
    if (pthread_barrier_init(&barrier, NULL, 2) != 0) {
        return 2;
    }
    if (pthread_create(&thread, NULL, worker, NULL) != 0) {
        return 3;
    }
    int barrier_result = pthread_barrier_wait(&barrier);
    if (barrier_result != 0 && barrier_result != PTHREAD_BARRIER_SERIAL_THREAD) {
        return 4;
    }
    shared += 1;
    if (pthread_join(thread, NULL) != 0) {
        return 5;
    }
    pthread_barrier_destroy(&barrier);
    return shared == 2 ? 0 : 6;
}
