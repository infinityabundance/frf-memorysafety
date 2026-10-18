/* Test-only ThreadSanitizer harmless control: C11 atomic increment. */
#include <pthread.h>
#include <stdatomic.h>

static atomic_int shared;

static void *worker(void *argument) {
    (void)argument;
    atomic_fetch_add_explicit(&shared, 1, memory_order_seq_cst);
    return NULL;
}

int main(void) {
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL) != 0) {
        return 2;
    }
    atomic_fetch_add_explicit(&shared, 1, memory_order_seq_cst);
    if (pthread_join(thread, NULL) != 0) {
        return 3;
    }
    return atomic_load_explicit(&shared, memory_order_seq_cst) == 2 ? 0 : 4;
}
