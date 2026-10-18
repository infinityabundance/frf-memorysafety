/* Phase 7.2 loader-map capture probe.
 *
 * LD_PRELOAD this object into a provider process and set FRF_DSO_MAP to a
 * writable path. The constructor copies /proc/self/maps before main runs, so
 * the recorded closure is the loader's actual map rather than a declared
 * dependency list. The probe itself is excluded by the bridge capture.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) static void frf_dso_probe(void) {
    const char *out = getenv("FRF_DSO_MAP");
    if (out == NULL) {
        return;
    }
    int in = open("/proc/self/maps", O_RDONLY);
    int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (in < 0 || fd < 0) {
        if (in >= 0) {
            close(in);
        }
        if (fd >= 0) {
            close(fd);
        }
        return;
    }
    char buffer[4096];
    ssize_t count;
    while ((count = read(in, buffer, sizeof buffer)) > 0) {
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t written = write(fd, buffer + offset, (size_t)(count - offset));
            if (written <= 0) {
                break;
            }
            offset += written;
        }
    }
    close(in);
    close(fd);
}
