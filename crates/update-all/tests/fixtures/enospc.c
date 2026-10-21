/* Linux process fixture: fail only selected evidence writes, never fill disk. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
ssize_t write(int fd, const void *buf, size_t count) {
    ssize_t (*real_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
    const char *target = getenv("EVIDENCE_FAILURE_TARGET");
    const char *armed = getenv("EVIDENCE_FAILURE_ARMED");
    if (target && (!armed || access(armed, F_OK) == 0)) {
        char link[64], path[4096];
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        ssize_t length = readlink(link, path, sizeof(path) - 1);
        if (length > 0) {
            path[length] = 0;
            size_t wanted = strlen(target);
            if ((size_t)length >= wanted && !strcmp(path + length - wanted, target)) {
                errno = ENOSPC;
                return -1;
            }
        }
    }
    return real_write(fd, buf, count);
}

/* Independently target the durability boundary after successful evidence writes. */
int fsync(int fd) {
    int (*real_fsync)(int) = dlsym(RTLD_NEXT, "fsync");
    const char *target = getenv("EVIDENCE_SYNC_FAILURE_TARGET");
    if (target && target[0] != '\0') {
        char link[64], path[4096];
        int formatted = snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        if (formatted > 0 && (size_t)formatted < sizeof(link)) {
            ssize_t length = readlink(link, path, sizeof(path) - 1);
            if (length > 0 && (size_t)length < sizeof(path) - 1) {
                path[length] = '\0';
                size_t wanted = strlen(target);
                if ((size_t)length >= wanted && !strcmp(path + length - wanted, target)) {
                    errno = ENOSPC;
                    return -1;
                }
            }
        }
    }
    if (!real_fsync) {
        errno = ENOSYS;
        return -1;
    }
    return real_fsync(fd);
}
