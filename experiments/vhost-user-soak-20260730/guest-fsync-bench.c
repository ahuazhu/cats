#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t monotonic_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &now) != 0) {
        perror("clock_gettime");
        exit(2);
    }
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static uint64_t parse_u64(const char *value, const char *name) {
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "invalid %s: %s\n", name, value);
        exit(2);
    }
    return (uint64_t)parsed;
}

static void write_all_at(int fd, const void *buffer, size_t length, off_t offset) {
    const uint8_t *cursor = buffer;
    size_t remaining = length;
    while (remaining > 0) {
        ssize_t written = pwrite(fd, cursor, remaining, offset);
        if (written < 0) {
            perror("pwrite");
            exit(3);
        }
        if (written == 0) {
            fprintf(stderr, "pwrite returned zero\n");
            exit(3);
        }
        cursor += (size_t)written;
        remaining -= (size_t)written;
        offset += written;
    }
}

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr,
                "usage: %s PATH SAMPLES START_INDEX SLOTS STRIDE_BYTES WRITE_BYTES\n",
                argv[0]);
        return 2;
    }

    const char *path = argv[1];
    uint64_t samples = parse_u64(argv[2], "samples");
    uint64_t start_index = parse_u64(argv[3], "start_index");
    uint64_t slots = parse_u64(argv[4], "slots");
    uint64_t stride = parse_u64(argv[5], "stride_bytes");
    uint64_t write_bytes = parse_u64(argv[6], "write_bytes");
    if (samples == 0 || slots == 0 || write_bytes == 0 || write_bytes > stride ||
        write_bytes > SIZE_MAX) {
        fprintf(stderr, "samples, slots, stride, and write size are inconsistent\n");
        return 2;
    }
    if (slots > (uint64_t)INT64_MAX / stride) {
        fprintf(stderr, "file size overflows off_t\n");
        return 2;
    }

    int fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        perror("open");
        return 3;
    }
    off_t logical_size = (off_t)(slots * stride);
    if (ftruncate(fd, logical_size) != 0) {
        perror("ftruncate");
        close(fd);
        return 3;
    }

    uint8_t *payload = NULL;
    int alloc_error = posix_memalign((void **)&payload, 4096, (size_t)write_bytes);
    if (alloc_error != 0) {
        fprintf(stderr, "posix_memalign: %s\n", strerror(alloc_error));
        close(fd);
        return 3;
    }

    puts("sample,write_us,fsync_us,total_us,offset");
    for (uint64_t sample = 0; sample < samples; sample++) {
        uint64_t logical_index = start_index + sample;
        memset(payload, (int)(logical_index & 0xff), (size_t)write_bytes);
        off_t offset = (off_t)((logical_index % slots) * stride);

        uint64_t total_started = monotonic_ns();
        uint64_t write_started = monotonic_ns();
        write_all_at(fd, payload, (size_t)write_bytes, offset);
        uint64_t write_finished = monotonic_ns();
        if (fsync(fd) != 0) {
            perror("fsync");
            free(payload);
            close(fd);
            return 4;
        }
        uint64_t finished = monotonic_ns();
        printf("%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
               sample,
               (write_finished - write_started) / UINT64_C(1000),
               (finished - write_finished) / UINT64_C(1000),
               (finished - total_started) / UINT64_C(1000),
               (uint64_t)offset);
    }

    free(payload);
    if (close(fd) != 0) {
        perror("close");
        return 4;
    }
    return 0;
}
