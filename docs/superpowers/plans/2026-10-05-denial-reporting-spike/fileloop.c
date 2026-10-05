/*
 * fileloop -- the file-heavy workload the denial-reporting spike is measured on. It opens, reads
 * one byte from and closes a file a given number of times and prints the nanoseconds one round
 * took, so the cost of a trapped openat can be read off directly. Not part of Phobos.
 *
 * Usage: fileloop PATH ROUNDS
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int main(int argument_count, char *arguments[]) {
    if (argument_count != 3) {
        fprintf(stderr, "usage: fileloop PATH ROUNDS\n");
        return 2;
    }
    const char *path = arguments[1];
    long rounds = strtol(arguments[2], nullptr, 10);
    long refused = 0;
    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (long round = 0; round < rounds; round++) {
        int descriptor = open(path, O_RDONLY | O_CLOEXEC);
        if (descriptor < 0) {
            refused++;
            continue;
        }
        char byte;
        if (read(descriptor, &byte, 1) < 0) {
            refused++;
        }
        close(descriptor);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double nanoseconds = (double)(end.tv_sec - start.tv_sec) * 1e9 + (double)(end.tv_nsec - start.tv_nsec);
    printf("fileloop %s rounds=%ld refused=%ld ns_per_round=%.0f\n", path, rounds, refused,
           nanoseconds / (double)rounds);
    return 0;
}
