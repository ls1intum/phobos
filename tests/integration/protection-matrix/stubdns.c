/*
 * A stub name server for the matrix: every A query is answered with 127.0.0.1, and a name whose first label
 * is "decoy" with 127.0.0.3; every other query type is answered with no record. It listens on one UDP port of
 * loopback, so it runs in a container with no network, and it ends after a number of seconds.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum { HEADER = 12, PACKET = 1500, TYPE_A = 1 };

int main(int argc, char **argv) {
    if (argc < 3) {
        return 2;
    }
    int server = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local = { .sin_family = AF_INET, .sin_port = htons((unsigned short)atoi(argv[1])) };
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(server, (struct sockaddr *)&local, sizeof(local)) != 0) {
        perror("bind");
        return 1;
    }
    puts("STUB-UP");
    fflush(stdout);
    for (int tick = 0; tick < atoi(argv[2]) * 10; tick++) {
        struct pollfd waiting = { .fd = server, .events = POLLIN };
        if (poll(&waiting, 1, 100) <= 0) {
            continue;
        }
        unsigned char query[PACKET];
        struct sockaddr_in from;
        socklen_t from_length = sizeof(from);
        ssize_t length = recvfrom(server, query, sizeof(query), 0, (struct sockaddr *)&from, &from_length);
        if (length < HEADER + 5) {
            continue;
        }
        size_t end = HEADER;
        while (end < (size_t)length && query[end] != 0) {
            end += (size_t)query[end] + 1;
        }
        end += 5;
        if (end > (size_t)length || end + 16 > PACKET) {
            continue;
        }
        int type = query[end - 4] * 256 + query[end - 3];
        unsigned char out[PACKET];
        memcpy(out, query, end);
        out[2] = (unsigned char)(0x81 | (query[2] & 0x01));
        out[3] = 0x80;
        memset(out + 6, 0, 6);
        size_t at = end;
        if (type == TYPE_A) {
            int decoy = memcmp(query + HEADER, "\x05" "decoy", 6) == 0;
            unsigned char record[] = { 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, decoy ? 3 : 1 };
            memcpy(out + at, record, sizeof(record));
            at += sizeof(record);
            out[7] = 1;
        }
        sendto(server, out, at, 0, (struct sockaddr *)&from, from_length);
    }
    return 0;
}
