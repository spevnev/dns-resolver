#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "mock_config.h"

uint8_t request_buffer[65536];
size_t request_length;

ssize_t sendto(int fd, const void *buffer, size_t length, int flags, const struct sockaddr *addr, socklen_t addr_len) {
    (void) fd;
    (void) flags;

    struct sockaddr_in *ip_addr = (struct sockaddr_in *) addr;
    assert(addr_len == sizeof(*ip_addr));

    assert(sizeof(request_buffer) >= length);
    memcpy(request_buffer, buffer, length);
    request_length = length;

    return length;
}
