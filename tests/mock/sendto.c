#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "response.h"

uint16_t request_id;

ssize_t sendto(int fd, const void *buffer, size_t length, int flags, const struct sockaddr *addr, socklen_t addr_len) {
    (void) fd;
    (void) flags;

    struct sockaddr_in *ip_addr = (struct sockaddr_in *) addr;
    assert(addr_len == sizeof(*ip_addr));

    assert(length > sizeof(request_id));
    memcpy(&request_id, buffer, sizeof(request_id));

    return length;
}
