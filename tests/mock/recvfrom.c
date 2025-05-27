#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "config.h"
#include "response.h"

ssize_t recvfrom(int fd, void *buffer, size_t buffer_size, int flags, struct sockaddr *addr, socklen_t *addr_len) {
    (void) fd;
    (void) flags;

    struct sockaddr_in ip_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(NAMESERVER_PORT),
        .sin_zero = {0},
    };
    int result = inet_pton(AF_INET, NAMESERVER_IP, &ip_addr.sin_addr);
    assert(result == 1);

    memcpy(addr, &ip_addr, sizeof(ip_addr));
    *addr_len = sizeof(ip_addr);

    assert(response_length <= buffer_size);
    memcpy(buffer, response, response_length);
    memcpy(buffer, &request_id, sizeof(request_id));

    return response_length;
}
