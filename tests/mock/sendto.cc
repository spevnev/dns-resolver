#include <arpa/inet.h>
#include <sys/socket.h>
#include <cassert>
#include <cstdio>
#include <vector>
#include "mock_config.hh"

std::vector<uint8_t> request_buffer;

extern "C" {
ssize_t sendto(int _fd, const void *buffer, size_t length, int _flags, const struct sockaddr *addr,
               socklen_t addr_len) {
    (void) _fd;
    (void) _flags;

    auto ip_addr = reinterpret_cast<const struct sockaddr_in *>(addr);
    assert(addr_len == sizeof(*ip_addr));

    auto buffer_ptr = reinterpret_cast<const uint8_t *>(buffer);
    request_buffer.assign(buffer_ptr, buffer_ptr + length);

    return length;
}
}
