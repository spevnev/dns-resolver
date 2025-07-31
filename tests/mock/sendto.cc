#include <arpa/inet.h>
#include <sys/socket.h>
#include <cassert>
#include <cstdio>
#include <vector>
#include "mock_config.hh"

std::vector<uint8_t> request_buffer;

extern "C" {
ssize_t sendto(int _fd, const void *buf, size_t n, int _flags, const struct sockaddr *addr, socklen_t addr_len) {
    (void) _fd;
    (void) _flags;

    const auto *ip_addr = reinterpret_cast<const struct sockaddr_in *>(addr);
    assert(addr_len == sizeof(*ip_addr));

    const auto *buffer_ptr = reinterpret_cast<const uint8_t *>(buf);
    request_buffer.assign(buffer_ptr, buffer_ptr + n);
    return n;
}
}
