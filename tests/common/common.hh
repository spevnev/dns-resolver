#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <print>  // IWYU pragma: keep

#define ASSERT(condition)                                                                          \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::println(stderr, "{}:{}: Assertion '{}' failed.", __FILE__, __LINE__, #condition); \
            exit(EXIT_FAILURE);                                                                    \
        }                                                                                          \
    } while (0)

inline in_addr_t get_ip4(const char *ip_str) {
    in_addr_t ip_addr;
    auto result = inet_pton(AF_INET, ip_str, &ip_addr);
    assert(result == 1);
    return ip_addr;
}

inline bool ip6_equals(struct in6_addr address_a, const char *ip_str) {
    struct in6_addr address_b;
    auto result = inet_pton(AF_INET6, ip_str, &address_b);
    assert(result == 1);
    return std::memcmp(&address_a, &address_b, sizeof(address_a)) == 0;
}
