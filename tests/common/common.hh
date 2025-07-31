#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cstdlib>
#include <print>  // IWYU pragma: keep

#define ASSERT(condition)                                                                          \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::println(stderr, "{}:{}: Assertion '{}' failed.", __FILE__, __LINE__, #condition); \
            exit(EXIT_FAILURE);                                                                    \
        }                                                                                          \
    } while (0)

in_addr_t get_ip4(const char *ip_str);
bool ip6_equals(struct in6_addr address, const char *ip_str);
