#ifndef COMMON_H
#define COMMON_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define ASSERT(condition)                                                                       \
    do {                                                                                        \
        if (!(condition)) {                                                                     \
            fprintf(stderr, "%s:%d: Assertion '%s' failed.\n", __FILE__, __LINE__, #condition); \
            exit(EXIT_FAILURE);                                                                 \
        }                                                                                       \
    } while (0)

in_addr_t get_ip4(const char *ip_str);
struct in6_addr get_ip6(const char *ip_str);

#endif  // COMMON_H
