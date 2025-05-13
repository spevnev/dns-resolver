#ifndef COMMON_H
#define COMMON_H

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

in_addr_t get_ip4(const char *ip_str);
struct in6_addr get_ip6(const char *ip_str);

#endif  // COMMON_H
