#include "common.h"
#include "error.h"

in_addr_t get_ip4(const char *ip_str) {
    in_addr_t ip_addr;
    if (inet_pton(AF_INET, ip_str, &ip_addr) != 1) ERROR("Invalid IPv4 address: %s", ip_str);
    return ip_addr;
}

struct in6_addr get_ip6(const char *ip_str) {
    struct in6_addr ip_addr;
    if (inet_pton(AF_INET6, ip_str, &ip_addr) != 1) ERROR("Invalid IPv6 address: %s", ip_str);
    return ip_addr;
}
