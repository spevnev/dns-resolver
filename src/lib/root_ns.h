#ifndef ROOT_NS_H
#define ROOT_NS_H

#include "dns.h"

// https://www.iana.org/domains/root/servers
__attribute__((unused)) static const char *ROOT_IP_ADDRS[] = {
    "198.41.0.4",    "170.247.170.2", "192.33.4.12",   "199.7.91.13",  "192.203.230.10", "192.5.5.241",  "192.112.36.4",
    "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",    "202.12.27.33",
};
#define ROOT_IP_ADDRS_COUNT (sizeof(ROOT_IP_ADDRS) / sizeof(*ROOT_IP_ADDRS))

#endif  // ROOT_NS_H
