#ifndef ROOT_NS_H
#define ROOT_NS_H

#include "dns.h"

// https://www.iana.org/domains/root/servers
__attribute__((unused)) static const char *ROOT_IP_ADDRS[] = {
    "198.41.0.4",    "170.247.170.2", "192.33.4.12",   "199.7.91.13",  "192.203.230.10", "192.5.5.241",  "192.112.36.4",
    "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",    "202.12.27.33",
};
#define ROOT_IP_ADDRS_COUNT (sizeof(ROOT_IP_ADDRS) / sizeof(*ROOT_IP_ADDRS))

// https://data.iana.org/root-anchors/root-anchors.xml
__attribute__((unused)) static const RR ROOT_DS[] = {
    {
        .domain = ".",
        .ttl = 0,
        .type = TYPE_DS,
        .data.ds = {
            .key_tag = 20326,
            .signing_algorithm = SIGNING_RSASHA256,
            .digest_algorithm = DIGEST_SHA256,
            .digest = (uint8_t[]) {0xE0,0x6D,0x44,0xB8,0x0B,0x8F,0x1D,0x39,0xA9,0x5C,0x0B,0x0D,0x7C,0x65,0xD0,0x84,0x58,0xE8,0x80,0x40,0x9B,0xBC,0x68,0x34,0x57,0x10,0x42,0x37,0xC7,0xF8,0xEC,0x8D},
            .digest_size = 32,
        },
    },
        {
        .domain = ".",
        .ttl = 0,
        .type = TYPE_DS,
        .data.ds = {
            .key_tag = 38696,
            .signing_algorithm = SIGNING_RSASHA256,
            .digest_algorithm = DIGEST_SHA256,
            .digest = (uint8_t[]) {0x68,0x3D,0x2D,0x0A,0xCB,0x8C,0x9B,0x71,0x2A,0x19,0x48,0xB2,0x7F,0x74,0x12,0x19,0x29,0x8D,0x0A,0x45,0x0D,0x61,0x2C,0x48,0x3A,0xF4,0x44,0xA4,0xC0,0xFB,0x2B,0x16},
            .digest_size = 32,
        },
    }
};
#define ROOT_DS_COUNT (sizeof(ROOT_DS) / sizeof(*ROOT_DS))

#endif  // ROOT_NS_H
