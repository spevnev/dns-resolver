#ifndef RESOLVE_H
#define RESOLVE_H

#include <stdbool.h>
#include <stdint.h>
#include "dns.h"

#define RESOLVE_RECURSION_DESIRED (1U << 0)
#define RESOLVE_EDNS (1U << 1)
#define RESOLVE_VERBOSE (1U << 31)

RRVec resolve(const char *domain, uint16_t qtype, const char *nameserver_ip, uint16_t port, uint64_t timeout_ms,
              uint32_t options);
void free_rr_vec(RRVec *rr_vec);

#endif  // RESOLVE_H
