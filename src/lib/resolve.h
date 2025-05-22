#ifndef RESOLVE_H
#define RESOLVE_H

#include <stdbool.h>
#include <stdint.h>
#include "dns.h"

#define RESOLVE_DISABLE_RDFLAG (1U << 0)
#define RESOLVE_DISABLE_EDNS (1U << 1)
#define RESOLVE_VERBOSE (1U << 31)

bool resolve(RRVec *result, const char *domain, uint16_t qtype, const char *nameserver, uint16_t port,
             uint64_t timeout_ms, uint32_t flags);
void free_rr_vec(RRVec *rr_vec);

#endif  // RESOLVE_H
