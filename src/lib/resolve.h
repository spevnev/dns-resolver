#ifndef RESOLVE_H
#define RESOLVE_H

#include <stdbool.h>
#include <stdint.h>
#include "dns.h"

#define RESOLVE_DISABLE_RDFLAG (1U << 0)
#define RESOLVE_DISABLE_EDNS (1U << 1)
#define RESOLVE_DISABLE_COOKIE (1U << 2)
#define RESOLVE_NO_ROOT_NS (1U << 3)
#define RESOLVE_VERBOSE (1U << 31)

bool resolve(const char *domain, uint16_t qtype, const char *nameserver, uint16_t port, uint64_t timeout_ms,
             uint32_t flags, RRVec *result);
void free_rr_vec(RRVec rr_vec);

#endif  // RESOLVE_H
