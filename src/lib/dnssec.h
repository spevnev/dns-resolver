#ifndef DNSSEC_H
#define DNSSEC_H

#include <stdint.h>
#include "dns.h"

int get_ds_digest_size(uint8_t algorithm);

bool verify_rrsig(const RRVec *rr_vec, const RRVec *dnskeys, const char *zone_domain, const RRVec *rrsig_vec);
bool verify_dnskeys(const RRVec *dnskeys, const RRVec *dss, const char *zone_domain, const RRVec *rrsig_vec);

#endif  // DNSSEC_H
