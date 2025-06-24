#ifndef DNSSEC_H
#define DNSSEC_H

#include <stdint.h>
#include "dns.h"

int get_ds_digest_size(uint8_t algorithm);

bool verify_dnskeys(RRVec dnskeys, RRVec dss, RRVec *verified_dnskeys_out);
bool verify_rrsig(RRVec rr_vec, RRType rr_type, const RR *rrsig_rr, RRVec dnskeys, const char *zone_domain);

#endif  // DNSSEC_H
