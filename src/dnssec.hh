#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "dns.hh"

int get_ds_digest_size(DigestAlgorithm algorithm);
uint16_t compute_key_tag(const std::vector<uint8_t> &data);

bool verify_rrsig(const std::vector<RR> &rrset, const std::vector<DNSKEY> &dnskeys, const std::string &zone_domain,
                  const std::vector<RRSIG> &rrsigs);
bool verify_dnskeys(const std::vector<RR> &dnskey_rrset, const std::vector<DS> &dss, const std::string &zone_domain,
                    const std::vector<RRSIG> &rrsigs);
