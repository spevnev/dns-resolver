#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "dns.hh"

namespace dnssec {
int get_ds_digest_size(DigestAlgorithm algorithm);
uint16_t compute_key_tag(const std::vector<uint8_t> &data);

bool authenticate_rrset(const std::vector<RR> &rrset, const std::vector<RRSIG> &rrsigs,
                        const std::vector<DNSKEY> &dnskeys, const std::string &zone_domain);
bool authenticate_delegation(const std::vector<RR> &dnskey_rrset, const std::vector<DS> &dss,
                             const std::vector<RRSIG> &rrsigs, const std::string &zone_domain);
bool authenticate_name_error(const std::string &domain, const std::vector<RR> &nsec3_rrset,
                             const std::vector<RR> &nsec_rrset, const std::string &zone_domain);
bool authenticate_no_ds(const std::string &domain, const std::vector<RR> &nsec3_rrset, const std::optional<RR> &nsec_rr,
                        const std::string &zone_domain);
bool authenticate_no_rrset(RRType rr_type, const std::string &domain, const std::vector<RR> &nsec3_rrset,
                           const std::optional<RR> &nsec_rr, const std::string &zone_domain);
};  // namespace dnssec
