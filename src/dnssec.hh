#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include "dns.hh"

int get_ds_digest_size(DigestAlgorithm algorithm);
uint16_t compute_key_tag(const std::vector<uint8_t> &data);

bool verify_rrsig(const std::vector<RR> &rrset, const std::vector<DNSKEY> &dnskeys, const std::string &zone_domain,
                  const std::vector<RRSIG> &rrsigs);
bool verify_dnskeys(const std::vector<RR> &dnskey_rrset, const std::vector<DS> &dss, const std::string &zone_domain,
                    const std::vector<RRSIG> &rrsigs);

bool nsec_covers_domain(const RR &nsec_rr, const std::string &domain);
std::optional<NSEC3> find_covering_nsec3(const std::vector<RR> &nsec3_rrset, const std::string_view &domain,
                                         const std::string &zone_domain);
std::optional<NSEC3> find_matching_nsec3(const std::vector<RR> &nsec3_rrset, const std::string_view &domain,
                                         const std::string &zone_domain);
std::optional<std::pair<std::string, NSEC3>> verify_closest_encloser_proof(const std::vector<RR> &nsec3_rrset,
                                                                           const std::string &domain,
                                                                           const std::string &zone_domain);
