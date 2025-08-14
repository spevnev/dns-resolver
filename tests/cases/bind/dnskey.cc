#include "common.hh"
#include "config.hh"
#include "resolve.hh"

/// dnskey DNSKEY 257 3 15 S4ETa4EcgxKaWQjBeHudmRZ0/38ibfF6/YmlnUNo8T4=

namespace {
const std::vector<uint8_t> dnskey_key = {
    0x4b, 0x81, 0x13, 0x6b, 0x81, 0x1c, 0x83, 0x12, 0x9a, 0x59, 0x08, 0xc1, 0x78, 0x7b, 0x9d, 0x99,
    0x16, 0x74, 0xff, 0x7f, 0x22, 0x6d, 0xf1, 0x7a, 0xfd, 0x89, 0xa5, 0x9d, 0x43, 0x68, 0xf1, 0x3e,
};

void check_response(const std::optional<std::vector<RR>> &response) {
    ASSERT(response.has_value());

    const auto &rrset = response.value();
    ASSERT(rrset.size() == 1);

    const auto &rr = rrset[0];
    ASSERT(rr.type == RRType::DNSKEY);
    const auto &dnskey = std::get<DNSKEY>(rr.data);

    ASSERT(dnskey.is_zone_key);
    ASSERT(dnskey.is_secure_entry);
    ASSERT(dnskey.protocol == DNSKEY_PROTOCOL);
    ASSERT(dnskey.algorithm == SigningAlgorithm::ED25519);
    ASSERT(dnskey.key == dnskey_key);
    ASSERT(dnskey.key_tag == 8710);
}
}  // namespace

int main() {
    Resolver unsigned_resolver{UNSIGNED_RESOLVER_CONFIG};
    Resolver signed_resolver{SIGNED_RESOLVER_CONFIG};
    check_response(unsigned_resolver.resolve("dnskey." UNSIGNED_DOMAIN, RRType::DNSKEY));
    check_response(signed_resolver.resolve("dnskey." SIGNED_DOMAIN, RRType::DNSKEY));
    return EXIT_SUCCESS;
}
