#include <vector>
#include "common.hh"
#include "config.hh"
#include "resolve.hh"

// DS can only be specified for the delegation point, which is marked by NS record.
/// ds NS ns.ds
/// ds DS 12345 8 1 2923F6FA36614586EA09B4424B438915CC1B9B67

namespace {
const std::vector<uint8_t> ds_digest = {0x29, 0x23, 0xf6, 0xfa, 0x36, 0x61, 0x45, 0x86, 0xea, 0x09,
                                        0xb4, 0x42, 0x4b, 0x43, 0x89, 0x15, 0xcc, 0x1b, 0x9b, 0x67};

void check_response(const std::optional<std::vector<RR>> &response) {
    ASSERT(response.has_value());

    const auto &rrset = response.value();
    ASSERT(rrset.size() == 1);

    const auto &rr = rrset[0];
    ASSERT(rr.type == RRType::DS);
    const auto &ds = std::get<DS>(rr.data);

    ASSERT(ds.key_tag == 12345);
    ASSERT(std::to_underlying(ds.signing_algorithm) == 8);
    ASSERT(std::to_underlying(ds.digest_algorithm) == 1);
    ASSERT(ds.digest == ds_digest);
}
}  // namespace

int main() {
    Resolver unsigned_resolver{UNSIGNED_RESOLVER_CONFIG};
    Resolver signed_resolver{SIGNED_RESOLVER_CONFIG};
    check_response(unsigned_resolver.resolve("ds." UNSIGNED_DOMAIN, RRType::DS));
    check_response(signed_resolver.resolve("ds." SIGNED_DOMAIN, RRType::DS));
    return EXIT_SUCCESS;
}
