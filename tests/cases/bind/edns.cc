#include "common.hh"
#include "config.hh"
#include "resolve.hh"

// RR is larger than the UDP payload size without EDNS (512 bytes), so response without EDNS will fail (truncated).

// clang-format off
/// edns TXT aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
// clang-format on

int main() {
    auto config_without_edns = UNSIGNED_RESOLVER_CONFIG;
    config_without_edns.edns = FeatureState::Disable;
    Resolver resolver_without_edns{config_without_edns};
    auto response = resolver_without_edns.resolve("edns." UNSIGNED_DOMAIN, RRType::TXT);
    ASSERT(!response.has_value());

    assert(UNSIGNED_RESOLVER_CONFIG.edns != FeatureState::Disable);
    Resolver resolver_with_edns{UNSIGNED_RESOLVER_CONFIG};
    response = resolver_with_edns.resolve("edns." UNSIGNED_DOMAIN, RRType::TXT);
    ASSERT(response.has_value());

    const auto &rrset = response.value();
    ASSERT(rrset.size() == 1);

    const auto &rr = rrset[0];
    ASSERT(rr.type == RRType::TXT);
    ASSERT(std::get<TXT>(rr.data).strings.size() == 5);

    return EXIT_SUCCESS;
}
