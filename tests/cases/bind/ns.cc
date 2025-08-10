#include "common.hh"
#include "config.hh"
#include "resolve.hh"

namespace {
void check_response(const std::optional<std::vector<RR>> &response, const std::string &zone_domain) {
    ASSERT(response.has_value());

    const auto &rrset = response.value();
    ASSERT(rrset.size() == 2);

    for (const auto &rr : rrset) {
        ASSERT(rr.type == RRType::NS);
        const auto &ns = std::get<NS>(rr.data);
        ASSERT(ns.domain.ends_with(zone_domain));
    }
}
}  // namespace

int main() {
    Resolver unsigned_resolver{UNSIGNED_RESOLVER_CONFIG};
    Resolver signed_resolver{SIGNED_RESOLVER_CONFIG};
    check_response(unsigned_resolver.resolve(UNSIGNED_DOMAIN, RRType::NS), UNSIGNED_DOMAIN);
    check_response(signed_resolver.resolve(SIGNED_DOMAIN, RRType::NS), SIGNED_DOMAIN);
    return EXIT_SUCCESS;
}
