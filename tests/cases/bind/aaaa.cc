#include "common.hh"
#include "config.hh"
#include "resolve.hh"

/// aaaa AAAA 1:2:3:4::

namespace {
void check_response(const std::optional<std::vector<RR>> &response) {
    ASSERT(response.has_value());

    const auto &rrset = response.value();
    ASSERT(rrset.size() == 1);

    const auto &rr = rrset[0];
    ASSERT(rr.type == RRType::AAAA);
    ASSERT(ip6_equals(std::get<AAAA>(rr.data).address, "1:2:3:4::"));
}
}  // namespace

int main() {
    Resolver unsigned_resolver{UNSIGNED_RESOLVER_CONFIG};
    Resolver signed_resolver{SIGNED_RESOLVER_CONFIG};
    check_response(unsigned_resolver.resolve("aaaa." UNSIGNED_DOMAIN, RRType::AAAA));
    check_response(signed_resolver.resolve("aaaa." SIGNED_DOMAIN, RRType::AAAA));
    return EXIT_SUCCESS;
}
