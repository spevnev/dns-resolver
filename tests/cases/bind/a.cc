#include "common.hh"
#include "config.hh"
#include "resolve.hh"

/// a A 1.2.3.4

namespace {
void check_response(const std::optional<std::vector<RR>> &response) {
    ASSERT(response.has_value());

    const auto &rrset = response.value();
    ASSERT(rrset.size() == 1);

    const auto &rr = rrset[0];
    ASSERT(rr.type == RRType::A);
    ASSERT(std::get<A>(rr.data).address == get_ip4("1.2.3.4"));
}
}  // namespace

int main() {
    Resolver unsigned_resolver{UNSIGNED_RESOLVER_CONFIG};
    Resolver signed_resolver{SIGNED_RESOLVER_CONFIG};
    check_response(unsigned_resolver.resolve("a." UNSIGNED_DOMAIN, RRType::A));
    check_response(signed_resolver.resolve("a." SIGNED_DOMAIN, RRType::A));
    return EXIT_SUCCESS;
}
