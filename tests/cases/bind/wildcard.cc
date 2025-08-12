#include "common.hh"
#include "config.hh"
#include "resolve.hh"

/// *.a.wildcard A 1.2.3.4

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
    Resolver nsec3_signed_resolver{NSEC3_SIGNED_RESOLVER_CONFIG};
    check_response(unsigned_resolver.resolve("sub.a.wildcard." UNSIGNED_DOMAIN, RRType::A));
    check_response(signed_resolver.resolve("sub.a.wildcard." SIGNED_DOMAIN, RRType::A));
    check_response(nsec3_signed_resolver.resolve("sub.a.wildcard." NSEC3_SIGNED_DOMAIN, RRType::A));

    check_response(unsigned_resolver.resolve("sub.sub.a.wildcard." UNSIGNED_DOMAIN, RRType::A));
    check_response(signed_resolver.resolve("sub.sub.a.wildcard." SIGNED_DOMAIN, RRType::A));
    check_response(nsec3_signed_resolver.resolve("sub.sub.a.wildcard." NSEC3_SIGNED_DOMAIN, RRType::A));
    return EXIT_SUCCESS;
}
