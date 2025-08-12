#include "common.hh"
#include "config.hh"
#include "resolve.hh"

/// *.no-data.wildcard A 1.2.3.4

namespace {
void check_response(const std::optional<std::vector<RR>> &response) {
    ASSERT(response.has_value());
    ASSERT(response->empty());
}
}  // namespace

int main() {
    Resolver unsigned_resolver{UNSIGNED_RESOLVER_CONFIG};
    Resolver signed_resolver{SIGNED_RESOLVER_CONFIG};
    Resolver nsec3_signed_resolver{NSEC3_SIGNED_RESOLVER_CONFIG};
    check_response(unsigned_resolver.resolve("no-data.wildcard." UNSIGNED_DOMAIN, RRType::HINFO));
    check_response(signed_resolver.resolve("no-data.wildcard." SIGNED_DOMAIN, RRType::HINFO));
    check_response(nsec3_signed_resolver.resolve("no-data.wildcard." NSEC3_SIGNED_DOMAIN, RRType::HINFO));

    check_response(unsigned_resolver.resolve("sub.no-data.wildcard." UNSIGNED_DOMAIN, RRType::HINFO));
    check_response(signed_resolver.resolve("sub.no-data.wildcard." SIGNED_DOMAIN, RRType::HINFO));
    check_response(nsec3_signed_resolver.resolve("sub.no-data.wildcard." NSEC3_SIGNED_DOMAIN, RRType::HINFO));

    check_response(unsigned_resolver.resolve("sub.sub.no-data.wildcard." UNSIGNED_DOMAIN, RRType::HINFO));
    check_response(signed_resolver.resolve("sub.sub.no-data.wildcard." SIGNED_DOMAIN, RRType::HINFO));
    check_response(nsec3_signed_resolver.resolve("sub.sub.no-data.wildcard." NSEC3_SIGNED_DOMAIN, RRType::HINFO));
    return EXIT_SUCCESS;
}
