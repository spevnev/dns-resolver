#include "common.hh"
#include "config.hh"
#include "resolve.hh"

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
    check_response(unsigned_resolver.resolve("name-error." UNSIGNED_DOMAIN, RRType::A));
    check_response(signed_resolver.resolve("name-error." SIGNED_DOMAIN, RRType::A));
    check_response(nsec3_signed_resolver.resolve("name-error." NSEC3_SIGNED_DOMAIN, RRType::A));
    return EXIT_SUCCESS;
}
