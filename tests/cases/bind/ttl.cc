#include "common.hh"
#include "config.hh"
#include "resolve.hh"

/// ttl 1234 A 1.2.3.4

namespace {
void check_response(const std::optional<std::vector<RR>> &response) {
    ASSERT(response.has_value());

    const auto &rrset = response.value();
    ASSERT(rrset.size() == 1);
    ASSERT(rrset[0].ttl == 1234);
}
}  // namespace

int main() {
    Resolver unsigned_resolver{UNSIGNED_RESOLVER_CONFIG};
    Resolver signed_resolver{SIGNED_RESOLVER_CONFIG};
    check_response(unsigned_resolver.resolve("ttl." UNSIGNED_DOMAIN, RRType::A));
    check_response(signed_resolver.resolve("ttl." SIGNED_DOMAIN, RRType::A));
    return EXIT_SUCCESS;
}
