#include "common.hh"
#include "config.hh"
#include "resolve.hh"

// RFC2181 Section 8.
// TTL is an unsigned number between 0 and 2147483647
/// invalid.ttl 2147483648 A 1.2.3.4

namespace {
void check_response(const std::optional<std::vector<RR>> &response) {
    const auto &rrset = response.value();
    ASSERT(rrset.size() == 1);

    // Treat TTL values received with the MSB set as if the entire value received was zero.
    ASSERT(rrset[0].ttl == 0);
}
}  // namespace

int main() {
    Resolver unsigned_resolver{UNSIGNED_RESOLVER_CONFIG};
    Resolver signed_resolver{SIGNED_RESOLVER_CONFIG};
    check_response(unsigned_resolver.resolve("invalid.ttl." UNSIGNED_DOMAIN, RRType::A));
    check_response(signed_resolver.resolve("invalid.ttl." SIGNED_DOMAIN, RRType::A));
    return EXIT_SUCCESS;
}
